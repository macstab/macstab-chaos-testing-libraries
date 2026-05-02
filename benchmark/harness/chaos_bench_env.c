/**
 * @file chaos_bench_env.c
 * @brief Best-effort capture of host and build environment for the JSON
 *        envelope.
 *
 * @details
 * Provenance is the difference between a number and a *reproducible*
 * number.  This module reads the ambient state — kernel version, CPU
 * model and feature flags, governor, isolated CPUs, THP setting,
 * container marker, libc identity, and the build's compile flags and
 * git SHA — and stores it in a `chaos_bench_env_t` struct.  The runner
 * emits the entire struct verbatim into every JSON output, so a result
 * file can be reproduced months later given only the JSON.
 *
 * **Failure model.**
 * Every read is best-effort: a missing or unreadable file produces an
 * empty string, never a fatal error.  This module never aborts.  The
 * downstream isolation check distinguishes empty-because-missing from
 * empty-because-permissions only when the difference is observable
 * (e.g. ENOENT vs EACCES); for the JSON envelope the value is "".
 *
 * **Sources, in order of robustness.**
 *  - `/proc/sys/kernel/osrelease` — single line, one shot.  Always
 *    present on Linux.
 *  - `/proc/version` — full kernel build banner.  Always present.
 *  - `/proc/cpuinfo` — multi-line, format mildly platform-dependent.
 *    We pull `model name` and `flags` for the first CPU only; subsequent
 *    CPUs are assumed homogeneous.  On heterogeneous (big.LITTLE) ARM
 *    SoCs this is incorrect; the wrapper script must avoid pinning across
 *    a P-core / E-core boundary if it cares about this.
 *  - `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` — single
 *    line.  Absent on systems without cpufreq (rare).
 *  - `/sys/devices/system/cpu/isolated` — single line, comma-separated
 *    or empty.  Always present on Linux >= 4.x.
 *  - `/sys/kernel/mm/transparent_hugepage/enabled` — single line with
 *    bracketed selection.  Always present when THP is compiled in.
 *  - `/.dockerenv` — sentinel for Docker; presence ⇒ containerized.
 *    Other container runtimes (podman, containerd, runsc, k8s) have
 *    different sentinels; we conservatively treat absence as
 *    "non-containerized" and let the user note runtime in their JSON
 *    consumer.
 *
 * **Build-time provenance.**
 * Two preprocessor symbols carry build-time provenance:
 *  - `CHAOS_BENCH_GIT_SHA` — set by the Makefile from `git rev-parse HEAD`.
 *  - `CHAOS_BENCH_CFLAGS`  — set by the Makefile from the actual
 *                            CFLAGS used to compile the harness.
 * Both are surfaced verbatim in the JSON.  If neither is defined the
 * JSON emits empty strings; this preserves the property that the source
 * tree compiles standalone without the Makefile.
 */

#include "chaos_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef CHAOS_BENCH_GIT_SHA
#  define CHAOS_BENCH_GIT_SHA ""
#endif
#ifndef CHAOS_BENCH_CFLAGS
#  define CHAOS_BENCH_CFLAGS ""
#endif

/**
 * @brief Reads up to @p capacity-1 bytes from @p path into @p buffer.
 *
 * @details Trailing newline is stripped.  On open or read failure the
 * buffer is set to "" and 0 is returned.  Truncation past @p capacity-1
 * is signalled via the return: 1 = full read, 0 = empty/failure, 2 =
 * truncated.
 */
static int chaos_bench_read_text(const char *path, char *buffer, size_t capacity)
{
    FILE *fp;
    size_t n;

    if (capacity == 0U)
    {
        return 0;
    }
    buffer[0] = '\0';
    fp = fopen(path, "r");
    if (fp == NULL)
    {
        return 0;
    }
    n = fread(buffer, 1U, capacity - 1U, fp);
    int truncated = !feof(fp);
    (void)fclose(fp);
    if (n == 0U)
    {
        buffer[0] = '\0';
        return 0;
    }
    /* Strip trailing newline(s). */
    while (n > 0U && (buffer[n - 1U] == '\n' || buffer[n - 1U] == '\r'))
    {
        --n;
    }
    buffer[n] = '\0';
    return truncated ? 2 : 1;
}

/**
 * @brief Extracts the value following `key:` from /proc/cpuinfo-format text.
 *
 * @details `/proc/cpuinfo` lines have the shape `<key>\s+:\s+<value>`.
 * We scan @p text for the first line whose prefix (up to ':') matches
 * @p key (case-sensitive, trimmed), then copy the value into @p out.
 * Subsequent CPU stanzas are ignored.
 */
static void chaos_bench_proc_cpuinfo_field(
    const char *text, const char *key, char *out, size_t capacity
)
{
    const char *cursor = text;
    size_t      key_len = strlen(key);

    out[0] = '\0';
    while (cursor != NULL && *cursor != '\0')
    {
        const char *eol = strchr(cursor, '\n');
        size_t      line_len = (eol != NULL) ? (size_t)(eol - cursor) : strlen(cursor);

        /* Trim leading whitespace then compare. */
        const char *p = cursor;
        while (p < cursor + line_len && (*p == ' ' || *p == '\t')) ++p;
        if ((size_t)(cursor + line_len - p) >= key_len &&
            strncmp(p, key, key_len) == 0)
        {
            const char *q = p + key_len;
            while (q < cursor + line_len && (*q == ' ' || *q == '\t')) ++q;
            if (q < cursor + line_len && *q == ':')
            {
                ++q;
                while (q < cursor + line_len && (*q == ' ' || *q == '\t')) ++q;
                size_t value_len = (size_t)(cursor + line_len - q);
                if (value_len >= capacity) value_len = capacity - 1U;
                memcpy(out, q, value_len);
                out[value_len] = '\0';
                return;
            }
        }
        cursor = (eol != NULL) ? eol + 1 : NULL;
    }
}

/**
 * @brief Returns 1 if the substring @p needle (whitespace-bounded) appears
 *        in the space-delimited list @p haystack.
 *
 * @details Used to test for a CPU flag in the /proc/cpuinfo `flags` line.
 */
static int chaos_bench_flag_present(const char *haystack, const char *needle)
{
    const char *p = haystack;
    size_t      n_len = strlen(needle);

    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '\0') break;
        const char *start = p;
        while (*p != '\0' && *p != ' ' && *p != '\t') ++p;
        if ((size_t)(p - start) == n_len && strncmp(start, needle, n_len) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Returns 1 if @p path exists, regardless of permission.
 */
static int chaos_bench_path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? 1 : 0;
}

/**
 * @brief Best-effort detection of glibc vs musl.
 *
 * @details glibc exposes `gnu_get_libc_version()`; musl does not.  We
 * detect glibc by checking the loader path: `/lib*\/ld-linux*` is glibc;
 * `/lib/ld-musl-*` is musl.  The check is heuristic and may fail on
 * exotic distros.
 */
static void chaos_bench_libc_detect(char *out, size_t capacity)
{
    out[0] = '\0';
    if (chaos_bench_path_exists("/lib64/ld-linux-x86-64.so.2") ||
        chaos_bench_path_exists("/lib/ld-linux-x86-64.so.2") ||
        chaos_bench_path_exists("/lib/ld-linux-aarch64.so.1") ||
        chaos_bench_path_exists("/lib64/ld-linux-aarch64.so.1"))
    {
        snprintf(out, capacity, "glibc");
        return;
    }
    if (chaos_bench_path_exists("/lib/ld-musl-x86_64.so.1") ||
        chaos_bench_path_exists("/lib/ld-musl-aarch64.so.1"))
    {
        snprintf(out, capacity, "musl");
        return;
    }
    snprintf(out, capacity, "unknown");
}

void chaos_bench_env_capture(chaos_bench_env_t *out_env)
{
    char  cpuinfo[CHAOS_BENCH_ENV_FIELD_MAX * 4];
    int   read_status;
    const char *ld_preload;

    memset(out_env, 0, sizeof(*out_env));

    /* Kernel identity. */
    read_status = chaos_bench_read_text(
        "/proc/sys/kernel/osrelease",
        out_env->kernel_release,
        sizeof(out_env->kernel_release)
    );
    out_env->kernel_truncated = (read_status == 2);
    (void)chaos_bench_read_text(
        "/proc/version",
        out_env->kernel_version,
        sizeof(out_env->kernel_version)
    );

    /* CPU. */
    read_status = chaos_bench_read_text(
        "/proc/cpuinfo", cpuinfo, sizeof(cpuinfo)
    );
    out_env->cpu_flags_truncated = (read_status == 2);
    chaos_bench_proc_cpuinfo_field(
        cpuinfo, "model name",
        out_env->cpu_model, sizeof(out_env->cpu_model)
    );
    if (out_env->cpu_model[0] == '\0')
    {
        /* aarch64 uses a different field name. */
        chaos_bench_proc_cpuinfo_field(
            cpuinfo, "Processor",
            out_env->cpu_model, sizeof(out_env->cpu_model)
        );
    }
    chaos_bench_proc_cpuinfo_field(
        cpuinfo, "flags",
        out_env->cpu_flags_blob, sizeof(out_env->cpu_flags_blob)
    );
    if (out_env->cpu_flags_blob[0] == '\0')
    {
        /* aarch64 uses 'Features' instead of 'flags'. */
        chaos_bench_proc_cpuinfo_field(
            cpuinfo, "Features",
            out_env->cpu_flags_blob, sizeof(out_env->cpu_flags_blob)
        );
    }
    out_env->has_constant_tsc =
        chaos_bench_flag_present(out_env->cpu_flags_blob, "constant_tsc");
    out_env->has_nonstop_tsc =
        chaos_bench_flag_present(out_env->cpu_flags_blob, "nonstop_tsc");

    /* Frequency governor. */
    (void)chaos_bench_read_text(
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
        out_env->governor, sizeof(out_env->governor)
    );

    /* CPU isolation list. */
    (void)chaos_bench_read_text(
        "/sys/devices/system/cpu/isolated",
        out_env->isolated_cpus, sizeof(out_env->isolated_cpus)
    );

    /* Transparent huge pages. */
    (void)chaos_bench_read_text(
        "/sys/kernel/mm/transparent_hugepage/enabled",
        out_env->thp_enabled, sizeof(out_env->thp_enabled)
    );

    /* SMT detection: cpu0/topology/thread_siblings_list contains the list of
     * sibling thread CPUs; if it includes more than one entry SMT is on. */
    {
        char siblings[64];
        if (chaos_bench_read_text(
                "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list",
                siblings, sizeof(siblings)) > 0)
        {
            out_env->smt_active = (strchr(siblings, ',') != NULL ||
                                   strchr(siblings, '-') != NULL) ? 1 : 0;
        }
    }

    /* Container marker. */
    out_env->container_marker = chaos_bench_path_exists("/.dockerenv");

    /* libc identity. */
    chaos_bench_libc_detect(out_env->libc_id, sizeof(out_env->libc_id));

    /* LD_PRELOAD as exposed to this process. */
    ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != NULL)
    {
        size_t n = strlen(ld_preload);
        if (n >= sizeof(out_env->ld_preload))
        {
            n = sizeof(out_env->ld_preload) - 1U;
            out_env->ld_preload_truncated = 1;
        }
        memcpy(out_env->ld_preload, ld_preload, n);
        out_env->ld_preload[n] = '\0';
    }

    /* Build-time provenance. */
    snprintf(out_env->git_sha, sizeof(out_env->git_sha), "%s", CHAOS_BENCH_GIT_SHA);
    snprintf(out_env->build_cflags, sizeof(out_env->build_cflags), "%s", CHAOS_BENCH_CFLAGS);
}
