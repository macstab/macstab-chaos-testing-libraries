/**
 * @file chaos_bench_env.c
 * @brief Captures host and build provenance for the JSON envelope.
 *
 * @details
 * A benchmark number without its environment cannot be reproduced or compared. This module
 * records the kernel release and build banner, CPU model and flags, cpu0 governor, isolated
 * CPUs, THP mode, SMT state, Docker marker, libc family, LD_PRELOAD, and the harness's git
 * SHA and CFLAGS into a @ref chaos_bench_env_t. The JSON writer emits all of it (except the
 * internal `*_truncated` flags) in the `environment` section, and the isolation check and
 * timer selection read from it.
 *
 * **Failure behaviour.**
 * Every read is best-effort: a missing or unreadable file leaves an empty string (or 0); the
 * module never fails and never aborts. ENOENT and EACCES are not distinguished, so an empty
 * governor means "no cpufreq" or "not readable" alike.
 *
 * **Sources.**
 *  - `/proc/sys/kernel/osrelease`: kernel release, one line.
 *  - `/proc/version`: full kernel build banner.
 *  - `/proc/cpuinfo`: first 16 KiB only. `model name` (x86) or `Processor` (older arm64
 *    kernels) and `flags` (x86) or `Features` (arm64) are taken from the first matching line,
 *    i.e. the first CPU; all CPUs are assumed identical. On heterogeneous (big.LITTLE,
 *    P-core/E-core) systems this can describe a different core than the pinned one.
 *  - `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor`: absent without cpufreq, and
 *    commonly inside VMs and containers.
 *  - `/sys/devices/system/cpu/isolated`: CPU list from `isolcpus=`, empty if none.
 *  - `/sys/kernel/mm/transparent_hugepage/enabled`: THP mode, selected value in brackets.
 *  - `/sys/devices/system/cpu/cpu0/topology/thread_siblings_list`: SMT is on if it lists
 *    more than one CPU.
 *  - `/.dockerenv`: Docker marker. Other runtimes (podman, containerd, gVisor, Kubernetes)
 *    are not detected and are reported as non-containerised.
 *  - Dynamic loader paths: libc family (see @ref chaos_bench_libc_detect).
 *  - `getenv("LD_PRELOAD")`: the preload list this process was started with.
 *
 * **Build-time provenance.**
 *  - `CHAOS_BENCH_GIT_SHA`: `Makefile.bench` sets it from `git rev-parse --short HEAD`
 *    (`unknown` outside a git checkout).
 *  - `CHAOS_BENCH_CFLAGS`: `Makefile.bench` sets it to the base CFLAGS string
 *    (`BENCH_CFLAGS_RAW`).
 * Both default to "" so the harness compiles without the Makefile.
 *
 * **Thread-safety.** Uses `getenv` and stdio; call once from the main thread before the
 * timed loop.
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
 * @brief Reads up to @p capacity-1 bytes of @p path into @p buffer, NUL-terminated.
 *
 * @details Strips trailing `\n`/`\r`. Truncation is inferred from EOF not having been
 * reached, so a file of exactly @p capacity-1 bytes is also reported as truncated.
 *
 * @return 1 read completely; 2 truncated; 0 open failed, file empty, or @p capacity is 0
 *         (@p buffer is then "" unless @p capacity is 0).
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
    /* /proc and /sys values end in a newline that must not reach the JSON strings. */
    while (n > 0U && (buffer[n - 1U] == '\n' || buffer[n - 1U] == '\r'))
    {
        --n;
    }
    buffer[n] = '\0';
    return truncated ? 2 : 1;
}

/**
 * @brief Copies the value of the first `<key> : <value>` line in @p text to @p out.
 *
 * @details Matches lines of the form `<ws><key><ws>:<ws><value>`, case-sensitively; leading
 * blanks and tabs around key and colon are skipped. Only the first match is used, so later
 * CPU stanzas are ignored. The value is truncated to @p capacity-1 bytes. @p out is "" if no
 * line matches.
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

        /* Skip leading blanks and tabs before comparing the key. */
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
 * @brief Returns 1 if @p needle is one whole token of the blank- or tab-separated list
 *        @p haystack, else 0.
 *
 * @details Whole-token matching keeps `tsc` from matching `constant_tsc`.
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
 * @brief Returns 1 if `stat(2)` on @p path succeeds, else 0 (search permission on the
 *        parent directories is still required).
 */
static int chaos_bench_path_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 ? 1 : 0;
}

/**
 * @brief Writes "glibc", "musl" or "unknown" to @p out, based on which dynamic loader exists.
 *
 * @details Probes the x86_64 and aarch64 glibc loaders (`ld-linux-x86-64.so.2`,
 * `ld-linux-aarch64.so.1` under `/lib` and `/lib64`) first, then the musl loaders
 * (`/lib/ld-musl-{x86_64,aarch64}.so.1`). A link-time check such as
 * `gnu_get_libc_version()` would not build on musl, hence the filesystem heuristic. It
 * reports the libc installed on the host image, not necessarily the one this binary uses: a
 * musl image with a glibc compatibility loader reports "glibc".
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
        /* Older arm64 kernels report the model as "Processor"; newer ones have no model line. */
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
        /* arm64 lists CPU features as "Features" instead of "flags". */
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

    /* cpu0's sibling list is a single CPU number unless SMT is on, in which case it holds
     * a ',' or '-' separated list. Unreadable leaves smt_active 0. */
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
