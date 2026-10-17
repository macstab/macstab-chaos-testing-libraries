/**
 * @file chaos_bench_isolation.c
 * @brief Decides the `OFFICIAL` vs `ADVISORY` execution mode from the captured environment.
 *
 * @details
 * Every JSON envelope carries `execution.mode`. `OFFICIAL` means every isolation check below
 * passed and the numbers may be published or used as a release gate. `ADVISORY` means at
 * least one check failed; the numbers remain valid for change detection on the same host
 * but must not be cited as absolute costs.
 *
 * **Checks.** Each failed check adds one warning with this `check` identifier.
 *
 * | check          | Passes when                                  | Why it matters                |
 * |----------------|----------------------------------------------|-------------------------------|
 * | `governor`     | cpu0 governor reads `performance`            | DVFS adds 5-30 % noise        |
 * | `isolcpus`     | `/sys/devices/system/cpu/isolated` non-empty | other tasks share the core    |
 * | `container`    | `/.dockerenv` absent                         | host owns scheduler and IRQs  |
 * | `smt`          | cpu0 sibling list has no `,` or `-`          | sibling shares exec units     |
 * | `constant_tsc` | flag present (x86 only)                      | TSC rate fixed in P-states    |
 * | `nonstop_tsc`  | flag present (x86 only)                      | TSC runs in deep C-states     |
 *
 * The TSC checks are compiled only for x86; other architectures skip them (the aarch64
 * generic timer is invariant by definition).
 *
 * The isolcpus check only requires the list to be non-empty; it does not verify that the
 * process runs on an isolated CPU. Pinning to one is the caller's responsibility.
 *
 * **Not checked.**
 *  - `nohz_full`, `rcu_nocbs`: no single canonical sysfs file; their absence shows up as
 *    sample variance.
 *  - IRQ affinity: needs every `/proc/irq/\*\/smp_affinity`, which hardened hosts restrict;
 *    it is a host provisioning duty.
 *  - Thermal throttling: not detectable statically; it shows up as bimodal samples.
 *  - Microcode revision: not captured.
 *
 * **Bias.** Conservative by design: any single failure downgrades to `ADVISORY`. A host that
 * would have measured cleanly can be marked `ADVISORY` (false alarm), but an `OFFICIAL` tag
 * always means every listed check passed.
 */

#include "chaos_bench_internal.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief Appends a warning with identifier @p check and detail `fmt % value`.
 *
 * @details Drops the warning silently once @ref CHAOS_BENCH_MAX_WARNINGS (32) are stored; no
 * truncation marker is emitted. With six checks the cap is unreachable today. @p check must
 * have static storage duration (it is stored by pointer); @p value NULL formats as "". The
 * detail is truncated to 255 bytes.
 */
static void chaos_bench_warn(
    chaos_bench_warning_t *warnings,
    size_t                *count,
    const char            *check,
    const char            *fmt,
    const char            *value
)
{
    if (*count >= CHAOS_BENCH_MAX_WARNINGS)
    {
        return;
    }
    warnings[*count].check = check;
    snprintf(warnings[*count].detail,
             sizeof(warnings[*count].detail),
             fmt, value != NULL ? value : "");
    ++(*count);
}

chaos_bench_exec_mode_t chaos_bench_isolation_check(
    const chaos_bench_env_t *env,
    chaos_bench_warning_t   *warnings,
    size_t                  *count
)
{
    *count = 0U;

    /* Any governor but performance lets the core clock drift during the run. */
    if (strcmp(env->governor, "performance") != 0)
    {
        chaos_bench_warn(warnings, count,
                         "governor",
                         "governor=%s (need performance)",
                         env->governor[0] != '\0' ? env->governor : "<absent>");
    }

    /* Non-empty list only; whether this process runs on an isolated CPU is not checked. */
    if (env->isolated_cpus[0] == '\0')
    {
        chaos_bench_warn(warnings, count,
                         "isolcpus",
                         "isolated_cpus=<empty> (need isolcpus= boot param)",
                         NULL);
    }

    /* Inside Docker the host, not the container, owns scheduler, governor and IRQs. */
    if (env->container_marker)
    {
        chaos_bench_warn(warnings, count,
                         "container",
                         "running in container (host policies apply)",
                         NULL);
    }

    /* A busy SMT sibling competes for the same execution units and caches. */
    if (env->smt_active)
    {
        chaos_bench_warn(warnings, count,
                         "smt",
                         "SMT/HyperThreading active on cpu0",
                         NULL);
    }

#if defined(__x86_64__) || defined(__i386__)
    if (!env->has_constant_tsc)
    {
        chaos_bench_warn(warnings, count,
                         "constant_tsc",
                         "CPU lacks constant_tsc flag",
                         NULL);
    }
    if (!env->has_nonstop_tsc)
    {
        chaos_bench_warn(warnings, count,
                         "nonstop_tsc",
                         "CPU lacks nonstop_tsc flag",
                         NULL);
    }
#endif

    return *count == 0U ? CHAOS_BENCH_EXEC_OFFICIAL : CHAOS_BENCH_EXEC_ADVISORY;
}
