/**
 * @file chaos_bench_isolation.c
 * @brief Computes the harness's `OFFICIAL` vs `ADVISORY` execution mode.
 *
 * @details
 * The harness publishes its execution mode in every JSON envelope.
 * `OFFICIAL` means every isolation precondition passed and the numbers
 * are suitable for publication or release-gate comparison.  `ADVISORY`
 * means at least one precondition failed; results are still valid for
 * change-detection on the same machine but must not be cited as
 * authoritative numbers.
 *
 * **Precondition matrix (Stage 1).**
 *
 * | Check                | Pass condition                                   | Why it matters                           |
 * |----------------------|--------------------------------------------------|------------------------------------------|
 * | governor             | `cpu0` governor is `performance`                 | freq scaling injects 5–30% variance      |
 * | constant_tsc         | x86_64 has CPUID flag                            | rdtscp ↔ ns conversion stability         |
 * | nonstop_tsc          | x86_64 has CPUID flag                            | TSC continues across C-states            |
 * | isolated             | `/sys/.../isolated` non-empty                    | scheduler can't preempt our core         |
 * | container            | `/.dockerenv` absent                             | container ⇒ host scheduler/governor rule |
 * | smt_off              | sibling list has no comma/dash                   | SMT sibling steals execution units       |
 *
 * On aarch64 we skip the two TSC checks (the architected timer is
 * always invariant); everything else applies identically.
 *
 * **What we do NOT check, and why.**
 *  - `nohz_full`, `rcu_nocbs`: not exposed via a single canonical path;
 *    the same effect is captured indirectly by the variance of the
 *    measurements themselves (Stage 2 will add this as a derived check).
 *  - IRQ affinity: requires reading every `/proc/irq/\*\/smp_affinity`,
 *    which is privileged on hardened hosts.  We rely on the bench host
 *    being configured correctly at provisioning time.
 *  - Thermal throttling: cannot be checked statically; appears as
 *    bimodality in the sample distribution (Stage 2).
 *  - Microcode version: captured in env metadata but does not affect
 *    OFFICIAL/ADVISORY status.  A microcode change that regresses
 *    benchmarks is itself a finding.
 *
 * **Bias.**
 * The check is intentionally pessimistic: any single failed precondition
 * downgrades to ADVISORY.  This produces false negatives (a benchmark
 * that would have been fine in advisory mode is downgraded too) but
 * never false positives — a JSON envelope tagged OFFICIAL has met every
 * documented condition.
 */

#include "chaos_bench_internal.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief Appends one warning to @p warnings if it has space.
 *
 * @details Out-of-band: silently drops the warning past the cap so the
 * caller has a constant-time append regardless of how many checks fail.
 * The runner reports total drops via a synthetic "...truncated" entry.
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

    /* Governor must be `performance` to bound frequency drift. */
    if (strcmp(env->governor, "performance") != 0)
    {
        chaos_bench_warn(warnings, count,
                         "governor",
                         "governor=%s (need performance)",
                         env->governor[0] != '\0' ? env->governor : "<absent>");
    }

    /* CPU isolation list must be non-empty. */
    if (env->isolated_cpus[0] == '\0')
    {
        chaos_bench_warn(warnings, count,
                         "isolcpus",
                         "isolated_cpus=<empty> (need isolcpus= boot param)",
                         NULL);
    }

    /* Container ⇒ host owns scheduler / governor / IRQs. */
    if (env->container_marker)
    {
        chaos_bench_warn(warnings, count,
                         "container",
                         "running in container (host policies apply)",
                         NULL);
    }

    /* SMT sibling co-tenancy steals execution units. */
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
