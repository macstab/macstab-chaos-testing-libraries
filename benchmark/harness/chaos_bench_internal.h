/**
 * @file chaos_bench_internal.h
 * @brief Types and functions shared between harness translation units only.
 *
 * @details
 * Included by `harness/\*.c` only. Benchmark kernels include `chaos_bench.h` and must not
 * include this header; everything here may change without notice.
 *
 * The split keeps the runner's state (parsed options, calibrated timer, captured environment,
 * statistics) out of the kernel-facing API while letting `chaos_bench_runner.c`,
 * `chaos_bench_env.c`, `chaos_bench_isolation.c`, `chaos_bench_timer.c`,
 * `chaos_bench_stats.c` and `chaos_bench_json.c` share it.
 *
 * **Thread-safety.** None of these functions lock; the runner calls them from the main thread.
 */

#ifndef CHAOS_BENCH_INTERNAL_H
#define CHAOS_BENCH_INTERNAL_H

#include "chaos_bench.h"
#include "chaos_bench_perf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @brief Maximum descriptors per binary; `chaos_bench_register` aborts beyond it.
 *
 * @details The cap turns a runaway registration (e.g. a macro expanded in a loop-generated
 * header) into an immediate abort instead of an unbounded list. The largest kernel file
 * registers 36 benchmarks.
 */
#define CHAOS_BENCH_MAX_REGISTERED 256U

/**
 * @brief Maximum `--iters` value, i.e. samples per run.
 *
 * @details One `double` per sample caps the sample buffer at 8 MiB, which fits typical
 * container memory limits. `--iters` outside [1, 1048576] is rejected with exit code 2.
 */
#define CHAOS_BENCH_MAX_SAMPLES 1048576U

/**
 * @brief Capacity, in bytes including the NUL, of the large environment string fields.
 *
 * @details Sizes the buffers for `/proc/sys/kernel/osrelease`, `/proc/version`, the cpuinfo
 * model and flags lines, the build CFLAGS and LD_PRELOAD. `/proc/cpuinfo` itself is read into
 * a 4x larger (16 KiB) stack buffer. Longer values are truncated; the `*_truncated` flags in
 * @ref chaos_bench_env_t record it, but the JSON envelope does not emit those flags.
 */
#define CHAOS_BENCH_ENV_FIELD_MAX 4096U

/**
 * @brief Maximum number of CPU flags collected from `/proc/cpuinfo`.
 *
 * @details Currently unused: the flags line is stored as one string in
 * `chaos_bench_env_t::cpu_flags_blob`.
 */
#define CHAOS_BENCH_MAX_CPU_FLAGS 256U

/**
 * @brief Result of the host isolation check, emitted as `execution.mode`.
 *
 * @details The checks are listed in chaos_bench_isolation.c.
 */
typedef enum chaos_bench_exec_mode
{
    CHAOS_BENCH_EXEC_OFFICIAL = 0, /**< All preconditions satisfied. */
    CHAOS_BENCH_EXEC_ADVISORY      /**< At least one precondition failed. */
} chaos_bench_exec_mode_t;

/**
 * @brief One failed isolation check, emitted in `execution.warnings`.
 *
 * @details `check` points to a string literal with a stable identifier (`governor`,
 * `isolcpus`, `container`, `smt`, `constant_tsc`, `nonstop_tsc`) that consumers can match
 * on; `detail` is free text such as `"governor=schedutil (need performance)"`.
 */
typedef struct chaos_bench_warning
{
    const char *check;            /**< Stable identifier, e.g. "governor". */
    char        detail[256];      /**< Human-readable failure description. */
} chaos_bench_warning_t;

/**
 * @brief Capacity of the warning array; further warnings are dropped silently.
 *
 * @details The isolation check can raise at most 6 warnings, so the cap is never reached
 * today. No truncation marker is emitted.
 */
#define CHAOS_BENCH_MAX_WARNINGS 32U

/**
 * @brief Host and build provenance, captured once at startup.
 *
 * @details Every string is NUL-terminated and owned by the struct; a missing source leaves
 * an empty string. A value longer than its buffer is truncated and, for the kernel release,
 * the cpuinfo read and LD_PRELOAD, the matching `*_truncated` flag is set. The JSON writer
 * reads the struct through a const pointer and emits every field except `*_truncated`.
 */
typedef struct chaos_bench_env
{
    char     kernel_release[CHAOS_BENCH_ENV_FIELD_MAX];      /**< /proc/sys/kernel/osrelease. */
    char     kernel_version[CHAOS_BENCH_ENV_FIELD_MAX];      /**< /proc/version. */
    char     cpu_model[CHAOS_BENCH_ENV_FIELD_MAX];           /**< cpuinfo model. */
    char     cpu_flags_blob[CHAOS_BENCH_ENV_FIELD_MAX];      /**< raw flags line. */
    char     governor[64];                                   /**< cpu0 cpufreq governor. */
    char     isolated_cpus[256];                             /**< /sys/.../isolated. */
    char     thp_enabled[64];                                /**< THP setting. */
    char     libc_id[128];                                   /**< glibc/musl/unknown. */
    char     git_sha[64];                                    /**< CHAOS_BENCH_GIT_SHA. */
    char     build_cflags[CHAOS_BENCH_ENV_FIELD_MAX];        /**< CHAOS_BENCH_CFLAGS. */
    char     ld_preload[CHAOS_BENCH_ENV_FIELD_MAX];          /**< current LD_PRELOAD env var. */
    int      smt_active;                                     /**< 1 if HT/SMT is on. */
    int      container_marker;                               /**< 1 if /.dockerenv exists. */
    int      has_constant_tsc;                               /**< 1 if cpu flag set. */
    int      has_nonstop_tsc;                                /**< 1 if cpu flag set. */
    int      kernel_truncated;
    int      cpu_flags_truncated;
    int      ld_preload_truncated;
} chaos_bench_env_t;

/**
 * @brief Fills @p out_env from `/proc`, `/sys`, the process environment and build defines.
 *
 * @details Never fails and never aborts: an unreadable source leaves its field empty (or 0).
 * Reads files with stdio, so it must run before the timed loop.
 *
 * @param[out] out_env  Caller-owned; zeroed, then filled. Must not be NULL.
 */
void chaos_bench_env_capture(chaos_bench_env_t *out_env);

/**
 * @brief Evaluates the isolation checks against @p env.
 *
 * @param[in]  env       Captured environment; all checks read from it, none touch the host.
 * @param[out] warnings  Array of at least @ref CHAOS_BENCH_MAX_WARNINGS entries; receives one
 *                       entry per failed check.
 * @param[out] count     Number of entries written; 0 when every check passed.
 *
 * @return `CHAOS_BENCH_EXEC_OFFICIAL` when @p count is 0, otherwise
 *         `CHAOS_BENCH_EXEC_ADVISORY`.
 */
chaos_bench_exec_mode_t chaos_bench_isolation_check(
    const chaos_bench_env_t *env,
    chaos_bench_warning_t   *warnings,
    size_t                  *count
);

/**
 * @brief Summary statistics of one run, all time values in nanoseconds per call.
 *
 * @details No outlier trimming is done, so `samples_after_trim` always equals `samples`; the
 * field exists so the envelope schema does not change if trimming is added. `median_ns` and
 * `p50_ns` hold the same value. Percentiles use type-7 (R-7) linear interpolation, NumPy's
 * default, so they match `numpy.percentile` on the same samples.
 */
typedef struct chaos_bench_stats
{
    size_t   samples;
    size_t   samples_after_trim;
    double   min_ns;
    double   max_ns;
    double   median_ns;
    double   mean_ns;
    double   stdev_ns;
    double   p50_ns;
    double   p90_ns;
    double   p95_ns;
    double   p99_ns;
    double   p999_ns;
    double   p9999_ns;
} chaos_bench_stats_t;

/**
 * @brief Computes @ref chaos_bench_stats_t over @p samples.
 *
 * @details Sorts @p samples in place with `qsort(3)`; allocates nothing. @p out is zeroed
 * first, so `sample_count == 0` yields an all-zero result instead of a crash.
 *
 * @param[in,out] samples       Per-call nanosecond values; ascending on return.
 * @param[in]     sample_count  Number of elements in @p samples.
 * @param[out]    out           Caller-owned result. Must not be NULL.
 */
void chaos_bench_stats_compute(
    double *samples, size_t sample_count, chaos_bench_stats_t *out
);

/**
 * @brief Counter that @ref chaos_bench_timer_read samples, emitted as `timer.source`.
 */
typedef enum chaos_bench_timer_source
{
    CHAOS_BENCH_TIMER_RDTSCP = 0,    /**< x86_64 with constant_tsc + nonstop_tsc. */
    CHAOS_BENCH_TIMER_CNTVCT,        /**< aarch64 generic timer. */
    CHAOS_BENCH_TIMER_CLOCK_MONOTONIC /**< Fallback: clock_gettime(CLOCK_MONOTONIC_RAW). */
} chaos_bench_timer_source_t;

/**
 * @brief Selected and calibrated timer, set up once per process.
 *
 * @details For the `CLOCK_MONOTONIC_RAW` fallback a "cycle" is one nanosecond (`hz` = 1e9,
 * `ns_per_cycle` = 1.0) and no calibration runs, although `calibration_window_ns` still
 * reports the nominal 100 ms.
 */
typedef struct chaos_bench_timer
{
    chaos_bench_timer_source_t  source;
    double                      hz;                    /**< Cycles/sec, calibrated. */
    double                      ns_per_cycle;          /**< 1e9 / hz. */
    uint64_t                    calibration_window_ns; /**< Wall-clock window used. */
    uint64_t                    overhead_ns;           /**< Self-time of one read pair. */
} chaos_bench_timer_t;

/**
 * @brief Selects the timer source for this CPU and calibrates it.
 *
 * @details Blocks for about 110 ms on rdtscp/cntvct (100 ms calibration plus a 10 ms
 * cross-check) and aborts if the two calibrations disagree by more than 1 %. Aborts if
 * `CLOCK_MONOTONIC_RAW` is unavailable. See chaos_bench_timer.c.
 *
 * @param[in]  env    Captured environment; on x86, rdtscp is chosen only if both
 *                    `constant_tsc` and `nonstop_tsc` are set.
 * @param[out] timer  Caller-owned; fully populated on return.
 */
void chaos_bench_timer_init(
    const chaos_bench_env_t *env, chaos_bench_timer_t *timer
);

/**
 * @brief Reads the selected counter, in timer cycles (ns for the fallback).
 *
 * @details The read is serializing in hardware (`rdtscp`+`lfence`, `isb`-bracketed `mrs`) and
 * carries a compiler memory clobber, so neither the CPU nor the compiler moves work across
 * it. It is an out-of-line function in chaos_bench_timer.c that switches on
 * `timer->source`; the call and branch are part of the measured `overhead_ns`.
 */
uint64_t chaos_bench_timer_read(const chaos_bench_timer_t *timer);

/**
 * @brief Converts a cycle delta to nanoseconds with the calibrated factor.
 */
static inline double chaos_bench_timer_cycles_to_ns(
    const chaos_bench_timer_t *timer, uint64_t cycles
)
{
    return (double)cycles * timer->ns_per_cycle;
}

/**
 * @brief Looks up a registered descriptor by exact, case-sensitive name.
 *
 * @return The descriptor, or NULL if @p name is NULL or not registered.
 */
chaos_bench_descriptor_t *chaos_bench_registry_find(const char *name);

/**
 * @brief Writes the complete result envelope for one run to @p out as one JSON object.
 *
 * @details Sections: `schema_version`, `benchmark`, `config`, `execution`, `timer`,
 * `scenario`, `stats`, `pmu`, `environment` (schema in chaos_bench_json.c). Uses stdio and
 * runs after the timed loop. Flushes @p out but does not close it. Write errors are not
 * detected.
 */
void chaos_bench_json_write_envelope(
    FILE                          *out,
    const chaos_bench_descriptor_t *desc,
    chaos_bench_mode_t              mode,
    size_t                          warmup_iters,
    size_t                          measurement_iters,
    size_t                          batch_size,
    chaos_bench_exec_mode_t         exec_mode,
    const chaos_bench_warning_t    *warnings,
    size_t                          warning_count,
    const chaos_bench_timer_t      *timer,
    const chaos_bench_env_t        *env,
    const char                     *scenario_path,
    int                             scenario_active,
    const chaos_bench_stats_t      *stats,
    const chaos_bench_pmu_t        *pmu
);

#endif /* CHAOS_BENCH_INTERNAL_H */
