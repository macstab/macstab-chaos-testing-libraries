/**
 * @file chaos_bench_internal.h
 * @brief Private types and helpers shared across harness translation units.
 *
 * @details
 * This header is included only by `harness/\*.c` files; it is not part of
 * the public API and benchmark kernels must not include it.  Anything
 * declared here may change without notice.
 *
 * The split exists because the harness's runtime configuration
 * (parsed argv, calibrated timer, captured environment) crosses
 * several translation units (`chaos_bench_runner.c`, `chaos_bench_stats.c`,
 * `chaos_bench_json.c`) but should not leak through the kernel-facing
 * `chaos_bench.h`.
 */

#ifndef CHAOS_BENCH_INTERNAL_H
#define CHAOS_BENCH_INTERNAL_H

#include "chaos_bench.h"
#include "chaos_bench_perf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/**
 * @brief Hard upper bound on benchmarks per binary; abort registration
 *        beyond this to keep the runner's static buffers tractable.
 *
 * @details A benchmark binary that exceeds this should be split per
 * subsystem.  Stage 1 binaries register on the order of 5-10 benchmarks.
 */
#define CHAOS_BENCH_MAX_REGISTERED 256U

/**
 * @brief Hard upper bound on samples per measurement run.
 *
 * @details At 8 bytes/sample, this caps the sample buffer at 8 MiB —
 * comfortably below typical container memory limits and small enough
 * that quicksort over the array stays in L2.
 */
#define CHAOS_BENCH_MAX_SAMPLES 1048576U

/**
 * @brief Maximum length of an environment-capture string field.
 *
 * @details Bounds buffers used to read `/proc/cpuinfo`, `/proc/version`,
 * and similar paths.  Truncation past this limit is logged in the JSON
 * envelope as `truncated: true`.
 */
#define CHAOS_BENCH_ENV_FIELD_MAX 4096U

/**
 * @brief Maximum number of CPU flags collected from `/proc/cpuinfo`.
 */
#define CHAOS_BENCH_MAX_CPU_FLAGS 256U

/**
 * @brief Computed isolation status, attached to JSON envelope.
 *
 * @details See `chaos_bench_isolation.c` for the precondition matrix.
 */
typedef enum chaos_bench_exec_mode
{
    CHAOS_BENCH_EXEC_OFFICIAL = 0, /**< All preconditions satisfied. */
    CHAOS_BENCH_EXEC_ADVISORY      /**< At least one precondition failed. */
} chaos_bench_exec_mode_t;

/**
 * @brief One precondition warning collected during isolation check.
 *
 * @details Empty when isolation is `OFFICIAL`.  In `ADVISORY` mode each
 * failed check records its identifier and a human-readable detail
 * (e.g. `"governor=schedutil"`).
 */
typedef struct chaos_bench_warning
{
    const char *check;            /**< Stable identifier, e.g. "governor". */
    char        detail[256];      /**< Human-readable failure description. */
} chaos_bench_warning_t;

/**
 * @brief Maximum advisory warnings recorded; surplus is dropped with a
 *        single `"...truncated"` sentinel.
 */
#define CHAOS_BENCH_MAX_WARNINGS 32U

/**
 * @brief Captured host/build environment, populated once at startup.
 *
 * @details All fields are owned by this struct and are NUL-terminated.
 * Strings that did not fit into their buffer are truncated and the
 * relevant `*_truncated` flag is set.  The struct is value-copied into
 * the JSON writer; no pointer escapes.
 */
typedef struct chaos_bench_env
{
    char     kernel_release[CHAOS_BENCH_ENV_FIELD_MAX];      /**< /proc/sys/kernel/osrelease. */
    char     kernel_version[CHAOS_BENCH_ENV_FIELD_MAX];      /**< /proc/version. */
    char     cpu_model[CHAOS_BENCH_ENV_FIELD_MAX];           /**< model name from /proc/cpuinfo. */
    char     cpu_flags_blob[CHAOS_BENCH_ENV_FIELD_MAX];      /**< raw flags line. */
    char     governor[64];                                   /**< cpu0 cpufreq governor. */
    char     isolated_cpus[256];                             /**< /sys/.../isolated. */
    char     thp_enabled[64];                                /**< THP setting. */
    char     libc_id[128];                                   /**< glibc/musl identifier if detectable. */
    char     git_sha[64];                                    /**< CHAOS_BENCH_GIT_SHA build define. */
    char     build_cflags[CHAOS_BENCH_ENV_FIELD_MAX];        /**< CHAOS_BENCH_CFLAGS build define. */
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
 * @brief Populates @p out_env with a best-effort snapshot of the host
 *        environment.  Never fails; missing fields remain empty strings.
 *
 * @param[out] out_env  Caller-owned target.  Must not be NULL.
 */
void chaos_bench_env_capture(chaos_bench_env_t *out_env);

/**
 * @brief Inspects the host and computes the execution mode.
 *
 * @param[in]  env       Captured environment (used for several checks).
 * @param[out] warnings  Receives one entry per failed precondition.
 *                       Pass an array of length @ref CHAOS_BENCH_MAX_WARNINGS.
 * @param[out] count     Number of warnings actually written.  Set to 0 if
 *                       no preconditions failed.
 *
 * @return CHAOS_BENCH_EXEC_OFFICIAL when @p count is 0; otherwise
 *         CHAOS_BENCH_EXEC_ADVISORY.
 */
chaos_bench_exec_mode_t chaos_bench_isolation_check(
    const chaos_bench_env_t *env,
    chaos_bench_warning_t   *warnings,
    size_t                  *count
);

/**
 * @brief Aggregated statistics over a sample array.
 *
 * @details All time-valued fields are nanoseconds.  `samples_after_trim`
 * counts the values used to compute statistics after outlier trimming
 * (Stage 1: no trimming; this field equals `samples`).  Percentiles use
 * the type-7 (R-7) interpolation method to match NumPy's default.
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
    double   p99_ns;
    double   p999_ns;
    double   p9999_ns;
} chaos_bench_stats_t;

/**
 * @brief Computes percentile statistics over an array of nanosecond samples.
 *
 * @details Sorts the array in place (so @p samples must be caller-owned
 * and writable) and computes the fields of @p out.  No allocation; uses
 * `qsort(3)` from libc.
 *
 * @param[in,out] samples       Array of nanosecond timings; sorted on return.
 * @param[in]     sample_count  Length of @p samples; must be > 0.
 * @param[out]    out           Caller-owned target.  Must not be NULL.
 */
void chaos_bench_stats_compute(
    double *samples, size_t sample_count, chaos_bench_stats_t *out
);

/**
 * @brief Identifies the timer source used by the harness.
 */
typedef enum chaos_bench_timer_source
{
    CHAOS_BENCH_TIMER_RDTSCP = 0,    /**< x86_64 with constant_tsc + nonstop_tsc. */
    CHAOS_BENCH_TIMER_CNTVCT,        /**< aarch64 generic timer. */
    CHAOS_BENCH_TIMER_CLOCK_MONOTONIC /**< Fallback: vDSO clock_gettime. */
} chaos_bench_timer_source_t;

/**
 * @brief Calibrated timer state, populated once per process at startup.
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
 * @brief Initialises @p timer by selecting and calibrating the best
 *        available source on the current CPU.
 *
 * @param[in]  env    Captured environment (used to gate rdtscp on the
 *                    `constant_tsc`/`nonstop_tsc` flags).
 * @param[out] timer  Caller-owned target; populated on return.
 */
void chaos_bench_timer_init(
    const chaos_bench_env_t *env, chaos_bench_timer_t *timer
);

/**
 * @brief Reads the calibrated timer's current value, in cycles.
 *
 * @details The function performs a *serializing* read so the compiler
 * and the CPU pipeline cannot reorder it past adjacent code.  Inlined
 * via the header definition to avoid call overhead in the timed loop.
 */
uint64_t chaos_bench_timer_read(const chaos_bench_timer_t *timer);

/**
 * @brief Converts a cycle delta to nanoseconds using the calibrated rate.
 */
static inline double chaos_bench_timer_cycles_to_ns(
    const chaos_bench_timer_t *timer, uint64_t cycles
)
{
    return (double)cycles * timer->ns_per_cycle;
}

/**
 * @brief Internal: walks the registered descriptor list looking for @p name.
 *
 * @return The descriptor or NULL.
 */
chaos_bench_descriptor_t *chaos_bench_registry_find(const char *name);

/**
 * @brief Internal: emits a JSON-encoded result envelope to @p out.
 *
 * @details Self-contained: writes the full envelope as a single object
 * with provenance, environment, mode, scenario, statistics, and timer
 * metadata.  No allocation in the timed path; the caller's buffers are
 * expected to be already populated.
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
