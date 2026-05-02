/**
 * @file chaos_bench_perf.h
 * @brief Linux PMU sampling via `perf_event_open(2)`.
 *
 * @details
 * Optional Stage 2 capability: when the kernel exposes the perf
 * subsystem and the calling process has the necessary capability
 * (`CAP_PERFMON` on Linux ≥ 5.8 with `kernel.perf_event_paranoid <= 2`,
 * or `CAP_SYS_ADMIN` on older kernels), the harness samples a fixed
 * panel of hardware and software counters across the measurement
 * window and emits the deltas in the JSON envelope.
 *
 * **Counter panel.**
 *  - `cycles`              — `PERF_COUNT_HW_CPU_CYCLES`
 *  - `instructions`        — `PERF_COUNT_HW_INSTRUCTIONS`
 *  - `branches`            — `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`
 *  - `branch_misses`       — `PERF_COUNT_HW_BRANCH_MISSES`
 *  - `cache_references`    — `PERF_COUNT_HW_CACHE_REFERENCES`
 *  - `cache_misses`        — `PERF_COUNT_HW_CACHE_MISSES`
 *  - `dtlb_load_misses`    — `PERF_COUNT_HW_CACHE_DTLB|READ|MISS`
 *  - `context_switches`    — `PERF_COUNT_SW_CONTEXT_SWITCHES`
 *  - `cpu_migrations`      — `PERF_COUNT_SW_CPU_MIGRATIONS`
 *  - `page_faults`         — `PERF_COUNT_SW_PAGE_FAULTS`
 *
 * The hardware events are opened with `disabled=1` and grouped under a
 * single leader so they sample atomically (read across the same
 * interval).  The software events are opened individually because the
 * kernel does not group hardware and software events into one
 * leader-set on every microarchitecture.
 *
 * **Failure modes.**
 *  - `ENOSYS`     — kernel built without CONFIG_PERF_EVENTS.
 *  - `EACCES`     — `perf_event_paranoid` too restrictive, or running
 *                   without `CAP_PERFMON`.
 *  - `EOPNOTSUPP` — counter not implemented on this microarchitecture
 *                   (e.g. some virtual CPUs lack hardware events).
 *  - `ENODEV`     — no PMU on this CPU.
 *
 * Any of these results in `chaos_bench_pmu_init` returning -1 with the
 * reason captured in the struct.  The runner emits a `pmu` section in
 * JSON with `available: false` and the reason; downstream consumers
 * treat absent counter data as missing-but-explained, not as a bug.
 *
 * **Non-Linux platforms.**
 * On macOS, FreeBSD, etc. this module compiles to a stub: every entry
 * point returns "unavailable: not_linux".  Benchmark binaries built
 * for those platforms still link cleanly; the JSON envelope just lacks
 * counter values.  The harness is itself portable to non-Linux for
 * development convenience even though the production target is Linux.
 *
 * **Thread-safety.** Same as the harness: not thread-safe.  PMU init is
 * called once before the measurement loop, read once inside it, closed
 * once after.  Concurrent benchmarks are out of scope (Stage 1+).
 */

#ifndef CHAOS_BENCH_PERF_H
#define CHAOS_BENCH_PERF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Counter panel size.  Keep in sync with `chaos_bench_perf.c`.
 */
#define CHAOS_BENCH_PMU_COUNTER_COUNT 10U

/**
 * @brief Per-counter identifiers, used as JSON field names.
 */
extern const char *const chaos_bench_pmu_counter_names[CHAOS_BENCH_PMU_COUNTER_COUNT];

/**
 * @brief Opaque PMU handle.  Allocated by the caller on the stack.
 *
 * @details The struct exposes one bool — `available` — that the runner
 * checks before reading or emitting counter values.  Internal fields
 * are private to the implementation.
 */
typedef struct chaos_bench_pmu
{
    int     available;                                       /**< 1 if init succeeded. */
    char    reason[256];                                     /**< Human-readable failure hint. */
    int     fds[CHAOS_BENCH_PMU_COUNTER_COUNT];              /**< perf fds; -1 if unused. */
    uint64_t baseline[CHAOS_BENCH_PMU_COUNTER_COUNT];        /**< Snapshot before measurement. */
    uint64_t total[CHAOS_BENCH_PMU_COUNTER_COUNT];           /**< Final counter delta. */
} chaos_bench_pmu_t;

/**
 * @brief Initialises @p pmu by opening the counter panel.
 *
 * @details Best-effort: a counter that fails to open is recorded as
 * unavailable but does not abort the others.  If at least one hardware
 * counter opens successfully, @c available is set to 1 and counters are
 * armed (DISABLE on; reset).  Otherwise @c available is 0 and @c reason
 * carries the diagnostic.
 *
 * Caller must invoke `chaos_bench_pmu_close` on the same struct
 * regardless of return value.
 *
 * @param[out] pmu  Caller-owned target.  Must not be NULL.
 *
 * @return 0 if at least one counter opened; -1 if all opens failed.
 */
int chaos_bench_pmu_init(chaos_bench_pmu_t *pmu);

/**
 * @brief Begins counting on every armed counter.
 *
 * @details Equivalent to `ioctl(fd, PERF_EVENT_IOC_RESET, 0)` followed
 * by `PERF_EVENT_IOC_ENABLE` on each open fd.  Failure on individual
 * fds is silently tolerated; the corresponding counter will read 0.
 */
void chaos_bench_pmu_start(chaos_bench_pmu_t *pmu);

/**
 * @brief Stops counting and reads accumulated values into @c total.
 *
 * @details Calls `PERF_EVENT_IOC_DISABLE` then `read(2)` on each open
 * fd.  Sums are stored in @c pmu->total in counter-name order matching
 * @c chaos_bench_pmu_counter_names.
 */
void chaos_bench_pmu_stop(chaos_bench_pmu_t *pmu);

/**
 * @brief Closes all open perf fds.  Idempotent.
 */
void chaos_bench_pmu_close(chaos_bench_pmu_t *pmu);

#ifdef __cplusplus
}
#endif

#endif /* CHAOS_BENCH_PERF_H */
