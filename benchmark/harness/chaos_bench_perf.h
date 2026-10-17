/**
 * @file chaos_bench_perf.h
 * @brief Optional hardware and software performance counters around the measurement loop,
 *        via `perf_event_open(2)`.
 *
 * @details
 * When the kernel permits, the runner counts a fixed panel of events for the calling thread
 * over exactly the measurement loop (not warmup, statistics or output) and emits the totals
 * in the envelope's `pmu.counters`. Counts are whole-loop totals, not per call; divide by
 * `measurement_iters * batch_size` for per-call values.
 *
 * **Counter panel** (index order = JSON order).
 *
 * | name               | perf event                                               |
 * |--------------------|----------------------------------------------------------|
 * | `cycles`           | `PERF_COUNT_HW_CPU_CYCLES` (group leader)                |
 * | `instructions`     | `PERF_COUNT_HW_INSTRUCTIONS`                             |
 * | `branches`         | `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`                      |
 * | `branch_misses`    | `PERF_COUNT_HW_BRANCH_MISSES`                            |
 * | `cache_references` | `PERF_COUNT_HW_CACHE_REFERENCES`                         |
 * | `cache_misses`     | `PERF_COUNT_HW_CACHE_MISSES`                             |
 * | `dtlb_load_misses` | `PERF_TYPE_HW_CACHE` DTLB / OP_READ / RESULT_MISS         |
 * | `context_switches` | `PERF_COUNT_SW_CONTEXT_SWITCHES`                         |
 * | `cpu_migrations`   | `PERF_COUNT_SW_CPU_MIGRATIONS`                           |
 * | `page_faults`      | `PERF_COUNT_SW_PAGE_FAULTS`                              |
 *
 * The seven hardware events form one group led by `cycles`, so the kernel schedules them
 * together and all cover the same interval. The three software events are opened standalone.
 * All events exclude kernel and hypervisor mode, which counts the wrapper's user-space work
 * only.
 *
 * **Permissions.** User-space-only counting of the own task is allowed for unprivileged
 * processes while `kernel.perf_event_paranoid` is 2 or lower. At higher values (3 on some
 * distribution kernels) it needs `CAP_PERFMON` (Linux 5.8+) or `CAP_SYS_ADMIN`. A container's
 * seccomp profile can block the syscall independently of both.
 *
 * **Failure behaviour.** Fail-open: each event that fails to open is skipped. If none opens,
 * `chaos_bench_pmu_init` returns -1, `available` is 0 and `reason` holds
 * `"perf_event_open failed: <strerror of the first error>"`; the envelope then reports
 * `"available": false` with that reason. Typical errors:
 *  - `ENOSYS`: kernel without `CONFIG_PERF_EVENTS`, or the syscall filtered.
 *  - `EACCES`/`EPERM`: paranoid level or capabilities, or a seccomp filter.
 *  - `ENOENT`/`EOPNOTSUPP`: event not supported by this CPU or virtual CPU.
 *  - `ENODEV`: no PMU.
 * An event that failed while others opened reports 0 in the envelope, indistinguishable from
 * a true zero.
 *
 * **Non-Linux.** The module compiles to stubs: `chaos_bench_pmu_init` returns -1 with reason
 * `"perf_event_open: not Linux"` and the other entry points do nothing. This keeps the harness
 * buildable on macOS for development.
 *
 * **Thread-safety.** None. The runner initialises, starts, stops and closes the PMU once,
 * from the main thread; events count that thread only (`pid = 0`, `cpu = -1`, no inherit).
 */

#ifndef CHAOS_BENCH_PERF_H
#define CHAOS_BENCH_PERF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Number of events in the panel; `chaos_bench_pmu_counter_names` and the event table
 *        in chaos_bench_perf.c must have exactly this many entries in the same order.
 */
#define CHAOS_BENCH_PMU_COUNTER_COUNT 10U

/**
 * @brief Event names in panel order, used as keys of `pmu.counters`; part of the JSON schema.
 */
extern const char *const chaos_bench_pmu_counter_names[CHAOS_BENCH_PMU_COUNTER_COUNT];

/**
 * @brief PMU state for one run; caller-allocated (the runner uses the stack).
 *
 * @details Callers read only `available`, `reason` and `total`; `fds` and `baseline` belong
 * to the implementation. `baseline` is currently unused.
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
 * @brief Zeroes @p pmu and opens every event in the panel.
 *
 * @details An event that fails to open keeps `fds[i] == -1`; the others are unaffected. The
 * hardware group is created disabled and starts counting at @ref chaos_bench_pmu_start. The
 * software events are created enabled and count from here on, but are reset at start.
 * If `cycles` fails to open there is no group leader: the remaining hardware events open
 * standalone and enabled, are reset at start, and are not disabled at stop (their reads
 * follow immediately, so the error is a few hundred instructions).
 *
 * Call @ref chaos_bench_pmu_close on @p pmu whatever the return value.
 *
 * @param[out] pmu  Caller-owned. Must not be NULL.
 *
 * @return 0 and `available = 1` if at least one event (hardware or software) opened;
 *         -1 and `available = 0` with `reason` set otherwise.
 */
int chaos_bench_pmu_init(chaos_bench_pmu_t *pmu);

/**
 * @brief Resets every open event and enables the hardware group.
 *
 * @details Issues `PERF_EVENT_IOC_RESET` on each open fd, then `PERF_EVENT_IOC_ENABLE` with
 * `PERF_IOC_FLAG_GROUP` on the leader. ioctl errors are ignored. No-op unless `available`.
 */
void chaos_bench_pmu_start(chaos_bench_pmu_t *pmu);

/**
 * @brief Disables the hardware group and reads every open event into `total`.
 *
 * @details Issues `PERF_EVENT_IOC_DISABLE` with `PERF_IOC_FLAG_GROUP` on the leader, then
 * one 8-byte `read(2)` per open fd (default `read_format`: the raw count). `total[i]` stays
 * 0 for unopened events and for failed or short reads. Software events are read while still
 * running. No-op unless `available`.
 */
void chaos_bench_pmu_stop(chaos_bench_pmu_t *pmu);

/**
 * @brief Closes every open perf fd and marks it -1; idempotent and safe after a failed
 *        @ref chaos_bench_pmu_init.
 */
void chaos_bench_pmu_close(chaos_bench_pmu_t *pmu);

#ifdef __cplusplus
}
#endif

#endif /* CHAOS_BENCH_PERF_H */
