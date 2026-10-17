/**
 * @file chaos_bench_perf.c
 * @brief `perf_event_open(2)` implementation of chaos_bench_perf.h; stubs on non-Linux.
 *
 * @details
 * Opens the counter panel, brackets the measurement loop with reset/enable and
 * disable/read, and records a readable reason when the kernel refuses. Inside containers
 * the usual refusal is `EACCES`/`EPERM` from `perf_event_paranoid` or the seccomp profile;
 * the reason string carries `strerror` verbatim so the operator can grant access or accept
 * the missing counters.
 *
 * **Group leader.**
 * Hardware events are opened with `group_fd` set to the `cycles` fd. The kernel schedules a
 * group onto the PMU all-or-nothing, so every member counts the same interval and none is
 * multiplexed and scaled. The price: the group must fit the PMU's simultaneous counters
 * (typically 4-8 general-purpose counters plus fixed ones). If it does not fit, the members
 * that overflow may fail to open (and report 0) or the group may not be scheduled at all;
 * no `read_format` time fields are requested, so the latter is not detectable from the
 * counts.
 *
 * Software events are opened standalone: hardware and software events cannot be grouped
 * under one leader on every PMU, and software events never compete for PMU counters.
 *
 * **Scope.**
 *  - No retry on transient errors such as ENOSPC; a failed event stays unused.
 *  - `pid = 0`, `cpu = -1`: the calling thread on any CPU. Threads the benchmark creates are
 *    not counted (`inherit` is 0).
 *  - `exclude_kernel = 1`, `exclude_hv = 1`: user-space work of the wrapper and the
 *    benchmark only; syscall time inside the kernel is not counted.
 */

#include "chaos_bench_perf.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

const char *const chaos_bench_pmu_counter_names[CHAOS_BENCH_PMU_COUNTER_COUNT] = {
    "cycles",
    "instructions",
    "branches",
    "branch_misses",
    "cache_references",
    "cache_misses",
    "dtlb_load_misses",
    "context_switches",
    "cpu_migrations",
    "page_faults"
};

#if defined(__linux__)

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

/**
 * @brief Event description: perf type, config word, and whether it is a software event
 *        (opened outside the hardware group).
 */
typedef struct chaos_bench_pmu_event
{
    uint32_t type;
    uint64_t config;
    int      is_software;
} chaos_bench_pmu_event_t;

/**
 * @brief Encodes a CACHE event triple as the perf 64-bit config word.
 *
 * @details `PERF_TYPE_HW_CACHE` config layout from `linux/perf_event.h`: cache id in bits
 * 0-7, operation in bits 8-15, result in bits 16-23.
 */
#define CHAOS_BENCH_CACHE_CFG(cache, op, res) \
    (((uint64_t)(cache)) | ((uint64_t)(op) << 8) | ((uint64_t)(res) << 16))

static const chaos_bench_pmu_event_t chaos_bench_pmu_events[CHAOS_BENCH_PMU_COUNTER_COUNT] = {
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,           0 },
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS,         0 },
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS,  0 },
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES,        0 },
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES,     0 },
    { PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES,         0 },
    { PERF_TYPE_HW_CACHE,
      CHAOS_BENCH_CACHE_CFG(PERF_COUNT_HW_CACHE_DTLB,
                            PERF_COUNT_HW_CACHE_OP_READ,
                            PERF_COUNT_HW_CACHE_RESULT_MISS),  0 },
    { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES,     1 },
    { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS,       1 },
    { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS,          1 }
};

/**
 * @brief Invokes `perf_event_open(2)` through `syscall(2)`; neither glibc nor musl provides a
 *        wrapper.
 *
 * @return New fd, or -1 with errno set.
 */
static long chaos_bench_perf_event_open(
    struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags
)
{
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int chaos_bench_pmu_init(chaos_bench_pmu_t *pmu)
{
    int      group_fd  = -1;
    int      any_open  = 0;
    int      first_err = 0;
    size_t   i;

    memset(pmu, 0, sizeof(*pmu));
    for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
    {
        pmu->fds[i] = -1;
    }

    for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
    {
        struct perf_event_attr attr;
        int                    leader_fd;
        int                    fd;

        memset(&attr, 0, sizeof(attr));
        attr.type           = chaos_bench_pmu_events[i].type;
        attr.size           = sizeof(attr);
        attr.config         = chaos_bench_pmu_events[i].config;
        attr.disabled       = (i == 0) ? 1 : 0; /* leader controls group. */
        attr.exclude_kernel = 1;
        attr.exclude_hv     = 1;

        /* Software events never join the hardware group; group_fd is -1 for them and, if
         * cycles failed to open, for the hardware events too. */
        leader_fd = chaos_bench_pmu_events[i].is_software ? -1 : group_fd;

        fd = (int)chaos_bench_perf_event_open(&attr, /*pid=*/0, /*cpu=*/-1,
                                              leader_fd, /*flags=*/0);
        if (fd < 0)
        {
            if (first_err == 0)
            {
                first_err = errno;
            }
            continue;
        }

        pmu->fds[i] = fd;
        if (i == 0)
        {
            group_fd = fd;
        }
        any_open = 1;
    }

    if (!any_open)
    {
        snprintf(pmu->reason, sizeof(pmu->reason),
                 "perf_event_open failed: %s",
                 first_err != 0 ? strerror(first_err) : "no counter opened");
        pmu->available = 0;
        return -1;
    }

    pmu->available = 1;
    return 0;
}

void chaos_bench_pmu_start(chaos_bench_pmu_t *pmu)
{
    size_t i;

    if (!pmu->available) return;
    for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
    {
        if (pmu->fds[i] < 0) continue;
        (void)ioctl(pmu->fds[i], PERF_EVENT_IOC_RESET, 0);
    }
    /* Enabling the leader with PERF_IOC_FLAG_GROUP starts the whole hardware group.
     * Software events were created enabled (disabled = 0) and need no ioctl. */
    if (pmu->fds[0] >= 0)
    {
        (void)ioctl(pmu->fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    }
}

void chaos_bench_pmu_stop(chaos_bench_pmu_t *pmu)
{
    size_t i;

    if (!pmu->available) return;
    if (pmu->fds[0] >= 0)
    {
        (void)ioctl(pmu->fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    }
    for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
    {
        uint64_t v = 0;
        if (pmu->fds[i] < 0) continue;
        if (read(pmu->fds[i], &v, sizeof(v)) == (ssize_t)sizeof(v))
        {
            pmu->total[i] = v;
        }
    }
}

void chaos_bench_pmu_close(chaos_bench_pmu_t *pmu)
{
    size_t i;
    for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
    {
        if (pmu->fds[i] >= 0)
        {
            (void)close(pmu->fds[i]);
            pmu->fds[i] = -1;
        }
    }
}

#else /* !__linux__ */

int chaos_bench_pmu_init(chaos_bench_pmu_t *pmu)
{
    memset(pmu, 0, sizeof(*pmu));
    snprintf(pmu->reason, sizeof(pmu->reason),
             "perf_event_open: not Linux");
    pmu->available = 0;
    return -1;
}

void chaos_bench_pmu_start(chaos_bench_pmu_t *pmu) { (void)pmu; }
void chaos_bench_pmu_stop (chaos_bench_pmu_t *pmu) { (void)pmu; }
void chaos_bench_pmu_close(chaos_bench_pmu_t *pmu) { (void)pmu; }

#endif /* __linux__ */
