/**
 * @file chaos_bench_perf.c
 * @brief Linux `perf_event_open(2)` wrapper; stub on non-Linux.
 *
 * @details
 * See chaos_bench_perf.h for the contract.  This file's job is to (a)
 * open the counter panel, (b) start / stop / read counters around the
 * measurement window, and (c) emit a coherent failure reason when the
 * kernel refuses.  The most common refusal mode in containers is
 * `EACCES` from `perf_event_paranoid >= 3`; we surface this verbatim so
 * the operator can fix it (or accept the absence of PMU data).
 *
 * **Group-leader pattern.**
 * Hardware counters are opened against the `cycles` leader (group_fd =
 * leader's fd, read_format inherited).  This guarantees they are
 * scheduled atomically by the kernel — every counter in the group reads
 * the same interval.  Without grouping, the kernel may multiplex on a
 * CPU that has fewer counters than we requested, scaling the values; we
 * lose precision.  Grouping caps us at the number of counters the CPU's
 * PMU supports simultaneously (typically 4–8), which is enough for our
 * panel of 7 hardware counters.
 *
 * Software counters (`context_switches`, `cpu_migrations`,
 * `page_faults`) are not grouped: the kernel does not allow mixing
 * hardware and software events under one leader on every
 * microarchitecture.  They are opened independently and read individually.
 *
 * **What this file does NOT do.**
 *  - It does not retry on transient ENOSPC (PMU exhaustion).  A failure
 *    here is reported once and the counter remains unused.
 *  - It does not support per-CPU sampling — we use `pid=0` (calling
 *    process) and `cpu=-1` (any CPU), which gives task-scoped counts.
 *    Per-CPU sampling is a Stage 4 capability for cache-line studies.
 *  - It does not enable kernel-mode counting (`exclude_kernel = 1`).
 *    Pure user-space counts are what we want for chaos library overhead.
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
 * @brief Per-counter configuration table.
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
 * @details See `linux/perf_event.h`: the CACHE event type packs the
 * (cache id, op id, result id) tuple into a single 64-bit config field.
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
 * @brief Wrapper around `perf_event_open(2)` syscall.
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

        /* Software counters are opened standalone (no group leader). */
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
    /* Enable the hardware-event leader (i=0); software events are armed
     * implicitly when their disabled bit defaults to 0. */
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
