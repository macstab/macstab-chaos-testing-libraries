/**
 * @file test_sleep_support.h
 * @brief Test seam for chaos_sleep_ms(): records each requested sleep instead of sleeping.
 *
 * @details Every library's LATENCY effect sleeps through chaos_sleep_ms() (src/common/
 * chaos_sleep.h), which issues CHAOS_SLEEP_SYSCALL in a loop and restarts on EINTR with the
 * remaining time the kernel wrote back. This header defines CHAOS_SLEEP_SYSCALL before
 * including chaos_sleep.h, so unit tests can assert the exact timespec requested per call and
 * prove the EINTR restart loop without real signals or wall-clock delay.
 *
 * Include it before the production actions source; a later include of chaos_sleep.h is then a
 * no-op through its include guard. Call chaos_test_sleep_reset() at the start of each test.
 *
 * Limits: at most 8 sleep calls per test (asserted); state is file-static, so each including
 * translation unit has its own copy and none of it is thread-safe.
 */

#ifndef CHAOS_TEST_SLEEP_SUPPORT_H
#define CHAOS_TEST_SLEEP_SUPPORT_H

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>

/** @brief Request passed to each stubbed sleep call, in call order (capacity 8). */
static struct timespec g_test_sleep_requests[8];
/** @brief Number of sleep system calls since the last reset. */
static size_t g_test_sleep_calls = 0U;
/** @brief Upcoming calls that fail with EINTR and report 1 ms (1000000 ns) remaining. */
static int g_test_sleep_interruptions = 0;

/**
 * @brief Replacement for the clock_nanosleep/nanosleep call inside chaos_sleep_ms().
 *
 * Records `*request`, then either succeeds (returns 0) or, while g_test_sleep_interruptions
 * is positive, consumes one interruption, writes 1 ms to `*remaining`, sets errno to EINTR
 * and returns -1, which drives chaos_sleep_ms() into its restart path.
 *
 * @param request    Requested duration; must not be NULL.
 * @param remaining  Receives the unslept time on EINTR; must not be NULL.
 * @return 0 on success, -1 with errno EINTR for a simulated interruption.
 */
static inline int chaos_test_sleep_syscall(struct timespec *request, struct timespec *remaining)
{
    assert(g_test_sleep_calls < sizeof(g_test_sleep_requests) / sizeof(g_test_sleep_requests[0]));
    g_test_sleep_requests[g_test_sleep_calls++] = *request;
    if (g_test_sleep_interruptions > 0)
    {
        --g_test_sleep_interruptions;
        remaining->tv_sec = 0;
        remaining->tv_nsec = 1000000L;
        errno = EINTR;
        return -1;
    }
    return 0;
}

/** @brief Clears the recorded requests and any pending simulated interruptions. */
static inline void chaos_test_sleep_reset(void)
{
    g_test_sleep_calls = 0U;
    g_test_sleep_interruptions = 0;
}

#define CHAOS_SLEEP_SYSCALL(request, remaining) chaos_test_sleep_syscall((request), (remaining))
#include "../../src/common/chaos_sleep.h"

#endif
