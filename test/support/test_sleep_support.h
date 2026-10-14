/**
 * @file test_sleep_support.h
 * @brief Records the sleeps of chaos_sleep_ms() instead of performing them.
 *
 * Include before the production actions source. Every library's LATENCY effect
 * sleeps through chaos_sleep_ms(), whose system call is replaced here by a stub
 * that records each request and can simulate signal interruptions.
 */

#ifndef CHAOS_TEST_SLEEP_SUPPORT_H
#define CHAOS_TEST_SLEEP_SUPPORT_H

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <time.h>

/** @brief Requests passed to the sleep system call, in call order. */
static struct timespec g_test_sleep_requests[8];
/** @brief Number of sleep system calls since the last reset. */
static size_t g_test_sleep_calls = 0U;
/** @brief Number of upcoming calls that fail with EINTR, leaving 1 ms remaining. */
static int g_test_sleep_interruptions = 0;

/** @brief Stub for the clock_nanosleep system call used by chaos_sleep_ms(). */
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

/** @brief Clears the recorded sleeps. */
static inline void chaos_test_sleep_reset(void)
{
    g_test_sleep_calls = 0U;
    g_test_sleep_interruptions = 0;
}

#define CHAOS_SLEEP_SYSCALL(request, remaining) chaos_test_sleep_syscall((request), (remaining))
#include "../../src/common/chaos_sleep.h"

#endif
