/**
 * @file chaos_sleep.h
 * @brief The sleep every library uses to inject LATENCY.
 *
 * @details
 * An injected delay is the library's own business and must not be visible to,
 * or changed by, any other preloaded library. The exported `usleep` and
 * `nanosleep` are interposed by libchaos-time, and a `dlsym(RTLD_NEXT, ...)`
 * pointer reaches libchaos-time's wrapper whenever it comes later in
 * `LD_PRELOAD`. Sleeping through either let a time rule end another library's
 * delay at once (`usleep:ERRNO:EINTR`) or lengthen it (`usleep:LATENCY`). The
 * delay therefore issues the `clock_nanosleep` system call directly, the same way
 * the fd cache maps its table with a raw `mmap`.
 *
 * The sleep is measured on CLOCK_MONOTONIC, is restarted with the remaining time
 * when a signal interrupts it, so the delay is always the configured length, and
 * leaves errno as it was.
 */

#ifndef CHAOS_SLEEP_H
#define CHAOS_SLEEP_H

#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @brief One relative sleep on CLOCK_MONOTONIC: -1 with errno set on failure.
 *
 * @details Unit tests define this before including the header to observe the
 * requests instead of sleeping.
 */
#ifndef CHAOS_SLEEP_SYSCALL
#ifdef __linux__
#define CHAOS_SLEEP_SYSCALL(request, remaining)                                                    \
    syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, (request), (remaining))
#else
#define CHAOS_SLEEP_SYSCALL(request, remaining) nanosleep((request), (remaining))
#endif
#endif

/**
 * @brief Sleeps for @p milliseconds without passing through any interposed symbol.
 *
 * @param milliseconds  Delay; zero returns at once.
 */
static inline void chaos_sleep_ms(uint64_t milliseconds)
{
    const int saved_errno = errno;
    struct timespec request;

    if (milliseconds == 0U)
    {
        return;
    }
    request.tv_sec = (time_t)(milliseconds / 1000U);
    request.tv_nsec = (long)((milliseconds % 1000U) * 1000000U);
    while (CHAOS_SLEEP_SYSCALL(&request, &request) != 0 && errno == EINTR)
    {
    }
    errno = saved_errno;
}

#endif
