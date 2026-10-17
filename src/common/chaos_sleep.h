/**
 * @file chaos_sleep.h
 * @brief The delay primitive behind every LATENCY effect, immune to other preloaded libraries.
 *
 * @details
 * An injected delay belongs to the library that injects it; no other library may observe,
 * shorten or lengthen it. libchaos-time interposes the exported `usleep` and `nanosleep`,
 * and a `dlsym(RTLD_NEXT, ...)` pointer resolves to libchaos-time's wrapper whenever that
 * library comes later in `LD_PRELOAD`. Sleeping through either would let a time rule end
 * another library's delay at once (`usleep:ERRNO:EINTR`) or stretch it
 * (`usleep:LATENCY`). On Linux the delay is therefore the `clock_nanosleep` system call
 * issued through `syscall(2)`, the same reasoning that makes the fd cache map its table
 * with a raw `mmap`.
 *
 * Guarantees (Linux):
 * - The delay is relative and measured on CLOCK_MONOTONIC, so wall-clock steps and
 *   libchaos-time OFFSET/REGRESS rules do not affect it.
 * - EINTR restarts the sleep with the remaining time the kernel wrote back, so a signal
 *   neither ends nor extends the delay. Signal handlers still run during it.
 * - errno is saved and restored: the wrapper that injects the delay reports the real
 *   function's errno, not the sleep's.
 * - Any other failure (none is expected for a valid request) ends the delay early and
 *   silently.
 *
 * The call blocks only the calling thread and takes no lock, so it is safe from any
 * thread. On a non-Linux host the fallback is libc `nanosleep`, which is interposable;
 * it only keeps the header compilable there.
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
 * @brief One relative CLOCK_MONOTONIC sleep: 0 when it ran to the end, -1 with errno set
 *        otherwise, the unslept time stored in @p remaining.
 *
 * @details Test seam: a unit test defines this macro before including the header to
 * record the requests instead of sleeping.
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
 * @brief Blocks the calling thread for @p milliseconds without calling an interposable
 *        symbol (Linux).
 *
 * @param milliseconds  Delay in ms; 0 returns at once without a system call.
 *
 * errno on return equals errno on entry.
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
    /* request doubles as the remaining-time output, so each retry sleeps only what the
     * signal left; a relative sleep restarted with the full request would drift. */
    while (CHAOS_SLEEP_SYSCALL(&request, &request) != 0 && errno == EINTR)
    {
    }
    errno = saved_errno;
}

#endif
