/**
 * @file chaos_time_hooks.c
 * @brief LD_PRELOAD interceptor wrappers for clock_gettime(2), gettimeofday(2),
 *        time(2), timespec_get(3), nanosleep(2), clock_nanosleep(2), sleep(3)
 *        and usleep(3).
 *
 * @details
 * glibc and musl serve gettimeofday, time and timespec_get without the exported
 * clock_gettime, sleep through their internal nanosleep, and glibc's nanosleep through
 * its internal clock_nanosleep. Each entry point is therefore wrapped, and the
 * wrappers map to three operations, so a rule applies however the program reads the
 * clock or sleeps:
 *
 * | Wrapper                     | Operation     | Effects                          |
 * |-----------------------------|---------------|----------------------------------|
 * | clock_gettime               | clock_gettime | LATENCY, ERRNO, OFFSET, REGRESS  |
 * | gettimeofday, time,         | clock_gettime | same, on CLOCK_REALTIME          |
 * | timespec_get(TIME_UTC)      |               |                                  |
 * | nanosleep, clock_nanosleep, | nanosleep     | LATENCY, ERRNO                   |
 * | sleep                       |               |                                  |
 * | usleep                      | usleep        | LATENCY, ERRNO                   |
 *
 * Wrapper sequence:
 *  1. chaos_time_ensure_symbols().
 *  2. **Bypass:** guard set (library code, or a signal handler that interrupted it),
 *     or a NULL output/request pointer: call the real function unchanged, so libc
 *     produces its own EFAULT or behaviour.
 *  3. LATENCY, then ERRNO (which skips the real call), each with its own rule lookup
 *     and firing decision.
 *  4. The real call, through a call helper.
 *  5. Clock reads only, on success: OFFSET, then REGRESS.
 *
 * Every rule lookup may reload the rule file (throttled to one look per 1 ms per
 * process, see chaos_time_config.h).
 *
 * ### Call helpers
 *
 * chaos_time_call_real_* raise the guard around the real function, so nothing it
 * calls is faulted. While a pointer is NULL (a call during symbol resolution, or a
 * symbol no later object defines) each helper issues the system call libc would have
 * made, with libc's return and errno conventions.
 *
 * ### errno
 *
 * Wrappers leave errno as the real function sets it; an ERRNO effect sets the injected
 * value (clock_nanosleep returns it instead, as the real one does). Rule lookups and
 * LATENCY sleeps preserve errno.
 *
 * @module chaos-time
 * @stability Internal — symbol names are public (exported ABI), implementation
 *            is not.
 */

#include "chaos_time_actions.h"
#include "chaos_time_config.h"
#include "chaos_time_internal.h"

#include <string.h>

/**
 * Real clock_gettime under the guard; raw SYS_clock_gettime while unresolved.
 *
 * @param clock_id  Clock.
 * @param value     Output; NULL is passed through (EFAULT from the kernel or libc).
 * @return          0, or -1 with errno set.
 */
static int chaos_time_call_real_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    int previous;
    int rc;

    if (g_chaos_time_real_clock_gettime == NULL)
    {
        /* Unresolved: a call from inside symbol resolution (preloaded allocator,
         * signal handler) or no definition later in the chain. The system call does
         * what libc would. */
        return (int)syscall(SYS_clock_gettime, clock_id, value);
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_clock_gettime(clock_id, value);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real nanosleep under the guard; raw SYS_nanosleep while unresolved.
 *
 * @param request    Duration.
 * @param remaining  Receives the unslept time on EINTR; may be NULL.
 * @return           0, or -1 with errno set.
 */
static int
chaos_time_call_real_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    int previous;
    int rc;

    if (g_chaos_time_real_nanosleep == NULL)
    {
        return (int)syscall(SYS_nanosleep, request, remaining);
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_nanosleep(request, remaining);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real usleep under the guard; while unresolved, one raw SYS_nanosleep (not restarted
 * on EINTR, like usleep).
 *
 * @param usec  Microseconds.
 * @return      0, or -1 with errno set.
 */
static int chaos_time_call_real_usleep(useconds_t usec)
{
    int previous;
    int rc;

    if (g_chaos_time_real_usleep == NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)(usec % 1000000U) * 1000L;
        return (int)syscall(SYS_nanosleep, &request, NULL);
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_usleep(usec);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real gettimeofday under the guard; raw SYS_gettimeofday while unresolved.
 *
 * @param value  Output.
 * @param zone   Obsolete timezone output; may be NULL.
 * @return       0, or -1 with errno set.
 */
static int chaos_time_call_real_gettimeofday(struct timeval *value, void *zone)
{
    int previous;
    int rc;

    if (g_chaos_time_real_gettimeofday == NULL)
    {
        return (int)syscall(SYS_gettimeofday, value, zone);
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_gettimeofday(value, zone);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real time under the guard; while unresolved, a raw CLOCK_REALTIME read.
 *
 * @param out  Optional output; may be NULL.
 * @return     Seconds since the epoch, or (time_t)-1.
 */
static time_t chaos_time_call_real_time(time_t *out)
{
    int previous;
    time_t result;

    if (g_chaos_time_real_time == NULL)
    {
        /* arm64 has no time system call, so every architecture reads the realtime
         * clock. A failed read leaves the (time_t)-1 time(2) reports errors with. */
        struct timespec now;

        now.tv_sec = (time_t)-1;
        (void)syscall(SYS_clock_gettime, CLOCK_REALTIME, &now);
        if (out != NULL)
        {
            *out = now.tv_sec;
        }
        return now.tv_sec;
    }
    previous = chaos_time_enter_internal();
    result = g_chaos_time_real_time(out);
    chaos_time_leave_internal(previous);
    return result;
}

/**
 * Real clock_nanosleep under the guard; raw SYS_clock_nanosleep while unresolved.
 *
 * @param clock_id   Clock.
 * @param flags      0 or TIMER_ABSTIME.
 * @param request    Duration or absolute deadline.
 * @param remaining  Receives the unslept time on EINTR (relative sleeps); may be NULL.
 * @return           0 or a positive error number; errno untouched.
 */
static int chaos_time_call_real_clock_nanosleep(
    clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remaining
)
{
    int previous;
    int rc;

    if (g_chaos_time_real_clock_nanosleep == NULL)
    {
        /* clock_nanosleep reports the error number and leaves errno alone. */
        const int saved_errno = errno;

        rc = syscall(SYS_clock_nanosleep, clock_id, flags, request, remaining) == 0 ? 0 : errno;
        errno = saved_errno;
        return rc;
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_clock_nanosleep(clock_id, flags, request, remaining);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real sleep under the guard; while unresolved, one raw SYS_nanosleep.
 *
 * @param seconds  Seconds.
 * @return         0, or the unslept seconds rounded up when a signal interrupts.
 */
static unsigned int chaos_time_call_real_sleep(unsigned int seconds)
{
    int previous;
    unsigned int rc;

    if (g_chaos_time_real_sleep == NULL)
    {
        /* sleep returns the whole seconds left when a signal cuts it short. */
        struct timespec request;

        request.tv_sec = (time_t)seconds;
        request.tv_nsec = 0L;
        if (syscall(SYS_nanosleep, &request, &request) == 0)
        {
            return 0U;
        }
        return (unsigned int)request.tv_sec + (request.tv_nsec != 0L ? 1U : 0U);
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_sleep(seconds);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Real timespec_get under the guard; while unresolved, a raw CLOCK_REALTIME read for
 * TIME_UTC and 0 for any other base.
 *
 * @param value  Output.
 * @param base   Time base.
 * @return       @p base on success, 0 on failure.
 */
static int chaos_time_call_real_timespec_get(struct timespec *value, int base)
{
    int previous;
    int rc;

    if (g_chaos_time_real_timespec_get == NULL)
    {
        /* TIME_UTC is the realtime clock; any other base, or a failed read, is 0. */
        if (base != TIME_UTC || syscall(SYS_clock_gettime, CLOCK_REALTIME, value) != 0)
        {
            return 0;
        }
        return base;
    }
    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_timespec_get(value, base);
    chaos_time_leave_internal(previous);
    return rc;
}

static int chaos_time_read_clock(clockid_t clock_id, struct timespec *value);

/**
 * Reports an injected EINTR as "nothing slept": *remaining = *request.
 *
 * POSIX writes the unslept time to *rem on EINTR; a caller that loops on EINTR with
 * rem as the next request then sleeps the full duration again instead of reading
 * uninitialised memory.
 *
 * @param request    Original request; NULL does nothing.
 * @param remaining  Output; NULL does nothing.
 */
static void chaos_time_copy_remaining(const struct timespec *request, struct timespec *remaining)
{
    if (request == NULL || remaining == NULL)
    {
        return;
    }

    *remaining = *request;
}

/**
 * Wrapper for clock_gettime(2): LATENCY, ERRNO, then the real read, OFFSET, REGRESS.
 *
 * Bypassed under the guard and for a NULL @p value (the real function reports its own
 * EFAULT). OFFSET and REGRESS change only the returned value, never the kernel clock;
 * CLOCK_MONOTONIC may then go backwards between reads, which is the fault under test.
 *
 * @param clock_id  Clock.
 * @param value     Output.
 * @return          0, or -1 with errno set (by the real function or an ERRNO rule).
 */
CHAOS_TIME_EXPORT int clock_gettime(clockid_t clock_id, struct timespec *value)
{
    uintptr_t value_bits = (uintptr_t)(void *)value;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal() || value_bits == 0U)
    {
        return chaos_time_call_real_clock_gettime(clock_id, value);
    }
    return chaos_time_read_clock(clock_id, value);
}

/**
 * Wrapper for gettimeofday(2): a CLOCK_REALTIME read under the clock_gettime rules.
 *
 * glibc and musl serve gettimeofday from the vDSO without calling clock_gettime, so an
 * OFFSET rule on clock_gettime alone would leave it unshifted and one process would
 * see two wall clocks. The value comes from chaos_time_read_clock(), truncated to
 * microseconds; a non-NULL @p zone is still filled by the real gettimeofday, which is
 * its only use. Bypassed under the guard and for a NULL @p value.
 *
 * @param value  Output.
 * @param zone   Obsolete timezone output; may be NULL.
 * @return       0, or -1 with errno set.
 */
CHAOS_TIME_EXPORT int gettimeofday(struct timeval *value, void *zone)
{
    struct timeval unused;
    struct timespec now;
    /* glibc declares the value argument nonnull, which lets the compiler drop a
     * plain NULL test. Reading it through a volatile keeps the test, so a NULL
     * value reaches the real call (and its EFAULT) instead of being written to. */
    struct timeval *volatile checked_value = value;
    uintptr_t value_bits = (uintptr_t)(void *)checked_value;
    uintptr_t zone_bits = (uintptr_t)zone;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal() || value_bits == 0U)
    {
        return chaos_time_call_real_gettimeofday(value, zone);
    }
    if (chaos_time_read_clock(CLOCK_REALTIME, &now) != 0)
    {
        return -1;
    }
    if (zone_bits != 0U && chaos_time_call_real_gettimeofday(&unused, zone) != 0)
    {
        return -1;
    }
    value->tv_sec = now.tv_sec;
    value->tv_usec = (suseconds_t)(now.tv_nsec / 1000L);
    return 0;
}

/**
 * Wrapper for time(2): a CLOCK_REALTIME read under the clock_gettime rules.
 *
 * Served by libc without clock_gettime, like gettimeofday. An ERRNO rule makes it
 * return (time_t)-1 with errno set, its only failure report; *out is then untouched.
 * Bypassed under the guard only (a NULL @p out is valid).
 *
 * @param out  Optional output; may be NULL.
 * @return     Seconds since the epoch, or (time_t)-1.
 */
CHAOS_TIME_EXPORT time_t time(time_t *out)
{
    struct timespec now;
    uintptr_t out_bits = (uintptr_t)(void *)out;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal())
    {
        return chaos_time_call_real_time(out);
    }
    if (chaos_time_read_clock(CLOCK_REALTIME, &now) != 0)
    {
        return (time_t)-1;
    }
    if (out_bits != 0U)
    {
        *out = now.tv_sec;
    }
    return now.tv_sec;
}

/**
 * Wrapper for timespec_get(3): a TIME_UTC read is a CLOCK_REALTIME read under the
 * clock_gettime rules.
 *
 * glibc and musl read the clock internally, without clock_gettime. Other bases, a NULL
 * @p value and calls under the guard go to the real function. Failure, including an
 * injected ERRNO, is reported as 0, timespec_get's only error value; errno is set.
 *
 * @param value  Output.
 * @param base   Time base; TIME_UTC is the only one C11 defines.
 * @return       @p base on success, 0 on failure.
 */
CHAOS_TIME_EXPORT int timespec_get(struct timespec *value, int base)
{
    /* Declared nonnull by glibc; read through a volatile so the test stays. */
    struct timespec *volatile checked_value = value;
    uintptr_t value_bits = (uintptr_t)(void *)checked_value;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal() || value_bits == 0U || base != TIME_UTC)
    {
        return chaos_time_call_real_timespec_get(value, base);
    }
    return chaos_time_read_clock(CLOCK_REALTIME, value) == 0 ? base : 0;
}

/**
 * One clock read under the clock_gettime rules: LATENCY, ERRNO, real read, OFFSET,
 * REGRESS.
 *
 * Shared by clock_gettime, gettimeofday, time and timespec_get, so every way of reading
 * a clock sees the same faults. Each effect has its own lookup and firing decision.
 *
 * @param clock_id  Clock to read.
 * @param value     Output; not NULL.
 * @return          0, or -1 with errno set.
 */
static int chaos_time_read_clock(clockid_t clock_id, struct timespec *value)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    chaos_time_rule_t offset_rule;
    chaos_time_rule_t regress_rule;
    int rc;

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &errno_rule
        ) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    rc = chaos_time_call_real_clock_gettime(clock_id, value);
    if (rc != 0)
    {
        return rc;
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &offset_rule
        ))
    {
        chaos_time_rule_apply_offset(&offset_rule, value);
    }
    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_REGRESS, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &regress_rule
        ))
    {
        chaos_time_rule_apply_regress(&regress_rule, value);
    }

    return 0;
}

/**
 * Wrapper for nanosleep(2): LATENCY, ERRNO, then the real sleep.
 *
 * An injected EINTR also sets *@p remaining to the full request. Bypassed under the
 * guard and for a NULL @p request.
 *
 * @param request    Duration.
 * @param remaining  Receives the unslept time on EINTR; may be NULL.
 * @return           0, or -1 with errno set.
 */
CHAOS_TIME_EXPORT int nanosleep(const struct timespec *request, struct timespec *remaining)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    uintptr_t request_bits = (uintptr_t)(const void *)request;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal() || request_bits == 0U)
    {
        return chaos_time_call_real_nanosleep(request, remaining);
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        if (errno == EINTR)
        {
            chaos_time_copy_remaining(request, remaining);
        }
        return -1;
    }

    return chaos_time_call_real_nanosleep(request, remaining);
}

/**
 * Wrapper for sleep(3) under the nanosleep rules: LATENCY, ERRNO, then the real sleep.
 *
 * glibc and musl implement sleep with their internal nanosleep, which never passes
 * the exported symbol. sleep has no error return: an injected error is reported like
 * an interruption, as all @p seconds unslept, with errno set to the injected value.
 * Bypassed under the guard only.
 *
 * @param seconds  Seconds.
 * @return         0 when the full time elapsed; otherwise the unslept seconds.
 */
CHAOS_TIME_EXPORT unsigned int sleep(unsigned int seconds)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal())
    {
        return chaos_time_call_real_sleep(seconds);
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        return seconds;
    }
    return chaos_time_call_real_sleep(seconds);
}

/**
 * Wrapper for clock_nanosleep(2) under the nanosleep rules: LATENCY, ERRNO, real sleep.
 *
 * The rules are the nanosleep ones whatever @p clock_id is (glibc's nanosleep is this
 * function internally). Failure is returned as the error number with errno untouched,
 * as the real function does; an injected EINTR fills @p remaining for a relative sleep
 * only, since POSIX does not write it for TIMER_ABSTIME.
 *
 * A TIMER_ABSTIME deadline was computed from the clock as the program reads it, shifted
 * by the OFFSET and REGRESS rules of @p clock_id, while the kernel waits on the real
 * clock. It is mapped back first (chaos_time_rule_unshift_deadline()), so a shifted
 * clock neither stalls an absolute sleep nor ends it at once. Bypassed under the guard
 * and for a NULL @p request.
 *
 * @param clock_id   Clock.
 * @param flags      0 or TIMER_ABSTIME.
 * @param request    Duration or absolute deadline.
 * @param remaining  Receives the unslept time on EINTR; may be NULL.
 * @return           0, or a positive error number.
 */
CHAOS_TIME_EXPORT int clock_nanosleep(
    clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remaining
)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    uintptr_t request_bits = (uintptr_t)(const void *)request;
    int saved_errno;
    int injected;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal() || request_bits == 0U)
    {
        return chaos_time_call_real_clock_nanosleep(clock_id, flags, request, remaining);
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    saved_errno = errno;
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        injected = errno;
        errno = saved_errno;
        if (injected == EINTR && (flags & TIMER_ABSTIME) == 0)
        {
            chaos_time_copy_remaining(request, remaining);
        }
        return injected;
    }

    if ((flags & TIMER_ABSTIME) != 0)
    {
        chaos_time_rule_t offset_rule;
        chaos_time_rule_t regress_rule;
        const int has_offset = chaos_time_config_match(
            CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &offset_rule
        );
        const int has_regress = chaos_time_config_match(
            CHAOS_TIME_EFFECT_REGRESS, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &regress_rule
        );
        struct timespec deadline = *request;

        if (chaos_time_rule_unshift_deadline(
                has_offset ? &offset_rule : NULL, has_regress ? &regress_rule : NULL, &deadline
            ))
        {
            return chaos_time_call_real_clock_nanosleep(clock_id, flags, &deadline, remaining);
        }
    }
    return chaos_time_call_real_clock_nanosleep(clock_id, flags, request, remaining);
}

/**
 * Wrapper for usleep(3): LATENCY, ERRNO, then the real sleep. Bypassed under the guard.
 *
 * @param usec  Microseconds.
 * @return      0, or -1 with errno set.
 */
CHAOS_TIME_EXPORT int usleep(useconds_t usec)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;

    chaos_time_ensure_symbols();

    if (chaos_time_in_internal())
    {
        return chaos_time_call_real_usleep(usec);
    }

    if (chaos_time_config_match(CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_USLEEP, 0, &latency_rule))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_time_call_real_usleep(usec);
}
