/**
 * @file chaos_time_hooks.c
 * @brief LD_PRELOAD interceptor wrappers for clock_gettime(2), gettimeofday(2),
 *        time(2), timespec_get(3), nanosleep(2), clock_nanosleep(2), sleep(3)
 *        and usleep(3).
 *
 * This translation unit contains the exported symbols that the dynamic linker
 * resolves instead of the libc originals when the library is loaded via
 * LD_PRELOAD.  gettimeofday, time and timespec_get read the realtime clock
 * through the clock_gettime rules, and clock_nanosleep and sleep follow the
 * nanosleep rules, so a
 * rule applies however the program reads the clock or sleeps.  Each wrapper
 * follows the same structure:
 *
 *  1. **Bypass check** — if the per-thread reentrancy guard is set, or if a
 *     mandatory pointer argument is NULL, forward directly to the real
 *     function without any chaos injection.
 *
 *  2. **LATENCY** — look up a matching LATENCY rule and sleep before the real
 *     call if one is found and the probability gate fires.
 *
 *  3. **ERRNO** — look up a matching ERRNO rule and return -1/errno early if
 *     one is found and the probability gate fires, without calling the real
 *     function.
 *
 *  4. **Real call** — call the real function through the saved pointer.
 *
 *  5. **OFFSET** (clock_gettime only) — if the real call succeeds, look up a
 *     matching OFFSET rule and apply a signed millisecond delta to the
 *     returned struct timespec.
 *
 * ### Bypass conditions
 *
 * The guard check (chaos_time_in_internal()) is the primary reentrancy
 * mechanism.  It fires whenever the library calls an intercepted symbol
 * internally — for example, during the config file stat(), during a LATENCY
 * sleep that calls real nanosleep, or if the C runtime's implementation of
 * another function happens to call clock_gettime.  When the guard is set, all
 * three chaos evaluation steps are skipped.
 *
 * The NULL pointer checks for the request/value arguments (cast to uintptr_t
 * before comparison to avoid implementation-defined behaviour on pointer-to-
 * integer conversion of NULL) ensure the wrappers do not pass NULL to
 * chaos_time_config_match(), which would produce meaningless matches.
 *
 * ### Inner call helpers
 *
 * chaos_time_call_real_* are private wrappers around the resolved function
 * pointers that raise the reentrancy guard for the duration of the real call.
 * They are used by the hooks for the actual dispatch step (step 4 above) so
 * that any intercepted symbol called by the real implementation is also
 * suppressed.
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
 * Calls the real clock_gettime with the reentrancy guard raised.
 *
 * Ensures that any function called by the libc clock_gettime implementation
 * (e.g. vDSO path, fallback syscall, internal lock acquisition) does not
 * re-enter the chaos wrappers.
 *
 * @param clock_id  POSIX clock identifier.
 * @param value     Output timespec.  May be NULL; the real function will
 *                  handle the resulting EFAULT.
 * @return          The return value of the real clock_gettime.
 */
static int chaos_time_call_real_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_clock_gettime(clock_id, value);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real nanosleep with the reentrancy guard raised.
 *
 * @param request    Requested sleep duration.
 * @param remaining  Output: remaining time if interrupted by a signal.
 *                   May be NULL.
 * @return           The return value of the real nanosleep.
 */
static int
chaos_time_call_real_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_nanosleep(request, remaining);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real usleep with the reentrancy guard raised.
 *
 * @param usec  Duration to sleep in microseconds.
 * @return      The return value of the real usleep.
 */
static int chaos_time_call_real_usleep(useconds_t usec)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_usleep(usec);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real gettimeofday with the reentrancy guard raised.
 *
 * @param value     Output timeval.
 * @param zone      Obsolete timezone output; may be NULL.
 * @return          The return value of the real gettimeofday.
 */
static int chaos_time_call_real_gettimeofday(struct timeval *value, void *zone)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_gettimeofday(value, zone);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real time with the reentrancy guard raised.
 *
 * @param out  Optional output; may be NULL.
 * @return     The return value of the real time.
 */
static time_t chaos_time_call_real_time(time_t *out)
{
    int previous;
    time_t result;

    previous = chaos_time_enter_internal();
    result = g_chaos_time_real_time(out);
    chaos_time_leave_internal(previous);
    return result;
}

/**
 * Calls the real clock_nanosleep with the reentrancy guard raised.
 *
 * @param clock_id   Clock to sleep against.
 * @param flags      0 or TIMER_ABSTIME.
 * @param request    Requested duration or absolute deadline.
 * @param remaining  Output: remaining time if interrupted.  May be NULL.
 * @return           The return value of the real clock_nanosleep.
 */
static int chaos_time_call_real_clock_nanosleep(
    clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remaining
)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_clock_nanosleep(clock_id, flags, request, remaining);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real sleep with the reentrancy guard raised.
 *
 * @param seconds  Duration to sleep.
 * @return         The return value of the real sleep.
 */
static unsigned int chaos_time_call_real_sleep(unsigned int seconds)
{
    int previous;
    unsigned int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_sleep(seconds);
    chaos_time_leave_internal(previous);
    return rc;
}

/**
 * Calls the real timespec_get with the reentrancy guard raised.
 *
 * @param value  Output timespec.
 * @param base   Time base.
 * @return       The return value of the real timespec_get.
 */
static int chaos_time_call_real_timespec_get(struct timespec *value, int base)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_timespec_get(value, base);
    chaos_time_leave_internal(previous);
    return rc;
}

static int chaos_time_read_clock(clockid_t clock_id, struct timespec *value);

/**
 * Copies the request timespec into the remaining output when an ERRNO rule
 * simulates EINTR.
 *
 * POSIX specifies that when nanosleep is interrupted by a signal (EINTR), the
 * remaining time is written to *rem.  An ERRNO rule with errnum == EINTR must
 * populate *remaining to match this contract so that callers that loop on
 * EINTR restart correctly (or at least do not read uninitialised memory).
 *
 * @param request    The original nanosleep request.  May be NULL (no-op).
 * @param remaining  Output pointer.  May be NULL (no-op).
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
 * Interceptor for clock_gettime(2).
 *
 * Injects LATENCY, ERRNO, and/or OFFSET faults as configured.  Effects are
 * applied in order: LATENCY first (before the real call), ERRNO second (may
 * short-circuit and return -1 without calling the real function), then OFFSET
 * after the real call succeeds.
 *
 * OFFSET modifies the struct timespec value written to @p value in-place.
 * It does not alter the kernel clock in any way.  For CLOCK_MONOTONIC this
 * may cause the sequence of values returned to the application to be
 * non-monotonic: if one call fires the probability gate and another does not,
 * or if the config changes between calls, the adjusted value may be less than
 * the previous adjusted value.  This is deliberate — the intent is to test
 * application resilience to backward time steps.
 *
 * The wrapper is bypassed (real function called directly) if:
 *  - The reentrancy guard is set (internal call from within the library).
 *  - @p value is NULL (POSIX says this is EFAULT; let the real function
 *    handle it to preserve the exact errno value).
 *
 * @param clock_id  POSIX clock identifier (CLOCK_REALTIME, CLOCK_MONOTONIC,
 *                  etc.).
 * @param value     Output timespec.  Must not be NULL for chaos injection to
 *                  apply.
 * @return          0 on success, -1 with errno set on failure.
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
 * Interceptor for gettimeofday(2).
 *
 * gettimeofday reads the realtime clock, and glibc and musl serve it from the
 * vDSO without calling clock_gettime, so an OFFSET rule on clock_gettime alone
 * would leave it unshifted: one process would see two different wall clocks.
 * The wrapper therefore reads CLOCK_REALTIME through the clock_gettime rules
 * (LATENCY, ERRNO, OFFSET) and converts the result. A non-NULL @p zone is
 * still filled by the real gettimeofday, which is all it is used for.
 *
 * @param value     Output timeval.  Must not be NULL for chaos injection.
 * @param zone      Obsolete timezone output; may be NULL.
 * @return          0 on success, -1 with errno set on failure.
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
 * Interceptor for time(2).
 *
 * Like gettimeofday, time is served from the vDSO without calling
 * clock_gettime, so it reads CLOCK_REALTIME through the clock_gettime rules.
 * An ERRNO rule makes it return (time_t)-1 with errno set, its only failure
 * report.
 *
 * @param out  Optional output for the result; may be NULL.
 * @return     Seconds since the Epoch, or (time_t)-1 on failure.
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
 * Interceptor for timespec_get(3).
 *
 * The C11 way to read the wall clock. glibc and musl read CLOCK_REALTIME
 * internally, without calling clock_gettime, so a TIME_UTC read goes through
 * the clock_gettime rules like gettimeofday() and time(). Other bases are
 * forwarded. Failure is reported as 0, timespec_get's only error value.
 *
 * @param value  Output timespec.
 * @param base   Time base; TIME_UTC is the only one C11 defines.
 * @return       @p base on success; 0 on failure.
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
 * Applies the clock_gettime rules to one read of @p clock_id.
 *
 * Shared by clock_gettime, gettimeofday and time so that every way of reading
 * a clock sees the same LATENCY, ERRNO and OFFSET.
 *
 * @param clock_id  Clock to read.
 * @param value     Output timespec; not NULL.
 * @return          0 on success, -1 with errno set on failure.
 */
static int chaos_time_read_clock(clockid_t clock_id, struct timespec *value)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    chaos_time_rule_t offset_rule;
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

    return 0;
}

/**
 * Interceptor for nanosleep(2).
 *
 * Injects LATENCY and/or ERRNO faults as configured.  OFFSET is not
 * supported for nanosleep because nanosleep does not produce a struct timespec
 * time value.
 *
 * When an ERRNO rule with errnum == EINTR fires, the wrapper populates
 * @p remaining with a copy of @p request to satisfy the POSIX contract that
 * *rem is set when nanosleep returns EINTR.
 *
 * The wrapper is bypassed if the reentrancy guard is set or if @p request is
 * NULL.
 *
 * @param request    Requested sleep duration.
 * @param remaining  Output: remaining time if the call is interrupted.
 *                   May be NULL.
 * @return           0 on success, -1 with errno set on failure or interruption.
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
 * Interceptor for sleep(3).
 *
 * glibc and musl implement sleep() with their internal nanosleep, which never
 * passes through the exported symbol, so it follows the nanosleep rules here:
 * LATENCY, then ERRNO. sleep() has no error return; an injected error is
 * reported the way an interrupted sleep is, as the whole request unslept, with
 * errno set to the injected value.
 *
 * @param seconds  Duration to sleep.
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
 * Interceptor for clock_nanosleep(2).
 *
 * clock_nanosleep is the general form of nanosleep (and what glibc's own
 * nanosleep calls internally, bypassing this symbol), so it follows the
 * nanosleep rules: LATENCY and ERRNO.  Unlike nanosleep it reports failure by
 * returning the error number and leaves errno untouched.  An injected EINTR
 * fills @p remaining for a relative sleep only; POSIX does not write it for
 * TIMER_ABSTIME.
 *
 * @param clock_id   Clock to sleep against.
 * @param flags      0 or TIMER_ABSTIME.
 * @param request    Requested duration or absolute deadline.
 * @param remaining  Output: remaining time if interrupted.  May be NULL.
 * @return           0 on success, or a positive error number.
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

    return chaos_time_call_real_clock_nanosleep(clock_id, flags, request, remaining);
}

/**
 * Interceptor for usleep(3).
 *
 * Injects LATENCY and/or ERRNO faults as configured.  OFFSET is not
 * applicable to usleep.
 *
 * Unlike clock_gettime and nanosleep, there is no mandatory pointer argument
 * to check, so the bypass condition is solely the reentrancy guard.
 *
 * @param usec  Duration to sleep in microseconds.
 * @return      0 on success, -1 with errno set on failure.
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
