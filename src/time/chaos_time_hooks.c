/**
 * @file chaos_time_hooks.c
 * @brief LD_PRELOAD interceptor wrappers for clock_gettime(2), nanosleep(2),
 *        and usleep(3).
 *
 * This translation unit contains the three exported symbols that the dynamic
 * linker resolves instead of the libc originals when the library is loaded via
 * LD_PRELOAD.  Each wrapper follows the same structure:
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
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    chaos_time_rule_t offset_rule;
    uintptr_t value_bits = (uintptr_t)(void *)value;
    int rc;

    if (chaos_time_in_internal() || value_bits == 0U)
    {
        return chaos_time_call_real_clock_gettime(clock_id, value);
    }

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
