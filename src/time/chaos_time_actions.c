/**
 * @file chaos_time_actions.c
 * @brief Implementation of chaos effect actions: probability gating,
 *        LATENCY sleep, ERRNO injection, and OFFSET arithmetic.
 *
 * This translation unit is the only place where probability thresholds are
 * evaluated, sleep calls are issued to real sleep functions, errno is set
 * unconditionally, and struct timespec values are arithmetically modified.
 *
 * ### LATENCY implementation and reentrancy
 *
 * The LATENCY action must sleep for a caller-specified duration without
 * triggering further chaos injection.  chaos_time_sleep_chunk() achieves this
 * by:
 *
 *  1. Calling chaos_time_enter_internal(), which saves the current guard value
 *     and sets it to 1.
 *  2. Calling g_chaos_time_real_usleep or g_chaos_time_real_nanosleep directly
 *     through the resolved function pointers — never through the symbol names
 *     `usleep` or `nanosleep`, which would resolve to the wrappers.
 *  3. Calling chaos_time_leave_internal(previous), which restores the guard to
 *     whatever value it had before step 1.
 *
 * **Why save/restore matters here:**
 *
 * Consider a LATENCY rule on `nanosleep` and a separate LATENCY rule on
 * `clock_gettime`.  Hypothetically, if the C runtime's nanosleep uses
 * clock_gettime internally and the guard were set-to-1 / set-to-0 rather than
 * save/restore, the sequence would be:
 *
 * @code
 *   [outer] nanosleep wrapper:       enter → previous=0, guard=1
 *   [outer] apply_latency:           sleep_chunk → enter → previous=1, guard=1
 *                                    real_nanosleep ...
 *                                    [inner] clock_gettime via runtime:
 *                                        guard==1, bypass → real call
 *                                    leave(1) → guard=1  ← correct with save/restore
 *                                               guard=0  ← BUG with set-to-0
 *   [outer] apply_latency returns
 *   [outer] nanosleep wrapper:       real nanosleep, leave(0) → guard=0
 * @endcode
 *
 * With set-to-0, the outer wrapper's guard is prematurely cleared after the
 * sleep chunk returns.  Any subsequent code in the outer wrapper that calls an
 * intercepted symbol (e.g. config stat via clock_gettime) would see guard==0
 * and re-enter chaos injection logic, which is incorrect.
 *
 * The save/restore pattern ensures the outer enter/leave pair is the sole
 * authority over when the guard transitions to 0 for the outermost frame.
 *
 * ### OFFSET arithmetic
 *
 * chaos_time_add_offset_ms() operates on int64_t intermediates to avoid
 * overflow and to handle signed nanosecond carry correctly.  The algorithm:
 *
 *  1. Decompose offset_ms into whole seconds (offset_ms / 1000) and a
 *     sub-second residual in nanoseconds ((offset_ms % 1000) * 1,000,000).
 *  2. Add each part to the corresponding field.
 *  3. Normalise tv_nsec into [0, 999,999,999] by iteratively borrowing from
 *     or lending to tv_sec.  The loop handles the case where the residual
 *     exceeds ±999,999,999 ns, which can happen when both the original
 *     tv_nsec and the residual are large in the same direction (maximum
 *     |residual| = 999 * 1,000,000 = 999,000,000 ns < 1 s, so at most one
 *     iteration of each while loop is ever needed in practice).
 *  4. Clamp negative tv_sec to {0, 0} rather than returning a negative
 *     timespec, which would violate the POSIX struct timespec invariant.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_time_actions.h"

#include <stdint.h>

/**
 * @copydoc chaos_time_probability_hit_sample
 *
 * The threshold is computed as `probability * 4294967296.0` (i.e. probability
 * * 2^32).  The sample is a uniformly distributed uint32_t in [0, 2^32), so
 * the comparison `(double)sample < threshold` fires with frequency
 * approximately equal to @p probability.  The double comparison avoids integer
 * overflow and handles the boundary cases (probability == 0.0 and == 1.0)
 * naturally via the fast-path guards.
 */
int chaos_time_probability_hit_sample(double probability, uint32_t sample)
{
    double threshold;

    if (probability <= 0.0)
    {
        return 0;
    }
    if (probability >= 1.0)
    {
        return 1;
    }

    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

/**
 * @copydoc chaos_time_probability_hit
 */
int chaos_time_probability_hit(double probability)
{
    return chaos_time_probability_hit_sample(probability, chaos_time_prng_next_u32());
}

/**
 * Sleeps for at most @p usec microseconds using the real sleep implementation.
 *
 * Wraps the sleep call inside chaos_time_enter_internal() /
 * chaos_time_leave_internal() to prevent the sleep itself from being
 * intercepted.  See the file-level documentation for the full reentrancy
 * analysis.
 *
 * Preference order:
 *  1. g_chaos_time_real_usleep — lower overhead on platforms that map usleep
 *     to a single syscall.
 *  2. g_chaos_time_real_nanosleep — used if usleep is unavailable; the
 *     microsecond value is converted to a struct timespec and the call is
 *     retried on EINTR to avoid partial sleeps.
 *
 * @param usec  Duration to sleep in microseconds.  Must be ≤ 1,000,000.
 */
static void chaos_time_sleep_chunk(useconds_t usec)
{
    int previous;

    previous = chaos_time_enter_internal();
    if (g_chaos_time_real_usleep != NULL)
    {
        (void)g_chaos_time_real_usleep(usec);
    }
    else if (g_chaos_time_real_nanosleep != NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)((usec % 1000000U) * 1000U);
        while (g_chaos_time_real_nanosleep(&request, &request) != 0 && errno == EINTR)
        {
        }
    }
    chaos_time_leave_internal(previous);
}

/**
 * Applies a signed millisecond offset to a struct timespec in-place.
 *
 * Decomposes the offset into whole seconds and a sub-second nanosecond
 * component, adds each part to the corresponding field of @p value, then
 * normalises the nanosecond field into [0, 999,999,999] by propagating carry
 * to or borrow from the second field.  Negative results are clamped to
 * {0, 0}.
 *
 * Operates on int64_t intermediates throughout to avoid signed overflow with
 * large tv_sec values or large negative offsets.
 *
 * @param value      struct timespec to update.  Ignored if NULL.
 * @param offset_ms  Signed millisecond delta.  A value of 0 is a no-op.
 */
static void chaos_time_add_offset_ms(struct timespec *value, int64_t offset_ms)
{
    int64_t seconds;
    int64_t nanoseconds;

    if (value == NULL || offset_ms == 0)
    {
        return;
    }

    seconds = (int64_t)value->tv_sec + (offset_ms / 1000);
    nanoseconds = (int64_t)value->tv_nsec + ((offset_ms % 1000) * INT64_C(1000000));

    while (nanoseconds >= INT64_C(1000000000))
    {
        ++seconds;
        nanoseconds -= INT64_C(1000000000);
    }
    while (nanoseconds < 0)
    {
        --seconds;
        nanoseconds += INT64_C(1000000000);
    }

    if (seconds < 0)
    {
        value->tv_sec = 0;
        value->tv_nsec = 0L;
        return;
    }

    value->tv_sec = (time_t)seconds;
    value->tv_nsec = (long)nanoseconds;
}

/**
 * @copydoc chaos_time_rule_should_trigger
 */
int chaos_time_rule_should_trigger(const chaos_time_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }

    return chaos_time_probability_hit(rule->probability);
}

/**
 * @copydoc chaos_time_rule_apply_latency
 *
 * Implementation notes:
 *
 *  - The millisecond duration is converted to microseconds and broken into
 *    chunks of at most 1,000,000 µs (1 s) because useconds_t is only
 *    guaranteed to represent values up to 1,000,000 on POSIX-conforming
 *    systems.
 *  - Probability is sampled once at the start; if the gate does not fire, no
 *    sleep occurs.
 *  - The reentrancy guard is raised inside chaos_time_sleep_chunk() around
 *    each real sleep call.  See the file-level documentation for why
 *    save/restore semantics are required rather than simple set/clear.
 */
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_LATENCY ||
        !chaos_time_rule_should_trigger(rule))
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;

        chaos_time_sleep_chunk(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/**
 * @copydoc chaos_time_rule_apply_errno
 */
int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_ERRNO ||
        !chaos_time_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}

/**
 * @copydoc chaos_time_rule_apply_offset
 *
 * Implementation notes:
 *
 *  - Delegates arithmetic to chaos_time_add_offset_ms().
 *  - Probability is sampled for each call independently; two threads
 *    calling clock_gettime simultaneously may each independently fire or
 *    not fire the probability gate, so they may receive different absolute
 *    timestamps even if the kernel returned identical values.  There is no
 *    synchronisation between threads.
 */
void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value)
{
    if (rule == NULL || value == NULL || rule->effect != CHAOS_TIME_EFFECT_OFFSET ||
        !chaos_time_rule_should_trigger(rule))
    {
        return;
    }

    chaos_time_add_offset_ms(value, rule->offset_ms);
}
