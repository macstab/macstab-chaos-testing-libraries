/**
 * @file chaos_time_actions.c
 * @brief Effect execution for libchaos-time: firing decision, LATENCY sleep, ERRNO,
 *        OFFSET and REGRESS arithmetic, deadline correction.
 *
 * @details
 * ### LATENCY
 *
 * The delay goes through the real usleep (or the real nanosleep) pointer, never the
 * exported symbol, with the guard raised for each chunk. The guard is saved and
 * restored, not set and cleared, because a wrapper may already hold it (see
 * @ref chaos_time_guard). Unlike the other libraries, which sleep with a raw
 * clock_nanosleep system call (chaos_sleep.h), libchaos-time sleeps through these
 * real-function pointers.
 *
 * ### Time arithmetic
 *
 * chaos_time_add_offset_ms() works in int64_t: offset_ms is split into seconds and a
 * nanosecond residual of at most 999000000 in magnitude, so one carry or borrow
 * normalises tv_nsec into [0, 999999999]; the loops are a guard, not a hot path. With
 * shifts bounded to 100 years at parse time (3155760000 s) the sum cannot overflow. A
 * result before the epoch is clamped to {0, 0} rather than returned as a negative
 * timespec.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_time_actions.h"

#include <errno.h>
#include <stdint.h>

/**
 * @copydoc chaos_time_probability_hit_sample
 *
 * Compared in double, which represents every uint32_t exactly and cannot overflow.
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
 * Sleeps @p usec through the real usleep, else the real nanosleep, under the guard.
 *
 * usleep is not restarted when a signal interrupts it, so the chunk may be shorter;
 * the nanosleep fallback resumes with the remaining time on EINTR. With neither
 * pointer resolved nothing sleeps. errno is preserved.
 *
 * @param usec  Microseconds, <= 1000000.
 */
static void chaos_time_sleep_chunk(useconds_t usec)
{
    /* An interrupted sleep sets EINTR; the delay is the library's, the errno the caller's. */
    const int saved_errno = errno;
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
    errno = saved_errno;
}

/**
 * Adds @p offset_ms to @p value, normalised; a result before the epoch becomes {0, 0}.
 *
 * Expects tv_nsec in [0, 999999999] on entry, as every clock returns it.
 *
 * @param value      Time to shift in place; NULL does nothing.
 * @param offset_ms  Signed shift in ms, |offset_ms| <= CHAOS_TIME_MAX_OFFSET_MS; 0 does
 *                   nothing.
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
int chaos_time_rule_should_trigger(chaos_time_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_at_ok(&rule->policy, rule->hit) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }

    /* Past the gates that cost nothing: this call is an evaluation of the rule and gets
     * its number. `@every=N` picks evaluations, so it gates here, before the draw; every
     * sample of this call follows from the same number. */
    if (!chaos_policy_every_ok(&rule->policy, chaos_time_rule_draw_begin(rule)))
    {
        return 0;
    }
    if (!chaos_time_probability_hit_sample(
            rule->probability, chaos_time_rule_draw(rule, CHAOS_TIME_DRAW_PROBABILITY)
        ))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/**
 * @copydoc chaos_time_rule_apply_latency
 *
 * One firing decision per call, before the first chunk.
 */
void chaos_time_rule_apply_latency(chaos_time_rule_t *rule)
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
int chaos_time_rule_apply_errno(chaos_time_rule_t *rule)
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
 */
void chaos_time_rule_apply_offset(chaos_time_rule_t *rule, struct timespec *value)
{
    if (rule == NULL || value == NULL || rule->effect != CHAOS_TIME_EFFECT_OFFSET ||
        !chaos_time_rule_should_trigger(rule))
    {
        return;
    }

    chaos_time_add_offset_ms(value, rule->offset_ms);
}

/**
 * @copydoc chaos_time_rule_apply_regress
 *
 * slot->state: 0 fresh -> 1 armed on the first read (left real); 1 -> 3 by CAS while
 * one thread decides; 3 -> 2 when the rule fires (the jump, one hit) or 3 -> 1 when it
 * does not; in 2 every read is shifted. A read that meets state 3 on another thread is
 * not shifted. The atfork child handler turns an inherited 3 back into 1.
 */
void chaos_time_rule_apply_regress(chaos_time_rule_t *rule, struct timespec *value)
{
    chaos_hit_slot_t *slot;

    if (rule == NULL || value == NULL || rule->effect != CHAOS_TIME_EFFECT_REGRESS ||
        rule->hit == NULL || !chaos_hit_slot_current(rule->hit, rule->hit_generation))
    {
        return;
    }
    /* Outside its @from/@until window, or before its `@at` delay has passed, the rule
     * shifts nothing -- before or after the jump. */
    if (!chaos_policy_window_open(&rule->policy) || !chaos_policy_at_ok(&rule->policy, rule->hit))
    {
        return;
    }
    slot = rule->hit;
    if (slot->state == 0U)
    {
        (void)__sync_bool_compare_and_swap(&slot->state, 0U, 1U);
        return;
    }
    if (slot->state != 2U)
    {
        /* Exactly one thread decides the jump (state 3 while it does), so the jump
         * is counted once; a concurrent read is not shifted yet. */
        if (!__sync_bool_compare_and_swap(&slot->state, 1U, 3U))
        {
            return;
        }
        if (!chaos_time_rule_should_trigger(rule))
        {
            slot->state = 1U;
            return;
        }
        slot->state = 2U;
    }
    chaos_time_add_offset_ms(value, -rule->offset_ms);
}

/** @brief Nanoseconds per second, for packing a reading into the slot's state word. */
#define CHAOS_TIME_NS_PER_SEC UINT64_C(1000000000)

/**
 * @brief Marks the slot's state word as a frozen reading rather than a REGRESS state.
 *
 * @details The top bit, which no clock reaches: 2^63 ns is 292 years of uptime, and the
 * kernel rejects a realtime value that large. It is not decoration. REGRESS keeps a small
 * state machine (0, 1, 2, 3) in the same word, and chaos_hits_pool_after_fork() rewrites a
 * 3 to a 1 for it; a plain `nanoseconds + 1` would alias that at a reading of 2 ns, which
 * CLOCK_PROCESS_CPUTIME_ID produces at the start of a process. The mark keeps a frozen
 * reading out of every value the other effect's machine uses.
 */
#define CHAOS_TIME_FREEZE_MARK (UINT64_C(1) << 63)

/**
 * @copydoc chaos_time_rule_apply_freeze
 *
 * slot->state holds the frozen reading in nanoseconds with CHAOS_TIME_FREEZE_MARK set, so a
 * cleared mark means "not frozen" for any reading, including 0. One CAS decides which
 * concurrent reader's value is kept; the losers read the winner's, so every thread sees the
 * same frozen time.
 */
void chaos_time_rule_apply_freeze(chaos_time_rule_t *rule, struct timespec *value)
{
    chaos_hit_slot_t *slot;
    uint64_t frozen;

    if (rule == NULL || value == NULL || rule->effect != CHAOS_TIME_EFFECT_FREEZE ||
        rule->hit == NULL || !chaos_hit_slot_current(rule->hit, rule->hit_generation))
    {
        return;
    }
    /* Outside its @from/@until window, or before its `@at` delay has passed, the rule
     * stops nothing -- before or after the freeze. */
    if (!chaos_policy_window_open(&rule->policy) || !chaos_policy_at_ok(&rule->policy, rule->hit))
    {
        return;
    }
    slot = rule->hit;
    frozen = slot->state;
    if ((frozen & CHAOS_TIME_FREEZE_MARK) == 0U)
    {
        if (!chaos_time_rule_should_trigger(rule))
        {
            return;
        }
        (void)__sync_bool_compare_and_swap(
            &slot->state,
            frozen,
            ((uint64_t)value->tv_sec * CHAOS_TIME_NS_PER_SEC + (uint64_t)value->tv_nsec) |
                CHAOS_TIME_FREEZE_MARK
        );
        frozen = slot->state;
    }
    frozen &= ~CHAOS_TIME_FREEZE_MARK;
    value->tv_sec = (time_t)(frozen / CHAOS_TIME_NS_PER_SEC);
    value->tv_nsec = (long)(frozen % CHAOS_TIME_NS_PER_SEC);
}

/**
 * @copydoc chaos_time_rule_unshift_deadline
 *
 * The program read now + O under OFFSET and now - R after a REGRESS jump, so its
 * deadline is O ahead of and R behind the real one: subtract O, add R.
 */
int chaos_time_rule_unshift_deadline(
    const chaos_time_rule_t *offset_rule,
    const chaos_time_rule_t *regress_rule,
    struct timespec *deadline
)
{
    int changed = 0;

    /* Every qualifier that can make the shift apply to some reads and not others has to
     * be absent, because this subtraction is unconditional: a deadline the program worked
     * out from a shifted clock is only shifted if the clock really was. `@every` and
     * `@at` are the two this list was missing -- with `@at=+60000` no read was shifted for
     * the first minute while every absolute clock_nanosleep had the offset taken off its
     * deadline anyway, so it woke at once and a loop sleeping absolutely spun. */
    if (offset_rule != NULL && offset_rule->effect == CHAOS_TIME_EFFECT_OFFSET &&
        offset_rule->probability >= 1.0 && offset_rule->policy.first == 0U &&
        offset_rule->policy.every == 0U && offset_rule->policy.at_ms == 0U &&
        !offset_rule->policy.has_size_above && !offset_rule->policy.has_size_below &&
        chaos_policy_window_open(&offset_rule->policy))
    {
        chaos_time_add_offset_ms(deadline, -offset_rule->offset_ms);
        changed = 1;
    }
    if (regress_rule != NULL && regress_rule->effect == CHAOS_TIME_EFFECT_REGRESS &&
        regress_rule->hit != NULL &&
        chaos_hit_slot_current(regress_rule->hit, regress_rule->hit_generation) &&
        regress_rule->hit->state == 2U && regress_rule->policy.every == 0U &&
        regress_rule->policy.at_ms == 0U && chaos_policy_window_open(&regress_rule->policy))
    {
        chaos_time_add_offset_ms(deadline, regress_rule->offset_ms);
        changed = 1;
    }
    return changed;
}
