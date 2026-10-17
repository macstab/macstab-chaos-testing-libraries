/**
 * @file chaos_time_actions.h
 * @brief Effect execution for libchaos-time: the firing decision, LATENCY, ERRNO,
 *        OFFSET, REGRESS and the TIMER_ABSTIME deadline correction.
 *
 * @details
 * The wrappers (chaos_time_hooks.c) select one rule per effect and hand each copy to
 * the matching function here, in this order:
 *
 * | Step | Function                          | When                                   |
 * |------|-----------------------------------|----------------------------------------|
 * | 1    | chaos_time_rule_apply_latency()   | before the real call                   |
 * | 2    | chaos_time_rule_apply_errno()     | before; on 1 the real call is skipped  |
 * | 3    | chaos_time_rule_apply_offset()    | after a successful clock read          |
 * | 4    | chaos_time_rule_apply_regress()   | after a successful clock read          |
 *
 * Every apply function makes its own firing decision (chaos_time_rule_should_trigger():
 * `@from`/`@until` window, `@size` gate, probability draw, `@first` claim and hit count),
 * so each effect of one call fires independently. All are thread-safe and lock-free;
 * none changes errno except apply_errno, whose purpose that is.
 *
 * @module chaos-time
 * @stability Internal.
 */

#ifndef CHAOS_TIME_ACTIONS_H
#define CHAOS_TIME_ACTIONS_H

#include "chaos_time_config.h"

/**
 * Whether @p sample falls below probability * 2^32.
 *
 * probability <= 0 never fires and >= 1 always fires, whatever the sample. Pure;
 * separated from the draw so tests can pass exact samples.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @param sample       Uniform value in [0, 2^32).
 * @return             Non-zero when it fires.
 */
int chaos_time_probability_hit_sample(double probability, uint32_t sample);

/**
 * Draws from the calling thread's PRNG and tests @p probability.
 *
 * Always advances the stream, also for probability 0 or 1.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @return             Non-zero when it fires.
 */
int chaos_time_probability_hit(double probability);

/**
 * The full firing decision for one call: window, size gate, probability, `@first`.
 *
 * In order: the `@from`/`@until` window is open, the call's size passes any `@size`
 * gate, the probability draw fires, and chaos_policy_fire() admits it (the rule is
 * still current, an `@first` claim is available). A firing is counted as one hit.
 *
 * @param rule  Rule copy; NULL returns 0.
 * @return      Non-zero when the effect is to be applied now.
 */
int chaos_time_rule_should_trigger(const chaos_time_rule_t *rule);

/**
 * LATENCY: sleeps rule->latency_ms before the real call, if the rule fires.
 *
 * Sleeps in chunks of at most 1 s through the real usleep (the real nanosleep if usleep
 * is unresolved; nothing if neither is), with the guard raised so no wrapper of this
 * library sees the sleep. POSIX only requires useconds_t to hold [0, 1000000], hence
 * the chunking. errno is preserved. A signal can cut a usleep chunk short, so the total
 * delay may be shorter than configured; the nanosleep fallback restarts on EINTR.
 *
 * @param rule  Rule copy; NULL or a non-LATENCY rule does nothing.
 */
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule);

/**
 * ERRNO: sets errno = rule->errnum if the rule fires.
 *
 * @param rule  Rule copy; NULL or a non-ERRNO rule returns 0.
 * @return      Non-zero when errno was set and the wrapper must fail the call without
 *              calling the real function.
 */
int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule);

/**
 * OFFSET: adds rule->offset_ms to @p value if the rule fires.
 *
 * Applied to the time the real function returned; the kernel clock is untouched. The
 * decision is made per read and per thread without state, so a rule with probability
 * below 1 (or a reload between reads) makes successive reads of CLOCK_MONOTONIC jump
 * backwards and forwards: the intended fault. A result before the epoch is clamped to
 * {0, 0}; tv_nsec always stays in [0, 999999999].
 *
 * @param rule   Rule copy; NULL or a non-OFFSET rule does nothing.
 * @param value  Time to shift in place; NULL does nothing.
 */
void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value);

/**
 * REGRESS: steps the clock back by rule->offset_ms once, then keeps it shifted.
 *
 * The first read under the rule stays real (so the program has a time to go back
 * from); the first later read where the rule fires jumps back and counts one hit;
 * every read after that is shifted without a new decision, so the clock advances
 * again from the earlier time. The state lives in the rule's hit slot: per process,
 * kept across reloads that keep the rule's text, reset in a forked child. A rule copy
 * without a current slot does nothing; outside the `@from`/`@until` window nothing is
 * shifted, before or after the jump.
 *
 * @param rule   Rule copy; NULL or a non-REGRESS rule does nothing.
 * @param value  Time to shift in place; NULL does nothing.
 */
void chaos_time_rule_apply_regress(const chaos_time_rule_t *rule, struct timespec *value);

/**
 * Maps a TIMER_ABSTIME deadline from the program's shifted clock back to the real one.
 *
 * The program computed the deadline from a clock shifted by OFFSET and REGRESS; the
 * kernel waits on the real clock. Only shifts that every read carries are undone, so
 * the correction is exact: an OFFSET rule that fires on every read (probability >= 1,
 * no `@first`, no `@size`, window open) and a REGRESS rule that has jumped (window
 * open). Nothing is drawn, counted or claimed. A result before the epoch is clamped to
 * {0, 0}.
 *
 * @param offset_rule   OFFSET rule of the deadline's clock, or NULL.
 * @param regress_rule  REGRESS rule of the deadline's clock, or NULL.
 * @param deadline      Deadline to convert in place.
 * @return 1 when @p deadline was changed, 0 when it stays as it is.
 */
int chaos_time_rule_unshift_deadline(
    const chaos_time_rule_t *offset_rule,
    const chaos_time_rule_t *regress_rule,
    struct timespec *deadline
);

#endif
