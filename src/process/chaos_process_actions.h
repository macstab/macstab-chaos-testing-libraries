/**
 * @file chaos_process_actions.h
 * @brief Effects of libchaos-process: the probability gate, LATENCY, ERRNO and
 *        FAIL_AFTER.
 *
 * @details
 * The wrappers match a rule per effect (chaos_process_config_match()) and hand it here;
 * these functions decide whether it fires on this call and what it does. A rule fires
 * only when its `@from`/`@until` window is open, its `@size` gate passes (never, in this
 * library: no wrapper passes a byte count), its probability draw hits and its `@first`
 * budget has room (chaos_policy.h); a firing counts one hit. Draws use the calling
 * thread's xorshift64* PRNG: no lock, no shared state.
 */

#ifndef CHAOS_PROCESS_ACTIONS_H
#define CHAOS_PROCESS_ACTIONS_H

#include "chaos_process_config.h"

/**
 * @brief Whether a draw @p sample hits @p probability: `sample < probability * 2^32`.
 *
 * probability <= 0 never hits and >= 1 always hits, without the multiply. Separate
 * from the draw so unit tests can pass a chosen sample.
 *
 * @param probability Probability in [0.0, 1.0].
 * @param sample      Uniform value in [0, 2^32).
 * @return Non-zero on a hit.
 */
int chaos_process_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief chaos_process_probability_hit_sample() with one draw from the calling thread's
 *        PRNG (drawn even when @p probability is 0 or 1).
 *
 * @param probability Probability in [0.0, 1.0].
 * @return Non-zero on a hit.
 */
int chaos_process_probability_hit(double probability);

/**
 * @brief Whether @p rule fires on this call: window open, size gate passed, probability
 *        hit, then an `@first` claim; a firing counts one hit.
 *
 * @param rule Rule; NULL returns 0.
 * @return Non-zero when the rule fires.
 */
int chaos_process_rule_should_trigger(const chaos_process_rule_t *rule);

/**
 * @brief Sleeps `rule->latency_ms` if @p rule is a LATENCY rule that fires.
 *
 * Uses chaos_sleep_ms() (src/common/chaos_sleep.h): a direct clock_nanosleep system call
 * on CLOCK_MONOTONIC, restarted with the remaining time on EINTR, so the full delay
 * elapses, errno is preserved and no other preloaded library (libchaos-time) can
 * shorten or lengthen it. Blocks the calling thread only.
 *
 * @param rule Rule; NULL, another effect or no firing does nothing.
 */
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule);

/**
 * @brief Reports `rule->errnum` if @p rule is an ERRNO rule that fires.
 *
 * @param rule   Rule; NULL or another effect returns 0.
 * @param errnum Receives the error; NULL returns 0.
 * @return Non-zero when the rule fired and *errnum was set.
 */
int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum);

/**
 * @brief Advances the FAIL_AFTER counter of @p operation and reports `rule->errnum`
 *        once N = rule->fail_after_count calls have gone through.
 *
 * The counter is incremented first (`__sync_fetch_and_add`) on every call that gets
 * here, whatever the outcome. The rule fires when the pre-increment value is >= N, the
 * probability draw hits, the window is open, the size gate passes and an `@first` claim
 * succeeds. With probability < 1, failures after the threshold are intermittent. Calls
 * 1..N never fail; N = 0 fails from the first call. See
 * g_chaos_process_fail_after_counters for sharing and reset.
 *
 * @param rule      Rule; NULL or another effect returns 0.
 * @param operation Counter index; out of range returns 0.
 * @param errnum    Receives the error; NULL returns 0.
 * @return Non-zero when the rule fired and *errnum was set.
 */
int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
);

#endif
