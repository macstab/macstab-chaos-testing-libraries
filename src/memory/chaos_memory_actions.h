/**
 * @file chaos_memory_actions.h
 * @brief Turns a matched libchaos-memory rule into its effect: the firing
 *        decision, LATENCY and ERRNO.
 *
 * @details
 * Sits between rule matching (chaos_memory_config.h) and the wrappers
 * (chaos_memory_hooks.c). Every wrapper runs two independent passes, LATENCY
 * first, so one call can be both delayed and failed:
 *
 * @code
 *   chaos_memory_rule_t rule;
 *   if (chaos_memory_config_match(CHAOS_MEMORY_EFFECT_LATENCY, op, flags, &rule)) {
 *       chaos_memory_rule_apply_latency(&rule);
 *   }
 *   if (chaos_memory_config_match(CHAOS_MEMORY_EFFECT_ERRNO, op, flags, &rule) &&
 *       chaos_memory_rule_apply_errno(&rule)) {
 *       return MAP_FAILED;  // -1 for munmap/mprotect/madvise
 *   }
 *   return real_function(...);
 * @endcode
 *
 * (The wrappers also store the call's length in rule.call_size for `@size`.)
 *
 * @par Thread and signal safety
 * Lock-free and allocation-free; the PRNG is thread-local; the sleep is a raw
 * system call that enters no wrapper.
 *
 * @par Stability
 * Internal.
 */
#ifndef CHAOS_MEMORY_ACTIONS_H
#define CHAOS_MEMORY_ACTIONS_H

#include "chaos_memory_config.h"

/**
 * @brief Bernoulli trial of @p probability with a caller-supplied sample; the
 *        deterministic core of chaos_memory_probability_hit(), exposed for tests.
 *
 * @details Fires when @p sample < @p probability * 2^32. Exact for probabilities
 * that are multiples of 2^-32; otherwise off by at most one sample value
 * (2^-32) from rounding.
 *
 * @param probability  Probability; <= 0.0 never fires, >= 1.0 always fires.
 * @param sample       Value uniform in [0, 2^32), normally chaos_memory_prng_next_u32().
 * @return 1 if the trial fires, 0 otherwise.
 */
int chaos_memory_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Bernoulli trial of @p probability with the next value of this thread's PRNG.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @return 1 if the trial fires, 0 otherwise.
 */
int chaos_memory_probability_hit(double probability);

/**
 * @brief Decides whether @p rule fires on this call; counts the hit when it does.
 *
 * @details In order: `@from`/`@until` window open, `@size` gate passed for
 * rule->call_size, PRNG draw below rule->probability, then chaos_policy_fire()
 * grants an `@first` slot and increments the rule's hit counter. A rule that has
 * left the active snapshot (stale hit_generation) does not fire.
 *
 * @param rule  Matched rule copy; NULL returns 0.
 * @return 1 if the rule fires, 0 otherwise.
 */
int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule);

/**
 * @brief Sleeps rule->latency_ms milliseconds if @p rule is a LATENCY rule that fires.
 *
 * @details The sleep is chaos_sleep_ms() (src/common/chaos_sleep.h): a raw
 * clock_nanosleep on CLOCK_MONOTONIC, restarted on EINTR, so the full delay
 * elapses, errno is preserved, and libchaos-time cannot shorten or lengthen it.
 * The real function is always called afterwards.
 *
 * @param rule  Matched rule copy; no-op if NULL, not LATENCY, or not firing.
 */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule);

/**
 * @brief Sets errno to rule->errnum if @p rule is an ERRNO rule that fires.
 *
 * @details The caller returns its failure value without calling the real function:
 * MAP_FAILED for mmap(); -1 for munmap(), mprotect() and madvise();
 * posix_madvise() returns the error number and restores errno.
 *
 * @param rule  Matched rule copy; no-op if NULL, not ERRNO, or not firing.
 * @return 1 if errno was set and the call must fail, 0 otherwise (errno untouched).
 */
int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule);

#endif
