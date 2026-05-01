/**
 * @file chaos_memory_actions.h
 * @brief Public interface for probabilistic fault-injection actions in
 *        libchaos-memory.
 *
 * @details
 * This header declares the functions that translate a matched
 * chaos_memory_rule_t into an observable effect (errno injection or latency).
 * It sits between the config matching layer (chaos_memory_config.h) and the
 * hook wrappers (chaos_memory_hooks.c).
 *
 * The four functions form a deliberate two-step pattern used by every hook:
 *
 * @code
 *   chaos_memory_rule_t rule;
 *   if (chaos_memory_config_match(CHAOS_MEMORY_EFFECT_LATENCY, op, flags, &rule)) {
 *       chaos_memory_rule_apply_latency(&rule);   // may or may not sleep
 *   }
 *   if (chaos_memory_config_match(CHAOS_MEMORY_EFFECT_ERRNO, op, flags, &rule) &&
 *       chaos_memory_rule_apply_errno(&rule)) {
 *       return MAP_FAILED;  // or -1
 *   }
 *   return real_syscall(...);
 * @endcode
 *
 * chaos_memory_rule_should_trigger() encapsulates the probability check so
 * that both apply functions share the same probabilistic gate.  It is also
 * exposed here for unit testing.
 *
 * @par Thread safety
 * All functions are thread-safe.  Probability sampling reads the per-thread
 * TLS PRNG state (no synchronisation needed).  Sleep uses the reentrancy guard
 * to avoid recursive hook invocations through usleep/nanosleep.
 *
 * @par Stability
 * Internal — do not include from outside the memory chaos module.
 */
#ifndef CHAOS_MEMORY_ACTIONS_H
#define CHAOS_MEMORY_ACTIONS_H

#include "chaos_memory_config.h"

/**
 * @brief Test whether a probability value fires for a given 32-bit PRNG sample.
 *
 * @details
 * Maps the floating-point @p probability into the integer range [0, 2^32) by
 * multiplying by 4294967296.0 (== 2^32) and comparing @p sample against the
 * resulting threshold.  This gives an unbiased Bernoulli trial for any
 * probability representable as a fraction of 2^32, with no division and no
 * branch misprediction beyond the fast-path boundary checks.
 *
 * Edge cases:
 *  - probability <= 0.0: always returns 0 (never fires).
 *  - probability >= 1.0: always returns 1 (always fires).
 *  - Intermediate values produce exact results for multiples of 2^-32 and
 *    approximate results (IEEE 754 rounding) for arbitrary fractions.
 *
 * @param probability  Target probability in [0.0, 1.0].  Values outside this
 *                     range are clamped by the <= 0.0 and >= 1.0 guards.
 * @param sample       A uniformly distributed 32-bit value (typically from
 *                     chaos_memory_prng_next_u32()).
 * @return             1 if @p sample falls below the probability threshold,
 *                     0 otherwise.
 */
int chaos_memory_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Test whether a probability value fires, drawing a sample from the
 *        per-thread PRNG.
 *
 * @details
 * Calls chaos_memory_prng_next_u32() to obtain a fresh sample and passes it
 * to chaos_memory_probability_hit_sample().  This is the normal call path
 * used by chaos_memory_rule_should_trigger().  The sample-based variant is
 * exposed separately to allow deterministic unit testing.
 *
 * @param probability  Target probability in [0.0, 1.0].
 * @return             1 if the PRNG sample falls below the threshold, 0 otherwise.
 */
int chaos_memory_probability_hit(double probability);

/**
 * @brief Determine whether a matched rule should fire on this specific call.
 *
 * @details
 * Evaluates rule->probability against a fresh PRNG draw.  Returns 0
 * immediately if @p rule is NULL.
 *
 * Used internally by chaos_memory_rule_apply_latency() and
 * chaos_memory_rule_apply_errno() to apply the probabilistic gate before
 * taking any observable action.
 *
 * @param rule  The matched rule.  May be NULL (returns 0).
 * @return      1 if the rule should fire this time, 0 otherwise.
 */
int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule);

/**
 * @brief Apply a LATENCY rule: sleep for rule->latency_ms milliseconds if
 *        the rule fires.
 *
 * @details
 * The sleep is performed as a series of up to 1-second chunks using the real
 * usleep(3) (preferred) or nanosleep(2) (fallback), always under the TLS
 * reentrancy guard.  Chunking prevents a single call from consuming more than
 * 1 second of PRNG-decided sleep per chunk without the guard, and handles
 * the EINTR restart requirement for nanosleep transparently.
 *
 * Does nothing if:
 *  - @p rule is NULL.
 *  - rule->effect != CHAOS_MEMORY_EFFECT_LATENCY.
 *  - The probability check (chaos_memory_rule_should_trigger) does not fire.
 *
 * The real syscall is always issued after this function returns — LATENCY does
 * not suppress the underlying operation.
 *
 * @param rule  The matched LATENCY rule.  No-op if NULL or wrong effect.
 */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule);

/**
 * @brief Apply an ERRNO rule: set errno and signal that the call should be
 *        short-circuited.
 *
 * @details
 * If the rule fires (chaos_memory_rule_should_trigger returns non-zero), sets
 * the calling thread's errno to rule->errnum and returns 1.  The caller is
 * responsible for returning the appropriate error sentinel:
 *  - mmap(2): MAP_FAILED ((void*)-1)
 *  - munmap(2), mprotect(2), madvise(2): -1
 *
 * Returns 0 (no-op) if:
 *  - @p rule is NULL.
 *  - rule->effect != CHAOS_MEMORY_EFFECT_ERRNO.
 *  - The probability check does not fire.
 *
 * @param rule  The matched ERRNO rule.  No-op if NULL or wrong effect.
 * @return      1 if errno was set and the call should be short-circuited,
 *              0 if the rule did not fire.
 */
int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule);

#endif
