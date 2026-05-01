/**
 * @file chaos_net_actions.h
 * @brief Fault-injection primitives: probability sampling, buffer corruption, latency, errno
 * injection.
 *
 * @details
 * This module provides the leaf-level operations that the interposition wrappers invoke
 * after a rule has been matched. Every function in this module is stateless with respect
 * to shared memory: probability samples draw from the per-thread PRNG, buffer corruption
 * operates on caller-supplied memory, and latency injection uses usleep.
 *
 * The module deliberately exposes both "raw sample" variants (taking an explicit
 * uint32_t random value) and "live" variants (calling the PRNG internally). The raw
 * variants enable deterministic unit testing without mocking the PRNG.
 *
 * @par Design constraints:
 *   - No heap allocation.
 *   - No global mutable state beyond the per-thread PRNG (defined in chaos_net_internal.h).
 *   - All functions are safe to call from the hot interposition path.
 *   - chaos_net_corrupt_buffer / chaos_net_corrupt_buffer_sample: exactly one bit is flipped
 *     per call. The bit is chosen by (index_sample % size) for the byte and (bit_sample & 7)
 *     for the bit within the byte. This is intentionally minimal — flipping a single bit is
 *     enough to exercise error-detection code paths without destroying all data.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#ifndef CHAOS_NET_ACTIONS_H
#define CHAOS_NET_ACTIONS_H

#include "chaos_net_config.h"

/**
 * @brief Tests whether a given probability value fires for a specific pre-drawn sample.
 *
 * @details Converts the probability to a fixed-point threshold over [0, 2^32) and
 * compares against @p sample. The mapping is:
 * @code
 *   threshold = probability * 4294967296.0   (= probability * 2^32)
 *   fires     = (double)sample < threshold
 * @endcode
 * This gives a uniform distribution: a sample drawn uniformly from [0, 2^32) falls
 * below the threshold with probability exactly equal to @p probability (to floating-
 * point precision). Edge cases: probability <= 0.0 always returns 0; probability >= 1.0
 * always returns 1 (short-circuits before the comparison).
 *
 * The separate-sample form exists for reproducible testing: the caller can supply
 * a deterministic value to verify boundary conditions without affecting the live PRNG.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @param sample       Pre-drawn uint32_t sample to test against the threshold.
 * @return Non-zero if the sample falls within the threshold (event fires); 0 otherwise.
 * @par Thread-safety: no shared state; safe.
 */
int chaos_net_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Tests whether a probability fires by drawing a fresh PRNG sample.
 *
 * @details Calls chaos_net_prng_next_u32() to obtain a sample from the calling
 * thread's PRNG stream, then delegates to chaos_net_probability_hit_sample().
 * Advances the thread's PRNG state by one step.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @return Non-zero if the event fires; 0 otherwise.
 * @par Thread-safety: reads/writes per-thread PRNG state; safe.
 */
int chaos_net_probability_hit(double probability);

/**
 * @brief Flips one bit in a buffer using pre-drawn samples.
 *
 * @details Computes the byte index as `index_sample % size` and the bit position
 * as `bit_sample & 7`. XORs the byte at that index with `(1 << bit_position)`.
 * This is a uniform selection over all bit positions in the buffer: given uniform
 * index_sample and bit_sample, each of the `size * 8` bits is equally likely to
 * be flipped.
 *
 * The raw-sample form allows the caller to supply deterministic values for testing.
 * Production callers should use chaos_net_corrupt_buffer() instead.
 *
 * @param buffer        Buffer to corrupt in place. May be NULL (no-op).
 * @param size          Length of @p buffer in bytes. Must be > 0 for any effect.
 * @param index_sample  Pre-drawn sample for byte selection. Reduced modulo @p size.
 * @param bit_sample    Pre-drawn sample for bit selection. Only bits 2:0 are used.
 * @par Thread-safety: no shared state; safe.
 */
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
);

/**
 * @brief Flips one bit in a buffer by drawing two fresh PRNG samples.
 *
 * @details Calls chaos_net_prng_next_u32() twice to obtain the byte-index sample
 * and bit-position sample, then delegates to chaos_net_corrupt_buffer_sample().
 * Advances the calling thread's PRNG state by two steps.
 *
 * Used by recv(), recvfrom(), and recvmsg() after a successful real recv call
 * when a CORRUPT rule fires.
 *
 * @param buffer  Buffer to corrupt in place. May be NULL (no-op).
 * @param size    Length of @p buffer in bytes. If 0, the call is a no-op.
 * @par Thread-safety: reads/writes per-thread PRNG state; safe.
 */
void chaos_net_corrupt_buffer(void *buffer, size_t size);

/**
 * @brief Introduces a blocking delay for the duration specified in a LATENCY rule.
 *
 * @details Calls usleep() in a loop, sleeping in chunks of at most 1 second
 * (1,000,000 µs) to avoid the implementation-defined behaviour of usleep()
 * for values >= 1,000,000 on some platforms. The loop handles the case where
 * usleep() is interrupted by a signal (EINTR): the remaining time is recalculated
 * from the original total on each iteration, so signal delivery does not reduce
 * the injected delay below rule->latency_ms.
 *
 * The function is a no-op if @p rule is NULL or rule->effect != CHAOS_NET_EFFECT_LATENCY.
 * Latency rules always fire (no probability check); the "should this fire" decision is
 * made by chaos_net_rule_should_trigger(), which returns 1 unconditionally for LATENCY.
 *
 * @param rule  Matched rule with effect == LATENCY. May be NULL (no-op).
 * @par Thread-safety: usleep is per-thread; safe.
 * @par Blocking: always blocks for approximately rule->latency_ms milliseconds.
 */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule);

/**
 * @brief Determines whether a matched rule should fire on this invocation.
 *
 * @details LATENCY rules always fire (they are deterministic delays, not random
 * failures). All other effect types (ERRNO, CORRUPT, TIMEOUT) sample their
 * probability field via chaos_net_probability_hit().
 *
 * This function is used by both the latency path (to confirm the effect type
 * before sleeping) and by the CORRUPT/TIMEOUT paths to decide whether to apply
 * the post-call modification.
 *
 * @param rule  Matched rule to evaluate. May be NULL (returns 0).
 * @return Non-zero if the rule should fire on this call; 0 otherwise.
 * @par Thread-safety: see chaos_net_probability_hit(); safe.
 */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule);

/**
 * @brief Applies an ERRNO rule: if the rule fires, sets errno and returns non-zero.
 *
 * @details Calls chaos_net_rule_should_trigger() to sample the probability. If it
 * fires, sets errno to rule->errnum and returns 1. If it does not fire or the rule
 * is not an ERRNO rule, returns 0 without modifying errno.
 *
 * The interposed wrappers use the return value to decide whether to return -1
 * immediately (skipping the real syscall) or to proceed. Example:
 * @code
 *   if (chaos_net_rule_apply_errno(&rule)) return -1;
 *   return g_chaos_net_real_connect(...);
 * @endcode
 *
 * @param rule  Matched rule with effect == ERRNO. May be NULL (returns 0).
 * @return 1 if the error was injected (errno is set); 0 if not injected.
 * @post If returns 1: errno == rule->errnum.
 * @post If returns 0: errno is unchanged.
 * @par Thread-safety: errno is per-thread on POSIX; safe.
 */
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule);

#endif
