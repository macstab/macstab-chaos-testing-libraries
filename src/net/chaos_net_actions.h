/**
 * @file chaos_net_actions.h
 * @brief Effect primitives: the firing decision, bit corruption, delay and errno injection.
 *
 * @details
 * The leaf operations a wrapper calls once it holds a matched rule copy. They keep no
 * shared state of their own: probability draws use the calling thread's PRNG, corruption
 * works on the caller's buffer, delays use chaos_sleep_ms(). The firing decision also
 * goes through the rule's qualifiers and hit slot (chaos_policy_fire()), which is where
 * hits are counted.
 *
 * Each randomised primitive has a `_sample` variant that takes the random values as
 * arguments, so unit tests can drive exact boundaries without controlling the PRNG.
 *
 * @par Constraints:
 *   - No heap allocation, no lock: callable on every wrapper's hot path and from signal
 *     handlers that reach a wrapper.
 *   - CORRUPT flips exactly one bit per firing: byte `index_sample % size`, bit
 *     `bit_sample & 7`. One bit is the smallest change a checksum, length check or parser
 *     must catch, and it leaves the rest of the payload intact for diagnosis.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#ifndef CHAOS_NET_ACTIONS_H
#define CHAOS_NET_ACTIONS_H

#include "chaos_net_config.h"

/**
 * @brief Whether @p probability fires for the pre-drawn 32-bit @p sample.
 *
 * @details Fixed-point comparison over [0, 2^32):
 * @code
 *   fires = (double)sample < probability * 4294967296.0
 * @endcode
 * A uniform sample fires with probability @p probability, to a resolution of 2^-32.
 * probability <= 0.0 never fires; probability >= 1.0 always fires, without comparing.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @param sample       Uniform 32-bit sample.
 * @return Non-zero if the event fires; 0 otherwise.
 * @par Thread-safety: pure function.
 */
int chaos_net_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Whether @p probability fires, drawing one sample from the thread's PRNG.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @return Non-zero if the event fires; 0 otherwise.
 * @par Thread-safety: advances only the calling thread's PRNG by one step.
 */
int chaos_net_probability_hit(double probability);

/**
 * @brief Flips one bit of @p buffer chosen by pre-drawn samples.
 *
 * @details Byte `index_sample % size`, bit `bit_sample & 7`. With uniform samples every
 * bit of the buffer is equally likely, up to the modulo bias of a 32-bit sample over
 * @p size (negligible below a few MiB). Production code uses chaos_net_corrupt_buffer().
 *
 * @param buffer        Buffer corrupted in place; NULL is a no-op.
 * @param size          Bytes of @p buffer that may be touched; 0 is a no-op.
 * @param index_sample  Sample for the byte, reduced modulo @p size.
 * @param bit_sample    Sample for the bit; only bits 2..0 are used.
 * @par Thread-safety: touches only @p buffer.
 */
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
);

/**
 * @brief Flips one bit of @p buffer, drawing two samples from the thread's PRNG.
 *
 * @details Used by recv, recvfrom and read after the real call returned data and a
 * CORRUPT rule fired; @p size is the byte count the call wrote, never the buffer size.
 *
 * @param buffer  Buffer corrupted in place; NULL is a no-op.
 * @param size    Bytes received; 0 is a no-op.
 * @par Thread-safety: advances only the calling thread's PRNG by two steps.
 */
void chaos_net_corrupt_buffer(void *buffer, size_t size);

/**
 * @brief Sleeps for a LATENCY rule's delay if the rule fires.
 *
 * @details No-op unless @p rule is a LATENCY rule and chaos_net_rule_should_trigger()
 * passes (window, `@size`, `@first`; there is no probability). The sleep is
 * chaos_sleep_ms() (src/common/chaos_sleep.h): a raw clock_nanosleep on CLOCK_MONOTONIC,
 * restarted on EINTR with the remaining time, so the full delay elapses, errno is
 * preserved, and no other preloaded library (libchaos-time in particular) can shorten or
 * stretch it.
 *
 * @param rule  Matched rule; NULL is a no-op.
 * @par Thread-safety: blocks only the calling thread.
 * @par Blocking: latency_ms milliseconds when the rule fires.
 */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule);

/**
 * @brief Decides whether a matched rule fires on this call, and counts the hit if so.
 *
 * @details Gates, in order: the `@from`/`@until` window, the `@size` gate against
 * rule->call_size, the probability (every effect except LATENCY), then
 * chaos_policy_fire(), which claims an `@first` slot, rejects a rule copy whose rule has
 * left the file, and counts the hit. Call it at most once per decision: each firing is
 * one hit.
 *
 * @param rule  Matched rule copy; NULL yields 0.
 * @return Non-zero if the effect is to be applied now; 0 otherwise.
 * @par Thread-safety: thread-local PRNG and atomic hit-slot updates.
 */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule);

/**
 * @brief Applies an ERRNO rule: sets errno and returns 1 when it fires.
 *
 * @details Wrappers return -1 at once on 1 and skip the real call:
 * @code
 *   if (chaos_net_rule_apply_errno(&rule)) return -1;
 *   return g_chaos_net_real_connect(...);
 * @endcode
 * A rule that is not ERRNO, or does not fire, leaves errno untouched.
 *
 * @param rule  Matched rule copy; NULL yields 0.
 * @return 1 if the error was injected; 0 otherwise.
 * @post Returns 1: errno == rule->errnum. Returns 0: errno unchanged.
 * @par Thread-safety: errno is thread-local.
 */
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule);

#endif
