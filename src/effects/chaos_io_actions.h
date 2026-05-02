/**
 * @file chaos_io_actions.h
 * @brief Fault-effect helper declarations used after a rule has already matched.
 *
 * @details
 * After the wrapper layer selects a matching rule it delegates to this module
 * for all effect execution.  Separating "decide whether to fire" from "what
 * the syscall interposers do" keeps each layer auditable in isolation and
 * makes the effect helpers independently testable.
 *
 * **Effect classes and their hot-path characteristics:**
 * - `ERRNO`: pre-call, sets `errno` and returns -1 without touching libc.
 *   Always gated by probability.
 * - `LATENCY`: pre-call, blocking sleep for `rule->latency_ms` ms.
 *   Always fires (probability == 1 is implied); the sleep is the effect.
 * - `TORN`: pre-call byte-count reduction for write operations.
 *   Gated by probability.  The shortened count is passed to the real libc
 *   call, which makes the partial write visible to callers that check the
 *   return value.
 * - `CORRUPT`: post-call single-bit flip in the read buffer.
 *   Gated by probability.  Applied only when the real call returned > 0
 *   bytes.
 *
 * **Testability design.**
 * Every stateful helper (probability check, torn count, buffer corruption)
 * has a `_sample` sibling that accepts explicit PRNG values instead of
 * drawing from the thread-local state.  This lets unit tests assert exact
 * outcomes without manipulating TLS or relying on PRNG sequences.
 *
 * **Module ownership:** effects/
 * **Stability:** internal – not part of any public ABI
 * **Thread-safety:** all functions operate on thread-local PRNG state and
 * caller-owned buffers; they are safe to call concurrently from different
 * threads.
 * **Blocking:** `chaos_io_rule_apply_latency()` blocks the calling thread.
 *   All other functions return without sleeping.
 */

#ifndef CHAOS_IO_ACTIONS_H
#define CHAOS_IO_ACTIONS_H

/*
 * Fault-effect helper declarations used after a rule has already matched.
 *
 * The wrapper layer stays smaller and easier to audit when probability checks,
 * torn-write sizing, corruption, and latency behavior all live in one focused
 * module.
 */

#include "chaos_io_config.h"

/**
 * @brief Evaluates whether a raw 32-bit sample falls inside a probability window.
 *
 * @details Converts `probability` to a threshold over the full `uint32_t`
 * range (`threshold = probability * 2^32`) and returns non-zero when
 * `(double)sample < threshold`.  The comparison is done in floating-point to
 * match the precision of the probability value without introducing integer
 * rounding artifacts.
 *
 * This is the deterministic form of probability evaluation and exists mainly so
 * tests can assert exact outcomes without depending on thread-local PRNG state.
 *
 * @param[in] probability  Trigger probability in [0.0, 1.0].
 *                         Values ≤ 0.0 always return 0; values ≥ 1.0 always
 *                         return 1.
 * @param[in] sample       Raw 32-bit value from a PRNG or test fixture.
 * @return Non-zero when the rule should trigger; zero otherwise.
 */
int chaos_io_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Evaluates whether the current call should trigger a probabilistic rule.
 *
 * @details Draws the next 32-bit sample from the thread-local PRNG via
 * `chaos_io_prng_next_u32()` and delegates to
 * `chaos_io_probability_hit_sample()`.  Production code uses this helper when
 * a matched rule is gated by probability rather than being always-on.
 *
 * @param[in] probability  Trigger probability in [0.0, 1.0].
 * @return Non-zero when the PRNG sample lands within the probability window.
 */
int chaos_io_probability_hit(double probability);

/**
 * @brief Computes the shortened byte count for a torn write from an explicit sample.
 *
 * @details A torn write must always be strictly shorter than the original
 * request to be meaningful.  The semantics are:
 * - `requested == 0`: returns 0 (no-op).
 * - `requested == 1`: returns 1 (cannot go shorter; single-byte write is
 *   already atomic on all POSIX targets).
 * - `requested > 1`: maps `sample` into `[1, requested - 1]` via
 *   `sample % (requested - 1) + 1`.
 *
 * The helper preserves `0` requests as `0`, returns `1` for single-byte
 * requests, and otherwise maps a sample into the inclusive range
 * `[1, requested - 1]` so a torn write always stays partial.
 *
 * @param[in] requested  Original byte count requested by the caller.
 * @param[in] sample     32-bit PRNG sample used for sizing.
 * @return Shortened byte count guaranteed to be ≤ `requested`.
 */
size_t chaos_io_torn_count_sample(size_t requested, uint32_t sample);

/**
 * @brief Computes the shortened byte count for a torn write in production.
 *
 * @details This is the hot-path wrapper around `chaos_io_torn_count_sample()`.
 * Draws one 32-bit sample from the thread-local PRNG and returns the result.
 *
 * @param[in] requested  Original byte count requested by the caller.
 * @return Shortened byte count guaranteed to be ≤ `requested`.
 */
size_t chaos_io_torn_count(size_t requested);

/**
 * @brief Flips one chosen bit in a mutable buffer using explicit samples.
 *
 * @details Selects byte index `index_sample % size` and flips bit
 * `bit_sample & 7` within that byte.  Both samples are independent so that
 * the byte index and the bit position within it are drawn from separate PRNG
 * values.
 *
 * No-op when `buffer == NULL` or `size == 0`.
 *
 * Tests use this deterministic form to assert exact corruption behavior.
 *
 * @param[in,out] buffer       Mutable byte buffer to corrupt.  May be NULL.
 * @param[in]     size         Byte length of `buffer`.
 * @param[in]     index_sample 32-bit sample used to select the target byte.
 * @param[in]     bit_sample   32-bit sample used to select the target bit
 *                             within the chosen byte.
 */
void chaos_io_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
);

/**
 * @brief Corrupts one random bit in a read buffer.
 *
 * @details `CORRUPT` rules model silent data corruption after the real read or
 * pread succeeds.  Draws two independent 32-bit samples from the thread-local
 * PRNG before calling `chaos_io_corrupt_buffer_sample()`.
 *
 * The two samples are captured into local variables before the call to avoid
 * depending on C function-argument evaluation order, which is unspecified.
 * Without the explicit captures, the compiler is free to evaluate the two
 * `chaos_io_prng_next_u32()` calls in either order, producing different byte
 * and bit selections depending on the platform.
 *
 * @param[in,out] buffer  Mutable read buffer returned from the real syscall.
 *                        May be NULL (no-op).
 * @param[in]     size    Number of valid bytes in `buffer`.
 */
void chaos_io_corrupt_buffer(void *buffer, size_t size);

/**
 * @brief Applies a blocking delay for a matched latency rule.
 *
 * @details Sleeps in bounded chunks of at most one second (`usleep` accepts at
 * most 999999 µs on many implementations; the loop uses 1 000 000 µs as the
 * per-chunk cap because `useconds_t` on Linux is at least 32 bits and the
 * POSIX maximum is explicitly 1 000 000 µs).  Looping avoids the risk of an
 * overflowed `useconds_t` on platforms where the type is narrower than the
 * configured delay.
 *
 * No-op when `rule == NULL` or `rule->effect != CHAOS_IO_EFFECT_LATENCY`.
 *
 * @param[in] rule  The matched latency rule.  May be NULL.
 *
 * @note This function blocks the calling thread.  It does not enter internal
 *       mode, so `usleep` calls are visible to the reentrancy guard if `usleep`
 *       is ever interposed.  `usleep` is not currently interposed.
 */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule);

/**
 * @brief Decides whether a matched rule should actually trigger on this call.
 *
 * @details Latency rules are always-on (every matched call is delayed); the
 * remaining effect types are gated through the probability helper.
 *
 * @param[in] rule  The matched rule.  May be NULL.
 * @return Non-zero when the effect should be applied; zero when the call
 *         should proceed without injection despite a rule match.
 */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule);

/**
 * @brief Applies an `ERRNO` rule by setting `errno` and signalling failure.
 *
 * @details Wrappers call this before touching the real libc symbol when a
 * matched rule is supposed to fail the operation outright.  The function
 * combines the trigger-probability check and the `errno` assignment in one
 * call.
 *
 * @param[in] rule  The matched rule.  May be NULL.
 * @return Non-zero when the wrapper should return -1 to the caller (errno has
 *         been set to `rule->errnum`); zero when the rule did not trigger.
 *
 * @post When returning non-zero: `errno == rule->errnum`.
 * @note Returns 0 without modifying `errno` when `rule->effect` is not
 *       `CHAOS_IO_EFFECT_ERRNO`.
 */
int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule);

#endif
