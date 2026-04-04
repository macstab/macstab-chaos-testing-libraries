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

/*
 * Evaluates whether a raw 32-bit sample falls inside a probability window.
 *
 * This is the deterministic form of probability evaluation and exists mainly so
 * tests can assert exact outcomes without depending on thread-local PRNG state.
 */
int chaos_io_probability_hit_sample(double probability, uint32_t sample);

/*
 * Evaluates whether the current call should trigger a probabilistic rule.
 *
 * Production code uses this helper when a matched rule is gated by probability
 * rather than being always-on.
 */
int chaos_io_probability_hit(double probability);

/*
 * Computes the shortened byte count for a torn write from an explicit sample.
 *
 * The helper maps a sample into the inclusive range `[1, requested]`, while
 * preserving `0` requests as `0`.
 */
size_t chaos_io_torn_count_sample(size_t requested, uint32_t sample);

/*
 * Computes the shortened byte count for a torn write in production.
 *
 * This is the hot-path wrapper around `chaos_io_torn_count_sample()`.
 */
size_t chaos_io_torn_count(size_t requested);

/*
 * Flips one chosen bit in a mutable buffer using explicit samples.
 *
 * Tests use this deterministic form to assert exact corruption behavior.
 */
void chaos_io_corrupt_buffer_sample(
    void *buffer,
    size_t size,
    uint32_t index_sample,
    uint32_t bit_sample);

/*
 * Corrupts one random bit in a read buffer.
 *
 * `CORRUPT` rules model silent data corruption after the real read or pread
 * succeeds.
 */
void chaos_io_corrupt_buffer(void *buffer, size_t size);

/*
 * Applies a blocking delay for a matched latency rule.
 *
 * The helper sleeps in bounded chunks until the configured delay has been fully
 * consumed.
 */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule);

/*
 * Decides whether a matched rule should actually trigger on this call.
 *
 * Latency rules are always-on; the remaining effect types are gated through the
 * probability helper.
 */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule);

/*
 * Applies an `ERRNO` rule by setting `errno` and signalling failure.
 *
 * Wrappers call this before touching the real libc symbol when a matched rule
 * is supposed to fail the operation outright.
 */
int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule);

#endif
