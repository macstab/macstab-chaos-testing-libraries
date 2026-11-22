/**
 * @file chaos_io_actions.h
 * @brief libchaos-io effect decisions and effect primitives, applied after a wrapper has
 *        selected a rule.
 *
 * @details
 * The wrapper decides which rule applies; this module decides whether it fires on this
 * call and carries out the effect. Keeping the two apart lets the effects be unit-tested
 * without interposition.
 *
 * | Effect | Applied | Gate | Caller sees |
 * |--------|---------|------|-------------|
 * | ERRNO | before the real function | qualifiers, probability | the error value, `errno` set |
 * | LATENCY | before the real function | qualifiers, probability | the real result, later |
 * | TORN | before the real function | qualifiers, probability | a short write, [1, n-1] bytes |
 * | CORRUPT | after a read of > 0 bytes | qualifiers, probability | one flipped bit |
 *
 * Qualifiers (`@first`, `@from`, `@until`, `@size`) are checked for every effect, and
 * every applied effect counts one hit (chaos_policy_fire()).
 *
 * @par Randomness
 * Samples come from the thread-local xorshift64* PRNG (chaos_io_internal.h). Each
 * `_sample` variant takes explicit samples instead, so unit tests can assert exact
 * outcomes.
 *
 * @par Thread and signal safety
 * Only thread-local PRNG state and caller-owned buffers are touched; the hit counters
 * are updated atomically. chaos_io_rule_apply_latency() blocks the calling thread; no
 * other function sleeps.
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
 * @brief Probability gate with an explicit sample: non-zero when
 *        `sample < probability * 2^32`.
 *
 * @details The comparison is in double precision, which represents every uint32_t
 * exactly, so the hit rate equals @p probability to within 2^-32.
 *
 * @param[in] probability  Probability; <= 0.0 never hits, >= 1.0 always hits.
 * @param[in] sample       Uniform 32-bit sample.
 * @return Non-zero on a hit.
 */
int chaos_io_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Byte count of a torn write, from an explicit sample.
 *
 * @details
 * - `requested == 0`: 0.
 * - `requested == 1`: 1; one byte cannot be torn without becoming a zero-byte write,
 *   which callers treat differently from a short write.
 * - `requested > 1`: `sample % (requested - 1) + 1`, in [1, requested - 1], so the write
 *   is always partial and never empty. The modulo is slightly biased toward small
 *   counts when `requested - 1` does not divide 2^32; irrelevant for fault injection.
 *
 * @param[in] requested  Byte count the caller asked to write.
 * @param[in] sample     Uniform 32-bit sample.
 * @return The count to pass to the real function; <= @p requested.
 */
size_t chaos_io_torn_count_sample(size_t requested, uint32_t sample);

/**
 * @brief chaos_io_torn_count_sample() with this call's first effect draw.
 *
 * @param[in] rule       Firing rule, after chaos_io_rule_should_trigger() returned 1.
 * @param[in] requested  Byte count the caller asked to write.
 * @return The count to pass to the real function; <= @p requested.
 */
size_t chaos_io_torn_count(const chaos_io_rule_t *rule, size_t requested);

/**
 * @brief Flips bit `bit_sample & 7` of byte `index_sample % size` in @p buffer.
 *
 * @param[in,out] buffer        Bytes to corrupt; NULL is a no-op.
 * @param[in]     size          Valid bytes in @p buffer; 0 is a no-op.
 * @param[in]     index_sample  Sample selecting the byte.
 * @param[in]     bit_sample    Sample selecting the bit within it.
 */
void chaos_io_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
);

/**
 * @brief CORRUPT effect: flips one bit among the @p size bytes a read returned.
 *
 * @details Models silent media or transport corruption that the caller cannot detect
 * from the return value. The byte index is this call's first effect draw, the bit its
 * second.
 *
 * @param[in]     rule    Firing rule, after chaos_io_rule_should_trigger() returned 1.
 * @param[in,out] buffer  Bytes returned by the real read; NULL is a no-op.
 * @param[in]     size    Bytes actually read (the real function's return value).
 */
void chaos_io_corrupt_buffer(const chaos_io_rule_t *rule, void *buffer, size_t size);

/**
 * @brief LATENCY effect: blocks the calling thread for `rule->latency_ms` when the rule's
 *        qualifiers let it fire.
 *
 * @details Sleeps with chaos_sleep_ms() (chaos_sleep.h): a raw `clock_nanosleep` system
 * call on CLOCK_MONOTONIC, restarted on EINTR, so the full delay elapses, errno is
 * preserved, and no other preloaded library (libchaos-time in particular) can shorten or
 * lengthen it. The sleep enters no interposed symbol, so it needs no re-entrancy guard.
 * A delay that fires counts one hit.
 *
 * @param[in] rule  Matched rule; NULL or a non-LATENCY effect is a no-op.
 */
void chaos_io_rule_apply_latency(chaos_io_rule_t *rule);

/**
 * @brief Decides whether a selected rule fires on this call, and counts the hit if so.
 *
 * @details Checks, in order: the `@from`/`@until` window, the `@size` gate against
 * `rule->call_size`, the probability, and finally chaos_policy_fire(), which claims a
 * `@first` allowance and counts the hit. A rule the window or size gate filtered out is
 * not an evaluation of it and gets no number.
 *
 * @param[in,out] rule  Selected rule copy; NULL returns 0. Past the first two gates this
 *                      call's draw base is written into it (chaos_io_rule_draw_begin()),
 *                      and the effects derive their samples from it.
 * @return Non-zero when the effect is to be applied; 0 to proceed without injection.
 */
int chaos_io_rule_should_trigger(chaos_io_rule_t *rule);

/**
 * @brief ERRNO effect: when the rule fires, sets `errno = rule->errnum` and tells the
 *        wrapper to fail the call without calling the real function.
 *
 * @param[in] rule  Selected rule; NULL or a non-ERRNO effect returns 0.
 * @return Non-zero when the wrapper must return its error value (errno is set); 0 when
 *         the rule did not fire, with errno unchanged.
 */
int chaos_io_rule_apply_errno(chaos_io_rule_t *rule);

/**
 * @brief FREE and FULL: the free-space counts a `statfs` answer should report.
 *
 * @details Both effects change the same two fields, in units of @p unit bytes: FULL
 * reports no free space at all, FREE the rule's byte count rounded down to whole units.
 * The total (`f_blocks`) is left alone: a filesystem that shrinks while a program runs is
 * not what is being modelled, a filling one is.
 *
 * The caller passes the unit because the two structures disagree: `struct statfs` counts
 * blocks in `f_bsize`, `struct statvfs` in `f_frsize`. A unit of 0 is no answer at all
 * (nothing can be expressed in it) and leaves the counts alone, so the wrapper reports
 * what the kernel said.
 *
 * @param[in]  rule       Firing FREE or FULL rule; anything else leaves the counts alone.
 * @param[in]  unit       Bytes per block of the structure being filled.
 * @param[out] blocks     Receives the free-block count; NULL is a no-op.
 * @return Non-zero when @p blocks was written.
 */
int chaos_io_free_blocks(const chaos_io_rule_t *rule, uint64_t unit, uint64_t *blocks);

#endif
