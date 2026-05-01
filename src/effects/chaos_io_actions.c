/**
 * @file chaos_io_actions.c
 * @brief Fault-effect evaluation helpers used after a rule has matched.
 *
 * @details
 * Keeping latency, probability, corruption, and torn-write logic separate from
 * the wrapper layer makes the interposition code smaller, more testable, and
 * easier to audit.
 *
 * **Invariants maintained by this file:**
 * - `chaos_io_torn_count()` always returns a value ≤ `requested`.  A torn
 *   write that returns the full `requested` count would be silently
 *   indistinguishable from success and would defeat the entire effect.
 * - `chaos_io_corrupt_buffer()` draws both PRNG samples before passing them
 *   to `chaos_io_corrupt_buffer_sample()`, ensuring the byte-index and
 *   bit-position selections are stable regardless of compiler argument
 *   evaluation order.
 * - `chaos_io_rule_apply_latency()` never sleeps for more than one second per
 *   loop iteration to avoid `useconds_t` overflow.
 *
 * **Module ownership:** effects/
 * **Stability:** internal
 */

/*
 * Fault-effect evaluation helpers used after a rule has matched.
 *
 * Keeping latency, probability, corruption, and torn-write logic separate from
 * the wrapper layer makes the interposition code smaller, more testable, and
 * easier to audit.
 */

#include "chaos_io_actions.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

/**
 * @brief Returns non-zero when a PRNG sample falls inside the configured probability window.
 *
 * @details The threshold is computed as `probability * 2^32` in double
 * precision.  A sample is "inside" the window when `(double)sample <
 * threshold`.  The 0.0 and 1.0 fast paths avoid floating-point operations for
 * the always-off and always-on extremes, which are common in test scenarios.
 */
int chaos_io_probability_hit_sample(double probability, uint32_t sample)
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
 * @brief Returns non-zero when the current thread PRNG hits the configured probability.
 */
int chaos_io_probability_hit(double probability)
{
    return chaos_io_probability_hit_sample(probability, chaos_io_prng_next_u32());
}

/**
 * @brief Returns the torn write count derived from an explicit sample.
 *
 * @details The modulo expression `sample % (requested - 1)` yields a value in
 * `[0, requested - 2]`; adding 1 shifts the range to `[1, requested - 1]`,
 * guaranteeing the result is always strictly smaller than `requested` and
 * always at least 1.
 *
 * The single-byte special case (`requested == 1`) exists because
 * `requested - 1 == 0` would produce a division-by-zero in the modulo.
 * Returning 1 for a single-byte request is also semantically correct: a
 * single-byte write cannot be torn into anything shorter without becoming a
 * zero-byte write, which would not be a valid torn write.
 */
size_t chaos_io_torn_count_sample(size_t requested, uint32_t sample)
{
    if (requested == 0U)
    {
        return 0U;
    }
    if (requested == 1U)
    {
        return 1U;
    }

    /*
     * Torn writes must stay strictly smaller than the original request, or the
     * wrapper would report a full write and silently fail to inject anything.
     */
    return (size_t)(sample % (requested - 1U)) + 1U;
}

/**
 * @brief Returns the torn write count derived from the thread-local PRNG.
 */
size_t chaos_io_torn_count(size_t requested)
{
    return chaos_io_torn_count_sample(requested, chaos_io_prng_next_u32());
}

/**
 * @brief Flips one random bit in a buffer using explicit samples.
 *
 * @details `index_sample % size` selects a byte uniformly from the buffer.
 * `bit_sample & 7` selects a bit within that byte.  The XOR with
 * `(1U << bit)` flips only the selected bit, leaving all others unchanged.
 *
 * The `unsigned char *` cast is necessary to avoid undefined behavior from
 * pointer arithmetic and bitwise operations on `void *`.
 */
void chaos_io_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;
    size_t index;
    unsigned int bit;

    if (buffer == NULL || size == 0U)
    {
        return;
    }

    index = (size_t)(index_sample % size);
    bit = (unsigned int)(bit_sample & 7U);
    bytes[index] ^= (unsigned char)(1U << bit);
}

/**
 * @brief Flips one random bit in a buffer using the thread-local PRNG.
 *
 * @details The two PRNG draws are captured into named local variables before
 * the call to `chaos_io_corrupt_buffer_sample()`.  This is required because
 * the C standard does not specify the order in which function arguments are
 * evaluated, so writing the two `chaos_io_prng_next_u32()` calls directly as
 * arguments would produce non-deterministic behavior across compilers and
 * optimization levels.
 */
void chaos_io_corrupt_buffer(void *buffer, size_t size)
{
    uint32_t index_sample = chaos_io_prng_next_u32();
    uint32_t bit_sample = chaos_io_prng_next_u32();

    /*
     * C does not define function-argument evaluation order, so the samples
     * must be captured explicitly to keep corruption deterministic across
     * compilers and architectures.
     */
    chaos_io_corrupt_buffer_sample(buffer, size, index_sample, bit_sample);
}

/**
 * @brief Applies a configured latency before the real libc call.
 *
 * @details Loops calling `usleep()` in chunks of at most 1 000 000 µs (1 s)
 * until `remaining_us` reaches zero.  The per-chunk cap avoids overflowing
 * `useconds_t`, which is required by POSIX to hold values up to at least
 * 1 000 000 but may be a narrower type (e.g. `unsigned int` on some
 * platforms) than the full `uint64_t` accumulated delay.
 *
 * `usleep` return values are discarded; a signal interruption
 * (`EINTR`-equivalent) would manifest as a shorter-than-requested sleep,
 * which is acceptable for a fault-injection library.
 */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_IO_EFFECT_LATENCY)
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;
        (void)usleep(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/**
 * @brief Returns non-zero when the rule should trigger for the current call.
 *
 * @details `LATENCY` is unconditional because the sleep duration IS the
 * probability-free effect: every matched call is delayed by exactly
 * `latency_ms` milliseconds.  All other effects are gated through
 * `chaos_io_probability_hit()`.
 */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_IO_EFFECT_LATENCY)
    {
        return 1;
    }
    return chaos_io_probability_hit(rule->probability);
}

/**
 * @brief Applies an ERRNO rule and returns non-zero when the wrapper should fail.
 *
 * @details Returns 0 without modifying `errno` when the rule pointer is NULL,
 * when `rule->effect != CHAOS_IO_EFFECT_ERRNO`, or when the probability check
 * does not trigger.  This keeps the wrapper-side errno unchanged for
 * passthrough calls.
 */
int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_IO_EFFECT_ERRNO)
    {
        return 0;
    }
    if (!chaos_io_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
