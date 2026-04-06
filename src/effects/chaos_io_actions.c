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

/* Returns non-zero when a PRNG sample falls inside the configured probability window. */
int chaos_io_probability_hit_sample(double probability, uint32_t sample)
{
    double threshold;

    if (probability <= 0.0) {
        return 0;
    }
    if (probability >= 1.0) {
        return 1;
    }

    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

/* Returns non-zero when the current thread PRNG hits the configured probability. */
int chaos_io_probability_hit(double probability)
{
    return chaos_io_probability_hit_sample(probability, chaos_io_prng_next_u32());
}

/* Returns the torn write count derived from an explicit sample. */
size_t chaos_io_torn_count_sample(size_t requested, uint32_t sample)
{
    if (requested == 0U) {
        return 0U;
    }
    if (requested == 1U) {
        return 1U;
    }

    /*
     * Torn writes must stay strictly smaller than the original request, or the
     * wrapper would report a full write and silently fail to inject anything.
     */
    return (size_t)(sample % (requested - 1U)) + 1U;
}

/* Returns the torn write count derived from the thread-local PRNG. */
size_t chaos_io_torn_count(size_t requested)
{
    return chaos_io_torn_count_sample(requested, chaos_io_prng_next_u32());
}

/* Flips one random bit in a buffer using explicit samples. */
void chaos_io_corrupt_buffer_sample(
    void *buffer,
    size_t size,
    uint32_t index_sample,
    uint32_t bit_sample)
{
    unsigned char *bytes = (unsigned char *)buffer;
    size_t index;
    unsigned int bit;

    if (buffer == NULL || size == 0U) {
        return;
    }

    index = (size_t)(index_sample % size);
    bit = (unsigned int)(bit_sample & 7U);
    bytes[index] ^= (unsigned char)(1U << bit);
}

/* Flips one random bit in a buffer using the thread-local PRNG. */
void chaos_io_corrupt_buffer(void *buffer, size_t size)
{
    chaos_io_corrupt_buffer_sample(buffer, size, chaos_io_prng_next_u32(), chaos_io_prng_next_u32());
}

/* Applies a configured latency before the real libc call. */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_IO_EFFECT_LATENCY) {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL) {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;
        (void)usleep(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/* Returns non-zero when the rule should trigger for the current call. */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule)
{
    if (rule == NULL) {
        return 0;
    }
    if (rule->effect == CHAOS_IO_EFFECT_LATENCY) {
        return 1;
    }
    return chaos_io_probability_hit(rule->probability);
}

/* Applies an ERRNO rule and returns non-zero when the wrapper should fail. */
int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_IO_EFFECT_ERRNO) {
        return 0;
    }
    if (!chaos_io_rule_should_trigger(rule)) {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
