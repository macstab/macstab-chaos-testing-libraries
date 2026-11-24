/**
 * @file chaos_io_actions.c
 * @brief libchaos-io effect decisions and primitives (see chaos_io_actions.h).
 *
 * @details
 * Invariants:
 * - chaos_io_torn_count() never returns more than requested and, for requests of 2 or
 *   more bytes, returns at least 1 and less than requested: a full-length "torn" write
 *   would be indistinguishable from success.
 * - chaos_io_corrupt_buffer() draws its two samples in a fixed order (byte, then bit),
 *   so a given PRNG state always corrupts the same bit.
 * - Every applied effect passes chaos_policy_fire() exactly once, so `@first` and the hit
 *   count see each injected fault once.
 * - chaos_io_rule_apply_latency() sleeps with a raw system call, so no other preloaded
 *   library can shorten or lengthen the delay.
 */

#include "chaos_io_actions.h"
#include "chaos_sleep.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

/**
 * @copydoc chaos_io_probability_hit_sample
 *
 * The explicit bounds settle the common 0 and 1 cases without floating-point work.
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
 * @copydoc chaos_io_torn_count_sample
 *
 * The `requested == 1` case also avoids a modulo by zero.
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

    /* [0, requested - 2] + 1 = [1, requested - 1]: never full, never empty. */
    return (size_t)(sample % (requested - 1U)) + 1U;
}

/** @copydoc chaos_io_torn_count */
size_t chaos_io_torn_count(const chaos_io_rule_t *rule, size_t requested)
{
    return chaos_io_torn_count_sample(
        requested, chaos_io_rule_draw(rule, CHAOS_IO_DRAW_FIRST_EFFECT)
    );
}

/** @copydoc chaos_io_corrupt_buffer_sample */
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

/** @copydoc chaos_io_corrupt_buffer */
void chaos_io_corrupt_buffer(const chaos_io_rule_t *rule, void *buffer, size_t size)
{
    chaos_io_corrupt_buffer_sample(
        buffer,
        size,
        chaos_io_rule_draw(rule, CHAOS_IO_DRAW_FIRST_EFFECT),
        chaos_io_rule_draw(rule, CHAOS_IO_DRAW_SECOND_EFFECT)
    );
}

/** @copydoc chaos_io_free_blocks */
int chaos_io_free_blocks(const chaos_io_rule_t *rule, uint64_t unit, uint64_t *blocks)
{
    if (rule == NULL || blocks == NULL || unit == 0U)
    {
        return 0;
    }
    if (rule->effect == CHAOS_IO_EFFECT_FULL)
    {
        *blocks = 0U;
        return 1;
    }
    if (rule->effect != CHAOS_IO_EFFECT_FREE)
    {
        return 0;
    }
    *blocks = rule->free_bytes / unit;
    return 1;
}

/** @copydoc chaos_io_rule_apply_latency */
void chaos_io_rule_apply_latency(chaos_io_rule_t *rule)
{
    /* A delay is gated and counted like any other effect: qualifiers (@first, @from,
     * @until, @size) and the probability of `LATENCY:ms@p`, which is 1.0 without one. */
    if (rule == NULL || rule->effect != CHAOS_IO_EFFECT_LATENCY ||
        !chaos_io_rule_should_trigger(rule))
    {
        return;
    }
    chaos_sleep_ms((uint64_t)rule->latency_ms);
}

/**
 * @copydoc chaos_io_rule_should_trigger
 *
 * chaos_policy_fire() runs last so a `@first` allowance is consumed only by a call that
 * actually injects.
 */
int chaos_io_rule_should_trigger(chaos_io_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_at_ok(&rule->policy, rule->hit) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }
    /* Past the gates that cost nothing: this call is an evaluation of the rule and gets
     * its number. `@every=N` picks evaluations, so it gates here, before the draw; every
     * sample of this call follows from the same number. */
    if (!chaos_policy_every_ok(&rule->policy, chaos_io_rule_draw_begin(rule)))
    {
        return 0;
    }
    if (!chaos_io_probability_hit_sample(
            rule->probability, chaos_io_rule_draw(rule, CHAOS_IO_DRAW_PROBABILITY)
        ))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/** @copydoc chaos_io_rule_apply_errno */
int chaos_io_rule_apply_errno(chaos_io_rule_t *rule)
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
