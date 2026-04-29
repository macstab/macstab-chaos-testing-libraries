#include "chaos_net_actions.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

int chaos_net_probability_hit_sample(double probability, uint32_t sample)
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

int chaos_net_probability_hit(double probability)
{
    return chaos_net_probability_hit_sample(probability, chaos_net_prng_next_u32());
}

void chaos_net_corrupt_buffer_sample(
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

void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    uint32_t index_sample = chaos_net_prng_next_u32();
    uint32_t bit_sample = chaos_net_prng_next_u32();

    chaos_net_corrupt_buffer_sample(buffer, size, index_sample, bit_sample);
}

void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_LATENCY)
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

int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        return 1;
    }
    return chaos_net_probability_hit(rule->probability);
}

int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_ERRNO)
    {
        return 0;
    }
    if (!chaos_net_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
