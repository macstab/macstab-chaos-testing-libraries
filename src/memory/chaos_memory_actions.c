#include "chaos_memory_actions.h"

#include <stdint.h>

int chaos_memory_probability_hit_sample(double probability, uint32_t sample)
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

int chaos_memory_probability_hit(double probability)
{
    return chaos_memory_probability_hit_sample(probability, chaos_memory_prng_next_u32());
}

static void chaos_memory_sleep_chunk(useconds_t usec)
{
    int previous;

    previous = chaos_memory_enter_internal();
    if (g_chaos_memory_real_usleep != NULL)
    {
        (void)g_chaos_memory_real_usleep(usec);
    }
    else if (g_chaos_memory_real_nanosleep != NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)((usec % 1000000U) * 1000U);
        while (g_chaos_memory_real_nanosleep(&request, &request) != 0 && errno == EINTR)
        {
        }
    }
    chaos_memory_leave_internal(previous);
}

int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }

    return chaos_memory_probability_hit(rule->probability);
}

void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_LATENCY ||
        !chaos_memory_rule_should_trigger(rule))
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;

        chaos_memory_sleep_chunk(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_ERRNO ||
        !chaos_memory_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
