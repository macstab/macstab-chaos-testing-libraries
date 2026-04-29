#include "chaos_time_actions.h"

#include <stdint.h>

int chaos_time_probability_hit_sample(double probability, uint32_t sample)
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

int chaos_time_probability_hit(double probability)
{
    return chaos_time_probability_hit_sample(probability, chaos_time_prng_next_u32());
}

static void chaos_time_sleep_chunk(useconds_t usec)
{
    int previous;

    previous = chaos_time_enter_internal();
    if (g_chaos_time_real_usleep != NULL)
    {
        (void)g_chaos_time_real_usleep(usec);
    }
    else if (g_chaos_time_real_nanosleep != NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)((usec % 1000000U) * 1000U);
        while (g_chaos_time_real_nanosleep(&request, &request) != 0 && errno == EINTR)
        {
        }
    }
    chaos_time_leave_internal(previous);
}

static void chaos_time_add_offset_ms(struct timespec *value, int64_t offset_ms)
{
    int64_t seconds;
    int64_t nanoseconds;

    if (value == NULL || offset_ms == 0)
    {
        return;
    }

    seconds = (int64_t)value->tv_sec + (offset_ms / 1000);
    nanoseconds = (int64_t)value->tv_nsec + ((offset_ms % 1000) * INT64_C(1000000));

    while (nanoseconds >= INT64_C(1000000000))
    {
        ++seconds;
        nanoseconds -= INT64_C(1000000000);
    }
    while (nanoseconds < 0)
    {
        --seconds;
        nanoseconds += INT64_C(1000000000);
    }

    if (seconds < 0)
    {
        value->tv_sec = 0;
        value->tv_nsec = 0L;
        return;
    }

    value->tv_sec = (time_t)seconds;
    value->tv_nsec = (long)nanoseconds;
}

int chaos_time_rule_should_trigger(const chaos_time_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }

    return chaos_time_probability_hit(rule->probability);
}

void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_LATENCY ||
        !chaos_time_rule_should_trigger(rule))
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;

        chaos_time_sleep_chunk(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_ERRNO ||
        !chaos_time_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}

void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value)
{
    if (rule == NULL || value == NULL || rule->effect != CHAOS_TIME_EFFECT_OFFSET ||
        !chaos_time_rule_should_trigger(rule))
    {
        return;
    }

    chaos_time_add_offset_ms(value, rule->offset_ms);
}
