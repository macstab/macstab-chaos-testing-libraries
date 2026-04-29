#include "chaos_process_actions.h"

#include <stdint.h>

int chaos_process_probability_hit_sample(double probability, uint32_t sample)
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

int chaos_process_probability_hit(double probability)
{
    return chaos_process_probability_hit_sample(probability, chaos_process_prng_next_u32());
}

static void chaos_process_sleep_chunk(useconds_t usec)
{
    int previous;

    previous = chaos_process_enter_internal();
    if (g_chaos_process_real_usleep != NULL)
    {
        (void)g_chaos_process_real_usleep(usec);
    }
    else if (g_chaos_process_real_nanosleep != NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)((usec % 1000000U) * 1000U);
        while (g_chaos_process_real_nanosleep(&request, &request) != 0 && errno == EINTR)
        {
        }
    }
    chaos_process_leave_internal(previous);
}

int chaos_process_rule_should_trigger(const chaos_process_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }

    return chaos_process_probability_hit(rule->probability);
}

void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_PROCESS_EFFECT_LATENCY ||
        !chaos_process_rule_should_trigger(rule))
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;

        chaos_process_sleep_chunk(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum)
{
    if (rule == NULL || errnum == NULL || rule->effect != CHAOS_PROCESS_EFFECT_ERRNO ||
        !chaos_process_rule_should_trigger(rule))
    {
        return 0;
    }

    *errnum = rule->errnum;
    return 1;
}

int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
)
{
    uint64_t observed;

    if (rule == NULL || errnum == NULL || operation < 0 || operation >= CHAOS_PROCESS_OP_COUNT ||
        rule->effect != CHAOS_PROCESS_EFFECT_FAIL_AFTER)
    {
        return 0;
    }

    observed =
        chaos_process_atomic_fetch_add_u64(&g_chaos_process_fail_after_counters[operation], 1U);
    if (observed < rule->fail_after_count || !chaos_process_probability_hit(rule->probability))
    {
        return 0;
    }

    *errnum = rule->errnum;
    return 1;
}
