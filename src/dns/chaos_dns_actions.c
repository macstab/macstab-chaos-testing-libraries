#include "chaos_dns_actions.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

int chaos_dns_probability_hit_sample(double probability, uint32_t sample)
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

int chaos_dns_probability_hit(double probability)
{
    return chaos_dns_probability_hit_sample(probability, chaos_dns_prng_next_u32());
}

void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_DNS_EFFECT_LATENCY)
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

int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    return chaos_dns_probability_hit(rule->probability);
}

int chaos_dns_rule_apply_gai(const chaos_dns_rule_t *rule, int *gai_error)
{
    if (rule == NULL || gai_error == NULL || rule->effect != CHAOS_DNS_EFFECT_GAI)
    {
        return 0;
    }
    if (!chaos_dns_rule_should_trigger(rule))
    {
        return 0;
    }

    *gai_error = rule->gai_error;
    return 1;
}

static void chaos_dns_call_real_freeaddrinfo(struct addrinfo *result)
{
    int previous;

    if (result == NULL || g_chaos_dns_real_freeaddrinfo == NULL)
    {
        return;
    }

    previous = chaos_dns_enter_internal();
    g_chaos_dns_real_freeaddrinfo(result);
    chaos_dns_leave_internal(previous);
}

size_t chaos_dns_result_count(const struct addrinfo *result)
{
    size_t count = 0U;

    while (result != NULL)
    {
        ++count;
        result = result->ai_next;
    }

    return count;
}

int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family)
{
    struct addrinfo *current;
    struct addrinfo *previous = NULL;
    int wanted_family;

    if (result == NULL || *result == NULL || family == CHAOS_DNS_FAMILY_ANY)
    {
        return 0;
    }

    wanted_family = family == CHAOS_DNS_FAMILY_INET4 ? AF_INET : AF_INET6;
    current = *result;
    while (current != NULL)
    {
        struct addrinfo *next = current->ai_next;

        if (current->ai_family != wanted_family)
        {
            if (previous == NULL)
            {
                *result = next;
            }
            else
            {
                previous->ai_next = next;
            }
            current->ai_next = NULL;
            chaos_dns_call_real_freeaddrinfo(current);
        }
        else
        {
            previous = current;
        }
        current = next;
    }

    return *result != NULL;
}

void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit)
{
    struct addrinfo *current;
    unsigned int count = 0U;

    if (result == NULL || *result == NULL || limit == 0U)
    {
        if (result != NULL && *result != NULL && limit == 0U)
        {
            chaos_dns_call_real_freeaddrinfo(*result);
            *result = NULL;
        }
        return;
    }

    current = *result;
    while (current != NULL)
    {
        ++count;
        if (count == limit)
        {
            struct addrinfo *tail = current->ai_next;

            current->ai_next = NULL;
            chaos_dns_call_real_freeaddrinfo(tail);
            return;
        }
        current = current->ai_next;
    }
}

void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    struct addrinfo **nodes;
    struct addrinfo *current;
    size_t count;
    size_t index;

    if (result == NULL || *result == NULL)
    {
        return;
    }

    count = chaos_dns_result_count(*result);
    if (count < 2U)
    {
        return;
    }

    nodes = (struct addrinfo **)calloc(count, sizeof(*nodes));
    if (nodes == NULL)
    {
        return;
    }

    current = *result;
    for (index = 0U; index < count; ++index)
    {
        nodes[index] = current;
        current = current->ai_next;
    }

    for (index = count - 1U; index > 0U; --index)
    {
        size_t swap_index = (size_t)(chaos_dns_prng_next_u32() % (uint32_t)(index + 1U));
        struct addrinfo *tmp = nodes[index];

        nodes[index] = nodes[swap_index];
        nodes[swap_index] = tmp;
    }

    for (index = 0U; index + 1U < count; ++index)
    {
        nodes[index]->ai_next = nodes[index + 1U];
    }
    nodes[count - 1U]->ai_next = NULL;
    *result = nodes[0];
    free(nodes);
}
