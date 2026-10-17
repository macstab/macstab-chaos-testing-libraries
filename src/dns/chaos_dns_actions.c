/**
 * @file chaos_dns_actions.c
 * @brief Effect primitives of libchaos-dns (contracts in chaos_dns_actions.h).
 *
 * @details
 * The only place in the library that sleeps (LATENCY), releases single addrinfo nodes
 * (FILTER_FAMILY, LIMIT) and allocates a temporary array (SHUFFLE).
 *
 * ### Releasing nodes
 * A node removed from a list is released by chaos_dns_call_real_freeaddrinfo():
 *   1. A node of a real result goes to the real freeaddrinfo, which alone knows how the
 *      C library allocated it (glibc: per node; musl: one reference-counted block per
 *      result). Either way it walks ai_next, so a single node is isolated first.
 *   2. A node of a list OVERRIDE built (chaos_dns_owned.h) is left alone: it lives in
 *      one block that the freeaddrinfo wrapper frees with the list.
 *   3. Never through the freeaddrinfo wrapper, and never with free().
 * Kept nodes stay with the caller and reach the application, which frees the list
 * through the freeaddrinfo wrapper.
 *
 * ### SHUFFLE allocation
 * chaos_dns_shuffle_result_list() calloc()s an array of N node pointers for the
 * Fisher-Yates pass and frees it before returning; no node is allocated or freed. If
 * calloc fails the list keeps its order.
 *
 * @module  libchaos-dns actions
 * @stability  Private
 */

#include "chaos_dns_actions.h"
#include "chaos_sleep.h"

#include "chaos_dns_owned.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Fire/no-fire decision for a pre-drawn sample (contract in the header).
 */
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

    /* Map [0, 1) onto [0, 2^32): a sample strictly below the threshold fires.
     * Converting a uint32_t to double is exact; probability 1.0 took the early return. */
    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

/**
 * @brief Fire/no-fire decision with one PRNG draw (contract in the header).
 */
int chaos_dns_probability_hit(double probability)
{
    return chaos_dns_probability_hit_sample(probability, chaos_dns_prng_next_u32());
}

/**
 * @brief Sleeps for a LATENCY rule (contract in the header).
 *
 * @details No decision here: the wrappers call chaos_dns_rule_should_trigger() first.
 * chaos_sleep_ms() is a raw system call, so no other preloaded library (libchaos-time in
 * particular) can shorten or stretch the delay; errno is preserved.
 */
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_DNS_EFFECT_LATENCY)
    {
        return;
    }
    chaos_sleep_ms((uint64_t)rule->latency_ms);
}

/**
 * @brief Firing decision for a rule copy (contract in the header).
 *
 * @details Cheap gates first (window, size), then the PRNG draw, then the hit slot: a
 * call the window or the size gate rejects neither consumes a random number nor claims
 * an `@first` slot.
 */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }
    if (!chaos_dns_probability_hit(rule->probability))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/**
 * @brief Applies a GAI rule (contract in the header).
 */
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

/**
 * @brief Releases a node or sub-list of a real result with the real freeaddrinfo.
 *
 * @details No-op for NULL, before the real function is resolved (leaking is the only
 * safe choice), and for a node of a list OVERRIDE built: such a node stays in its block
 * until the whole list is freed (chaos_dns_owned.h). The guard is saved and restored
 * around the call, so this works inside an existing section too.
 *
 * @param result  Head of the nodes to release.
 */
static void chaos_dns_call_real_freeaddrinfo(struct addrinfo *result)
{
    int previous;

    /* A node of a list we built (OVERRIDE) stays in its block until the list itself is
     * freed; only real results are released node by node. */
    if (result == NULL || g_chaos_dns_real_freeaddrinfo == NULL || chaos_dns_owned_contains(result))
    {
        return;
    }

    previous = chaos_dns_enter_internal();
    g_chaos_dns_real_freeaddrinfo(result);
    chaos_dns_leave_internal(previous);
}

/**
 * @brief Node count of an addrinfo list (contract in the header).
 */
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

/**
 * @brief Removes nodes of the other family (contract in the header).
 *
 * @details One pass with `previous` and `current`. A dropped node is unlinked, then
 * isolated (ai_next = NULL) before it is released, because freeaddrinfo walks ai_next
 * and would otherwise release the rest of the chain too. The canonical name is handed to
 * the next node first, so it survives on the new head.
 */
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
            /* The canonical name lives on the first node: hand it on rather than free it
             * with the node, so the new head keeps it. A last node keeps it, and frees
             * it, when nothing is left. */
            if (current->ai_canonname != NULL && next != NULL && next->ai_canonname == NULL)
            {
                next->ai_canonname = current->ai_canonname;
                current->ai_canonname = NULL;
            }
            /* Unlink. */
            if (previous == NULL)
            {
                *result = next;
            }
            else
            {
                previous->ai_next = next;
            }
            /* Isolate before releasing: freeaddrinfo walks ai_next and would release
             * nodes that are still in the list. */
            current->ai_next = NULL;
            chaos_dns_call_real_freeaddrinfo(current);
        }
        else
        {
            previous = current;
        }
        current = next;
    }

    /* The name only moves from a dropped node to the next, so it ends on the first
     * survivor, the new head (or with the last node, if none is left). */
    return *result != NULL;
}

/**
 * @brief Cuts a list after @p limit nodes (contract in the header).
 *
 * @details The tail is detached by terminating node @p limit and released in one call:
 * every tail node goes, so the real freeaddrinfo may walk the whole sub-list.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit)
{
    struct addrinfo *current;
    unsigned int count = 0U;

    if (result == NULL || *result == NULL || limit == 0U)
    {
        if (result != NULL && *result != NULL && limit == 0U)
        {
            /* Limit 0 (never produced by the parser): release the whole list. */
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
            /* Detach the tail and release it as one sub-list. */
            struct addrinfo *tail = current->ai_next;

            current->ai_next = NULL; /* terminate the kept prefix */
            chaos_dns_call_real_freeaddrinfo(tail);
            return;
        }
        current = current->ai_next;
    }
}

/**
 * @brief Fisher-Yates shuffle of a list (contract in the header).
 *
 * @details Array of node pointers in list order; descending sweep swapping node i with
 * node `prng % (i + 1)`; canonical name swapped from the old head to the new one (the C
 * libraries set it only on the head); relink; free the array.
 */
void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    struct addrinfo **nodes;
    struct addrinfo *current;
    char *canonname;
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

    /* Fail-open: without the array the list keeps its order. */
    nodes = (struct addrinfo **)calloc(count, sizeof(*nodes));
    if (nodes == NULL)
    {
        return;
    }

    /* Node pointers in list order. */
    current = *result;
    for (index = 0U; index < count; ++index)
    {
        nodes[index] = current;
        current = current->ai_next;
    }

    /* Descending Fisher-Yates sweep; j uniform in [0, i] up to a modulo bias below
     * (i + 1) / 2^32. */
    for (index = count - 1U; index > 0U; --index)
    {
        size_t swap_index = (size_t)(chaos_dns_prng_next_u32() % (uint32_t)(index + 1U));
        struct addrinfo *tmp = nodes[index];

        nodes[index] = nodes[swap_index];
        nodes[swap_index] = tmp;
    }

    /* Relink. The canonical name belongs to the head (callers read it there): swap it
     * with the new head's (NULL in what the C libraries return), so none is lost. */
    canonname = (*result)->ai_canonname;
    (*result)->ai_canonname = nodes[0]->ai_canonname;
    nodes[0]->ai_canonname = canonname;
    for (index = 0U; index + 1U < count; ++index)
    {
        nodes[index]->ai_next = nodes[index + 1U];
    }
    nodes[count - 1U]->ai_next = NULL;
    *result = nodes[0];

    /* The pointer array only; the nodes now form the list. */
    free(nodes);
}
