/**
 * @file chaos_dns_actions.c
 * @brief Implementation of pre-call effects and post-call result-set transforms.
 *
 * @details
 * This translation unit implements all functions declared in
 * chaos_dns_actions.h.  It is the only place in the library that:
 *   - Issues blocking sleeps (LATENCY).
 *   - Calls g_chaos_dns_real_freeaddrinfo on individual addrinfo nodes (FILTER_FAMILY, LIMIT).
 *   - Heap-allocates a temporary pointer array (SHUFFLE).
 *
 * ### addrinfo ownership model
 *
 * The transform functions (chaos_dns_filter_result_list,
 * chaos_dns_limit_result_list, chaos_dns_shuffle_result_list) operate on
 * addrinfo lists whose nodes were allocated by the real getaddrinfo — either
 * directly by the real resolver call, or by the OVERRIDE path which calls the
 * real getaddrinfo with AI_NUMERICHOST for each IP literal.
 *
 * Nodes that are removed from the list (by FILTER_FAMILY or LIMIT) are freed
 * immediately via chaos_dns_call_real_freeaddrinfo().  This is correct
 * because:
 *   1. The nodes were allocated by the real getaddrinfo; only the matching
 *      real freeaddrinfo knows their internal memory layout.
 *   2. Calling the interposed freeaddrinfo entry point instead would re-enter
 *      the library (setting the reentrancy guard) and might apply additional
 *      unexpected logic.
 *   3. Calling the system malloc/free directly would be incorrect because
 *      getaddrinfo may use a custom allocator internally.
 *
 * Nodes that are *kept* in the list remain owned by the caller (the
 * getaddrinfo interposer in chaos_dns_lookup.c).  When the application
 * eventually calls freeaddrinfo on the result, the interposed freeaddrinfo
 * entry point delegates to the real freeaddrinfo for the surviving nodes.
 *
 * ### SHUFFLE allocation
 *
 * chaos_dns_shuffle_result_list() heap-allocates a temporary `struct
 * addrinfo *[]` array solely to hold pointers during the Fisher–Yates shuffle.
 * This array is freed before the function returns.  No addrinfo nodes are
 * allocated or freed; only the ai_next chain is re-wired.  If calloc fails,
 * the function is a no-op and the list is returned in its original order.
 *
 * @module  libchaos-dns actions
 * @stability  Private
 */

#include "chaos_dns_actions.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/**
 * @brief Test whether a probabilistic rule fires given a pre-supplied sample.
 *        See chaos_dns_actions.h for the full contract.
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

    /* Map probability [0,1] onto the uint32 range [0, 2^32).
     * A sample value strictly less than the threshold triggers the rule.
     * At probability == 1.0 the threshold equals 4294967296.0 which is larger
     * than any uint32, so the fast path above handles that case. */
    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

/**
 * @brief Test whether a probabilistic rule fires, drawing from the PRNG.
 *        See chaos_dns_actions.h for the full contract.
 */
int chaos_dns_probability_hit(double probability)
{
    return chaos_dns_probability_hit_sample(probability, chaos_dns_prng_next_u32());
}

/**
 * @brief Sleep for the duration specified in a LATENCY rule.
 *        See chaos_dns_actions.h for the full contract.
 *
 * @details usleep(3) accepts at most 999999 µs on POSIX systems.  The loop
 * divides the total into chunks of at most 1,000,000 µs to avoid exceeding
 * this limit, and continues until the full latency has been injected.
 * A SIGALRM or other signal interrupting usleep will cause an early return
 * from that chunk; the remaining microseconds are re-attempted in the next
 * iteration, so the effective latency is at least the requested value minus
 * signal handling overhead.
 */
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
        /* usleep takes useconds_t; cap each sleep at 1,000,000 µs (= 1 s). */
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;
        (void)usleep(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/**
 * @brief Decide whether this rule fires on the current call.
 *        See chaos_dns_actions.h for the full contract.
 */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    return chaos_dns_probability_hit(rule->probability);
}

/**
 * @brief Apply a GAI effect rule if it fires.
 *        See chaos_dns_actions.h for the full contract.
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
 * @brief Call the real freeaddrinfo under the reentrancy guard.
 *
 * @details Sets the TLS reentrancy guard before invoking
 * g_chaos_dns_real_freeaddrinfo so that the call cannot be intercepted by the
 * library's own interposed freeaddrinfo entry point.  This is the correct
 * way to free nodes that were allocated by the real getaddrinfo.
 *
 * The guard is saved and restored (not simply set to 1) so that this function
 * can be called from within an already-internal context without incorrectly
 * resetting the guard to 0 on return.
 *
 * @param result  Head of the addrinfo sub-list to free; no-op if NULL.
 *                Also no-op if g_chaos_dns_real_freeaddrinfo is NULL (not yet
 *                initialised), though this should never happen at call sites.
 */
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

/**
 * @brief Count nodes in an addrinfo list.  See chaos_dns_actions.h.
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
 * @brief Remove addrinfo nodes that do not match the target address family.
 *        See chaos_dns_actions.h for the full contract and ownership model.
 *
 * @details Traversal is done with explicit `current` and `previous` pointers.
 * When a node is removed:
 *   1. `current->ai_next` is saved in `next`.
 *   2. The node is unlinked (previous->ai_next or *result is updated to `next`).
 *   3. `current->ai_next` is set to NULL so freeaddrinfo receives a
 *      single-node list, not the rest of the chain.
 *   4. chaos_dns_call_real_freeaddrinfo(current) releases the node.
 *
 * Setting ai_next to NULL before freeing is critical: if the node's internal
 * allocator stores adjacent nodes contiguously, passing a non-NULL ai_next
 * could cause the real freeaddrinfo to walk and double-free the rest of the
 * list.
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
    current       = *result;
    while (current != NULL)
    {
        struct addrinfo *next = current->ai_next;

        if (current->ai_family != wanted_family)
        {
            /* Unlink this node from the list. */
            if (previous == NULL)
            {
                *result = next;
            }
            else
            {
                previous->ai_next = next;
            }
            /* Isolate the node before freeing to prevent the real freeaddrinfo
             * from walking ai_next and freeing nodes we still need. */
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

/**
 * @brief Truncate an addrinfo list to at most @p limit nodes.
 *        See chaos_dns_actions.h for the full contract and ownership model.
 *
 * @details When the N-th node (where N == limit) is reached, the tail
 * (current->ai_next onwards) is detached in a single pointer assignment and
 * freed via chaos_dns_call_real_freeaddrinfo().  Unlike filter, where nodes
 * must be freed one by one (to avoid contaminating the remainder of the list),
 * here the entire tail can be freed in one call because none of the tail nodes
 * are kept.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit)
{
    struct addrinfo *current;
    unsigned int     count = 0U;

    if (result == NULL || *result == NULL || limit == 0U)
    {
        if (result != NULL && *result != NULL && limit == 0U)
        {
            /* Limit of zero: free the entire list. */
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
            /* Detach the tail and free it as a sub-list in a single call. */
            struct addrinfo *tail = current->ai_next;

            current->ai_next = NULL;   /* terminate the kept prefix */
            chaos_dns_call_real_freeaddrinfo(tail);
            return;
        }
        current = current->ai_next;
    }
}

/**
 * @brief Randomly permute addrinfo list nodes using Fisher–Yates.
 *        See chaos_dns_actions.h for the full contract and allocation notes.
 *
 * @details The algorithm:
 *   1. Count nodes N.  Return immediately if N < 2.
 *   2. calloc an array of N `struct addrinfo *` pointers.  calloc (not malloc)
 *      is used so that a partial failure leaves the array zero-initialised
 *      rather than containing garbage — defensively, though the loop always
 *      fills all slots.
 *   3. Fill the array with node pointers in list order.
 *   4. Fisher–Yates descending sweep: for i in [N-1, 1], swap nodes[i] with
 *      nodes[j] where j = prng_next_u32() % (i+1).
 *   5. Relink: for each index i in [0, N-2], nodes[i]->ai_next = nodes[i+1].
 *      Set nodes[N-1]->ai_next = NULL.
 *   6. Set *result = nodes[0].
 *   7. free the temporary array.
 *
 * No addrinfo nodes are allocated or freed.  The temporary array is always
 * freed before return, including on the early-return path (count < 2).
 */
void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    struct addrinfo **nodes;
    struct addrinfo  *current;
    size_t            count;
    size_t            index;

    if (result == NULL || *result == NULL)
    {
        return;
    }

    count = chaos_dns_result_count(*result);
    if (count < 2U)
    {
        return;
    }

    /* Heap-allocate a pointer array for the shuffle.  On failure, leave the
     * list unchanged (fail-open: caller still has a valid list). */
    nodes = (struct addrinfo **)calloc(count, sizeof(*nodes));
    if (nodes == NULL)
    {
        return;
    }

    /* Step 1: fill the pointer array in current list order. */
    current = *result;
    for (index = 0U; index < count; ++index)
    {
        nodes[index] = current;
        current      = current->ai_next;
    }

    /* Step 2: Fisher–Yates descending sweep.
     * j is drawn from [0, i] inclusive via prng_next_u32() % (i+1).
     * Modulo bias is negligible for i+1 ≤ 256. */
    for (index = count - 1U; index > 0U; --index)
    {
        size_t           swap_index = (size_t)(chaos_dns_prng_next_u32() % (uint32_t)(index + 1U));
        struct addrinfo *tmp        = nodes[index];

        nodes[index]      = nodes[swap_index];
        nodes[swap_index] = tmp;
    }

    /* Step 3: relink the shuffled pointers into a singly-linked list. */
    for (index = 0U; index + 1U < count; ++index)
    {
        nodes[index]->ai_next = nodes[index + 1U];
    }
    nodes[count - 1U]->ai_next = NULL;
    *result = nodes[0];

    /* Step 4: free the temporary pointer array (not the addrinfo nodes). */
    free(nodes);
}
