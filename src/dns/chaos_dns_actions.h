/**
 * @file chaos_dns_actions.h
 * @brief Probability sampling, latency injection, and addrinfo result-set transforms.
 *
 * @details
 * This header declares the functions that actually *apply* a matched rule
 * to an in-flight DNS call.  Functions divide into two groups:
 *
 * ### Pre-call effects (no addrinfo list involved)
 *   - chaos_dns_probability_hit_sample() / chaos_dns_probability_hit() —
 *     stochastic trigger decision.
 *   - chaos_dns_rule_apply_latency() — blocking sleep.
 *   - chaos_dns_rule_should_trigger() — convenience wrapper combining rule
 *     probability with the PRNG.
 *   - chaos_dns_rule_apply_gai() — return a synthetic EAI_* code.
 *
 * ### Post-call result-set transforms (addrinfo list mutation)
 *   These functions mutate the `struct addrinfo *` linked list that was
 *   returned by the real getaddrinfo (or synthesised by the OVERRIDE path).
 *   They are called in the fixed order documented in chaos_dns_config.h:
 *   FILTER_FAMILY → SHUFFLE → LIMIT.
 *
 *   **Ownership model for transform functions**
 *
 *   The caller (getaddrinfo interposer in chaos_dns_lookup.c) owns the entire
 *   addrinfo list pointed to by `*result` before and after all transforms.
 *   However, the *contents* of the list may change:
 *
 *   - chaos_dns_filter_result_list() unlinks nodes whose ai_family does not
 *     match and immediately calls g_chaos_dns_real_freeaddrinfo() on each
 *     unlinked node.  Ownership of those nodes is transferred from the caller
 *     to the function and then freed; the caller must not touch those nodes
 *     after the call.  The surviving nodes remain caller-owned.
 *
 *   - chaos_dns_limit_result_list() unlinks and frees the tail of the list
 *     (all nodes beyond the limit) via g_chaos_dns_real_freeaddrinfo().
 *     Ownership of the freed tail is transferred and consumed; the surviving
 *     prefix remains caller-owned.
 *
 *   - chaos_dns_shuffle_result_list() reorders nodes in place by relinking
 *     `ai_next` pointers.  No nodes are allocated or freed; ownership is
 *     unchanged.  A temporary `struct addrinfo *[]` array is heap-allocated
 *     for the shuffle and freed before the function returns.
 *
 *   **Why g_chaos_dns_real_freeaddrinfo is used for node freeing**
 *
 *   The nodes being freed were allocated by the real getaddrinfo (either the
 *   genuine call or the OVERRIDE path which also calls the real getaddrinfo
 *   with AI_NUMERICHOST).  They must therefore be freed with the matching
 *   real freeaddrinfo, not with the library's own malloc/free or the
 *   interposed freeaddrinfo entry point (which would re-enter the library).
 *
 *   **Why FILTER_FAMILY must come before SHUFFLE and LIMIT**
 *
 *   FILTER_FAMILY reduces the result set to a specific family.  If SHUFFLE
 *   ran first, the final shuffled order would include addresses of the wrong
 *   family that were subsequently discarded, wasting PRNG draws and producing
 *   a shuffle over a smaller-than-expected set.  If LIMIT ran first, it might
 *   truncate to N addresses of mixed family, and the subsequent filter could
 *   reduce the count below N, potentially to zero — making the LIMIT
 *   semantics surprising.  By filtering first, SHUFFLE and LIMIT always
 *   operate on the set that will actually be returned.
 *
 *   **Why SHUFFLE must come before LIMIT**
 *
 *   LIMIT applied before SHUFFLE would keep only the first N entries in the
 *   OS-determined order.  SHUFFLE before LIMIT means the limit selects N
 *   entries from a randomised order, giving uniform coverage over the full
 *   set across repeated calls — which is the intended fault-injection
 *   semantics.
 *
 * @module  libchaos-dns actions
 * @stability  Private
 */

#ifndef CHAOS_DNS_ACTIONS_H
#define CHAOS_DNS_ACTIONS_H

#include "chaos_dns_config.h"

/**
 * @brief Determine whether a probabilistic rule fires, given a pre-supplied sample.
 *
 * @details Maps @p probability ∈ [0.0, 1.0] to a threshold over the uint32
 * range [0, 2^32) and returns non-zero if @p sample falls below the threshold.
 * Using a pre-supplied sample allows unit tests to inject deterministic values
 * without modifying PRNG state.
 *
 * Edge cases:
 *   - probability ≤ 0.0 → always returns 0 (never fires).
 *   - probability ≥ 1.0 → always returns 1 (always fires).
 *
 * The threshold is `probability * 4294967296.0` (2^32), and the comparison is
 * `(double)sample < threshold`, which correctly handles the boundary: at
 * probability == 1.0 all 2^32 possible sample values yield true because
 * threshold == 4294967296.0 > any uint32 cast to double.
 *
 * @param probability  Trigger probability in [0.0, 1.0].
 * @param sample       A uint32 value drawn from a uniform distribution.
 * @return  Non-zero if the rule fires; zero otherwise.
 *
 * @threadsafety  Pure function — no shared state.
 */
int chaos_dns_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Determine whether a probabilistic rule fires, drawing a PRNG sample.
 *
 * @details Convenience wrapper that calls chaos_dns_prng_next_u32() for the
 * sample and delegates to chaos_dns_probability_hit_sample().  Advances the
 * calling thread's PRNG state by one step.
 *
 * @param probability  Trigger probability in [0.0, 1.0].
 * @return  Non-zero if the rule fires; zero otherwise.
 *
 * @threadsafety  Reads and writes only TLS (PRNG state); safe for concurrent use.
 */
int chaos_dns_probability_hit(double probability);

/**
 * @brief Sleep for the duration specified in a LATENCY rule.
 *
 * @details Sleeps for `rule->latency_ms` milliseconds using usleep(3) in a
 * loop to work around the POSIX limit of 1,000,000 µs per usleep call.  Each
 * iteration sleeps at most 1,000,000 µs (one second); the loop continues
 * until the full duration has elapsed.  Signals that interrupt usleep are
 * not retried; the effective latency may be slightly shorter than configured
 * if the process receives a signal during sleep.
 *
 * @param rule  Rule with effect == CHAOS_DNS_EFFECT_LATENCY and a valid
 *              `latency_ms` field.  No-op if NULL or wrong effect.
 *
 * @threadsafety  Safe — operates only on the calling thread's execution context.
 */
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule);

/**
 * @brief Return non-zero if the calling thread's PRNG says this rule fires.
 *
 * @details Calls chaos_dns_probability_hit() with `rule->probability`.  Used
 * by the getaddrinfo and getnameinfo interposers to decide whether each
 * matched rule is actually applied on the current call.
 *
 * @param rule  The matched rule; its `probability` field is sampled.
 * @return  Non-zero if the rule should be applied; zero to skip.
 *
 * @threadsafety  Advances TLS PRNG state; safe for concurrent use.
 */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule);

/**
 * @brief Apply a GAI (synthetic EAI_* error) rule if it fires.
 *
 * @details Checks that the rule's effect is CHAOS_DNS_EFFECT_GAI, samples the
 * probability, and if the rule fires, stores `rule->gai_error` into
 * `*gai_error` and returns non-zero so the caller can return early.
 *
 * @param rule       Matched rule with effect == CHAOS_DNS_EFFECT_GAI.
 * @param gai_error  Output: receives the EAI_* constant if the rule fires.
 * @return  Non-zero if the EAI error was written and the caller should return it;
 *          zero if the rule did not fire or was inapplicable.
 *
 * @threadsafety  Advances TLS PRNG state; safe for concurrent use.
 */
int chaos_dns_rule_apply_gai(const chaos_dns_rule_t *rule, int *gai_error);

/**
 * @brief Count the number of nodes in an addrinfo linked list.
 *
 * @param result  Head of the list; may be NULL (returns 0).
 * @return  Number of nodes in the list.
 *
 * @threadsafety  Safe — read-only traversal; caller must ensure the list is
 *               not modified concurrently.
 */
size_t chaos_dns_result_count(const struct addrinfo *result);

/**
 * @brief Remove all addrinfo nodes not matching the specified address family.
 *
 * @details Traverses `*result` and unlinks every node whose `ai_family` does
 * not equal the target family.  Each unlinked node is freed immediately via
 * g_chaos_dns_real_freeaddrinfo() (called with the reentrancy guard set).
 *
 * **Ownership transfer**: for each removed node, ownership is transferred from
 * the caller to this function and then released via freeaddrinfo.  The caller
 * must not access any node that has been unlinked.
 *
 * If @p family is CHAOS_DNS_FAMILY_ANY, no filtering is performed and the
 * function returns 0 immediately without modifying the list.
 *
 * @param result  Pointer to the head pointer of the list.  `*result` may be
 *                modified to skip removed nodes.
 * @param family  The address family to retain (INET4, INET6, or ANY).
 * @return  Non-zero if at least one node survives after filtering; zero if
 *          the list is empty after filtering (caller should return EAI_NONAME).
 *
 * @pre   `*result` is a valid addrinfo list allocated by the real getaddrinfo.
 * @post  All surviving nodes remain valid; freed nodes are gone.
 *
 * @threadsafety  Safe — operates on caller-owned list; calls real freeaddrinfo
 *               under the reentrancy guard.
 */
int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family);

/**
 * @brief Truncate an addrinfo list to at most @p limit nodes.
 *
 * @details Traverses `*result` counting nodes.  When the count reaches
 * @p limit, the remainder of the list (starting from `current->ai_next`) is
 * detached and freed via g_chaos_dns_real_freeaddrinfo() in a single call on
 * the sub-list head.
 *
 * **Ownership transfer**: the truncated tail nodes are freed; the caller must
 * not access them after this call.  The surviving prefix (up to @p limit
 * nodes) remains caller-owned.
 *
 * If @p limit is zero, the entire list is freed and `*result` is set to NULL.
 * If the list already has ≤ @p limit nodes, the function is a no-op.
 *
 * @param result  Pointer to the head pointer; `*result` may be set to NULL.
 * @param limit   Maximum number of nodes to retain; must be ≥ 1 for normal use
 *                (zero causes total free).
 *
 * @pre   `*result` is a valid addrinfo list allocated by the real getaddrinfo.
 * @post  `*result` has at most @p limit nodes; excess nodes are freed.
 *
 * @threadsafety  Safe — operates on caller-owned list; calls real freeaddrinfo
 *               under the reentrancy guard.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit);

/**
 * @brief Randomly permute the nodes in an addrinfo linked list in place.
 *
 * @details Implements the Fisher–Yates (Knuth) shuffle:
 *   1. Count the list length N.  If N < 2, return immediately.
 *   2. Heap-allocate an array of N `struct addrinfo *` pointers and fill it
 *      with the nodes in their current order.
 *   3. For i = N-1 down to 1: swap nodes[i] with nodes[j], where j is drawn
 *      uniformly from [0, i] using chaos_dns_prng_next_u32() % (i + 1).
 *   4. Relink the shuffled array into a singly-linked list and set *result to
 *      nodes[0].
 *   5. Free the temporary pointer array.
 *
 * If the heap allocation for the pointer array fails (calloc returns NULL),
 * the function returns without modifying the list (fail-open: the caller
 * still has a valid list in the original order).
 *
 * **Ownership**: no addrinfo nodes are allocated or freed.  Only ai_next
 * pointers are modified.  The caller retains ownership of all nodes
 * throughout.
 *
 * **PRNG usage**: each swap step draws one 32-bit value from
 * chaos_dns_prng_next_u32().  The modulo is taken over (i+1) which is at
 * most N ≤ CHAOS_DNS_MAX_RULES (256), well within the range where modulo bias
 * is negligible.
 *
 * @param result  Pointer to the head pointer of the list.
 *
 * @pre   `*result` is a valid addrinfo list.
 * @post  `*result` contains the same nodes in a uniformly random permutation;
 *        all nodes are still reachable via ai_next.
 *
 * @threadsafety  Advances TLS PRNG state; otherwise operates on caller-owned
 *               list with a local heap allocation that is freed before return.
 *               Safe for concurrent use on separate lists.
 */
void chaos_dns_shuffle_result_list(struct addrinfo **result);

#endif
