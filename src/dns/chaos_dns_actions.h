/**
 * @file chaos_dns_actions.h
 * @brief Effect primitives of libchaos-dns: the firing decision, delays, synthetic EAI_*
 *        errors, and the addrinfo list transforms.
 *
 * @details
 * The functions a wrapper calls once it holds a matched rule copy.
 *
 * ### Decision and pre-call effects
 *   - chaos_dns_probability_hit_sample() / chaos_dns_probability_hit() -- probability.
 *   - chaos_dns_rule_should_trigger() -- `@from`/`@until` window, `@size` gate,
 *     probability, then `@first` and hit counting (chaos_policy_fire()).
 *   - chaos_dns_rule_apply_latency() -- the delay itself (the caller decides first).
 *   - chaos_dns_rule_apply_gai() -- decision plus the EAI_* code.
 *
 * ### Result-list transforms
 *   Applied to the list the real getaddrinfo returned, or to the list OVERRIDE built,
 *   in the fixed order FILTER_FAMILY, SHUFFLE, LIMIT (chaos_dns_lookup.c):
 *   - FILTER_FAMILY first, so SHUFFLE and LIMIT work on the addresses that will
 *     actually be returned: LIMIT 2 after the filter yields two addresses of the wanted
 *     family, not up to two minus whatever the filter then drops.
 *   - SHUFFLE before LIMIT, so LIMIT keeps a random subset rather than always the first
 *     addresses in resolver order.
 *
 * ### Ownership
 *   The getaddrinfo wrapper owns `*result` throughout and hands it to the application.
 *   - chaos_dns_filter_result_list() unlinks nodes of the other family; nodes of a real
 *     result are released one by one with the real freeaddrinfo, nodes of a list built
 *     by OVERRIDE (chaos_dns_owned.h) are only unlinked, since they live in one block
 *     that goes with the list.
 *   - chaos_dns_limit_result_list() cuts the tail the same way.
 *   - chaos_dns_shuffle_result_list() only relinks ai_next (and moves the canonical name
 *     to the new head); it allocates a temporary pointer array.
 *   Real nodes go to the real freeaddrinfo, never to free() (the C library allocates
 *   them its own way: musl as one reference-counted block per result) and never to the
 *   freeaddrinfo wrapper.
 *
 * @module  libchaos-dns actions
 * @stability  Private
 */

#ifndef CHAOS_DNS_ACTIONS_H
#define CHAOS_DNS_ACTIONS_H

#include "chaos_dns_config.h"

/**
 * @brief Whether @p probability fires for the pre-drawn 32-bit @p sample.
 *
 * @details `(double)sample < probability * 2^32`: a uniform sample fires with
 * probability @p probability, to a resolution of 2^-32. probability <= 0.0 never fires;
 * probability >= 1.0 always fires, without comparing. The sample argument lets unit tests
 * drive exact boundaries without the PRNG.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @param sample       Uniform 32-bit sample.
 * @return  Non-zero if the rule fires; zero otherwise.
 *
 * @threadsafety  Pure function.
 */
int chaos_dns_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Whether @p probability fires, drawing one sample from the thread's PRNG.
 *
 * @param probability  Probability in [0.0, 1.0].
 * @return  Non-zero if the rule fires; zero otherwise.
 *
 * @threadsafety  Advances only the calling thread's PRNG by one step.
 */
int chaos_dns_probability_hit(double probability);

/**
 * @brief Sleeps for a LATENCY rule's latency_ms.
 *
 * @details Does not decide: callers run chaos_dns_rule_should_trigger() first, so the
 * qualifiers and the probability (`<ms>@<p>`) gate the delay. The sleep is
 * chaos_sleep_ms() (src/common/chaos_sleep.h): a raw clock_nanosleep on CLOCK_MONOTONIC,
 * restarted on EINTR with the remaining time, so the full delay elapses, errno is
 * preserved, and no other preloaded library (libchaos-time in particular) can shorten
 * or stretch it.
 *
 * @param rule  LATENCY rule copy; NULL or another effect is a no-op.
 *
 * @threadsafety  Blocks only the calling thread.
 */
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule);

/**
 * @brief Decides whether a matched rule fires on this call, and counts the hit if so.
 *
 * @details Gates, in order: the `@from`/`@until` window, the `@size` gate against
 * rule->call_size, the probability, then chaos_policy_fire(), which claims an `@first`
 * slot, rejects a copy whose rule has left the rule file, and counts the hit. Call it at
 * most once per decision: each firing is one hit.
 *
 * @param rule  Matched rule copy; NULL yields 0.
 * @return  Non-zero if the effect is to be applied now; zero otherwise.
 *
 * @threadsafety  Thread-local PRNG and atomic hit-slot updates.
 */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule);

/**
 * @brief Applies a GAI rule: stores its EAI_* code and returns 1 when it fires.
 *
 * @details No-op for a NULL rule, a NULL @p gai_error or another effect. Otherwise
 * chaos_dns_rule_should_trigger() decides.
 *
 * @param rule       Matched rule copy.
 * @param gai_error  Output: the EAI_* code when the rule fires; untouched otherwise.
 * @return  Non-zero if the caller must return @p *gai_error without resolving.
 *
 * @threadsafety  See chaos_dns_rule_should_trigger().
 */
int chaos_dns_rule_apply_gai(const chaos_dns_rule_t *rule, int *gai_error);

/**
 * @brief Number of nodes in an addrinfo list.
 *
 * @param result  Head of the list; NULL yields 0.
 * @return  Node count.
 *
 * @threadsafety  Read-only; the list must not change concurrently.
 */
size_t chaos_dns_result_count(const struct addrinfo *result);

/**
 * @brief Removes every node whose ai_family is not the one @p family keeps.
 *
 * @details Each removed node is unlinked and isolated (ai_next = NULL); a node of a real
 * result is then released with the real freeaddrinfo under the guard, a node of a list
 * built by OVERRIDE is left in its block. The canonical name, which callers read from
 * the head, moves on to the next node when its node is dropped, so it ends on the new
 * head. CHAOS_DNS_FAMILY_ANY returns 0 at once without touching the list.
 *
 * @param result  Address of the head pointer; `*result` changes when the head is dropped.
 * @param family  Family to keep: INET4 (AF_INET) or INET6 (AF_INET6).
 * @return  Non-zero if at least one node survives; zero if none does (the caller
 *          returns EAI_NONAME) or for ANY.
 *
 * @pre   `*result` is a list from the real getaddrinfo or from OVERRIDE.
 *
 * @threadsafety  Caller-owned list only.
 */
int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family);

/**
 * @brief Cuts an addrinfo list after @p limit nodes.
 *
 * @details The tail after node @p limit is detached and released with one call (nodes
 * of a real result go to the real freeaddrinfo; an OVERRIDE list's tail stays in its
 * block). A list of at most @p limit nodes is untouched. @p limit 0 releases the whole
 * list and sets `*result` to NULL; the parser never produces it (LIMIT requires >= 1).
 *
 * @param result  Address of the head pointer.
 * @param limit   Nodes to keep.
 *
 * @post  `*result` has at most @p limit nodes.
 *
 * @threadsafety  Caller-owned list only.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit);

/**
 * @brief Permutes the nodes of an addrinfo list uniformly at random, in place.
 *
 * @details Fisher-Yates: the N node pointers go into a calloc()ed array; for i from
 * N - 1 down to 1, node i is swapped with node `prng % (i + 1)`; the array is relinked
 * and the canonical name moved from the old head to the new one. Lists of fewer than 2
 * nodes are untouched. If calloc fails the list stays in its original order
 * (fail-open). The modulo bias of a 32-bit draw is below N / 2^32, negligible for
 * resolver-sized lists.
 *
 * @param result  Address of the head pointer; `*result` becomes the new head.
 *
 * @post  Same nodes, all reachable through ai_next; no node allocated or freed.
 *
 * @threadsafety  Thread-local PRNG; caller-owned list; one temporary heap allocation.
 */
void chaos_dns_shuffle_result_list(struct addrinfo **result);

#endif
