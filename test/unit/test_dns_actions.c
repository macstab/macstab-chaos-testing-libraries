/**
 * @file test_dns_actions.c
 * @brief Unit tests for the libchaos-dns effect helpers: probability, rule firing, GAI,
 *   LATENCY, and the FILTER_FAMILY / SHUFFLE / LIMIT result-list transforms.
 *
 * @details
 * Unit under test: `src/dns/chaos_dns_actions.c`, compiled into this file together with
 * `src/dns/chaos_dns_owned.c`. The suite proves:
 * - probability: 0.0 never hits, 1.0 always hits, and 0.5 maps the 32-bit sample space at
 *   2^31 (sample 0 hits, UINT32_MAX misses);
 * - firing: `chaos_dns_rule_should_trigger()` applies the `@from`/`@until` window, the `@size`
 *   gate, probability and `@first=N` in that order, and counts a hit only when the effect
 *   fires; a GAI rule writes its `gai_error` only when it fires, other effects never do;
 * - transforms: FILTER_FAMILY and LIMIT release exactly the dropped nodes through the real
 *   freeaddrinfo, SHUFFLE never loses a node, and all three keep `ai_canonname` on the head
 *   (where the C libraries put it and where callers read it);
 * - ownership: nodes of a list libchaos-dns built itself (OVERRIDE, see `chaos_dns_owned.h`)
 *   are only unlinked, never passed to the real freeaddrinfo; with no real freeaddrinfo
 *   resolved, dropped nodes are unlinked and leaked rather than freed by the wrong allocator;
 * - SHUFFLE fails open: when its temporary pointer array cannot be allocated the list is
 *   returned unchanged.
 *
 * Seams:
 * - `calloc` is macro-redirected to `chaos_dns_test_calloc()` for the actions source only, so
 *   `g_force_calloc_fail` fails SHUFFLE's scratch allocation without real memory pressure.
 * - `CHAOS_DNS_DEFINE_TEST_GLOBALS()` defines the real-function pointers and TLS state the
 *   source links against; `reset_actions_state()` installs `chaos_dns_test_freeaddrinfo()` as
 *   the real freeaddrinfo, which frees `make_result_node()` lists and counts every node.
 * - The PRNG state `g_chaos_dns_tls_prng_state` is set directly where order matters.
 *
 * Out of scope: the interposed entry points (`test_chaos_dns.c`), rule parsing and matching
 * (`test_dns_config.c`), and symbol resolution / constructor behaviour (`test_dns_runtime.c`).
 */

#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

/** @brief Non-zero makes every `calloc()` inside the actions source return NULL. */
static int g_force_calloc_fail = 0;

/**
 * @brief Nodes released through `chaos_dns_test_freeaddrinfo()` since the last reset.
 *
 * Counts nodes, not calls: LIMIT frees its tail as one sub-list, FILTER_FAMILY frees each
 * dropped node on its own, and both must add up to the number of nodes removed.
 */
static int g_freeaddrinfo_calls = 0;

/**
 * @brief `calloc()` replacement for the actions source; NULL while `g_force_calloc_fail` is set.
 *
 * The only `calloc()` in that source is SHUFFLE's pointer array, so this fails exactly that
 * allocation. Test code below the `#undef` uses the real `calloc()`.
 */
static void *chaos_dns_test_calloc(size_t count, size_t size)
{
    if (g_force_calloc_fail != 0)
    {
        return NULL;
    }
    return calloc(count, size);
}

/**
 * @brief Stand-in for the real freeaddrinfo: frees a `make_result_node()` list node by node.
 *
 * Frees `ai_addr`, `ai_canonname` and the node, and counts each node in
 * `g_freeaddrinfo_calls`. Freeing `ai_canonname` per node means a name duplicated onto two
 * nodes would be a double free under ASan, so it also checks that the transforms move the name
 * instead of copying it.
 *
 * @param result  Head of the list; NULL is a no-op.
 */
static void chaos_dns_test_freeaddrinfo(struct addrinfo *result)
{
    while (result != NULL)
    {
        struct addrinfo *next = result->ai_next;

        ++g_freeaddrinfo_calls;
        free(result->ai_addr);
        free(result->ai_canonname);
        free(result);
        result = next;
    }
}

#define calloc chaos_dns_test_calloc
#include "../../src/dns/chaos_dns_actions.c"
#undef calloc
#include "../../src/dns/chaos_dns_owned.c"

/**
 * @brief Heap-allocates one unlinked addrinfo node shaped like a C library result.
 *
 * @param family     `AF_INET` gets a `sockaddr_in`; any other value an AF_INET6 `sockaddr_in6`.
 * @param canonname  Duplicated into `ai_canonname`; NULL leaves it NULL.
 * @return The node; asserts on allocation failure. Release with chaos_dns_test_freeaddrinfo().
 */
static struct addrinfo *make_result_node(int family, const char *canonname)
{
    struct addrinfo *node = (struct addrinfo *)calloc(1U, sizeof(*node));

    assert(node != NULL);
    node->ai_family = family;
    if (family == AF_INET)
    {
        struct sockaddr_in *address = (struct sockaddr_in *)calloc(1U, sizeof(*address));

        assert(address != NULL);
        address->sin_family = AF_INET;
        node->ai_addr = (struct sockaddr *)address;
        node->ai_addrlen = (socklen_t)sizeof(*address);
    }
    else
    {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)calloc(1U, sizeof(*address));

        assert(address != NULL);
        address->sin6_family = AF_INET6;
        node->ai_addr = (struct sockaddr *)address;
        node->ai_addrlen = (socklen_t)sizeof(*address);
    }
    if (canonname != NULL)
    {
        node->ai_canonname = strdup(canonname);
        assert(node->ai_canonname != NULL);
    }

    return node;
}

/**
 * @brief Clears real-function pointers and PRNG state, then installs the counting freeaddrinfo
 *   and clears the calloc failure flag and node counter.
 */
static void reset_actions_state(void)
{
    chaos_dns_test_reset_runtime();
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_force_calloc_fail = 0;
    g_freeaddrinfo_calls = 0;
}

/**
 * @brief Proves the probability boundaries and that a GAI rule reports its error only when it
 *   fires.
 *
 * @details `hit_sample(p, s)` hits when `s < p * 2^32`; 0.0 and 1.0 short-circuit so no sample
 * can turn them into the opposite outcome. A GAI rule at 1.0 writes `EAI_AGAIN` and returns 1;
 * at 0.0, with a NULL rule or a NULL output it returns 0. A LATENCY rule at 1.0 returns 0 and
 * leaves the output untouched, so the getaddrinfo wrapper cannot fail a call through a rule of
 * the wrong effect.
 */
static void test_probability_and_gai_helpers(void)
{
    chaos_dns_rule_t rule;
    int gai_error = 0;

    reset_actions_state();
    assert(!chaos_dns_probability_hit_sample(0.0, 0U));
    assert(chaos_dns_probability_hit_sample(1.0, 0U));
    assert(chaos_dns_probability_hit_sample(0.5, 0U));
    assert(!chaos_dns_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_dns_probability_hit(0.0));
    assert(chaos_dns_probability_hit(1.0));

    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_DNS_EFFECT_GAI;
    rule.gai_error = EAI_AGAIN;
    rule.probability = 1.0;
    assert(chaos_dns_rule_should_trigger(&rule));
    assert(chaos_dns_rule_apply_gai(&rule, &gai_error));
    assert(gai_error == EAI_AGAIN);

    rule.probability = 0.0;
    assert(!chaos_dns_rule_apply_gai(&rule, &gai_error));
    assert(!chaos_dns_rule_apply_gai(NULL, &gai_error));
    assert(!chaos_dns_rule_apply_gai(&rule, NULL));
    assert(!chaos_dns_rule_should_trigger(NULL));

    /* Effect is checked before probability: a firing LATENCY rule must not write an error. */
    gai_error = 0;
    rule.probability = 1.0;
    rule.effect = CHAOS_DNS_EFFECT_LATENCY;
    assert(!chaos_dns_rule_apply_gai(&rule, &gai_error));
    assert(gai_error == 0);
}

/**
 * @brief Proves the LATENCY, count and free helpers accept degenerate input.
 *
 * @details A LATENCY rule of 1 ms sleeps for real through `chaos_sleep_ms()` (the duration is
 * not asserted here); a REWRITE rule passed to the latency helper returns without sleeping.
 * An empty list counts 0 nodes, and freeing NULL never reaches the real freeaddrinfo.
 */
static void test_latency_and_count_helpers(void)
{
    chaos_dns_rule_t rule;

    reset_actions_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_DNS_EFFECT_LATENCY;
    rule.latency_ms = 1U;
    chaos_dns_rule_apply_latency(&rule);
    rule.effect = CHAOS_DNS_EFFECT_REWRITE;
    chaos_dns_rule_apply_latency(&rule);
    assert(chaos_dns_result_count(NULL) == 0U);
    chaos_dns_call_real_freeaddrinfo(NULL);
}

/**
 * @brief Proves FILTER_FAMILY and LIMIT relink the list and free exactly the removed nodes.
 *
 * @details {v4, v6, v4} filtered to INET4 frees the middle node (relink across an interior
 * node); LIMIT 1 then frees the tail and LIMIT 0 frees the rest, leaving the head NULL. The
 * node counter checks every step. FILTER_FAMILY returns 0 for a NULL list pointer, an empty
 * list and ANY. Finally {v6, v4} filtered to INET4 drops the head, proving `*result` is
 * updated when the first node goes.
 */
static void test_filter_and_limit_helpers(void)
{
    struct addrinfo *head;

    reset_actions_state();
    head = make_result_node(AF_INET, "v4");
    head->ai_next = make_result_node(AF_INET6, "v6");
    head->ai_next->ai_next = make_result_node(AF_INET, "v4b");

    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    assert(head != NULL);
    assert(head->ai_family == AF_INET);
    assert(head->ai_next != NULL);
    assert(head->ai_next->ai_family == AF_INET);
    assert(head->ai_next->ai_next == NULL);
    assert(g_freeaddrinfo_calls == 1);

    chaos_dns_limit_result_list(&head, 1U);
    assert(head != NULL);
    assert(head->ai_next == NULL);
    assert(g_freeaddrinfo_calls == 2);

    chaos_dns_limit_result_list(&head, 0U);
    assert(head == NULL);
    assert(g_freeaddrinfo_calls == 3);

    assert(!chaos_dns_filter_result_list(NULL, CHAOS_DNS_FAMILY_INET6));
    assert(!chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET6));
    assert(!chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_ANY));

    head = make_result_node(AF_INET6, "only6");
    head->ai_next = make_result_node(AF_INET, "tail4");
    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    assert(head != NULL);
    assert(head->ai_family == AF_INET);
    chaos_dns_test_freeaddrinfo(head);
}

/**
 * @brief Proves SHUFFLE never loses or duplicates a node and fails open.
 *
 * @details A seeded 3-node shuffle still holds 3 nodes, and freeing them node by node under
 * ASan proves none is linked twice. A 1-node list, a NULL list pointer and an empty list are
 * left alone (fewer than 2 nodes allocate nothing). With the pointer-array allocation failed,
 * a 2-node list comes back intact instead of half relinked. LIMIT 2 on 3 nodes keeps
 * exactly two.
 */
static void test_shuffle_helper(void)
{
    struct addrinfo *head;

    reset_actions_state();
    head = make_result_node(AF_INET, "one");
    head->ai_next = make_result_node(AF_INET6, "two");
    head->ai_next->ai_next = make_result_node(AF_INET, "three");
    g_chaos_dns_tls_prng_state = 1U;
    chaos_dns_shuffle_result_list(&head);
    assert(chaos_dns_result_count(head) == 3U);
    chaos_dns_test_freeaddrinfo(head);

    head = make_result_node(AF_INET, "single");
    chaos_dns_shuffle_result_list(&head);
    assert(chaos_dns_result_count(head) == 1U);
    chaos_dns_test_freeaddrinfo(head);

    chaos_dns_shuffle_result_list(NULL);
    head = NULL;
    chaos_dns_shuffle_result_list(&head);

    g_force_calloc_fail = 1;
    head = make_result_node(AF_INET, "a");
    head->ai_next = make_result_node(AF_INET6, "b");
    chaos_dns_shuffle_result_list(&head);
    assert(chaos_dns_result_count(head) == 2U);
    chaos_dns_test_freeaddrinfo(head);

    g_force_calloc_fail = 0;
    head = make_result_node(AF_INET, "a");
    head->ai_next = make_result_node(AF_INET6, "b");
    head->ai_next->ai_next = make_result_node(AF_INET, "c");
    chaos_dns_limit_result_list(&head, 2U);
    assert(head != NULL);
    assert(head->ai_next != NULL);
    assert(head->ai_next->ai_next == NULL);
    chaos_dns_test_freeaddrinfo(head);
}

/**
 * @brief Proves a hit is counted only when the effect fires.
 *
 * @details The hits file must report firings, not evaluations: probability 1.0 fires and
 * counts 1, probability 0.0 neither fires nor counts. A rule with no hit slot (a copy made
 * outside a rule snapshot) still fires.
 */
static void test_should_trigger_counts_hits(void)
{
    chaos_dns_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_DNS_EFFECT_GAI;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_dns_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_dns_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Proves `chaos_dns_rule_should_trigger()` applies `@first`, `@from`/`@until` and
 *   `@size`.
 *
 * @details `@first=2` fires twice, then stops, and the hit count stays 2. The window is
 * compared with the wall clock in Unix ms: `@until=1` has passed, `@from=4000000000000`
 * (year 2096) has not started, and `@from=1` is open. `@size>100` rejects a call without a
 * byte count (`CHAOS_POLICY_NO_SIZE`) and a call of exactly 100 bytes (strict bound), passes
 * 101, and `@size<101` added on top rejects 101 again.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_dns_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_DNS_EFFECT_GAI;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_dns_rule_should_trigger(&rule) == 1);
    assert(chaos_dns_rule_should_trigger(&rule) == 1);
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_dns_rule_should_trigger(&rule) == 1);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_dns_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_dns_rule_should_trigger(&rule) == 0);
}

/**
 * @brief Proves `ai_canonname` stays on the head through every transform, and that nodes of
 *   an OVERRIDE list are never freed individually.
 *
 * @details Callers read the canonical name from the first node only. FILTER_FAMILY dropping
 * the named head hands the name to the next node; 20 shuffles keep it on whichever node ends
 * up first. When FILTER_FAMILY drops every node the name travels to the last one and is freed
 * with it (2 nodes freed, no leak). For a `chaos_dns_owned_copy()` list FILTER_FAMILY and
 * LIMIT only unlink: freeing one node of that single allocation would corrupt the heap, so the
 * counter stays 0 and the block is released whole by chaos_dns_owned_free().
 */
static void test_canonname_and_owned_lists(void)
{
    struct addrinfo *head;
    struct addrinfo *parts[1];
    struct addrinfo *owned;
    int index;

    reset_actions_state();
    head = make_result_node(AF_INET6, "canon");
    head->ai_next = make_result_node(AF_INET, NULL);
    head->ai_next->ai_next = make_result_node(AF_INET6, NULL);
    head->ai_next->ai_next->ai_next = make_result_node(AF_INET, NULL);
    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    assert(head->ai_canonname != NULL && strcmp(head->ai_canonname, "canon") == 0);
    assert(head->ai_next->ai_canonname == NULL);

    for (index = 0; index < 20; ++index)
    {
        chaos_dns_shuffle_result_list(&head);
        assert(head->ai_canonname != NULL && head->ai_next->ai_canonname == NULL);
    }
    chaos_dns_test_freeaddrinfo(head);

    g_freeaddrinfo_calls = 0;
    head = make_result_node(AF_INET6, "gone");
    head->ai_next = make_result_node(AF_INET6, NULL);
    assert(!chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    assert(head == NULL && g_freeaddrinfo_calls == 2);

    reset_actions_state();
    parts[0] = make_result_node(AF_INET, NULL);
    parts[0]->ai_next = make_result_node(AF_INET6, NULL);
    parts[0]->ai_next->ai_next = make_result_node(AF_INET, NULL);
    owned = chaos_dns_owned_copy(parts, 1U, "name");
    chaos_dns_test_freeaddrinfo(parts[0]);
    g_freeaddrinfo_calls = 0;
    head = owned;
    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    chaos_dns_limit_result_list(&head, 1U);
    assert(head == owned && head->ai_next == NULL && g_freeaddrinfo_calls == 0);
    assert(chaos_dns_owned_free(head) == 1);
}

/**
 * @brief Proves the FILTER_FAMILY and LIMIT edge cases, including a missing real
 *   freeaddrinfo.
 *
 * @details
 * - {v4, v6, v4} filtered to INET6 leaves {v6}, frees 2 nodes, and the head's name "v4" has
 *   moved onto the surviving v6 node.
 * - ANY on a non-empty list returns 0 and frees nothing.
 * - LIMIT 5 on 2 nodes changes nothing; LIMIT with a NULL list pointer or an empty list, with
 *   limit 0 or 1, frees nothing.
 * - With `g_chaos_dns_real_freeaddrinfo` NULL (symbol not yet resolved) a dropped node is
 *   unlinked, its `ai_next` cleared, and not freed: leaking is preferred over calling into an
 *   unresolved symbol or another allocator.
 * - The latency helper accepts NULL.
 */
static void test_filter_and_limit_edges(void)
{
    struct addrinfo *head;
    struct addrinfo *dropped;

    reset_actions_state();
    head = make_result_node(AF_INET, "v4");
    head->ai_next = make_result_node(AF_INET6, NULL);
    head->ai_next->ai_next = make_result_node(AF_INET, NULL);
    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET6));
    assert(head != NULL && head->ai_family == AF_INET6 && head->ai_next == NULL);
    assert(head->ai_canonname != NULL && strcmp(head->ai_canonname, "v4") == 0);
    assert(g_freeaddrinfo_calls == 2);

    head->ai_next = make_result_node(AF_INET, NULL);
    assert(!chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_ANY));
    assert(chaos_dns_result_count(head) == 2U);
    assert(g_freeaddrinfo_calls == 2);

    chaos_dns_limit_result_list(&head, 5U);
    assert(chaos_dns_result_count(head) == 2U);
    assert(g_freeaddrinfo_calls == 2);
    chaos_dns_test_freeaddrinfo(head);

    g_freeaddrinfo_calls = 0;
    head = NULL;
    chaos_dns_limit_result_list(NULL, 0U);
    chaos_dns_limit_result_list(NULL, 1U);
    chaos_dns_limit_result_list(&head, 0U);
    chaos_dns_limit_result_list(&head, 1U);
    assert(head == NULL && g_freeaddrinfo_calls == 0);

    g_chaos_dns_real_freeaddrinfo = NULL;
    head = make_result_node(AF_INET6, NULL);
    dropped = head;
    head->ai_next = make_result_node(AF_INET, NULL);
    assert(chaos_dns_filter_result_list(&head, CHAOS_DNS_FAMILY_INET4));
    assert(head != dropped && head->ai_family == AF_INET && head->ai_next == NULL);
    assert(dropped->ai_next == NULL);
    assert(g_freeaddrinfo_calls == 0);
    chaos_dns_test_freeaddrinfo(dropped);
    chaos_dns_test_freeaddrinfo(head);

    chaos_dns_rule_apply_latency(NULL);
}

int main(void)
{
    test_canonname_and_owned_lists();
    test_should_trigger_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_and_gai_helpers();
    test_latency_and_count_helpers();
    test_filter_and_limit_helpers();
    test_shuffle_helper();
    test_filter_and_limit_edges();
    return 0;
}
