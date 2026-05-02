/**
 * @file test_dns_actions.c
 * @brief Unit tests for DNS-domain probability, GAI error injection, latency, result-list
 *   filtering, limiting, and shuffling helpers.
 *
 * Subsystem under test: `src/dns/chaos_dns_actions.c`
 *
 * Coverage approach:
 * - The production source file is included directly after replacing `calloc` with a test-local
 *   stub controlled by `g_force_calloc_fail`. This lets tests exercise the graceful-fallback
 *   path in `chaos_dns_shuffle_result_list` when temporary memory allocation fails, without
 *   system-level memory pressure.
 * - `CHAOS_DNS_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals required
 *   by the production action helpers.
 * - `chaos_dns_test_freeaddrinfo` is the test-local freeaddrinfo that actually releases the
 *   memory allocated by `make_result_node`. It is assigned to
 *   `g_chaos_dns_real_freeaddrinfo` in `reset_actions_state()` so the production
 *   `chaos_dns_call_real_freeaddrinfo` dispatches through it correctly.
 * - `make_result_node(family, canonname)` constructs a single `addrinfo` node with a real
 *   `sockaddr_in` or `sockaddr_in6` and an optional `canonname` copy, suitable for use
 *   in linked-list operations.
 *
 * Properties under test:
 * - Probability helpers: `chaos_dns_probability_hit_sample` at 0.0, 1.0, 0.5 boundary
 *   samples (0 and UINT32_MAX); `chaos_dns_probability_hit` at 0.0 and 1.0.
 * - GAI injection: `chaos_dns_rule_apply_gai` with probability=1.0 sets the output error
 *   and returns true; probability=0.0 does not apply; NULL rule or NULL output → false.
 * - `chaos_dns_rule_should_trigger`: NULL → false; GAI effect with probability=1.0 → true.
 * - Latency helper: a rule with LATENCY effect and `latency_ms=1` causes real sleep (not
 *   asserted on duration, just verifies no crash); REWRITE effect ignores the call.
 * - `chaos_dns_result_count(NULL)` → 0; `chaos_dns_call_real_freeaddrinfo(NULL)` is a no-op.
 * - Filter: `CHAOS_DNS_FAMILY_INET4` removes AF_INET6 nodes and keeps AF_INET nodes; the
 *   freed node count tracked via `g_freeaddrinfo_calls` is correct; NULL result-list pointer
 *   → false; empty list → false; `FAMILY_ANY` is a no-op (→ false).
 * - Filter with IPv6-first list: head node is AF_INET6, second is AF_INET; after filtering
 *   for INET4 the head becomes the AF_INET node.
 * - Limit: `limit(&head, 1)` frees the tail node; `limit(&head, 0)` frees all remaining
 *   nodes (head becomes NULL).
 * - Shuffle: 3-node list with a seeded PRNG retains all 3 nodes (count invariant);
 *   single-node list is unaffected; NULL and empty-list arguments are safe; calloc failure
 *   leaves the list intact (2 nodes remain); `limit` after shuffle produces expected count.
 *
 * What is NOT tested here:
 * - DNS wrapper call paths (tested in `test_chaos_dns.c`).
 * - Config file parsing and rule selection (tested in `test_dns_config.c`).
 * - Constructor initialisation and symbol resolution (tested in `test_dns_runtime.c`).
 */

#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

/**
 * @brief When non-zero, the `chaos_dns_test_calloc` stub returns NULL unconditionally.
 *
 * Set to 1 before calling `chaos_dns_shuffle_result_list` to exercise the allocation-failure
 * fallback path (shuffle aborts gracefully, leaving the list unchanged).
 */
static int g_force_calloc_fail = 0;

/**
 * @brief Number of times `chaos_dns_test_freeaddrinfo` has been called since the last reset.
 *
 * Incremented once per node freed. Used to assert that filter and limit operations release
 * exactly the expected number of nodes.
 */
static int g_freeaddrinfo_calls = 0;

/**
 * @brief Test-local calloc stub gated by `g_force_calloc_fail`.
 *
 * Returns NULL when `g_force_calloc_fail` is non-zero; otherwise delegates to the real
 * `calloc`. Replaces `calloc` inside the production actions source to intercept the temporary
 * array allocation used by `chaos_dns_shuffle_result_list`.
 *
 * @param count  Number of elements.
 * @param size   Size of each element.
 * @return NULL when forced to fail; real calloc result otherwise.
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
 * @brief Test-local freeaddrinfo that walks the linked list and frees each node's memory.
 *
 * Increments `g_freeaddrinfo_calls` for each node freed. Releases `ai_addr`, `ai_canonname`,
 * and the node itself in that order. Assigned to `g_chaos_dns_real_freeaddrinfo` by
 * `reset_actions_state()` so production code dispatches through this function.
 *
 * @param result  Head of the addrinfo linked list; may be NULL.
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

/**
 * @brief Allocate a single addrinfo node with a real sockaddr and optional canonname.
 *
 * For `AF_INET`, allocates and initialises a `sockaddr_in`; for any other family (treated as
 * IPv6), allocates a `sockaddr_in6`. If `canonname` is non-NULL, a `strdup` copy is stored
 * in `ai_canonname`. The caller is responsible for freeing the returned node via
 * `chaos_dns_test_freeaddrinfo`.
 *
 * @param family    Address family; `AF_INET` for IPv4, anything else for IPv6.
 * @param canonname Optional canonical name string; NULL if not needed.
 * @return Newly allocated addrinfo node; aborts on allocation failure.
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
 * @brief Reset all per-test action state to well-known defaults.
 *
 * Calls `chaos_dns_test_reset_runtime()` to zero the PRNG and real-function-pointer globals,
 * installs `chaos_dns_test_freeaddrinfo` as the active freeaddrinfo implementation, and
 * clears `g_force_calloc_fail` and `g_freeaddrinfo_calls`.
 */
static void reset_actions_state(void)
{
    chaos_dns_test_reset_runtime();
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_force_calloc_fail = 0;
    g_freeaddrinfo_calls = 0;
}

/**
 * @brief Invariant: probability sampling and GAI injection helpers produce correct
 *   outcomes at boundary values and respect NULL guards.
 *
 * Triggering condition: `chaos_dns_probability_hit_sample` with p=0.0/1.0/0.5 and
 *   sample=0/UINT32_MAX; `chaos_dns_probability_hit` with p=0.0/1.0; a rule with
 *   GAI effect and probability=1.0; and then with probability=0.0.
 *
 * Expected observable behaviour:
 * - `probability_hit_sample(0.0, 0)` → false; `(1.0, 0)` → true.
 * - `probability_hit_sample(0.5, 0)` → true (sample < threshold); `(0.5, UINT32_MAX)` → false.
 * - `probability_hit(0.0)` → false; `probability_hit(1.0)` → true.
 * - GAI rule with probability=1.0: `should_trigger` → true; `apply_gai` sets output to
 *   `EAI_AGAIN` and returns true.
 * - GAI rule with probability=0.0: `apply_gai` returns false and does not modify the output.
 * - NULL rule or NULL output pointer: `apply_gai` and `should_trigger` return false.
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
}

/**
 * @brief Invariant: latency application and result counting helpers handle edge cases safely.
 *
 * Triggering condition: `chaos_dns_rule_apply_latency` with a LATENCY rule and with a
 *   REWRITE rule; `chaos_dns_result_count(NULL)`; `chaos_dns_call_real_freeaddrinfo(NULL)`.
 *
 * Expected observable behaviour:
 * - A LATENCY rule with `latency_ms=1` completes without crashing (real nanosleep is invoked;
 *   no duration assertion is made in this test).
 * - A REWRITE rule passed to `apply_latency` is silently ignored (effect mismatch).
 * - `chaos_dns_result_count(NULL)` → 0.
 * - `chaos_dns_call_real_freeaddrinfo(NULL)` is a no-op (no crash, no freeaddrinfo call).
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
 * @brief Invariant: filter and limit operations remove exactly the expected nodes and
 *   update the list correctly.
 *
 * Triggering condition: a 3-node list (AF_INET, AF_INET6, AF_INET) filtered for INET4,
 *   then limited to 1 node, then limited to 0 nodes; followed by a 2-node list with
 *   AF_INET6 as head filtered for INET4.
 *
 * Expected observable behaviour:
 * - Filtering for INET4: the AF_INET6 node is freed (`g_freeaddrinfo_calls == 1`); the
 *   resulting list has 2 AF_INET nodes; head and head->ai_next are both AF_INET;
 *   head->ai_next->ai_next is NULL.
 * - `limit(&head, 1)`: the second node is freed (`g_freeaddrinfo_calls == 2`); head->ai_next
 *   is NULL.
 * - `limit(&head, 0)`: the remaining node is freed (`g_freeaddrinfo_calls == 3`);
 *   head becomes NULL.
 * - `filter_result_list(NULL, ...)` → false; filter on an already-NULL list → false;
 *   `FAMILY_ANY` on a NULL list → false (no-op).
 * - Filtering an IPv6-first 2-node list for INET4: the AF_INET6 head is removed and the
 *   remaining head is AF_INET (relink across the former head).
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
 * @brief Invariant: shuffle preserves node count, handles degenerate inputs safely, and
 *   falls back gracefully when the temporary allocation fails.
 *
 * Triggering condition: a 3-node list shuffled with a seeded PRNG; a single-node list;
 *   NULL and empty-list arguments; `g_force_calloc_fail = 1` with a 2-node list; a 3-node
 *   list followed by `chaos_dns_limit_result_list`.
 *
 * Expected observable behaviour:
 * - 3-node list with `g_chaos_dns_tls_prng_state = 1`: after shuffle,
 *   `chaos_dns_result_count(head) == 3` (nodes rearranged but none lost).
 * - Single-node list: count remains 1 after shuffle.
 * - `chaos_dns_shuffle_result_list(NULL)` is a no-op.
 * - Passing a pointer to a NULL head is a no-op.
 * - When `g_force_calloc_fail = 1` (temporary array cannot be allocated), a 2-node list
 *   is left untouched: count remains 2.
 * - 3-node list → `limit(&head, 2)` → count 2, with head and head->ai_next non-NULL
 *   and head->ai_next->ai_next NULL.
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

int main(void)
{
    test_probability_and_gai_helpers();
    test_latency_and_count_helpers();
    test_filter_and_limit_helpers();
    test_shuffle_helper();
    return 0;
}
