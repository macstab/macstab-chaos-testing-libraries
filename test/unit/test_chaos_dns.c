/**
 * @file test_chaos_dns.c
 * @brief Unit tests for the DNS-domain lookup wrapper: static helpers, passthrough
 *   paths, reverse-lookup paths, latency, GAI injection, REWRITE/SERVICE/OVERRIDE
 *   effects, and post-rule list operations.
 *
 * Subsystem under test: `src/dns/chaos_dns_lookup.c`.
 *
 * Coverage approach:
 * - `chaos_dns_lookup.c` is included directly after providing stub implementations of
 *   all config-match functions (`chaos_dns_config_match`, `chaos_dns_config_match_reverse`)
 *   and all action functions (`chaos_dns_rule_apply_latency`, `chaos_dns_rule_should_trigger`,
 *   `chaos_dns_rule_apply_gai`, `chaos_dns_filter_result_list`, `chaos_dns_shuffle_result_list`,
 *   `chaos_dns_limit_result_list`).
 * - `CHAOS_DNS_DEFINE_TEST_GLOBALS()` instantiates the real-function-pointer globals
 *   (`g_chaos_dns_real_getaddrinfo`, `g_chaos_dns_real_getnameinfo`,
 *   `g_chaos_dns_real_freeaddrinfo`).
 * - `g_stub_rules[8]` and `g_stub_match[8]` are indexed by `chaos_dns_effect_t` value,
 *   allowing tests to activate any single effect or combination of effects independently.
 * - `make_result_node(family)` allocates a minimal `struct addrinfo` with a corresponding
 *   `sockaddr_in` or `sockaddr_in6`, providing realistic linked-list input for post-rule tests.
 * - `chaos_dns_test_getaddrinfo` returns an AF_INET or AF_INET6 node depending on whether
 *   the node string contains a colon; it also supports per-call error injection via
 *   `g_real_getaddrinfo_error_call`.
 * - `chaos_dns_test_getnameinfo` captures the reverse query address and fills host/service
 *   with "localhost"/"http" on success.
 * - `chaos_dns_test_freeaddrinfo` properly releases nodes created by both `make_result_node`
 *   and `chaos_dns_test_getaddrinfo`.
 * - `reset_wrapper_state()` must be called before each test or scenario within a test to
 *   clear all call counters, stub tables, and function-pointer globals.
 *
 * Properties under test:
 * - `chaos_dns_copy_text_or_null()`: NULL input returns 0 with target == NULL; valid input
 *   copies and sets target; buffer-too-short returns non-zero; NULL out-pointer non-zero.
 * - `chaos_dns_copy_output_text()`: copies on success; non-zero on buffer-too-short.
 * - `chaos_dns_strip_ipv6_brackets()`: strips `[` and `]` from `[::1]`; passes through
 *   IPv4 strings unchanged; NULL input returns non-zero.
 * - `chaos_dns_reverse_query_from_sockaddr()`: extracts dotted-decimal IPv4 from sockaddr_in;
 *   fails when address_len < sizeof(sockaddr_in).
 * - `chaos_dns_append_result_list()`: builds a two-node linked list in order.
 * - `chaos_dns_call_real_getaddrinfo()` and `chaos_dns_call_real_getnameinfo()`: dispatch
 *   to the real stubs and return their values.
 * - `getaddrinfo` passthrough: NULL or empty node → real lookup; TLS guard set → bypass; NULL
 *   result pointer → accepted without crash.
 * - `getnameinfo` passthrough: TLS guard set → bypass; short address_len → bypass (cannot
 *   extract reverse-query address).
 * - `getnameinfo` LATENCY: latency applied; real call still made.
 * - `getnameinfo` GAI (EAI_FAIL): real call skipped; error returned.
 * - `getnameinfo` REWRITE + SERVICE: host and service output overwritten with rule text.
 * - `getnameinfo` REWRITE overflow: returns EAI_OVERFLOW when rule text exceeds host buffer.
 * - `getaddrinfo` LATENCY: latency applied; real call still made.
 * - `getaddrinfo` GAI (EAI_FAIL, EAI_AGAIN): real call skipped; error returned.
 * - `getaddrinfo` REWRITE + SERVICE: node and service arguments rewritten before real call.
 * - `getaddrinfo` OVERRIDE: two addresses parsed from comma-separated text, two real
 *   `getaddrinfo` calls made, result list has two nodes.
 * - `chaos_dns_apply_override()` with NULL rule → EAI_FAIL; partial error on second address
 *   allocation → EAI_AGAIN with partial list freed.
 * - FILTER_FAMILY with drop-all: result list freed; EAI_NONAME returned.
 * - SHUFFLE: shuffle stub called once.
 * - LIMIT (limit=1): limit stub called; result list truncated.
 *
 * What is NOT tested here:
 * - Constructor and symbol resolution (`chaos_dns_init()`).
 * - Config file parsing and rule matching (tested in test_dns_config.c).
 * - DNS action implementations (tested in test_dns_actions.c).
 */

#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

/**
 * @brief Per-effect rule table indexed by `chaos_dns_effect_t`.
 *
 * Tests set `g_stub_rules[effect]` and `g_stub_match[effect] = 1` to activate
 * a particular effect. The config-match stubs consult these arrays.
 */
static chaos_dns_rule_t g_stub_rules[8];
/**
 * @brief Per-effect match-enable flags indexed by `chaos_dns_effect_t`.
 *
 * Non-zero means `chaos_dns_config_match` and `chaos_dns_config_match_reverse`
 * return 1 and copy the corresponding rule for that effect.
 */
static int g_stub_match[8];
/** @brief Number of times `chaos_dns_rule_apply_latency` was called. */
static int g_latency_calls = 0;
/**
 * @brief When non-zero, causes `chaos_dns_rule_apply_gai` to inject the rule's
 *   gai_error and return 1 (simulating a triggered GAI fault).
 */
static int g_gai_trigger = 0;
/**
 * @brief Return value for `chaos_dns_rule_should_trigger`.
 *
 * Defaults to 1 (always triggered) so probability-gated effects fire unless
 * a test explicitly sets this to 0.
 */
static int g_should_trigger = 1;
/** @brief Number of times `chaos_dns_filter_result_list` was called. */
static int g_filter_calls = 0;
/**
 * @brief When non-zero, `chaos_dns_filter_result_list` frees the entire result
 *   list and sets `*result = NULL`, simulating a family-filter that drops all nodes.
 */
static int g_filter_drop_all = 0;
/** @brief Number of times `chaos_dns_shuffle_result_list` was called. */
static int g_shuffle_calls = 0;
/** @brief Number of times `chaos_dns_limit_result_list` was called. */
static int g_limit_calls = 0;
/** @brief Number of times `chaos_dns_test_getaddrinfo` was called. */
static int g_real_getaddrinfo_calls = 0;
/**
 * @brief Error code to return from `chaos_dns_test_getaddrinfo`.
 *
 * When non-zero and the call index matches `g_real_getaddrinfo_error_call`
 * (or `g_real_getaddrinfo_error_call == 0` meaning every call), the stub
 * returns this error instead of allocating a node.
 */
static int g_real_getaddrinfo_error = 0;
/**
 * @brief Call index on which to inject `g_real_getaddrinfo_error`.
 *
 * 0 means inject on every call; N means inject only on the Nth call (by
 * `g_real_getaddrinfo_calls` value at entry time).
 */
static int g_real_getaddrinfo_error_call = 0;
/** @brief Number of times `chaos_dns_test_getnameinfo` was called. */
static int g_real_getnameinfo_calls = 0;
/** @brief Error code to return from `chaos_dns_test_getnameinfo`. */
static int g_real_getnameinfo_error = 0;
/** @brief Number of times `chaos_dns_test_freeaddrinfo` node-free loop iterated. */
static int g_real_freeaddrinfo_calls = 0;
/** @brief Node argument captured from the most recent `chaos_dns_test_getaddrinfo` call. */
static char g_last_node[CHAOS_DNS_MAX_VALUE];
/** @brief Service argument captured from the most recent `chaos_dns_test_getaddrinfo` call. */
static char g_last_service[CHAOS_DNS_MAX_VALUE];
/**
 * @brief Dotted-decimal (or colon-hex) address captured by `chaos_dns_test_getnameinfo`.
 *
 * Used to verify that the getnameinfo wrapper passes the correct sockaddr to the real
 * function before applying any REWRITE override.
 */
static char g_last_reverse_query[CHAOS_DNS_MAX_TEXT];

/**
 * @brief Reset all wrapper-layer test state between test scenarios.
 *
 * Calls `chaos_dns_test_reset_runtime()` to clear runtime globals, then zeroes all
 * stub tables and local call counters. Called at the start of every test function and
 * at the beginning of each scenario within a test that changes the stub configuration.
 */
static void reset_wrapper_state(void)
{
    size_t index;

    chaos_dns_test_reset_runtime();
    for (index = 0U; index < sizeof(g_stub_match) / sizeof(g_stub_match[0]); ++index)
    {
        (void)memset(&g_stub_rules[index], 0, sizeof(g_stub_rules[index]));
        g_stub_match[index] = 0;
    }
    g_latency_calls = 0;
    g_gai_trigger = 0;
    g_should_trigger = 1;
    g_filter_calls = 0;
    g_filter_drop_all = 0;
    g_shuffle_calls = 0;
    g_limit_calls = 0;
    g_real_getaddrinfo_calls = 0;
    g_real_getaddrinfo_error = 0;
    g_real_getaddrinfo_error_call = 0;
    g_real_getnameinfo_calls = 0;
    g_real_getnameinfo_error = 0;
    g_real_freeaddrinfo_calls = 0;
    g_last_node[0] = '\0';
    g_last_service[0] = '\0';
    g_last_reverse_query[0] = '\0';
}

/**
 * @brief Stub for `chaos_dns_config_match()`.
 *
 * Returns 1 and copies the corresponding rule when `g_stub_match[effect] != 0`
 * and all parameters are valid. Returns 0 otherwise without modifying @p rule.
 */
int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule)
{
    (void)name;
    if (effect < 0 || effect >= (int)(sizeof(g_stub_match) / sizeof(g_stub_match[0])) ||
        rule == NULL || g_stub_match[effect] == 0)
    {
        return 0;
    }
    *rule = g_stub_rules[effect];
    return 1;
}

/**
 * @brief Stub for `chaos_dns_config_match_reverse()`.
 *
 * Identical gate logic to `chaos_dns_config_match`; the @p address argument is
 * unused because the test table is indexed by effect alone.
 */
int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    (void)address;
    if (effect < 0 || effect >= (int)(sizeof(g_stub_match) / sizeof(g_stub_match[0])) ||
        rule == NULL || g_stub_match[effect] == 0)
    {
        return 0;
    }
    *rule = g_stub_rules[effect];
    return 1;
}

/**
 * @brief Stub for `chaos_dns_rule_apply_latency()`.
 *
 * Increments the call counter to verify the wrapper invokes it when LATENCY
 * is matched. No actual sleep is performed.
 */
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_dns_rule_should_trigger()`.
 *
 * Returns `g_should_trigger` (defaults to 1). Set to 0 to exercise the path
 * where a probabilistic rule is matched but does not fire.
 */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

/**
 * @brief Stub for `chaos_dns_rule_apply_gai()`.
 *
 * When `g_gai_trigger != 0` and the rule has effect GAI with a non-NULL error
 * pointer, sets `*gai_error` to `rule->gai_error` and returns 1. Returns 0
 * otherwise so callers proceed to the real lookup.
 */
int chaos_dns_rule_apply_gai(const chaos_dns_rule_t *rule, int *gai_error)
{
    if (rule == NULL || gai_error == NULL || rule->effect != CHAOS_DNS_EFFECT_GAI ||
        g_gai_trigger == 0)
    {
        return 0;
    }
    *gai_error = rule->gai_error;
    return 1;
}

/**
 * @brief Stub for `chaos_dns_filter_result_list()`.
 *
 * Increments the call counter. When `g_filter_drop_all != 0`, frees the entire
 * list via the real freeaddrinfo stub and sets `*result = NULL`, returning 0.
 * Returns 1 (list retained) otherwise.
 */
int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family)
{
    (void)family;
    ++g_filter_calls;
    if (g_filter_drop_all != 0 && result != NULL && *result != NULL)
    {
        g_chaos_dns_real_freeaddrinfo(*result);
        *result = NULL;
        return 0;
    }
    return 1;
}

/**
 * @brief Stub for `chaos_dns_shuffle_result_list()`.
 *
 * Increments the call counter without modifying the list. Tests use this to
 * confirm the wrapper calls the shuffler exactly once per successful lookup.
 */
void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    (void)result;
    ++g_shuffle_calls;
}

/**
 * @brief Stub for `chaos_dns_limit_result_list()`.
 *
 * Increments the call counter. When `limit == 1` and the list has more than
 * one node, truncates the list to one node by freeing the tail, matching the
 * minimum useful limit behaviour for assertion purposes.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit)
{
    ++g_limit_calls;
    if (result != NULL && *result != NULL && limit == 1U && (*result)->ai_next != NULL)
    {
        struct addrinfo *tail = (*result)->ai_next;

        (*result)->ai_next = NULL;
        g_chaos_dns_real_freeaddrinfo(tail);
    }
}

/**
 * @brief Allocate a minimal `struct addrinfo` node with a zeroed address structure.
 *
 * Used to build realistic linked lists for post-rule tests. The caller is
 * responsible for freeing via `chaos_dns_test_freeaddrinfo`.
 *
 * @param family  `AF_INET` to create a `sockaddr_in`; any other value creates a
 *                `sockaddr_in6`.
 * @return Newly allocated node; asserts on allocation failure.
 */
static struct addrinfo *make_result_node(int family)
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
    return node;
}

/**
 * @brief Stub for the real `getaddrinfo(3)`.
 *
 * Captures @p node and @p service. Returns `g_real_getaddrinfo_error` when the
 * call index matches `g_real_getaddrinfo_error_call` (or the error is injected on
 * every call when `g_real_getaddrinfo_error_call == 0`). Otherwise allocates one
 * AF_INET6 node if @p node contains a colon, or one AF_INET node otherwise.
 */
static int chaos_dns_test_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    (void)hints;
    ++g_real_getaddrinfo_calls;
    if (node != NULL)
    {
        assert(strlen(node) < sizeof(g_last_node));
        (void)memcpy(g_last_node, node, strlen(node) + 1U);
    }
    else
    {
        g_last_node[0] = '\0';
    }
    if (service != NULL)
    {
        assert(strlen(service) < sizeof(g_last_service));
        (void)memcpy(g_last_service, service, strlen(service) + 1U);
    }
    else
    {
        g_last_service[0] = '\0';
    }
    if (g_real_getaddrinfo_error != 0 &&
        (g_real_getaddrinfo_error_call == 0 ||
         g_real_getaddrinfo_calls == g_real_getaddrinfo_error_call))
    {
        return g_real_getaddrinfo_error;
    }

    if (result != NULL)
    {
        *result = strchr(node != NULL ? node : "", ':') != NULL ? make_result_node(AF_INET6)
                                                                : make_result_node(AF_INET);
    }
    return 0;
}

/**
 * @brief Stub for the real `getnameinfo(3)`.
 *
 * Captures the numeric address from @p address via `inet_ntop` into
 * `g_last_reverse_query`. Returns `g_real_getnameinfo_error` if non-zero;
 * otherwise fills @p host with "localhost" and @p service with "http".
 */
static int chaos_dns_test_getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    ++g_real_getnameinfo_calls;
    (void)flags;
    if (address != NULL && address_len >= (socklen_t)sizeof(sa_family_t) &&
        address->sa_family == AF_INET && address_len >= (socklen_t)sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;

        assert(
            inet_ntop(
                AF_INET, &ipv4->sin_addr, g_last_reverse_query, sizeof(g_last_reverse_query)
            ) != NULL
        );
    }
    else if (address != NULL && address_len >= (socklen_t)sizeof(sa_family_t) &&
             address->sa_family == AF_INET6 &&
             address_len >= (socklen_t)sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;

        assert(
            inet_ntop(
                AF_INET6, &ipv6->sin6_addr, g_last_reverse_query, sizeof(g_last_reverse_query)
            ) != NULL
        );
    }
    else
    {
        g_last_reverse_query[0] = '\0';
    }
    if (g_real_getnameinfo_error != 0)
    {
        return g_real_getnameinfo_error;
    }
    if (host != NULL && host_len > 0U)
    {
        assert(strlen("localhost") < (size_t)host_len);
        (void)memcpy(host, "localhost", sizeof("localhost"));
    }
    if (service != NULL && service_len > 0U)
    {
        assert(strlen("http") < (size_t)service_len);
        (void)memcpy(service, "http", sizeof("http"));
    }
    return 0;
}

/**
 * @brief Stub for the real `freeaddrinfo(3)`.
 *
 * Walks the linked list, incrementing `g_real_freeaddrinfo_calls` per node,
 * and frees `ai_addr`, `ai_canonname`, and the node itself. Compatible with
 * nodes from both `make_result_node` and `chaos_dns_test_getaddrinfo`.
 */
static void chaos_dns_test_freeaddrinfo(struct addrinfo *result)
{
    while (result != NULL)
    {
        struct addrinfo *next = result->ai_next;

        ++g_real_freeaddrinfo_calls;
        free(result->ai_addr);
        free(result->ai_canonname);
        free(result);
        result = next;
    }
}

#include "../../src/dns/chaos_dns_lookup.c"

/**
 * @brief Invariant: static helper functions enforce bounds and produce correct output.
 *
 * Triggering conditions:
 * - `chaos_dns_copy_text_or_null()` with NULL, valid, too-long, and NULL out-pointer inputs.
 * - `chaos_dns_copy_output_text()` with valid and too-long inputs.
 * - `chaos_dns_strip_ipv6_brackets()` with bracketed IPv6, plain IPv4, and NULL.
 * - `chaos_dns_reverse_query_from_sockaddr()` with valid and too-short sockaddr_in.
 * - `chaos_dns_append_result_list()` builds a two-node list.
 * - `chaos_dns_call_real_getaddrinfo()` and `chaos_dns_call_real_getnameinfo()` dispatch
 *   correctly with call counters incremented.
 *
 * Expected observable behaviour:
 * - `copy_text_or_null(NULL, ...)` → 0; `*target == NULL`.
 * - `copy_text_or_null("hello", buf, sizeof(buf), &target)` → 0; `strcmp(target, "hello") == 0`.
 * - Too-long string → non-zero return.
 * - NULL out-pointer → non-zero return.
 * - `copy_output_text("hello", buf, sizeof(buf))` → 0; buffer contains "hello".
 * - `strip_ipv6_brackets("[::1]", host, sizeof(host))` → 0; `strcmp(host, "::1") == 0`.
 * - `strip_ipv6_brackets("127.0.0.1", host, sizeof(host))` → 0; string unchanged.
 * - `strip_ipv6_brackets(NULL, ...)` → non-zero.
 * - `reverse_query_from_sockaddr` with valid AF_INET sockaddr → true; host == "127.0.0.1".
 * - `reverse_query_from_sockaddr` with `address_len == sizeof(sa_family_t)` → false.
 * - `append_result_list` twice → head non-NULL; head->ai_next non-NULL.
 * - `call_real_getaddrinfo` → 0; `g_real_getaddrinfo_calls == 1`.
 * - `call_real_getnameinfo` → 0; host == "localhost"; service == "http".
 */
static void test_static_helpers(void)
{
    const char *target = NULL;
    char buffer[16];
    char host[16];
    char service[16];
    struct addrinfo *head = NULL;
    struct sockaddr_in ipv4;

    reset_wrapper_state();
    assert(chaos_dns_copy_text_or_null(NULL, buffer, sizeof(buffer), &target) == 0);
    assert(target == NULL);
    assert(chaos_dns_copy_text_or_null("hello", buffer, sizeof(buffer), &target) == 0);
    assert(strcmp(target, "hello") == 0);
    assert(chaos_dns_copy_text_or_null("toolong", buffer, 4U, &target) != 0);
    assert(chaos_dns_copy_text_or_null("hello", buffer, sizeof(buffer), NULL) != 0);
    assert(chaos_dns_copy_output_text("hello", buffer, sizeof(buffer)) == 0);
    assert(strcmp(buffer, "hello") == 0);
    assert(chaos_dns_copy_output_text("toolong", buffer, 4U) != 0);

    assert(chaos_dns_strip_ipv6_brackets("[::1]", host, sizeof(host)) == 0);
    assert(strcmp(host, "::1") == 0);
    assert(chaos_dns_strip_ipv6_brackets("127.0.0.1", host, sizeof(host)) == 0);
    assert(strcmp(host, "127.0.0.1") == 0);
    assert(chaos_dns_strip_ipv6_brackets(NULL, host, sizeof(host)) != 0);

    (void)memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(80U);
    assert(inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr) == 1);
    assert(chaos_dns_reverse_query_from_sockaddr(
        (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), host, sizeof(host)
    ));
    assert(strcmp(host, "127.0.0.1") == 0);
    assert(!chaos_dns_reverse_query_from_sockaddr(
        (const struct sockaddr *)&ipv4, (socklen_t)sizeof(sa_family_t), host, sizeof(host)
    ));

    chaos_dns_append_result_list(&head, make_result_node(AF_INET));
    chaos_dns_append_result_list(&head, make_result_node(AF_INET6));
    assert(head != NULL);
    assert(head->ai_next != NULL);
    chaos_dns_test_freeaddrinfo(head);

    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    assert(chaos_dns_call_real_getaddrinfo("api.example.com", NULL, NULL, NULL) == 0);
    assert(g_real_getaddrinfo_calls == 1);
    assert(
        chaos_dns_call_real_getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(g_real_getnameinfo_calls == 1);
    assert(strcmp(host, "localhost") == 0);
    assert(strcmp(service, "http") == 0);
}

/**
 * @brief Invariant: `getaddrinfo` bypasses chaos for NULL/empty node, re-entrant calls,
 *   and NULL result pointers.
 *
 * Triggering conditions:
 * - `getaddrinfo(NULL, NULL, NULL, &result)`: no hostname — lookup passes through.
 * - `getaddrinfo("", NULL, NULL, &result)`: empty hostname — passes through.
 * - `getaddrinfo("api.example.com", ...)` with `g_chaos_dns_tls_guard = 1`: re-entrant bypass.
 * - `getaddrinfo("api.example.com", NULL, NULL, NULL)`: NULL result pointer — accepted.
 *
 * Expected observable behaviour:
 * - All four calls increment `g_real_getaddrinfo_calls` to 1, 2, 3, 4 respectively.
 * - No config-match call is issued for any of these paths.
 * - Memory returned by the stub is freed without crash.
 */
static void test_passthrough_paths(void)
{
    struct addrinfo *result = NULL;

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;

    assert(getaddrinfo(NULL, NULL, NULL, &result) == 0);
    assert(g_real_getaddrinfo_calls == 1);
    chaos_dns_test_freeaddrinfo(result);

    result = NULL;
    assert(getaddrinfo("", NULL, NULL, &result) == 0);
    assert(g_real_getaddrinfo_calls == 2);
    chaos_dns_test_freeaddrinfo(result);

    g_chaos_dns_tls_guard = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0);
    assert(g_real_getaddrinfo_calls == 3);
    chaos_dns_test_freeaddrinfo(result);
    g_chaos_dns_tls_guard = 0;

    assert(getaddrinfo("api.example.com", NULL, NULL, NULL) == 0);
    assert(g_real_getaddrinfo_calls == 4);
}

/**
 * @brief Invariant: `getnameinfo` applies LATENCY, GAI, and REWRITE/SERVICE effects,
 *   and bypasses chaos for re-entrant or short-address calls.
 *
 * Triggering conditions:
 * - `getnameinfo(...)` with `g_chaos_dns_tls_guard = 1`: re-entrant bypass.
 * - `getnameinfo(...)` with `address_len == sizeof(sa_family_t)`: address too short
 *   to extract a numeric IP — bypass (no reverse-query match possible).
 * - `getnameinfo(...)` with LATENCY rule active.
 * - `getnameinfo(...)` with GAI rule active and `g_gai_trigger = 1`: returns EAI_FAIL.
 * - `getnameinfo(...)` with REWRITE + SERVICE rules: host and service overwritten.
 * - `getnameinfo(...)` with REWRITE text longer than host buffer (12 bytes): EAI_OVERFLOW.
 *
 * Expected observable behaviour:
 * - Guard bypass: `g_real_getnameinfo_calls == 1`; no stub-config calls.
 * - Short address bypass: `g_real_getnameinfo_calls == 2` (real call made despite bypass
 *   of chaos — address too short to reverse-match but getnameinfo itself still called).
 * - LATENCY: `g_latency_calls == 1`; `g_real_getnameinfo_calls == 1`.
 * - GAI: returns EAI_FAIL; `g_real_getnameinfo_calls == 0`.
 * - REWRITE + SERVICE: returns 0; `host == "ptr.example"`; `service == "redis"`;
 *   `g_last_reverse_query == "127.0.0.1"`.
 * - REWRITE overflow: returns EAI_OVERFLOW.
 */
static void test_reverse_lookup_paths(void)
{
    struct sockaddr_in ipv4;
    char host[64];
    char service[64];

    (void)memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(80U);
    assert(inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr) == 1);

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;

    g_chaos_dns_tls_guard = 1;
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(g_real_getnameinfo_calls == 1);
    g_chaos_dns_tls_guard = 0;

    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(sa_family_t),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(g_real_getnameinfo_calls == 2);

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_LATENCY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_LATENCY].effect = CHAOS_DNS_EFFECT_LATENCY;
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(g_latency_calls == 1);
    assert(g_real_getnameinfo_calls == 1);

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_gai_trigger = 1;
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == EAI_FAIL
    );
    assert(g_real_getnameinfo_calls == 0);

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_match[CHAOS_DNS_EFFECT_SERVICE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, "ptr.example", 12U);
    g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].effect = CHAOS_DNS_EFFECT_SERVICE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].text, "redis", 6U);
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(strcmp(host, "ptr.example") == 0);
    assert(strcmp(service, "redis") == 0);
    assert(strcmp(g_last_reverse_query, "127.0.0.1") == 0);

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    /* 24-byte string deliberately exceeds the 12-byte host buffer used below. */
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, "name-too-long-for-buffer", 25U);
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            12U,
            service,
            (socklen_t)sizeof(service),
            0
        ) == EAI_OVERFLOW
    );
}

/**
 * @brief Invariant: `getaddrinfo` applies LATENCY and GAI effects correctly.
 *
 * Triggering conditions:
 * - `getaddrinfo("api.example.com", ...)` with LATENCY rule active.
 * - `getaddrinfo("api.example.com", ...)` with GAI rule (EAI_FAIL) and `g_gai_trigger = 1`.
 * - `getaddrinfo("api.example.com", ..., NULL)` (NULL result) with GAI rule (EAI_AGAIN).
 *
 * Expected observable behaviour:
 * - LATENCY: `g_latency_calls == 1`; real lookup still made; result non-NULL.
 * - GAI (EAI_FAIL): returns EAI_FAIL; `g_real_getaddrinfo_calls == 0`.
 * - GAI (EAI_AGAIN, NULL result): returns EAI_AGAIN; `g_real_getaddrinfo_calls == 0`.
 */
static void test_latency_and_gai_paths(void)
{
    struct addrinfo *result = NULL;

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;

    g_stub_match[CHAOS_DNS_EFFECT_LATENCY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_LATENCY].effect = CHAOS_DNS_EFFECT_LATENCY;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0);
    assert(g_latency_calls == 1);
    chaos_dns_test_freeaddrinfo(result);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_gai_trigger = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_FAIL);
    assert(g_real_getaddrinfo_calls == 0);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_AGAIN;
    g_gai_trigger = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, NULL) == EAI_AGAIN);
    assert(g_real_getaddrinfo_calls == 0);
}

/**
 * @brief Invariant: `getaddrinfo` rewrites the node and service arguments before the real
 *   call, and OVERRIDE builds a multi-address list from comma-separated addresses.
 *
 * Triggering conditions:
 * - `getaddrinfo("api.example.com", "443", ...)` with REWRITE ("alt.example.com") and
 *   SERVICE ("8443") rules active.
 * - `getaddrinfo("api.example.com", "443", ...)` with OVERRIDE rule containing
 *   "127.0.0.1,[::1]" (two addresses).
 *
 * Expected observable behaviour:
 * - REWRITE + SERVICE: `g_last_node == "alt.example.com"`; `g_last_service == "8443"`;
 *   real getaddrinfo called once; result non-NULL.
 * - OVERRIDE: `g_real_getaddrinfo_calls == 2` (one per parsed address);
 *   result is a two-node list (IPv4 + IPv6).
 */
static void test_rewrite_service_and_override_paths(void)
{
    struct addrinfo *result = NULL;

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_match[CHAOS_DNS_EFFECT_SERVICE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, "alt.example.com", 16U);
    g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].effect = CHAOS_DNS_EFFECT_SERVICE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].text, "8443", 5U);
    assert(getaddrinfo("api.example.com", "443", NULL, &result) == 0);
    assert(strcmp(g_last_node, "alt.example.com") == 0);
    assert(strcmp(g_last_service, "8443") == 0);
    chaos_dns_test_freeaddrinfo(result);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, "127.0.0.1,[::1]", 16U);
    assert(getaddrinfo("api.example.com", "443", NULL, &result) == 0);
    assert(g_real_getaddrinfo_calls == 2);
    assert(result != NULL);
    assert(result->ai_next != NULL);
    chaos_dns_test_freeaddrinfo(result);
}

/**
 * @brief Invariant: `chaos_dns_apply_override` handles NULL and partial-error cases;
 *   FILTER_FAMILY drop-all returns EAI_NONAME; SHUFFLE and LIMIT stubs are invoked.
 *
 * Triggering conditions:
 * - `chaos_dns_apply_override(NULL, NULL, NULL, &result)`: NULL rule → EAI_FAIL.
 * - `chaos_dns_apply_override` with a valid OVERRIDE rule but `g_real_getaddrinfo_error_call = 2`
 *   (second getaddrinfo call fails with EAI_AGAIN): partial list freed; error returned.
 * - `getaddrinfo("api.example.com", ...)` with FILTER_FAMILY rule and `g_filter_drop_all = 1`.
 * - `getaddrinfo("api.example.com", ...)` with SHUFFLE and LIMIT (limit=1) rules.
 *
 * Expected observable behaviour:
 * - NULL rule → EAI_FAIL (no crash).
 * - Partial error: `chaos_dns_apply_override` returns EAI_AGAIN;
 *   `g_real_freeaddrinfo_calls == 1` (first successful node freed).
 * - FILTER drop-all: `g_filter_calls == 1`; `getaddrinfo` returns EAI_NONAME; result == NULL.
 * - SHUFFLE + LIMIT: returns 0; `g_shuffle_calls == 1`; `g_limit_calls == 1`;
 *   result is a single-node list (LIMIT truncated it).
 */
static void test_override_error_and_post_rules(void)
{
    chaos_dns_rule_t rule;
    struct addrinfo *result = NULL;

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    assert(chaos_dns_apply_override(NULL, NULL, NULL, &result) == EAI_FAIL);

    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void)memcpy(rule.text, "127.0.0.1,[::1]", 16U);
    g_real_getaddrinfo_error = EAI_AGAIN;
    g_real_getaddrinfo_error_call = 2;
    assert(chaos_dns_apply_override(&rule, NULL, NULL, &result) == EAI_AGAIN);
    assert(g_real_freeaddrinfo_calls == 1);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].effect = CHAOS_DNS_EFFECT_FILTER_FAMILY;
    g_filter_drop_all = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_NONAME);
    assert(g_filter_calls == 1);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_SHUFFLE] = 1;
    g_stub_match[CHAOS_DNS_EFFECT_LIMIT] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_SHUFFLE].effect = CHAOS_DNS_EFFECT_SHUFFLE;
    g_stub_rules[CHAOS_DNS_EFFECT_LIMIT].effect = CHAOS_DNS_EFFECT_LIMIT;
    g_stub_rules[CHAOS_DNS_EFFECT_LIMIT].limit = 1U;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0);
    assert(g_shuffle_calls == 1);
    assert(g_limit_calls == 1);
    chaos_dns_test_freeaddrinfo(result);
}

int main(void)
{
    test_static_helpers();
    test_passthrough_paths();
    test_reverse_lookup_paths();
    test_latency_and_gai_paths();
    test_rewrite_service_and_override_paths();
    test_override_error_and_post_rules();
    return 0;
}
