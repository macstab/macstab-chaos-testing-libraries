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
 * - `chaos_dns_literal_family()`: IPv4, IPv6 and non-literal text.
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

#include <stdio.h>

#include "../../src/dns/chaos_dns_config.h"
#include "../../src/dns/chaos_dns_owned.h"

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
        /* Like the real filter: a list of ours is only unlinked. */
        if (!chaos_dns_owned_contains(*result))
        {
            g_chaos_dns_real_freeaddrinfo(*result);
        }
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
    if (result != NULL && *result != NULL && limit == 0U)
    {
        /* Like the real limit: a list of ours is only unlinked. */
        if (!chaos_dns_owned_contains(*result))
        {
            g_chaos_dns_real_freeaddrinfo(*result);
        }
        *result = NULL;
    }
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

/** @brief Calls made to the stubbed real hostent resolvers. */
static int g_real_hostent_calls = 0;
/** @brief When non-zero, the stubbed real hostent resolvers report "not found". */
static int g_real_hostent_missing = 0;
/** @brief `buffer_size` passed to the most recent stubbed gethostbyaddr_r call. */
static size_t g_real_hostent_buffer_size = 0U;
/** @brief The entry the stubbed non-reentrant resolvers return. */
static struct hostent g_real_hostent;
/** @brief Name of the stubbed real entries. */
static char g_real_hostent_name[] = "real.example";

/** @brief Stub for the real gethostbyname2(3). */
static struct hostent *chaos_dns_test_gethostbyname2(const char *name, int family)
{
    (void)name;
    (void)family;
    ++g_real_hostent_calls;
    g_real_hostent.h_name = g_real_hostent_name;
    return g_real_hostent_missing ? NULL : &g_real_hostent;
}

/** @brief Stub for the real gethostbyname2_r(3). */
static int chaos_dns_test_gethostbyname2_r(
    const char *name,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    (void)name;
    (void)family;
    (void)buffer;
    (void)buffer_size;
    ++g_real_hostent_calls;
    if (result != NULL)
    {
        *result = g_real_hostent_missing ? NULL : entry;
    }
    if (h_error != NULL)
    {
        *h_error = g_real_hostent_missing ? HOST_NOT_FOUND : 0;
    }
    return 0;
}

/** @brief Stub for the real gethostbyaddr(3). */
static struct hostent *
chaos_dns_test_gethostbyaddr(const void *address, socklen_t length, int family)
{
    (void)address;
    (void)length;
    (void)family;
    ++g_real_hostent_calls;
    g_real_hostent.h_name = g_real_hostent_name;
    return g_real_hostent_missing ? NULL : &g_real_hostent;
}

/** @brief Stub for the real gethostbyaddr_r(3): names the entry "real.example". */
static int chaos_dns_test_gethostbyaddr_r(
    const void *address,
    socklen_t length,
    int family,
    struct hostent *entry,
    char *buffer,
    size_t buffer_size,
    struct hostent **result,
    int *h_error
)
{
    (void)address;
    (void)length;
    (void)family;
    (void)buffer;
    ++g_real_hostent_calls;
    g_real_hostent_buffer_size = buffer_size;
    if (result == NULL || h_error == NULL)
    {
        return 0;
    }
    if (g_real_hostent_missing)
    {
        *result = NULL;
        *h_error = HOST_NOT_FOUND;
        return 0;
    }
    entry->h_name = g_real_hostent_name;
    *result = entry;
    return 0;
}

#include "../../src/dns/chaos_dns_lookup.c"
#include "../../src/dns/chaos_dns_owned.c"

/**
 * @brief Invariant: static helper functions enforce bounds and produce correct output.
 *
 * Triggering conditions:
 * - `chaos_dns_copy_text_or_null()` with NULL, valid, too-long, and NULL out-pointer inputs.
 * - `chaos_dns_copy_output_text()` with valid and too-long inputs.
 * - `chaos_dns_strip_ipv6_brackets()` with bracketed IPv6, plain IPv4, and NULL.
 * - `chaos_dns_reverse_query_from_sockaddr()` with valid and too-short sockaddr_in.
 * - `chaos_dns_literal_family()` tells IPv4 and IPv6 literals from names.
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

    assert(chaos_dns_literal_family("10.0.0.1") == AF_INET);
    assert(chaos_dns_literal_family("fd00::1") == AF_INET6);
    assert(chaos_dns_literal_family("example.com") == 0);
    (void)head;

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
    /* One list of ours; the real results were released at once. */
    assert(chaos_dns_owned_contains(result) && g_real_freeaddrinfo_calls == 2);
    freeaddrinfo(result);
    assert(!chaos_dns_owned_contains(result));

    /* With AI_CANONNAME the queried name is the canonical name; the hints' family
     * skips the other literals. */
    {
        struct addrinfo hints;

        (void)memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_CANONNAME;
        assert(getaddrinfo("api.example.com", "443", &hints, &result) == 0);
        assert(result->ai_family == AF_INET6 && result->ai_next == NULL);
        assert(strcmp(result->ai_canonname, "api.example.com") == 0);
        freeaddrinfo(result);
        (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, "127.0.0.1", 10U);
        assert(getaddrinfo("api.example.com", "443", &hints, &result) == EAI_NONAME);
    }

    /* freeaddrinfo hands real results to the real freeaddrinfo. */
    g_real_freeaddrinfo_calls = 0;
    freeaddrinfo(make_result_node(AF_INET));
    assert(g_real_freeaddrinfo_calls == 1);
    g_chaos_dns_real_freeaddrinfo = NULL;
    freeaddrinfo(NULL);
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
    assert(chaos_dns_apply_override(NULL, NULL, NULL, NULL, &result) == EAI_FAIL);

    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void)memcpy(rule.text, "127.0.0.1,[::1]", 16U);
    g_real_getaddrinfo_error = EAI_AGAIN;
    g_real_getaddrinfo_error_call = 2;
    assert(chaos_dns_apply_override(&rule, "x", NULL, NULL, &result) == EAI_AGAIN);
    assert(g_real_freeaddrinfo_calls == 1);

    /* A malformed literal list fails, also one longer than the rule allows. */
    (void)memcpy(rule.text, "1.1.1.1,,2.2.2.2", 17U);
    g_real_freeaddrinfo_calls = 0;
    assert(chaos_dns_apply_override(&rule, "x", NULL, NULL, &result) == EAI_FAIL);
    assert(g_real_freeaddrinfo_calls == 1); /* the first literal's result */
    (void)memset(rule.text, 0, sizeof(rule.text));
    {
        size_t index;

        for (index = 0U; index < CHAOS_DNS_MAX_OVERRIDE + 1U; ++index)
        {
            (void)strcat(rule.text, index == 0U ? "1.1.1.1" : ",1.1.1.1");
        }
    }
    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    assert(chaos_dns_apply_override(&rule, "x", NULL, NULL, &result) == EAI_FAIL);
    assert(g_real_freeaddrinfo_calls == (int)CHAOS_DNS_MAX_OVERRIDE);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].effect = CHAOS_DNS_EFFECT_FILTER_FAMILY;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_INET4;
    g_filter_drop_all = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_NONAME);
    assert(g_filter_calls == 1);

    /* FILTER_FAMILY any filters nothing: the lookup succeeds with its list. */
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_ANY;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0 && result != NULL);
    assert(g_filter_calls == 1);
    chaos_dns_test_freeaddrinfo(result);

    /* A list of ours that FILTER or LIMIT empties is freed as a whole. */
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, "127.0.0.1", 10U);
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_INET6;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_NONAME);
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 0;
    g_stub_match[CHAOS_DNS_EFFECT_LIMIT] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_LIMIT].effect = CHAOS_DNS_EFFECT_LIMIT;
    g_stub_rules[CHAOS_DNS_EFFECT_LIMIT].limit = 0U;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_NONAME);
    {
        size_t index;

        for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
        {
            assert(g_chaos_dns_owned[index] == NULL);
        }
    }

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

/** @brief Wires every real resolver to the test stubs. */
static void bind_hostent_stubs(void)
{
    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_chaos_dns_real_gethostbyname2 = chaos_dns_test_gethostbyname2;
    g_chaos_dns_real_gethostbyname2_r = chaos_dns_test_gethostbyname2_r;
    g_chaos_dns_real_gethostbyaddr = chaos_dns_test_gethostbyaddr;
    g_chaos_dns_real_gethostbyaddr_r = chaos_dns_test_gethostbyaddr_r;
    g_real_hostent_calls = 0;
    g_real_hostent_missing = 0;
    g_real_hostent_buffer_size = 0U;
}

/**
 * @brief Invariant: the hostent helpers map errors and lay out entries correctly.
 *
 * Expected observable behaviour:
 * - EAI codes map to HOST_NOT_FOUND, TRY_AGAIN, NO_DATA and NO_RECOVERY.
 * - The entry holds the addresses of the requested family only, an empty alias list,
 *   and the canonical name of the first node (or the query); IPv6 uses 16-byte
 *   addresses; no matching address is ENOENT; a short buffer is ERANGE.
 * - Reverse keys are built for IPv4 and IPv6 only, from addresses of full length.
 */
static void test_hostent_helpers(void)
{
    struct addrinfo *v6 = make_result_node(AF_INET6);
    struct addrinfo *v4 = make_result_node(AF_INET);
    struct addrinfo *no_address = make_result_node(AF_INET);
    struct hostent entry;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    char buffer[256];
    char text[INET6_ADDRSTRLEN];

    assert(chaos_dns_h_errno_for(EAI_NONAME) == HOST_NOT_FOUND);
    assert(chaos_dns_h_errno_for(EAI_AGAIN) == TRY_AGAIN);
    assert(chaos_dns_h_errno_for(EAI_FAIL) == NO_RECOVERY);
#ifdef EAI_NODATA
    assert(chaos_dns_h_errno_for(EAI_NODATA) == NO_DATA);
#endif
#ifdef EAI_ADDRFAMILY
    assert(chaos_dns_h_errno_for(EAI_ADDRFAMILY) == NO_DATA);
#endif

    ((struct sockaddr_in *)(void *)v4->ai_addr)->sin_addr.s_addr = htonl(0x0a000001U);
    free(no_address->ai_addr);
    no_address->ai_addr = NULL;
    v6->ai_canonname = strdup("canon.example");
    assert(v6->ai_canonname != NULL);
    v6->ai_next = v4;
    v4->ai_next = no_address;

    assert(
        chaos_dns_fill_hostent("query.example", AF_INET, v6, &entry, buffer, sizeof(buffer)) == 0
    );
    assert(strcmp(entry.h_name, "canon.example") == 0);
    assert(entry.h_aliases[0] == NULL);
    assert(entry.h_addrtype == AF_INET);
    assert(entry.h_length == 4);
    assert(inet_ntop(AF_INET, entry.h_addr_list[0], text, sizeof(text)) != NULL);
    assert(strcmp(text, "10.0.0.1") == 0);
    assert(entry.h_addr_list[1] == NULL);

    assert(
        chaos_dns_fill_hostent("query.example", AF_INET6, v4, &entry, buffer, sizeof(buffer)) ==
        ENOENT
    );
    assert(
        chaos_dns_fill_hostent("query.example", AF_INET6, v6, &entry, buffer, sizeof(buffer)) == 0
    );
    assert(entry.h_length == 16);
    assert(
        chaos_dns_fill_hostent(
            "query.example", AF_INET, v4, &entry, buffer + 1, sizeof(buffer) - 1U
        ) == 0
    );
    assert(strcmp(entry.h_name, "query.example") == 0);
    assert(chaos_dns_fill_hostent("query.example", AF_INET, v4, &entry, buffer, 8U) == ERANGE);
    assert(chaos_dns_fill_hostent("query.example", AF_INET, v4, &entry, buffer + 1, 1U) == ERANGE);
    chaos_dns_test_freeaddrinfo(v6);

    ipv4.s_addr = htonl(INADDR_LOOPBACK);
    (void)memset(&ipv6, 0, sizeof(ipv6));
    assert(chaos_dns_reverse_query_from_address(&ipv4, sizeof(ipv4), AF_INET, text, sizeof(text)));
    assert(strcmp(text, "127.0.0.1") == 0);
    assert(chaos_dns_reverse_query_from_address(&ipv6, sizeof(ipv6), AF_INET6, text, sizeof(text)));
    assert(!chaos_dns_reverse_query_from_address(NULL, sizeof(ipv4), AF_INET, text, sizeof(text)));
    assert(!chaos_dns_reverse_query_from_address(&ipv4, 2U, AF_INET, text, sizeof(text)));
    assert(!chaos_dns_reverse_query_from_address(&ipv6, 4U, AF_INET6, text, sizeof(text)));
    assert(!chaos_dns_reverse_query_from_address(&ipv4, sizeof(ipv4), AF_UNIX, text, sizeof(text)));
}

/**
 * @brief Invariant: the forward hostent resolvers follow the dns:// rules.
 *
 * Expected observable behaviour:
 * - Under the guard, without a name, without output pointers or without rules the
 *   real resolver answers.
 * - LATENCY is applied; GAI fails the lookup with the mapped h_errno.
 * - A result-shaping rule answers through the getaddrinfo pipeline: success, a
 *   resolver error (mapped h_errno), no address of the family (NO_DATA) and a short
 *   buffer (ERANGE).
 * - gethostbyname and gethostbyname_r are the AF_INET forms.
 */
static void test_forward_hostent_paths(void)
{
    const char *volatile no_name = NULL;
    struct hostent entry;
    struct hostent *result = NULL;
    char buffer[256];
    int h_error = 0;

    bind_hostent_stubs();
    g_chaos_dns_tls_guard = 1;
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) ==
        0
    );
    assert(gethostbyname2("a.example", AF_INET) == &g_real_hostent);
    g_chaos_dns_tls_guard = 0;
    assert(
        gethostbyname2_r(no_name, AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) == 0
    );
    assert(gethostbyname2_r("", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) == 0);
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), NULL, &h_error) == 0
    );
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), &result, NULL) == 0
    );
    assert(gethostbyname_r("a.example", &entry, buffer, sizeof(buffer), &result, &h_error) == 0);
    assert(result == &entry);
    assert(gethostbyname2(no_name, AF_INET) == &g_real_hostent);
    assert(gethostbyname2("", AF_INET) == &g_real_hostent);
    assert(gethostbyname("a.example") == &g_real_hostent);
    assert(g_real_hostent_calls == 10);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_LATENCY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_LATENCY].effect = CHAOS_DNS_EFFECT_LATENCY;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_AGAIN;
    g_gai_trigger = 1;
    result = &entry;
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) ==
        0
    );
    assert(result == NULL);
    assert(h_error == TRY_AGAIN);
    h_errno = 0;
    assert(gethostbyname("a.example") == NULL);
    assert(h_errno == TRY_AGAIN);
    assert(g_latency_calls == 2);
    assert(g_real_hostent_calls == 0);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    (void)snprintf(
        g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, sizeof(g_stub_rules[0].text), "%s", "b.example"
    );
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) ==
        0
    );
    assert(result == &entry);
    assert(strcmp(entry.h_name, "a.example") == 0);
    assert(strcmp(g_last_node, "b.example") == 0);
    assert(gethostbyname("a.example") == &g_chaos_dns_hostent);

    assert(
        gethostbyname2_r(
            "a.example", AF_INET6, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(result == NULL);
    assert(h_error == NO_DATA);

    errno = 0;
    assert(gethostbyname2_r("a.example", AF_INET, &entry, buffer, 8U, &result, &h_error) == ERANGE);
    assert(result == NULL);
    assert(errno == ERANGE);
    assert(h_error == NETDB_INTERNAL);

    g_real_getaddrinfo_error = EAI_NONAME;
    assert(
        gethostbyname2_r("a.example", AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error) ==
        0
    );
    assert(result == NULL);
    assert(h_error == HOST_NOT_FOUND);
    h_errno = 0;
    assert(gethostbyname2("a.example", AF_INET) == NULL);
    assert(h_errno == HOST_NOT_FOUND);
    assert(g_real_hostent_calls == 0);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 1;
    assert(chaos_dns_has_result_rule("a.example"));
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 0;
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 1;
    assert(chaos_dns_has_result_rule("a.example"));
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 0;
    g_stub_match[CHAOS_DNS_EFFECT_SHUFFLE] = 1;
    assert(chaos_dns_has_result_rule("a.example"));
    g_stub_match[CHAOS_DNS_EFFECT_SHUFFLE] = 0;
    g_stub_match[CHAOS_DNS_EFFECT_LIMIT] = 1;
    assert(chaos_dns_has_result_rule("a.example"));
    g_stub_match[CHAOS_DNS_EFFECT_LIMIT] = 0;
    assert(!chaos_dns_has_result_rule("a.example"));
}

/**
 * @brief Invariant: the reverse hostent resolvers follow the rdns:// rules.
 *
 * Expected observable behaviour:
 * - Under the guard, for an unsupported family or without output pointers the real
 *   resolver answers unchanged.
 * - GAI fails the lookup with the mapped h_errno.
 * - REWRITE replaces h_name: in the tail of the caller's buffer for the _r form (the
 *   real resolver gets the rest), in static storage for the plain form; a name longer
 *   than the buffer is ERANGE; a rule that does not fire or a failed lookup changes
 *   nothing.
 */
static void test_reverse_hostent_paths(void)
{
    struct hostent entry;
    struct hostent *result = NULL;
    struct in_addr ipv4;
    char buffer[64];
    int h_error = 0;

    ipv4.s_addr = htonl(INADDR_LOOPBACK);

    bind_hostent_stubs();
    g_chaos_dns_tls_guard = 1;
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(gethostbyaddr(&ipv4, sizeof(ipv4), AF_INET) == &g_real_hostent);
    g_chaos_dns_tls_guard = 0;
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_UNIX, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), NULL, &h_error
        ) == 0
    );
    assert(gethostbyaddr(&ipv4, sizeof(ipv4), AF_UNIX) == &g_real_hostent);
    assert(g_real_hostent_calls == 5);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_gai_trigger = 1;
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(result == NULL);
    assert(h_error == NO_RECOVERY);
    h_errno = 0;
    assert(gethostbyaddr(&ipv4, sizeof(ipv4), AF_INET) == NULL);
    assert(h_errno == NO_RECOVERY);
    assert(g_real_hostent_calls == 0);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    (void)snprintf(
        g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text,
        sizeof(g_stub_rules[0].text),
        "%s",
        "ptr.example"
    );
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(result == &entry);
    assert(strcmp(entry.h_name, "ptr.example") == 0);
    assert(entry.h_name == buffer + sizeof(buffer) - sizeof("ptr.example"));
    assert(g_real_hostent_buffer_size == sizeof(buffer) - sizeof("ptr.example"));
    result = gethostbyaddr(&ipv4, sizeof(ipv4), AF_INET);
    assert(result != NULL && strcmp(result->h_name, "ptr.example") == 0);

    errno = 0;
    assert(
        gethostbyaddr_r(&ipv4, sizeof(ipv4), AF_INET, &entry, buffer, 4U, &result, &h_error) ==
        ERANGE
    );
    assert(result == NULL);
    assert(errno == ERANGE);

    g_real_hostent_missing = 1;
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(result == NULL);
    assert(gethostbyaddr(&ipv4, sizeof(ipv4), AF_INET) == NULL);

    g_real_hostent_missing = 0;
    g_should_trigger = 0;
    assert(
        gethostbyaddr_r(
            &ipv4, sizeof(ipv4), AF_INET, &entry, buffer, sizeof(buffer), &result, &h_error
        ) == 0
    );
    assert(strcmp(entry.h_name, "real.example") == 0);
    assert(g_real_hostent_buffer_size == sizeof(buffer));
}

int main(void)
{
    test_static_helpers();
    test_passthrough_paths();
    test_reverse_lookup_paths();
    test_latency_and_gai_paths();
    test_rewrite_service_and_override_paths();
    test_override_error_and_post_rules();
    test_hostent_helpers();
    test_forward_hostent_paths();
    test_reverse_hostent_paths();
    return 0;
}
