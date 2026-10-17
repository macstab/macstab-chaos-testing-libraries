/**
 * @file test_chaos_dns.c
 * @brief Unit tests for the libchaos-dns wrappers: getaddrinfo, getnameinfo, freeaddrinfo and
 *   the gethostbyname / gethostbyaddr families.
 *
 * @details
 * Unit under test: `src/dns/chaos_dns_lookup.c` (with `chaos_dns_owned.c`). The suite proves
 * the wrapper pipeline, not rule parsing or the effects themselves:
 * - bypass: re-entrant calls (TLS guard), a NULL or empty name, a NULL address, an address
 *   too short or of a family with no reverse key, and a NULL result pointer all go straight
 *   to the real function;
 * - order: LATENCY, then GAI (which skips the real resolver; EAI_SYSTEM sets errno EIO), then
 *   REWRITE/SERVICE on the arguments, OVERRIDE or the real call, then FILTER_FAMILY, SHUFFLE
 *   and LIMIT on the result; reverse lookups apply REWRITE/SERVICE to the outputs after a
 *   successful real call, with EAI_OVERFLOW when the caller's buffer is too small;
 * - OVERRIDE resolves each IP literal with the real getaddrinfo, copies all nodes into one
 *   list of ours and releases the real results at once; the interposed freeaddrinfo frees
 *   ours itself and hands every other list to the real function;
 * - the hostent resolvers follow the same `dns://` / `rdns://` rules, map EAI codes to
 *   h_errno, build entries from the getaddrinfo pipeline when a result-shaping rule matches,
 *   and report ERANGE for a short caller buffer;
 * - a rule that matches but does not fire changes nothing;
 * - before the real functions are resolved every wrapper fails cleanly (EAI_SYSTEM or
 *   NETDB_INTERNAL with errno ENOSYS) instead of calling through NULL.
 *
 * Seams:
 * - The config and action entry points the wrapper calls are defined here as stubs, driven
 *   per effect by `g_stub_match[]` / `g_stub_rules[]` (indexed by `chaos_dns_effect_t`),
 *   `g_should_trigger` (default 1) and `g_gai_trigger`. The transform stubs only count calls,
 *   except FILTER_FAMILY drop-all and LIMIT 0/1, which reshape the list like the real ones,
 *   including "unlink only" for lists of ours.
 * - `CHAOS_DNS_DEFINE_TEST_GLOBALS()` provides the real-function pointers; each scenario wires
 *   the ones it needs to local fakes. The fake getaddrinfo records its arguments and returns
 *   one AF_INET6 node for a name containing ':' and one AF_INET node otherwise, failing with
 *   `g_real_getaddrinfo_error` on every call or on call N; the fake getnameinfo records the
 *   reverse key and answers "localhost"/"http"; the fake freeaddrinfo frees and counts nodes.
 * - `reset_wrapper_state()` starts every scenario from no rules, no real functions and zero
 *   counters, so scenarios do not leak state into each other.
 *
 * Out of scope: symbol resolution (`test_dns_runtime.c`), rule parsing and matching
 * (`test_dns_config.c`) and the effect implementations (`test_dns_actions.c`).
 */

#include "../support/test_dns_support.h"

#include <stdio.h>

#include "../../src/dns/chaos_dns_config.h"
#include "../../src/dns/chaos_dns_owned.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

/** @brief Rule each config-match stub returns, indexed by `chaos_dns_effect_t`. */
static chaos_dns_rule_t g_stub_rules[8];
/** @brief Non-zero makes the forward and reverse match stubs report a match for that effect. */
static int g_stub_match[8];
/** @brief Calls of the LATENCY stub (no sleep is performed). */
static int g_latency_calls = 0;
/** @brief Non-zero makes a matched GAI rule fire and report its `gai_error`. */
static int g_gai_trigger = 0;
/** @brief Result of the should-trigger stub; 1 by default, 0 for "matched but not fired". */
static int g_should_trigger = 1;
/** @brief Calls of the FILTER_FAMILY stub. */
static int g_filter_calls = 0;
/** @brief Non-zero makes the FILTER_FAMILY stub drop every node, as for a family-less answer. */
static int g_filter_drop_all = 0;
/** @brief Calls of the SHUFFLE stub. */
static int g_shuffle_calls = 0;
/** @brief Calls of the LIMIT stub. */
static int g_limit_calls = 0;
/** @brief Calls of the fake real getaddrinfo. */
static int g_real_getaddrinfo_calls = 0;
/** @brief Non-zero: the fake real getaddrinfo fails with this EAI code (see next). */
static int g_real_getaddrinfo_error = 0;
/** @brief 1-based call on which `g_real_getaddrinfo_error` applies; 0 means every call. */
static int g_real_getaddrinfo_error_call = 0;
/** @brief Calls of the fake real getnameinfo. */
static int g_real_getnameinfo_calls = 0;
/** @brief Non-zero: the fake real getnameinfo fails with this EAI code. */
static int g_real_getnameinfo_error = 0;
/** @brief Nodes released by the fake real freeaddrinfo (nodes, not calls). */
static int g_real_freeaddrinfo_calls = 0;
/** @brief Name the fake real getaddrinfo last received; proves REWRITE reached it. */
static char g_last_node[CHAOS_DNS_MAX_VALUE];
/** @brief Service the fake real getaddrinfo last received; proves SERVICE reached it. */
static char g_last_service[CHAOS_DNS_MAX_VALUE];
/** @brief Numeric address the fake real getnameinfo last received. */
static char g_last_reverse_query[CHAOS_DNS_MAX_TEXT];

/** @brief Clears every rule, flag, counter and real-function pointer; call per scenario. */
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

/** @brief Forward-match stub: the table entry for @p effect when enabled; the name is ignored. */
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

/** @brief Reverse-match stub: same table as the forward stub; the address is ignored. */
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

/** @brief LATENCY stub: counts calls without sleeping. */
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/** @brief Should-trigger stub: returns `g_should_trigger` for every rule. */
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

/** @brief GAI stub: fires a GAI rule while `g_gai_trigger` is set, mirroring the real checks. */
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
 * @brief FILTER_FAMILY stub: counts calls; under `g_filter_drop_all` empties the list (freeing
 *   real nodes, only unlinking ours, like the real filter) and returns 0.
 */
int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family)
{
    (void)family;
    ++g_filter_calls;
    if (g_filter_drop_all != 0 && result != NULL && *result != NULL)
    {
        if (!chaos_dns_owned_contains(*result))
        {
            g_chaos_dns_real_freeaddrinfo(*result);
        }
        *result = NULL;
        return 0;
    }
    return 1;
}

/** @brief SHUFFLE stub: counts calls and leaves the order alone, so results stay predictable. */
void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    (void)result;
    ++g_shuffle_calls;
}

/**
 * @brief LIMIT stub: counts calls; limit 0 empties the list (only unlinking ours, like the real
 *   LIMIT) and limit 1 frees everything after the head.
 */
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit)
{
    ++g_limit_calls;
    if (result != NULL && *result != NULL && limit == 0U)
    {
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
 * @brief Heap-allocates one unlinked addrinfo node with a zeroed address.
 *
 * @param family  `AF_INET` gets a `sockaddr_in`; any other value an AF_INET6 `sockaddr_in6`.
 * @return The node; asserts on allocation failure. Release with chaos_dns_test_freeaddrinfo().
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
 * @brief Fake real getaddrinfo: records name and service, applies the configured failure, and
 *   otherwise returns one AF_INET6 node for a name containing ':' and one AF_INET node else.
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
 * @brief Fake real getnameinfo: records the numeric address (empty for an unusable one), then
 *   fails with `g_real_getnameinfo_error` or answers "localhost" / "http".
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

/** @brief Fake real freeaddrinfo: frees and counts every node of the list. */
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

/** @brief Calls of the four fake real hostent resolvers together. */
static int g_real_hostent_calls = 0;
/** @brief Non-zero makes the fake hostent resolvers report HOST_NOT_FOUND. */
static int g_real_hostent_missing = 0;
/** @brief Buffer size the fake gethostbyaddr_r last received; shows what REWRITE reserved. */
static size_t g_real_hostent_buffer_size = 0U;
/** @brief Non-zero makes the fake gethostbyaddr_r fail with this return value. */
static int g_real_hostent_rc = 0;
/** @brief Static entry the fake non-reentrant resolvers return. */
static struct hostent g_real_hostent;
/** @brief h_name of every entry the fakes return. */
static char g_real_hostent_name[] = "real.example";

/** @brief Fake real gethostbyname2. */
static struct hostent *chaos_dns_test_gethostbyname2(const char *name, int family)
{
    (void)name;
    (void)family;
    ++g_real_hostent_calls;
    g_real_hostent.h_name = g_real_hostent_name;
    return g_real_hostent_missing ? NULL : &g_real_hostent;
}

/** @brief Fake real gethostbyname2_r. */
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

/** @brief Fake real gethostbyaddr. */
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

/** @brief Fake real gethostbyaddr_r: records the buffer size and names the entry "real.example". */
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
    if (g_real_hostent_rc != 0)
    {
        *result = NULL;
        *h_error = NETDB_INTERNAL;
        return g_real_hostent_rc;
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
 * @brief Proves the bounded copy, bracket-strip, reverse-key and literal-family helpers, and
 *   the dispatch to the real functions.
 *
 * @details Every helper that writes a caller buffer fails rather than truncates: a too-long
 * text, a NULL source or target, or a zero size. `[::1]` loses its brackets and an IPv4
 * literal passes unchanged; an address too long for 16 bytes fails with or without brackets.
 * A reverse key comes only from a full-length `sockaddr_in` or `sockaddr_in6`; a short length,
 * a NULL address or AF_UNIX yields none, so the wrapper bypasses the rules.
 */
static void test_static_helpers(void)
{
    char buffer[16];
    char host[16];
    char service[16];
    struct addrinfo *head = NULL;
    struct sockaddr_in ipv4;

    reset_wrapper_state();
    assert(chaos_dns_copy_output_text("hello", buffer, sizeof(buffer)) == 0);
    assert(strcmp(buffer, "hello") == 0);
    assert(chaos_dns_copy_output_text("toolong", buffer, 4U) != 0);
    assert(chaos_dns_copy_output_text(NULL, buffer, sizeof(buffer)) != 0);
    assert(chaos_dns_copy_output_text("a", NULL, sizeof(buffer)) != 0);
    assert(chaos_dns_copy_output_text("a", buffer, 0U) != 0);

    assert(chaos_dns_strip_ipv6_brackets("[::1]", host, sizeof(host)) == 0);
    assert(strcmp(host, "::1") == 0);
    assert(chaos_dns_strip_ipv6_brackets("127.0.0.1", host, sizeof(host)) == 0);
    assert(strcmp(host, "127.0.0.1") == 0);
    assert(chaos_dns_strip_ipv6_brackets(NULL, host, sizeof(host)) != 0);
    assert(chaos_dns_strip_ipv6_brackets("", host, sizeof(host)) != 0);
    assert(chaos_dns_strip_ipv6_brackets("[1111:2222:3333:4444::1]", host, sizeof(host)) != 0);
    assert(chaos_dns_strip_ipv6_brackets("1111:2222:3333:4444::1", host, sizeof(host)) != 0);

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
    assert(!chaos_dns_reverse_query_from_sockaddr(NULL, (socklen_t)sizeof(ipv4), host, sizeof(host))
    );
    {
        struct sockaddr_in6 ipv6;
        char text[INET6_ADDRSTRLEN];
        struct sockaddr unix_address;

        (void)memset(&ipv6, 0, sizeof(ipv6));
        ipv6.sin6_family = AF_INET6;
        assert(inet_pton(AF_INET6, "fd00::1", &ipv6.sin6_addr) == 1);
        assert(chaos_dns_reverse_query_from_sockaddr(
            (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), text, sizeof(text)
        ));
        assert(strcmp(text, "fd00::1") == 0);
        assert(!chaos_dns_reverse_query_from_sockaddr(
            (const struct sockaddr *)&ipv6,
            (socklen_t)sizeof(struct sockaddr_in),
            text,
            sizeof(text)
        ));
        (void)memset(&unix_address, 0, sizeof(unix_address));
        unix_address.sa_family = AF_UNIX;
        assert(!chaos_dns_reverse_query_from_sockaddr(
            &unix_address, (socklen_t)sizeof(unix_address), text, sizeof(text)
        ));
    }

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
 * @brief Proves getaddrinfo goes straight to the real function for a NULL or empty name,
 *   under the TLS guard, and with a NULL result pointer.
 *
 * @details No rule is enabled, so a single real call per invocation is the only observable
 * effect; the guard case proves the library's own lookups are never subject to its rules.
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
 * @brief Proves the getnameinfo pipeline: bypass, LATENCY, GAI, output REWRITE/SERVICE and
 *   EAI_OVERFLOW.
 *
 * @details
 * - Under the TLS guard, and with an address too short to yield a reverse key, the real
 *   function answers.
 * - LATENCY delays and the real call still runs; GAI returns its code without a real call.
 * - REWRITE and SERVICE replace the host and service the real call wrote; the reverse key
 *   passed on is the numeric address.
 * - A failed real lookup is returned unchanged and the caller's buffer is not written.
 * - A replacement longer than the caller's host (12 bytes) or service (8 bytes) buffer
 *   returns EAI_OVERFLOW, as the real getnameinfo does.
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
    {
        char untouched[16] = "untouched";

        reset_wrapper_state();
        g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
        g_real_getnameinfo_error = EAI_NONAME;
        g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
        g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
        (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, "ptr.example", 12U);
        assert(
            getnameinfo(
                (const struct sockaddr *)&ipv4,
                (socklen_t)sizeof(ipv4),
                untouched,
                (socklen_t)sizeof(untouched),
                service,
                (socklen_t)sizeof(service),
                0
            ) == EAI_NONAME
        );
        assert(strcmp(untouched, "untouched") == 0);
    }

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_SERVICE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].effect = CHAOS_DNS_EFFECT_SERVICE;
    (void)memcpy(g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].text, "service-name-too-long", 22U);
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            service,
            8U,
            0
        ) == EAI_OVERFLOW
    );

    reset_wrapper_state();
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
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
 * @brief Proves getaddrinfo applies LATENCY before the lookup and GAI instead of it.
 *
 * @details GAI returns EAI_FAIL or EAI_AGAIN with no real call, also for a NULL result
 * pointer. GAI with EAI_SYSTEM sets errno to EIO: EAI_SYSTEM tells the caller to read errno,
 * which must then hold a system error, not a stale value.
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

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_SYSTEM;
    g_gai_trigger = 1;
    errno = 0;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_SYSTEM);
    assert(errno == EIO);
    assert(g_real_getaddrinfo_calls == 0);
}

/**
 * @brief Proves REWRITE/SERVICE substitute the real call's arguments, and OVERRIDE returns one
 *   list of ours that freeaddrinfo releases.
 *
 * @details
 * - REWRITE and SERVICE: the real getaddrinfo receives "alt.example.com" and "8443".
 * - OVERRIDE "127.0.0.1,[::1]": one real call per literal, a two-node list in one allocation
 *   of ours, both real results already freed; freeaddrinfo() deregisters it.
 * - With AI_CANONNAME the queried name becomes `ai_canonname`; an AF_INET6 hint skips the v4
 *   literal, and a rule with only v4 literals then yields EAI_NONAME.
 * - freeaddrinfo() hands a real list to the real function and tolerates NULL with no real
 *   function resolved.
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
    assert(chaos_dns_owned_contains(result) && g_real_freeaddrinfo_calls == 2);
    freeaddrinfo(result);
    assert(!chaos_dns_owned_contains(result));

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

    g_real_freeaddrinfo_calls = 0;
    freeaddrinfo(make_result_node(AF_INET));
    assert(g_real_freeaddrinfo_calls == 1);
    g_chaos_dns_real_freeaddrinfo = NULL;
    freeaddrinfo(NULL);
}

/**
 * @brief Proves OVERRIDE failure handling and the result-list transforms after the lookup.
 *
 * @details
 * - A NULL rule is EAI_FAIL. A failure resolving the second literal returns that error and
 *   frees the first literal's result. A malformed list (empty element) is EAI_FAIL after
 *   freeing what was resolved; so is a list of more than `CHAOS_DNS_MAX_OVERRIDE` (32)
 *   literals, after freeing all 32.
 * - FILTER_FAMILY that drops every node returns EAI_NONAME; FILTER_FAMILY ANY is not applied.
 * - An OVERRIDE list emptied by FILTER_FAMILY or LIMIT 0 returns EAI_NONAME and its block is
 *   freed: the registry of our lists is empty afterwards, so nothing leaks.
 * - SHUFFLE and LIMIT each run once on a successful lookup.
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

    (void)memcpy(rule.text, "1.1.1.1,,2.2.2.2", 17U);
    g_real_freeaddrinfo_calls = 0;
    assert(chaos_dns_apply_override(&rule, "x", NULL, NULL, &result) == EAI_FAIL);
    assert(g_real_freeaddrinfo_calls == 1); /* first literal's result */
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

    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_ANY;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0 && result != NULL);
    assert(g_filter_calls == 1);
    chaos_dns_test_freeaddrinfo(result);

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

/** @brief Resets all state and wires every real resolver, hostent ones included, to the fakes. */
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
    g_real_hostent_rc = 0;
}

/**
 * @brief Proves the hostent helpers: EAI to h_errno mapping, entry layout, and reverse keys.
 *
 * @details EAI_NONAME, EAI_AGAIN and EAI_FAIL map to HOST_NOT_FOUND, TRY_AGAIN and NO_RECOVERY;
 * EAI_NODATA and EAI_ADDRFAMILY (where the libc defines them) to NO_DATA. An entry holds only
 * addresses of the requested family (4 or 16 bytes), skips nodes without an address, has an
 * empty alias list, and is named after the first node's canonical name or else the query. No
 * address of the family is ENOENT; a buffer too small, also after alignment from an odd start
 * address, is ERANGE. Reverse keys come only from full-length AF_INET and AF_INET6 addresses.
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
 * @brief Proves gethostbyname, gethostbyname2 and their _r forms follow the `dns://` rules.
 *
 * @details
 * - Under the guard, with a NULL or empty name, with a NULL result or h_error pointer, or with
 *   no rule, the real resolver answers (10 real calls).
 * - LATENCY applies and GAI fails the lookup with the mapped h_errno (EAI_AGAIN gives
 *   TRY_AGAIN) without a real call.
 * - A result-shaping rule (here REWRITE) answers through the getaddrinfo pipeline: the entry
 *   keeps the queried name, the plain form returns the library's static entry, an AF_INET6
 *   query with only v4 results is NO_DATA, an 8-byte buffer is ERANGE with errno ERANGE and
 *   NETDB_INTERNAL, and a resolver error maps to HOST_NOT_FOUND.
 * - OVERRIDE, FILTER_FAMILY, SHUFFLE and LIMIT each count as result-shaping.
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
 * @brief Proves gethostbyaddr and gethostbyaddr_r follow the `rdns://` rules.
 *
 * @details
 * - Under the guard, for a family with no reverse key, or with a NULL result pointer, the
 *   real resolver answers unchanged.
 * - GAI fails the lookup with the mapped h_errno (EAI_FAIL gives NO_RECOVERY).
 * - REWRITE stores the new h_name in the tail of the caller's buffer for the _r form and hands
 *   the real resolver only the rest, so the two never overlap; the plain form uses static
 *   storage. A 4-byte buffer is ERANGE. A failed real lookup, or a REWRITE that does not fire,
 *   leaves the real answer and the full buffer.
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

/**
 * @brief Proves matched-but-not-fired rules change nothing, and covers the remaining
 *   getnameinfo, OVERRIDE and hostent edge paths.
 *
 * @details
 * - Every effect matched, none firing: getaddrinfo passes the original name and service,
 *   runs no transform and no delay; getnameinfo returns the real host and service.
 * - getnameinfo with a NULL address or a 1-byte address calls the real function directly.
 *   Asked only for the service, or only for the host (the other length 0), only the rule
 *   for the requested output is applied.
 * - FILTER_FAMILY that keeps nodes lets the lookup continue.
 * - OVERRIDE whose first literal fails returns that error without trying the second.
 * - OVERRIDE with all `CHAOS_DNS_MAX_OWNED` (256) registry slots taken returns EAI_MEMORY
 *   after freeing both literals' results.
 * - gethostbyname2_r through OVERRIDE releases our list itself; only the literal's real
 *   result reaches the real freeaddrinfo, and the registry ends empty.
 * - The hostent prelude with LATENCY and GAI not firing calls the real resolver.
 * - gethostbyaddr_r without an h_error pointer skips the rules; a real failure (ERANGE) is
 *   returned as is and REWRITE does not touch h_name.
 */
static void test_rules_that_do_not_fire(void)
{
    struct addrinfo *result = NULL;
    struct addrinfo *copies[CHAOS_DNS_MAX_OWNED];
    struct addrinfo *lists[1];
    struct sockaddr_in ipv4;
    struct in_addr address;
    struct hostent entry;
    struct hostent *entry_result = NULL;
    char buffer[256];
    char host[64];
    char service[64];
    int h_error = 0;
    int effect;
    size_t index;

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_chaos_dns_real_getnameinfo = chaos_dns_test_getnameinfo;
    for (effect = 0; effect < (int)(sizeof(g_stub_match) / sizeof(g_stub_match[0])); ++effect)
    {
        g_stub_match[effect] = 1;
        g_stub_rules[effect].effect = (chaos_dns_effect_t)effect;
    }
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_INET6;
    (void)snprintf(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, sizeof(host), "alt.example");
    (void)snprintf(g_stub_rules[CHAOS_DNS_EFFECT_SERVICE].text, sizeof(host), "8443");
    (void)snprintf(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, sizeof(host), "192.0.2.1");
    g_should_trigger = 0;
    assert(getaddrinfo("api.example.com", "443", NULL, &result) == 0);
    assert(result != NULL && result->ai_family == AF_INET);
    assert(strcmp(g_last_node, "api.example.com") == 0);
    assert(strcmp(g_last_service, "443") == 0);
    assert(g_real_getaddrinfo_calls == 1);
    assert(g_latency_calls == 0);
    assert(g_filter_calls == 0 && g_shuffle_calls == 0 && g_limit_calls == 0);
    chaos_dns_test_freeaddrinfo(result);

    (void)memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr) == 1);
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
    assert(strcmp(host, "localhost") == 0 && strcmp(service, "http") == 0);
    assert(g_latency_calls == 0);

    g_real_getnameinfo_calls = 0;
    g_should_trigger = 1;
    g_gai_trigger = 1;
    assert(getnameinfo(NULL, 0U, host, (socklen_t)sizeof(host), NULL, 0U, 0) == 0);
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4, 1U, host, (socklen_t)sizeof(host), NULL, 0U, 0
        ) == 0
    );
    assert(strcmp(host, "localhost") == 0);
    assert(g_real_getnameinfo_calls == 2);
    assert(g_latency_calls == 0);

    g_gai_trigger = 0;
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            NULL,
            0U,
            service,
            (socklen_t)sizeof(service),
            0
        ) == 0
    );
    assert(strcmp(service, "8443") == 0);
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), host, 0U, service, 0U, 0
        ) == 0
    );
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4,
            (socklen_t)sizeof(ipv4),
            host,
            (socklen_t)sizeof(host),
            NULL,
            0U,
            0
        ) == 0
    );
    assert(strcmp(host, "alt.example") == 0);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_FILTER_FAMILY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].effect = CHAOS_DNS_EFFECT_FILTER_FAMILY;
    g_stub_rules[CHAOS_DNS_EFFECT_FILTER_FAMILY].family = CHAOS_DNS_FAMILY_INET4;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == 0 && result != NULL);
    assert(g_filter_calls == 1);
    chaos_dns_test_freeaddrinfo(result);

    reset_wrapper_state();
    g_chaos_dns_real_getaddrinfo = chaos_dns_test_getaddrinfo;
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void
    )snprintf(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, sizeof(host), "192.0.2.1,192.0.2.2");
    g_real_getaddrinfo_error = EAI_AGAIN;
    g_real_getaddrinfo_error_call = 1;
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_AGAIN);
    assert(g_real_getaddrinfo_calls == 1);
    assert(g_real_freeaddrinfo_calls == 0);

    g_real_getaddrinfo_error = 0;
    g_real_getaddrinfo_calls = 0;
    lists[0] = make_result_node(AF_INET);
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        copies[index] = chaos_dns_owned_copy(lists, 1U, NULL);
        assert(copies[index] != NULL);
    }
    assert(getaddrinfo("api.example.com", NULL, NULL, &result) == EAI_MEMORY);
    assert(g_real_getaddrinfo_calls == 2);
    assert(g_real_freeaddrinfo_calls == 2);
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        assert(chaos_dns_owned_free(copies[index]) == 1);
    }
    chaos_dns_test_freeaddrinfo(lists[0]);

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_OVERRIDE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].effect = CHAOS_DNS_EFFECT_OVERRIDE;
    (void)snprintf(g_stub_rules[CHAOS_DNS_EFFECT_OVERRIDE].text, sizeof(host), "192.0.2.1");
    assert(
        gethostbyname2_r(
            "a.example", AF_INET, &entry, buffer, sizeof(buffer), &entry_result, &h_error
        ) == 0
    );
    assert(entry_result == &entry && entry.h_addrtype == AF_INET);
    assert(g_real_freeaddrinfo_calls == 1); /* literal's real result only */
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        assert(g_chaos_dns_owned[index] == NULL);
    }

    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_LATENCY] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_LATENCY].effect = CHAOS_DNS_EFFECT_LATENCY;
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_should_trigger = 0;
    assert(gethostbyname2("a.example", AF_INET) == &g_real_hostent);
    assert(g_latency_calls == 0);
    assert(g_real_hostent_calls == 1);

    address.s_addr = htonl(INADDR_LOOPBACK);
    bind_hostent_stubs();
    g_stub_match[CHAOS_DNS_EFFECT_GAI] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].effect = CHAOS_DNS_EFFECT_GAI;
    g_stub_rules[CHAOS_DNS_EFFECT_GAI].gai_error = EAI_FAIL;
    g_gai_trigger = 1;
    assert(
        gethostbyaddr_r(
            &address, sizeof(address), AF_INET, &entry, buffer, sizeof(buffer), &entry_result, NULL
        ) == 0
    );
    assert(g_real_hostent_calls == 1);

    bind_hostent_stubs();
    assert(
        gethostbyaddr_r(
            &address,
            sizeof(address),
            AF_INET,
            &entry,
            buffer,
            sizeof(buffer),
            &entry_result,
            &h_error
        ) == 0
    );
    assert(entry_result == &entry && strcmp(entry.h_name, "real.example") == 0);
    assert(g_real_hostent_buffer_size == sizeof(buffer));

    g_stub_match[CHAOS_DNS_EFFECT_REWRITE] = 1;
    g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].effect = CHAOS_DNS_EFFECT_REWRITE;
    (void)snprintf(g_stub_rules[CHAOS_DNS_EFFECT_REWRITE].text, sizeof(host), "ptr.example");
    g_real_hostent_rc = ERANGE;
    entry.h_name = NULL;
    assert(
        gethostbyaddr_r(
            &address,
            sizeof(address),
            AF_INET,
            &entry,
            buffer,
            sizeof(buffer),
            &entry_result,
            &h_error
        ) == ERANGE
    );
    assert(entry_result == NULL && h_error == NETDB_INTERNAL);
    assert(entry.h_name == NULL);
}

/**
 * @brief Proves every wrapper fails cleanly while its real function is unresolved (NULL), as
 *   during symbol resolution itself; there is no syscall to fall back to.
 *
 * @details getaddrinfo and getnameinfo return EAI_SYSTEM with errno ENOSYS. The _r hostent
 * forms return ENOSYS with `*result` NULL and h_error NETDB_INTERNAL; the plain forms return
 * NULL with h_errno NETDB_INTERNAL and errno ENOSYS. freeaddrinfo leaks the list rather than
 * free it with an unknown allocator.
 */
static void test_unresolved_fallbacks(void)
{
    struct addrinfo *result = NULL;
    struct addrinfo *node;
    struct sockaddr_in ipv4;
    struct in_addr address;
    struct hostent entry;
    struct hostent *entry_result = &entry;
    char buffer[256];
    char host[64];
    int h_error = 0;

    reset_wrapper_state();

    errno = 0;
    assert(getaddrinfo("api.example.com", "80", NULL, &result) == EAI_SYSTEM);
    assert(errno == ENOSYS);
    assert(result == NULL);

    (void)memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "127.0.0.1", &ipv4.sin_addr) == 1);
    errno = 0;
    assert(
        getnameinfo(
            (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), host, sizeof(host), NULL, 0, 0
        ) == EAI_SYSTEM
    );
    assert(errno == ENOSYS);

    node = make_result_node(AF_INET);
    freeaddrinfo(node);
    assert(g_real_freeaddrinfo_calls == 0);
    chaos_dns_test_freeaddrinfo(node);

    errno = 0;
    assert(
        gethostbyname2_r(
            "api.example.com", AF_INET, &entry, buffer, sizeof(buffer), &entry_result, &h_error
        ) == ENOSYS
    );
    assert(entry_result == NULL);
    assert(h_error == NETDB_INTERNAL);
    assert(errno == ENOSYS);

    errno = 0;
    h_errno = 0;
    assert(gethostbyname2("api.example.com", AF_INET) == NULL);
    assert(h_errno == NETDB_INTERNAL);
    assert(errno == ENOSYS);

    address = ipv4.sin_addr;
    entry_result = &entry;
    h_error = 0;
    errno = 0;
    assert(
        gethostbyaddr_r(
            &address,
            (socklen_t)sizeof(address),
            AF_INET,
            &entry,
            buffer,
            sizeof(buffer),
            &entry_result,
            &h_error
        ) == ENOSYS
    );
    assert(entry_result == NULL);
    assert(h_error == NETDB_INTERNAL);
    assert(errno == ENOSYS);

    errno = 0;
    h_errno = 0;
    assert(gethostbyaddr(&address, (socklen_t)sizeof(address), AF_INET) == NULL);
    assert(h_errno == NETDB_INTERNAL);
    assert(errno == ENOSYS);
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
    test_rules_that_do_not_fire();
    test_unresolved_fallbacks();
    return 0;
}
