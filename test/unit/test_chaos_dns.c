#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

static chaos_dns_rule_t g_stub_rules[8];
static int g_stub_match[8];
static int g_latency_calls = 0;
static int g_gai_trigger = 0;
static int g_should_trigger = 1;
static int g_filter_calls = 0;
static int g_filter_drop_all = 0;
static int g_shuffle_calls = 0;
static int g_limit_calls = 0;
static int g_real_getaddrinfo_calls = 0;
static int g_real_getaddrinfo_error = 0;
static int g_real_getaddrinfo_error_call = 0;
static int g_real_getnameinfo_calls = 0;
static int g_real_getnameinfo_error = 0;
static int g_real_freeaddrinfo_calls = 0;
static char g_last_node[CHAOS_DNS_MAX_VALUE];
static char g_last_service[CHAOS_DNS_MAX_VALUE];
static char g_last_reverse_query[CHAOS_DNS_MAX_TEXT];

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

void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

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

void chaos_dns_shuffle_result_list(struct addrinfo **result)
{
    (void)result;
    ++g_shuffle_calls;
}

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
