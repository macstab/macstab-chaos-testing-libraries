#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

CHAOS_DNS_DEFINE_TEST_GLOBALS();

static int g_force_calloc_fail = 0;
static int g_freeaddrinfo_calls = 0;

static void *chaos_dns_test_calloc(size_t count, size_t size)
{
    if (g_force_calloc_fail != 0)
    {
        return NULL;
    }
    return calloc(count, size);
}

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

static void reset_actions_state(void)
{
    chaos_dns_test_reset_runtime();
    g_chaos_dns_real_freeaddrinfo = chaos_dns_test_freeaddrinfo;
    g_force_calloc_fail = 0;
    g_freeaddrinfo_calls = 0;
}

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
