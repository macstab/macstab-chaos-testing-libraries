#include "chaos_dns_actions.h"
#include "chaos_dns_config.h"
#include "chaos_dns_internal.h"

#include <arpa/inet.h>
#include <string.h>

static int chaos_dns_call_real_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getaddrinfo(node, service, hints, result);
    chaos_dns_leave_internal(previous);
    return rc;
}

static int chaos_dns_call_real_getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = g_chaos_dns_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    chaos_dns_leave_internal(previous);
    return rc;
}

static int
chaos_dns_copy_text_or_null(const char *text, char *buffer, size_t buffer_size, const char **target)
{
    size_t len;

    if (target == NULL)
    {
        return -1;
    }
    if (text == NULL)
    {
        *target = NULL;
        return 0;
    }

    len = strlen(text);
    if (len >= buffer_size)
    {
        return -1;
    }

    (void)memcpy(buffer, text, len + 1U);
    *target = buffer;
    return 0;
}

static int chaos_dns_copy_output_text(const char *text, char *target, size_t target_size)
{
    size_t len;

    if (text == NULL || target == NULL || target_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len >= target_size)
    {
        return -1;
    }

    (void)memcpy(target, text, len + 1U);
    return 0;
}

static int chaos_dns_reverse_query_from_sockaddr(
    const struct sockaddr *address, socklen_t address_len, char *buffer, size_t buffer_size
)
{
    if (address == NULL || buffer == NULL || buffer_size == 0U ||
        address_len < (socklen_t)sizeof(sa_family_t))
    {
        return 0;
    }
    if (address->sa_family == AF_INET)
    {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;

        if (address_len < (socklen_t)sizeof(*ipv4))
        {
            return 0;
        }
        return inet_ntop(AF_INET, &ipv4->sin_addr, buffer, buffer_size) != NULL;
    }
    if (address->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;

        if (address_len < (socklen_t)sizeof(*ipv6))
        {
            return 0;
        }
        return inet_ntop(AF_INET6, &ipv6->sin6_addr, buffer, buffer_size) != NULL;
    }

    return 0;
}

static void chaos_dns_append_result_list(struct addrinfo **head, struct addrinfo *next)
{
    struct addrinfo *tail;

    if (head == NULL || next == NULL)
    {
        return;
    }
    if (*head == NULL)
    {
        *head = next;
        return;
    }

    tail = *head;
    while (tail->ai_next != NULL)
    {
        tail = tail->ai_next;
    }
    tail->ai_next = next;
}

static int chaos_dns_strip_ipv6_brackets(const char *token, char *host, size_t host_size)
{
    size_t len;

    if (token == NULL || host == NULL || host_size == 0U)
    {
        return -1;
    }

    len = strlen(token);
    if (len == 0U)
    {
        return -1;
    }
    if (token[0] == '[' && len > 2U && token[len - 1U] == ']')
    {
        if (len - 2U >= host_size)
        {
            return -1;
        }
        (void)memcpy(host, token + 1, len - 2U);
        host[len - 2U] = '\0';
        return 0;
    }
    if (len >= host_size)
    {
        return -1;
    }

    (void)memcpy(host, token, len + 1U);
    return 0;
}

static int chaos_dns_apply_override(
    const chaos_dns_rule_t *rule,
    const char *service,
    const struct addrinfo *hints,
    struct addrinfo **result
)
{
    char override_text[CHAOS_DNS_MAX_VALUE];
    char *cursor;
    struct addrinfo hints_copy;
    const struct addrinfo *lookup_hints;
    struct addrinfo *combined = NULL;

    if (rule == NULL || result == NULL)
    {
        return EAI_FAIL;
    }
    if (strlen(rule->text) >= sizeof(override_text))
    {
        return EAI_FAIL;
    }

    (void)memcpy(override_text, rule->text, strlen(rule->text) + 1U);
    if (hints != NULL)
    {
        hints_copy = *hints;
    }
    else
    {
        (void)memset(&hints_copy, 0, sizeof(hints_copy));
    }
    hints_copy.ai_flags |= AI_NUMERICHOST;
    lookup_hints = &hints_copy;

    cursor = override_text;
    while (*cursor != '\0')
    {
        char *token = cursor;
        char *separator = strchr(cursor, ',');
        char host[CHAOS_DNS_MAX_TEXT];
        struct addrinfo *partial = NULL;
        int rc;

        if (separator != NULL)
        {
            *separator++ = '\0';
            cursor = separator;
        }
        else
        {
            cursor += strlen(cursor);
        }

        token = token + strspn(token, " \t\r\n");
        if (chaos_dns_strip_ipv6_brackets(token, host, sizeof(host)) != 0)
        {
            if (combined != NULL)
            {
                g_chaos_dns_real_freeaddrinfo(combined);
            }
            return EAI_FAIL;
        }

        rc = chaos_dns_call_real_getaddrinfo(host, service, lookup_hints, &partial);
        if (rc != 0)
        {
            if (combined != NULL)
            {
                g_chaos_dns_real_freeaddrinfo(combined);
            }
            return rc;
        }
        chaos_dns_append_result_list(&combined, partial);
    }

    *result = combined;
    return combined != NULL ? 0 : EAI_NONAME;
}

CHAOS_DNS_EXPORT int getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    chaos_dns_rule_t override_rule;
    chaos_dns_rule_t filter_rule;
    chaos_dns_rule_t shuffle_rule;
    chaos_dns_rule_t limit_rule;
    char node_buffer[CHAOS_DNS_MAX_VALUE];
    char service_buffer[CHAOS_DNS_MAX_VALUE];
    const char *effective_node = node;
    const char *effective_service = service;
    int rc;
    int gai_error;

    if (chaos_dns_in_internal() || node == NULL || *node == '\0')
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_LATENCY, node, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, node, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        return gai_error;
    }

    if (result == NULL)
    {
        return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
    }

    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, node, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule))
    {
        if (chaos_dns_copy_text_or_null(
                rewrite_rule.text, node_buffer, sizeof(node_buffer), &effective_node
            ) != 0)
        {
            return EAI_FAIL;
        }
    }
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SERVICE, node, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule))
    {
        if (chaos_dns_copy_text_or_null(
                service_rule.text, service_buffer, sizeof(service_buffer), &effective_service
            ) != 0)
        {
            return EAI_FAIL;
        }
    }

    *result = NULL;
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, node, &override_rule) &&
        chaos_dns_rule_should_trigger(&override_rule))
    {
        rc = chaos_dns_apply_override(&override_rule, effective_service, hints, result);
    }
    else
    {
        rc = chaos_dns_call_real_getaddrinfo(effective_node, effective_service, hints, result);
    }
    if (rc != 0)
    {
        return rc;
    }

    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_FILTER_FAMILY, node, &filter_rule) &&
        chaos_dns_rule_should_trigger(&filter_rule) &&
        !chaos_dns_filter_result_list(result, filter_rule.family))
    {
        return EAI_NONAME;
    }
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_SHUFFLE, node, &shuffle_rule) &&
        chaos_dns_rule_should_trigger(&shuffle_rule))
    {
        chaos_dns_shuffle_result_list(result);
    }
    if (chaos_dns_config_match(CHAOS_DNS_EFFECT_LIMIT, node, &limit_rule) &&
        chaos_dns_rule_should_trigger(&limit_rule))
    {
        chaos_dns_limit_result_list(result, limit_rule.limit);
        if (*result == NULL)
        {
            return EAI_NONAME;
        }
    }

    return 0;
}

CHAOS_DNS_EXPORT int getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    chaos_dns_rule_t latency_rule;
    chaos_dns_rule_t gai_rule;
    chaos_dns_rule_t rewrite_rule;
    chaos_dns_rule_t service_rule;
    char query[CHAOS_DNS_MAX_TEXT];
    int rc;
    int gai_error;

    if (chaos_dns_in_internal() || address == NULL)
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }
    if (!chaos_dns_reverse_query_from_sockaddr(address, address_len, query, sizeof(query)))
    {
        return chaos_dns_call_real_getnameinfo(
            address, address_len, host, host_len, service, service_len, flags
        );
    }

    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_LATENCY, query, &latency_rule) &&
        chaos_dns_rule_should_trigger(&latency_rule))
    {
        chaos_dns_rule_apply_latency(&latency_rule);
    }

    if (chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, query, &gai_rule) &&
        chaos_dns_rule_apply_gai(&gai_rule, &gai_error))
    {
        return gai_error;
    }

    rc = chaos_dns_call_real_getnameinfo(
        address, address_len, host, host_len, service, service_len, flags
    );
    if (rc != 0)
    {
        return rc;
    }

    if (host != NULL && host_len > 0U &&
        chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, query, &rewrite_rule) &&
        chaos_dns_rule_should_trigger(&rewrite_rule) &&
        chaos_dns_copy_output_text(rewrite_rule.text, host, (size_t)host_len) != 0)
    {
        return EAI_OVERFLOW;
    }

    if (service != NULL && service_len > 0U &&
        chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_SERVICE, query, &service_rule) &&
        chaos_dns_rule_should_trigger(&service_rule) &&
        chaos_dns_copy_output_text(service_rule.text, service, (size_t)service_len) != 0)
    {
        return EAI_OVERFLOW;
    }

    return 0;
}
