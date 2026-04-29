#ifndef CHAOS_NET_CONFIG_H
#define CHAOS_NET_CONFIG_H

#include "chaos_net_internal.h"

#include <netinet/in.h>

typedef enum chaos_net_operation
{
    CHAOS_NET_OP_INVALID = -1,
    CHAOS_NET_OP_BIND = 0,
    CHAOS_NET_OP_LISTEN,
    CHAOS_NET_OP_CONNECT,
    CHAOS_NET_OP_ACCEPT,
    CHAOS_NET_OP_SOCKET,
    CHAOS_NET_OP_SHUTDOWN,
    CHAOS_NET_OP_POLL,
    CHAOS_NET_OP_SEND,
    CHAOS_NET_OP_RECV
} chaos_net_operation_t;

typedef enum chaos_net_effect
{
    CHAOS_NET_EFFECT_INVALID = -1,
    CHAOS_NET_EFFECT_ERRNO = 0,
    CHAOS_NET_EFFECT_LATENCY,
    CHAOS_NET_EFFECT_CORRUPT,
    CHAOS_NET_EFFECT_TIMEOUT
} chaos_net_effect_t;

typedef enum chaos_net_endpoint_kind
{
    CHAOS_NET_ENDPOINT_INVALID = -1,
    CHAOS_NET_ENDPOINT_ANY = 0,
    CHAOS_NET_ENDPOINT_TCP4,
    CHAOS_NET_ENDPOINT_TCP6,
    CHAOS_NET_ENDPOINT_UDP4,
    CHAOS_NET_ENDPOINT_UDP6,
    CHAOS_NET_ENDPOINT_UNIX
} chaos_net_endpoint_kind_t;

typedef struct chaos_net_endpoint
{
    chaos_net_endpoint_kind_t kind;
    size_t selector_len;
    uint16_t port;
    int wildcard_host;
    union
    {
        struct in_addr ipv4;
        struct in6_addr ipv6;
        char text[CHAOS_NET_MAX_TEXT];
    } value;
} chaos_net_endpoint_t;

typedef struct chaos_net_rule
{
    chaos_net_endpoint_t selector;
    chaos_net_operation_t operation;
    chaos_net_effect_t effect;
    int errnum;
    double probability;
    unsigned int latency_ms;
} chaos_net_rule_t;

void chaos_net_config_init(void);
int chaos_net_config_prepare(void);

int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
);

int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
);

int chaos_net_config_parse_line(char *line, chaos_net_rule_t *rule);
int chaos_net_config_parse_buffer(char *buffer, chaos_net_rule_t *rules, size_t *rule_count);
int chaos_net_config_select_endpoint_rule(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule
);

#endif
