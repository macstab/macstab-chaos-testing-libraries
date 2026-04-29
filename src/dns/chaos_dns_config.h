#ifndef CHAOS_DNS_CONFIG_H
#define CHAOS_DNS_CONFIG_H

#include "chaos_dns_internal.h"

typedef enum chaos_dns_selector_kind
{
    CHAOS_DNS_SELECTOR_INVALID = -1,
    CHAOS_DNS_SELECTOR_ANY = 0,
    CHAOS_DNS_SELECTOR_EXACT,
    CHAOS_DNS_SELECTOR_SUFFIX
} chaos_dns_selector_kind_t;

typedef enum chaos_dns_selector_domain
{
    CHAOS_DNS_SELECTOR_DOMAIN_INVALID = -1,
    CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP = 0,
    CHAOS_DNS_SELECTOR_DOMAIN_REVERSE
} chaos_dns_selector_domain_t;

typedef enum chaos_dns_effect
{
    CHAOS_DNS_EFFECT_INVALID = -1,
    CHAOS_DNS_EFFECT_GAI = 0,
    CHAOS_DNS_EFFECT_LATENCY,
    CHAOS_DNS_EFFECT_REWRITE,
    CHAOS_DNS_EFFECT_SERVICE,
    CHAOS_DNS_EFFECT_OVERRIDE,
    CHAOS_DNS_EFFECT_FILTER_FAMILY,
    CHAOS_DNS_EFFECT_LIMIT,
    CHAOS_DNS_EFFECT_SHUFFLE
} chaos_dns_effect_t;

typedef enum chaos_dns_family_filter
{
    CHAOS_DNS_FAMILY_INVALID = -1,
    CHAOS_DNS_FAMILY_ANY = 0,
    CHAOS_DNS_FAMILY_INET4,
    CHAOS_DNS_FAMILY_INET6
} chaos_dns_family_filter_t;

typedef struct chaos_dns_selector
{
    chaos_dns_selector_kind_t kind;
    chaos_dns_selector_domain_t domain;
    size_t selector_len;
    char text[CHAOS_DNS_MAX_TEXT];
} chaos_dns_selector_t;

typedef struct chaos_dns_rule
{
    chaos_dns_selector_t selector;
    chaos_dns_effect_t effect;
    int gai_error;
    double probability;
    unsigned int latency_ms;
    unsigned int limit;
    chaos_dns_family_filter_t family;
    char text[CHAOS_DNS_MAX_VALUE];
} chaos_dns_rule_t;

void chaos_dns_config_init(void);
int chaos_dns_config_prepare(void);

int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
);

int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule);

int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

int chaos_dns_config_parse_line(char *line, chaos_dns_rule_t *rule);
int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count);
int chaos_dns_config_select_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *name,
    chaos_dns_rule_t *rule
);

int chaos_dns_config_select_reverse_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *address,
    chaos_dns_rule_t *rule
);

#endif
