#ifndef CHAOS_DNS_ACTIONS_H
#define CHAOS_DNS_ACTIONS_H

#include "chaos_dns_config.h"

int chaos_dns_probability_hit_sample(double probability, uint32_t sample);
int chaos_dns_probability_hit(double probability);
void chaos_dns_rule_apply_latency(const chaos_dns_rule_t *rule);
int chaos_dns_rule_should_trigger(const chaos_dns_rule_t *rule);
int chaos_dns_rule_apply_gai(const chaos_dns_rule_t *rule, int *gai_error);
size_t chaos_dns_result_count(const struct addrinfo *result);
int chaos_dns_filter_result_list(struct addrinfo **result, chaos_dns_family_filter_t family);
void chaos_dns_limit_result_list(struct addrinfo **result, unsigned int limit);
void chaos_dns_shuffle_result_list(struct addrinfo **result);

#endif
