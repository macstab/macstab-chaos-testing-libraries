#ifndef CHAOS_NET_ACTIONS_H
#define CHAOS_NET_ACTIONS_H

#include "chaos_net_config.h"

int chaos_net_probability_hit_sample(double probability, uint32_t sample);
int chaos_net_probability_hit(double probability);
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
);
void chaos_net_corrupt_buffer(void *buffer, size_t size);
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule);
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule);
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule);

#endif
