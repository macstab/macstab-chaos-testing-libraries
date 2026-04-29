#ifndef CHAOS_MEMORY_ACTIONS_H
#define CHAOS_MEMORY_ACTIONS_H

#include "chaos_memory_config.h"

int chaos_memory_probability_hit_sample(double probability, uint32_t sample);
int chaos_memory_probability_hit(double probability);

int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule);
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule);
int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule);

#endif
