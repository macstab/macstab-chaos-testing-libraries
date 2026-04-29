#ifndef CHAOS_TIME_ACTIONS_H
#define CHAOS_TIME_ACTIONS_H

#include "chaos_time_config.h"

int chaos_time_probability_hit_sample(double probability, uint32_t sample);
int chaos_time_probability_hit(double probability);
int chaos_time_rule_should_trigger(const chaos_time_rule_t *rule);
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule);
int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule);
void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value);

#endif
