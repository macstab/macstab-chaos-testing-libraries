#ifndef CHAOS_PROCESS_ACTIONS_H
#define CHAOS_PROCESS_ACTIONS_H

#include "chaos_process_config.h"

int chaos_process_probability_hit_sample(double probability, uint32_t sample);
int chaos_process_probability_hit(double probability);
int chaos_process_rule_should_trigger(const chaos_process_rule_t *rule);
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule);
int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum);
int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
);

#endif
