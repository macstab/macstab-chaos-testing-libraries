#ifndef CHAOS_TIME_CONFIG_H
#define CHAOS_TIME_CONFIG_H

#include "chaos_time_internal.h"

typedef enum chaos_time_operation
{
    CHAOS_TIME_OP_INVALID = -1,
    CHAOS_TIME_OP_CLOCK_GETTIME = 0,
    CHAOS_TIME_OP_NANOSLEEP,
    CHAOS_TIME_OP_USLEEP
} chaos_time_operation_t;

typedef enum chaos_time_selector_kind
{
    CHAOS_TIME_SELECTOR_INVALID = -1,
    CHAOS_TIME_SELECTOR_ANY = 0,
    CHAOS_TIME_SELECTOR_OPERATION,
    CHAOS_TIME_SELECTOR_CLOCK_ID
} chaos_time_selector_kind_t;

typedef enum chaos_time_effect
{
    CHAOS_TIME_EFFECT_INVALID = -1,
    CHAOS_TIME_EFFECT_ERRNO = 0,
    CHAOS_TIME_EFFECT_LATENCY,
    CHAOS_TIME_EFFECT_OFFSET
} chaos_time_effect_t;

typedef struct chaos_time_selector
{
    chaos_time_selector_kind_t kind;
    chaos_time_operation_t operation;
    clockid_t clock_id;
    size_t selector_len;
    char text[CHAOS_TIME_MAX_TEXT];
} chaos_time_selector_t;

typedef struct chaos_time_rule
{
    chaos_time_selector_t selector;
    chaos_time_effect_t effect;
    int errnum;
    double probability;
    unsigned int latency_ms;
    int64_t offset_ms;
} chaos_time_rule_t;

void chaos_time_config_init(void);
int chaos_time_config_prepare(void);

int chaos_time_config_match_loaded(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

int chaos_time_config_parse_line(char *line, chaos_time_rule_t *rule);
int chaos_time_config_parse_buffer(char *buffer, chaos_time_rule_t *rules, size_t *rule_count);
int chaos_time_config_select_rule(
    const chaos_time_rule_t *rules,
    size_t rule_count,
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

#endif
