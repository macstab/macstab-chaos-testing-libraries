#ifndef CHAOS_PROCESS_CONFIG_H
#define CHAOS_PROCESS_CONFIG_H

#include "chaos_process_internal.h"

typedef enum chaos_process_operation
{
    CHAOS_PROCESS_OP_INVALID = -1,
    CHAOS_PROCESS_OP_PTHREAD_CREATE = 0,
    CHAOS_PROCESS_OP_FORK,
    CHAOS_PROCESS_OP_POSIX_SPAWN,
    CHAOS_PROCESS_OP_POSIX_SPAWNP,
    CHAOS_PROCESS_OP_EXECVE,
    CHAOS_PROCESS_OP_EXECVEAT,
    CHAOS_PROCESS_OP_WAITPID,
    CHAOS_PROCESS_OP_COUNT
} chaos_process_operation_t;

typedef enum chaos_process_selector_kind
{
    CHAOS_PROCESS_SELECTOR_INVALID = -1,
    CHAOS_PROCESS_SELECTOR_ANY = 0,
    CHAOS_PROCESS_SELECTOR_OPERATION
} chaos_process_selector_kind_t;

typedef enum chaos_process_effect
{
    CHAOS_PROCESS_EFFECT_INVALID = -1,
    CHAOS_PROCESS_EFFECT_ERRNO = 0,
    CHAOS_PROCESS_EFFECT_LATENCY,
    CHAOS_PROCESS_EFFECT_FAIL_AFTER
} chaos_process_effect_t;

typedef struct chaos_process_selector
{
    chaos_process_selector_kind_t kind;
    chaos_process_operation_t operation;
    size_t selector_len;
} chaos_process_selector_t;

typedef struct chaos_process_rule
{
    chaos_process_selector_t selector;
    chaos_process_effect_t effect;
    int errnum;
    double probability;
    unsigned int latency_ms;
    uint64_t fail_after_count;
} chaos_process_rule_t;

void chaos_process_config_init(void);
int chaos_process_config_prepare(void);

int chaos_process_config_match_loaded(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

int chaos_process_config_parse_line(char *line, chaos_process_rule_t *rule);
int chaos_process_config_parse_buffer(
    char *buffer, chaos_process_rule_t *rules, size_t *rule_count
);
int chaos_process_config_select_rule(
    const chaos_process_rule_t *rules,
    size_t rule_count,
    chaos_process_effect_t effect,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule
);

#endif
