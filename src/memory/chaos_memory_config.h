#ifndef CHAOS_MEMORY_CONFIG_H
#define CHAOS_MEMORY_CONFIG_H

#include "chaos_memory_internal.h"

typedef enum chaos_memory_operation
{
    CHAOS_MEMORY_OP_INVALID = -1,
    CHAOS_MEMORY_OP_MMAP = 0,
    CHAOS_MEMORY_OP_MPROTECT,
    CHAOS_MEMORY_OP_MADVISE,
    CHAOS_MEMORY_OP_MUNMAP
} chaos_memory_operation_t;

typedef enum chaos_memory_selector_kind
{
    CHAOS_MEMORY_SELECTOR_INVALID = -1,
    CHAOS_MEMORY_SELECTOR_ANY = 0,
    CHAOS_MEMORY_SELECTOR_OPERATION,
    CHAOS_MEMORY_SELECTOR_MMAP_KIND
} chaos_memory_selector_kind_t;

typedef enum chaos_memory_mmap_kind
{
    CHAOS_MEMORY_MMAP_KIND_INVALID = -1,
    CHAOS_MEMORY_MMAP_KIND_ANON = 0,
    CHAOS_MEMORY_MMAP_KIND_FILE
} chaos_memory_mmap_kind_t;

typedef enum chaos_memory_effect
{
    CHAOS_MEMORY_EFFECT_INVALID = -1,
    CHAOS_MEMORY_EFFECT_ERRNO = 0,
    CHAOS_MEMORY_EFFECT_LATENCY
} chaos_memory_effect_t;

typedef struct chaos_memory_selector
{
    chaos_memory_selector_kind_t kind;
    chaos_memory_operation_t operation;
    chaos_memory_mmap_kind_t mmap_kind;
    size_t selector_len;
} chaos_memory_selector_t;

typedef struct chaos_memory_rule
{
    chaos_memory_selector_t selector;
    chaos_memory_effect_t effect;
    int errnum;
    double probability;
    unsigned int latency_ms;
} chaos_memory_rule_t;

void chaos_memory_config_init(void);
int chaos_memory_config_prepare(void);

int chaos_memory_config_match_loaded(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

int chaos_memory_config_match(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

int chaos_memory_config_parse_line(char *line, chaos_memory_rule_t *rule);
int chaos_memory_config_parse_buffer(char *buffer, chaos_memory_rule_t *rules, size_t *rule_count);
int chaos_memory_config_select_rule(
    const chaos_memory_rule_t *rules,
    size_t rule_count,
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

#endif
