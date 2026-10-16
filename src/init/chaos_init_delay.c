/**
 * @file chaos_init_delay.c
 * @brief chaos-init: calls held back by a LATENCY rule.
 */

#include "chaos_init_delay.h"

#include <stddef.h>

typedef struct chaos_init_delayed
{
    uint64_t id;
    uint64_t due_ms;
} chaos_init_delayed_t;

static chaos_init_delayed_t g_chaos_init_delayed[CHAOS_INIT_MAX_DELAYED];
static size_t g_chaos_init_delayed_count = 0U;

int chaos_init_delay_add(uint64_t id, uint64_t due_ms)
{
    if (g_chaos_init_delayed_count == CHAOS_INIT_MAX_DELAYED)
    {
        return -1;
    }
    g_chaos_init_delayed[g_chaos_init_delayed_count].id = id;
    g_chaos_init_delayed[g_chaos_init_delayed_count].due_ms = due_ms;
    ++g_chaos_init_delayed_count;
    return 0;
}

int chaos_init_delay_next(uint64_t *due_ms)
{
    size_t index;

    if (g_chaos_init_delayed_count == 0U)
    {
        return 0;
    }
    *due_ms = g_chaos_init_delayed[0].due_ms;
    for (index = 1U; index < g_chaos_init_delayed_count; ++index)
    {
        if (g_chaos_init_delayed[index].due_ms < *due_ms)
        {
            *due_ms = g_chaos_init_delayed[index].due_ms;
        }
    }
    return 1;
}

int chaos_init_delay_pop(uint64_t now_ms, uint64_t *id)
{
    size_t index;

    for (index = 0U; index < g_chaos_init_delayed_count; ++index)
    {
        if (g_chaos_init_delayed[index].due_ms <= now_ms)
        {
            *id = g_chaos_init_delayed[index].id;
            g_chaos_init_delayed[index] = g_chaos_init_delayed[--g_chaos_init_delayed_count];
            return 1;
        }
    }
    return 0;
}
