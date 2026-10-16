/**
 * @file chaos_init_delay.c
 * @brief chaos-init: calls held back by a LATENCY rule.
 */

#include "chaos_init_delay.h"

#include <stddef.h>
#include <string.h>

typedef struct chaos_init_delayed
{
    uint64_t id;
    chaos_init_call_t call;
    uint64_t due_ms;
    chaos_init_verdict_t answer;
} chaos_init_delayed_t;

static chaos_init_delayed_t g_chaos_init_delayed[CHAOS_INIT_MAX_DELAYED];
static size_t g_chaos_init_delayed_count = 0U;

chaos_init_verdict_t chaos_init_delay_answer(const chaos_init_verdict_t *verdict)
{
    chaos_init_verdict_t answer = *verdict;

    answer.action = verdict->error != 0 ? CHAOS_INIT_FAIL
                    : verdict->returns  ? CHAOS_INIT_RETURN
                                        : CHAOS_INIT_PASS;
    answer.delay_ms = 0U;
    return answer;
}

int chaos_init_delay_add(
    uint64_t id, const chaos_init_call_t *call, uint64_t due_ms, const chaos_init_verdict_t *answer
)
{
    if (g_chaos_init_delayed_count == CHAOS_INIT_MAX_DELAYED)
    {
        return -1;
    }
    g_chaos_init_delayed[g_chaos_init_delayed_count].id = id;
    g_chaos_init_delayed[g_chaos_init_delayed_count].call = *call;
    g_chaos_init_delayed[g_chaos_init_delayed_count].due_ms = due_ms;
    g_chaos_init_delayed[g_chaos_init_delayed_count].answer = *answer;
    ++g_chaos_init_delayed_count;
    return 0;
}

int chaos_init_delay_resume(const chaos_init_call_t *call, uint64_t id)
{
    size_t index;

    for (index = 0U; index < g_chaos_init_delayed_count; ++index)
    {
        const chaos_init_call_t *parked = &g_chaos_init_delayed[index].call;

        if (parked->tid == call->tid && parked->nr == call->nr &&
            memcmp(parked->args, call->args, sizeof(parked->args)) == 0)
        {
            g_chaos_init_delayed[index].id = id;
            return 1;
        }
    }
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

int chaos_init_delay_pop(uint64_t now_ms, uint64_t *id, chaos_init_verdict_t *answer)
{
    size_t index;

    for (index = 0U; index < g_chaos_init_delayed_count; ++index)
    {
        if (g_chaos_init_delayed[index].due_ms <= now_ms)
        {
            *id = g_chaos_init_delayed[index].id;
            *answer = g_chaos_init_delayed[index].answer;
            g_chaos_init_delayed[index] = g_chaos_init_delayed[--g_chaos_init_delayed_count];
            return 1;
        }
    }
    return 0;
}
