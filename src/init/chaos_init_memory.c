/**
 * @file chaos_init_memory.c
 * @brief chaos-init: libchaos-memory rules for system calls of supervised processes.
 *
 * @details The memory rule core is compiled in unchanged. Everything it matches on
 * is in the arguments: the operation, mmap's flags (anonymous or file-backed) and
 * the length for `@size`. As in the hooks, a LATENCY rule delays the call and an
 * ERRNO rule then fails it; both can apply to one call.
 */

#include "chaos_init_memory.h"

#include "../memory/chaos_memory_actions.c"
#include "../memory/chaos_memory_config.c"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/syscall.h>

/* What the rule core expects the preload library to provide. */
__thread int g_chaos_memory_tls_guard = 0;
__thread uint64_t g_chaos_memory_tls_prng_state = 0U;
uint64_t g_chaos_memory_process_seed = UINT64_C(0x6a09e667f3bcc909);

/* Per-process hit slots of the memory rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_memory, CHAOS_MEMORY_MAX_RULES);

static uint64_t g_chaos_init_memory_load = 0U;
static const chaos_memory_config_state_t *g_chaos_init_memory_seen_state = NULL;
static uint64_t g_chaos_init_memory_seen_stamp = 0U;

static size_t chaos_init_memory_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_memory_config_state_t *state = chaos_memory_config_active_state();

    if (g_chaos_init_memory_load == 0U || state != g_chaos_init_memory_seen_state ||
        g_chaos_memory_cached_mtime != g_chaos_init_memory_seen_stamp)
    {
        g_chaos_init_memory_seen_state = state;
        g_chaos_init_memory_seen_stamp = g_chaos_memory_cached_mtime;
        ++g_chaos_init_memory_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_memory_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_memory_rules = {
    CHAOS_MEMORY_HITS_PREFIX,
    CHAOS_MEMORY_MAX_RULES,
    chaos_init_memory_snapshot,
    g_chaos_init_memory_slots,
    g_chaos_init_memory_hashes,
    g_chaos_init_memory_generation,
    g_chaos_init_memory_count,
    g_chaos_init_memory_total,
    g_chaos_init_memory_pending,
    g_chaos_init_memory_buffer,
    g_chaos_init_memory_file,
};

void chaos_init_memory_start(void)
{
    uint64_t seed;

    chaos_memory_config_init();
    if (getrandom(&seed, sizeof(seed), 0) == (ssize_t)sizeof(seed))
    {
        g_chaos_memory_process_seed = seed;
    }
    (void)chaos_init_tracee_register(&g_chaos_init_memory_rules);
}

/**
 * @brief Whether the @p effect rule for the call fires for the calling process;
 *        @p rule is the matched copy.
 */
static int chaos_init_memory_fires(
    const chaos_init_call_t *call,
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int flags,
    chaos_memory_rule_t *rule
)
{
    const chaos_memory_config_state_t *state;

    if (!chaos_memory_config_match(effect, operation, flags, rule))
    {
        return 0;
    }
    state = chaos_memory_config_active_state();
    rule->call_size = call->args[1];
    rule->hit = chaos_init_tracee_hit(
        &g_chaos_init_memory_rules, call->tid, state->hits, state->rule_count, rule->hit
    );
    rule->hit_generation = rule->hit != NULL ? rule->hit->generation : 0U;
    return rule->hit != NULL && chaos_memory_rule_should_trigger(rule);
}

int chaos_init_memory_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    chaos_memory_operation_t operation;
    chaos_memory_rule_t rule;
    int flags = 0;

    switch (call->nr)
    {
    case __NR_mmap:
        operation = CHAOS_MEMORY_OP_MMAP;
        flags = (int)call->args[3];
        break;
    case __NR_munmap:
        operation = CHAOS_MEMORY_OP_MUNMAP;
        break;
    case __NR_mprotect:
        operation = CHAOS_MEMORY_OP_MPROTECT;
        break;
    case __NR_madvise:
        operation = CHAOS_MEMORY_OP_MADVISE;
        break;
    default:
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;
    if (chaos_init_memory_fires(call, CHAOS_MEMORY_EFFECT_LATENCY, operation, flags, &rule))
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    if (chaos_init_memory_fires(call, CHAOS_MEMORY_EFFECT_ERRNO, operation, flags, &rule))
    {
        /* After a delay, or at once. */
        verdict->action = verdict->action == CHAOS_INIT_DELAY ? CHAOS_INIT_DELAY : CHAOS_INIT_FAIL;
        verdict->error = rule.errnum;
    }
    return 1;
}
