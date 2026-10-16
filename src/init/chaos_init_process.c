/**
 * @file chaos_init_process.c
 * @brief chaos-init: libchaos-process rules for system calls of supervised processes.
 *
 * @details The process rule core is compiled in unchanged. The hooks' operations
 * are told apart by the system call and, for clone, its flags: a thread
 * (CLONE_THREAD) is pthread_create, a child that shares the memory until it
 * executes (CLONE_VFORK, as posix_spawn() and Go's os/exec make it) is
 * posix_spawn, any other child is fork. posix_spawnp cannot be told from
 * posix_spawn here: the path search happens in the C library.
 *
 * As in the hooks: LATENCY delays the call, then ERRNO or FAIL_AFTER fails it.
 * FAIL_AFTER counts calls per operation in each process, from 0 again after a
 * reload of the rule file; the core keeps those counters in one array, which is
 * swapped in for the calling process around each decision.
 */

#include "chaos_init_process.h"

#include "../process/chaos_process_actions.c"
#include "../process/chaos_process_config.c"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <linux/sched.h>
#include <sys/random.h>
#include <sys/syscall.h>

/* What the rule core expects the preload library to provide. */
__thread int g_chaos_process_tls_guard = 0;
__thread uint64_t g_chaos_process_tls_prng_state = 0U;
uint64_t g_chaos_process_process_seed = UINT64_C(0xbb67ae8584caa73b);
volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U};

/* Per-process hit slots and FAIL_AFTER counters of the process rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_process, CHAOS_PROCESS_MAX_RULES);
static uint64_t g_chaos_init_process_counters[CHAOS_INIT_MAX_TRACEES][CHAOS_PROCESS_OP_COUNT];
static uint64_t g_chaos_init_process_counters_load[CHAOS_INIT_MAX_TRACEES];

/** @brief The application chaos-init started, while its first execve() is pending. */
static pid_t g_chaos_init_process_application = 0;

static uint64_t g_chaos_init_process_load = 0U;
static const chaos_process_config_state_t *g_chaos_init_process_seen_state = NULL;
static uint64_t g_chaos_init_process_seen_stamp = 0U;

static size_t chaos_init_process_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_process_config_state_t *state = chaos_process_config_active_state();

    if (g_chaos_init_process_load == 0U || state != g_chaos_init_process_seen_state ||
        g_chaos_process_cached_mtime != g_chaos_init_process_seen_stamp)
    {
        g_chaos_init_process_seen_state = state;
        g_chaos_init_process_seen_stamp = g_chaos_process_cached_mtime;
        ++g_chaos_init_process_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_process_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_process_rules = {
    CHAOS_PROCESS_HITS_PREFIX,
    CHAOS_PROCESS_MAX_RULES,
    chaos_init_process_snapshot,
    g_chaos_init_process_slots,
    g_chaos_init_process_hashes,
    g_chaos_init_process_generation,
    g_chaos_init_process_count,
    g_chaos_init_process_total,
    g_chaos_init_process_pending,
    g_chaos_init_process_buffer,
    g_chaos_init_process_file,
};

void chaos_init_process_start(pid_t application)
{
    uint64_t seed;

    chaos_process_config_init();
    if (getrandom(&seed, sizeof(seed), 0) == (ssize_t)sizeof(seed))
    {
        g_chaos_process_process_seed = seed;
    }
    g_chaos_init_process_application = application;
    (void)chaos_init_tracee_register(&g_chaos_init_process_rules);
}

/** @brief The operation a clone with @p flags stands for. */
static chaos_process_operation_t chaos_init_process_clone(uint64_t flags)
{
    if ((flags & CLONE_THREAD) != 0U)
    {
        return CHAOS_PROCESS_OP_PTHREAD_CREATE;
    }
    return (flags & CLONE_VFORK) != 0U ? CHAOS_PROCESS_OP_POSIX_SPAWN : CHAOS_PROCESS_OP_FORK;
}

/** @brief The operation of @p call; CHAOS_PROCESS_OP_INVALID for other system calls. */
static chaos_process_operation_t chaos_init_process_operation(const chaos_init_call_t *call)
{
    uint64_t flags = 0U;

    switch (call->nr)
    {
    case __NR_clone:
        return chaos_init_process_clone(call->args[0]);
#ifdef __NR_clone3
    case __NR_clone3:
        /* struct clone_args begins with the flags; unreadable, it is a fork. */
        (void)chaos_init_read_memory(call->tid, call->args[0], &flags, sizeof(flags));
        return chaos_init_process_clone(flags);
#endif
#ifdef __NR_fork
    case __NR_fork:
        return CHAOS_PROCESS_OP_FORK;
#endif
#ifdef __NR_vfork
    case __NR_vfork:
        return CHAOS_PROCESS_OP_POSIX_SPAWN;
#endif
    case __NR_execve:
        return CHAOS_PROCESS_OP_EXECVE;
    case __NR_execveat:
        return CHAOS_PROCESS_OP_EXECVEAT;
    case __NR_wait4:
    case __NR_waitid:
        return CHAOS_PROCESS_OP_WAITPID;
    default:
        return CHAOS_PROCESS_OP_INVALID;
    }
}

/** @brief Gives @p rule the calling process's slot; 0 when it has none. */
static int chaos_init_process_slot(const chaos_init_call_t *call, chaos_process_rule_t *rule)
{
    const chaos_process_config_state_t *state = chaos_process_config_active_state();

    rule->hit = chaos_init_tracee_hit(
        &g_chaos_init_process_rules, call->tid, state->hits, state->rule_count, rule->hit
    );
    rule->hit_generation = rule->hit != NULL ? rule->hit->generation : 0U;
    return rule->hit != NULL;
}

/**
 * @brief FAIL_AFTER for the calling process: its counters swapped into the core's
 *        array around the decision, reset when the rules were reloaded.
 */
static int chaos_init_process_fail_after(
    const chaos_init_call_t *call,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule,
    int *error
)
{
    const chaos_init_text_t *texts;
    uint64_t load;
    const int tracee = chaos_init_tracee_of(call->tid);
    int fails;
    int index;

    if (tracee < 0 || !chaos_init_process_slot(call, rule))
    {
        return 0;
    }
    (void)chaos_init_process_snapshot(&texts, &load);
    if (g_chaos_init_process_counters_load[tracee] != load)
    {
        memset(g_chaos_init_process_counters[tracee], 0, sizeof(g_chaos_init_process_counters[0]));
        g_chaos_init_process_counters_load[tracee] = load;
    }
    for (index = 0; index < CHAOS_PROCESS_OP_COUNT; ++index)
    {
        g_chaos_process_fail_after_counters[index] = g_chaos_init_process_counters[tracee][index];
    }
    fails = chaos_process_rule_fail_after_error(rule, operation, error);
    for (index = 0; index < CHAOS_PROCESS_OP_COUNT; ++index)
    {
        g_chaos_init_process_counters[tracee][index] = g_chaos_process_fail_after_counters[index];
    }
    return fails;
}

int chaos_init_process_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_process_operation_t operation = chaos_init_process_operation(call);
    chaos_process_rule_t rule;
    int error = 0;

    if (operation == CHAOS_PROCESS_OP_INVALID)
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;
    if (operation == CHAOS_PROCESS_OP_EXECVE && call->tid == g_chaos_init_process_application)
    {
        g_chaos_init_process_application = 0; /* the start of the application itself */
        return 1;
    }
    if (chaos_process_config_match(CHAOS_PROCESS_EFFECT_LATENCY, operation, &rule) &&
        chaos_init_process_slot(call, &rule) && chaos_process_rule_should_trigger(&rule))
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    if ((chaos_process_config_match(CHAOS_PROCESS_EFFECT_ERRNO, operation, &rule) &&
         chaos_init_process_slot(call, &rule) && chaos_process_rule_error_number(&rule, &error)) ||
        (chaos_process_config_match(CHAOS_PROCESS_EFFECT_FAIL_AFTER, operation, &rule) &&
         chaos_init_process_fail_after(call, operation, &rule, &error)))
    {
        verdict->action = verdict->action == CHAOS_INIT_DELAY ? CHAOS_INIT_DELAY : CHAOS_INIT_FAIL;
        verdict->error = error;
    }
    return 1;
}
