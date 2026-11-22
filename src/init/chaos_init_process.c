/**
 * @file chaos_init_process.c
 * @brief `chaos-init`: libchaos-process rules applied to tracee system calls.
 *
 * @details The libchaos-process rule core is compiled in by `#include`, unchanged. The
 * wrappers' operations are recovered from the system call:
 *
 * | System call | Operation |
 * |---|---|
 * | clone/clone3 with CLONE_THREAD | pthread_create |
 * | clone/clone3 with CLONE_VFORK, vfork | posix_spawn (glibc posix_spawn(), Go os/exec) |
 * | any other clone/clone3, fork | fork |
 * | execve / execveat | execve / execveat |
 * | wait4, waitid | waitpid |
 *
 * clone3 flags are read from the first field of `struct clone_args` in tracee memory;
 * unreadable means fork. posix_spawnp cannot be told from posix_spawn: the PATH search
 * happens in the C library and issues the same system calls. A posix_spawnp rule could
 * therefore never fire and rejects its file (CHAOS_PROCESS_RULE_SUPPORTED).
 *
 * @par Effects
 * As in the wrappers: LATENCY delays the call, then ERRNO or FAIL_AFTER fails it.
 *
 * @par FAIL_AFTER counters
 * The core counts calls per operation in one global array, as each preloaded process has
 * its own. Here every process gets its own array, swapped in around each decision. The
 * counters restart from 0 after a reload, and so do a forked child's and a new image's
 * (execve): the wrappers clear them in their atfork child handler, so that a child never
 * inherits an exhausted FAIL_AFTER budget, and both modes behave alike.
 *
 * @par Application start
 * The child's execve() of the entrypoint is never faulted (chaos_init_process_start()).
 *
 * Test seam: CHAOS_INIT_PROCESS_OF replaces the /proc identity lookup.
 */

#include "chaos_init_process.h"

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_process_rule;
static int chaos_init_process_supported(const struct chaos_process_rule *rule);
#define CHAOS_PROCESS_RULE_SUPPORTED(rule) chaos_init_process_supported(rule)

#include "../process/chaos_process_actions.c"
#include "../process/chaos_process_config.c"
#include "chaos_init_proc.h"
#include "chaos_init_core.h"
#include "chaos_init_tracee.h"

#include <linux/sched.h>
#include <sys/random.h>
#include <sys/syscall.h>

#ifndef CHAOS_INIT_PROCESS_OF
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) chaos_init_process_of((tid), (tgid), (start))
#endif

/* Symbols the rule core expects from the preload library. The FAIL_AFTER array is the
 * core's per-process counter set; here it only holds the calling process's counters for
 * the duration of one decision (chaos_init_process_fail_after()). */
__thread int g_chaos_process_tls_guard = 0;
uint64_t g_chaos_process_lineage = 0U;
uint64_t g_chaos_process_process_seed = UINT64_C(0xbb67ae8584caa73b);
volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U};

/* CHAOS_PROCESS_RULE_SUPPORTED: everything except a posix_spawnp operation selector. */
static int chaos_init_process_supported(const struct chaos_process_rule *rule)
{
    return rule->selector.kind != CHAOS_PROCESS_SELECTOR_OPERATION ||
           rule->selector.operation != CHAOS_PROCESS_OP_POSIX_SPAWNP;
}

/* Per-process hit slots and FAIL_AFTER counters of the process rules, indexed by tracee
 * entry. `_load` is the rule load the counters belong to (stale load: reset to 0). */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_process, CHAOS_PROCESS_MAX_RULES);
static uint64_t g_chaos_init_process_counters[CHAOS_INIT_MAX_TRACEES][CHAOS_PROCESS_OP_COUNT];
static uint64_t g_chaos_init_process_counters_load[CHAOS_INIT_MAX_TRACEES];
/* The process (chaos_init_tracee_serial()) an entry's counters belong to; a mismatch
 * means the entry was reused by another process. */
static uint64_t g_chaos_init_process_counters_owner[CHAOS_INIT_MAX_TRACEES];

/** @brief The child chaos-init forked, while it still runs chaos-init's image; 0 after. */
static pid_t g_chaos_init_process_application = 0;
/**
 * @brief Identity (chaos_init_process_of()) of chaos-init's image in that child, recorded
 *        at its first execve(); 0 before.
 */
static uint64_t g_chaos_init_process_start_image = 0U;

static uint64_t g_chaos_init_process_load = 0U;
static const chaos_process_config_state_t *g_chaos_init_process_seen_state = NULL;
static uint64_t g_chaos_init_process_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for process; reload detection as in chaos_init_io.c. Its
 * load counter also keys the FAIL_AFTER counters. */
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

    chaos_process_config_init();
    g_chaos_process_process_seed = chaos_init_seed();
    g_chaos_init_process_application = application;
    (void)chaos_init_tracee_register(&g_chaos_init_process_rules);
}

/** @brief The operation a clone with @p flags stands for (CLONE_THREAD wins over VFORK). */
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
        /* struct clone_args begins with the u64 flags; unreadable leaves 0, i.e. fork. */
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

/**
 * @brief Replaces @p rule's snapshot slot with the calling process's slot.
 * @return 1, or 0 when the process has none (it ended): the rule must not fire.
 */
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
 * @brief Makes the FAIL_AFTER counters of entry @p tracee belong to its current process
 *        and rule load @p load.
 *
 * @details No-op when owner and load already match; otherwise the counters reset to 0.
 * A forked child is a process of its own here and therefore starts from 0, which is what
 * the wrappers do: their atfork child handler clears the counters so a child never
 * inherits an exhausted FAIL_AFTER budget (chaos_process_hooks.c).
 */
static void chaos_init_process_counters_of(int tracee, uint64_t load)
{
    const uint64_t serial = chaos_init_tracee_serial(tracee);

    if (g_chaos_init_process_counters_owner[tracee] == serial &&
        g_chaos_init_process_counters_load[tracee] == load)
    {
        return;
    }
    memset(g_chaos_init_process_counters[tracee], 0, sizeof(g_chaos_init_process_counters[0]));
    g_chaos_init_process_counters_owner[tracee] = serial;
    g_chaos_init_process_counters_load[tracee] = load;
}

/**
 * @brief Evaluates FAIL_AFTER for the calling process: copies its counters into the core's
 *        global array, lets the core count and decide, and copies them back.
 * @param error  Output: the errno to fail with when 1 is returned.
 * @return 1 when the call fails, else 0 (also when the process has no entry or slot).
 */
static int chaos_init_process_fail_after(
    const chaos_init_call_t *call,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule,
    int *error
)
{
    const int tracee = chaos_init_tracee_of(call->tid);
    int fails;
    int index;

    if (tracee < 0 || !chaos_init_process_slot(call, rule))
    {
        return 0;
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

/* LATENCY and ERRNO/FAIL_AFTER are matched independently, as in the wrappers; FAIL_AFTER
 * is consulted only when no ERRNO rule fires. */
int chaos_init_process_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_process_operation_t operation = chaos_init_process_operation(call);
    chaos_process_rule_t rule;
    const chaos_init_text_t *texts;
    uint64_t load;
    int tracee;
    int error = 0;

    if (operation == CHAOS_PROCESS_OP_INVALID)
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;
    if (operation == CHAOS_PROCESS_OP_EXECVE && call->tid == g_chaos_init_process_application)
    {
        pid_t group;
        uint64_t image;

        /* The application's start, exempt for as long as chaos-init's image issues it: a
         * failed execve() leaves the image unchanged, so the /bin/sh retry for a script
         * without #! is exempt too. The first execve() from a different image ends the
         * exemption for good, as does a failed identity lookup. */
        if (CHAOS_INIT_PROCESS_OF(call->tid, &group, &image) == 0 &&
            (g_chaos_init_process_start_image == 0U || image == g_chaos_init_process_start_image))
        {
            g_chaos_init_process_start_image = image;
            return 1;
        }
        g_chaos_init_process_application = 0;
    }
    tracee = chaos_init_tracee_of(call->tid);
    (void)chaos_process_config_prepare(); /* reload first: fixes the load decided under */
    (void)chaos_init_process_snapshot(&texts, &load);
    if (tracee >= 0)
    {
        chaos_init_process_counters_of(tracee, load);
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
