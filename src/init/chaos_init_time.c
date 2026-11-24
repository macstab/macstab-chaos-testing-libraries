/**
 * @file chaos_init_time.c
 * @brief `chaos-init`: libchaos-time rules applied to tracee system calls.
 *
 * @details The libchaos-time rule core is compiled in by `#include`, unchanged. What it
 * matches on is in the registers: the operation (clock read or sleep) and, for a clock
 * read, the clock in `args[0]`.
 *
 * @par The value is the supervisor's, not the kernel's
 * A clock read that a value-changing rule matches does not run. The supervisor reads the
 * same clock, applies the effect and writes the result into the tracee's buffer at commit
 * time, then answers 0. Nothing of the tracee is needed for that but the output pointer,
 * and the value is read at the moment the answer goes out -- so a delayed read reports
 * the time after its delay, as the library's does.
 *
 * The draw for OFFSET, REGRESS and FREEZE happens at commit, which is where the library
 * draws it: after the real call. LATENCY and ERRNO are drawn at decision time, because
 * the verdict is what carries them.
 *
 * @par Why the reads arrive at all
 * `clock_gettime` and friends are served from the vDSO without a system call. The
 * supervisor makes the tracee's lookups fail at every `execve` (chaos_init_vdso.h), after
 * which the C library and the Go runtime fall back to the system call. Without that step
 * this file would decide nothing.
 *
 * @par Cost
 * A notified clock read costs a notification round trip instead of a vDSO call. The
 * filter therefore notifies only the clocks the rules name (chaos_init_time_clocks()),
 * and a process whose rules work on the wall clock keeps its monotonic reads at the price
 * of a plain system call.
 *
 * @par What SECCOMP mode cannot do
 * `usleep` rules are rejected: libc serves `usleep` through `nanosleep`, so the
 * supervisor cannot tell the two apart and the rule would load and never fire.
 */

#include "chaos_init_time.h"

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_time_rule;
static int chaos_init_time_supported(const struct chaos_time_rule *rule);
#define CHAOS_TIME_RULE_SUPPORTED(rule) chaos_init_time_supported(rule)

#include "../time/chaos_time_actions.c"
#include "../time/chaos_time_config.c"
#include "chaos_init_core.h"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/time.h>

/* Symbols the rule core expects from the preload library; the seed is replaced from
 * getrandom() in chaos_init_time_start(). The sleep pointers are plain libc here, as in
 * chaos_init_io.c: the supervisor is under no filter and wraps nothing. It parks a
 * delayed call rather than sleeping in it, so nothing here reaches them. */
chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = nanosleep;
chaos_time_usleep_fn g_chaos_time_real_usleep = usleep;
__thread int g_chaos_time_tls_guard = 0;
uint64_t g_chaos_time_lineage = 0U;
uint64_t g_chaos_time_process_seed = UINT64_C(0x3c6ef372fe94f82b);

/* CHAOS_TIME_RULE_SUPPORTED: everything on a clock read, because the supervisor produces
 * the value itself, and ERRNO and LATENCY on a sleep, which are a reply and a delay. A
 * `usleep` rule is rejected: libc sleeps through `nanosleep`, so the filter cannot tell
 * which entry point the program used and the rule would never fire. */
static int chaos_init_time_supported(const struct chaos_time_rule *rule)
{
    return rule->selector.operation != CHAOS_TIME_OP_USLEEP;
}

/** @brief Test seam: the clock the supervisor reads for a tracee's call. */
#ifndef CHAOS_INIT_TIME_CLOCK
#define CHAOS_INIT_TIME_CLOCK clock_gettime
#endif

/* Per-process hit slots of the time rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_time, CHAOS_TIME_MAX_RULES);

static uint64_t g_chaos_init_time_load = 0U;
static const chaos_time_config_state_t *g_chaos_init_time_seen_state = NULL;
static uint64_t g_chaos_init_time_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for time; reload detection as in chaos_init_io.c. */
static size_t chaos_init_time_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_time_config_state_t *state = chaos_time_config_active_state();

    if (g_chaos_init_time_load == 0U || state != g_chaos_init_time_seen_state ||
        g_chaos_time_cached_mtime != g_chaos_init_time_seen_stamp)
    {
        g_chaos_init_time_seen_state = state;
        g_chaos_init_time_seen_stamp = g_chaos_time_cached_mtime;
        ++g_chaos_init_time_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_time_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_time_rules = {
    CHAOS_TIME_HITS_PREFIX,
    CHAOS_TIME_MAX_RULES,
    chaos_init_time_snapshot,
    /* The same header the library writes, so a reader correlates the counts with the
     * same reload generation whichever mode produced them. */
    chaos_time_hits_header,
    g_chaos_init_time_slots,
    g_chaos_init_time_hashes,
    g_chaos_init_time_generation,
    g_chaos_init_time_count,
    g_chaos_init_time_total,
    g_chaos_init_time_pending,
    g_chaos_init_time_buffer,
    g_chaos_init_time_file,
};

void chaos_init_time_start(void)
{

    chaos_time_config_init();
    g_chaos_time_process_seed = chaos_init_seed();
    (void)chaos_init_tracee_register(&g_chaos_init_time_rules);
}

/** @brief How a time system call reports its value. */
typedef enum chaos_init_time_shape
{
    CHAOS_INIT_TIME_NONE = 0, /**< A sleep: no value to write. */
    CHAOS_INIT_TIME_TIMESPEC, /**< clock_gettime: struct timespec. */
    CHAOS_INIT_TIME_TIMEVAL   /**< gettimeofday: struct timeval. */
#ifdef __NR_time
    ,
    CHAOS_INIT_TIME_SECONDS /**< time: time_t; x86_64 only, aarch64 has no vDSO time. */
#endif
} chaos_init_time_shape_t;

/**
 * @brief Decodes @p call into what the rule core needs to match it.
 *
 * @param operation  Output: the operation.
 * @param clock      Output: the clock of a read; CLOCK_REALTIME where the call has none.
 * @param shape      Output: how the value is reported.
 * @param target     Output: where the value goes in the tracee; 0 when there is none.
 * @return 1 when it is a time call, else 0.
 */
static int chaos_init_time_decode(
    const chaos_init_call_t *call,
    chaos_time_operation_t *operation,
    clockid_t *clock,
    chaos_init_time_shape_t *shape,
    uint64_t *target
)
{
    *operation = CHAOS_TIME_OP_CLOCK_GETTIME;
    *clock = CLOCK_REALTIME;
    *shape = CHAOS_INIT_TIME_TIMESPEC;
    *target = 0U;
    switch (call->nr)
    {
    case __NR_clock_gettime:
        *clock = (clockid_t)(int32_t)call->args[0];
        *target = call->args[1];
        return 1;
#ifdef __NR_gettimeofday
    case __NR_gettimeofday:
        *shape = CHAOS_INIT_TIME_TIMEVAL;
        *target = call->args[0];
        return 1;
#endif
#ifdef __NR_time
    case __NR_time:
        *shape = CHAOS_INIT_TIME_SECONDS;
        *target = call->args[0];
        return 1;
#endif
    case __NR_nanosleep:
    case __NR_clock_nanosleep:
        *operation = CHAOS_TIME_OP_NANOSLEEP;
        *shape = CHAOS_INIT_TIME_NONE;
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief Whether a rule with @p effect matches the call and fires for the calling process.
 *
 * @param rule  Output: the matched copy (valid when 1 is returned).
 */
static int chaos_init_time_fires(
    const chaos_init_call_t *call,
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock,
    chaos_time_rule_t *rule
)
{
    const chaos_time_config_state_t *state;

    if (!chaos_time_config_match(effect, operation, clock, rule))
    {
        return 0;
    }
    state = chaos_time_config_active_state();
    rule->hit = chaos_init_tracee_hit(
        &g_chaos_init_time_rules, call->tid, state->hits, state->rule_count, rule->hit
    );
    rule->hit_generation = rule->hit != NULL ? rule->hit->generation : 0U;
    return rule->hit != NULL && chaos_time_rule_should_trigger(rule);
}

/**
 * @brief Matches the rule that changes a read value, without drawing for it.
 *
 * @details The draw belongs to the applier (chaos_time_rule_apply_offset() and its
 * siblings decide and apply in one step), so this only prepares the copy -- which is why
 * it must not be called twice for one call.
 *
 * @return The effect found, or CHAOS_TIME_EFFECT_INVALID when no rule changes the value.
 */
static chaos_time_effect_t
chaos_init_time_value_rule(const chaos_init_call_t *call, clockid_t clock, chaos_time_rule_t *rule)
{
    static const chaos_time_effect_t effects[] = {
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_EFFECT_REGRESS, CHAOS_TIME_EFFECT_FREEZE
    };
    const chaos_time_config_state_t *state;
    size_t index;

    for (index = 0U; index < sizeof(effects) / sizeof(effects[0]); ++index)
    {
        if (!chaos_time_config_match(effects[index], CHAOS_TIME_OP_CLOCK_GETTIME, clock, rule))
        {
            continue;
        }
        state = chaos_time_config_active_state();
        rule->hit = chaos_init_tracee_hit(
            &g_chaos_init_time_rules, call->tid, state->hits, state->rule_count, rule->hit
        );
        rule->hit_generation = rule->hit != NULL ? rule->hit->generation : 0U;
        if (rule->hit != NULL)
        {
            return effects[index];
        }
    }
    return CHAOS_TIME_EFFECT_INVALID;
}

int chaos_init_time_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    chaos_time_operation_t operation;
    chaos_init_time_shape_t shape;
    chaos_time_rule_t rule;
    struct timespec reading;
    clockid_t clock;
    uint64_t target;

    if (!chaos_init_time_decode(call, &operation, &clock, &shape, &target))
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;
    if (!chaos_time_config_prepare())
    {
        return 1;
    }
    if (chaos_init_time_fires(call, CHAOS_TIME_EFFECT_LATENCY, operation, clock, &rule))
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    if (chaos_init_time_fires(call, CHAOS_TIME_EFFECT_ERRNO, operation, clock, &rule))
    {
        /* With a LATENCY hit the call stays DELAY and fails when due
         * (chaos_init_delay_answer()); otherwise it fails at once. */
        verdict->action = verdict->action == CHAOS_INIT_DELAY ? CHAOS_INIT_DELAY : CHAOS_INIT_FAIL;
        verdict->error = rule.errnum;
        return 1;
    }
    /* A value the supervisor has to produce: only for a read it can serve, which means a
     * clock it can read itself and a buffer to write. Anything else runs as it is, so a
     * rule on a clock this kernel does not know is left to the kernel's own EINVAL. */
    if (shape == CHAOS_INIT_TIME_NONE || target == 0U ||
        chaos_init_time_value_rule(call, clock, &rule) == CHAOS_TIME_EFFECT_INVALID ||
        CHAOS_INIT_TIME_CLOCK(clock, &reading) != 0)
    {
        return 1;
    }
    /* The call does not run; the answer carries the value, written at commit. A delayed
     * read keeps its delay and answers with the value when it is due. */
    verdict->action = verdict->action == CHAOS_INIT_DELAY ? CHAOS_INIT_DELAY : CHAOS_INIT_RETURN;
    verdict->returns = 1;
    verdict->value = 0;
    verdict->writes_time = 1;
    return 1;
}

void chaos_init_time_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict)
{
    chaos_time_operation_t operation;
    chaos_init_time_shape_t shape;
    chaos_time_rule_t rule;
    struct timespec reading;
    clockid_t clock;
    uint64_t target;

    if (verdict->writes_time == 0 ||
        !chaos_init_time_decode(call, &operation, &clock, &shape, &target) ||
        CHAOS_INIT_TIME_CLOCK(clock, &reading) != 0)
    {
        return;
    }
    switch (chaos_init_time_value_rule(call, clock, &rule))
    {
    case CHAOS_TIME_EFFECT_OFFSET:
        chaos_time_rule_apply_offset(&rule, &reading);
        break;
    case CHAOS_TIME_EFFECT_REGRESS:
        chaos_time_rule_apply_regress(&rule, &reading);
        break;
    case CHAOS_TIME_EFFECT_FREEZE:
        chaos_time_rule_apply_freeze(&rule, &reading);
        break;
    default:
        /* The rule file changed between the decision and the reply: the real value is
         * then what the tracee gets, which is what the call would have produced. */
        break;
    }
    if (shape == CHAOS_INIT_TIME_TIMEVAL)
    {
        struct timeval value;

        value.tv_sec = reading.tv_sec;
        value.tv_usec = (suseconds_t)(reading.tv_nsec / 1000L);
        (void)chaos_init_write_memory(call->tid, target, &value, sizeof(value));
        return;
    }
#ifdef __NR_time
    if (shape == CHAOS_INIT_TIME_SECONDS)
    {
        const time_t seconds = reading.tv_sec;

        (void)chaos_init_write_memory(call->tid, target, &seconds, sizeof(seconds));
        return;
    }
#endif
    (void)chaos_init_write_memory(call->tid, target, &reading, sizeof(reading));
}

size_t chaos_init_time_calls(long *out, size_t capacity)
{
    static const long reads[] = {
        __NR_clock_gettime,
#ifdef __NR_gettimeofday
        __NR_gettimeofday,
#endif
#ifdef __NR_time
        __NR_time,
#endif
    };
    static const long sleeps[] = {__NR_nanosleep, __NR_clock_nanosleep};
    const chaos_time_config_state_t *state;
    size_t count = 0U;
    size_t index;
    int wants_reads = 0;
    int wants_wall = 0;
    int wants_sleeps = 0;

    if (out == NULL || !chaos_time_config_prepare())
    {
        return 0U;
    }
    state = chaos_time_config_active_state();
    for (index = 0U; index < state->rule_count; ++index)
    {
        const chaos_time_selector_t *selector = &state->rules[index].selector;

        if (selector->kind == CHAOS_TIME_SELECTOR_CLOCK_ID)
        {
            wants_reads = 1;
            /* gettimeofday and time read the wall clock and nothing else, so a rule on
             * another clock leaves them alone. */
            wants_wall = wants_wall || selector->clock_id == CLOCK_REALTIME;
            continue;
        }
        if (selector->kind == CHAOS_TIME_SELECTOR_ANY ||
            selector->operation == CHAOS_TIME_OP_CLOCK_GETTIME)
        {
            wants_reads = 1;
            wants_wall = 1;
        }
        if (selector->kind == CHAOS_TIME_SELECTOR_ANY ||
            selector->operation == CHAOS_TIME_OP_NANOSLEEP)
        {
            wants_sleeps = 1;
        }
    }
    for (index = 0U; wants_reads && index < sizeof(reads) / sizeof(reads[0]); ++index)
    {
        if (index > 0U && !wants_wall)
        {
            break;
        }
        if (count == capacity)
        {
            return count;
        }
        out[count++] = reads[index];
    }
    for (index = 0U; wants_sleeps && index < sizeof(sleeps) / sizeof(sleeps[0]); ++index)
    {
        if (count == capacity)
        {
            return count;
        }
        out[count++] = sleeps[index];
    }
    return count;
}

size_t chaos_init_time_clocks(long *out, size_t capacity)
{
    const chaos_time_config_state_t *state;
    size_t count = 0U;
    size_t index;

    if (out == NULL || !chaos_time_config_prepare())
    {
        return 0U;
    }
    state = chaos_time_config_active_state();
    for (index = 0U; index < state->rule_count; ++index)
    {
        const chaos_time_selector_t *selector = &state->rules[index].selector;
        size_t seen;

        if (selector->kind != CHAOS_TIME_SELECTOR_CLOCK_ID)
        {
            /* A rule that names no clock applies to every one of them, so there is
             * nothing left to narrow: the filter notifies them all. */
            if (selector->kind == CHAOS_TIME_SELECTOR_ANY ||
                selector->operation == CHAOS_TIME_OP_CLOCK_GETTIME)
            {
                return 0U;
            }
            continue;
        }
        for (seen = 0U; seen < count; ++seen)
        {
            if (out[seen] == (long)selector->clock_id)
            {
                break;
            }
        }
        if (seen < count)
        {
            continue;
        }
        if (count == capacity)
        {
            return count;
        }
        out[count++] = (long)selector->clock_id;
    }
    return count;
}
