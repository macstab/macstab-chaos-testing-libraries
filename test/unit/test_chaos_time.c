/**
 * @file test_chaos_time.c
 * @brief Proves the libchaos-time wrappers (clock_gettime, gettimeofday, time, timespec_get,
 *   nanosleep, clock_nanosleep, sleep, usleep): which rules each consults, in which order,
 *   what each returns when an effect fires, and the raw-syscall fallback of the real-function
 *   helpers.
 *
 * @details Unit under test: `src/time/chaos_time_hooks.c`, included directly so the wrappers
 * replace the libc symbols inside this binary and the `static` helpers are callable.
 *
 * Isolation seams:
 * - `CHAOS_TIME_DEFINE_TEST_GLOBALS()` defines the real-function pointers (NULL) and an empty
 *   `chaos_time_ensure_symbols()`, so no wrapper ever calls `dlsym`. Each case installs the
 *   recording stand-ins it needs; the stand-in clock reads {10 s, 250 ms}, gettimeofday,
 *   time and timespec_get read 77 s, so the source of a returned value is identifiable.
 * - `chaos_time_config_match()` is replaced by a table lookup:
 *   `g_stub_match[effect][operation]` decides whether a rule matches and `g_stub_rules`
 *   supplies it. The clock id is ignored. No rule file is read.
 * - The effect actions are replaced: LATENCY and REGRESS only count calls, ERRNO fires only
 *   while `g_errno_trigger` is set (otherwise the rule "matched but did not fire"), OFFSET
 *   adds whole and sub-second milliseconds with a forward carry only, and the deadline
 *   conversion subtracts the OFFSET rule's whole seconds. Their real arithmetic is covered
 *   by test_time_actions.c.
 * - The thread guard is set directly to prove the internal-call bypass.
 *
 * The last test leaves every pointer NULL and makes real system calls: it reads the wall
 * clock and sleeps about 20 ms per sleeping call, plus one sleep cut short by SIGALRM after
 * 50 ms.
 *
 * Out of scope: constructor and symbol resolution (test_time_runtime.c), rule parsing and
 * matching (test_time_config.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

#include <signal.h>
#include <sys/syscall.h>
#include <sys/time.h>

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/**
 * @brief Rule returned by the match stub, indexed `[effect][operation]` by enum value; one
 *   row per effect up to REGRESS, one column per time operation.
 */
static chaos_time_rule_t g_stub_rules[CHAOS_TIME_EFFECT_REGRESS + 1][3];
/** @brief Non-zero makes the match stub report the rule in the same cell of `g_stub_rules`. */
static int g_stub_match[CHAOS_TIME_EFFECT_REGRESS + 1][3];
/** @brief Calls to the LATENCY action stub. */
static int g_latency_calls = 0;
/** @brief Non-zero lets a matched ERRNO rule fire; zero models a probability miss. */
static int g_errno_trigger = 0;
/** @brief Calls to the OFFSET action stub. */
static int g_offset_calls = 0;

/** @brief Calls to the REGRESS action stub. */
static int g_regress_calls = 0;
/** @brief Calls to the real-`clock_gettime` stand-in. */
static int g_real_clock_gettime_calls = 0;
/** @brief Non-zero makes the real-`clock_gettime` stand-in fail with this errno. */
static int g_real_clock_gettime_error = 0;
/** @brief Calls to the real-`nanosleep` stand-in. */
static int g_real_nanosleep_calls = 0;
/**
 * @brief Non-zero makes the real-`nanosleep` stand-in fail with this errno, reporting 500 ms
 *   remaining, and the real-`clock_nanosleep` stand-in return it as its result.
 */
static int g_real_nanosleep_error = 0;
/** @brief Calls to the real-`usleep` stand-in. */
static int g_real_usleep_calls = 0;
/** @brief Non-zero makes the real-`usleep` stand-in fail with this errno. */
static int g_real_usleep_error = 0;
/** @brief Clock id of the latest real-`clock_gettime` call; proves which clock a wrapper reads. */
static clockid_t g_last_clock_id = (clockid_t)0;
/** @brief Request of the latest real-`nanosleep` call ({0, 0} for a NULL request). */
static struct timespec g_last_sleep_request;
/** @brief Argument of the latest real-`usleep` call. */
static useconds_t g_last_usleep = 0U;
/** @brief Calls to the real-`gettimeofday` stand-in. */
static int g_real_gettimeofday_calls = 0;
/** @brief Calls to the real-`time` stand-in. */
static int g_real_time_calls = 0;
/** @brief Calls to the real-`clock_nanosleep` stand-in. */
static int g_real_clock_nanosleep_calls = 0;
/** @brief Non-zero makes the real-`gettimeofday` stand-in fail with this errno. */
static int g_real_gettimeofday_error = 0;

/**
 * @brief Unresolves every real function, clears the guard, empties the rule table and zeroes
 *   the stub counters and switches, so each scenario sees only the rules it sets.
 *
 * @details `g_real_sleep_calls`, `g_real_timespec_get_calls` and `g_unshift_calls` are
 * defined later in the file and are not cleared here; the tests that read them reset them.
 */
static void reset_wrapper_state(void)
{
    size_t effect_index;
    size_t operation_index;

    chaos_time_test_reset_runtime();
    /* Clear every effect row up to REGRESS; a match left set leaks into later scenarios. */
    for (effect_index = 0U; effect_index <= (size_t)CHAOS_TIME_EFFECT_REGRESS; ++effect_index)
    {
        for (operation_index = 0U; operation_index < 3U; ++operation_index)
        {
            (void)memset(
                &g_stub_rules[effect_index][operation_index],
                0,
                sizeof(g_stub_rules[effect_index][operation_index])
            );
            g_stub_match[effect_index][operation_index] = 0;
        }
    }
    g_latency_calls = 0;
    g_errno_trigger = 0;
    g_offset_calls = 0;
    g_regress_calls = 0;
    g_real_clock_gettime_calls = 0;
    g_real_clock_gettime_error = 0;
    g_real_nanosleep_calls = 0;
    g_real_nanosleep_error = 0;
    g_real_usleep_calls = 0;
    g_real_usleep_error = 0;
    g_real_gettimeofday_calls = 0;
    g_real_time_calls = 0;
    g_real_clock_nanosleep_calls = 0;
    g_real_gettimeofday_error = 0;
    g_last_clock_id = (clockid_t)0;
    g_last_sleep_request.tv_sec = 0;
    g_last_sleep_request.tv_nsec = 0L;
    g_last_usleep = 0U;
}

/**
 * @brief Rule-lookup seam: returns 1 and copies `g_stub_rules[effect][operation]` when that
 *   cell is enabled; out-of-range indexes and a NULL @p rule return 0.
 *
 * @details @p clock_id is ignored, so a clock-gettime rule applies to every clock; tests
 * check the clock a wrapper reads through `g_last_clock_id` instead.
 */
int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
)
{
    (void)clock_id;
    if (effect < 0 || effect > CHAOS_TIME_EFFECT_REGRESS || operation < 0 ||
        operation > CHAOS_TIME_OP_USLEEP || rule == NULL || g_stub_match[effect][operation] == 0)
    {
        return 0;
    }

    *rule = g_stub_rules[effect][operation];
    return 1;
}

/** @brief LATENCY seam: counts the call and does not sleep. */
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief ERRNO seam: for an ERRNO rule while `g_errno_trigger` is set, stores `errnum` in
 *   errno and returns 1; otherwise returns 0 and leaves errno alone.
 */
int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }
    errno = rule->errnum;
    return 1;
}

/** @brief REGRESS seam: counts the call and leaves @p value unchanged. */
void chaos_time_rule_apply_regress(const chaos_time_rule_t *rule, struct timespec *value)
{
    assert(rule != NULL);
    assert(value != NULL);
    ++g_regress_calls;
}

/** @brief Calls to the deadline-conversion stub. */
static int g_unshift_calls = 0;

/**
 * @brief Deadline-conversion seam: with an OFFSET rule, moves the deadline back by the rule's
 *   whole seconds and returns 1; without one returns 0. The REGRESS rule is ignored.
 */
int chaos_time_rule_unshift_deadline(
    const chaos_time_rule_t *offset_rule,
    const chaos_time_rule_t *regress_rule,
    struct timespec *deadline
)
{
    (void)regress_rule;
    ++g_unshift_calls;
    if (offset_rule == NULL)
    {
        return 0;
    }
    deadline->tv_sec -= (time_t)(offset_rule->offset_ms / 1000);
    return 1;
}

/**
 * @brief OFFSET seam: counts the call and adds `offset_ms` to @p value with a forward carry
 *   only, which suffices for the positive offsets used here.
 */
void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value)
{
    assert(rule != NULL);
    assert(value != NULL);
    ++g_offset_calls;
    value->tv_sec += (time_t)(rule->offset_ms / 1000);
    value->tv_nsec += (long)((rule->offset_ms % 1000) * 1000000LL);
    if (value->tv_nsec >= 1000000000L)
    {
        ++value->tv_sec;
        value->tv_nsec -= 1000000000L;
    }
}

/**
 * @brief Real-`clock_gettime` stand-in: records the clock id, then fails with
 *   `g_real_clock_gettime_error` or reads {10 s, 250 ms}.
 */
static int chaos_time_test_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    ++g_real_clock_gettime_calls;
    g_last_clock_id = clock_id;
    if (g_real_clock_gettime_error != 0)
    {
        errno = g_real_clock_gettime_error;
        return -1;
    }
    assert(value != NULL);
    value->tv_sec = 10;
    value->tv_nsec = 250000000L;
    return 0;
}

/**
 * @brief Real-`nanosleep` stand-in: records the request, then fails with
 *   `g_real_nanosleep_error` and 500 ms remaining, or succeeds with nothing remaining.
 */
static int chaos_time_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_real_nanosleep_calls;
    if (request != NULL)
    {
        g_last_sleep_request = *request;
    }
    else
    {
        g_last_sleep_request.tv_sec = 0;
        g_last_sleep_request.tv_nsec = 0L;
    }
    if (g_real_nanosleep_error != 0)
    {
        errno = g_real_nanosleep_error;
        if (remaining != NULL)
        {
            remaining->tv_sec = 0;
            remaining->tv_nsec = 500000000L;
        }
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

/** @brief Real-`usleep` stand-in: records @p usec, then fails with `g_real_usleep_error`. */
static int chaos_time_test_usleep(useconds_t usec)
{
    ++g_real_usleep_calls;
    g_last_usleep = usec;
    if (g_real_usleep_error != 0)
    {
        errno = g_real_usleep_error;
        return -1;
    }
    return 0;
}

/**
 * @brief Real-`gettimeofday` stand-in: fails with `g_real_gettimeofday_error`, or reads
 *   {77 s, 5 us} and zeroes a non-NULL @p zone (two ints).
 *
 * @details 77 s differs from the clock stand-in's 10 s, so a test can tell whether the
 * wrapper's value came from this call or from the clock_gettime rules.
 */
static int chaos_time_test_gettimeofday(struct timeval *value, void *zone)
{
    ++g_real_gettimeofday_calls;
    if (g_real_gettimeofday_error != 0)
    {
        errno = g_real_gettimeofday_error;
        return -1;
    }
    value->tv_sec = 77;
    value->tv_usec = 5;
    if (zone != NULL)
    {
        (void)memset(zone, 0, sizeof(int) * 2U);
    }
    return 0;
}

/** @brief Real-`time` stand-in: returns 77 and stores it through a non-NULL @p out. */
static time_t chaos_time_test_time(time_t *out)
{
    ++g_real_time_calls;
    if (out != NULL)
    {
        *out = 77;
    }
    return 77;
}

/** @brief Request of the latest real-`clock_nanosleep` call; proves deadline conversion. */
static struct timespec g_real_clock_nanosleep_request;

/**
 * @brief Real-`clock_nanosleep` stand-in: records the request and returns
 *   `g_real_nanosleep_error` (0 for success), reporting by value as clock_nanosleep does.
 */

static int chaos_time_test_clock_nanosleep(
    clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remaining
)
{
    (void)clock_id;
    (void)flags;
    (void)remaining;
    if (request != NULL)
    {
        g_real_clock_nanosleep_request = *request;
    }
    ++g_real_clock_nanosleep_calls;
    return g_real_nanosleep_error;
}

/** @brief Calls to the real-`sleep` stand-in; not cleared by `reset_wrapper_state()`. */
static int g_real_sleep_calls = 0;
/** @brief Calls to the real-`timespec_get` stand-in; not cleared by `reset_wrapper_state()`. */
static int g_real_timespec_get_calls = 0;

/** @brief Real-`sleep` stand-in: returns 0, the result of a sleep that ran to completion. */
static unsigned int chaos_time_test_sleep(unsigned int seconds)
{
    (void)seconds;
    ++g_real_sleep_calls;
    return 0U;
}

/** @brief Real-`timespec_get` stand-in: reads {77 s, 5 ns} and returns @p base. */
static int chaos_time_test_timespec_get(struct timespec *value, int base)
{
    ++g_real_timespec_get_calls;
    if (value != NULL)
    {
        value->tv_sec = 77;
        value->tv_nsec = 5L;
    }
    return base;
}

#include "../../src/time/chaos_time_hooks.c"

/**
 * @brief Volatile pointer type for calling timespec_get with NULL: libc declares the argument
 *   nonnull, so a direct call with NULL would let the compiler drop the wrapper's check.
 */
typedef int (*volatile timespec_get_fn_t)(struct timespec *, int);

/**
 * @brief Proves the real-function helpers call the resolved pointer once with the caller's
 *   arguments, and that `chaos_time_copy_remaining()` copies the request and tolerates NULL
 *   on either side.
 *
 * @details The copy helper fills `remaining` when an injected EINTR pretends the whole
 * request was interrupted; a NULL `remaining` is legal for nanosleep callers.
 */
static void test_call_real_helpers(void)
{
    struct timespec request;
    struct timespec remaining;
    struct timespec value;

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_chaos_time_real_usleep = chaos_time_test_usleep;

    assert(chaos_time_call_real_clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_real_clock_gettime_calls == 1);
    assert(g_last_clock_id == CLOCK_MONOTONIC);

    request.tv_sec = 1;
    request.tv_nsec = 0L;
    assert(chaos_time_call_real_nanosleep(&request, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    assert(chaos_time_call_real_usleep(1234U) == 0);
    assert(g_real_usleep_calls == 1);
    assert(g_last_usleep == 1234U);

    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    chaos_time_copy_remaining(&request, &remaining);
    assert(remaining.tv_sec == 1);
    assert(remaining.tv_nsec == 0L);

    remaining.tv_sec = 9;
    remaining.tv_nsec = 1L;
    chaos_time_copy_remaining(NULL, &remaining);
    assert(remaining.tv_sec == 9);
    assert(remaining.tv_nsec == 1L);
    chaos_time_copy_remaining(&request, NULL);
}

/**
 * @brief Proves the clock_gettime wrapper: the guard bypasses all rules, LATENCY delays and
 *   then reads, ERRNO fails with -1 without reading, OFFSET shifts a successful read, and a
 *   failed real read is returned unshifted.
 *
 * @details OFFSET +1500 ms on {10 s, 250 ms} yields {11 s, 750 ms}. With the real call failing
 * EFAULT the wrapper must return -1/EFAULT without applying OFFSET, because the buffer
 * contents are undefined after a failed read.
 */
static void test_clock_gettime_paths(void)
{
    struct timespec value;

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_tls_guard = 1;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_real_clock_gettime_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_clock_gettime_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EINVAL;
    g_errno_trigger = 1;
    errno = 0;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == -1);
    assert(errno == EINVAL);
    assert(g_real_clock_gettime_calls == 0);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 1500;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_offset_calls == 1);
    assert(value.tv_sec == 11);
    assert(value.tv_nsec == 750000000L);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_real_clock_gettime_error = EFAULT;
    errno = 0;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == -1);
    assert(errno == EFAULT);
    assert(g_offset_calls == 0);
}

/**
 * @brief Proves the nanosleep wrapper: the guard and a NULL request go straight to the real
 *   call, LATENCY delays and then sleeps, and an injected EINTR returns -1 without sleeping
 *   and reports the whole request as remaining.
 *
 * @details A NULL request is passed through so the real call reports its own error (EFAULT)
 * rather than the wrapper dereferencing it. Filling `remaining` makes the injected EINTR
 * look like a signal at time zero, so a retry loop in the caller sleeps the full time.
 */
static void test_nanosleep_paths(void)
{
    struct timespec request;
    struct timespec remaining;

    request.tv_sec = 2;
    request.tv_nsec = 300000000L;

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_chaos_time_tls_guard = 1;
    assert(nanosleep(&request, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    assert(nanosleep(NULL, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(nanosleep(&request, &remaining) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    errno = 0;
    assert(nanosleep(&request, &remaining) == -1);
    assert(errno == EINTR);
    assert(remaining.tv_sec == request.tv_sec);
    assert(remaining.tv_nsec == request.tv_nsec);
    assert(g_real_nanosleep_calls == 0);
}

/**
 * @brief Proves the usleep wrapper, which has its own rule operation: the guard bypasses the
 *   rules, LATENCY delays and then sleeps, and ERRNO returns -1 with the rule's errno
 *   (EINTR) without sleeping.
 */
static void test_usleep_paths(void)
{
    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_chaos_time_tls_guard = 1;
    assert(usleep(1234U) == 0);
    assert(g_real_usleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_USLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_USLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(usleep(1234U) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_usleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(usleep(1234U) == -1);
    assert(errno == EINTR);
    assert(g_real_usleep_calls == 0);
}

/**
 * @brief Proves gettimeofday derives its value from a CLOCK_REALTIME read through the
 *   clock_gettime rules, so one rule set skews every wall-clock API consistently.
 *
 * @details Cases:
 * - Guard set: the real gettimeofday runs (77 s). NULL value: passed to the real call, whose
 *   EFAULT is returned.
 * - OFFSET +1500 ms: {11 s, 750000 us} from the shifted clock read of CLOCK_REALTIME; the real
 *   gettimeofday does not run.
 * - Non-NULL timezone: the real gettimeofday runs only to fill it (zeroed), while the value
 *   still comes from the rules; if that call fails EFAULT, the wrapper returns -1/EFAULT.
 * - ERRNO on the clock read: -1/EINVAL, no clock read.
 */
static void test_gettimeofday_paths(void)
{
    struct timeval value;
    /* Called through a volatile pointer: libc declares the value nonnull, so a direct call
     * with NULL would let the compiler drop the wrapper's NULL check under test. */
    chaos_time_gettimeofday_fn volatile call_gettimeofday = gettimeofday;
    int zone[2] = {7, 7};

    reset_wrapper_state();
    g_chaos_time_real_gettimeofday = chaos_time_test_gettimeofday;
    g_chaos_time_tls_guard = 1;
    assert(gettimeofday(&value, NULL) == 0);
    assert(value.tv_sec == 77);
    assert(g_real_gettimeofday_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_gettimeofday = chaos_time_test_gettimeofday;
    g_real_gettimeofday_error = EFAULT;
    errno = 0;
    assert(call_gettimeofday(NULL, NULL) == -1);
    assert(errno == EFAULT);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_real_gettimeofday = chaos_time_test_gettimeofday;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 1500;
    assert(gettimeofday(&value, NULL) == 0);
    assert(value.tv_sec == 11);
    assert(value.tv_usec == 750000);
    assert(g_last_clock_id == CLOCK_REALTIME);
    assert(g_real_gettimeofday_calls == 0);

    assert(gettimeofday(&value, zone) == 0);
    assert(value.tv_sec == 11);
    assert(zone[0] == 0 && zone[1] == 0);
    assert(g_real_gettimeofday_calls == 1);

    g_real_gettimeofday_error = EFAULT;
    errno = 0;
    assert(gettimeofday(&value, zone) == -1);
    assert(errno == EFAULT);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EINVAL;
    g_errno_trigger = 1;
    errno = 0;
    assert(gettimeofday(&value, NULL) == -1);
    assert(errno == EINVAL);
    assert(g_real_clock_gettime_calls == 0);
}

/**
 * @brief Proves time() derives its result from a CLOCK_REALTIME read through the
 *   clock_gettime rules.
 *
 * @details Guard set: the real time runs (77). OFFSET +1500 ms on {10 s, 250 ms}: returns
 * 11, stores it through a non-NULL pointer and accepts NULL; the real time does not run.
 * ERRNO (EOVERFLOW): returns (time_t)-1 with errno set and leaves `*out` unwritten.
 */
static void test_time_paths(void)
{
    time_t out = 0;

    reset_wrapper_state();
    g_chaos_time_real_time = chaos_time_test_time;
    g_chaos_time_tls_guard = 1;
    assert(time(&out) == 77);
    assert(out == 77);
    assert(g_real_time_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 1500;
    assert(time(&out) == 11);
    assert(out == 11);
    assert(time(NULL) == 11);
    assert(g_last_clock_id == CLOCK_REALTIME);
    assert(g_real_time_calls == 0);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EOVERFLOW;
    g_errno_trigger = 1;
    errno = 0;
    out = 5;
    assert(time(&out) == (time_t)-1);
    assert(errno == EOVERFLOW);
    assert(out == 5);
}

/**
 * @brief Proves clock_nanosleep follows the nanosleep rules, returns an injected error by
 *   value without touching errno, and converts an absolute deadline back to real time.
 *
 * @details Cases:
 * - Guard set, or a NULL request: the real call runs; the latter's EFAULT is returned.
 * - LATENCY: delays, then the real call runs.
 * - ERRNO EINTR, relative: returns EINTR, errno keeps its sentinel, remaining = request.
 * - ERRNO EINTR with TIMER_ABSTIME: remaining is not written; POSIX does not use it for
 *   absolute sleeps.
 * - ERRNO EINVAL: returns EINVAL, remaining is not written, the real call never runs.
 * - TIMER_ABSTIME with an OFFSET +2000 ms clock rule: the real call waits on the deadline
 *   2 s earlier. A relative sleep is not converted. Without a clock rule the conversion is
 *   still asked and returns 0, so the original deadline is used.
 */
static void test_clock_nanosleep_paths(void)
{
    struct timespec request;
    struct timespec remaining;

    request.tv_sec = 2;
    request.tv_nsec = 300000000L;

    reset_wrapper_state();
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_chaos_time_tls_guard = 1;
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == 0);
    assert(g_real_clock_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_real_nanosleep_error = EFAULT;
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, NULL, &remaining) == EFAULT);
    assert(g_real_clock_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_clock_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    errno = 4242;
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == EINTR);
    assert(errno == 4242);
    assert(remaining.tv_sec == request.tv_sec);
    assert(remaining.tv_nsec == request.tv_nsec);

    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    assert(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &request, &remaining) == EINTR);
    assert(remaining.tv_sec == 0);

    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINVAL;
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == EINVAL);
    assert(remaining.tv_sec == 0);
    assert(g_real_clock_nanosleep_calls == 0);

    /* The program computed the deadline from a shifted clock; the kernel waits on the real
     * clock, so the deadline must be converted back. A relative duration has no epoch. */
    reset_wrapper_state();
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_unshift_calls = 0;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 2000;
    assert(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &request, NULL) == 0);
    assert(g_unshift_calls == 1);
    assert(g_real_clock_nanosleep_request.tv_sec == request.tv_sec - 2);
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL) == 0);
    assert(g_unshift_calls == 1);
    assert(g_real_clock_nanosleep_request.tv_sec == request.tv_sec);
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 0;
    assert(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &request, NULL) == 0);
    assert(g_unshift_calls == 2);
    assert(g_real_clock_nanosleep_request.tv_sec == request.tv_sec);
}

/**
 * @brief Proves sleep follows the nanosleep rules and timespec_get(TIME_UTC) follows the
 *   clock_gettime rules on CLOCK_REALTIME.
 *
 * @details sleep has no errno-reporting contract beyond its return value:
 * - Under the guard or without a rule the real sleep runs; LATENCY delays and then sleeps.
 * - ERRNO returns all 3 seconds as unslept, sets errno (EINTR) and does not sleep.
 *
 * timespec_get:
 * - The guard, a NULL value and a base other than TIME_UTC go to the real call.
 * - OFFSET +1500 ms yields {11 s, 750 ms} and returns TIME_UTC; the real call does not run.
 * - ERRNO returns 0, timespec_get's only failure indication.
 */
static void test_sleep_and_timespec_get_paths(void)
{
    timespec_get_fn_t call_timespec_get = timespec_get;
    struct timespec value;

    reset_wrapper_state();
    g_real_sleep_calls = 0;
    g_chaos_time_real_sleep = chaos_time_test_sleep;
    g_chaos_time_tls_guard = 1;
    assert(sleep(3U) == 0U);
    g_chaos_time_tls_guard = 0;
    assert(sleep(3U) == 0U);
    assert(g_real_sleep_calls == 2);

    reset_wrapper_state();
    g_real_sleep_calls = 0;
    g_chaos_time_real_sleep = chaos_time_test_sleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(sleep(3U) == 0U);
    assert(g_latency_calls == 1);
    assert(g_real_sleep_calls == 1);

    reset_wrapper_state();
    g_real_sleep_calls = 0;
    g_chaos_time_real_sleep = chaos_time_test_sleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(sleep(3U) == 3U);
    assert(errno == EINTR);
    assert(g_real_sleep_calls == 0);

    reset_wrapper_state();
    g_real_timespec_get_calls = 0;
    g_chaos_time_real_timespec_get = chaos_time_test_timespec_get;
    g_chaos_time_tls_guard = 1;
    assert(timespec_get(&value, TIME_UTC) == TIME_UTC);
    g_chaos_time_tls_guard = 0;
    assert(call_timespec_get(NULL, TIME_UTC) == TIME_UTC);
    assert(timespec_get(&value, TIME_UTC + 1) == TIME_UTC + 1);
    assert(g_real_timespec_get_calls == 3);

    reset_wrapper_state();
    g_real_timespec_get_calls = 0;
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_real_timespec_get = chaos_time_test_timespec_get;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 1500;
    assert(timespec_get(&value, TIME_UTC) == TIME_UTC);
    assert(value.tv_sec == 11);
    assert(value.tv_nsec == 750000000L);
    assert(g_last_clock_id == CLOCK_REALTIME);
    assert(g_real_timespec_get_calls == 0);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EINVAL;
    g_errno_trigger = 1;
    assert(timespec_get(&value, TIME_UTC) == 0);
}

/** @brief Proves a successful clock read passes a matching REGRESS rule to its action. */
static void test_clock_read_applies_regress(void)
{
    struct timespec value;

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_REGRESS][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_REGRESS][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_REGRESS;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_regress_calls == 1);
}

/**
 * @brief Proves a matched rule that does not fire changes nothing, an injected error other
 *   than EINTR leaves `remaining` alone, and an absolute deadline with only a REGRESS rule is
 *   offered for conversion.
 *
 * @details With `g_errno_trigger` clear, ERRNO rules on all three operations match but do not
 * fire: clock_gettime, nanosleep, sleep, clock_nanosleep and usleep each succeed through one
 * real call. With the trigger set, nanosleep fails EINVAL without sleeping and leaves the
 * sentinel in `remaining`: only an interruption reports time left. The REGRESS-only deadline
 * reaches the real call unchanged because the conversion stub converts only OFFSET; the real
 * conversion depends on whether the clock has jumped (test_time_actions.c).
 */
static void test_rules_that_do_not_fire(void)
{
    struct timespec value;
    struct timespec request;
    struct timespec remaining;

    request.tv_sec = 2;
    request.tv_nsec = 300000000L;

    reset_wrapper_state();
    g_real_sleep_calls = 0;
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_chaos_time_real_sleep = chaos_time_test_sleep;
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EINVAL;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINVAL;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].errnum = EINVAL;

    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(value.tv_sec == 10);
    assert(nanosleep(&request, &remaining) == 0);
    assert(sleep(3U) == 0U);
    assert(clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) == 0);
    assert(usleep(1234U) == 0);
    assert(g_real_clock_gettime_calls == 1);
    assert(g_real_nanosleep_calls == 1);
    assert(g_real_sleep_calls == 1);
    assert(g_real_clock_nanosleep_calls == 1);
    assert(g_real_usleep_calls == 1);

    /* Only EINTR reports time left; EINVAL must leave the caller's buffer alone. */
    g_errno_trigger = 1;
    remaining.tv_sec = 9;
    remaining.tv_nsec = 9L;
    errno = 0;
    assert(nanosleep(&request, &remaining) == -1);
    assert(errno == EINVAL);
    assert(remaining.tv_sec == 9 && remaining.tv_nsec == 9L);
    assert(g_real_nanosleep_calls == 1);

    /* REGRESS alone still asks for conversion; the stub returns 0, so the deadline is
     * unchanged. */
    reset_wrapper_state();
    g_unshift_calls = 0;
    g_chaos_time_real_clock_nanosleep = chaos_time_test_clock_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_REGRESS][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_REGRESS][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_REGRESS;
    assert(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &request, NULL) == 0);
    assert(g_unshift_calls == 1);
    assert(g_real_clock_nanosleep_calls == 1);
    assert(g_real_clock_nanosleep_request.tv_sec == request.tv_sec);
}

/**
 * @brief Empty SIGALRM handler: the default action would kill the process, while a caught
 *   signal makes the sleep return early.
 */
static void chaos_time_test_on_alarm(int signal_number)
{
    (void)signal_number;
}

/**
 * @brief Monotonic time in ms via the raw syscall, which bypasses the clock_gettime wrapper
 *   compiled into this binary.
 */
static long long chaos_time_test_now_ms(void)
{
    struct timespec now;

    assert(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) == 0);
    return (long long)now.tv_sec * 1000LL + (long long)(now.tv_nsec / 1000000L);
}

/**
 * @brief Proves that with every real pointer NULL, as for a call arriving while the symbols
 *   resolve, each real-function helper makes the raw system call instead of calling NULL,
 *   and keeps the libc function's result contract.
 *
 * @details Uses the real kernel:
 * - clock_gettime, gettimeofday, time and timespec_get(TIME_UTC) read the wall clock within
 *   5 s of a raw CLOCK_REALTIME read; time also fills a non-NULL `out`; timespec_get with
 *   another base returns 0.
 * - nanosleep, usleep and clock_nanosleep of 20 ms each take at least 15 ms, so they really
 *   slept; sleep(0) returns 0.
 * - clock_nanosleep on clock -1 returns EINVAL by value and leaves errno at its sentinel.
 * - sleep(2) interrupted by SIGALRM after 50 ms returns 2: the seconds left (about 1.95)
 *   rounded up, as sleep(3) specifies. It must take 40 ms to 1900 ms, proving the signal,
 *   not the timeout, ended it.
 */
static void test_call_real_helpers_without_pointers(void)
{
    struct sigaction action;
    struct sigaction previous_action;
    struct itimerval timer;
    struct timespec kernel_now;
    struct timespec value;
    struct timespec request;
    struct timeval wall;
    time_t out = 0;
    long long started;

    reset_wrapper_state();
    assert(syscall(SYS_clock_gettime, CLOCK_REALTIME, &kernel_now) == 0);

    value.tv_sec = 0;
    assert(chaos_time_call_real_clock_gettime(CLOCK_REALTIME, &value) == 0);
    assert(value.tv_sec >= kernel_now.tv_sec && value.tv_sec <= kernel_now.tv_sec + 5);
    wall.tv_sec = 0;
    assert(chaos_time_call_real_gettimeofday(&wall, NULL) == 0);
    assert(wall.tv_sec >= kernel_now.tv_sec && wall.tv_sec <= kernel_now.tv_sec + 5);
    assert(chaos_time_call_real_time(&out) >= kernel_now.tv_sec);
    assert(out >= kernel_now.tv_sec && out <= kernel_now.tv_sec + 5);
    assert(chaos_time_call_real_time(NULL) <= kernel_now.tv_sec + 5);
    value.tv_sec = 0;
    assert(chaos_time_call_real_timespec_get(&value, TIME_UTC) == TIME_UTC);
    assert(value.tv_sec >= kernel_now.tv_sec && value.tv_sec <= kernel_now.tv_sec + 5);
    assert(chaos_time_call_real_timespec_get(&value, TIME_UTC + 1) == 0);

    request.tv_sec = 0;
    request.tv_nsec = 20000000L;
    started = chaos_time_test_now_ms();
    assert(chaos_time_call_real_nanosleep(&request, NULL) == 0);
    assert(chaos_time_test_now_ms() - started >= 15LL);
    started = chaos_time_test_now_ms();
    assert(chaos_time_call_real_usleep(20000U) == 0);
    assert(chaos_time_test_now_ms() - started >= 15LL);
    started = chaos_time_test_now_ms();
    assert(chaos_time_call_real_clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL) == 0);
    assert(chaos_time_test_now_ms() - started >= 15LL);
    errno = 4242;
    assert(chaos_time_call_real_clock_nanosleep((clockid_t)-1, 0, &request, NULL) == EINVAL);
    assert(errno == 4242);
    assert(chaos_time_call_real_sleep(0U) == 0U);

    /* One-shot 50 ms ITIMER_REAL; the previous SIGALRM disposition is restored afterwards. */
    (void)memset(&action, 0, sizeof(action));
    action.sa_handler = chaos_time_test_on_alarm;
    (void)sigemptyset(&action.sa_mask);
    assert(sigaction(SIGALRM, &action, &previous_action) == 0);
    (void)memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = 50000;
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    started = chaos_time_test_now_ms();
    assert(chaos_time_call_real_sleep(2U) == 2U);
    assert(chaos_time_test_now_ms() - started >= 40LL);
    assert(chaos_time_test_now_ms() - started < 1900LL);
    assert(sigaction(SIGALRM, &previous_action, NULL) == 0);
}

int main(void)
{
    test_clock_read_applies_regress();
    test_call_real_helpers();
    test_clock_gettime_paths();
    test_nanosleep_paths();
    test_usleep_paths();
    test_gettimeofday_paths();
    test_time_paths();
    test_clock_nanosleep_paths();
    test_sleep_and_timespec_get_paths();
    test_rules_that_do_not_fire();
    test_call_real_helpers_without_pointers();
    return 0;
}
