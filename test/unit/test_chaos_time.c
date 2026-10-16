/**
 * @file test_chaos_time.c
 * @brief Unit tests for the TIME-domain wrapper hooks: real-function dispatch helpers,
 *   clock_gettime, nanosleep, and usleep wrapper paths.
 *
 * Subsystem under test: `src/time/chaos_time_hooks.c`.
 *
 * Coverage approach:
 * - `chaos_time_hooks.c` is included directly via `test_time_support.h`, which provides
 *   `CHAOS_TIME_DEFINE_TEST_GLOBALS()` to instantiate real-function-pointer globals and
 *   `chaos_time_test_reset_runtime()` to clear them between tests.
 * - `g_stub_rules[3][3]` and `g_stub_match[3][3]` are indexed by
 *   `[effect_index][operation_index]` where the three operations are:
 *   OP_CLOCK_GETTIME (0), OP_NANOSLEEP (1), OP_USLEEP (2); and effects are
 *   LATENCY (0), ERRNO (1), OFFSET (2).
 * - Stub implementations of `chaos_time_config_match`, `chaos_time_rule_apply_latency`,
 *   `chaos_time_rule_apply_errno`, and `chaos_time_rule_apply_offset` intercept all
 *   action and config calls.
 * - `reset_wrapper_state()` clears the runtime, stub tables, and all local counters
 *   before each test or scenario.
 *
 * Properties under test:
 * - `chaos_time_call_real_clock_gettime()`: dispatches to stub; clock_id forwarded;
 *   call count == 1.
 * - `chaos_time_call_real_nanosleep()`: dispatches to stub; request forwarded; returns 0.
 * - `chaos_time_call_real_usleep()`: dispatches to stub; usec forwarded; returns 0.
 * - `chaos_time_copy_remaining()`: copies `request` into `remaining`; NULL request is a
 *   no-op; NULL remaining is a no-op.
 * - `clock_gettime` wrapper: guard bypass; LATENCY; ERRNO (EINVAL); OFFSET (+1500ms);
 *   real-function error passthrough (EFAULT) with no offset applied.
 * - `nanosleep` wrapper: guard bypass; NULL request passthrough; LATENCY; ERRNO (EINTR)
 *   with remaining filled from request; real call skipped on ERRNO.
 * - `usleep` wrapper: guard bypass; LATENCY; ERRNO (EINTR).
 *
 * What is NOT tested here:
 * - Constructor and symbol resolution (`chaos_time_init()`).
 * - Config file parsing and rule matching.
 * - TIME action implementations (tested in test_time_actions.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/**
 * @brief Per-effect, per-operation rule table for the config-match stub.
 *
 * Index as `g_stub_rules[effect_index][operation_index]`. Tests fill the
 * desired cell and set the corresponding `g_stub_match` entry to 1.
 */
static chaos_time_rule_t g_stub_rules[CHAOS_TIME_EFFECT_REGRESS + 1][3];
/**
 * @brief Per-effect, per-operation match-enable flags.
 *
 * Non-zero means `chaos_time_config_match(effect, op, clock_id, rule)` returns 1
 * and copies the rule from `g_stub_rules[effect][op]`.
 */
static int g_stub_match[CHAOS_TIME_EFFECT_REGRESS + 1][3];
/** @brief Number of times `chaos_time_rule_apply_latency` was called. */
static int g_latency_calls = 0;
/**
 * @brief When non-zero, causes `chaos_time_rule_apply_errno` to inject the rule's
 *   `errnum` into `errno` and return 1.
 */
static int g_errno_trigger = 0;
/** @brief Number of times `chaos_time_rule_apply_offset` was called. */
static int g_offset_calls = 0;

/** @brief Number of times `chaos_time_rule_apply_regress()` was called. */
static int g_regress_calls = 0;
/** @brief Number of times `chaos_time_test_clock_gettime` was called. */
static int g_real_clock_gettime_calls = 0;
/**
 * @brief When non-zero, causes `chaos_time_test_clock_gettime` to set errno to this
 *   value and return -1 (simulates EFAULT for invalid pointer).
 */
static int g_real_clock_gettime_error = 0;
/** @brief Number of times `chaos_time_test_nanosleep` was called. */
static int g_real_nanosleep_calls = 0;
/**
 * @brief When non-zero, causes `chaos_time_test_nanosleep` to set errno and return -1,
 *   and populate `remaining` with `{0, 500000000}` (500 ms remaining).
 */
static int g_real_nanosleep_error = 0;
/** @brief Number of times `chaos_time_test_usleep` was called. */
static int g_real_usleep_calls = 0;
/**
 * @brief When non-zero, causes `chaos_time_test_usleep` to set errno and return -1.
 *
 * EINTR is the representative usleep error (interrupted by signal).
 */
static int g_real_usleep_error = 0;
/** @brief `clock_id` argument captured from the most recent `chaos_time_test_clock_gettime` call.
 */
static clockid_t g_last_clock_id = (clockid_t)0;
/** @brief `request` argument captured from the most recent `chaos_time_test_nanosleep` call. */
static struct timespec g_last_sleep_request;
/** @brief `usec` argument captured from the most recent `chaos_time_test_usleep` call. */
static useconds_t g_last_usleep = 0U;
/** @brief Number of times `chaos_time_test_gettimeofday` was called. */
static int g_real_gettimeofday_calls = 0;
/** @brief Number of times `chaos_time_test_time` was called. */
static int g_real_time_calls = 0;
/** @brief Number of times `chaos_time_test_clock_nanosleep` was called. */
static int g_real_clock_nanosleep_calls = 0;
/** @brief When non-zero, `chaos_time_test_gettimeofday` fails with this errno. */
static int g_real_gettimeofday_error = 0;

/**
 * @brief Reset all wrapper-layer test state between test functions and scenarios.
 *
 * Calls `chaos_time_test_reset_runtime()` to clear runtime globals, then zeroes all
 * stub tables and local counters.
 */
static void reset_wrapper_state(void)
{
    size_t effect_index;
    size_t operation_index;

    chaos_time_test_reset_runtime();
    /* Every effect row, REGRESS included: a match left set leaks into later tests. */
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
 * @brief Stub for `chaos_time_config_match()`.
 *
 * Returns 1 and copies the rule when `g_stub_match[effect][operation] != 0`.
 * The `clock_id` argument is ignored because the test table is indexed by
 * operation alone.
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

/**
 * @brief Stub for `chaos_time_rule_apply_latency()`.
 *
 * Increments the call counter without performing any sleep.
 */
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_time_rule_apply_errno()`.
 *
 * When `g_errno_trigger != 0` and the rule has ERRNO effect, sets `errno` to
 * `rule->errnum` and returns 1. EINTR (interrupted by signal) and EINVAL
 * (invalid argument) are the representative errors used in tests.
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

/**
 * @brief Stub for `chaos_time_rule_apply_offset()`.
 *
 * Increments the call counter and applies the rule's offset_ms to @p value
 * using the same arithmetic as the production implementation, allowing tests
 * to assert on the exact updated timestamp.
 */
void chaos_time_rule_apply_regress(const chaos_time_rule_t *rule, struct timespec *value)
{
    assert(rule != NULL);
    assert(value != NULL);
    ++g_regress_calls;
}

/** @brief Number of times `chaos_time_rule_unshift_deadline()` was called. */
static int g_unshift_calls = 0;

/**
 * @brief Stub for `chaos_time_rule_unshift_deadline()`: moves the deadline back by
 *        the OFFSET rule's offset_ms when one is given.
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
 * @brief Stub for `chaos_time_rule_apply_offset()`.
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
 * @brief Stub for the real `clock_gettime(2)`.
 *
 * Captures `clock_id`, returns -1 with `errno = g_real_clock_gettime_error` on failure,
 * or fills @p value with `{10s, 250ms}` and returns 0 on success. The deterministic
 * timestamp allows OFFSET tests to assert on the exact resulting value.
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
 * @brief Stub for the real `nanosleep(2)`.
 *
 * Captures @p request. When `g_real_nanosleep_error != 0`, fills @p remaining with
 * `{0, 500000000}` (500 ms), sets errno, and returns -1. Otherwise zeroes @p remaining
 * and returns 0.
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

/**
 * @brief Stub for the real `usleep(3)`.
 *
 * Captures @p usec. Returns -1 with `errno = g_real_usleep_error` on failure,
 * or 0 on success.
 */
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
 * @brief Stub for the real `gettimeofday(2)`.
 *
 * Fills @p value with `{77s, 5us}` and zeroes a non-NULL @p zone, so a test can
 * tell a value produced by the real call from one derived from clock_gettime.
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

/** @brief Stub for the real `time(2)`. Returns 77. */
static time_t chaos_time_test_time(time_t *out)
{
    ++g_real_time_calls;
    if (out != NULL)
    {
        *out = 77;
    }
    return 77;
}

/** @brief Stub for the real `clock_nanosleep(2)`. Returns 0 or `g_real_nanosleep_error`. */
static struct timespec g_real_clock_nanosleep_request;

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

/** @brief Number of times `chaos_time_test_sleep` was called. */
static int g_real_sleep_calls = 0;
/** @brief Number of times `chaos_time_test_timespec_get` was called. */
static int g_real_timespec_get_calls = 0;

/** @brief Stub for the real `sleep(3)`. Returns 0 (slept fully). */
static unsigned int chaos_time_test_sleep(unsigned int seconds)
{
    (void)seconds;
    ++g_real_sleep_calls;
    return 0U;
}

/** @brief Stub for the real `timespec_get(3)`. Fills {77s, 5ns}; returns @p base. */
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

/** @brief timespec_get called through a pointer: the libc declaration is nonnull. */
typedef int (*volatile timespec_get_fn_t)(struct timespec *, int);

/**
 * @brief Invariant: `chaos_time_call_real_*` helpers dispatch to the real stubs
 *   and `chaos_time_copy_remaining` copies or ignores correctly.
 *
 * Triggering condition: each `chaos_time_call_real_*` helper called once with clean
 *   state; `chaos_time_copy_remaining` called with valid, NULL request, and NULL remaining.
 *
 * Expected observable behaviour:
 * - `call_real_clock_gettime(CLOCK_MONOTONIC, &value)` → 0; `g_last_clock_id == CLOCK_MONOTONIC`;
 *   `g_real_clock_gettime_calls == 1`.
 * - `call_real_nanosleep({1s, 0ns}, &remaining)` → 0; `g_real_nanosleep_calls == 1`.
 * - `call_real_usleep(1234)` → 0; `g_last_usleep == 1234`; `g_real_usleep_calls == 1`.
 * - `copy_remaining(&request, &remaining)`: copies tv_sec and tv_nsec from request.
 * - `copy_remaining(NULL, &remaining)`: remaining unchanged; no crash.
 * - `copy_remaining(&request, NULL)`: no crash.
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
 * @brief Invariant: the `clock_gettime` wrapper applies guard bypass, LATENCY, ERRNO,
 *   OFFSET, and real-function error passthrough.
 *
 * Triggering conditions:
 * - `clock_gettime(CLOCK_MONOTONIC, &value)` with `g_chaos_time_tls_guard = 1`.
 * - `clock_gettime(CLOCK_MONOTONIC, &value)` with LATENCY rule for OP_CLOCK_GETTIME.
 * - `clock_gettime(CLOCK_MONOTONIC, &value)` with ERRNO rule (EINVAL) and `g_errno_trigger = 1`.
 * - `clock_gettime(CLOCK_MONOTONIC, &value)` with OFFSET rule (+1500ms); stub returns {10s, 250ms}.
 * - `clock_gettime(CLOCK_MONOTONIC, &value)` with `g_real_clock_gettime_error = EFAULT`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; `g_real_clock_gettime_calls == 1`.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EINVAL): returns -1; `errno == EINVAL`; real stub not called.
 * - OFFSET (+1500ms on {10s, 250ms}): `g_offset_calls == 1`; `value.tv_sec == 11`;
 *   `value.tv_nsec == 750000000` (250ms + 1500ms = 1750ms → +1s carry, 750ms remaining).
 * - Real-function error (EFAULT): returns -1; `errno == EFAULT`; `g_offset_calls == 0`
 *   (offset not applied when real call fails).
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
 * @brief Invariant: the `nanosleep` wrapper applies guard bypass, NULL request passthrough,
 *   LATENCY, and ERRNO effects.
 *
 * Triggering conditions:
 * - `nanosleep(&request, &remaining)` with `g_chaos_time_tls_guard = 1`.
 * - `nanosleep(NULL, &remaining)`: NULL request → passthrough with real call.
 * - `nanosleep(&request, &remaining)` with LATENCY rule for OP_NANOSLEEP.
 * - `nanosleep(&request, &remaining)` with ERRNO rule (EINTR) and `g_errno_trigger = 1`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; `g_real_nanosleep_calls == 1`.
 * - NULL request passthrough: returns 0; `g_real_nanosleep_calls == 1`.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EINTR): returns -1; `errno == EINTR`; `remaining` filled with request values;
 *   `g_real_nanosleep_calls == 0`.
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
 * @brief Invariant: the `usleep` wrapper applies guard bypass, LATENCY, and ERRNO effects.
 *
 * Triggering conditions:
 * - `usleep(1234)` with `g_chaos_time_tls_guard = 1`.
 * - `usleep(1234)` with LATENCY rule for OP_USLEEP.
 * - `usleep(1234)` with ERRNO rule (EINTR) and `g_errno_trigger = 1`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; `g_real_usleep_calls == 1`.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EINTR): returns -1; `errno == EINTR`; real stub not called.
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
 * @brief Invariant: gettimeofday reads CLOCK_REALTIME through the clock_gettime rules.
 *
 * Triggering conditions: guard set; NULL value; OFFSET rule (+1500ms on {10s, 250ms});
 * non-NULL timezone; ERRNO rule; real clock_gettime failing; real gettimeofday failing
 * while filling the timezone.
 *
 * Expected observable behaviour:
 * - Guard or NULL value: the real gettimeofday runs, its value is returned unchanged.
 * - OFFSET: `{11s, 750000us}` from the shifted clock_gettime; real gettimeofday not called;
 *   the clock read is CLOCK_REALTIME.
 * - Non-NULL timezone: filled by the real gettimeofday; the value still comes from the rules.
 * - ERRNO or a failing real call: -1 with the errno of the failure.
 */
static void test_gettimeofday_paths(void)
{
    struct timeval value;
    /* Called through a pointer: the libc declaration marks the value nonnull, and
     * the NULL case is exactly what this test exercises. */
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
 * @brief Invariant: time reads CLOCK_REALTIME through the clock_gettime rules.
 *
 * Expected observable behaviour:
 * - Guard set: the real time runs (77).
 * - OFFSET +1500ms on {10s, 250ms}: returns 11 and stores it through a non-NULL pointer;
 *   a NULL pointer is allowed.
 * - ERRNO: returns (time_t)-1 with errno set.
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
 * @brief Invariant: clock_nanosleep follows the nanosleep rules and reports errors by value.
 *
 * Expected observable behaviour:
 * - Guard set or NULL request: the real clock_nanosleep runs.
 * - LATENCY: applied, then the real call runs.
 * - ERRNO EINTR, relative: returns EINTR, errno untouched, remaining = request.
 * - ERRNO EINTR, TIMER_ABSTIME: returns EINTR, remaining not written.
 * - ERRNO EINVAL: returns EINVAL, remaining not written; the real call never runs.
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

    /* An absolute deadline from a shifted clock is converted back before the kernel
     * waits on the real one; a relative sleep is left alone. */
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
 * @brief Invariant: sleep follows the nanosleep rules; timespec_get(TIME_UTC) the
 *   clock_gettime/realtime rules.
 *
 * Expected observable behaviour:
 * - sleep under the guard or without a rule: the real sleep runs.
 * - sleep with LATENCY: delay applied, then the real sleep.
 * - sleep with ERRNO: returns the full request unslept, errno set, no real call.
 * - timespec_get under the guard, with a NULL value or a base other than TIME_UTC:
 *   forwarded to the real call.
 * - timespec_get(TIME_UTC) with OFFSET +1500ms on {10s, 250ms}: {11s, 750ms}, returns
 *   TIME_UTC, reads CLOCK_REALTIME; with ERRNO: returns 0.
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

/**
 * @brief Invariant: a successful clock read applies a matching REGRESS rule.
 */
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
 * @brief Invariant: an ERRNO rule that matches but does not fire leaves every wrapper
 *   to the real call; clock_gettime with no buffer skips the rules; an injected
 *   nanosleep error other than EINTR leaves `remaining` alone; an absolute
 *   clock_nanosleep with only a REGRESS rule keeps its deadline until the clock jumped.
 *
 * Expected observable behaviour:
 * - clock_gettime, nanosleep, sleep, clock_nanosleep and usleep each return the real
 *   stub's success value, and each real stub ran once.
 * - clock_gettime(CLOCK_REALTIME, NULL) with a firing ERRNO rule: the real call's
 *   EFAULT, not the rule's EINVAL.
 * - nanosleep with an injected EINVAL: -1, errno EINVAL, `remaining` untouched.
 * - TIMER_ABSTIME with a REGRESS rule only: the deadline is offered for conversion and,
 *   unchanged, reaches the real clock_nanosleep.
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

    /* An injected error other than EINTR does not report time left. */
    g_errno_trigger = 1;
    remaining.tv_sec = 9;
    remaining.tv_nsec = 9L;
    errno = 0;
    assert(nanosleep(&request, &remaining) == -1);
    assert(errno == EINVAL);
    assert(remaining.tv_sec == 9 && remaining.tv_nsec == 9L);
    assert(g_real_nanosleep_calls == 1);

    /* An absolute deadline with only a REGRESS rule: offered for conversion, and
     * unchanged (the stub converts only OFFSET) it reaches the real call. */
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
    return 0;
}
