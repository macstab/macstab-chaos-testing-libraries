/**
 * @file test_time_actions.c
 * @brief Unit tests for TIME-domain probability, latency, errno, and time-offset helpers.
 *
 * Subsystem under test: `src/time/chaos_time_actions.c`
 *
 * Coverage approach:
 * - The production source file is included directly after providing local stubs for `usleep`
 *   and `nanosleep`. The usleep stub records chunk durations; the nanosleep stub can simulate
 *   a configurable number of EINTR interrupts before succeeding.
 * - The `CHAOS_TIME_DEFINE_TEST_GLOBALS()` macro instantiates the real-function-pointer globals
 *   required by the production action helpers.
 *
 * Properties under test:
 * - Probability boundary values: 0.0 always false, 1.0 always true, midpoint determinism.
 * - `chaos_time_rule_should_trigger(NULL)` returns false.
 * - Latency decomposition: 2500 ms → three usleep intervals (1s + 1s + 0.5s).
 * - Sub-second latency (1 ms) → nanosleep called with tv_nsec=1000000; no usleep calls.
 * - EINTR retry: 1 ms with `g_nanosleep_eintr_count=1` → nanosleep called twice.
 * - probability=0.0 for latency → no sleep calls issued.
 * - errno injection: EINVAL at probability=1.0 sets errno; NULL rule returns false.
 * - Offset application: positive 1500ms advances {10s, 250ms} to {11s, 750ms}.
 * - Offset application: negative -1500ms retreats {2s, 100ms} to {0s, 600ms}.
 * - Offset clamps to zero: -500ms applied to {0s, 100ms} yields {0s, 0ns}.
 * - `chaos_time_add_offset_ms`: zero delta is a no-op; NULL pointer is a no-op.
 * - `chaos_time_add_offset_ms` with carry: {1s, 900ms} + 200ms → {2s, 100ms}.
 * - NULL rule or NULL value pointer to `apply_offset` is a no-op (no crash, no modification).
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection.
 * - TIME wrapper call paths (tested in test_chaos_time.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/**
 * @brief Captured usleep durations from the test-local sleep stub.
 *
 * Populated in call order during latency decomposition tests.
 */
static useconds_t g_sleep_chunks[8];
/** @brief Number of usleep calls recorded since the last reset. */
static size_t g_sleep_count = 0U;
/** @brief Number of nanosleep stub calls made since the last reset. */
static int g_nanosleep_calls = 0;
/**
 * @brief Number of EINTR responses remaining before nanosleep succeeds.
 *
 * Decrements on each EINTR-simulating call. When zero, the stub returns success.
 * Tests set this before calling the action under test.
 */
static int g_nanosleep_eintr_count = 0;
/** @brief The `request` argument captured by the most recent nanosleep stub call. */
static struct timespec g_last_nanosleep_request;

/**
 * @brief Test-local usleep stub that records durations instead of sleeping.
 *
 * Asserts that the call array has not overflowed. Returns 0 always.
 *
 * @param usec  Sleep duration in microseconds, recorded at `g_sleep_chunks[g_sleep_count]`.
 * @return 0 (success, never fails).
 */
static int chaos_time_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

/**
 * @brief Test-local nanosleep stub that can simulate multiple EINTR interrupts.
 *
 * Increments `g_nanosleep_calls` and captures the request into `g_last_nanosleep_request`.
 * When `g_nanosleep_eintr_count > 0`, decrements the counter, fills @p remaining with the
 * full @p request (as a real EINTR would), and returns -1 with errno=EINTR. Otherwise
 * zeros @p remaining and returns 0 (success).
 *
 * @param request    Requested sleep duration; must be non-NULL.
 * @param remaining  Output for time remaining on EINTR; may be NULL.
 * @return 0 on success, -1 with errno=EINTR on simulated interrupt.
 */
static int chaos_time_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    assert(request != NULL);
    g_last_nanosleep_request = *request;
    if (g_nanosleep_eintr_count > 0)
    {
        --g_nanosleep_eintr_count;
        if (remaining != NULL)
        {
            remaining->tv_sec = request->tv_sec;
            remaining->tv_nsec = request->tv_nsec;
        }
        errno = EINTR;
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

#include "../../src/time/chaos_time_actions.c"

/**
 * @brief Reset all action-layer test state between test functions.
 *
 * Calls `chaos_time_test_reset_runtime()` to clear runtime globals, then zeroes all
 * local sleep-tracking counters, EINTR flags, and the captured nanosleep request.
 */
static void reset_action_state(void)
{
    size_t index;

    chaos_time_test_reset_runtime();
    g_sleep_count = 0U;
    g_nanosleep_calls = 0;
    g_nanosleep_eintr_count = 0;
    g_last_nanosleep_request.tv_sec = 0;
    g_last_nanosleep_request.tv_nsec = 0L;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

/**
 * @brief Invariant: probability sampling produces correct 0/1 decisions at boundary and midpoint.
 *
 * Triggering condition: `chaos_time_probability_hit_sample(p, sample)` with boundary and
 *   mid-range values, and `chaos_time_rule_should_trigger(NULL)`.
 *
 * Expected observable behaviour:
 * - p=0.0, any sample → 0.
 * - p=1.0, sample=MAX → 1.
 * - p=0.5, sample=0 → 1; p=0.5, sample=MAX → 0.
 * - `should_trigger(NULL)` → false.
 */
static void test_probability_helpers(void)
{
    assert(!chaos_time_probability_hit_sample(0.0, 0U));
    assert(chaos_time_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_time_probability_hit_sample(0.5, 0U));
    assert(!chaos_time_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_time_rule_should_trigger(NULL));
}

/**
 * @brief Invariant: latency decomposition, sub-second nanosleep path, and EINTR retry.
 *
 * Triggering conditions:
 * - `chaos_time_rule_apply_latency(&rule)` with latency_ms=2500 and the usleep stub.
 * - `chaos_time_rule_apply_latency(&rule)` with latency_ms=1 and the nanosleep stub.
 * - Same 1 ms call with `g_nanosleep_eintr_count=1` set before the call.
 * - `chaos_time_rule_apply_latency(&rule)` with probability=0.0 and latency_ms=100.
 *
 * Expected observable behaviour:
 * - 2500 ms → `g_sleep_count == 3`: chunks 1 000 000 + 1 000 000 + 500 000 µs.
 * - 1 ms → `g_sleep_count == 0`, `g_nanosleep_calls == 1`,
 *   `g_last_nanosleep_request.tv_nsec == 1000000`.
 * - 1 ms with one EINTR → `g_nanosleep_calls == 2`.
 * - probability=0.0 → both counters remain 0.
 */
static void test_latency_helper(void)
{
    chaos_time_rule_t rule;

    reset_action_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 3U);
    assert(g_sleep_chunks[0] == 1000000U);
    assert(g_sleep_chunks[1] == 1000000U);
    assert(g_sleep_chunks[2] == 500000U);

    reset_action_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
    assert(g_nanosleep_calls == 1);
    assert(g_last_nanosleep_request.tv_sec == 0);
    assert(g_last_nanosleep_request.tv_nsec == 1000000L);

    reset_action_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_nanosleep_eintr_count = 1;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_LATENCY;
    rule.probability = 0.0;
    rule.latency_ms = 100U;
    chaos_time_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
}

/**
 * @brief Invariant: errno injection, time offset application, and NULL guards.
 *
 * Triggering conditions:
 * - `chaos_time_rule_apply_errno(&rule)` with EINVAL at probability=1.0.
 * - `chaos_time_rule_apply_offset(&rule, &value)` with positive and negative offsets.
 * - `chaos_time_add_offset_ms()` with zero, NULL, and carry cases.
 * - NULL rule and NULL value passed to apply_offset.
 *
 * Expected observable behaviour:
 * - probability=1.0, errnum=EINVAL → returns true; errno==EINVAL.
 * - NULL rule → returns false.
 * - +1500ms on {10s, 250ms} → {11s, 750ms} (carry from ms fraction).
 * - -1500ms on {2s, 100ms} → {0s, 600ms} (borrow into seconds).
 * - -500ms on {0s, 100ms} → {0s, 0ns} (clamped at zero, not negative).
 * - `add_offset_ms(&value, 0)` → unchanged {3s, 400ms}.
 * - `add_offset_ms(NULL, 500)` → no crash, original value unchanged.
 * - `add_offset_ms({1s, 900ms}, 200)` → {2s, 100ms} (nanosecond carry).
 * - `apply_offset(NULL, &value)` → no crash; value unchanged.
 * - `apply_offset(&rule, NULL)` → no crash.
 */
static void test_errno_and_offset_helpers(void)
{
    chaos_time_rule_t rule;
    struct timespec value;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.errnum = EINVAL;
    errno = 0;
    assert(chaos_time_rule_apply_errno(&rule));
    assert(errno == EINVAL);
    assert(!chaos_time_rule_apply_errno(NULL));

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_TIME_EFFECT_OFFSET;
    rule.probability = 1.0;
    rule.offset_ms = 1500;
    value.tv_sec = 10;
    value.tv_nsec = 250000000L;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 11);
    assert(value.tv_nsec == 750000000L);

    value.tv_sec = 2;
    value.tv_nsec = 100000000L;
    rule.offset_ms = -1500;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 0);
    assert(value.tv_nsec == 600000000L);

    value.tv_sec = 0;
    value.tv_nsec = 100000000L;
    rule.offset_ms = -500;
    chaos_time_rule_apply_offset(&rule, &value);
    assert(value.tv_sec == 0);
    assert(value.tv_nsec == 0L);

    value.tv_sec = 3;
    value.tv_nsec = 400000000L;
    chaos_time_add_offset_ms(&value, 0);
    assert(value.tv_sec == 3);
    assert(value.tv_nsec == 400000000L);

    value.tv_sec = 3;
    value.tv_nsec = 400000000L;
    chaos_time_add_offset_ms(NULL, 500);
    assert(value.tv_sec == 3);
    assert(value.tv_nsec == 400000000L);

    value.tv_sec = 1;
    value.tv_nsec = 900000000L;
    chaos_time_add_offset_ms(&value, 200);
    assert(value.tv_sec == 2);
    assert(value.tv_nsec == 100000000L);

    value.tv_sec = 7;
    value.tv_nsec = 0L;
    chaos_time_rule_apply_offset(NULL, &value);
    assert(value.tv_sec == 7);
    assert(value.tv_nsec == 0L);
    chaos_time_rule_apply_offset(&rule, NULL);
}

int main(void)
{
    test_probability_helpers();
    test_latency_helper();
    test_errno_and_offset_helpers();
    return 0;
}
