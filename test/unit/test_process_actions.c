/**
 * @file test_process_actions.c
 * @brief Unit tests for PROCESS-domain probability, latency, errno, and fail-after helpers.
 *
 * Subsystem under test: `src/process/chaos_process_actions.c`
 *
 * Coverage approach:
 * - The production source file is included directly after overriding `usleep` and
 *   providing a stub `nanosleep` that optionally fires EINTR once. This lets tests
 *   exercise the retry loop inside the latency helper without real sleeps.
 * - The `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` macro instantiates the real-function-pointer
 *   globals required by the production action helpers.
 *
 * Properties under test:
 * - `chaos_process_rule_should_trigger(NULL)` returns false.
 * - Probability boundary values and mid-range PRNG reproducibility.
 * - Latency decomposition: 2500 ms → three usleep intervals (1s + 1s + 0.5s).
 * - Sub-millisecond latency: 5 ms uses nanosleep with EINTR retry (two calls).
 * - Probability=0 for latency: no sleep calls issued.
 * - `chaos_process_rule_error_number()`: EAGAIN injected at probability=1.0; skipped at 0.0;
 *   NULL rule and NULL errnum output both return false.
 * - FAIL_AFTER: first call with count=1 does not fire (counter decrements to 0);
 *   second call fires (counter already at 0); count=0 fires immediately.
 * - FAIL_AFTER NULL guards: NULL rule, INVALID operation, NULL errnum return false.
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection.
 * - PROCESS wrapper call paths (tested in test_chaos_process.c).
 */

#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

/** @brief Number of times the usleep stub was called. */
static int g_usleep_calls = 0;
/** @brief Microseconds value passed to the most recent usleep stub call. */
static useconds_t g_last_usleep = 0U;
/** @brief Number of times the nanosleep stub was called. */
static int g_nanosleep_calls = 0;
/**
 * @brief When non-zero, causes the nanosleep stub to return EINTR once.
 *
 * Simulates the EINTR retry path inside `chaos_process_rule_apply_latency()`.
 * The flag is cleared after the first EINTR is injected so subsequent calls
 * succeed, ensuring the retry loop terminates.
 */
static int g_force_eintr_once = 0;

/**
 * @brief Test-local usleep stub that records call count and last duration.
 *
 * @param usec  Duration in microseconds.
 * @return 0 (success).
 */
static int stub_usleep(useconds_t usec)
{
    ++g_usleep_calls;
    g_last_usleep = usec;
    return 0;
}

/**
 * @brief Test-local nanosleep stub that can simulate a single EINTR.
 *
 * When `g_force_eintr_once != 0`, clears the flag, copies @p request into @p remaining
 * (as a real EINTR would), sets errno to EINTR, and returns -1. Otherwise returns 0.
 *
 * @param request    Requested sleep duration.
 * @param remaining  Output for time remaining on EINTR; may be NULL.
 * @return 0 on success, -1 with errno=EINTR on the simulated interrupt.
 */
static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    if (g_force_eintr_once != 0)
    {
        g_force_eintr_once = 0;
        errno = EINTR;
        if (remaining != NULL && request != NULL)
        {
            *remaining = *request;
        }
        return -1;
    }
    (void)request;
    (void)remaining;
    return 0;
}

#include "../../src/process/chaos_process_actions.c"

/**
 * @brief Reset all action-layer test state between test functions.
 *
 * Calls `chaos_process_test_reset_runtime()` to clear the runtime globals, then
 * zeroes all local stub counters and flags.
 */
static void reset_action_state(void)
{
    chaos_process_test_reset_runtime();
    g_usleep_calls = 0;
    g_last_usleep = 0U;
    g_nanosleep_calls = 0;
    g_force_eintr_once = 0;
}

/**
 * @brief Invariant: probability hit returns correct 0/1 decisions at boundary and mid values.
 *
 * Triggering conditions: `chaos_process_rule_should_trigger(NULL)` and
 *   `chaos_process_probability_hit_sample()` with boundary and mid-range values,
 *   followed by `chaos_process_probability_hit()` with the same seed to verify reproducibility.
 *
 * Expected observable behaviour:
 * - NULL rule: `should_trigger` returns false.
 * - p=0.0, sample=0 → 0; p=1.0, sample=MAX → 1.
 * - p=0.5, sample=0 → 1; p=0.5, sample=MAX → 0.
 * - `probability_hit(0.0)` → 0; `probability_hit(1.0)` → 1 regardless of PRNG state.
 */
static void test_probability_helpers(void)
{
    reset_action_state();
    assert(!chaos_process_rule_should_trigger(NULL));
    assert(!chaos_process_probability_hit_sample(0.0, 0U));
    assert(chaos_process_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_process_probability_hit_sample(0.5, 0U));
    assert(!chaos_process_probability_hit_sample(0.5, 0xffffffffU));

    chaos_process_prng_seed_thread(UINT64_C(0x1234));
    assert(!chaos_process_probability_hit(0.0));
    assert(chaos_process_probability_hit(1.0));
}

/**
 * @brief Invariant: latency decomposition and EINTR retry behaviour.
 *
 * Triggering conditions:
 * - `chaos_process_rule_apply_latency()` with 2500 ms and the usleep stub.
 * - `chaos_process_rule_apply_latency()` with 5 ms and a nanosleep stub that fires EINTR once.
 * - `chaos_process_rule_apply_latency()` with probability=0.0 (no sleep issued).
 *
 * Expected observable behaviour:
 * - 2500 ms → `g_usleep_calls == 3`, `g_last_usleep == 500000`.
 * - 5 ms (sub-1s) → `g_nanosleep_calls == 2` (one EINTR + one success).
 * - probability=0.0 → both counters remain 0.
 */
static void test_latency_helper(void)
{
    chaos_process_rule_t rule;

    reset_action_state();
    g_chaos_process_real_usleep = stub_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_PROCESS_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_usleep_calls == 3);
    assert(g_last_usleep == 500000U);

    reset_action_state();
    g_chaos_process_real_nanosleep = stub_nanosleep;
    g_force_eintr_once = 1;
    rule.latency_ms = 5U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    rule.probability = 0.0;
    chaos_process_rule_apply_latency(&rule);
    assert(g_usleep_calls == 0);
    assert(g_nanosleep_calls == 0);
}

/**
 * @brief Invariant: errno injection respects probability and validates pointer arguments.
 *
 * Triggering condition: `chaos_process_rule_error_number(&rule, &errnum)` with various
 *   probability values and NULL arguments.
 *
 * Expected observable behaviour:
 * - probability=1.0, errnum=EAGAIN → returns true, `errnum == EAGAIN`.
 * - probability=0.0 → returns false, `errnum` unchanged (still 0).
 * - NULL rule → returns false.
 * - NULL errnum output → returns false.
 */
static void test_error_number_helpers(void)
{
    chaos_process_rule_t rule;
    int errnum = 0;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.errnum = EAGAIN;
    assert(chaos_process_rule_error_number(&rule, &errnum));
    assert(errnum == EAGAIN);

    errnum = 0;
    rule.probability = 0.0;
    assert(!chaos_process_rule_error_number(&rule, &errnum));
    assert(errnum == 0);
    assert(!chaos_process_rule_error_number(NULL, &errnum));
    assert(!chaos_process_rule_error_number(&rule, NULL));
}

/**
 * @brief Invariant: FAIL_AFTER decrements a per-operation counter and fires once it reaches zero.
 *
 * Triggering condition: `chaos_process_rule_fail_after_error()` called repeatedly on the
 *   same operation with `fail_after_count=1`.
 *
 * Expected observable behaviour:
 * - First call with count=1: counter decrements from 1 to 0, returns false (not yet fired).
 * - Second call: counter is 0, returns true (fires); `errnum == EAGAIN`.
 * - After `reset_action_state()`, count=0: fires immediately on first call.
 * - probability=0.0: never fires regardless of counter.
 * - NULL rule, INVALID operation, NULL errnum: all return false without modifying state.
 */
static void test_fail_after_helper(void)
{
    chaos_process_rule_t rule;
    int errnum = 0;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    rule.probability = 1.0;
    rule.errnum = EAGAIN;
    rule.fail_after_count = 1U;

    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_PTHREAD_CREATE, &errnum));
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_PTHREAD_CREATE, &errnum));
    assert(errnum == EAGAIN);

    reset_action_state();
    rule.fail_after_count = 0U;
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum));
    assert(errnum == EAGAIN);

    rule.probability = 0.0;
    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum));
    assert(!chaos_process_rule_fail_after_error(NULL, CHAOS_PROCESS_OP_FORK, &errnum));
    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_INVALID, &errnum));
    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, NULL));
}

int main(void)
{
    test_probability_helpers();
    test_latency_helper();
    test_error_number_helpers();
    test_fail_after_helper();
    return 0;
}
