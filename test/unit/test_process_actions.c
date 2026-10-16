/**
 * @file test_process_actions.c
 * @brief Unit tests for PROCESS-domain probability, latency, errno, and fail-after helpers.
 *
 * Subsystem under test: `src/process/chaos_process_actions.c`
 *
 * Coverage approach:
 * - The production source file is included after test_sleep_support.h, which records each
 *   sleep request instead of sleeping and can simulate EINTR, so tests exercise the retry
 *   loop without real sleeps.
 * - The `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` macro instantiates the real-function-pointer
 *   globals required by the production action helpers.
 *
 * Properties under test:
 * - `chaos_process_rule_should_trigger(NULL)` returns false.
 * - Probability boundary values and mid-range PRNG reproducibility.
 * - Latency: 2500 ms → one sleep of {2 s, 500 ms}; EINTR resumes with the remaining time.
 * - Probability=0 for latency: no sleep issued.
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

#include "../support/test_sleep_support.h"

#include "../../src/process/chaos_process_actions.c"

/**
 * @brief Reset all action-layer test state between test functions.
 *
 * Calls `chaos_process_test_reset_runtime()` to clear the runtime globals, then
 * clears the recorded sleeps.
 */
static void reset_action_state(void)
{
    chaos_process_test_reset_runtime();
    chaos_test_sleep_reset();
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
 * @brief Invariant: latency sleeps for exactly the rule's duration and resumes after EINTR.
 *
 * Expected observable behaviour:
 * - 2500 ms → one sleep of {2 s, 500 ms}.
 * - 5 ms with one EINTR → two sleeps, the second for the remaining time.
 * - probability=0.0 → no sleep.
 * - NULL rule, or an ERRNO rule → no sleep.
 */
static void test_latency_helper(void)
{
    chaos_process_rule_t rule;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_PROCESS_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(g_test_sleep_requests[0].tv_sec == 2);
    assert(g_test_sleep_requests[0].tv_nsec == 500000000L);

    reset_action_state();
    g_test_sleep_interruptions = 1;
    rule.latency_ms = 5U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 2U);
    assert(g_test_sleep_requests[0].tv_nsec == 5000000L);

    reset_action_state();
    rule.probability = 0.0;
    chaos_process_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);

    /* No rule, or a rule of another effect, never sleeps. */
    rule.probability = 1.0;
    chaos_process_rule_apply_latency(NULL);
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    chaos_process_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);
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
 * - A FAIL_AFTER rule → returns false, `errnum` unchanged.
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

    /* A rule of another effect never yields an error number. */
    rule.probability = 1.0;
    rule.effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    assert(!chaos_process_rule_error_number(&rule, &errnum));
    assert(errnum == 0);
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
 * - An operation past the last one, or an ERRNO rule: false; counters untouched.
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

    /* An operation past the last one, or a rule of another effect, never fires and
     * leaves the counters alone. */
    reset_action_state();
    rule.probability = 1.0;
    errnum = 0;
    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_COUNT, &errnum));
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    assert(!chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum));
    assert(errnum == 0);
    assert(g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] == 0U);
}

/**
 * @brief Invariant: a rule's hit counter advances exactly when its effect fires.
 *
 * Triggering condition: should_trigger on a rule with probability 1.0, then 0.0,
 *   then on a rule without a counter.
 *
 * Expected observable behaviour: the count is 1 after the firing call and stays 1
 *   after the call that does not fire; a rule without a counter still fires.
 */
static void test_should_trigger_counts_hits(void)
{
    chaos_process_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_process_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_process_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Invariant: should_trigger honours `@first`, `@from` and `@until`.
 *
 * Expected observable behaviour: `@first=2` fires twice and then never; a window
 *   that ended or has not started yet does not fire; an open window does.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_process_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_process_rule_should_trigger(&rule) == 1);
    assert(chaos_process_rule_should_trigger(&rule) == 1);
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_process_rule_should_trigger(&rule) == 1);

    /* A size gate passes only calls with a byte count in range. */
    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_process_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_process_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_process_rule_should_trigger(&rule) == 0);
}

/**
 * @brief Invariant: FAIL_AFTER honours the rule's window, `@first` and size gate.
 */
static void test_fail_after_honours_qualifiers(void)
{
    chaos_process_rule_t rule;
    chaos_hit_slot_t slot;
    int errnum = 0;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    rule.errnum = EAGAIN;
    rule.probability = 1.0;
    rule.hit = &slot;
    rule.policy.until_ms = 1;
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum) == 0);
    rule.policy.until_ms = 0;
    rule.policy.first = 1U;
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum) == 1);
    assert(errnum == EAGAIN);
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum) == 0);

    /* A size gate the call does not pass keeps the rule from firing. */
    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = 100U;
    errnum = 0;
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum) == 0);
    assert(errnum == 0);
    rule.call_size = 101U;
    assert(chaos_process_rule_fail_after_error(&rule, CHAOS_PROCESS_OP_FORK, &errnum) == 1);
    assert(errnum == EAGAIN);
}

int main(void)
{
    test_should_trigger_honours_qualifiers();
    test_fail_after_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_helpers();
    test_latency_helper();
    test_error_number_helpers();
    test_fail_after_helper();
    return 0;
}
