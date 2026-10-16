/**
 * @file test_memory_actions.c
 * @brief Unit tests for memory-domain probability sampling, latency application, and
 *   errno injection helpers.
 *
 * Subsystem under test: `src/memory/chaos_memory_actions.c`
 *
 * Coverage approach:
 * - The production source file is included after test_sleep_support.h, which records each
 *   sleep request instead of sleeping and can simulate EINTR.
 * - `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals
 *   required by the production action helpers.
 * - `reset_action_state()` resets the PRNG and function-pointer globals (via
 *   `chaos_memory_test_reset_runtime()`) and clears all sleep tracking state.
 *
 * Properties under test:
 * - `chaos_memory_probability_hit_sample`: boundary values 0.0 and 1.0; midpoint 0.5 with
 *   sample=0 (hit) and sample=UINT32_MAX (miss).
 * - `chaos_memory_rule_should_trigger(NULL)` → false.
 * - Latency: 2500 ms → one sleep of {2 s, 500 ms}; EINTR resumes with the remaining time.
 * - Latency with probability=0.0: no sleep even when `latency_ms > 0`.
 * - `chaos_memory_rule_apply_errno`: probability=1.0 sets errno to ENOMEM and returns true;
 *   NULL rule → false.
 *
 * What is NOT tested here:
 * - Memory wrapper call paths that invoke action helpers at interception time.
 * - Config file parsing and rule selection (tested in `test_memory_config.c`).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/memory/chaos_memory_actions.c"

/**
 * @brief Reset all per-test action state to well-known defaults.
 *
 * Calls `chaos_memory_test_reset_runtime()` to zero PRNG and function-pointer globals,
 * then clears the recorded sleeps.
 */
static void reset_action_state(void)
{
    chaos_memory_test_reset_runtime();
    chaos_test_sleep_reset();
}

/**
 * @brief Invariant: probability sampling produces the correct binary decision at all
 *   boundary values; `should_trigger(NULL)` is safe.
 *
 * Triggering condition: `chaos_memory_probability_hit_sample` with p=0.0/1.0/0.5 and
 *   sample=0/UINT32_MAX; `chaos_memory_rule_should_trigger(NULL)`.
 *
 * Expected observable behaviour:
 * - `probability_hit_sample(0.0, 0)` → false.
 * - `probability_hit_sample(1.0, UINT32_MAX)` → true.
 * - `probability_hit_sample(0.5, 0)` → true (0 < threshold).
 * - `probability_hit_sample(0.5, UINT32_MAX)` → false (UINT32_MAX ≥ threshold).
 * - `rule_should_trigger(NULL)` → false (NULL guard).
 */
static void test_probability_helpers(void)
{
    assert(!chaos_memory_probability_hit_sample(0.0, 0U));
    assert(chaos_memory_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_memory_probability_hit_sample(0.5, 0U));
    assert(!chaos_memory_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_memory_rule_should_trigger(NULL));
}

/**
 * @brief Invariant: latency sleeps for exactly the rule's duration, resumes after EINTR,
 *   and skips the sleep when probability is 0.
 *
 * Expected observable behaviour:
 * - LATENCY, probability=1.0, latency_ms=2500: one sleep of {2 s, 500 ms}.
 * - Same with one EINTR: a second sleep for the remaining time; errno untouched.
 * - probability=0.0, latency_ms=100: no sleep.
 * - NULL rule, or an ERRNO rule: no sleep.
 */
static void test_latency_helper(void)
{
    chaos_memory_rule_t rule;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(g_test_sleep_requests[0].tv_sec == 2);
    assert(g_test_sleep_requests[0].tv_nsec == 500000000L);

    reset_action_state();
    g_test_sleep_interruptions = 1;
    errno = 4242;
    chaos_memory_rule_apply_latency(&rule);
    assert(errno == 4242);
    assert(g_test_sleep_calls == 2U);
    assert(g_test_sleep_requests[1].tv_nsec == 1000000L);

    reset_action_state();
    rule.probability = 0.0;
    rule.latency_ms = 100U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);

    /* No rule, or a rule of another effect, never sleeps. */
    rule.probability = 1.0;
    chaos_memory_rule_apply_latency(NULL);
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);
}

/**
 * @brief Invariant: `chaos_memory_rule_apply_errno` sets errno and returns true with
 *   probability=1.0, and returns false for a NULL rule.
 *
 * Triggering condition: a rule with ERRNO effect, errnum=ENOMEM, probability=1.0; then
 *   `apply_errno(NULL)`.
 *
 * Expected observable behaviour:
 * - `apply_errno(&rule)` with probability=1.0: returns true; `errno == ENOMEM`.
 *   ENOMEM is the canonical allocation-failure code for memory interceptors and is used here
 *   to verify that the specific error code from the rule is what actually gets injected.
 * - `apply_errno(NULL)` → false (NULL guard).
 * - probability=0.0, or a LATENCY rule → false; errno untouched.
 */
static void test_errno_helper(void)
{
    chaos_memory_rule_t rule;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.errnum = ENOMEM;
    errno = 0;
    assert(chaos_memory_rule_apply_errno(&rule));
    assert(errno == ENOMEM);
    assert(!chaos_memory_rule_apply_errno(NULL));

    /* A rule that does not fire, or one of another effect, leaves errno alone. */
    errno = 4242;
    rule.probability = 0.0;
    assert(!chaos_memory_rule_apply_errno(&rule));
    rule.probability = 1.0;
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    assert(!chaos_memory_rule_apply_errno(&rule));
    assert(errno == 4242);
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
    chaos_memory_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_memory_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_memory_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Invariant: should_trigger honours `@first`, `@from` and `@until`.
 *
 * Expected observable behaviour: `@first=2` fires twice and then never; a window
 *   that ended or has not started yet does not fire; an open window does.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_memory_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_memory_rule_should_trigger(&rule) == 1);
    assert(chaos_memory_rule_should_trigger(&rule) == 1);
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_memory_rule_should_trigger(&rule) == 1);

    /* A size gate passes only calls with a byte count in range. */
    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_memory_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_memory_rule_should_trigger(&rule) == 0);
}

int main(void)
{
    test_should_trigger_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_helpers();
    test_latency_helper();
    test_errno_helper();
    return 0;
}
