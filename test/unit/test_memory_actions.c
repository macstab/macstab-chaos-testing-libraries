/**
 * @file test_memory_actions.c
 * @brief Proves the libchaos-memory trigger gate and the LATENCY and ERRNO effects in isolation.
 *
 * @details
 * Unit under test: `src/memory/chaos_memory_actions.c`, compiled into this binary by `#include`.
 *
 * Isolation:
 * - test_sleep_support.h is included first and defines `CHAOS_SLEEP_SYSCALL`, so the
 *   `clock_nanosleep` system call behind chaos_sleep_ms() is replaced by a stub that records each
 *   request and can fail the next N calls with EINTR, leaving 1 ms remaining. No test sleeps.
 * - `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` defines the real-function pointers (all NULL), the TLS
 *   reentrancy guard and PRNG state, and a no-op chaos_memory_ensure_symbols(), so the actions
 *   link without the wrapper translation units.
 * - Tests choose probability 0.0 or 1.0, which chaos_memory_probability_hit_sample() decides
 *   without consulting the PRNG; the sampled midpoint case passes the sample explicitly.
 *
 * Not covered here: the wrappers that call these helpers (test_chaos_memory.c) and rule
 * parsing and selection (test_memory_config.c).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/memory/chaos_memory_actions.c"

/** @brief Restores the runtime globals and the sleep stub so tests cannot leak into each other. */
static void reset_action_state(void)
{
    chaos_memory_test_reset_runtime();
    chaos_test_sleep_reset();
}

/**
 * @brief Proves the probability decision at its edges and that a NULL rule never fires.
 *
 * @details Probability 0.0 never fires and 1.0 always fires, whatever the sample, because both
 * are short-circuited before the threshold arithmetic. At 0.5 the threshold is 2^31: sample 0
 * lies below it (fires) and sample 0xffffffff lies above it (does not), which pins the
 * comparison direction `sample < probability * 2^32`.
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
 * @brief Proves LATENCY sleeps the full configured delay exactly once per firing.
 *
 * @details
 * - 2500 ms becomes one request of {2 s, 500000000 ns}: milliseconds are split, not truncated.
 * - After one EINTR the sleep is reissued with the stub's 1 ms remainder, and errno keeps the
 *   caller's sentinel 4242: an injected delay must neither end early nor leak EINTR.
 * - Probability 0.0, a NULL rule and a rule of another effect issue no request.
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

    rule.probability = 1.0;
    chaos_memory_rule_apply_latency(NULL);
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);
}

/**
 * @brief Proves ERRNO stores the rule's errnum and reports a firing, and otherwise leaves errno.
 *
 * @details A firing ENOMEM rule returns 1 with errno == ENOMEM; the wrapper turns that into
 * MAP_FAILED or -1. A NULL rule, probability 0.0 and a LATENCY rule return 0 and keep the
 * sentinel 4242, because a wrapper that falls through to the real function must not see a
 * stale injected errno.
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

    errno = 4242;
    rule.probability = 0.0;
    assert(!chaos_memory_rule_apply_errno(&rule));
    rule.probability = 1.0;
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    assert(!chaos_memory_rule_apply_errno(&rule));
    assert(errno == 4242);
}

/**
 * @brief Proves a hit is counted only when the rule fires, and a rule without a slot still fires.
 *
 * @details The zeroed slot's generation matches the rule's zero `hit_generation`, so the slot
 * counts as current. A NULL slot models a rule copy outside a snapshot: it must fire without
 * dereferencing anything.
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
 * @brief Proves the gate applies the `@first`, `@from`, `@until` and `@size` qualifiers.
 *
 * @details
 * - `@first=2` claims two firings and then refuses; the count stops at 2 with it.
 * - `@until` 1 ms after the epoch has already ended; `@from` 4000000000000 ms (year 2096) has not
 *   begun; `@from` 1 ms is open. The real clock is used, so the bounds are chosen far from now.
 * - `@size>100` rejects a call without a byte count (`CHAOS_POLICY_NO_SIZE`) and 100 itself
 *   (bounds are exclusive), passes 101, and `@size<101` then excludes 101 as well.
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
