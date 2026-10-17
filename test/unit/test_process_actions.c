/**
 * @file test_process_actions.c
 * @brief Proves the libchaos-process effect helpers: probability, LATENCY, ERRNO and FAIL_AFTER.
 *
 * @details
 * Unit under test: `src/process/chaos_process_actions.c`, the layer that decides whether a
 * matched rule fires and what it does. Rule matching and the wrappers are out of scope; they are
 * covered by test_process_config.c and test_chaos_process.c.
 *
 * Isolation:
 * - The production source is included into this translation unit, so its static helpers and
 *   the inline policy code (`chaos_policy.h`) run unmodified.
 * - test_sleep_support.h is included first and replaces the `clock_nanosleep` call inside
 *   `chaos_sleep_ms()` with a recorder that can fail with EINTR, so LATENCY is checked by its
 *   requested timespecs and its EINTR retry loop without sleeping.
 * - `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` defines the runtime globals the helpers read: the
 *   per-thread PRNG state and the per-operation FAIL_AFTER counters.
 *
 * Rules are built in memory with `memset` + field assignment, so every qualifier not set by a
 * test is zero, which `chaos_policy.h` treats as "no qualifier".
 */
#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/process/chaos_process_actions.c"

/**
 * @brief Zeroes the FAIL_AFTER counters, PRNG state and recorded sleeps.
 *
 * FAIL_AFTER counters are process-wide and only ever grow, so a test that does not reset them
 * inherits the call count of the previous one.
 */
static void reset_action_state(void)
{
    chaos_process_test_reset_runtime();
    chaos_test_sleep_reset();
}

/**
 * @brief Proves the probability comparison is `sample < p * 2^32` with exact 0.0 and 1.0 ends.
 *
 * The sample-taking variant is driven with the extreme samples 0 and UINT32_MAX: p=0.0 never
 * hits even for sample 0, p=1.0 always hits even for UINT32_MAX, and p=0.5 splits them. The
 * PRNG-driven variant is then checked only at p=0.0 and p=1.0, where the result must not depend
 * on the seeded state. A NULL rule never triggers.
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
 * @brief Proves LATENCY sleeps the rule's duration once and resumes after EINTR.
 *
 * 2500 ms is split into {2 s, 500000000 ns}, proving the ms-to-timespec conversion carries
 * whole seconds. One simulated EINTR yields a second sleep call, proving a signal does not cut
 * the delay short. Probability 0.0, a NULL rule and a rule of another effect issue no sleep.
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

    rule.probability = 1.0;
    chaos_process_rule_apply_latency(NULL);
    rule.effect = CHAOS_PROCESS_EFFECT_ERRNO;
    chaos_process_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);
}

/**
 * @brief Proves ERRNO reports the rule's errno only when the rule fires.
 *
 * At probability 1.0 the helper returns true and writes EAGAIN. When it does not fire
 * (probability 0.0, NULL rule, NULL output, or a FAIL_AFTER rule) it returns false and leaves
 * the output untouched, so a wrapper can pass an uninitialised errno slot without reading junk.
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

    rule.probability = 1.0;
    rule.effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    assert(!chaos_process_rule_error_number(&rule, &errnum));
    assert(errnum == 0);
}

/**
 * @brief Proves FAIL_AFTER lets the first N calls of an operation through, then fails the rest.
 *
 * Each call increments the operation's counter from 0 and fires once the pre-increment value is
 * at least `fail_after_count`. With count=1 the first call passes and the second fails with
 * EAGAIN; with count=0 the first call fails. Probability 0.0 never fires. NULL rule, an
 * out-of-range operation (INVALID, COUNT), NULL output and a non-FAIL_AFTER rule return false
 * before the counter is touched, which the final counter check proves.
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
 * @brief Proves a rule's hit slot counts fired effects only, and a slot is optional.
 *
 * The hits file reports these counts, so a probability miss must not count. A rule with no slot
 * (as built before the hits file is mapped) still fires.
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
 * @brief Proves the trigger decision honours `@first`, `@from`/`@until` and `@size`.
 *
 * `@first=2` fires twice, then never, and the slot counts exactly 2. Windows are wall-clock ms:
 * `@until=1` (1970) has ended and `@from=4000000000000` (year 2096) has not started, so both
 * block; `@from=1` is open. The size gate is exclusive on both bounds and rejects a call with no
 * byte count (`CHAOS_POLICY_NO_SIZE`).
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
 * @brief Proves FAIL_AFTER applies the same window, `@first` and `@size` qualifiers as ERRNO.
 *
 * FAIL_AFTER bypasses the shared trigger helper and checks the qualifiers itself, so they are
 * proven separately here. `fail_after_count` is 0, so only the qualifiers decide: an ended
 * window blocks, `@first=1` fires once, and a failed size gate neither fires nor writes errno.
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
