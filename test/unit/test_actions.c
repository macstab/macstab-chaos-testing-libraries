/**
 * @file test_actions.c
 * @brief Unit tests for IO-domain probability, torn-write count, buffer corruption,
 *   latency, trigger, and errno helpers.
 *
 * Subsystem under test: `src/effects/chaos_io_actions.c`
 *
 * Coverage approach:
 * - The production source file is included after test_sleep_support.h, which replaces the
 *   sleep system call with a stub that records each request, so tests assert on the exact
 *   sleep generated for a given `latency_ms` without real sleeps.
 * - The `CHAOS_IO_DEFINE_TEST_GLOBALS()` macro instantiates all real-function-pointer
 *   globals required by the production action helpers.
 *
 * Properties under test:
 * - Probability sampling: boundary values (0.0, 1.0), out-of-range p (-1.0, 2.0),
 *   and mid-range determinism (p=0.5 with sample=0 and sample=MAX).
 * - `chaos_io_probability_hit(p)` with a seeded PRNG reproduces the result that would be
 *   obtained by manually drawing the next sample and calling `probability_hit_sample`.
 * - Torn-write count sampling: `torn_count_sample` with zero/one size, small count,
 *   and UINT32_MAX; `torn_count(10)` seeded for reproducibility.
 * - Buffer corruption: NULL buffer and zero size are silently ignored; bit 5 of byte 1
 *   flipped by index_sample=1, bit_sample=5 gives {0, 0x20, 0};
 *   `corrupt_buffer()` produces the same result as calling `corrupt_buffer_sample()`
 *   with the two next PRNG values after a common seed.
 * - Latency: 2500 ms → one sleep of {2 s, 500 ms}, resumed after EINTR with errno kept;
 *   NULL and zero-initialised rules produce no sleep.
 * - `chaos_io_rule_should_trigger()`: NULL → 0; LATENCY effect → 1 unconditionally;
 *   ERRNO with probability=0.0 → 0; ERRNO with probability=1.0 → 1.
 * - Errno application: NULL rule → 0; zero-initialised rule → 0; probability=0.0 → 0,
 *   errno unchanged; probability=1.0 → 1, errno=EIO.
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection.
 * - IO wrapper call paths (tested in test_chaos_io.c).
 */

#include "../support/test_support.h"

#include <stdint.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/effects/chaos_io_actions.c"

/**
 * @brief Invariant: probability sampling produces correct 0/1 decisions at boundary and midpoint.
 *
 * Triggering condition: `chaos_io_probability_hit_sample(p, sample)` with boundary,
 *   out-of-range, and mid-range values, followed by a seeded `chaos_io_probability_hit(p)`.
 *
 * Expected observable behaviour:
 * - p=0.0 → 0 regardless of sample.
 * - p=-1.0 (out-of-range low) → 0.
 * - p=1.0 → 1 regardless of sample.
 * - p=2.0 (out-of-range high) → 1.
 * - p=0.5, sample=0 → 1 (sample < threshold); sample=MAX → 0.
 * - `probability_hit(0.25)` with seed 123456789 reproduces the same hit decision as
 *   drawing the next PRNG value explicitly and calling `probability_hit_sample`.
 */
static void test_probability_helpers(void)
{
    assert(chaos_io_probability_hit_sample(0.0, 0U) == 0);
    assert(chaos_io_probability_hit_sample(-1.0, 0U) == 0);
    assert(chaos_io_probability_hit_sample(1.0, 0xffffffffU) == 1);
    assert(chaos_io_probability_hit_sample(2.0, 0xffffffffU) == 1);
    assert(chaos_io_probability_hit_sample(0.5, 0U) == 1);
    assert(chaos_io_probability_hit_sample(0.5, 0xffffffffU) == 0);

    chaos_io_prng_seed_thread(123456789U);
    {
        uint32_t expected_sample = chaos_io_prng_next_u32();
        int expected_hit = chaos_io_probability_hit_sample(0.25, expected_sample);

        chaos_io_prng_seed_thread(123456789U);
        assert(chaos_io_probability_hit(0.25) == expected_hit);
    }
}

/**
 * @brief Invariant: torn-write count sampling produces bounded results and is PRNG-reproducible.
 *
 * Triggering condition: `chaos_io_torn_count_sample(size, sample)` and `chaos_io_torn_count(10)`.
 *
 * Expected observable behaviour:
 * - `torn_count_sample(0, 123)` → 0 (no bytes → no torn).
 * - `torn_count_sample(1, 123)` → 1 (single byte can only be 1).
 * - `torn_count_sample(2, 123)` → 1 (always at least 1 and less than total).
 * - `torn_count_sample(10, 3)` → 4 (deterministic for known sample).
 * - `torn_count_sample(10, UINT32_MAX)` < 10 (never returns full size).
 * - `torn_count(10)` with seed 42 reproduces the result from drawing the same PRNG sample.
 */
static void test_torn_helpers(void)
{
    chaos_io_prng_seed_thread(42U);
    {
        uint32_t expected_sample = chaos_io_prng_next_u32();
        size_t expected_count = chaos_io_torn_count_sample(10U, expected_sample);

        chaos_io_prng_seed_thread(42U);
        assert(chaos_io_torn_count(10U) == expected_count);
    }

    assert(chaos_io_torn_count_sample(0U, 123U) == 0U);
    assert(chaos_io_torn_count_sample(1U, 123U) == 1U);
    assert(chaos_io_torn_count_sample(2U, 123U) == 1U);
    assert(chaos_io_torn_count_sample(10U, 3U) == 4U);
    assert(chaos_io_torn_count_sample(10U, UINT32_MAX) < 10U);
}

/**
 * @brief Invariant: buffer corruption flips exactly one bit at the expected byte position.
 *
 * Triggering condition: `chaos_io_corrupt_buffer_sample(buffer, size, index_sample, bit_sample)`.
 *
 * Expected observable behaviour:
 * - NULL buffer or zero size: silently ignored.
 * - `{0,0,0}` with index_sample=1 and bit_sample=5 → `{0, 0x20, 0}`
 *   (1 << 5 = 0x20 = bit 5 of byte at index 1).
 * - `chaos_io_corrupt_buffer()` produces the same result as calling `corrupt_buffer_sample()`
 *   with the two next PRNG values drawn from the same seed.
 */
static void test_corrupt_helpers(void)
{
    unsigned char buffer[] = {0x00U, 0x00U, 0x00U};
    unsigned char expected[] = {0x00U, 0x20U, 0x00U};
    unsigned char seeded_buffer[] = {0x00U, 0x00U, 0x00U, 0x00U};
    unsigned char seeded_expected[] = {0x00U, 0x00U, 0x00U, 0x00U};

    chaos_io_corrupt_buffer_sample(NULL, sizeof(buffer), 0U, 0U);
    chaos_io_corrupt_buffer_sample(buffer, 0U, 0U, 0U);

    chaos_io_corrupt_buffer_sample(buffer, sizeof(buffer), 1U, 5U);
    assert(memcmp(buffer, expected, sizeof(buffer)) == 0);

    chaos_io_prng_seed_thread(99U);
    {
        uint32_t expected_index_sample = chaos_io_prng_next_u32();
        uint32_t expected_bit_sample = chaos_io_prng_next_u32();

        chaos_io_corrupt_buffer_sample(
            seeded_expected, sizeof(seeded_expected), expected_index_sample, expected_bit_sample
        );
    }

    chaos_io_prng_seed_thread(99U);
    chaos_io_corrupt_buffer(seeded_buffer, sizeof(seeded_buffer));
    assert(memcmp(seeded_buffer, seeded_expected, sizeof(seeded_buffer)) == 0);
}

/**
 * @brief Invariant: latency sleeps for exactly the rule's duration and trigger logic respects
 *   effect type vs probability.
 *
 * Triggering conditions:
 * - `chaos_io_rule_apply_latency(NULL)` and `apply_latency(&rule)` with a zero-initialised rule.
 * - `chaos_io_rule_apply_latency(&rule)` with latency_ms=2500 and effect=LATENCY.
 * - `chaos_io_rule_should_trigger()` with NULL, LATENCY, ERRNO+p=0, ERRNO+p=1.
 *
 * Expected observable behaviour:
 * - NULL rule, zero-initialised rule and 0 ms → no sleep.
 * - 2500 ms → one sleep of {2 s, 500 ms}; an EINTR resumes with the remaining time and
 *   leaves errno untouched.
 * - `should_trigger(NULL)` → 0.
 * - LATENCY effect → 1 (unconditional).
 * - ERRNO + probability=0.0 → 0; ERRNO + probability=1.0 → 1.
 */
/**
 * @brief Invariant: a LATENCY rule delays only the calls its qualifiers let it fire on,
 *   and counts each delay as a hit.
 *
 * Expected observable behaviour: `@first=1` delays once, then never; a window that
 * has not started and a size gate the call fails do not delay; every delay is a hit.
 */
static void test_latency_honours_qualifiers(void)
{
    chaos_io_rule_t rule;
    chaos_hit_slot_t slot;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_IO_EFFECT_LATENCY;
    rule.latency_ms = 5U;
    rule.hit = &slot;
    rule.policy.first = 1U;

    chaos_test_sleep_reset();
    chaos_io_rule_apply_latency(&rule);
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(slot.count == 1U);

    (void)memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.from_ms = INT64_C(4000000000000);
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);

    (void)memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = 10U;
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    rule.call_size = 101U;
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 2U);
    assert(slot.count == 2U);
}

static void test_latency_and_trigger_helpers(void)
{
    chaos_io_rule_t rule;

    (void)memset(&rule, 0, sizeof(rule));

    chaos_test_sleep_reset();
    chaos_io_rule_apply_latency(NULL);
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);

    rule.effect = CHAOS_IO_EFFECT_LATENCY;
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);

    rule.latency_ms = 2500U;
    chaos_io_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(g_test_sleep_requests[0].tv_sec == 2);
    assert(g_test_sleep_requests[0].tv_nsec == 500000000L);

    /* A signal interrupts the sleep: it resumes with the remaining time, and the
     * caller's errno is untouched. */
    chaos_test_sleep_reset();
    g_test_sleep_interruptions = 1;
    errno = 4242;
    chaos_io_rule_apply_latency(&rule);
    assert(errno == 4242);
    assert(g_test_sleep_calls == 2U);
    assert(g_test_sleep_requests[1].tv_sec == 0);
    assert(g_test_sleep_requests[1].tv_nsec == 1000000L);

    assert(chaos_io_rule_should_trigger(NULL) == 0);
    assert(chaos_io_rule_should_trigger(&rule) == 1);

    rule.effect = CHAOS_IO_EFFECT_ERRNO;
    rule.probability = 0.0;
    assert(chaos_io_rule_should_trigger(&rule) == 0);

    rule.probability = 1.0;
    assert(chaos_io_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Invariant: errno injection sets the target error code and is gated by probability.
 *
 * Triggering condition: `chaos_io_rule_apply_errno(&rule)` with effect=ERRNO, errnum=EIO,
 *   and various probability values.
 *
 * Expected observable behaviour:
 * - NULL rule → 0; errno unchanged.
 * - Zero-initialised rule (no effect set) → 0; errno unchanged.
 * - probability=0.0: returns 0; errno left at its current value (123).
 * - probability=1.0: returns 1; errno set to EIO.
 *
 * EIO is chosen as a representative disk-IO errno to verify that the specific error code
 * requested by the rule is what actually gets injected.
 */
static void test_errno_application(void)
{
    chaos_io_rule_t rule;

    (void)memset(&rule, 0, sizeof(rule));
    errno = 0;
    assert(chaos_io_rule_apply_errno(NULL) == 0);
    assert(chaos_io_rule_apply_errno(&rule) == 0);

    rule.effect = CHAOS_IO_EFFECT_ERRNO;
    rule.errnum = EIO;
    rule.probability = 0.0;
    errno = 123;
    assert(chaos_io_rule_apply_errno(&rule) == 0);
    assert(errno == 123);

    rule.probability = 1.0;
    errno = 0;
    assert(chaos_io_rule_apply_errno(&rule) == 1);
    assert(errno == EIO);

    /* Any other effect never sets errno, however sure its probability. */
    rule.effect = CHAOS_IO_EFFECT_LATENCY;
    errno = 123;
    assert(chaos_io_rule_apply_errno(&rule) == 0);
    assert(errno == 123);
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
    chaos_io_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_IO_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_io_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_io_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Invariant: should_trigger honours `@first`, `@from` and `@until`.
 *
 * Expected observable behaviour: `@first=2` fires twice and then never; a window
 *   that ended or has not started yet does not fire; an open window does.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_io_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_IO_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_io_rule_should_trigger(&rule) == 1);
    assert(chaos_io_rule_should_trigger(&rule) == 1);
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_io_rule_should_trigger(&rule) == 1);

    /* A size gate passes only calls with a byte count in range. */
    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_io_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_io_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_io_rule_should_trigger(&rule) == 0);
}

int main(void)
{
    test_should_trigger_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_helpers();
    test_torn_helpers();
    test_corrupt_helpers();
    test_latency_and_trigger_helpers();
    test_latency_honours_qualifiers();
    test_errno_application();
    return 0;
}
