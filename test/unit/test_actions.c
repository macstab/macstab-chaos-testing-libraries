/**
 * @file test_actions.c
 * @brief Proves the libchaos-io effect helpers that run after a rule matched: probability
 *        gating, TORN length selection, CORRUPT bit flips, LATENCY sleeps, ERRNO
 *        injection, and the qualifier and hit-count gate they all pass through.
 *
 * @details Unit under test: `src/effects/chaos_io_actions.c`, compiled in by `#include`.
 *
 * Isolation:
 * - `test_sleep_support.h` is included first and defines CHAOS_SLEEP_SYSCALL, so every
 *   LATENCY sleep is recorded as a timespec instead of slept; this lets the suite assert
 *   the exact request and drive the EINTR restart loop without signals or wall time.
 * - `CHAOS_IO_DEFINE_TEST_GLOBALS()` provides the real-function pointers and TLS state
 *   the helpers link against, so no wrapper or rule file is involved.
 * - Randomised helpers are split into a `_sample` form that takes explicit samples and a
 *   PRNG form; the PRNG form is checked against the sample form after reseeding the
 *   thread PRNG with the same seed, which pins both the arithmetic and the draw order.
 *
 * Not covered here: rule file parsing and selection (test_config_parse.c), wrapper call
 * paths (test_chaos_io.c).
 */

#include "../support/test_support.h"

#include <stdint.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/effects/chaos_io_actions.c"

/**
 * @brief Probability gate: p <= 0 never hits and p >= 1 always hits, whatever the
 *        sample (out-of-range values clamp rather than misbehave); in between a sample
 *        hits when it is below p * 2^32.
 *
 * @details The PRNG form must equal the sample form fed the next draw from the same
 * seed, so the gate consumes exactly one 32-bit draw per call.
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
 * @brief TORN length: for n >= 2 bytes the result is `sample % (n - 1) + 1`, always in
 *        [1, n - 1], so a torn write is never empty and never complete; 0 bytes gives 0
 *        and 1 byte gives 1 (the modulus would be zero).
 *
 * @details `torn_count(10)` must equal the sample form fed the next draw from seed 42.
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
 * @brief CORRUPT flips exactly one bit: byte `index_sample % size`, bit `bit_sample & 7`
 *        (index 1, bit 5 turns {0,0,0} into {0,0x20,0}); a NULL buffer or zero size is a
 *        no-op rather than a fault.
 *
 * @details `corrupt_buffer()` must equal the sample form fed the next two draws from
 * seed 99 in order index, then bit; this pins the draw order the source fixes by
 * capturing both samples before the call.
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
 * @brief LATENCY goes through the same qualifier gate and hit count as every other
 *        effect: `@first=1` delays once then never, a `@from` window that has not
 *        started (4e12 ms, about year 2096) and a failed `@size>100` gate do not delay,
 *        and each delay counts one hit.
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

/**
 * @brief LATENCY sleep requests and the trigger gate.
 *
 * @details A NULL rule, a zero-initialised rule and a 0 ms LATENCY rule do not sleep;
 * 2500 ms is one request of {2 s, 500000000 ns}. `should_trigger` is 0 for NULL, 1 for
 * LATENCY although probability is 0.0 (LATENCY has no probability), and follows the
 * probability for ERRNO.
 */
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

    /* An EINTR from the sleep restarts it with the remaining time the kernel reported
     * (the stub reports 1 ms), and the EINTR never leaks into the caller's errno. */
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
 * @brief ERRNO injection returns 1 and sets errno to the rule's errnum only when the
 *        rule is ERRNO and fires; in every other case it returns 0 and leaves errno
 *        untouched, so a pass-through call keeps the caller's errno.
 *
 * @details errno is pre-set to a sentinel (123) before each non-firing case to detect
 * any write.
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

    /* A non-ERRNO effect never sets errno, even at probability 1.0. */
    rule.effect = CHAOS_IO_EFFECT_LATENCY;
    errno = 123;
    assert(chaos_io_rule_apply_errno(&rule) == 0);
    assert(errno == 123);
}

/**
 * @brief The hit count advances exactly when the effect fires: 1 after a firing call,
 *        still 1 after a call the probability gate rejects; a rule without a hit slot
 *        (NULL) still fires.
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
 * @brief `should_trigger` honours every qualifier: `@first=2` fires twice then never
 *        (and counts 2 hits); `@until` in the past (1 ms after the epoch) and `@from` in
 *        the future do not fire, an open window does; `@size` bounds are exclusive.
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

    /* `@size>100` rejects an unknown size (CHAOS_POLICY_NO_SIZE) and exactly 100, accepts
     * 101; adding `@size<101` rejects 101 again (both bounds exclusive). */
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
