/**
 * @file test_net_actions.c
 * @brief Unit tests for the libchaos-net effect helpers: probability, rule firing, CORRUPT,
 *   LATENCY and ERRNO.
 *
 * @details
 * Unit under test: `src/net/chaos_net_actions.c`. The suite proves:
 * - probability: 0.0 and negative values never hit, 1.0 always hits, 0.5 splits the 32-bit
 *   sample space at 2^31; a draw is reproducible from a seed, and seed 0 behaves like seed 1
 *   (xorshift must never start from the all-zero state, which it cannot leave);
 * - CORRUPT flips exactly one bit, at byte `index_sample % size` and bit `bit_sample & 7`,
 *   and ignores a NULL or empty buffer;
 * - firing: the `@from`/`@until` window and `@size` gate apply first; LATENCY rules carry no
 *   probability and fire on every permitted call; other effects then draw against their
 *   probability; `@first=N` caps the firings; a hit is counted only when the effect fires;
 * - LATENCY sleeps once for the whole delay (2500 ms is one 2 s + 500 ms request);
 * - ERRNO sets errno only when an ERRNO rule fires; otherwise errno is untouched.
 *
 * Seams: the source is compiled into this file. `test_sleep_support.h` replaces the sleep
 * syscall used by `chaos_sleep_ms()` with a recorder, so LATENCY is observed without waiting.
 * `CHAOS_NET_DEFINE_TEST_GLOBALS()` provides the real-function pointers and PRNG state.
 *
 * Out of scope: rule parsing (`test_net_config.c`), the socket wrappers (`test_chaos_net.c`)
 * and PRNG seeding across threads.
 */

#include "../support/test_net_support.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

#include "../support/test_sleep_support.h"

#include "../../src/net/chaos_net_actions.c"

/**
 * @brief Proves the probability boundaries, reproducible draws from a seed, and that seed 0
 *   is replaced by 1.
 *
 * @details Out-of-range probabilities are clamped, never sampled: -1.0 never hits and 1.0
 * hits even for sample UINT32_MAX. Re-seeding with the same value and calling
 * `chaos_net_probability_hit()` matches drawing the sample by hand.
 */
static void test_probability_helpers(void)
{
    assert(chaos_net_probability_hit_sample(0.0, 0U) == 0);
    assert(chaos_net_probability_hit_sample(-1.0, 0U) == 0);
    assert(chaos_net_probability_hit_sample(1.0, 0xffffffffU) == 1);
    assert(chaos_net_probability_hit_sample(0.5, 0U) == 1);
    assert(chaos_net_probability_hit_sample(0.5, 0xffffffffU) == 0);

    chaos_net_prng_seed_thread(123456U);
    {
        uint32_t expected_sample = chaos_net_prng_next_u32();
        int expected_hit = chaos_net_probability_hit_sample(0.25, expected_sample);

        chaos_net_prng_seed_thread(123456U);
        assert(chaos_net_probability_hit(0.25) == expected_hit);
    }

    chaos_net_prng_seed_thread(1U);
    {
        const uint32_t from_one = chaos_net_prng_next_u32();

        chaos_net_prng_seed_thread(0U);
        assert(g_chaos_net_tls_prng_state != 0U);
        assert(chaos_net_prng_next_u32() == from_one);
    }
}

/**
 * @brief Proves CORRUPT flips one bit at the position the two samples select, and that the
 *   PRNG-driven form draws the index sample first and the bit sample second.
 *
 * @details Index sample 1, bit sample 5 on three zero bytes yields `{0, 0x20, 0}`. A NULL or
 * zero-length buffer is left alone (a recv() of 0 bytes has nothing to corrupt).
 */
static void test_corrupt_helpers(void)
{
    unsigned char buffer[] = {0x00U, 0x00U, 0x00U};
    unsigned char expected[] = {0x00U, 0x20U, 0x00U};
    unsigned char seeded_buffer[] = {0x00U, 0x00U, 0x00U, 0x00U};
    unsigned char seeded_expected[] = {0x00U, 0x00U, 0x00U, 0x00U};

    chaos_net_corrupt_buffer_sample(NULL, sizeof(buffer), 0U, 0U);
    chaos_net_corrupt_buffer_sample(buffer, 0U, 0U, 0U);

    chaos_net_corrupt_buffer_sample(buffer, sizeof(buffer), 1U, 5U);
    assert(memcmp(buffer, expected, sizeof(buffer)) == 0);

    chaos_net_prng_seed_thread(99U);
    {
        uint32_t expected_index_sample = chaos_net_prng_next_u32();
        uint32_t expected_bit_sample = chaos_net_prng_next_u32();

        chaos_net_corrupt_buffer_sample(
            seeded_expected, sizeof(seeded_expected), expected_index_sample, expected_bit_sample
        );
    }

    chaos_net_prng_seed_thread(99U);
    chaos_net_corrupt_buffer(seeded_buffer, sizeof(seeded_buffer));
    assert(memcmp(seeded_buffer, seeded_expected, sizeof(seeded_buffer)) == 0);
}

/**
 * @brief Proves LATENCY applies the qualifiers and counts each delay as a hit.
 *
 * @details `@first=1` delays once and then never. A `@from` in 2096 does not delay. `@size>100`
 * skips a 10-byte call and delays a 101-byte one. Two delays, two hits.
 */
static void test_latency_honours_qualifiers(void)
{
    chaos_net_rule_t rule;
    chaos_hit_slot_t slot;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    rule.latency_ms = 5U;
    rule.hit = &slot;
    rule.policy.first = 1U;

    chaos_test_sleep_reset();
    chaos_net_rule_apply_latency(&rule);
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(slot.count == 1U);

    (void)memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.from_ms = INT64_C(4000000000000);
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);

    (void)memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = 10U;
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    rule.call_size = 101U;
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 2U);
    assert(slot.count == 2U);
}

/**
 * @brief Proves LATENCY sleeps once for the whole delay, and that LATENCY rules fire without a
 *   probability while ERRNO rules draw against theirs.
 *
 * @details A NULL rule and a rule of no effect do not sleep. 2500 ms is a single sleep request
 * of 2 s + 500000000 ns, not a sequence of shorter sleeps. A LATENCY rule with probability 0
 * still fires: its value field is the delay, not a probability. ERRNO at 0.0 never fires and
 * at 1.0 always does.
 */
static void test_latency_and_trigger_helpers(void)
{
    chaos_net_rule_t rule;

    (void)memset(&rule, 0, sizeof(rule));

    chaos_test_sleep_reset();
    chaos_net_rule_apply_latency(NULL);
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    rule.latency_ms = 2500U;
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 1U);
    assert(g_test_sleep_requests[0].tv_sec == 2);
    assert(g_test_sleep_requests[0].tv_nsec == 500000000L);

    assert(chaos_net_rule_should_trigger(NULL) == 0);
    assert(chaos_net_rule_should_trigger(&rule) == 1);

    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.probability = 0.0;
    assert(chaos_net_rule_should_trigger(&rule) == 0);

    rule.probability = 1.0;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Proves ERRNO writes the rule's errno only when an ERRNO rule fires.
 *
 * @details A NULL rule, a rule of no effect, a rule at probability 0.0 and a firing LATENCY
 * rule all return 0 and leave errno as it was (123): the wrapper relies on errno being
 * untouched when it goes on to make the real call. At 1.0 errno becomes ECONNREFUSED.
 */
static void test_errno_application(void)
{
    chaos_net_rule_t rule;

    (void)memset(&rule, 0, sizeof(rule));
    errno = 0;
    assert(chaos_net_rule_apply_errno(NULL) == 0);
    assert(chaos_net_rule_apply_errno(&rule) == 0);

    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.errnum = ECONNREFUSED;
    rule.probability = 0.0;
    errno = 123;
    assert(chaos_net_rule_apply_errno(&rule) == 0);
    assert(errno == 123);

    rule.probability = 1.0;
    errno = 0;
    assert(chaos_net_rule_apply_errno(&rule) == 1);
    assert(errno == ECONNREFUSED);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    errno = 123;
    assert(chaos_net_rule_apply_errno(&rule) == 0);
    assert(errno == 123);
}

/**
 * @brief Proves a hit is counted only when the effect fires.
 *
 * @details The hits file must report firings, not evaluations: probability 1.0 fires and
 * counts 1, probability 0.0 neither fires nor counts. A rule with no hit slot (a copy made
 * outside a rule snapshot) still fires.
 */
static void test_should_trigger_counts_hits(void)
{
    chaos_net_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
    assert(slot.count == 1U);
    rule.probability = 0.0;
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    assert(slot.count == 1U);
    rule.hit = NULL;
    rule.probability = 1.0;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Proves `chaos_net_rule_should_trigger()` applies `@first`, `@from`/`@until` and
 *   `@size`.
 *
 * @details `@first=2` fires twice, then stops, and the hit count stays 2. The window is
 * compared with the wall clock in Unix ms: `@until=1` has passed, `@from=4000000000000`
 * (year 2096) has not started, and `@from=1` is open. `@size>100` rejects a call without a
 * byte count (`CHAOS_POLICY_NO_SIZE`) and a call of exactly 100 bytes (strict bound), passes
 * 101, and `@size<101` added on top rejects 101 again.
 */
static void test_should_trigger_honours_qualifiers(void)
{
    chaos_net_rule_t rule;
    chaos_hit_slot_t slot;

    memset(&rule, 0, sizeof(rule));
    memset(&slot, 0, sizeof(slot));
    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.hit = &slot;
    rule.probability = 1.0;
    rule.policy.first = 2U;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
    assert(chaos_net_rule_should_trigger(&rule) == 1);
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    assert(slot.count == 2U);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.until_ms = 1;
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    rule.policy.until_ms = 0;
    rule.policy.from_ms = INT64_C(4000000000000);
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    rule.policy.from_ms = 1;
    assert(chaos_net_rule_should_trigger(&rule) == 1);

    memset(&rule.policy, 0, sizeof(rule.policy));
    rule.policy.has_size_above = 1U;
    rule.policy.size_above = 100U;
    rule.call_size = CHAOS_POLICY_NO_SIZE;
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    rule.call_size = 100U;
    assert(chaos_net_rule_should_trigger(&rule) == 0);
    rule.call_size = 101U;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
    rule.policy.has_size_below = 1U;
    rule.policy.size_below = 101U;
    assert(chaos_net_rule_should_trigger(&rule) == 0);
}

int main(void)
{
    test_should_trigger_honours_qualifiers();
    test_should_trigger_counts_hits();
    test_probability_helpers();
    test_corrupt_helpers();
    test_latency_and_trigger_helpers();
    test_latency_honours_qualifiers();
    test_errno_application();
    return 0;
}
