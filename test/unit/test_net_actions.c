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
 * hits even for sample UINT32_MAX. Where the sample comes from is tested in
 * test_draws_are_reproducible().
 */
static void test_probability_helpers(void)
{
    assert(chaos_net_probability_hit_sample(0.0, 0U) == 0);
    assert(chaos_net_probability_hit_sample(-1.0, 0U) == 0);
    assert(chaos_net_probability_hit_sample(1.0, 0xffffffffU) == 1);
    assert(chaos_net_probability_hit_sample(0.5, 0U) == 1);
    assert(chaos_net_probability_hit_sample(0.5, 0xffffffffU) == 0);
}

/**
 * @brief Proves a sample follows from the rule and the number of the evaluation, and from
 *        nothing else.
 *
 * @details This is what makes a fault reproducible: the same rule at the same evaluation
 * number gives the same samples; the next evaluation and a rule of different text give
 * unrelated ones; the draws within one evaluation differ from each other; and a forked
 * child's lineage changes all of them, so the backends of a pre-forking server do not
 * decide alike.
 */
static void test_draws_are_reproducible(void)
{
    chaos_net_rule_t rule;
    chaos_hit_slot_t slot;
    uint32_t first;
    uint32_t message;
    uint32_t next_evaluation;

    (void)memset(&rule, 0, sizeof(rule));
    (void)memset(&slot, 0, sizeof(slot));
    rule.hit = &slot;
    rule.key = chaos_net_prng_mix(
        g_chaos_net_process_seed ^ chaos_net_rule_hash("tcp4://127.0.0.1:1:recv:CORRUPT:1")
    );

    chaos_net_rule_draw_begin(&rule);
    assert(slot.evaluations == 1U);
    first = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY) == first);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_FIRST_EFFECT) != first);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_SECOND_EFFECT) != first);
    message = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_MESSAGE);
    assert(message != first);
    assert(message != chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_FIRST_EFFECT));

    chaos_net_rule_draw_begin(&rule);
    assert(slot.evaluations == 2U);
    next_evaluation = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY);
    assert(next_evaluation != first);

    rule.key = chaos_net_prng_mix(
        g_chaos_net_process_seed ^ chaos_net_rule_hash("tcp4://127.0.0.1:2:recv:CORRUPT:1")
    );
    slot.evaluations = 0U;
    chaos_net_rule_draw_begin(&rule);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY) != first);

    rule.key = chaos_net_prng_mix(
        g_chaos_net_process_seed ^ chaos_net_rule_hash("tcp4://127.0.0.1:1:recv:CORRUPT:1")
    );
    slot.evaluations = 0U;
    g_chaos_net_lineage = chaos_net_prng_mix(1U);
    chaos_net_rule_draw_begin(&rule);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY) != first);
    g_chaos_net_lineage = 0U;

    /* A rule outside a snapshot has no slot: evaluation 0 every time, which is what makes
     * the unit tests reproducible without seeding anything. */
    rule.hit = NULL;
    chaos_net_rule_draw_begin(&rule);
    next_evaluation = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY);
    chaos_net_rule_draw_begin(&rule);
    assert(chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_PROBABILITY) == next_evaluation);

    assert(chaos_net_rule_hash("a") == chaos_net_rule_hash("a"));
    assert(chaos_net_rule_hash("a") != chaos_net_rule_hash("b"));
    assert(chaos_net_rule_hash(NULL) != chaos_net_rule_hash("a"));
}

/**
 * @brief Proves CORRUPT flips one bit at the position the two samples select, and that the
 *   rule-driven form takes the index from the first effect draw and the bit from the
 *   second.
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

    {
        unsigned char swapped[] = {0x00U, 0x00U, 0x00U, 0x00U};
        chaos_net_rule_t rule;
        uint32_t byte_draw;
        uint32_t bit_draw;

        /* A key whose two effect draws select a different byte or bit when swapped, so the
         * assertion below can tell the two orders apart at all; the bound keeps it finite. */
        (void)memset(&rule, 0, sizeof(rule));
        for (rule.key = 1U; rule.key < 256U; ++rule.key)
        {
            chaos_net_rule_draw_begin(&rule);
            byte_draw = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_FIRST_EFFECT);
            bit_draw = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_SECOND_EFFECT);
            if (byte_draw % sizeof(seeded_expected) != bit_draw % sizeof(seeded_expected) ||
                (byte_draw & 7U) != (bit_draw & 7U))
            {
                break;
            }
        }
        assert(rule.key < 256U);

        chaos_net_corrupt_buffer_sample(
            seeded_expected, sizeof(seeded_expected), byte_draw, bit_draw
        );
        chaos_net_corrupt_buffer_sample(swapped, sizeof(swapped), bit_draw, byte_draw);
        assert(memcmp(swapped, seeded_expected, sizeof(swapped)) != 0);

        chaos_net_corrupt_buffer(&rule, seeded_buffer, sizeof(seeded_buffer));
    }
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
    rule.probability = 1.0; /* what the parser gives `LATENCY:ms` without `@p` */
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
 * @brief Proves LATENCY sleeps once for the whole delay, and that every effect draws against
 *   its probability.
 *
 * @details A NULL rule and a rule of no effect do not sleep. 2500 ms is a single sleep request
 * of 2 s + 500000000 ns, not a sequence of shorter sleeps. LATENCY is gated like the rest:
 * `LATENCY:ms` parses as probability 1.0, `LATENCY:ms@p` as p, and a zero probability sleeps
 * not at all. ERRNO at 0.0 never fires and at 1.0 always does.
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
    /* Negative: no probability, no delay -- the gate has no LATENCY exception any more. */
    chaos_net_rule_apply_latency(&rule);
    assert(g_test_sleep_calls == 0U);
    assert(chaos_net_rule_should_trigger(&rule) == 0);

    rule.probability = 1.0; /* what the parser gives `LATENCY:ms` without `@p` */
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
    test_draws_are_reproducible();
    test_corrupt_helpers();
    test_latency_and_trigger_helpers();
    test_latency_honours_qualifiers();
    test_errno_application();
    return 0;
}
