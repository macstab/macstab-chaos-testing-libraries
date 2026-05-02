/**
 * @file test_net_actions.c
 * @brief Unit tests for NET-domain probabilistic, corruption, latency, and errno helpers.
 *
 * Subsystem under test: `src/net/chaos_net_actions.c`
 *
 * Coverage approach:
 * - Includes production source directly via `#include "../../src/net/chaos_net_actions.c"`
 *   after defining `usleep` to a test-controlled stub. This gives access to all static
 *   helper functions without LD_PRELOAD.
 * - The `usleep` macro override redirects sleep calls into a local array so tests can
 *   assert on the exact useconds values generated for a given latency_ms setting.
 *
 * Properties under test:
 * - Probability sampling: boundary values (0.0, 1.0) and mid-range determinism.
 * - `chaos_net_probability_hit()` reproduces a seeded sample reproducibly.
 * - Buffer corruption: single-bit flip at a deterministic index+bit position.
 * - `chaos_net_corrupt_buffer()` and `chaos_net_corrupt_buffer_sample()` equivalence.
 * - Latency decomposition: 2500 ms becomes exactly three usleep calls of 1s, 1s, 0.5s.
 * - `chaos_net_rule_should_trigger()` unconditional for LATENCY effect, probability-gated
 *   for ERRNO effect.
 * - Errno application: ECONNREFUSED injected at probability 1.0; skipped at 0.0.
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection.
 * - Actual socket wrapper call paths (tested in test_chaos_net.c).
 * - Thread-safety of `chaos_net_prng_seed_thread()`.
 */

#include "../support/test_net_support.h"

/**
 * @brief Captured usleep durations from the test-local sleep stub.
 *
 * Populated in call order. The array size (8) is deliberately small relative to
 * the maximum possible chunk count to catch excessive sleep decompositions via
 * the assert inside the stub.
 */
static useconds_t g_sleep_chunks[8];

/**
 * @brief Number of usleep calls recorded since the last reset.
 *
 * Used by tests to assert the exact number of sleep intervals generated.
 */
static size_t g_sleep_count = 0U;

/**
 * @brief Test-local usleep stub that records durations instead of sleeping.
 *
 * Asserts that the call array has not overflowed. Returns 0 (success) always.
 *
 * @param usec  Sleep duration in microseconds, recorded at `g_sleep_chunks[g_sleep_count]`.
 * @return 0 (success, never fails).
 */
static int chaos_net_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

CHAOS_NET_DEFINE_TEST_GLOBALS();

/* Override usleep before including the production implementation. */
#define usleep chaos_net_test_usleep
#include "../../src/net/chaos_net_actions.c"
#undef usleep

/**
 * @brief Reset sleep-tracking state between test functions.
 *
 * Zeroes `g_sleep_count` and clears all recorded chunk values. Called at the
 * start of any test that exercises the latency code path.
 */
static void chaos_net_test_reset_sleep_state(void)
{
    size_t index;

    g_sleep_count = 0U;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

/**
 * @brief Invariant: probability sampling produces correct 0/1 decisions at boundary and midpoint.
 *
 * Triggering condition: `chaos_net_probability_hit_sample(p, sample)` called with
 *   boundary probabilities and hand-picked sample values.
 *
 * Expected observable behaviour:
 * - p=0.0 always returns 0 regardless of sample.
 * - p=-1.0 (out-of-range) always returns 0.
 * - p=1.0 always returns 1 regardless of sample.
 * - p=0.5 with sample=0 returns 1 (sample < threshold).
 * - p=0.5 with sample=0xffffffff returns 0 (sample >= threshold).
 * - `chaos_net_probability_hit(p)` with a seeded PRNG reproduces the result that
 *   would be obtained by manually drawing the next sample and calling
 *   `chaos_net_probability_hit_sample(p, sample)`.
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
}

/**
 * @brief Invariant: buffer corruption flips exactly one bit at the expected byte position.
 *
 * Triggering condition: `chaos_net_corrupt_buffer_sample(buffer, size, index_sample, bit_sample)`.
 *
 * Expected observable behaviour:
 * - NULL or zero-size buffer calls are silently ignored (no crash, no modification).
 * - Buffer `{0, 0, 0}` with index_sample=1 and bit_sample=5 produces `{0, 0x20, 0}`.
 *   (bit 5 of byte 1: 1 << 5 = 0x20).
 * - `chaos_net_corrupt_buffer()` produces the same result as calling
 *   `chaos_net_corrupt_buffer_sample()` with the two next PRNG values after a
 *   common seed.
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
 * @brief Invariant: latency of 2500ms decomposes into three usleep intervals and trigger
 *   logic respects effect type vs probability.
 *
 * Triggering condition:
 * - `chaos_net_rule_apply_latency(&rule)` with latency_ms=2500 and effect=LATENCY.
 * - `chaos_net_rule_should_trigger()` with various effect/probability combinations.
 *
 * Expected observable behaviour:
 * - NULL rule pointer to `apply_latency`: no crash, no sleep calls.
 * - Zero-initialised rule to `apply_latency`: no crash, no sleep calls (no effect set).
 * - 2500 ms generates exactly 3 usleep calls: 1 000 000 + 1 000 000 + 500 000 µs.
 * - `chaos_net_rule_should_trigger(NULL)` returns 0.
 * - LATENCY effect triggers unconditionally (returns 1 regardless of probability).
 * - ERRNO effect with probability=0.0 does not trigger (returns 0).
 * - ERRNO effect with probability=1.0 triggers (returns 1).
 */
static void test_latency_and_trigger_helpers(void)
{
    chaos_net_rule_t rule;

    (void)memset(&rule, 0, sizeof(rule));

    chaos_net_test_reset_sleep_state();
    chaos_net_rule_apply_latency(NULL);
    chaos_net_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    rule.latency_ms = 2500U;
    chaos_net_rule_apply_latency(&rule);
    assert(g_sleep_count == 3U);
    assert(g_sleep_chunks[0] == 1000000U);
    assert(g_sleep_chunks[1] == 1000000U);
    assert(g_sleep_chunks[2] == 500000U);

    assert(chaos_net_rule_should_trigger(NULL) == 0);
    assert(chaos_net_rule_should_trigger(&rule) == 1);

    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.probability = 0.0;
    assert(chaos_net_rule_should_trigger(&rule) == 0);

    rule.probability = 1.0;
    assert(chaos_net_rule_should_trigger(&rule) == 1);
}

/**
 * @brief Invariant: errno injection sets the target error code and is gated by probability.
 *
 * Triggering condition:
 * - `chaos_net_rule_apply_errno(&rule)` with effect=ERRNO, errnum=ECONNREFUSED,
 *   and various probability values.
 *
 * Expected observable behaviour:
 * - NULL rule returns 0; errno is unchanged.
 * - Zero-initialised rule (no effect set) returns 0; errno is unchanged.
 * - probability=0.0: returns 0; errno is left at its current value (123).
 * - probability=1.0: returns 1; errno is set to ECONNREFUSED.
 *
 * ECONNREFUSED is chosen as a representative network errno to verify that the
 * specific error code requested by the rule is what actually gets injected.
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
}

int main(void)
{
    test_probability_helpers();
    test_corrupt_helpers();
    test_latency_and_trigger_helpers();
    test_errno_application();
    return 0;
}
