#include "../support/test_net_support.h"

static useconds_t g_sleep_chunks[8];
static size_t g_sleep_count = 0U;

static int chaos_net_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

CHAOS_NET_DEFINE_TEST_GLOBALS();

#define usleep chaos_net_test_usleep
#include "../../src/net/chaos_net_actions.c"
#undef usleep

static void chaos_net_test_reset_sleep_state(void)
{
    size_t index;

    g_sleep_count = 0U;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

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
