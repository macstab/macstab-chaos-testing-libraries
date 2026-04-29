#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

static useconds_t g_sleep_chunks[8];
static size_t g_sleep_count = 0U;
static int g_nanosleep_calls = 0;
static int g_nanosleep_eintr_count = 0;
static struct timespec g_last_nanosleep_request;

static int chaos_memory_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

static int chaos_memory_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    assert(request != NULL);
    g_last_nanosleep_request = *request;
    if (g_nanosleep_eintr_count > 0)
    {
        --g_nanosleep_eintr_count;
        if (remaining != NULL)
        {
            remaining->tv_sec = request->tv_sec;
            remaining->tv_nsec = request->tv_nsec;
        }
        errno = EINTR;
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

#include "../../src/memory/chaos_memory_actions.c"

static void reset_action_state(void)
{
    size_t index;

    chaos_memory_test_reset_runtime();
    g_sleep_count = 0U;
    g_nanosleep_calls = 0;
    g_nanosleep_eintr_count = 0;
    g_last_nanosleep_request.tv_sec = 0;
    g_last_nanosleep_request.tv_nsec = 0L;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

static void test_probability_helpers(void)
{
    assert(!chaos_memory_probability_hit_sample(0.0, 0U));
    assert(chaos_memory_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_memory_probability_hit_sample(0.5, 0U));
    assert(!chaos_memory_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_memory_rule_should_trigger(NULL));
}

static void test_latency_helper(void)
{
    chaos_memory_rule_t rule;

    reset_action_state();
    g_chaos_memory_real_usleep = chaos_memory_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 3U);
    assert(g_sleep_chunks[0] == 1000000U);
    assert(g_sleep_chunks[1] == 1000000U);
    assert(g_sleep_chunks[2] == 500000U);

    reset_action_state();
    g_chaos_memory_real_nanosleep = chaos_memory_test_nanosleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
    assert(g_nanosleep_calls == 1);
    assert(g_last_nanosleep_request.tv_sec == 0);
    assert(g_last_nanosleep_request.tv_nsec == 1000000L);

    reset_action_state();
    g_chaos_memory_real_nanosleep = chaos_memory_test_nanosleep;
    g_nanosleep_eintr_count = 1;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    g_chaos_memory_real_usleep = chaos_memory_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 0.0;
    rule.latency_ms = 100U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
}

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
}

int main(void)
{
    test_probability_helpers();
    test_latency_helper();
    test_errno_helper();
    return 0;
}
