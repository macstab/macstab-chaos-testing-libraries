#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

static int g_usleep_calls = 0;
static useconds_t g_last_usleep = 0U;
static int g_nanosleep_calls = 0;
static int g_force_eintr_once = 0;

static int stub_usleep(useconds_t usec)
{
    ++g_usleep_calls;
    g_last_usleep = usec;
    return 0;
}

static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    if (g_force_eintr_once != 0)
    {
        g_force_eintr_once = 0;
        errno = EINTR;
        if (remaining != NULL && request != NULL)
        {
            *remaining = *request;
        }
        return -1;
    }
    (void)request;
    (void)remaining;
    return 0;
}

#include "../../src/process/chaos_process_actions.c"

static void reset_action_state(void)
{
    chaos_process_test_reset_runtime();
    g_usleep_calls = 0;
    g_last_usleep = 0U;
    g_nanosleep_calls = 0;
    g_force_eintr_once = 0;
}

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

static void test_latency_helper(void)
{
    chaos_process_rule_t rule;

    reset_action_state();
    g_chaos_process_real_usleep = stub_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_PROCESS_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_usleep_calls == 3);
    assert(g_last_usleep == 500000U);

    reset_action_state();
    g_chaos_process_real_nanosleep = stub_nanosleep;
    g_force_eintr_once = 1;
    rule.latency_ms = 5U;
    chaos_process_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    rule.probability = 0.0;
    chaos_process_rule_apply_latency(&rule);
    assert(g_usleep_calls == 0);
    assert(g_nanosleep_calls == 0);
}

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
}

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
}

int main(void)
{
    test_probability_helpers();
    test_latency_helper();
    test_error_number_helpers();
    test_fail_after_helper();
    return 0;
}
