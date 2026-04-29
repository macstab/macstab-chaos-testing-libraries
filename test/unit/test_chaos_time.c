#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

CHAOS_TIME_DEFINE_TEST_GLOBALS();

static chaos_time_rule_t g_stub_rules[3][3];
static int g_stub_match[3][3];
static int g_latency_calls = 0;
static int g_errno_trigger = 0;
static int g_offset_calls = 0;
static int g_real_clock_gettime_calls = 0;
static int g_real_clock_gettime_error = 0;
static int g_real_nanosleep_calls = 0;
static int g_real_nanosleep_error = 0;
static int g_real_usleep_calls = 0;
static int g_real_usleep_error = 0;
static clockid_t g_last_clock_id = (clockid_t)0;
static struct timespec g_last_sleep_request;
static useconds_t g_last_usleep = 0U;

static void reset_wrapper_state(void)
{
    size_t effect_index;
    size_t operation_index;

    chaos_time_test_reset_runtime();
    for (effect_index = 0U; effect_index < 3U; ++effect_index)
    {
        for (operation_index = 0U; operation_index < 3U; ++operation_index)
        {
            (void)memset(
                &g_stub_rules[effect_index][operation_index],
                0,
                sizeof(g_stub_rules[effect_index][operation_index])
            );
            g_stub_match[effect_index][operation_index] = 0;
        }
    }
    g_latency_calls = 0;
    g_errno_trigger = 0;
    g_offset_calls = 0;
    g_real_clock_gettime_calls = 0;
    g_real_clock_gettime_error = 0;
    g_real_nanosleep_calls = 0;
    g_real_nanosleep_error = 0;
    g_real_usleep_calls = 0;
    g_real_usleep_error = 0;
    g_last_clock_id = (clockid_t)0;
    g_last_sleep_request.tv_sec = 0;
    g_last_sleep_request.tv_nsec = 0L;
    g_last_usleep = 0U;
}

int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
)
{
    (void)clock_id;
    if (effect < 0 || effect > CHAOS_TIME_EFFECT_OFFSET || operation < 0 ||
        operation > CHAOS_TIME_OP_USLEEP || rule == NULL || g_stub_match[effect][operation] == 0)
    {
        return 0;
    }

    *rule = g_stub_rules[effect][operation];
    return 1;
}

void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_TIME_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }
    errno = rule->errnum;
    return 1;
}

void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value)
{
    assert(rule != NULL);
    assert(value != NULL);
    ++g_offset_calls;
    value->tv_sec += (time_t)(rule->offset_ms / 1000);
    value->tv_nsec += (long)((rule->offset_ms % 1000) * 1000000LL);
    if (value->tv_nsec >= 1000000000L)
    {
        ++value->tv_sec;
        value->tv_nsec -= 1000000000L;
    }
}

static int chaos_time_test_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    ++g_real_clock_gettime_calls;
    g_last_clock_id = clock_id;
    if (g_real_clock_gettime_error != 0)
    {
        errno = g_real_clock_gettime_error;
        return -1;
    }
    assert(value != NULL);
    value->tv_sec = 10;
    value->tv_nsec = 250000000L;
    return 0;
}

static int chaos_time_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_real_nanosleep_calls;
    if (request != NULL)
    {
        g_last_sleep_request = *request;
    }
    else
    {
        g_last_sleep_request.tv_sec = 0;
        g_last_sleep_request.tv_nsec = 0L;
    }
    if (g_real_nanosleep_error != 0)
    {
        errno = g_real_nanosleep_error;
        if (remaining != NULL)
        {
            remaining->tv_sec = 0;
            remaining->tv_nsec = 500000000L;
        }
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

static int chaos_time_test_usleep(useconds_t usec)
{
    ++g_real_usleep_calls;
    g_last_usleep = usec;
    if (g_real_usleep_error != 0)
    {
        errno = g_real_usleep_error;
        return -1;
    }
    return 0;
}

#include "../../src/time/chaos_time_hooks.c"

static void test_call_real_helpers(void)
{
    struct timespec request;
    struct timespec remaining;
    struct timespec value;

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_chaos_time_real_usleep = chaos_time_test_usleep;

    assert(chaos_time_call_real_clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_real_clock_gettime_calls == 1);
    assert(g_last_clock_id == CLOCK_MONOTONIC);

    request.tv_sec = 1;
    request.tv_nsec = 0L;
    assert(chaos_time_call_real_nanosleep(&request, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    assert(chaos_time_call_real_usleep(1234U) == 0);
    assert(g_real_usleep_calls == 1);
    assert(g_last_usleep == 1234U);

    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    chaos_time_copy_remaining(&request, &remaining);
    assert(remaining.tv_sec == 1);
    assert(remaining.tv_nsec == 0L);

    remaining.tv_sec = 9;
    remaining.tv_nsec = 1L;
    chaos_time_copy_remaining(NULL, &remaining);
    assert(remaining.tv_sec == 9);
    assert(remaining.tv_nsec == 1L);
    chaos_time_copy_remaining(&request, NULL);
}

static void test_clock_gettime_paths(void)
{
    struct timespec value;

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_chaos_time_tls_guard = 1;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_real_clock_gettime_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_clock_gettime_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_CLOCK_GETTIME].errnum = EINVAL;
    g_errno_trigger = 1;
    errno = 0;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == -1);
    assert(errno == EINVAL);
    assert(g_real_clock_gettime_calls == 0);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_stub_match[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].effect =
        CHAOS_TIME_EFFECT_OFFSET;
    g_stub_rules[CHAOS_TIME_EFFECT_OFFSET][CHAOS_TIME_OP_CLOCK_GETTIME].offset_ms = 1500;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    assert(g_offset_calls == 1);
    assert(value.tv_sec == 11);
    assert(value.tv_nsec == 750000000L);

    reset_wrapper_state();
    g_chaos_time_real_clock_gettime = chaos_time_test_clock_gettime;
    g_real_clock_gettime_error = EFAULT;
    errno = 0;
    assert(clock_gettime(CLOCK_MONOTONIC, &value) == -1);
    assert(errno == EFAULT);
    assert(g_offset_calls == 0);
}

static void test_nanosleep_paths(void)
{
    struct timespec request;
    struct timespec remaining;

    request.tv_sec = 2;
    request.tv_nsec = 300000000L;

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_chaos_time_tls_guard = 1;
    assert(nanosleep(&request, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    assert(nanosleep(NULL, &remaining) == 0);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_NANOSLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(nanosleep(&request, &remaining) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_nanosleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_nanosleep = chaos_time_test_nanosleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_NANOSLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    errno = 0;
    assert(nanosleep(&request, &remaining) == -1);
    assert(errno == EINTR);
    assert(remaining.tv_sec == request.tv_sec);
    assert(remaining.tv_nsec == request.tv_nsec);
    assert(g_real_nanosleep_calls == 0);
}

static void test_usleep_paths(void)
{
    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_chaos_time_tls_guard = 1;
    assert(usleep(1234U) == 0);
    assert(g_real_usleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_stub_match[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_USLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_LATENCY][CHAOS_TIME_OP_USLEEP].effect =
        CHAOS_TIME_EFFECT_LATENCY;
    assert(usleep(1234U) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_usleep_calls == 1);

    reset_wrapper_state();
    g_chaos_time_real_usleep = chaos_time_test_usleep;
    g_stub_match[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP] = 1;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].effect = CHAOS_TIME_EFFECT_ERRNO;
    g_stub_rules[CHAOS_TIME_EFFECT_ERRNO][CHAOS_TIME_OP_USLEEP].errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(usleep(1234U) == -1);
    assert(errno == EINTR);
    assert(g_real_usleep_calls == 0);
}

int main(void)
{
    test_call_real_helpers();
    test_clock_gettime_paths();
    test_nanosleep_paths();
    test_usleep_paths();
    return 0;
}
