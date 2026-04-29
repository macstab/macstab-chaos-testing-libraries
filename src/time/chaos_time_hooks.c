#include "chaos_time_actions.h"
#include "chaos_time_config.h"
#include "chaos_time_internal.h"

#include <string.h>

static int chaos_time_call_real_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_clock_gettime(clock_id, value);
    chaos_time_leave_internal(previous);
    return rc;
}

static int
chaos_time_call_real_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_nanosleep(request, remaining);
    chaos_time_leave_internal(previous);
    return rc;
}

static int chaos_time_call_real_usleep(useconds_t usec)
{
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = g_chaos_time_real_usleep(usec);
    chaos_time_leave_internal(previous);
    return rc;
}

static void chaos_time_copy_remaining(const struct timespec *request, struct timespec *remaining)
{
    if (request == NULL || remaining == NULL)
    {
        return;
    }

    *remaining = *request;
}

CHAOS_TIME_EXPORT int clock_gettime(clockid_t clock_id, struct timespec *value)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    chaos_time_rule_t offset_rule;
    uintptr_t value_bits = (uintptr_t)(void *)value;
    int rc;

    if (chaos_time_in_internal() || value_bits == 0U)
    {
        return chaos_time_call_real_clock_gettime(clock_id, value);
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &errno_rule
        ) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    rc = chaos_time_call_real_clock_gettime(clock_id, value);
    if (rc != 0)
    {
        return rc;
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, clock_id, &offset_rule
        ))
    {
        chaos_time_rule_apply_offset(&offset_rule, value);
    }

    return 0;
}

CHAOS_TIME_EXPORT int nanosleep(const struct timespec *request, struct timespec *remaining)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;
    uintptr_t request_bits = (uintptr_t)(const void *)request;

    if (chaos_time_in_internal() || request_bits == 0U)
    {
        return chaos_time_call_real_nanosleep(request, remaining);
    }

    if (chaos_time_config_match(
            CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &latency_rule
        ))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        if (errno == EINTR)
        {
            chaos_time_copy_remaining(request, remaining);
        }
        return -1;
    }

    return chaos_time_call_real_nanosleep(request, remaining);
}

CHAOS_TIME_EXPORT int usleep(useconds_t usec)
{
    chaos_time_rule_t latency_rule;
    chaos_time_rule_t errno_rule;

    if (chaos_time_in_internal())
    {
        return chaos_time_call_real_usleep(usec);
    }

    if (chaos_time_config_match(CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_USLEEP, 0, &latency_rule))
    {
        chaos_time_rule_apply_latency(&latency_rule);
    }
    if (chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &errno_rule) &&
        chaos_time_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_time_call_real_usleep(usec);
}
