#include "chaos_memory_actions.h"
#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

static void *chaos_memory_call_real_mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset
)
{
    int previous;
    void *result;

    previous = chaos_memory_enter_internal();
    result = g_chaos_memory_real_mmap(address, length, protection, flags, fd, offset);
    chaos_memory_leave_internal(previous);
    return result;
}

static int chaos_memory_call_real_mprotect(void *address, size_t length, int protection)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_mprotect(address, length, protection);
    chaos_memory_leave_internal(previous);
    return rc;
}

static int chaos_memory_call_real_munmap(void *address, size_t length)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_munmap(address, length);
    chaos_memory_leave_internal(previous);
    return rc;
}

static int chaos_memory_call_real_madvise(void *address, size_t length, int advice)
{
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = g_chaos_memory_real_madvise(address, length, advice);
    chaos_memory_leave_internal(previous);
    return rc;
}

CHAOS_MEMORY_EXPORT void *
mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MMAP, flags, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, flags, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return MAP_FAILED;
    }

    return chaos_memory_call_real_mmap(address, length, protection, flags, fd, offset);
}

CHAOS_MEMORY_EXPORT int munmap(void *address, size_t length)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_munmap(address, length);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MUNMAP, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MUNMAP, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        /* Synthetic munmap failure intentionally leaves the mapping active. */
        return -1;
    }

    return chaos_memory_call_real_munmap(address, length);
}

CHAOS_MEMORY_EXPORT int mprotect(void *address, size_t length, int protection)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_mprotect(address, length, protection);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MPROTECT, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_mprotect(address, length, protection);
}

CHAOS_MEMORY_EXPORT int madvise(void *address, size_t length, int advice)
{
    chaos_memory_rule_t latency_rule;
    chaos_memory_rule_t errno_rule;

    if (chaos_memory_in_internal())
    {
        return chaos_memory_call_real_madvise(address, length, advice);
    }

    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, &latency_rule
        ))
    {
        chaos_memory_rule_apply_latency(&latency_rule);
    }
    if (chaos_memory_config_match(
            CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MADVISE, 0, &errno_rule
        ) &&
        chaos_memory_rule_apply_errno(&errno_rule))
    {
        return -1;
    }

    return chaos_memory_call_real_madvise(address, length, advice);
}
