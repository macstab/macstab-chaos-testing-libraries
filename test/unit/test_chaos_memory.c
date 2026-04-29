#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

static chaos_memory_rule_t g_stub_rules[2][4];
static int g_stub_match[2][4];
static int g_latency_calls = 0;
static int g_errno_trigger = 0;
static int g_real_mmap_calls = 0;
static int g_real_mmap_error = 0;
static int g_real_munmap_calls = 0;
static int g_real_munmap_error = 0;
static int g_real_mprotect_calls = 0;
static int g_real_mprotect_error = 0;
static int g_real_madvise_calls = 0;
static int g_real_madvise_error = 0;
static int g_last_mmap_flags = 0;
static void *g_last_munmap_address = NULL;
static int g_last_mprotect_prot = 0;
static int g_last_madvise_advice = 0;
static size_t g_last_length = 0U;
static void *g_real_mmap_result = (void *)(uintptr_t)0x12345000U;

static void reset_wrapper_state(void)
{
    size_t effect_index;
    size_t operation_index;

    chaos_memory_test_reset_runtime();
    for (effect_index = 0U; effect_index < 2U; ++effect_index)
    {
        for (operation_index = 0U; operation_index < 4U; ++operation_index)
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
    g_real_mmap_calls = 0;
    g_real_mmap_error = 0;
    g_real_munmap_calls = 0;
    g_real_munmap_error = 0;
    g_real_mprotect_calls = 0;
    g_real_mprotect_error = 0;
    g_real_madvise_calls = 0;
    g_real_madvise_error = 0;
    g_last_mmap_flags = 0;
    g_last_munmap_address = NULL;
    g_last_mprotect_prot = 0;
    g_last_madvise_advice = 0;
    g_last_length = 0U;
}

int chaos_memory_config_match(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
)
{
    if (operation == CHAOS_MEMORY_OP_MMAP)
    {
        g_last_mmap_flags = mmap_flags;
    }
    if (effect < 0 || effect > CHAOS_MEMORY_EFFECT_LATENCY || operation < 0 ||
        operation > CHAOS_MEMORY_OP_MUNMAP || rule == NULL || g_stub_match[effect][operation] == 0)
    {
        return 0;
    }

    *rule = g_stub_rules[effect][operation];
    return 1;
}

void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }
    errno = rule->errnum;
    return 1;
}

static void *chaos_memory_test_mmap(
    void *address, size_t length, int protection, int flags, int fd, off_t offset
)
{
    (void)address;
    (void)protection;
    (void)fd;
    (void)offset;

    ++g_real_mmap_calls;
    g_last_mmap_flags = flags;
    g_last_length = length;
    if (g_real_mmap_error != 0)
    {
        errno = g_real_mmap_error;
        return MAP_FAILED;
    }
    return g_real_mmap_result;
}

static int chaos_memory_test_munmap(void *address, size_t length)
{
    ++g_real_munmap_calls;
    g_last_munmap_address = address;
    g_last_length = length;
    if (g_real_munmap_error != 0)
    {
        errno = g_real_munmap_error;
        return -1;
    }
    return 0;
}

static int chaos_memory_test_mprotect(void *address, size_t length, int protection)
{
    (void)address;

    ++g_real_mprotect_calls;
    g_last_length = length;
    g_last_mprotect_prot = protection;
    if (g_real_mprotect_error != 0)
    {
        errno = g_real_mprotect_error;
        return -1;
    }
    return 0;
}

static int chaos_memory_test_madvise(void *address, size_t length, int advice)
{
    (void)address;

    ++g_real_madvise_calls;
    g_last_length = length;
    g_last_madvise_advice = advice;
    if (g_real_madvise_error != 0)
    {
        errno = g_real_madvise_error;
        return -1;
    }
    return 0;
}

#include "../../src/memory/chaos_memory_hooks.c"

static void test_call_real_helpers(void)
{
    reset_wrapper_state();
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;

    assert(
        chaos_memory_call_real_mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
        g_real_mmap_result
    );
    assert(g_real_mmap_calls == 1);
    assert(g_last_mmap_flags == (MAP_PRIVATE | MAP_ANONYMOUS));
    assert(g_last_length == 4096U);

    assert(chaos_memory_call_real_munmap((void *)(uintptr_t)0x2000U, 4096U) == 0);
    assert(g_real_munmap_calls == 1);
    assert(g_last_munmap_address == (void *)(uintptr_t)0x2000U);
    assert(g_last_length == 4096U);

    assert(chaos_memory_call_real_mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == 0);
    assert(g_real_mprotect_calls == 1);
    assert(g_last_mprotect_prot == PROT_READ);

    assert(chaos_memory_call_real_madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == 0);
    assert(g_real_madvise_calls == 1);
    assert(g_last_madvise_advice == 7);
}

static void test_mmap_paths(void)
{
    reset_wrapper_state();
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_chaos_memory_tls_guard = 1;
    assert(mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == g_real_mmap_result);
    assert(g_real_mmap_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_stub_match[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MMAP] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MMAP].effect =
        CHAOS_MEMORY_EFFECT_LATENCY;
    assert(mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == g_real_mmap_result);
    assert(g_latency_calls == 1);
    assert(g_real_mmap_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MMAP] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MMAP].effect =
        CHAOS_MEMORY_EFFECT_ERRNO;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MMAP].errnum = ENOMEM;
    g_errno_trigger = 1;
    errno = 0;
    assert(mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED);
    assert(errno == ENOMEM);
    assert(g_real_mmap_calls == 0);

    reset_wrapper_state();
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_real_mmap_error = EINVAL;
    errno = 0;
    assert(mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED);
    assert(errno == EINVAL);
}

static void test_munmap_paths(void)
{
    reset_wrapper_state();
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_chaos_memory_tls_guard = 1;
    assert(munmap((void *)(uintptr_t)0x2000U, 4096U) == 0);
    assert(g_real_munmap_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_stub_match[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MUNMAP] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MUNMAP].effect =
        CHAOS_MEMORY_EFFECT_LATENCY;
    assert(munmap((void *)(uintptr_t)0x2000U, 4096U) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_munmap_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MUNMAP] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MUNMAP].effect =
        CHAOS_MEMORY_EFFECT_ERRNO;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MUNMAP].errnum = EINVAL;
    g_errno_trigger = 1;
    errno = 0;
    assert(munmap((void *)(uintptr_t)0x2000U, 4096U) == -1);
    assert(errno == EINVAL);
    assert(g_real_munmap_calls == 0);

    reset_wrapper_state();
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_real_munmap_error = ENOMEM;
    errno = 0;
    assert(munmap((void *)(uintptr_t)0x2000U, 4096U) == -1);
    assert(errno == ENOMEM);
}

static void test_mprotect_paths(void)
{
    reset_wrapper_state();
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_chaos_memory_tls_guard = 1;
    assert(mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == 0);
    assert(g_real_mprotect_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_stub_match[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MPROTECT] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MPROTECT].effect =
        CHAOS_MEMORY_EFFECT_LATENCY;
    assert(mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_mprotect_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MPROTECT] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MPROTECT].effect =
        CHAOS_MEMORY_EFFECT_ERRNO;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MPROTECT].errnum = EACCES;
    g_errno_trigger = 1;
    errno = 0;
    assert(mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == -1);
    assert(errno == EACCES);
    assert(g_real_mprotect_calls == 0);

    reset_wrapper_state();
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_real_mprotect_error = EFAULT;
    errno = 0;
    assert(mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == -1);
    assert(errno == EFAULT);
}

static void test_madvise_paths(void)
{
    reset_wrapper_state();
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;
    g_chaos_memory_tls_guard = 1;
    assert(madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == 0);
    assert(g_real_madvise_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;
    g_stub_match[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MADVISE] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MADVISE].effect =
        CHAOS_MEMORY_EFFECT_LATENCY;
    assert(madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_madvise_calls == 1);

    reset_wrapper_state();
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;
    g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE].effect =
        CHAOS_MEMORY_EFFECT_ERRNO;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE].errnum = EINVAL;
    g_errno_trigger = 1;
    errno = 0;
    assert(madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == -1);
    assert(errno == EINVAL);
    assert(g_real_madvise_calls == 0);

    reset_wrapper_state();
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;
    g_real_madvise_error = ENOMEM;
    errno = 0;
    assert(madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == -1);
    assert(errno == ENOMEM);
}

int main(void)
{
    test_call_real_helpers();
    test_mmap_paths();
    test_munmap_paths();
    test_mprotect_paths();
    test_madvise_paths();
    return 0;
}
