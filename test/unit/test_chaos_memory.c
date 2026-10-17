/**
 * @file test_chaos_memory.c
 * @brief Proves the libchaos-memory wrappers: mmap, munmap, mprotect, madvise and posix_madvise.
 *
 * @details
 * Unit under test: `src/memory/chaos_memory_hooks.c`, compiled into this binary by `#include`.
 * The test binary therefore exports the wrappers itself, and calls to `mmap` and friends in the
 * tests reach them directly, with no LD_PRELOAD.
 *
 * Isolation:
 * - chaos_memory_config_match() is replaced by a lookup in `g_stub_rules[effect][operation]`,
 *   enabled per entry by `g_stub_match`, so each wrapper path is selected without a rule file.
 * - chaos_memory_rule_apply_latency() only counts calls; chaos_memory_rule_apply_errno() fires
 *   only while `g_errno_trigger` is set, so a matched rule that does not fire is testable.
 * - Each test points the real-function pointers at local stubs that count calls, record
 *   arguments and can fail with a chosen errno. `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` makes
 *   chaos_memory_ensure_symbols() a no-op, so the wrappers never replace those pointers.
 * - test_call_real_helpers() leaves the pointers NULL on purpose to drive the raw system-call
 *   fallback, so that part maps and unmaps one real page.
 *
 * Not covered here: rule parsing and selection (test_memory_config.c), the constructor
 * (test_memory_runtime.c) and the trigger gate and effects (test_memory_actions.c).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

/** @brief Rule the match stub returns, indexed by the effect and operation enum values. */
static chaos_memory_rule_t g_stub_rules[2][4];
/** @brief Non-zero entries make the match stub report a match for that effect and operation. */
static int g_stub_match[2][4];
/** @brief LATENCY applications since the last reset. */
static int g_latency_calls = 0;
/** @brief Non-zero: a matched ERRNO rule fires; zero models its probability not firing. */
static int g_errno_trigger = 0;
/** @brief Real mmap calls. */
static int g_real_mmap_calls = 0;
/** @brief Non-zero: the real mmap fails with this errno. */
static int g_real_mmap_error = 0;
/** @brief Real munmap calls. */
static int g_real_munmap_calls = 0;
/** @brief Non-zero: the real munmap fails with this errno. */
static int g_real_munmap_error = 0;
/** @brief Real mprotect calls. */
static int g_real_mprotect_calls = 0;
/** @brief Non-zero: the real mprotect fails with this errno. */
static int g_real_mprotect_error = 0;
/** @brief Real madvise calls. */
static int g_real_madvise_calls = 0;
/** @brief Non-zero: the real madvise fails with this errno. */
static int g_real_madvise_error = 0;
/** @brief mmap flags last seen by the match stub or the real mmap. */
static int g_last_mmap_flags = 0;
/** @brief Address the real munmap last received. */
static void *g_last_munmap_address = NULL;
/** @brief Protection the real mprotect last received. */
static int g_last_mprotect_prot = 0;
/** @brief Advice the real madvise last received. */
static int g_last_madvise_advice = 0;
/** @brief Length the last real mmap, munmap, mprotect or madvise received. */
static size_t g_last_length = 0U;
/** @brief Real mmap's success result: page-aligned, neither NULL nor MAP_FAILED. */
static void *g_real_mmap_result = (void *)(uintptr_t)0x12345000U;

/**
 * @brief Clears the rule tables, counters, failure switches and recorded arguments, and NULLs the
 *        real-function pointers and the reentrancy guard.
 */
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

/**
 * @brief Replaces rule lookup: returns the table entry when enabled, 1 on a match.
 *
 * @details Out-of-range enum values and a NULL out-rule report no match rather than index past
 * the table. The mmap flags are recorded because selector matching depends on MAP_ANONYMOUS.
 */
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

/** @brief Replaces LATENCY: counts the application; the wrapper must pass a rule. */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Replaces ERRNO with the production contract: under `g_errno_trigger`, stores the
 *        rule's errnum and returns 1; otherwise returns 0 and leaves errno alone.
 */
int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }
    errno = rule->errnum;
    return 1;
}

/** @brief Real mmap stand-in: records flags and length; MAP_FAILED under the error switch. */
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

/** @brief Real munmap stand-in: records address and length; -1 under the error switch. */
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

/** @brief Real mprotect stand-in: records length and protection; -1 under the error switch. */
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

/** @brief Real madvise stand-in: records length and advice; -1 under the error switch. */
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

/** @brief Real posix_madvise calls; not cleared by reset_wrapper_state(). */
static int g_real_posix_madvise_calls = 0;

/** @brief Real posix_madvise stand-in: counts the call and succeeds. */
static int chaos_memory_test_posix_madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    ++g_real_posix_madvise_calls;
    return 0;
}

#include "../../src/memory/chaos_memory_hooks.c"

/**
 * @brief Proves the call-real helpers forward their arguments, and fall back to the system calls
 *        while the real functions are unresolved.
 *
 * @details
 * - Wired: each helper reaches its stub once with the arguments unchanged.
 * - Unresolved (NULL pointers, as during dlsym() when an allocator maps memory): the helpers
 *   issue the raw system calls on one real page, and report real kernel errors, never a made-up
 *   failure. munmap of the unaligned 0x1001 fails with EINVAL; mmap without MAP_ANONYMOUS on
 *   fd -1 fails with MAP_FAILED.
 * - The posix_madvise fallback returns the error number with errno unchanged, and treats
 *   POSIX_MADV_DONTNEED as a no-op as glibc and musl do: the written byte survives, where
 *   MADV_DONTNEED (the same value) would discard an anonymous page's content.
 * - No stub runs in the unresolved part.
 */
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

    /* Not resolved yet (a call from inside the symbol lookup): the system calls
     * themselves, never a made-up failure. */
    reset_wrapper_state();
    {
        void *page =
            chaos_memory_call_real_mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int saved;

        assert(page != MAP_FAILED);
        assert(chaos_memory_call_real_mprotect(page, 4096U, PROT_READ | PROT_WRITE) == 0);
        assert(chaos_memory_call_real_madvise(page, 4096U, MADV_NORMAL) == 0);
        assert(chaos_memory_call_real_posix_madvise(page, 4096U, POSIX_MADV_NORMAL) == 0);
        /* POSIX_MADV_DONTNEED is advice only: the page keeps what was written, which
         * MADV_DONTNEED (the same number) would have discarded. */
        ((volatile char *)page)[0] = 'x';
        assert(chaos_memory_call_real_posix_madvise(page, 4096U, POSIX_MADV_DONTNEED) == 0);
        assert(((volatile char *)page)[0] == 'x');
        assert(chaos_memory_call_real_munmap(page, 4096U) == 0);
        errno = 0;
        assert(chaos_memory_call_real_munmap((void *)(uintptr_t)0x1001U, 4096U) == -1);
        assert(errno == EINVAL);
        errno = 4242;
        saved = chaos_memory_call_real_posix_madvise((void *)(uintptr_t)0x1001U, 4096U, 0);
        assert(saved == EINVAL && errno == 4242);
        assert(
            chaos_memory_call_real_mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE, -1, 0) == MAP_FAILED
        );
    }
    assert(g_real_mmap_calls == 0 && g_real_munmap_calls == 0);
    assert(g_real_mprotect_calls == 0 && g_real_madvise_calls == 0);
}

/**
 * @brief Proves the four mmap paths: reentrant passthrough, LATENCY, ERRNO and real failure.
 *
 * @details With the reentrancy guard set the real mmap runs and no rule is consulted. LATENCY
 * delays and then calls the real mmap. A firing ERRNO rule returns MAP_FAILED with ENOMEM and
 * skips the real call, so no mapping is created. Without a rule, the real call's MAP_FAILED and
 * EINVAL reach the caller unchanged.
 */
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

/**
 * @brief Proves the same four paths for munmap: an injected EINVAL returns -1 without
 *        unmapping, and a real ENOMEM passes through.
 */
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

/**
 * @brief Proves the same four paths for mprotect: an injected EACCES returns -1 without changing
 *        protection, and a real EFAULT passes through.
 */
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

/**
 * @brief Proves the same four paths for madvise: an injected EINVAL returns -1 without advising,
 *        and a real ENOMEM passes through.
 */
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

/**
 * @brief Proves posix_madvise uses the `madvise` rules but keeps its own error convention.
 *
 * @details Under the guard and with no rule the real function runs. LATENCY delays and then
 * calls it. A firing ERRNO rule returns the error number (EAGAIN) and leaves errno at the
 * sentinel 4242, because posix_madvise reports failure by return value, not through errno.
 */
static void test_posix_madvise_paths(void)
{
    reset_wrapper_state();
    g_real_posix_madvise_calls = 0;
    g_chaos_memory_real_posix_madvise = chaos_memory_test_posix_madvise;
    g_chaos_memory_tls_guard = 1;
    assert(posix_madvise((void *)(uintptr_t)0x1000U, 4096U, POSIX_MADV_NORMAL) == 0);
    g_chaos_memory_tls_guard = 0;
    assert(posix_madvise((void *)(uintptr_t)0x1000U, 4096U, POSIX_MADV_NORMAL) == 0);
    assert(g_real_posix_madvise_calls == 2);

    reset_wrapper_state();
    g_real_posix_madvise_calls = 0;
    g_chaos_memory_real_posix_madvise = chaos_memory_test_posix_madvise;
    g_stub_match[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MADVISE] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_LATENCY][CHAOS_MEMORY_OP_MADVISE].effect =
        CHAOS_MEMORY_EFFECT_LATENCY;
    assert(posix_madvise((void *)(uintptr_t)0x1000U, 4096U, POSIX_MADV_NORMAL) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_posix_madvise_calls == 1);

    reset_wrapper_state();
    g_real_posix_madvise_calls = 0;
    g_chaos_memory_real_posix_madvise = chaos_memory_test_posix_madvise;
    g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE] = 1;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE].effect =
        CHAOS_MEMORY_EFFECT_ERRNO;
    g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][CHAOS_MEMORY_OP_MADVISE].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 4242;
    assert(posix_madvise((void *)(uintptr_t)0x1000U, 4096U, POSIX_MADV_NORMAL) == EAGAIN);
    assert(errno == 4242);
    assert(g_real_posix_madvise_calls == 0);
}

/**
 * @brief Proves a matched ERRNO rule whose probability does not fire leaves every wrapper to the
 *        real call, exactly once and with its success result.
 */
static void test_errno_rule_that_does_not_fire(void)
{
    int operation;

    reset_wrapper_state();
    g_real_posix_madvise_calls = 0;
    g_chaos_memory_real_mmap = chaos_memory_test_mmap;
    g_chaos_memory_real_munmap = chaos_memory_test_munmap;
    g_chaos_memory_real_mprotect = chaos_memory_test_mprotect;
    g_chaos_memory_real_madvise = chaos_memory_test_madvise;
    g_chaos_memory_real_posix_madvise = chaos_memory_test_posix_madvise;
    for (operation = CHAOS_MEMORY_OP_MMAP; operation <= CHAOS_MEMORY_OP_MUNMAP; ++operation)
    {
        g_stub_match[CHAOS_MEMORY_EFFECT_ERRNO][operation] = 1;
        g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][operation].effect = CHAOS_MEMORY_EFFECT_ERRNO;
        g_stub_rules[CHAOS_MEMORY_EFFECT_ERRNO][operation].errnum = ENOMEM;
    }
    g_errno_trigger = 0;

    assert(mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == g_real_mmap_result);
    assert(munmap((void *)(uintptr_t)0x2000U, 4096U) == 0);
    assert(mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == 0);
    assert(madvise((void *)(uintptr_t)0x1000U, 4096U, 7) == 0);
    assert(posix_madvise((void *)(uintptr_t)0x1000U, 4096U, POSIX_MADV_NORMAL) == 0);
    assert(g_real_mmap_calls == 1);
    assert(g_real_munmap_calls == 1);
    assert(g_real_mprotect_calls == 1);
    assert(g_real_madvise_calls == 1);
    assert(g_real_posix_madvise_calls == 1);
}

int main(void)
{
    test_call_real_helpers();
    test_mmap_paths();
    test_munmap_paths();
    test_mprotect_paths();
    test_madvise_paths();
    test_posix_madvise_paths();
    test_errno_rule_that_does_not_fire();
    return 0;
}
