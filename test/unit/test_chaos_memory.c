/**
 * @file test_chaos_memory.c
 * @brief Integration tests for MEMORY-domain wrapper call paths: mmap, munmap, mprotect,
 *   and madvise.
 *
 * Subsystem under test: `src/memory/chaos_memory_hooks.c`
 *
 * Coverage approach:
 * - The production source is included directly after providing stub implementations for
 *   `chaos_memory_config_match`, `chaos_memory_rule_apply_latency`, and
 *   `chaos_memory_rule_apply_errno`. The four real-function globals are wired to local
 *   stubs via `reset_wrapper_state()` rather than through `dlsym`.
 * - A 2×4 stub rule table (`g_stub_rules[effect][operation]`) controls which effect is
 *   returned for a given (effect, operation) pair so tests can drive each wrapper path
 *   without config-file I/O.
 * - `g_errno_trigger` controls whether `chaos_memory_rule_apply_errno` actually fires,
 *   decoupling rule matching from errno injection.
 * - `g_real_mmap_result` is a non-NULL, non-MAP_FAILED address (0x12345000) that stubs
 *   return on success to satisfy MAP_FAILED checks in the wrappers.
 *
 * Properties under test:
 * - `chaos_memory_call_real_mmap/munmap/mprotect/madvise()` pass arguments through to the
 *   real-function stubs and capture flags, address, length, prot, and advice correctly.
 * - mmap passthrough: TLS guard set → real mmap called; guard clear → wrapper logic runs.
 * - mmap latency: LATENCY effect → `g_latency_calls == 1`; real mmap called.
 * - mmap errno injection: ERRNO effect with trigger → MAP_FAILED returned; errno=ENOMEM;
 *   real mmap not called.
 * - mmap real error: no rule matched + `g_real_mmap_error=EINVAL` → MAP_FAILED; errno=EINVAL.
 * - munmap passthrough: TLS guard set → real munmap called.
 * - munmap latency / errno / real error: same pattern as mmap.
 * - mprotect passthrough: TLS guard set → real mprotect called.
 * - mprotect latency / errno / real error: same pattern as mmap.
 * - madvise passthrough: TLS guard set → real madvise called.
 * - madvise latency / errno / real error: same pattern as mmap.
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection (tested in test_memory_config.c).
 * - Constructor and symbol resolution (tested in test_memory_runtime.c).
 * - Action helpers (tested in test_memory_actions.c).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

/**
 * @brief Stub rule table indexed by [effect][operation].
 *
 * Effect indices: 0=ERRNO, 1=LATENCY. Operation indices: 0=MMAP, 1=MPROTECT, 2=MADVISE,
 * 3=MUNMAP. Rules are pre-populated by individual tests before calling wrappers.
 */
static chaos_memory_rule_t g_stub_rules[2][4];
/**
 * @brief Match-enable table parallel to `g_stub_rules`.
 *
 * A zero entry causes `chaos_memory_config_match` to return 0 (no match) regardless of
 * the rule contents.
 */
static int g_stub_match[2][4];
/** @brief Number of times `chaos_memory_rule_apply_latency` stub was called. */
static int g_latency_calls = 0;
/**
 * @brief When non-zero, `chaos_memory_rule_apply_errno` injects the rule's errnum.
 *
 * Decouples rule matching from actual errno injection so tests can match a rule but
 * still let the real call proceed.
 */
static int g_errno_trigger = 0;
/** @brief Number of times the mmap stub was called. */
static int g_real_mmap_calls = 0;
/** @brief When non-zero, the mmap stub sets errno to this value and returns MAP_FAILED. */
static int g_real_mmap_error = 0;
/** @brief Number of times the munmap stub was called. */
static int g_real_munmap_calls = 0;
/** @brief When non-zero, the munmap stub sets errno to this value and returns -1. */
static int g_real_munmap_error = 0;
/** @brief Number of times the mprotect stub was called. */
static int g_real_mprotect_calls = 0;
/** @brief When non-zero, the mprotect stub sets errno to this value and returns -1. */
static int g_real_mprotect_error = 0;
/** @brief Number of times the madvise stub was called. */
static int g_real_madvise_calls = 0;
/** @brief When non-zero, the madvise stub sets errno to this value and returns -1. */
static int g_real_madvise_error = 0;
/** @brief MAP_PRIVATE|MAP_ANONYMOUS flags captured by the last mmap stub call. */
static int g_last_mmap_flags = 0;
/** @brief Address argument captured by the last munmap stub call. */
static void *g_last_munmap_address = NULL;
/** @brief Protection bits captured by the last mprotect stub call. */
static int g_last_mprotect_prot = 0;
/** @brief Advice value captured by the last madvise stub call. */
static int g_last_madvise_advice = 0;
/** @brief Length argument captured by the most recent real-function stub call. */
static size_t g_last_length = 0U;
/**
 * @brief Address returned by the mmap stub on success.
 *
 * Fixed to 0x12345000, a page-aligned non-NULL non-MAP_FAILED address, so that
 * callers which check for MAP_FAILED can distinguish success from error.
 */
static void *g_real_mmap_result = (void *)(uintptr_t)0x12345000U;

/**
 * @brief Reset all wrapper test state between test functions.
 *
 * Clears all stub rule and match tables, call counters, error flags, and
 * captured argument values. Calls `chaos_memory_test_reset_runtime()` to restore
 * function-pointer globals to NULL.
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
 * @brief Stub for `chaos_memory_config_match`.
 *
 * Looks up `g_stub_match[effect][operation]`; if set, copies the corresponding
 * rule into @p rule and returns 1. Also captures `mmap_flags` into `g_last_mmap_flags`
 * when the operation is MMAP so tests can verify the flags forwarded to the config layer.
 *
 * @param effect     Effect to look up.
 * @param operation  Operation to look up.
 * @param mmap_flags MAP_* flags; relevant only for MMAP operations.
 * @param rule       Output rule populated on match.
 * @return 1 if matched, 0 otherwise.
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

/**
 * @brief Stub for `chaos_memory_rule_apply_latency`.
 *
 * Increments `g_latency_calls` without sleeping.
 *
 * @param rule  Must be non-NULL (asserted).
 */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_memory_rule_apply_errno`.
 *
 * When `g_errno_trigger != 0` and the rule carries effect=ERRNO, sets errno to
 * `rule->errnum` and returns 1. Otherwise returns 0 without modifying errno.
 *
 * @param rule  Rule to examine.
 * @return 1 if errno was injected, 0 otherwise.
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

/**
 * @brief Stub for the real `mmap(2)`.
 *
 * Captures `flags` and `length`, increments `g_real_mmap_calls`. Returns `g_real_mmap_result`
 * on success or MAP_FAILED with `errno = g_real_mmap_error` when that flag is set.
 */
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

/**
 * @brief Stub for the real `munmap(2)`.
 *
 * Captures address and length, increments `g_real_munmap_calls`. Returns -1 with injected
 * errno when `g_real_munmap_error` is set.
 */
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

/**
 * @brief Stub for the real `mprotect(2)`.
 *
 * Captures length and protection, increments `g_real_mprotect_calls`. Returns -1 with
 * injected errno when `g_real_mprotect_error` is set.
 */
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

/**
 * @brief Stub for the real `madvise(2)`.
 *
 * Captures length and advice, increments `g_real_madvise_calls`. Returns -1 with
 * injected errno when `g_real_madvise_error` is set.
 */
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

/**
 * @brief Invariant: `chaos_memory_call_real_*` helpers forward arguments correctly.
 *
 * Triggering condition: direct calls to all four `call_real_*` helpers with specific
 *   arguments and real-function stubs wired.
 *
 * Expected observable behaviour:
 * - `call_real_mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`:
 *   returns `g_real_mmap_result`; flags=MAP_PRIVATE|MAP_ANONYMOUS; length=4096.
 * - `call_real_munmap(0x2000, 4096)`: returns 0; address=0x2000; length=4096.
 * - `call_real_mprotect(0x1000, 4096, PROT_READ)`: returns 0; prot=PROT_READ.
 * - `call_real_madvise(0x1000, 4096, 7)`: returns 0; advice=7.
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

    /* Cover the NULL-pointer guard paths in each call-real helper. */
    reset_wrapper_state();
    errno = 0;
    assert(chaos_memory_call_real_mmap(NULL, 4096U, PROT_READ, MAP_PRIVATE, -1, 0) == MAP_FAILED);
    assert(errno == ENOMEM);
    assert(g_real_mmap_calls == 0);

    errno = 0;
    assert(chaos_memory_call_real_munmap((void *)(uintptr_t)0x1000U, 4096U) == -1);
    assert(errno == ENOMEM);
    assert(g_real_munmap_calls == 0);

    errno = 0;
    assert(chaos_memory_call_real_mprotect((void *)(uintptr_t)0x1000U, 4096U, PROT_READ) == -1);
    assert(errno == ENOMEM);
    assert(g_real_mprotect_calls == 0);

    errno = 0;
    assert(chaos_memory_call_real_madvise((void *)(uintptr_t)0x1000U, 4096U, 0) == -1);
    assert(errno == ENOMEM);
    assert(g_real_madvise_calls == 0);
}

/**
 * @brief Invariant: the mmap wrapper respects the TLS guard, applies latency, injects errno,
 *   and propagates real errors.
 *
 * Triggering conditions:
 * - TLS guard set → passthrough to real mmap.
 * - LATENCY rule matched → latency applied; real mmap called; returns success.
 * - ERRNO rule with trigger → MAP_FAILED returned; errno=ENOMEM; real mmap not called.
 * - No rule + `g_real_mmap_error=EINVAL` → MAP_FAILED returned; errno=EINVAL.
 *
 * Expected observable behaviour: call counts and errno values match predictions above.
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
 * @brief Invariant: the munmap wrapper respects the TLS guard, applies latency, injects errno,
 *   and propagates real errors.
 *
 * Triggering conditions: same pattern as `test_mmap_paths` but for munmap.
 *
 * Expected observable behaviour:
 * - TLS guard → passthrough.
 * - LATENCY → latency applied; real munmap called; returns 0.
 * - ERRNO with trigger → -1; errno=EINVAL; real munmap not called.
 * - Real error `g_real_munmap_error=ENOMEM` → -1; errno=ENOMEM.
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
 * @brief Invariant: the mprotect wrapper respects the TLS guard, applies latency, injects errno,
 *   and propagates real errors.
 *
 * Triggering conditions: same pattern as `test_mmap_paths` but for mprotect.
 *
 * Expected observable behaviour:
 * - TLS guard → passthrough.
 * - LATENCY → latency applied; real mprotect called; returns 0.
 * - ERRNO with trigger → -1; errno=EACCES; real mprotect not called.
 * - Real error `g_real_mprotect_error=EFAULT` → -1; errno=EFAULT.
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
 * @brief Invariant: the madvise wrapper respects the TLS guard, applies latency, injects errno,
 *   and propagates real errors.
 *
 * Triggering conditions: same pattern as `test_mmap_paths` but for madvise.
 *
 * Expected observable behaviour:
 * - TLS guard → passthrough.
 * - LATENCY → latency applied; real madvise called; returns 0.
 * - ERRNO with trigger → -1; errno=EINVAL; real madvise not called.
 * - Real error `g_real_madvise_error=ENOMEM` → -1; errno=ENOMEM.
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

int main(void)
{
    test_call_real_helpers();
    test_mmap_paths();
    test_munmap_paths();
    test_mprotect_paths();
    test_madvise_paths();
    return 0;
}
