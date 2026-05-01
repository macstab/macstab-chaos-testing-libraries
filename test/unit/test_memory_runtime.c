/**
 * @file test_memory_runtime.c
 * @brief Unit tests for the MEMORY-domain constructor: symbol resolution, seed material,
 *   and function-pointer table wiring.
 *
 * Subsystem under test: `src/memory/chaos_memory.c` (the `chaos_memory_init()` constructor).
 *
 * Coverage approach:
 * - All six intercepted symbols (mmap, munmap, mprotect, madvise, nanosleep, usleep) are
 *   mapped to local stubs via a test-controlled `dlsym` stub.
 * - `dlerror`, `abort`, and (on Linux) `syscall` are overridden via `#define` before
 *   `chaos_memory.c` is included, exercising the constructor without LD_PRELOAD.
 * - On Linux, the raw-syscall stub delivers a deterministic 8-byte seed value
 *   (0x1122334455667788) to test the exact stored process_seed.
 * - The abort path is intercepted via `setjmp`/`longjmp` to verify fatal-error behaviour.
 *
 * Properties under test:
 * - `chaos_memory_resolve_symbol()`: pointer wired correctly; `dlerror()` called once.
 * - `chaos_memory_read_seed_material()` (Linux): returns 0x1122334455667788; exactly
 *   one openat, one read, one close raw syscall.
 * - `chaos_memory_read_seed_material()` (non-Linux): returns a non-zero value.
 * - Abort path: unresolvable symbol triggers `abort()`.
 * - Linux seed fallback: open failure → PID-based fallback; short read → same fallback.
 * - `chaos_memory_init()`: all six real-function-pointer globals wired; config_init called
 *   once; process_seed and tls_prng_state non-zero.
 *
 * What is NOT tested here:
 * - mmap/mprotect/madvise wrapper call paths (tested in test_chaos_memory.c).
 * - Config file loading or rule matching.
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Number of times `chaos_memory_config_init()` stub was called. */
static int g_config_init_calls = 0;
/** @brief Number of times the `dlerror` stub was called. */
static int g_dlerror_calls = 0;
/** @brief Error string returned by the `dlerror` stub; NULL means no error. */
static const char *g_dlerror_text = NULL;
/** @brief `setjmp` buffer used to return from an expected `abort()`. */
static jmp_buf g_abort_env;
/** @brief Non-zero when the test expects `abort()` to be called. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief SYS_openat dispatch count. */
static int g_syscall_open_calls = 0;
/** @brief SYS_read dispatch count. */
static int g_syscall_read_calls = 0;
/** @brief SYS_close dispatch count. */
static int g_syscall_close_calls = 0;
/** @brief When non-zero, causes SYS_openat to return -1. */
static int g_force_open_fail = 0;
/** @brief When non-zero, causes SYS_read to return sizeof(seed)-1 (short read). */
static int g_force_short_read = 0;
#endif

/**
 * @brief Reset all test-local and runtime globals before each test function.
 */
static void reset_test_state(void)
{
    chaos_memory_test_reset_runtime();
    g_config_init_calls = 0;
    g_dlerror_calls = 0;
    g_dlerror_text = NULL;
    g_expect_abort = 0;
#ifdef __linux__
    g_syscall_open_calls = 0;
    g_syscall_read_calls = 0;
    g_syscall_close_calls = 0;
    g_force_open_fail = 0;
    g_force_short_read = 0;
#endif
}

/* -------------------------------------------------------------------------
 * Stub implementations for the six intercepted functions
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for `mmap(2)`. Returns a fixed non-NULL address (0x12345000).
 *
 * The fixed address is chosen to be page-aligned and non-zero so that callers
 * which check for MAP_FAILED (== (void*)-1) do not treat it as an error.
 */
static void *
stub_mmap(void *address, size_t length, int protection, int flags, int fd, off_t offset)
{
    (void)address;
    (void)length;
    (void)protection;
    (void)flags;
    (void)fd;
    (void)offset;
    return (void *)(uintptr_t)0x12345000U;
}

/** @brief Stub for `munmap(2)`. Returns 0 (success). */
static int stub_munmap(void *address, size_t length)
{
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `mprotect(2)`. Returns 0 (success). */
static int stub_mprotect(void *address, size_t length, int protection)
{
    (void)address;
    (void)length;
    (void)protection;
    return 0;
}

/** @brief Stub for `madvise(2)`. Returns 0 (success). */
static int stub_madvise(void *address, size_t length, int advice)
{
    (void)address;
    (void)length;
    (void)advice;
    return 0;
}

/** @brief Stub for `nanosleep(2)`. Returns 0 (success, no sleep). */
static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)request;
    (void)remaining;
    return 0;
}

/** @brief Stub for `usleep(3)`. Returns 0 (success, no sleep). */
static int stub_usleep(useconds_t usec)
{
    (void)usec;
    return 0;
}

/**
 * @brief Stub for `chaos_memory_config_init()`.
 *
 * Increments the call counter to verify the constructor calls it exactly once.
 */
void chaos_memory_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for `dlerror()`.
 *
 * Returns `g_dlerror_text` and increments `g_dlerror_calls`. The call count
 * verifies that the production resolver calls `dlerror()` once per symbol.
 */
static char *chaos_memory_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Stub for `dlsym(RTLD_NEXT, symbol)`.
 *
 * Maps each of the six expected symbol names to the corresponding stub function
 * via `CHAOS_MEMORY_TEST_DLSYM_RESULT`. Returns NULL for unrecognised symbols.
 */
static void *chaos_memory_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "mmap") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_mmap_fn, stub_mmap);
    if (strcmp(symbol, "munmap") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_munmap_fn, stub_munmap);
    if (strcmp(symbol, "mprotect") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_mprotect_fn, stub_mprotect);
    if (strcmp(symbol, "madvise") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_madvise_fn, stub_madvise);
    if (strcmp(symbol, "nanosleep") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_nanosleep_fn, stub_nanosleep);
    if (strcmp(symbol, "usleep") == 0)
        return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_usleep_fn, stub_usleep);
    return NULL;
}

#ifdef __linux__
/**
 * @brief Stub for `syscall(2)` used by the constructor to read `/dev/urandom`.
 *
 * Delivers seed `0x1122334455667788` on a successful SYS_read. Returns -1 for
 * SYS_openat when `g_force_open_fail != 0`. Returns `sizeof(seed)-1` for SYS_read
 * when `g_force_short_read != 0`.
 */
static long chaos_memory_test_syscall(long number, ...)
{
    if (number == SYS_openat)
    {
        ++g_syscall_open_calls;
        if (g_force_open_fail != 0)
        {
            return -1;
        }
        return 9;
    }
    if (number == SYS_read)
    {
        va_list args;
        int fd;
        void *buffer;
        size_t size;
        uint64_t seed = UINT64_C(0x1122334455667788);

        ++g_syscall_read_calls;
        va_start(args, number);
        fd = va_arg(args, int);
        buffer = va_arg(args, void *);
        size = va_arg(args, size_t);
        va_end(args);
        assert(fd == 9);
        assert(size == sizeof(seed));
        (void)memcpy(buffer, &seed, sizeof(seed));
        if (g_force_short_read != 0)
        {
            return (long)(sizeof(seed) - 1U);
        }
        return (long)sizeof(seed);
    }
    if (number == SYS_close)
    {
        ++g_syscall_close_calls;
        return 0;
    }

    return -1;
}
#endif

/**
 * @brief Stub for `abort()`.
 *
 * When `g_expect_abort != 0`, uses `longjmp` to return to the test's `setjmp`
 * frame. An unexpected abort triggers `assert(!"unexpected abort")` to produce a
 * clear failure rather than silently hanging.
 */
static void chaos_memory_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

/* -------------------------------------------------------------------------
 * Symbol overrides and production source inclusion
 * --------------------------------------------------------------------- */

#define dlsym chaos_memory_test_dlsym
#define dlerror chaos_memory_test_dlerror
#define abort chaos_memory_test_abort
#ifdef __linux__
#define syscall chaos_memory_test_syscall
#endif
#include "../../src/memory/chaos_memory.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

/* -------------------------------------------------------------------------
 * Test functions
 * --------------------------------------------------------------------- */

/**
 * @brief Invariant: `chaos_memory_resolve_symbol()` wires a pointer and reads a valid seed.
 *
 * Triggering condition: `chaos_memory_resolve_symbol(&mmap_fn, "mmap")` with clean state.
 *
 * Expected observable behaviour:
 * - `mmap_fn` is set to `stub_mmap`.
 * - `g_dlerror_calls == 1`.
 * - On Linux: `chaos_memory_read_seed_material()` returns 0x1122334455667788; exactly
 *   one of each raw syscall is issued.
 * - Non-Linux: returns a non-zero value.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_memory_mmap_fn mmap_fn = NULL;

    reset_test_state();
    chaos_memory_resolve_symbol(&mmap_fn, "mmap");
    assert(mmap_fn == stub_mmap);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_memory_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_memory_read_seed_material() != 0U);
#endif
}

/**
 * @brief Invariant: `chaos_memory_resolve_symbol()` calls `abort()` for a missing symbol.
 *
 * Triggering condition: `g_dlerror_text = "missing"` with an unrecognised symbol name
 *   causes the production resolver to call `abort()`.
 *
 * Expected observable behaviour: `longjmp` transfers control out of the setjmp block;
 *   the assertion on the next line is never reached.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_memory_mmap_fn mmap_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_memory_resolve_symbol(&mmap_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Invariant: seed fallback paths produce PID-based seeds when /dev/urandom fails.
 *
 * Triggering conditions:
 * - `g_force_open_fail = 1`: open fails; no read or close attempted.
 * - `g_force_short_read = 1`: read returns one fewer byte than expected; close is called.
 *
 * Expected observable behaviour: both paths return `0x6a09e667f3bcc909 XOR getpid()`.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_memory_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_memory_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Invariant: `chaos_memory_init()` wires all six function pointers and seeds the PRNG.
 *
 * Triggering condition: `chaos_memory_init()` called after `reset_test_state()`.
 *
 * Expected observable behaviour:
 * - All six `g_chaos_memory_real_*` globals equal their stub counterparts.
 * - `g_config_init_calls` increments by 1.
 * - `g_chaos_memory_process_seed != 0` and `g_chaos_memory_tls_prng_state != 0`.
 */
static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    chaos_memory_init();
    assert(g_chaos_memory_real_mmap == stub_mmap);
    assert(g_chaos_memory_real_munmap == stub_munmap);
    assert(g_chaos_memory_real_mprotect == stub_mprotect);
    assert(g_chaos_memory_real_madvise == stub_madvise);
    assert(g_chaos_memory_real_nanosleep == stub_nanosleep);
    assert(g_chaos_memory_real_usleep == stub_usleep);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_memory_process_seed != 0U);
    assert(g_chaos_memory_tls_prng_state != 0U);
}

int main(void)
{
    test_resolve_symbol_and_seed_helpers();
    test_resolve_symbol_abort_path();
#ifdef __linux__
    test_seed_fallback_paths();
#endif
    test_constructor_init();
    return 0;
}
