/**
 * @file test_time_runtime.c
 * @brief Unit tests for the TIME-domain constructor: symbol resolution, seed material,
 *   and function-pointer table wiring.
 *
 * Subsystem under test: `src/time/chaos_time.c` (the `chaos_time_init()` constructor).
 *
 * Coverage approach:
 * - All three intercepted symbols (clock_gettime, nanosleep, usleep) are mapped to local
 *   stubs via a test-controlled `dlsym` stub.
 * - `dlerror`, `abort`, and (on Linux) `syscall` are overridden via `#define` before
 *   `chaos_time.c` is included, exercising the constructor without LD_PRELOAD.
 * - On Linux, the raw-syscall stub delivers a deterministic 8-byte seed value
 *   (0x1122334455667788) to verify the exact stored `process_seed`.
 * - The abort path is intercepted via `setjmp`/`longjmp` to verify fatal-error behaviour.
 *
 * Properties under test:
 * - `chaos_time_resolve_symbol()`: pointer wired correctly; `dlerror()` called once.
 * - `chaos_time_read_seed_material()` (Linux): returns 0x1122334455667788; exactly
 *   one openat, one read, one close raw syscall.
 * - `chaos_time_read_seed_material()` (non-Linux): returns a non-zero value.
 * - Abort path: unresolvable symbol triggers `abort()`.
 * - Linux seed fallback: open failure → PID-based fallback; short read → same fallback.
 * - `chaos_time_init()`: all three real-function-pointer globals wired; config_init called
 *   once; process_seed and tls_prng_state non-zero.
 *
 * What is NOT tested here:
 * - Config file loading or rule matching.
 * - TIME wrapper call paths (tested in test_chaos_time.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Number of times `chaos_time_config_init()` stub was called. */
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
    chaos_time_test_reset_runtime();
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

/** @brief Stub for `clock_gettime(2)`. Returns 0 without modifying @p value. */
static int stub_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    (void)clock_id;
    (void)value;
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
 * @brief Stub for `chaos_time_config_init()`.
 *
 * Increments the call counter to verify the constructor calls it exactly once.
 */
void chaos_time_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for `dlerror()`.
 *
 * Returns `g_dlerror_text` and increments `g_dlerror_calls`. The call count
 * verifies that the production resolver calls `dlerror()` once per symbol.
 */
static char *chaos_time_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Stub for `dlsym(RTLD_NEXT, symbol)`.
 *
 * Maps each of the three expected symbol names to the corresponding stub via
 * `CHAOS_TIME_TEST_DLSYM_RESULT`. Returns NULL for unrecognised symbols, which triggers
 * the abort path in the production resolver.
 */
static void *chaos_time_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "clock_gettime") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_clock_gettime_fn, stub_clock_gettime);
    if (strcmp(symbol, "nanosleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_nanosleep_fn, stub_nanosleep);
    if (strcmp(symbol, "usleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_usleep_fn, stub_usleep);
    return NULL;
}

#ifdef __linux__
/**
 * @brief Stub for `syscall(2)` used by the constructor to read `/dev/urandom`.
 *
 * Delivers seed `0x1122334455667788` on a successful SYS_read. Returns -1 for
 * SYS_openat when `g_force_open_fail != 0`. Returns `sizeof(seed)-1` for SYS_read
 * when `g_force_short_read != 0` (triggering the PID-based fallback path).
 */
static long chaos_time_test_syscall(long number, ...)
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
 * frame. An unexpected abort triggers `assert(!"unexpected abort")`.
 */
static void chaos_time_test_abort(void)
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

#define dlsym chaos_time_test_dlsym
#define dlerror chaos_time_test_dlerror
#define abort chaos_time_test_abort
#ifdef __linux__
#define syscall chaos_time_test_syscall
#endif
#include "../../src/time/chaos_time.c"
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
 * @brief Invariant: `chaos_time_resolve_symbol()` wires a pointer and reads a valid seed.
 *
 * Triggering condition: `chaos_time_resolve_symbol(&clock_gettime_fn, "clock_gettime")`
 *   with clean state.
 *
 * Expected observable behaviour:
 * - `clock_gettime_fn` is set to `stub_clock_gettime`.
 * - `g_dlerror_calls == 1`.
 * - On Linux: `chaos_time_read_seed_material()` returns 0x1122334455667788; exactly
 *   one of each raw syscall is issued.
 * - Non-Linux: returns a non-zero value.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_time_clock_gettime_fn clock_gettime_fn = NULL;

    reset_test_state();
    chaos_time_resolve_symbol(&clock_gettime_fn, "clock_gettime");
    assert(clock_gettime_fn == stub_clock_gettime);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_time_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_time_read_seed_material() != 0U);
#endif
}

/**
 * @brief Invariant: `chaos_time_resolve_symbol()` calls `abort()` for a missing symbol.
 *
 * Triggering condition: `g_dlerror_text = "missing"` with an unrecognised symbol name.
 *
 * Expected observable behaviour: `longjmp` transfers control out of the setjmp block.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_time_clock_gettime_fn clock_gettime_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_time_resolve_symbol(&clock_gettime_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Invariant: seed fallback paths produce PID-based seeds when /dev/urandom fails.
 *
 * Triggering conditions:
 * - `g_force_open_fail = 1`: no read or close attempted.
 * - `g_force_short_read = 1`: read returns one fewer byte; close is still called.
 *
 * Expected observable behaviour: both paths return `0x6a09e667f3bcc909 XOR getpid()`.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_time_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_time_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Invariant: `chaos_time_init()` wires all three function pointers and seeds the PRNG.
 *
 * Triggering condition: `chaos_time_init()` called after `reset_test_state()`.
 *
 * Expected observable behaviour:
 * - `g_chaos_time_real_clock_gettime == stub_clock_gettime`.
 * - `g_chaos_time_real_nanosleep == stub_nanosleep`.
 * - `g_chaos_time_real_usleep == stub_usleep`.
 * - `g_config_init_calls` increments by 1.
 * - `g_chaos_time_process_seed != 0` and `g_chaos_time_tls_prng_state != 0`.
 */
static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    chaos_time_init();
    assert(g_chaos_time_real_clock_gettime == stub_clock_gettime);
    assert(g_chaos_time_real_nanosleep == stub_nanosleep);
    assert(g_chaos_time_real_usleep == stub_usleep);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_time_process_seed != 0U);
    assert(g_chaos_time_tls_prng_state != 0U);
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
