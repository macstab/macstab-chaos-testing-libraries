/**
 * @file test_dns_runtime.c
 * @brief Unit tests for DNS-domain constructor initialisation, symbol resolution, and
 *   entropy seeding.
 *
 * Subsystem under test: `src/dns/chaos_dns.c`
 *
 * Coverage approach:
 * - The production source file is included directly after replacing four symbols via
 *   `#define`: `dlsym`, `dlerror`, `abort`, and (Linux only) `syscall`. The replacements
 *   allow tests to control which symbols are "found", inject abort interception via
 *   `setjmp`/`longjmp`, and exercise the `/dev/urandom` seed path through a controllable
 *   syscall stub.
 * - `chaos_dns_config_init` is replaced with a local stub that counts calls; this decouples
 *   the runtime tests from config-subsystem behaviour.
 * - On Linux, the syscall stub handles `SYS_openat`, `SYS_read`, and `SYS_close`. It returns
 *   a fake fd (9), copies a fixed 64-bit seed into the read buffer, and counts each call.
 *   `g_force_open_fail` and `g_force_short_read` inject the two fallback paths.
 * - `reset_test_state()` zeroes all counters and flags before each test.
 *
 * Properties under test:
 * - `chaos_dns_resolve_symbol`: successfully fills a function-pointer slot and calls
 *   `dlerror` exactly once (to consume any stale error string); NULL from dlsym + non-NULL
 *   dlerror triggers `abort`.
 * - `chaos_dns_read_seed_material` (Linux): normal path returns the fixed seed constant
 *   `0x1122334455667788` via exactly 1 open, 1 read, 1 close syscall.
 * - `chaos_dns_read_seed_material` (non-Linux): returns a non-zero value (platform entropy
 *   path not fully controlled; only non-zero is asserted).
 * - `chaos_dns_init` (constructor): all three real-function-pointer globals are wired to
 *   the stubs; `g_chaos_dns_process_seed` and `g_chaos_dns_tls_prng_state` are non-zero;
 *   `chaos_dns_config_init` is called exactly once more than before the call.
 * - Linux open-fail fallback: `chaos_dns_read_seed_material` returns a deterministic PID-
 *   derived fallback seed when `SYS_openat` fails; open called once, read/close not called.
 * - Linux short-read fallback: returns the same PID-derived seed when `SYS_read` returns
 *   fewer bytes than requested; open/read/close each called once.
 *
 * What is NOT tested here:
 * - Config file parsing and rule selection (tested in `test_dns_config.c`).
 * - DNS wrapper call paths that exercise getaddrinfo/getnameinfo interception (tested in
 *   `test_chaos_dns.c`).
 * - Action helpers (tested in `test_dns_actions.c`).
 */

#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Number of times the `chaos_dns_config_init` stub has been called. */
static int g_config_init_calls = 0;

/** @brief Number of times `chaos_dns_test_dlerror` has been invoked. */
static int g_dlerror_calls = 0;

/**
 * @brief Text returned by the dlerror stub; NULL means no error (symbol resolved OK).
 *
 * Set to a non-NULL string before resolving a missing symbol to trigger the abort path.
 */
static const char *g_dlerror_text = NULL;

/** @brief setjmp environment used to capture the `abort` call in abort-path tests. */
static jmp_buf g_abort_env;

/**
 * @brief Non-zero when the test expects `abort` to be called.
 *
 * The abort stub calls `longjmp(g_abort_env, 1)` when set; otherwise it asserts to catch
 * unexpected aborts.
 */
static int g_expect_abort = 0;

#ifdef __linux__
/** @brief Number of `SYS_openat` calls dispatched by the syscall stub. */
static int g_syscall_open_calls = 0;

/** @brief Number of `SYS_read` calls dispatched by the syscall stub. */
static int g_syscall_read_calls = 0;

/** @brief Number of `SYS_close` calls dispatched by the syscall stub. */
static int g_syscall_close_calls = 0;

/**
 * @brief When non-zero, the `SYS_openat` case in the syscall stub returns -1.
 *
 * Used to exercise the open-failure fallback path in `chaos_dns_read_seed_material`.
 */
static int g_force_open_fail = 0;

/**
 * @brief When non-zero, the `SYS_read` case returns `sizeof(seed) - 1` (short read).
 *
 * Used to exercise the short-read fallback path in `chaos_dns_read_seed_material`.
 */
static int g_force_short_read = 0;
#endif

/**
 * @brief Reset all test-state counters and flags to zero.
 *
 * Calls `chaos_dns_test_reset_runtime()` to clear PRNG and function-pointer globals, then
 * zeroes all local counters and flags.
 */
static void reset_test_state(void)
{
    chaos_dns_test_reset_runtime();
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

/**
 * @brief Stub getaddrinfo that returns 0 (success) unconditionally.
 *
 * All parameters are ignored. Used as the resolved function pointer for the "getaddrinfo"
 * symbol in `chaos_dns_test_dlsym`.
 */
static int stub_getaddrinfo(
    const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result
)
{
    (void)node;
    (void)service;
    (void)hints;
    (void)result;
    return 0;
}

/**
 * @brief Stub getnameinfo that returns 0 (success) unconditionally.
 *
 * All parameters are ignored. Used as the resolved function pointer for the "getnameinfo"
 * symbol in `chaos_dns_test_dlsym`.
 */
static int stub_getnameinfo(
    const struct sockaddr *address,
    socklen_t address_len,
    char *host,
    socklen_t host_len,
    char *service,
    socklen_t service_len,
    int flags
)
{
    (void)address;
    (void)address_len;
    (void)host;
    (void)host_len;
    (void)service;
    (void)service_len;
    (void)flags;
    return 0;
}

/**
 * @brief Stub freeaddrinfo that does nothing.
 *
 * Used as the resolved function pointer for the "freeaddrinfo" symbol in
 * `chaos_dns_test_dlsym`.
 *
 * @param result  Ignored.
 */
static void stub_freeaddrinfo(struct addrinfo *result)
{
    (void)result;
}

/**
 * @brief Stub replacing `chaos_dns_config_init`; counts invocations.
 *
 * The production `chaos_dns.c` calls this during the constructor. The test asserts that the
 * count increases by exactly 1 per `chaos_dns_init()` call.
 */
void chaos_dns_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub dlerror that counts calls and returns `g_dlerror_text`.
 *
 * The production resolve helper calls `dlerror()` once after `dlsym` to check for errors.
 * When `g_dlerror_text` is non-NULL, the production code treats it as a fatal resolution
 * failure and calls `abort`.
 *
 * @return `(char *)g_dlerror_text`.
 */
static char *chaos_dns_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Stub dlsym that dispatches known symbols to test stubs and returns NULL otherwise.
 *
 * Returns UB-safe function-pointer results via `CHAOS_DNS_TEST_DLSYM_RESULT` for
 * "getaddrinfo", "getnameinfo", and "freeaddrinfo". Any other symbol name returns NULL,
 * which combined with a non-NULL `g_dlerror_text` will trigger the abort path.
 *
 * @param handle  Ignored.
 * @param symbol  Symbol name to resolve.
 * @return Stub function pointer or NULL.
 */
static void *chaos_dns_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "getaddrinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_getaddrinfo_fn, stub_getaddrinfo);
    if (strcmp(symbol, "getnameinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_getnameinfo_fn, stub_getnameinfo);
    if (strcmp(symbol, "freeaddrinfo") == 0)
        return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_freeaddrinfo_fn, stub_freeaddrinfo);
    return NULL;
}

#ifdef __linux__
/**
 * @brief Stub syscall for `SYS_openat`, `SYS_read`, and `SYS_close`.
 *
 * `SYS_openat`: increments `g_syscall_open_calls`; returns -1 if `g_force_open_fail`, else 9.
 * `SYS_read`: increments `g_syscall_read_calls`; asserts fd==9 and size==sizeof(uint64_t);
 *   copies the fixed seed `0x1122334455667788` into the buffer; returns short if
 *   `g_force_short_read`, else full size.
 * `SYS_close`: increments `g_syscall_close_calls`; returns 0.
 * Any other number: returns -1.
 *
 * @param number  Linux syscall number.
 * @param ...     Variadic arguments matching the syscall ABI.
 * @return Syscall return value.
 */
static long chaos_dns_test_syscall(long number, ...)
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
 * @brief Stub abort that longjmps when expected; hard-fails otherwise.
 *
 * When `g_expect_abort` is non-zero, calls `longjmp(g_abort_env, 1)` so the test can
 * verify that the abort path was reached without terminating the process. If abort is
 * called unexpectedly, the `assert(!"unexpected abort")` fires.
 */
static void chaos_dns_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

#define dlsym chaos_dns_test_dlsym
#define dlerror chaos_dns_test_dlerror
#define abort chaos_dns_test_abort
#ifdef __linux__
#define syscall chaos_dns_test_syscall
#endif
#include "../../src/dns/chaos_dns.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

/**
 * @brief Invariant: `chaos_dns_resolve_symbol` fills the function-pointer slot and
 *   calls `dlerror` exactly once; on non-Linux platforms `chaos_dns_read_seed_material`
 *   returns a non-zero value.
 *
 * Triggering condition: `chaos_dns_resolve_symbol` with symbol "getaddrinfo"; then
 *   `chaos_dns_read_seed_material` (Linux: with full syscall trace; non-Linux: just
 *   non-zero check).
 *
 * Expected observable behaviour:
 * - After `resolve_symbol(&getaddrinfo_fn, "getaddrinfo")`:
 *   `getaddrinfo_fn == stub_getaddrinfo` and `g_dlerror_calls == 1`.
 * - Linux: `chaos_dns_read_seed_material()` == `0x1122334455667788`; open/read/close each
 *   called exactly once.
 * - Non-Linux: `chaos_dns_read_seed_material()` != 0 (platform source provides entropy).
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_dns_getaddrinfo_fn getaddrinfo_fn = NULL;

    reset_test_state();
    chaos_dns_resolve_symbol(&getaddrinfo_fn, "getaddrinfo");
    assert(getaddrinfo_fn == stub_getaddrinfo);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_dns_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_dns_read_seed_material() != 0U);
#endif
}

/**
 * @brief Invariant: `chaos_dns_resolve_symbol` calls `abort` when dlsym returns NULL and
 *   dlerror returns a non-NULL error string.
 *
 * Triggering condition: `g_dlerror_text = "missing"` and `g_expect_abort = 1` before
 *   calling `chaos_dns_resolve_symbol` with a symbol name not handled by the dlsym stub.
 *   A `setjmp` guard captures the `longjmp` from the abort stub.
 *
 * Expected observable behaviour:
 * - Control transfers to the `setjmp` guard (the `assert(0 && ...)` after the call is never
 *   reached).
 * - `g_expect_abort` is cleared after the test to prevent the next test from misinterpreting
 *   any subsequent abort call.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_dns_getaddrinfo_fn getaddrinfo_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_dns_resolve_symbol(&getaddrinfo_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Invariant: `chaos_dns_read_seed_material` returns a deterministic PID-derived
 *   fallback seed when the `/dev/urandom` open or read fails.
 *
 * Triggering condition (Linux only):
 * 1. `g_force_open_fail = 1` — SYS_openat returns -1; read and close are never invoked.
 * 2. `g_force_short_read = 1` — SYS_openat succeeds; SYS_read returns fewer bytes than
 *    requested.
 *
 * Expected observable behaviour:
 * - In both cases the return value equals `0x6a09e667f3bcc909 ^ (uint64_t)getpid()`.
 * - Open-fail: open_calls=1, read_calls=0, close_calls=0.
 * - Short-read: open_calls=1, read_calls=1, close_calls=1.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_dns_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_dns_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Invariant: `chaos_dns_init` wires all three real-function-pointer globals, seeds
 *   the PRNG, and calls `chaos_dns_config_init` exactly once.
 *
 * Triggering condition: `chaos_dns_init()` called after `reset_test_state()`.
 *
 * Expected observable behaviour:
 * - `g_chaos_dns_real_getaddrinfo == stub_getaddrinfo`.
 * - `g_chaos_dns_real_getnameinfo == stub_getnameinfo`.
 * - `g_chaos_dns_real_freeaddrinfo == stub_freeaddrinfo`.
 * - `g_chaos_dns_process_seed != 0`.
 * - `g_chaos_dns_tls_prng_state != 0`.
 * - `g_config_init_calls` increased by exactly 1.
 */
static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    chaos_dns_init();
    assert(g_chaos_dns_real_getaddrinfo == stub_getaddrinfo);
    assert(g_chaos_dns_real_getnameinfo == stub_getnameinfo);
    assert(g_chaos_dns_real_freeaddrinfo == stub_freeaddrinfo);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_dns_process_seed != 0U);
    assert(g_chaos_dns_tls_prng_state != 0U);
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
