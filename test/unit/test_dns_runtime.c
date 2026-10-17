/**
 * @file test_dns_runtime.c
 * @brief Unit tests for the libchaos-dns constructor: real-function resolution, seeding and
 *   the start-up rule load.
 *
 * @details
 * Unit under test: `src/dns/chaos_dns.c`. The suite proves:
 * - `chaos_dns_resolve_symbol()` stores the `dlsym(RTLD_NEXT)` result, clears a stale
 *   `dlerror()` once first, never overwrites a pointer that is already set, and aborts when
 *   dlsym returns NULL with a pending dlerror (no real function means no way to delegate);
 * - seeding on Linux reads 8 bytes from `/dev/urandom` through raw `SYS_openat`/`SYS_read`/
 *   `SYS_close` (no interposable libc wrapper), closes the fd on a short read, and falls back
 *   to `0x6a09e667f3bcc909 ^ getpid()` when the open fails or the read is short; on other
 *   platforms only a non-zero seed is asserted;
 * - the constructor wires the real getaddrinfo/getnameinfo/freeaddrinfo, seeds the process
 *   and main-thread PRNG, initialises the config module once and loads the rule file once, so
 *   a bad rule file is reported at start-up rather than on the first lookup.
 *
 * Seams: the source is compiled into this file with `dlsym`, `dlerror`, `abort` and (Linux)
 * `syscall` macro-redirected to local stubs:
 * - the dlsym stub returns local stubs for the three resolver symbols and NULL for any other
 *   name; `g_dlerror_text` decides whether that NULL is an error;
 * - the abort stub `longjmp()`s back to the test when `g_expect_abort` is set and fails the
 *   test otherwise;
 * - the syscall stub returns fd 9 and the fixed seed `0x1122334455667788`, with
 *   `g_force_open_fail` and `g_force_short_read` selecting the two fallback paths.
 * `chaos_dns_config_init()` and `chaos_dns_config_prepare()` are replaced by counters, so no
 * rule file is read.
 *
 * Out of scope: rule parsing (`test_dns_config.c`), the interposed entry points
 * (`test_chaos_dns.c`) and the effect helpers (`test_dns_actions.c`).
 */

#include "../support/test_dns_support.h"

#include "../../src/dns/chaos_dns_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Calls of the `chaos_dns_config_init()` stub. */
static int g_config_init_calls = 0;

/** @brief Calls of the `chaos_dns_config_prepare()` stub (start-up rule loads). */
static int g_config_prepare_calls = 0;

/** @brief Calls of the dlerror stub. */
static int g_dlerror_calls = 0;

/** @brief Returned by the dlerror stub; non-NULL turns a NULL dlsym result into an abort. */
static const char *g_dlerror_text = NULL;

/** @brief Where the abort stub returns to when an abort is expected. */
static jmp_buf g_abort_env;

/** @brief Non-zero while a test expects abort(); otherwise abort() fails the test. */
static int g_expect_abort = 0;

#ifdef __linux__
/** @brief `SYS_openat` calls seen by the syscall stub. */
static int g_syscall_open_calls = 0;

/** @brief `SYS_read` calls seen by the syscall stub. */
static int g_syscall_read_calls = 0;

/** @brief `SYS_close` calls seen by the syscall stub. */
static int g_syscall_close_calls = 0;

/** @brief Non-zero makes `SYS_openat` fail (no `/dev/urandom`). */
static int g_force_open_fail = 0;

/** @brief Non-zero makes `SYS_read` return 7 of 8 bytes, a short read. */
static int g_force_short_read = 0;
#endif

/** @brief Clears real-function pointers, PRNG state, counters and fault flags. */
static void reset_test_state(void)
{
    chaos_dns_test_reset_runtime();
    g_config_init_calls = 0;
    g_config_prepare_calls = 0;
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

/** @brief Real getaddrinfo handed out by the dlsym stub; only its address matters. */
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

/** @brief Real getnameinfo handed out by the dlsym stub; only its address matters. */
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

/** @brief Real freeaddrinfo handed out by the dlsym stub; only its address matters. */
static void stub_freeaddrinfo(struct addrinfo *result)
{
    (void)result;
}

/** @brief Replaces the config module's initialiser; counts calls. */
void chaos_dns_config_init(void)
{
    ++g_config_init_calls;
}

/** @brief Replaces the start-up rule load; counts calls and reports success. */
int chaos_dns_config_prepare(void)
{
    ++g_config_prepare_calls;
    return 0;
}

/**
 * @brief dlerror() replacement: counts calls and returns `g_dlerror_text`.
 *
 * The resolver calls dlerror() once before dlsym to clear stale state and a second time only
 * when dlsym returned NULL, so a successful resolution counts exactly 1 call.
 */
static char *chaos_dns_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief dlsym() replacement: the three resolver stubs by name, NULL for anything else.
 *
 * `CHAOS_DNS_TEST_DLSYM_RESULT` converts the function pointer to `void *` through memcpy, the
 * same representation dlsym() uses, without an ISO C function-to-object pointer cast. The
 * gethostbyname2/gethostbyaddr families resolve to NULL with no dlerror, which the resolver
 * stores as "absent" without aborting.
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
 * @brief syscall() replacement modelling `/dev/urandom` for the seed reader.
 *
 * `SYS_openat` returns fd 9, or -1 under `g_force_open_fail`. `SYS_read` asserts it reads
 * exactly 8 bytes from fd 9, writes `0x1122334455667788`, and reports 7 bytes under
 * `g_force_short_read`. `SYS_close` succeeds. Each is counted; any other number returns -1.
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
 * @brief abort() replacement: `longjmp()`s to `g_abort_env` when expected, fails the test
 *   otherwise, so the abort path is observable without killing the test process.
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
 * @brief Proves symbol resolution fills an unset pointer once and the seed comes from
 *   `/dev/urandom`.
 *
 * @details Resolving "getaddrinfo" stores the stub with one dlerror() call. Resolving into the
 * now-set pointer with an unknown name changes nothing and calls neither dlsym nor dlerror:
 * a pointer a harness or an earlier call wired is never replaced. On Linux the seed equals the
 * 8 bytes read, through exactly one open, read and close; elsewhere it is only non-zero.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_dns_getaddrinfo_fn getaddrinfo_fn = NULL;

    reset_test_state();
    chaos_dns_resolve_symbol(&getaddrinfo_fn, "getaddrinfo");
    assert(getaddrinfo_fn == stub_getaddrinfo);
    assert(g_dlerror_calls == 1);

    chaos_dns_resolve_symbol(&getaddrinfo_fn, "missing-symbol");
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
 * @brief Proves a failed lookup (dlsym NULL with a pending dlerror) aborts the process.
 *
 * @details libchaos-dns fails closed here: without the real function no wrapper could
 * delegate. The abort stub `longjmp()`s back past the call, so reaching the assertion after
 * it means abort() was not called.
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
 * @brief Proves the seed falls back to `0x6a09e667f3bcc909 ^ getpid()` when `/dev/urandom`
 *   cannot be opened or returns a short read (Linux only).
 *
 * @details A failed open performs no read and no close. A short read still closes the fd,
 * so a process without full entropy does not leak a descriptor per seeding.
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
 * @brief Proves the constructor resolves the real functions, seeds both PRNG states, and
 *   initialises and loads the configuration exactly once each.
 *
 * @details The run-once guard is reset first because the constructor has already run when
 * this binary was loaded; without the reset `chaos_dns_ensure_symbols()` would do nothing and
 * the pointers cleared by `reset_test_state()` would stay NULL.
 */
static void test_constructor_init(void)
{
    int config_calls_before;
    int prepare_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    prepare_calls_before = g_config_prepare_calls;
    g_chaos_dns_symbols_once = CHAOS_ONCE_INIT;
    chaos_dns_init();
    assert(g_chaos_dns_real_getaddrinfo == stub_getaddrinfo);
    assert(g_chaos_dns_real_getnameinfo == stub_getnameinfo);
    assert(g_chaos_dns_real_freeaddrinfo == stub_freeaddrinfo);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_config_prepare_calls == prepare_calls_before + 1);
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
