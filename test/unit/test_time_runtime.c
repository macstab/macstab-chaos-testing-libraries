/**
 * @file test_time_runtime.c
 * @brief Proves the libchaos-time constructor: real-function resolution, the abort on a
 *   failed lookup, seed collection and its fallback, and the start-up rule load.
 *
 * @details Unit under test: `src/time/chaos_time.c`, included directly so its `static`
 * functions are callable. Isolation seams, all applied by `#define` before the include:
 * - `dlsym` maps each of the eight real function names (clock_gettime, nanosleep, usleep,
 *   gettimeofday, time, clock_nanosleep, sleep, timespec_get) to a local no-op stub and
 *   returns NULL for anything else, so no real libc symbol is ever bound.
 * - `dlerror` returns a test-chosen string and counts calls, which separates "symbol absent
 *   but no error" (accepted) from "lookup failed" (abort).
 * - `abort` `longjmp`s back into the test when an abort is expected, and asserts otherwise.
 * - `syscall` (Linux only) fakes the raw openat/read/close sequence on `/dev/urandom`: it
 *   returns fd 9, writes the fixed seed 0x1122334455667788 and can force an open failure or
 *   a 7-byte short read. Production uses raw syscalls here, so stubbing libc `open`/`read`
 *   would not intercept anything.
 * - `chaos_time_config_init()` and `chaos_time_config_prepare()` are replaced by counting
 *   stubs, so no rule file is read.
 *
 * Out of scope: rule parsing and matching (test_time_config.c) and the wrappers
 * (test_chaos_time.c).
 */

#include "../support/test_time_support.h"

#include "../../src/time/chaos_time_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Calls to the `chaos_time_config_init()` stub. */
static int g_config_init_calls = 0;

/** @brief Calls to the `chaos_time_config_prepare()` stub (the start-up rule load). */
static int g_config_prepare_calls = 0;
/** @brief Calls to the `dlerror` stub; one per lookup proves the error state is cleared. */
static int g_dlerror_calls = 0;
/** @brief Value the `dlerror` stub returns; NULL reports "no lookup error". */
static const char *g_dlerror_text = NULL;
/** @brief Return point for an expected `abort()`. */
static jmp_buf g_abort_env;
/** @brief Non-zero while a test expects `abort()`; any other abort fails the run. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief Raw `SYS_openat` calls seen by the `syscall` stub. */
static int g_syscall_open_calls = 0;
/** @brief Raw `SYS_read` calls seen by the `syscall` stub. */
static int g_syscall_read_calls = 0;
/** @brief Raw `SYS_close` calls seen by the `syscall` stub. */
static int g_syscall_close_calls = 0;
/** @brief Non-zero makes `SYS_openat` fail with -1. */
static int g_force_open_fail = 0;
/** @brief Non-zero makes `SYS_read` return 7 of the 8 requested bytes. */
static int g_force_short_read = 0;
#endif

/**
 * @brief Clears the runtime globals and every stub counter and switch, so each test
 *   starts with unresolved function pointers and no injected failure.
 */
static void reset_test_state(void)
{
    chaos_time_test_reset_runtime();
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

/*
 * Real-function stubs. They are never called; only their addresses matter, as proof that
 * the constructor stored the pointer `dlsym` returned for each name.
 */

/** @brief Address stand-in for the real `clock_gettime`. */
static int stub_clock_gettime(clockid_t clock_id, struct timespec *value)
{
    (void)clock_id;
    (void)value;
    return 0;
}

/** @brief Address stand-in for the real `nanosleep`. */
static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)request;
    (void)remaining;
    return 0;
}

/** @brief Address stand-in for the real `usleep`. */
static int stub_usleep(useconds_t usec)
{
    (void)usec;
    return 0;
}

/** @brief Address stand-in for the real `gettimeofday`. */
static int stub_gettimeofday(struct timeval *value, void *zone)
{
    (void)value;
    (void)zone;
    return 0;
}

/** @brief Address stand-in for the real `time`. */
static time_t stub_time(time_t *out)
{
    (void)out;
    return 0;
}

/** @brief Address stand-in for the real `sleep`. */
static unsigned int stub_sleep(unsigned int seconds)
{
    (void)seconds;
    return 0U;
}

/** @brief Address stand-in for the real `timespec_get`. */
static int stub_timespec_get(struct timespec *value, int base)
{
    (void)value;
    return base;
}

/** @brief Address stand-in for the real `clock_nanosleep`. */
static int stub_clock_nanosleep(
    clockid_t clock_id, int flags, const struct timespec *request, struct timespec *remaining
)
{
    (void)clock_id;
    (void)flags;
    (void)request;
    (void)remaining;
    return 0;
}

/** @brief Replaces the config initialiser; counts calls so the constructor's single call is
 *   observable. */
void chaos_time_config_init(void)
{
    ++g_config_init_calls;
}

/** @brief Replaces the start-up rule load; counts calls and reports success without reading
 *   a rule file. */
int chaos_time_config_prepare(void)
{
    ++g_config_prepare_calls;
    return 0;
}

/**
 * @brief `dlerror` seam: returns `g_dlerror_text` and counts calls.
 *
 * The resolver calls `dlerror()` once to clear stale state before `dlsym` and, only when
 * `dlsym` returns NULL, once more to tell a missing symbol from a failed lookup.
 */
static char *chaos_time_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief `dlsym` seam: returns the matching address stand-in for each of the eight real
 *   function names, and NULL for any other name.
 *
 * A NULL result reaches `abort()` only when `dlerror` also reports an error, which the abort
 * test arranges through `g_dlerror_text`.
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
    if (strcmp(symbol, "gettimeofday") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_gettimeofday_fn, stub_gettimeofday);
    if (strcmp(symbol, "time") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_time_fn, stub_time);
    if (strcmp(symbol, "sleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_sleep_fn, stub_sleep);
    if (strcmp(symbol, "timespec_get") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_timespec_get_fn, stub_timespec_get);
    if (strcmp(symbol, "clock_nanosleep") == 0)
        return CHAOS_TIME_TEST_DLSYM_RESULT(chaos_time_clock_nanosleep_fn, stub_clock_nanosleep);
    return NULL;
}

#ifdef __linux__
/**
 * @brief `syscall` seam for the raw `/dev/urandom` read.
 *
 * `SYS_openat` returns fd 9 (or -1 under `g_force_open_fail`). `SYS_read` asserts it
 * received fd 9 and an 8-byte request, writes 0x1122334455667788 and returns 8, or 7 under
 * `g_force_short_read`; the bytes are written even on the short read, so only the length
 * check can reject them. `SYS_close` succeeds. Any other number returns -1.
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
 * @brief `abort` seam: `longjmp`s to `g_abort_env` when an abort is expected and fails the
 *   run otherwise, so the fatal path can be tested in-process.
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
 * Seams: the macros rename the calls inside chaos_time.c only; they are undefined again
 * right after the include so the tests below use the real names.
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
 * @brief Proves the resolver stores the `dlsym` result, never replaces a wired pointer, and
 *   that seed collection returns the 8 bytes read from `/dev/urandom`.
 *
 * @details One resolve stores the stand-in with one `dlerror` call (the clearing call; the
 * second call happens only on a NULL result). A second resolve of an unknown name on the
 * same, already wired pointer must return before `dlsym`/`dlerror`, which is what lets a test
 * harness pre-wire pointers. On Linux the seed must equal the stub's bytes after exactly one
 * openat, read and close; elsewhere only the pid-derived value is available, so the test
 * checks it is non-zero.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_time_clock_gettime_fn clock_gettime_fn = NULL;

    reset_test_state();
    chaos_time_resolve_symbol(&clock_gettime_fn, "clock_gettime");
    assert(clock_gettime_fn == stub_clock_gettime);
    assert(g_dlerror_calls == 1);

    /* A pointer that is already wired is left alone: no dlsym, no dlerror. */
    chaos_time_resolve_symbol(&clock_gettime_fn, "missing-symbol");
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
 * @brief Proves a failed lookup aborts: `dlsym` returns NULL and `dlerror` reports an error.
 *
 * @details Aborting is deliberate; the process must never run with a NULL real function.
 * Reaching the assert after the call means the resolver returned instead of aborting.
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
 * @brief Proves both `/dev/urandom` failures fall back to `0x6a09e667f3bcc909 ^ getpid()`.
 *
 * @details A failed open issues no read and no close. A 7-byte short read is rejected even
 * though the stub wrote all 8 bytes, and the fd is still closed, so the fallback leaks no
 * descriptor.
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
 * @brief Proves the constructor binds all eight real functions, seeds the process and the
 *   calling thread's PRNG, initialises the config once and loads the rules once.
 *
 * @details The run-once flag is reset because resolution goes through `chaos_once()`; without
 * the reset an earlier resolution in this binary would turn the call into a no-op.
 * `reset_test_state()` cleared the pointers, so each one must come from the `dlsym` seam.
 */
static void test_constructor_init(void)
{
    int config_calls_before;
    int prepare_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    prepare_calls_before = g_config_prepare_calls;
    g_chaos_time_symbols_once = CHAOS_ONCE_INIT;
    chaos_time_init();
    assert(g_chaos_time_real_clock_gettime == stub_clock_gettime);
    assert(g_chaos_time_real_nanosleep == stub_nanosleep);
    assert(g_chaos_time_real_usleep == stub_usleep);
    assert(g_chaos_time_real_gettimeofday == stub_gettimeofday);
    assert(g_chaos_time_real_time == stub_time);
    assert(g_chaos_time_real_clock_nanosleep == stub_clock_nanosleep);
    assert(g_chaos_time_real_sleep == stub_sleep);
    assert(g_chaos_time_real_timespec_get == stub_timespec_get);
    assert(g_config_init_calls == config_calls_before + 1);
    /* The rules load at start-up, so a bad rule file is reported before main(). */
    assert(g_config_prepare_calls == prepare_calls_before + 1);
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
