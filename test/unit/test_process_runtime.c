/**
 * @file test_process_runtime.c
 * @brief Unit tests for the PROCESS-domain constructor: symbol resolution, seed material,
 *   and function-pointer table wiring.
 *
 * Subsystem under test: `src/process/chaos_process.c` (the `chaos_process_init()` constructor).
 *
 * Coverage approach:
 * - All nine intercepted symbols (pthread_create, fork, posix_spawn, posix_spawnp, execve,
 *   execveat, waitpid, nanosleep, usleep) are mapped to local stubs via a test-controlled
 *   `dlsym` stub.
 * - `dlerror`, `abort`, and (on Linux) `syscall` are overridden via `#define` before
 *   `chaos_process.c` is included, exercising the constructor without LD_PRELOAD.
 * - On Linux, the raw-syscall stub delivers a deterministic 8-byte seed value
 *   (0x1122334455667788) to verify the exact stored `process_seed`.
 * - The abort path is intercepted via `setjmp`/`longjmp` to verify fatal-error behaviour.
 *
 * Properties under test:
 * - `chaos_process_resolve_symbol()`: pointer wired correctly; `dlerror()` called once.
 * - `chaos_process_read_seed_material()` (Linux): returns 0x1122334455667788; exactly
 *   one openat, one read, one close raw syscall.
 * - `chaos_process_read_seed_material()` (non-Linux): returns a non-zero value.
 * - Abort path: unresolvable symbol triggers `abort()`.
 * - Linux seed fallback: open failure → PID-based fallback; short read → same fallback.
 * - `chaos_process_init()`: all nine real-function-pointer globals wired; config_init called
 *   once; process_seed and tls_prng_state non-zero.
 *
 * What is NOT tested here:
 * - Config file loading or rule matching.
 * - PROCESS wrapper call paths (tested in test_chaos_process.c).
 */

#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Number of times `chaos_process_config_init()` stub was called. */
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
    chaos_process_test_reset_runtime();
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

/** @brief Stub for `pthread_create(3)`. Returns 0 (success) without creating a thread. */
static int stub_pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attributes,
    void *(*start_routine)(void *),
    void *argument
)
{
    (void)thread;
    (void)attributes;
    (void)start_routine;
    (void)argument;
    return 0;
}

/**
 * @brief Stub for `fork(2)`. Returns a fixed child PID (123) without creating a process.
 *
 * @return 123 (simulated child PID as seen by the parent).
 */
static pid_t stub_fork(void)
{
    return 123;
}

/**
 * @brief Stub for `posix_spawn(3)`. Writes a fixed PID (234) and returns 0.
 *
 * @param pid  Receives the simulated child PID when non-NULL.
 * @return 0 (success).
 */
static int stub_posix_spawn(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    (void)path;
    (void)file_actions;
    (void)attributes;
    (void)argv;
    (void)envp;
    if (pid != NULL)
    {
        *pid = 234;
    }
    return 0;
}

/**
 * @brief Stub for `posix_spawnp(3)`. Writes a fixed PID (345) and returns 0.
 *
 * @param pid  Receives the simulated child PID when non-NULL.
 * @return 0 (success).
 */
static int stub_posix_spawnp(
    pid_t *pid,
    const char *file,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    (void)file;
    (void)file_actions;
    (void)attributes;
    (void)argv;
    (void)envp;
    if (pid != NULL)
    {
        *pid = 345;
    }
    return 0;
}

/** @brief Stub for `execve(2)`. Returns 0 without replacing the process image. */
static int stub_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;
    return 0;
}

/** @brief Stub for `execveat(2)`. Returns 0 without replacing the process image. */
static int
stub_execveat(int directory_fd, const char *path, char *const argv[], char *const envp[], int flags)
{
    (void)directory_fd;
    (void)path;
    (void)argv;
    (void)envp;
    (void)flags;
    return 0;
}

/**
 * @brief Stub for `waitpid(2)`. Returns @p pid unchanged so callers can verify the value.
 *
 * @param pid  PID to wait for; echoed back as the return value.
 * @return @p pid (simulates a completed wait for that child).
 */
static pid_t stub_waitpid(pid_t pid, int *status, int options)
{
    (void)status;
    (void)options;
    return pid;
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
 * @brief Stub for `chaos_process_config_init()`.
 *
 * Increments the call counter to verify the constructor calls it exactly once.
 */
void chaos_process_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for `dlerror()`.
 *
 * Returns `g_dlerror_text` and increments `g_dlerror_calls`. The call count
 * verifies that the production resolver calls `dlerror()` once per symbol.
 */
static char *chaos_process_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Stub for `dlsym(RTLD_NEXT, symbol)`.
 *
 * Maps each of the nine expected symbol names to the corresponding stub function
 * via `CHAOS_PROCESS_TEST_DLSYM_RESULT`. Returns NULL for unrecognised symbols,
 * which causes the production resolver to call `dlerror` and then `abort`.
 */
static void *chaos_process_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "pthread_create") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(
            chaos_process_pthread_create_fn, stub_pthread_create
        );
    if (strcmp(symbol, "fork") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_fork_fn, stub_fork);
    if (strcmp(symbol, "posix_spawn") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_posix_spawn_fn, stub_posix_spawn);
    if (strcmp(symbol, "posix_spawnp") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_posix_spawnp_fn, stub_posix_spawnp);
    if (strcmp(symbol, "execve") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_execve_fn, stub_execve);
    if (strcmp(symbol, "execveat") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_execveat_fn, stub_execveat);
    if (strcmp(symbol, "waitpid") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_waitpid_fn, stub_waitpid);
    if (strcmp(symbol, "nanosleep") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_nanosleep_fn, stub_nanosleep);
    if (strcmp(symbol, "usleep") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_usleep_fn, stub_usleep);
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
static long chaos_process_test_syscall(long number, ...)
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
static void chaos_process_test_abort(void)
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

#define dlsym chaos_process_test_dlsym
#define dlerror chaos_process_test_dlerror
#define abort chaos_process_test_abort
#ifdef __linux__
#define syscall chaos_process_test_syscall
#endif
#include "../../src/process/chaos_process.c"
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
 * @brief Invariant: `chaos_process_resolve_symbol()` wires a pointer and reads a valid seed.
 *
 * Triggering condition: `chaos_process_resolve_symbol(&fork_fn, "fork")` with clean state.
 *
 * Expected observable behaviour:
 * - `fork_fn` is set to `stub_fork`.
 * - `g_dlerror_calls == 1`.
 * - On Linux: `chaos_process_read_seed_material()` returns 0x1122334455667788; exactly
 *   one of each raw syscall is issued.
 * - Non-Linux: returns a non-zero value.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_process_fork_fn fork_fn = NULL;

    reset_test_state();
    chaos_process_resolve_symbol(&fork_fn, "fork");
    assert(fork_fn == stub_fork);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_process_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_process_read_seed_material() != 0U);
#endif
}

/**
 * @brief Invariant: `chaos_process_resolve_symbol()` calls `abort()` for a missing symbol.
 *
 * Triggering condition: `g_dlerror_text = "missing"` with an unrecognised symbol name
 *   causes the production resolver to call `abort()`.
 *
 * Expected observable behaviour: `longjmp` transfers control out of the setjmp block;
 *   the assertion on the next line is never reached.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_process_fork_fn fork_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_process_resolve_symbol(&fork_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Invariant: seed fallback paths produce PID-based seeds when /dev/urandom fails.
 *
 * Triggering conditions:
 * - `g_force_open_fail = 1`: SYS_openat returns -1; no read or close attempted.
 * - `g_force_short_read = 1`: SYS_read returns `sizeof(seed)-1`; close is still called.
 *
 * Expected observable behaviour: both paths return `0x6a09e667f3bcc909 XOR getpid()`.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_process_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_process_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Invariant: `chaos_process_init()` wires all nine function pointers and seeds the PRNG.
 *
 * Triggering condition: `chaos_process_init()` called after `reset_test_state()`.
 *
 * Expected observable behaviour:
 * - All nine `g_chaos_process_real_*` globals equal their stub counterparts.
 *   On Linux, `execveat` is included; on non-Linux it is omitted from the check.
 * - `g_config_init_calls` increments by 1.
 * - `g_chaos_process_process_seed != 0` and `g_chaos_process_tls_prng_state != 0`.
 */
static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    chaos_process_init();
    assert(g_chaos_process_real_pthread_create == stub_pthread_create);
    assert(g_chaos_process_real_fork == stub_fork);
    assert(g_chaos_process_real_posix_spawn == stub_posix_spawn);
    assert(g_chaos_process_real_posix_spawnp == stub_posix_spawnp);
    assert(g_chaos_process_real_execve == stub_execve);
#ifdef __linux__
    assert(g_chaos_process_real_execveat == stub_execveat);
#endif
    assert(g_chaos_process_real_waitpid == stub_waitpid);
    assert(g_chaos_process_real_nanosleep == stub_nanosleep);
    assert(g_chaos_process_real_usleep == stub_usleep);
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_chaos_process_process_seed != 0U);
    assert(g_chaos_process_tls_prng_state != 0U);
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
