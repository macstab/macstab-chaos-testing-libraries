/**
 * @file test_process_runtime.c
 * @brief Proves the libchaos-process constructor: real-function resolution, seeding, rule load.
 *
 * @details
 * Unit under test: `src/process/chaos_process.c`. It must resolve every real function via
 * `dlsym(RTLD_NEXT)` (aborting for a mandatory one that is missing, tolerating an optional
 * one), seed the PRNG from `/dev/urandom` with a deterministic fallback, and load the rule file
 * at start-up. Rule matching and the wrappers are covered elsewhere.
 *
 * Isolation:
 * - `dlsym`, `dlerror`, `abort` and, on Linux, `syscall` are redefined as macros to local stubs
 *   before the production source is included, so the constructor runs as plain code with no
 *   LD_PRELOAD and no dynamic linker involvement.
 * - The `dlsym` stub maps each of the 13 resolved symbol names to a distinct stub, so pointer
 *   equality proves which symbol landed in which slot.
 * - The `syscall` stub fakes `/dev/urandom`: fd 9, seed 0x1122334455667788, with switches for a
 *   failed open and a short read.
 * - The `abort` stub `longjmp`s back to the test, so the fatal path is observable in-process.
 * - `chaos_process_config_init()` and `chaos_process_config_prepare()` are counting stubs; the
 *   config module is not linked.
 */
#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Calls to the `chaos_process_config_init()` stub. */
static int g_config_init_calls = 0;

/** @brief Calls to the `chaos_process_config_prepare()` stub. */
static int g_config_prepare_calls = 0;
/** @brief Calls to the `dlerror` stub; proves the clear-then-check error discipline. */
static int g_dlerror_calls = 0;
/** @brief Error string returned by the `dlerror` stub; NULL means no error. */
static const char *g_dlerror_text = NULL;
/** @brief Return point for an expected `abort()`. */
static jmp_buf g_abort_env;
/** @brief Non-zero while an `abort()` is expected; otherwise abort fails the test. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief Calls of `syscall(SYS_openat, ...)`. */
static int g_syscall_open_calls = 0;
/** @brief Calls of `syscall(SYS_read, ...)`. */
static int g_syscall_read_calls = 0;
/** @brief Calls of `syscall(SYS_close, ...)`. */
static int g_syscall_close_calls = 0;
/** @brief Non-zero makes SYS_openat fail with -1, as with no `/dev/urandom` in a sandbox. */
static int g_force_open_fail = 0;
/** @brief Non-zero makes SYS_read return 7 of 8 bytes (a short read). */
static int g_force_short_read = 0;
#endif

/** @brief Clears runtime globals and every stub counter and switch before a test. */
static void reset_test_state(void)
{
    chaos_process_test_reset_runtime();
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

/** @brief Real-function stand-in for `pthread_create(3)`; its address is the assertion. */
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

/** @brief Real-function stand-in for `fork(2)`; returns 123 without forking. */
static pid_t stub_fork(void)
{
    return 123;
}

/** @brief Real-function stand-in for `posix_spawn(3)`; stores pid 234 and returns 0. */
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

/** @brief Real-function stand-in for `posix_spawnp(3)`; stores pid 345 and returns 0. */
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

/** @brief Real-function stand-in for `execve(2)`; returns 0 without exec. */
static int stub_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;
    return 0;
}

/** @brief Real-function stand-in for `execveat(2)`; returns 0 without exec. */
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

/** @brief Real-function stand-in for `wait4(2)`; returns @p pid. */
static pid_t stub_wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    (void)status;
    (void)options;
    (void)usage;
    return pid;
}

/** @brief Real-function stand-in for `execvpe(3)`; returns -1. */
static int stub_execvpe(const char *file, char *const argv[], char *const envp[])
{
    (void)file;
    (void)argv;
    (void)envp;
    return -1;
}

/** @brief Real-function stand-in for `fexecve(3)`; returns -1. */
static int stub_fexecve(int fd, char *const argv[], char *const envp[])
{
    (void)fd;
    (void)argv;
    (void)envp;
    return -1;
}

/** @brief Real-function stand-in for `system(3)`; returns 0. */
static int stub_system(const char *command)
{
    (void)command;
    return 0;
}

/** @brief Real-function stand-in for `popen(3)`; returns NULL. */
static FILE *stub_popen(const char *command, const char *mode)
{
    (void)command;
    (void)mode;
    return NULL;
}

/** @brief Real-function stand-in for `waitid(2)`; returns 0. */
static int stub_waitid(idtype_t type, id_t id, siginfo_t *info, int options)
{
    (void)type;
    (void)id;
    (void)info;
    (void)options;
    return 0;
}

/** @brief Real-function stand-in for `waitpid(2)`; returns @p pid. */
static pid_t stub_waitpid(pid_t pid, int *status, int options)
{
    (void)status;
    (void)options;
    return pid;
}

/** @brief Replaces the config module's initialiser; counts calls. */
void chaos_process_config_init(void)
{
    ++g_config_init_calls;
}

/** @brief Replaces the start-up rule load; counts calls and reports success. */
int chaos_process_config_prepare(void)
{
    ++g_config_prepare_calls;
    return 0;
}

/**
 * @brief Replaces `dlerror()`: counts calls and returns `g_dlerror_text`.
 *
 * The resolver clears the error with one call before `dlsym` and checks it with a second only
 * when `dlsym` returns NULL, so a successful resolution costs exactly one call.
 */
static char *chaos_process_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Replaces `dlsym(RTLD_NEXT, symbol)`: maps the 13 resolved names to their stubs.
 *
 * Any other name returns NULL. The mandatory resolver then aborts only if `dlerror()` also
 * reports an error, mirroring how a real NULL symbol value is told apart from a missing one.
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
    if (strcmp(symbol, "wait4") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_wait4_fn, stub_wait4);
    if (strcmp(symbol, "waitid") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_waitid_fn, stub_waitid);
    if (strcmp(symbol, "execvpe") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_execvpe_fn, stub_execvpe);
    if (strcmp(symbol, "fexecve") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_fexecve_fn, stub_fexecve);
    if (strcmp(symbol, "system") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_system_fn, stub_system);
    if (strcmp(symbol, "popen") == 0)
        return CHAOS_PROCESS_TEST_DLSYM_RESULT(chaos_process_popen_fn, stub_popen);
    return NULL;
}

#ifdef __linux__
/**
 * @brief Replaces `syscall(2)`, which the seeder uses so it cannot re-enter wrappers.
 *
 * SYS_openat returns fd 9 (or -1 under `g_force_open_fail`). SYS_read asserts fd 9 and an
 * 8-byte request, writes 0x1122334455667788 and returns 8 (or 7 under `g_force_short_read`).
 * SYS_close succeeds. Counters let tests prove no read or close follows a failed open.
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
 * @brief Replaces `abort()`: `longjmp`s to the test when expected, otherwise fails an assert.
 */
static void chaos_process_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

/* The macros below must precede the include so every call site in the production source binds
 * to the stubs; they are undone afterwards so the tests themselves use the real names. */

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

/**
 * @brief Proves symbol resolution fills only unset pointers and the seed comes from urandom.
 *
 * Resolving "fork" stores `stub_fork` after one `dlerror()` clear. Resolving into the now set
 * pointer is a no-op even for a name `dlsym` cannot find, which is what lets a test harness
 * pre-wire real functions. On Linux the seed is the 8 bytes read through exactly one
 * openat/read/close; elsewhere it is the non-zero constant-XOR-pid fallback.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_process_fork_fn fork_fn = NULL;

    reset_test_state();
    chaos_process_resolve_symbol(&fork_fn, "fork");
    assert(fork_fn == stub_fork);
    assert(g_dlerror_calls == 1);

    chaos_process_resolve_symbol(&fork_fn, "missing-symbol");
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
 * @brief Proves a missing mandatory symbol aborts the process.
 *
 * Aborting at load is preferred to a NULL real function that would SIGSEGV later inside a
 * wrapper. `dlsym` returns NULL and `dlerror()` reports "missing"; the abort stub `longjmp`s
 * out, so reaching the assertion after the call means abort was not called.
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
 * @brief Proves a missing optional symbol leaves NULL, clears dlerror, and never aborts.
 *
 * Optional symbols can be absent: `execveat`, `execvpe` and `fexecve` on musl, `pthread_create`
 * before glibc 2.34 when libpthread is not loaded. The resolver must store NULL and consume
 * the pending error with a second `dlerror()` (2 calls), so a later unrelated `dlerror()`
 * caller does not see it. A pre-wired pointer is kept and costs no `dlerror()` call.
 */
static void test_try_resolve_symbol_missing(void)
{
    chaos_process_execveat_fn execveat_fn = NULL;
    chaos_process_execveat_fn wired = (chaos_process_execveat_fn)(uintptr_t)0xdead;

    reset_test_state();
    g_dlerror_text = "missing-on-musl";
    chaos_process_try_resolve_symbol(&execveat_fn, "this-symbol-does-not-exist");
    assert(execveat_fn == NULL);
    assert(g_dlerror_calls == 2);

    reset_test_state();
    chaos_process_try_resolve_symbol(&wired, "this-symbol-does-not-exist");
    assert(wired == (chaos_process_execveat_fn)(uintptr_t)0xdead);
    assert(g_dlerror_calls == 0);
}

/**
 * @brief Proves the seed falls back to `0x6a09e667f3bcc909 ^ getpid()` when urandom fails.
 *
 * A failed open issues no read and no close. A short read (7 of 8 bytes) discards the partial
 * seed but still closes the fd, so the fallback path does not leak a descriptor.
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
 * @brief Proves the constructor wires all 13 real functions, seeds the PRNG and loads rules.
 *
 * The run-once state is reset first so the constructor resolves again into the pointers
 * `reset_test_state()` cleared. `execveat` is resolved on Linux only, so it is checked only
 * there. The config module is initialised and the rule file loaded exactly once each, and both
 * the process seed and the calling thread's PRNG state are non-zero.
 */
static void test_constructor_init(void)
{
    int config_calls_before;
    int prepare_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
    prepare_calls_before = g_config_prepare_calls;
    g_chaos_process_symbols_once = CHAOS_ONCE_INIT;
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
    assert(g_chaos_process_real_wait4 == stub_wait4);
    assert(g_chaos_process_real_waitid == stub_waitid);
    assert(g_chaos_process_real_execvpe == stub_execvpe);
    assert(g_chaos_process_real_fexecve == stub_fexecve);
    assert(g_chaos_process_real_system == stub_system);
    assert(g_chaos_process_real_popen == stub_popen);
    assert(g_config_init_calls == config_calls_before + 1);
    /* Loading at start-up reports a bad rule file before the first intercepted call. */
    assert(g_config_prepare_calls == prepare_calls_before + 1);
    assert(g_chaos_process_process_seed != 0U);
    assert(g_chaos_process_tls_prng_state != 0U);
}

int main(void)
{
    test_resolve_symbol_and_seed_helpers();
    test_resolve_symbol_abort_path();
#ifdef __linux__
    test_try_resolve_symbol_missing();
    test_seed_fallback_paths();
#endif
    test_constructor_init();
    return 0;
}
