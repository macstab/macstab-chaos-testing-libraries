/**
 * @file test_chaos_process.c
 * @brief Proves the libchaos-process wrappers: effect order, error convention, fallbacks.
 *
 * @details
 * Unit under test: `src/process/chaos_process_hooks.c`, the wrappers for pthread_create, fork,
 * posix_spawn(p), the exec family, system, popen and the wait family. For every wrapper the
 * suite proves:
 * - the re-entrancy guard bypasses all rules and calls the real function;
 * - a LATENCY rule delays and then still calls the real function;
 * - a firing ERRNO or FAIL_AFTER rule fails the call without calling the real function, using
 *   the function's own error convention: the error as return value for pthread_create and
 *   posix_spawn(p) (errno untouched), -1 + errno for fork/exec/wait, NULL + errno for popen;
 * - a real-function error passes through unchanged;
 * - with no real function resolved, a wrapper backed by one system call makes that call, and
 *   one with no single system call fails with ENOSYS (EAGAIN for pthread_create).
 *
 * Isolation:
 * - The 20 interposed names are renamed by macro to `chaos_process_test_*_wrapper` before the
 *   production source is included, so the wrappers are callable without LD_PRELOAD and do not
 *   collide with libc. The tests themselves still use libc's real `fork` and `waitpid`.
 * - Rule matching and the effect helpers are replaced by stubs: `g_stub_match` /
 *   `g_stub_rules` decide which (effect, operation) matches, and `g_errno_trigger` /
 *   `g_fail_after_trigger` decide whether a matched rule fires. Probability, qualifiers and
 *   counters are therefore out of scope here (see test_process_actions.c).
 * - The real-function pointers are set per scenario to counting stubs with distinct return
 *   values (fork 123, posix_spawn pid 234, posix_spawnp pid 345, waitpid 321).
 * - `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` makes `chaos_process_ensure_symbols()` a no-op so a
 *   wrapper never overwrites the pointers a test set.
 *
 * Every scenario starts from `reset_wrapper_state()`, because a pointer, match flag or trigger
 * left set by one scenario would change the next one's outcome.
 */
#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

#include <fcntl.h> /* AT_FDCWD */

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

/** @brief Rule returned by the match stub, indexed `[effect][operation]`. */
static chaos_process_rule_t g_stub_rules[3][CHAOS_PROCESS_OP_COUNT];
/** @brief Non-zero makes `chaos_process_config_match(effect, op)` match, `[effect][op]`. */
static int g_stub_match[3][CHAOS_PROCESS_OP_COUNT];
/** @brief LATENCY applications; the stub never sleeps. */
static int g_latency_calls = 0;
/** @brief Non-zero makes a matched ERRNO rule fire; zero models a probability miss. */
static int g_errno_trigger = 0;
/** @brief Non-zero makes a matched FAIL_AFTER rule fire; zero models "not yet". */
static int g_fail_after_trigger = 0;
/** @brief Calls that reached the real `pthread_create` stub. */
static int g_real_pthread_create_calls = 0;
/** @brief Calls that reached the real `fork` stub. */
static int g_real_fork_calls = 0;
/** @brief Calls that reached the real `posix_spawn` stub. */
static int g_real_posix_spawn_calls = 0;
/** @brief Calls that reached the real `posix_spawnp` stub. */
static int g_real_posix_spawnp_calls = 0;
/** @brief Calls that reached the real `execve` stub. */
static int g_real_execve_calls = 0;
/** @brief Calls that reached the real `execveat` stub (Linux only). */
static int g_real_execveat_calls = 0;
/** @brief Calls that reached the real `waitpid` stub. */
static int g_real_waitpid_calls = 0;
/** @brief Return value of the real `pthread_create` stub (0 or an error number). */
static int g_real_pthread_create_result = 0;
/** @brief Return value of the real `fork` stub; 123 is a parent-side child pid. */
static pid_t g_real_fork_result = 123;
/** @brief Return value of the real `posix_spawn` stub. */
static int g_real_posix_spawn_result = 0;
/** @brief Return value of the real `posix_spawnp` stub. */
static int g_real_posix_spawnp_result = 0;
/** @brief Return value of the real `execve` stub; -1 also sets `g_real_execve_errno`. */
static int g_real_execve_result = 0;
/** @brief Return value of the real `execveat` stub; -1 also sets its errno (Linux only). */
static int g_real_execveat_result = 0;
/** @brief Return value of the real `waitpid`/`wait4` stubs; 321 is a reaped child pid. */
static pid_t g_real_waitpid_result = 321;
/** @brief errno the real `execve` stub sets when it returns -1. */
static int g_real_execve_errno = 0;
/** @brief errno the real `execveat` stub sets when it returns -1 (Linux only). */
static int g_real_execveat_errno = 0;
/** @brief errno the real `waitpid` stub sets when it returns -1. */
static int g_real_waitpid_errno = 0;
/** @brief `pid` seen by the last real `waitpid`/`wait4` stub call. */
static pid_t g_last_waitpid_pid = 0;
/** @brief `options` seen by the last real `waitpid`/`wait4` stub call. */
static int g_last_waitpid_options = 0;

/**
 * @brief Clears real-function pointers, match tables, triggers, counters and stub results.
 *
 * Also zeroes the guard, so a scenario that set it cannot leak a bypass into the next one.
 * Counters declared after this function (wait4, waitid, exec family) are reset by the tests
 * that use them.
 */
static void reset_wrapper_state(void)
{
    size_t effect_index;
    size_t operation_index;

    chaos_process_test_reset_runtime();
    for (effect_index = 0U; effect_index < 3U; ++effect_index)
    {
        for (operation_index = 0U; operation_index < (size_t)CHAOS_PROCESS_OP_COUNT;
             ++operation_index)
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
    g_fail_after_trigger = 0;
    g_real_pthread_create_calls = 0;
    g_real_fork_calls = 0;
    g_real_posix_spawn_calls = 0;
    g_real_posix_spawnp_calls = 0;
    g_real_execve_calls = 0;
    g_real_execveat_calls = 0;
    g_real_waitpid_calls = 0;
    g_real_pthread_create_result = 0;
    g_real_fork_result = 123;
    g_real_posix_spawn_result = 0;
    g_real_posix_spawnp_result = 0;
    g_real_execve_result = 0;
    g_real_execveat_result = 0;
    g_real_waitpid_result = 321;
    g_real_execve_errno = 0;
    g_real_execveat_errno = 0;
    g_real_waitpid_errno = 0;
    g_last_waitpid_pid = 0;
    g_last_waitpid_options = 0;
}

/**
 * @brief Replaces rule matching: matches when `g_stub_match[effect][operation]` is set.
 *
 * Copies the configured rule out, as the real matcher does, and rejects out-of-range indices so
 * a wrapper passing a wrong operation fails to match instead of reading past the tables.
 */
int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
)
{
    if (effect < 0 || effect > CHAOS_PROCESS_EFFECT_FAIL_AFTER || operation < 0 ||
        operation >= CHAOS_PROCESS_OP_COUNT || rule == NULL || g_stub_match[effect][operation] == 0)
    {
        return 0;
    }

    *rule = g_stub_rules[effect][operation];
    return 1;
}

/** @brief Replaces LATENCY: counts the call instead of sleeping. */
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Replaces the ERRNO decision: fires when `g_errno_trigger` is set and the rule is ERRNO.
 *
 * Keeps the real helper's contract: writes `*errnum` only when it returns 1.
 */
int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum)
{
    if (rule == NULL || errnum == NULL || rule->effect != CHAOS_PROCESS_EFFECT_ERRNO ||
        g_errno_trigger == 0)
    {
        return 0;
    }

    *errnum = rule->errnum;
    return 1;
}

/**
 * @brief Replaces the FAIL_AFTER decision: fires when `g_fail_after_trigger` is set.
 *
 * Tests give FAIL_AFTER a different errno than ERRNO in the same suite (ENOMEM vs EAGAIN,
 * ENOENT vs EACCES, ECHILD vs EINTR), so the observed errno identifies which effect fired.
 */
int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
)
{
    if (rule == NULL || errnum == NULL || operation < 0 || operation >= CHAOS_PROCESS_OP_COUNT ||
        rule->effect != CHAOS_PROCESS_EFFECT_FAIL_AFTER || g_fail_after_trigger == 0)
    {
        return 0;
    }

    *errnum = rule->errnum;
    return 1;
}

/** @brief Non-NULL start routine for pthread_create calls; never run by the stubs. */
static void *stub_start_routine(void *argument)
{
    return argument;
}

/** @brief Real `pthread_create` stand-in: counts, returns `g_real_pthread_create_result`. */
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
    ++g_real_pthread_create_calls;
    return g_real_pthread_create_result;
}

/** @brief Real `fork` stand-in: counts, returns `g_real_fork_result`; never forks. */
static pid_t stub_fork(void)
{
    ++g_real_fork_calls;
    return g_real_fork_result;
}

/**
 * @brief Real `posix_spawn` stand-in: counts, stores pid 234, returns its configured result.
 *
 * 234 differs from the fork (123) and posix_spawnp (345) values, so a pid proves which real
 * function the wrapper reached.
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

    ++g_real_posix_spawn_calls;
    if (pid != NULL)
    {
        *pid = 234;
    }
    return g_real_posix_spawn_result;
}

/** @brief Real `posix_spawnp` stand-in: counts, stores pid 345, returns its result. */
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

    ++g_real_posix_spawnp_calls;
    if (pid != NULL)
    {
        *pid = 345;
    }
    return g_real_posix_spawnp_result;
}

/**
 * @brief Arguments of the last exec stub call, copied while the caller's array is alive.
 *
 * The execl forms build argv as a VLA on their own stack, which is gone once they return, so
 * the strings are copied rather than the pointer kept. An empty string after the last argument
 * marks the terminating NULL.
 */
static char g_last_exec_args[4][16];
/** @brief `argv` passed to the last real `execve` stub call; proves pass-through. */
static char *const *g_last_execve_argv = NULL;
/** @brief `envp` passed to the last real `execve` stub call; proves `environ` use. */
static char *const *g_last_execve_envp = NULL;

/**
 * @brief Copies up to three arguments into `g_last_exec_args`.
 *
 * Asserts a NULL follows them, proving the wrapper terminated the argv it assembled.
 */
static void record_exec_args(char *const argv[])
{
    size_t index;

    (void)memset(g_last_exec_args, 0, sizeof(g_last_exec_args));
    for (index = 0U; index < 3U && argv[index] != NULL; ++index)
    {
        (void)snprintf(g_last_exec_args[index], sizeof(g_last_exec_args[index]), "%s", argv[index]);
    }
    assert(argv[index] == NULL);
}

/** @brief Real `execve` stand-in: records argv/envp, counts, returns its configured result. */
static int stub_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    g_last_execve_argv = argv;
    g_last_execve_envp = envp;
    record_exec_args(argv);

    ++g_real_execve_calls;
    if (g_real_execve_result == -1)
    {
        errno = g_real_execve_errno;
    }
    return g_real_execve_result;
}

#ifdef __linux__
/** @brief Real `execveat` stand-in: counts and returns its configured result and errno. */
static int
stub_execveat(int directory_fd, const char *path, char *const argv[], char *const envp[], int flags)
{
    (void)directory_fd;
    (void)path;
    (void)argv;
    (void)envp;
    (void)flags;

    ++g_real_execveat_calls;
    if (g_real_execveat_result == -1)
    {
        errno = g_real_execveat_errno;
    }
    return g_real_execveat_result;
}
#endif

/** @brief Calls that reached the real `wait4` stub. */
static int g_real_wait4_calls = 0;
/** @brief `usage` seen by the last real `wait4` stub call; proves wait3 passes it on. */
static struct rusage *g_last_wait4_usage = NULL;
/** @brief Calls that reached the real `waitid` stub. */
static int g_real_waitid_calls = 0;

/** @brief Real `wait4` stand-in: records pid/options/usage, returns `g_real_waitpid_result`. */
static pid_t stub_wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    (void)status;
    ++g_real_wait4_calls;
    g_last_waitpid_pid = pid;
    g_last_waitpid_options = options;
    g_last_wait4_usage = usage;
    return g_real_waitpid_result;
}

/** @brief Real `waitid` stand-in: counts and returns 0. */
static int stub_waitid(idtype_t type, id_t id, siginfo_t *info, int options)
{
    (void)type;
    (void)id;
    (void)info;
    (void)options;
    ++g_real_waitid_calls;
    return 0;
}

/** @brief Real `waitpid` stand-in: records pid/options, returns its configured result. */
static pid_t stub_waitpid(pid_t pid, int *status, int options)
{
    (void)status;
    ++g_real_waitpid_calls;
    g_last_waitpid_pid = pid;
    g_last_waitpid_options = options;
    if (g_real_waitpid_result == -1)
    {
        errno = g_real_waitpid_errno;
    }
    return g_real_waitpid_result;
}

/** @brief Calls that reached the real execvpe, fexecve, system or popen stubs. */
static int g_real_exec_family_calls = 0;
/** @brief `argv` passed to the last real `execvpe` stub call. */
static char *const *g_last_execvpe_argv = NULL;
/** @brief `envp` passed to the last real `execvpe` stub call. */
static char *const *g_last_execvpe_envp = NULL;

/** @brief Real `execvpe` stand-in: records argv/envp, fails with -1/ENOENT. */
static int stub_execvpe(const char *file, char *const argv[], char *const envp[])
{
    (void)file;
    ++g_real_exec_family_calls;
    g_last_execvpe_argv = argv;
    g_last_execvpe_envp = envp;
    record_exec_args(argv);
    errno = ENOENT;
    return -1;
}

/** @brief Real `fexecve` stand-in: fails with -1/ENOENT. */
static int stub_fexecve(int fd, char *const argv[], char *const envp[])
{
    (void)fd;
    (void)argv;
    (void)envp;
    ++g_real_exec_family_calls;
    errno = ENOENT;
    return -1;
}

/** @brief Real `system` stand-in: returns 7, a value no injected failure produces. */
static int stub_system(const char *command)
{
    (void)command;
    ++g_real_exec_family_calls;
    return 7;
}

/** @brief Real `popen` stand-in: returns `stdin` as a recognisable non-NULL stream. */
static FILE *stub_popen(const char *command, const char *mode)
{
    (void)command;
    (void)mode;
    ++g_real_exec_family_calls;
    return stdin;
}

/* Renaming the 20 interposed names keeps the wrappers from replacing libc's symbols in this test
 * binary and makes them callable by a distinct name. The #undefs restore libc's real fork and
 * waitpid for the child-process helpers below. */
#define pthread_create chaos_process_test_pthread_create_wrapper
#define fork chaos_process_test_fork_wrapper
#define posix_spawn chaos_process_test_posix_spawn_wrapper
#define posix_spawnp chaos_process_test_posix_spawnp_wrapper
#define execve chaos_process_test_execve_wrapper
#ifdef __linux__
#define execveat chaos_process_test_execveat_wrapper
#endif
#define waitpid chaos_process_test_waitpid_wrapper
#define wait chaos_process_test_wait_wrapper
#define wait3 chaos_process_test_wait3_wrapper
#define wait4 chaos_process_test_wait4_wrapper
#define waitid chaos_process_test_waitid_wrapper
#define execv chaos_process_test_execv_wrapper
#define execvp chaos_process_test_execvp_wrapper
#define execvpe chaos_process_test_execvpe_wrapper
#define execl chaos_process_test_execl_wrapper
#define execlp chaos_process_test_execlp_wrapper
#define execle chaos_process_test_execle_wrapper
#define fexecve chaos_process_test_fexecve_wrapper
#define system chaos_process_test_system_wrapper
#define popen chaos_process_test_popen_wrapper
#include "../../src/process/chaos_process_hooks.c"
#undef popen
#undef system
#undef fexecve
#undef execle
#undef execlp
#undef execl
#undef execvpe
#undef execvp
#undef execv
#undef waitid
#undef wait4
#undef wait3
#undef wait
#undef waitpid
#ifdef __linux__
#undef execveat
#endif
#undef execve
#undef posix_spawnp
#undef posix_spawn
#undef fork
#undef pthread_create

/**
 * @brief Proves each real-function helper forwards its arguments and result unchanged.
 *
 * Also covers the two late-binding cases. pthread_create still unresolved is resolved on first
 * use (libpthread loaded by `dlopen()` after start-up); if it stays unresolved the call returns
 * EAGAIN, the error pthread_create documents, because no single system call creates a thread.
 * execveat unresolved (musl) falls back to the raw system call, proven by the kernel's ENOENT
 * for a missing program while the stub's counter stays put.
 */
static void test_call_real_helpers(void)
{
    pthread_t thread = (pthread_t)0;
    pid_t pid = 0;
    char *argv[] = {(char *)"tool", NULL};
    char *envp[] = {NULL};

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_chaos_process_real_fork = stub_fork;
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_chaos_process_real_execve = stub_execve;
#ifdef __linux__
    g_chaos_process_real_execveat = stub_execveat;
#endif
    g_chaos_process_real_waitpid = stub_waitpid;

    assert(chaos_process_call_real_pthread_create(&thread, NULL, stub_start_routine, NULL) == 0);
    assert(g_real_pthread_create_calls == 1);

    g_chaos_process_real_pthread_create = NULL;
    g_test_late_pthread_create = stub_pthread_create;
    assert(chaos_process_call_real_pthread_create(&thread, NULL, stub_start_routine, NULL) == 0);
    assert(g_real_pthread_create_calls == 2);

    g_chaos_process_real_pthread_create = NULL;
    g_test_late_pthread_create = NULL;
    assert(
        chaos_process_call_real_pthread_create(&thread, NULL, stub_start_routine, NULL) == EAGAIN
    );
    assert(g_real_pthread_create_calls == 2);
    g_chaos_process_real_pthread_create = stub_pthread_create;

    assert(chaos_process_call_real_fork() == 123);
    assert(g_real_fork_calls == 1);

    assert(chaos_process_call_real_posix_spawn(&pid, "/bin/echo", NULL, NULL, argv, envp) == 0);
    assert(g_real_posix_spawn_calls == 1);
    assert(pid == 234);

    assert(chaos_process_call_real_posix_spawnp(&pid, "echo", NULL, NULL, argv, envp) == 0);
    assert(g_real_posix_spawnp_calls == 1);
    assert(pid == 345);

    assert(chaos_process_call_real_execve("/bin/echo", argv, envp) == 0);
    assert(g_real_execve_calls == 1);

#ifdef __linux__
    assert(chaos_process_call_real_execveat(AT_FDCWD, "/bin/echo", argv, envp, 0) == 0);
    assert(g_real_execveat_calls == 1);

    g_chaos_process_real_execveat = NULL;
    errno = 0;
    assert(
        chaos_process_call_real_execveat(AT_FDCWD, "/nonexistent/chaos-tool", argv, envp, 0) == -1
    );
    assert(errno == ENOENT);
    assert(g_real_execveat_calls == 1);
    g_chaos_process_real_execveat = stub_execveat;
#endif

    assert(chaos_process_call_real_waitpid(777, NULL, WNOHANG) == 321);
    assert(g_real_waitpid_calls == 1);
    assert(g_last_waitpid_pid == 777);
    assert(g_last_waitpid_options == WNOHANG);
}

/**
 * @brief Proves the pthread_create wrapper returns injected errors as the result, not in errno.
 *
 * pthread_create reports failure by return value and leaves errno unspecified; a wrapper that
 * set errno instead would make a failing call look successful. Scenarios: guard bypass,
 * LATENCY then real call, ERRNO (EAGAIN) and FAIL_AFTER (ENOMEM) without the real call and with
 * errno still 0, and a real EAGAIN passed through.
 */
static void test_pthread_create_paths(void)
{
    pthread_t thread = (pthread_t)0;

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == 0);
    assert(g_real_pthread_create_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_PTHREAD_CREATE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_PTHREAD_CREATE].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_pthread_create_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_PTHREAD_CREATE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_PTHREAD_CREATE].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_PTHREAD_CREATE].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(
        chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == EAGAIN
    );
    assert(errno == 0);
    assert(g_real_pthread_create_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_PTHREAD_CREATE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_PTHREAD_CREATE].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_PTHREAD_CREATE].errnum = ENOMEM;
    g_fail_after_trigger = 1;
    assert(
        chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == ENOMEM
    );
    assert(g_real_pthread_create_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_real_pthread_create_result = EAGAIN;
    assert(
        chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == EAGAIN
    );
}

/**
 * @brief Proves the fork wrapper fails with -1 + errno and never forks when a rule fires.
 *
 * Scenarios: guard bypass and LATENCY both reach the real fork (pid 123); ERRNO (EAGAIN) and
 * FAIL_AFTER (ENOMEM) return -1 with that errno and leave the real fork uncalled.
 */
static void test_fork_paths(void)
{
    reset_wrapper_state();
    g_chaos_process_real_fork = stub_fork;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_fork_wrapper() == 123);
    assert(g_real_fork_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_fork = stub_fork;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_FORK] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_FORK].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_fork_wrapper() == 123);
    assert(g_latency_calls == 1);
    assert(g_real_fork_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_fork = stub_fork;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_FORK] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_FORK].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_FORK].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_fork_wrapper() == -1);
    assert(errno == EAGAIN);
    assert(g_real_fork_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_fork = stub_fork;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_FORK] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_FORK].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_FORK].errnum = ENOMEM;
    g_fail_after_trigger = 1;
    errno = 0;
    assert(chaos_process_test_fork_wrapper() == -1);
    assert(errno == ENOMEM);
    assert(g_real_fork_calls == 0);
}

/**
 * @brief Proves the posix_spawn wrapper returns injected errors as the result, errno untouched.
 *
 * posix_spawn, like pthread_create, reports failure by return value. Scenarios: guard bypass
 * (pid 234 written by the real function), LATENCY then real call, ERRNO (EAGAIN) and FAIL_AFTER
 * (ENOMEM) without the real call.
 */
static void test_posix_spawn_paths(void)
{
    pid_t pid = 0;
    char *argv[] = {(char *)"echo", NULL};
    char *envp[] = {NULL};

    reset_wrapper_state();
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_posix_spawn_wrapper(&pid, "/bin/echo", NULL, NULL, argv, envp) == 0);
    assert(g_real_posix_spawn_calls == 1);
    assert(pid == 234);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_POSIX_SPAWN] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_POSIX_SPAWN].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_posix_spawn_wrapper(&pid, "/bin/echo", NULL, NULL, argv, envp) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_posix_spawn_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(
        chaos_process_test_posix_spawn_wrapper(&pid, "/bin/echo", NULL, NULL, argv, envp) == EAGAIN
    );
    assert(errno == 0);
    assert(g_real_posix_spawn_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWN] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWN].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWN].errnum = ENOMEM;
    g_fail_after_trigger = 1;
    assert(
        chaos_process_test_posix_spawn_wrapper(&pid, "/bin/echo", NULL, NULL, argv, envp) == ENOMEM
    );
    assert(g_real_posix_spawn_calls == 0);
}

/**
 * @brief Proves posix_spawnp has its own operation and the posix_spawn error convention.
 *
 * Rules are keyed on OP_POSIX_SPAWNP, not OP_POSIX_SPAWN; pid 345 proves the wrapper reached
 * the real posix_spawnp. Scenarios match test_posix_spawn_paths().
 */
static void test_posix_spawnp_paths(void)
{
    pid_t pid = 0;
    char *argv[] = {(char *)"echo", NULL};
    char *envp[] = {NULL};

    reset_wrapper_state();
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "echo", NULL, NULL, argv, envp) == 0);
    assert(g_real_posix_spawnp_calls == 1);
    assert(pid == 345);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_POSIX_SPAWNP] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_POSIX_SPAWNP].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "echo", NULL, NULL, argv, envp) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_posix_spawnp_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWNP] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWNP].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWNP].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "echo", NULL, NULL, argv, envp) == EAGAIN);
    assert(errno == 0);
    assert(g_real_posix_spawnp_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWNP] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWNP].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_POSIX_SPAWNP].errnum = ENOMEM;
    g_fail_after_trigger = 1;
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "echo", NULL, NULL, argv, envp) == ENOMEM);
    assert(g_real_posix_spawnp_calls == 0);
}

/**
 * @brief Proves the execve wrapper fails with -1 + errno and does not exec when a rule fires.
 *
 * Scenarios: guard bypass and LATENCY reach the real execve; ERRNO (EACCES) and FAIL_AFTER
 * (ENOENT) return -1 with that errno and skip it; a real E2BIG failure keeps its errno, proving
 * the wrapper does not clobber errno after the real call.
 */
static void test_execve_paths(void)
{
    char *argv[] = {(char *)"echo", NULL};
    char *envp[] = {NULL};

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == 0);
    assert(g_real_execve_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_EXECVE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_EXECVE].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_execve_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE].errnum = EACCES;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == -1);
    assert(errno == EACCES);
    assert(g_real_execve_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVE].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVE].errnum = ENOENT;
    g_fail_after_trigger = 1;
    errno = 0;
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == -1);
    assert(errno == ENOENT);
    assert(g_real_execve_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_real_execve_result = -1;
    g_real_execve_errno = E2BIG;
    errno = 0;
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == -1);
    assert(errno == E2BIG);
}

#ifdef __linux__
/**
 * @brief Proves execveat (Linux only) has its own operation and the execve error convention.
 *
 * Rules are keyed on OP_EXECVEAT. Scenarios and errnos match test_execve_paths().
 */
static void test_execveat_paths(void)
{
    char *argv[] = {(char *)"echo", NULL};
    char *envp[] = {NULL};

    reset_wrapper_state();
    g_chaos_process_real_execveat = stub_execveat;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == 0);
    assert(g_real_execveat_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_execveat = stub_execveat;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_EXECVEAT] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_EXECVEAT].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_execveat_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_execveat = stub_execveat;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT].errnum = EACCES;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == -1);
    assert(errno == EACCES);
    assert(g_real_execveat_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_execveat = stub_execveat;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVEAT] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVEAT].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_EXECVEAT].errnum = ENOENT;
    g_fail_after_trigger = 1;
    errno = 0;
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == -1);
    assert(errno == ENOENT);
    assert(g_real_execveat_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_execveat = stub_execveat;
    g_real_execveat_result = -1;
    g_real_execveat_errno = E2BIG;
    errno = 0;
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == -1);
    assert(errno == E2BIG);
}
#endif

/**
 * @brief Proves the waitpid wrapper forwards pid/options and fails with -1 + errno on a rule.
 *
 * Scenarios: guard bypass (pid 456 forwarded, 321 returned), LATENCY then real call, ERRNO
 * (EINTR) and FAIL_AFTER (ECHILD) without reaping anything, and a real ECHILD passed through.
 * Not reaping matters: an injected failure must leave the child for a later retry.
 */
static void test_waitpid_paths(void)
{
    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == 321);
    assert(g_real_waitpid_calls == 1);
    assert(g_last_waitpid_pid == 456);

    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    g_stub_match[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_WAITPID] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_LATENCY][CHAOS_PROCESS_OP_WAITPID].effect =
        CHAOS_PROCESS_EFFECT_LATENCY;
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == 321);
    assert(g_latency_calls == 1);
    assert(g_real_waitpid_calls == 1);

    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID].errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == -1);
    assert(errno == EINTR);
    assert(g_real_waitpid_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID].errnum = ECHILD;
    g_fail_after_trigger = 1;
    errno = 0;
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == -1);
    assert(errno == ECHILD);
    assert(g_real_waitpid_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    g_real_waitpid_result = -1;
    g_real_waitpid_errno = ECHILD;
    errno = 0;
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == -1);
    assert(errno == ECHILD);
}

/**
 * @brief Proves wait, wait3, wait4 and waitid share the `waitpid` selector.
 *
 * One `waitpid` rule covers every way to reap a child, so a rule cannot be dodged by a program
 * that calls wait4 or waitid. wait(s) becomes waitpid(-1, s, 0); wait3 becomes wait4(-1, ...)
 * with `usage` passed through. wait4 and waitid reach the real call with no rule and under the
 * guard, and fail with -1 + errno under a firing ERRNO or FAIL_AFTER rule on OP_WAITPID.
 */
static void test_wait_family_paths(void)
{
    struct rusage usage;
    siginfo_t info;

    reset_wrapper_state();
    g_chaos_process_real_waitpid = stub_waitpid;
    assert(chaos_process_test_wait_wrapper(NULL) == 321);
    assert(g_last_waitpid_pid == -1);
    assert(g_last_waitpid_options == 0);

    reset_wrapper_state();
    g_chaos_process_real_wait4 = stub_wait4;
    g_real_wait4_calls = 0;
    assert(chaos_process_test_wait3_wrapper(NULL, WNOHANG, &usage) == 321);
    assert(g_real_wait4_calls == 1);
    assert(g_last_waitpid_pid == -1);
    assert(g_last_waitpid_options == WNOHANG);
    assert(g_last_wait4_usage == &usage);

    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_wait4_wrapper(7, NULL, 0, NULL) == 321);
    assert(g_real_wait4_calls == 2);
    g_chaos_process_tls_guard = 0;

    reset_wrapper_state();
    g_chaos_process_real_waitid = stub_waitid;
    g_real_waitid_calls = 0;
    assert(chaos_process_test_waitid_wrapper(P_ALL, 0, &info, WEXITED) == 0);
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_waitid_wrapper(P_ALL, 0, &info, WEXITED) == 0);
    g_chaos_process_tls_guard = 0;
    assert(g_real_waitid_calls == 2);

    reset_wrapper_state();
    g_chaos_process_real_wait4 = stub_wait4;
    g_chaos_process_real_waitid = stub_waitid;
    g_real_wait4_calls = 0;
    g_real_waitid_calls = 0;
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_WAITPID].errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_wait4_wrapper(7, NULL, 0, NULL) == -1);
    assert(errno == EINTR);
    errno = 0;
    assert(chaos_process_test_waitid_wrapper(P_ALL, 0, &info, WEXITED) == -1);
    assert(errno == EINTR);
    assert(g_real_wait4_calls == 0);
    assert(g_real_waitid_calls == 0);

    reset_wrapper_state();
    g_chaos_process_real_waitid = stub_waitid;
    g_real_waitid_calls = 0;
    g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID].effect =
        CHAOS_PROCESS_EFFECT_FAIL_AFTER;
    g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][CHAOS_PROCESS_OP_WAITPID].errnum = ECHILD;
    g_fail_after_trigger = 1;
    errno = 0;
    assert(chaos_process_test_waitid_wrapper(P_ALL, 0, &info, WEXITED) == -1);
    assert(errno == ECHILD);
    assert(g_real_waitid_calls == 0);
}

/**
 * @brief Proves the exec family maps onto existing selectors and builds argv correctly.
 *
 * Mapping: execv/execl/execle/execvp/execlp/execvpe use `execve`, fexecve uses `execveat`
 * (Linux only), system and popen use `posix_spawn`.
 * - execv/execl/execle reach the real execve with the given or assembled argv (NULL-terminated,
 *   checked through `g_last_exec_args`) and `environ`, or execle's trailing envp.
 * - execvp/execlp reach the real execvpe with `environ`.
 * - A firing ERRNO rule fails execvpe, fexecve, system (-1) and popen (NULL) with its errno and
 *   no real call.
 * - An unresolved real execvpe or fexecve fails with ENOSYS.
 * - system(NULL) bypasses rules: it only asks whether a shell exists and must not be failed.
 */
static void test_exec_family_paths(void)
{
    char *const argv[] = {(char *)"tool", (char *)"-x", NULL};
    char *const envp[] = {(char *)"A=1", NULL};

    reset_wrapper_state();
    g_chaos_process_real_execve = stub_execve;
    g_real_execve_result = -1;
    g_real_execve_errno = ENOENT;
    assert(chaos_process_test_execv_wrapper("/bin/tool", argv) == -1);
    assert(g_last_execve_argv == argv);
    assert(g_last_execve_envp == environ);

    assert(chaos_process_test_execl_wrapper("/bin/tool", "tool", "-x", "-y", (char *)NULL) == -1);
    assert(strcmp(g_last_exec_args[0], "tool") == 0);
    assert(strcmp(g_last_exec_args[2], "-y") == 0);
    assert(g_last_execve_envp == environ);

    assert(chaos_process_test_execle_wrapper("/bin/tool", "tool", (char *)NULL, envp) == -1);
    assert(strcmp(g_last_exec_args[0], "tool") == 0);
    assert(g_last_exec_args[1][0] == '\0');
    assert(g_last_execve_envp == envp);
    assert(chaos_process_test_execle_wrapper("/bin/tool", "tool", "-v", (char *)NULL, envp) == -1);
    assert(strcmp(g_last_exec_args[1], "-v") == 0);
    assert(g_last_execve_envp == envp);

    reset_wrapper_state();
    g_real_exec_family_calls = 0;
    g_chaos_process_real_execvpe = stub_execvpe;
    assert(chaos_process_test_execvp_wrapper("tool", argv) == -1);
    assert(g_last_execvpe_argv == argv);
    assert(g_last_execvpe_envp == environ);
    assert(chaos_process_test_execlp_wrapper("tool", "tool", "-z", (char *)NULL) == -1);
    assert(strcmp(g_last_exec_args[1], "-z") == 0);
    assert(g_last_exec_args[2][0] == '\0');
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_execvpe_wrapper("tool", argv, envp) == -1);
    g_chaos_process_tls_guard = 0;
    assert(g_real_exec_family_calls == 3);

    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVE].errnum = EACCES;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_execvpe_wrapper("tool", argv, envp) == -1);
    assert(errno == EACCES);
    assert(g_real_exec_family_calls == 3);

    reset_wrapper_state();
    g_chaos_process_real_execvpe = NULL;
    g_chaos_process_real_fexecve = NULL;
    errno = 0;
    assert(chaos_process_test_execvpe_wrapper("tool", argv, envp) == -1);
    assert(errno == ENOSYS);
    errno = 0;
    assert(chaos_process_test_fexecve_wrapper(3, argv, envp) == -1);
    assert(errno == ENOSYS);

    reset_wrapper_state();
    g_real_exec_family_calls = 0;
    g_chaos_process_real_fexecve = stub_fexecve;
    assert(chaos_process_test_fexecve_wrapper(3, argv, envp) == -1);
    assert(errno == ENOENT);
    assert(g_real_exec_family_calls == 1);
#ifdef __linux__
    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_EXECVEAT].errnum = EACCES;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_fexecve_wrapper(3, argv, envp) == -1);
    assert(errno == EACCES);
    assert(g_real_exec_family_calls == 1);
#endif

    reset_wrapper_state();
    g_real_exec_family_calls = 0;
    g_chaos_process_real_system = stub_system;
    g_chaos_process_real_popen = stub_popen;
    assert(chaos_process_test_system_wrapper("true") == 7);
    assert(chaos_process_test_popen_wrapper("true", "r") == stdin);
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_popen_wrapper("true", "r") == stdin);
    g_chaos_process_tls_guard = 0;
    assert(g_real_exec_family_calls == 3);

    g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN] = 1;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN].effect =
        CHAOS_PROCESS_EFFECT_ERRNO;
    g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][CHAOS_PROCESS_OP_POSIX_SPAWN].errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_process_test_system_wrapper("true") == -1);
    assert(errno == EAGAIN);
    errno = 0;
    assert(chaos_process_test_popen_wrapper("true", "r") == NULL);
    assert(errno == EAGAIN);
    assert(chaos_process_test_system_wrapper(NULL) == 7);
    g_chaos_process_tls_guard = 1;
    assert(chaos_process_test_system_wrapper("true") == 7);
    g_chaos_process_tls_guard = 0;
    assert(g_real_exec_family_calls == 5);
}

/**
 * @brief Proves a matched rule that does not fire leaves every wrapper to the real call.
 *
 * An ERRNO and a FAIL_AFTER rule match every operation while both triggers are off, modelling
 * a probability miss or a FAIL_AFTER count not yet reached. Each wrapper must then return the
 * real result exactly once. Finally fexecve under the guard reaches the real fexecve (ENOENT)
 * although its ERRNO rule would fire (EACCES), proving the guard check precedes rule matching.
 */
static void test_rules_that_do_not_fire(void)
{
    pthread_t thread = (pthread_t)0;
    pid_t pid = 0;
    char *argv[] = {(char *)"echo", NULL};
    char *envp[] = {NULL};
    int operation;

    reset_wrapper_state();
    g_real_exec_family_calls = 0;
    g_chaos_process_real_pthread_create = stub_pthread_create;
    g_chaos_process_real_fork = stub_fork;
    g_chaos_process_real_posix_spawn = stub_posix_spawn;
    g_chaos_process_real_posix_spawnp = stub_posix_spawnp;
    g_chaos_process_real_execve = stub_execve;
#ifdef __linux__
    g_chaos_process_real_execveat = stub_execveat;
#endif
    g_chaos_process_real_waitpid = stub_waitpid;
    g_chaos_process_real_execvpe = stub_execvpe;
    g_chaos_process_real_fexecve = stub_fexecve;
    for (operation = 0; operation < (int)CHAOS_PROCESS_OP_COUNT; ++operation)
    {
        g_stub_match[CHAOS_PROCESS_EFFECT_ERRNO][operation] = 1;
        g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][operation].effect = CHAOS_PROCESS_EFFECT_ERRNO;
        g_stub_rules[CHAOS_PROCESS_EFFECT_ERRNO][operation].errnum = EACCES;
        g_stub_match[CHAOS_PROCESS_EFFECT_FAIL_AFTER][operation] = 1;
        g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][operation].effect =
            CHAOS_PROCESS_EFFECT_FAIL_AFTER;
        g_stub_rules[CHAOS_PROCESS_EFFECT_FAIL_AFTER][operation].errnum = ENOMEM;
    }

    assert(chaos_process_test_pthread_create_wrapper(&thread, NULL, stub_start_routine, NULL) == 0);
    assert(chaos_process_test_fork_wrapper() == 123);
    assert(chaos_process_test_posix_spawn_wrapper(&pid, "/bin/echo", NULL, NULL, argv, envp) == 0);
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "echo", NULL, NULL, argv, envp) == 0);
    assert(chaos_process_test_execve_wrapper("/bin/echo", argv, envp) == 0);
#ifdef __linux__
    assert(chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/echo", argv, envp, 0) == 0);
    assert(g_real_execveat_calls == 1);
#endif
    assert(chaos_process_test_waitpid_wrapper(456, NULL, WNOHANG) == 321);
    errno = 0;
    assert(chaos_process_test_execvpe_wrapper("echo", argv, envp) == -1);
    assert(errno == ENOENT);
    assert(g_real_pthread_create_calls == 1);
    assert(g_real_fork_calls == 1);
    assert(g_real_posix_spawn_calls == 1);
    assert(g_real_posix_spawnp_calls == 1);
    assert(g_real_execve_calls == 1);
    assert(g_real_waitpid_calls == 1);
    assert(g_real_exec_family_calls == 1);

    g_errno_trigger = 1;
    g_chaos_process_tls_guard = 1;
    errno = 0;
    assert(chaos_process_test_fexecve_wrapper(3, argv, envp) == -1);
    assert(errno == ENOENT);
    g_chaos_process_tls_guard = 0;
    assert(g_real_exec_family_calls == 2);
}

/** @brief Forks (libc's real fork) a child that `_exit`s with @p code; returns its pid. */
static pid_t spawn_exiting_child(int code)
{
    pid_t child = fork();

    assert(child >= 0);
    if (child == 0)
    {
        _exit(code);
    }
    return child;
}

/**
 * @brief Execs `/bin/sh -c "exit 7"` through a wrapper with no real exec resolved, in a child.
 *
 * Runs in a child because a successful exec replaces the calling process.
 *
 * @param use_execveat  Non-zero uses the execveat wrapper (Linux only), else execve.
 * @return The child's exit status: 7 when the raw system call ran the shell, 99 when the exec
 *   returned.
 */
static int exit_status_of_exec_child(int use_execveat)
{
    char *argv[] = {(char *)"sh", (char *)"-c", (char *)"exit 7", NULL};
    char *envp[] = {NULL};
    int status = 0;
    pid_t child = fork();

    assert(child >= 0);
    if (child == 0)
    {
        g_chaos_process_real_execve = NULL;
#ifdef __linux__
        g_chaos_process_real_execveat = NULL;
        if (use_execveat)
        {
            (void)chaos_process_test_execveat_wrapper(AT_FDCWD, "/bin/sh", argv, envp, 0);
            _exit(99);
        }
#endif
        (void)chaos_process_test_execve_wrapper("/bin/sh", argv, envp);
        _exit(99);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    return WEXITSTATUS(status);
}

/**
 * @brief Proves a wrapper whose real function is unresolved never calls through NULL.
 *
 * All real-function pointers are NULL, as while the symbol lookup itself runs. Wrappers backed
 * by one system call make it: execve and execveat run a real program (exit status 7) or get
 * the kernel's ENOENT, and waitpid/wait4/waitid reap real children with the right status.
 * fork, posix_spawn(p), system and popen have no single system call and fail with ENOSYS in
 * their own convention: -1 + errno, ENOSYS as the result (pid untouched), -1 + errno, NULL +
 * errno.
 */
static void test_unresolved_fallbacks(void)
{
    char *argv[] = {(char *)"tool", NULL};
    char *envp[] = {NULL};
    struct rusage usage;
    siginfo_t info;
    pid_t pid = 42;
    pid_t child;
    int status = 0;

    reset_wrapper_state();

    errno = 0;
    assert(chaos_process_test_fork_wrapper() == -1);
    assert(errno == ENOSYS);
    assert(
        chaos_process_test_posix_spawn_wrapper(&pid, "/bin/true", NULL, NULL, argv, envp) == ENOSYS
    );
    assert(chaos_process_test_posix_spawnp_wrapper(&pid, "true", NULL, NULL, argv, envp) == ENOSYS);
    assert(pid == 42);
    errno = 0;
    assert(chaos_process_test_system_wrapper("true") == -1);
    assert(errno == ENOSYS);
    errno = 0;
    assert(chaos_process_test_popen_wrapper("true", "r") == NULL);
    assert(errno == ENOSYS);

    errno = 0;
    assert(chaos_process_test_execve_wrapper("/nonexistent/chaos-tool", argv, envp) == -1);
    assert(errno == ENOENT);
    assert(exit_status_of_exec_child(0) == 7);
#ifdef __linux__
    assert(exit_status_of_exec_child(1) == 7);
#endif

    child = spawn_exiting_child(5);
    assert(chaos_process_test_waitpid_wrapper(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 5);

    child = spawn_exiting_child(6);
    (void)memset(&usage, 0, sizeof(usage));
    assert(chaos_process_test_wait4_wrapper(child, &status, 0, &usage) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 6);

    child = spawn_exiting_child(9);
    (void)memset(&info, 0, sizeof(info));
    assert(chaos_process_test_waitid_wrapper(P_PID, (id_t)child, &info, WEXITED) == 0);
    assert(info.si_pid == child);
    assert(info.si_status == 9);
}

int main(void)
{
    test_call_real_helpers();
    test_pthread_create_paths();
    test_fork_paths();
    test_posix_spawn_paths();
    test_posix_spawnp_paths();
    test_execve_paths();
#ifdef __linux__
    test_execveat_paths();
#endif
    test_waitpid_paths();
    test_wait_family_paths();
    test_exec_family_paths();
    test_rules_that_do_not_fire();
    test_unresolved_fallbacks();
    return 0;
}
