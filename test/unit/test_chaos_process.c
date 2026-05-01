/**
 * @file test_chaos_process.c
 * @brief Unit tests for the PROCESS-domain wrapper hooks: real-function dispatch helpers,
 *   pthread_create, fork, posix_spawn, posix_spawnp, execve, execveat (Linux), and waitpid.
 *
 * Subsystem under test: `src/process/chaos_process_hooks.c`.
 *
 * Coverage approach:
 * - `chaos_process_hooks.c` is included directly after replacing the six (seven on Linux)
 *   intercepted function names with test-local wrapper names via `#define`:
 *     - `pthread_create` → `chaos_process_test_pthread_create_wrapper`
 *     - `fork`           → `chaos_process_test_fork_wrapper`
 *     - `posix_spawn`    → `chaos_process_test_posix_spawn_wrapper`
 *     - `posix_spawnp`   → `chaos_process_test_posix_spawnp_wrapper`
 *     - `execve`         → `chaos_process_test_execve_wrapper`
 *     - `execveat`       → `chaos_process_test_execveat_wrapper` (Linux-only)
 *     - `waitpid`        → `chaos_process_test_waitpid_wrapper`
 *   This lets tests call the wrappers directly without LD_PRELOAD.
 * - `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` instantiates the real-function-pointer table.
 * - `g_stub_rules[3][CHAOS_PROCESS_OP_COUNT]` and `g_stub_match[3][CHAOS_PROCESS_OP_COUNT]`
 *   are indexed by `[effect_index][operation_index]`. Setting `g_stub_match[e][op] = 1`
 *   causes `chaos_process_config_match(e, op, rule)` to return 1 and copy the corresponding
 *   rule, activating that effect for the next wrapper call.
 * - `reset_wrapper_state()` must be called before each test function (and sometimes between
 *   scenarios within a test) to prevent cross-test contamination.
 * - Each wrapper is tested with four effect scenarios: guard bypass, LATENCY, ERRNO, FAIL_AFTER,
 *   plus a real-function-error passthrough where applicable.
 *
 * Properties under test:
 * - `chaos_process_call_real_pthread_create()`: dispatches to stub; call count == 1.
 * - `chaos_process_call_real_fork()`: returns `g_real_fork_result` (123); call count == 1.
 * - `chaos_process_call_real_posix_spawn()`: pid set to 234; call count == 1.
 * - `chaos_process_call_real_posix_spawnp()`: pid set to 345; call count == 1.
 * - `chaos_process_call_real_execve()`: returns 0; call count == 1.
 * - `chaos_process_call_real_execveat()` (Linux): returns 0; call count == 1.
 * - `chaos_process_call_real_waitpid()`: returns 321; pid and options forwarded.
 * - All wrappers: guard bypass (`g_chaos_process_tls_guard = 1`) → real call, no effect.
 * - All wrappers: LATENCY effect → `g_latency_calls == 1`; real call still made.
 * - All wrappers: ERRNO effect with `g_errno_trigger = 1` → returns error code; real call
 *   skipped; pthread/posix_spawn return the error directly (not via errno); fork/execve/waitpid
 *   set errno.
 * - All wrappers: FAIL_AFTER effect with `g_fail_after_trigger = 1` → returns error; real call
 *   skipped.
 * - All wrappers: real function error passthrough → returns error from real stub; errno set.
 *
 * What is NOT tested here:
 * - Constructor and symbol resolution (`chaos_process_init()`).
 * - Config file parsing and rule matching.
 * - FAIL_AFTER countdown logic (per-operation decrement below threshold).
 */

#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

#include <fcntl.h> /* AT_FDCWD */

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

/**
 * @brief Per-effect, per-operation rule table for the config-match stub.
 *
 * Index as `g_stub_rules[effect_index][operation_index]`. Tests fill the
 * desired cell and set the corresponding `g_stub_match` entry to 1.
 */
static chaos_process_rule_t g_stub_rules[3][CHAOS_PROCESS_OP_COUNT];
/**
 * @brief Per-effect, per-operation match-enable flags for the config-match stub.
 *
 * Non-zero means `chaos_process_config_match(effect, op, rule)` returns 1 and
 * copies the rule from `g_stub_rules[effect][op]` into the caller's output.
 */
static int g_stub_match[3][CHAOS_PROCESS_OP_COUNT];
/** @brief Number of times `chaos_process_rule_apply_latency` was called. */
static int g_latency_calls = 0;
/**
 * @brief When non-zero, causes `chaos_process_rule_error_number` to inject the
 *   rule's `errnum` and return 1, simulating a triggered ERRNO fault.
 */
static int g_errno_trigger = 0;
/**
 * @brief When non-zero, causes `chaos_process_rule_fail_after_error` to inject
 *   the rule's `errnum` and return 1, simulating a triggered FAIL_AFTER fault.
 */
static int g_fail_after_trigger = 0;
/** @brief Number of times the `stub_pthread_create` function was called. */
static int g_real_pthread_create_calls = 0;
/** @brief Number of times the `stub_fork` function was called. */
static int g_real_fork_calls = 0;
/** @brief Number of times the `stub_posix_spawn` function was called. */
static int g_real_posix_spawn_calls = 0;
/** @brief Number of times the `stub_posix_spawnp` function was called. */
static int g_real_posix_spawnp_calls = 0;
/** @brief Number of times the `stub_execve` function was called. */
static int g_real_execve_calls = 0;
/** @brief Number of times the `stub_execveat` function was called (Linux-only). */
static int g_real_execveat_calls = 0;
/** @brief Number of times the `stub_waitpid` function was called. */
static int g_real_waitpid_calls = 0;
/** @brief Return value for `stub_pthread_create`; 0 == success, EAGAIN == resource limit. */
static int g_real_pthread_create_result = 0;
/** @brief Return value for `stub_fork`; 123 simulates a successful parent-side pid. */
static pid_t g_real_fork_result = 123;
/** @brief Return value for `stub_posix_spawn`; 0 == success. */
static int g_real_posix_spawn_result = 0;
/** @brief Return value for `stub_posix_spawnp`; 0 == success. */
static int g_real_posix_spawnp_result = 0;
/** @brief Return value for `stub_execve`; 0 == success, -1 == failure. */
static int g_real_execve_result = 0;
/** @brief Return value for `stub_execveat`; 0 == success, -1 == failure (Linux-only). */
static int g_real_execveat_result = 0;
/** @brief Return value for `stub_waitpid`; 321 simulates a normal child exit. */
static pid_t g_real_waitpid_result = 321;
/**
 * @brief errno value to set when `stub_execve` returns -1.
 *
 * E2BIG is used as a representative exec-failure errno (argument list too long).
 */
static int g_real_execve_errno = 0;
/**
 * @brief errno value to set when `stub_execveat` returns -1 (Linux-only).
 *
 * E2BIG is used for the same reason as `g_real_execve_errno`.
 */
static int g_real_execveat_errno = 0;
/** @brief errno value to set when `stub_waitpid` returns -1. */
static int g_real_waitpid_errno = 0;
/** @brief `pid` argument captured from the most recent `stub_waitpid` call. */
static pid_t g_last_waitpid_pid = 0;
/** @brief `options` argument captured from the most recent `stub_waitpid` call. */
static int g_last_waitpid_options = 0;

/**
 * @brief Reset all wrapper-layer test state between test functions.
 *
 * Calls `chaos_process_test_reset_runtime()` to clear the runtime function-pointer
 * table, then zeroes all local stub tables and counters.
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
 * @brief Stub for `chaos_process_config_match()`.
 *
 * Returns 1 and copies `g_stub_rules[effect][operation]` into @p rule when
 * `g_stub_match[effect][operation] != 0` and all indices are in range.
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

/**
 * @brief Stub for `chaos_process_rule_apply_latency()`.
 *
 * Increments the latency call counter without performing any sleep.
 */
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_process_rule_error_number()`.
 *
 * When `g_errno_trigger != 0` and the rule has ERRNO effect with a valid error
 * pointer, sets `*errnum` to `rule->errnum` and returns 1. Returns 0 otherwise.
 *
 * EAGAIN is the canonical ERRNO used in tests (resource temporarily unavailable),
 * chosen because it is a realistic threading failure code for `pthread_create` and `fork`.
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
 * @brief Stub for `chaos_process_rule_fail_after_error()`.
 *
 * When `g_fail_after_trigger != 0` and the rule has FAIL_AFTER effect with valid
 * parameters, sets `*errnum` to `rule->errnum` and returns 1. Returns 0 otherwise.
 *
 * ENOMEM is used in tests to distinguish FAIL_AFTER from ERRNO (EAGAIN) without
 * ambiguity, reflecting realistic allocation-failure semantics.
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

/** @brief Minimal thread start function used as a non-NULL argument to pthread_create tests. */
static void *stub_start_routine(void *argument)
{
    return argument;
}

/** @brief Stub for the real `pthread_create`. Increments counter; returns
 * `g_real_pthread_create_result`. */
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

/** @brief Stub for the real `fork`. Increments counter; returns `g_real_fork_result` (123). */
static pid_t stub_fork(void)
{
    ++g_real_fork_calls;
    return g_real_fork_result;
}

/**
 * @brief Stub for the real `posix_spawn`. Increments counter; sets `*pid = 234`.
 *
 * Returns `g_real_posix_spawn_result`. The fixed pid value 234 is chosen to be
 * distinct from the fork stub (123) and posix_spawnp stub (345).
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

/**
 * @brief Stub for the real `posix_spawnp`. Increments counter; sets `*pid = 345`.
 *
 * Returns `g_real_posix_spawnp_result`. The fixed pid value 345 allows tests to
 * distinguish posix_spawnp from posix_spawn output.
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

    ++g_real_posix_spawnp_calls;
    if (pid != NULL)
    {
        *pid = 345;
    }
    return g_real_posix_spawnp_result;
}

/**
 * @brief Stub for the real `execve`. Increments counter.
 *
 * When `g_real_execve_result == -1`, sets `errno = g_real_execve_errno` to simulate
 * a failed exec (e.g. E2BIG for argument-list overflow, EACCES for permission denied).
 */
static int stub_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;

    ++g_real_execve_calls;
    if (g_real_execve_result == -1)
    {
        errno = g_real_execve_errno;
    }
    return g_real_execve_result;
}

#ifdef __linux__
/**
 * @brief Stub for the real `execveat` (Linux-only). Increments counter.
 *
 * When `g_real_execveat_result == -1`, sets `errno = g_real_execveat_errno`.
 * E2BIG is the representative error used in tests, same rationale as execve.
 */
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

/**
 * @brief Stub for the real `waitpid`. Captures `pid` and `options`.
 *
 * Returns `g_real_waitpid_result` (321 by default). When `g_real_waitpid_result == -1`,
 * sets `errno = g_real_waitpid_errno`. ECHILD (no child process) and EINTR (interrupted
 * by signal) are the representative errors used in tests.
 */
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

/* Rename all intercepted function names to test-local wrappers before including the source. */
#define pthread_create chaos_process_test_pthread_create_wrapper
#define fork chaos_process_test_fork_wrapper
#define posix_spawn chaos_process_test_posix_spawn_wrapper
#define posix_spawnp chaos_process_test_posix_spawnp_wrapper
#define execve chaos_process_test_execve_wrapper
#ifdef __linux__
#define execveat chaos_process_test_execveat_wrapper
#endif
#define waitpid chaos_process_test_waitpid_wrapper
#include "../../src/process/chaos_process_hooks.c"
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
 * @brief Invariant: `chaos_process_call_real_*` helpers dispatch to the real stubs
 *   and return their values.
 *
 * Triggering condition: each `chaos_process_call_real_*` function called once with
 *   clean state after wiring all real-function-pointer globals to their stubs.
 *
 * Expected observable behaviour:
 * - `call_real_pthread_create`: returns 0; `g_real_pthread_create_calls == 1`.
 * - `call_real_fork`: returns 123; `g_real_fork_calls == 1`.
 * - `call_real_posix_spawn`: returns 0; pid == 234; call count == 1.
 * - `call_real_posix_spawnp`: returns 0; pid == 345; call count == 1.
 * - `call_real_execve`: returns 0; call count == 1.
 * - `call_real_execveat` (Linux): returns 0; call count == 1.
 * - `call_real_waitpid(777, NULL, WNOHANG)`: returns 321; `g_last_waitpid_pid == 777`;
 *   `g_last_waitpid_options == WNOHANG`.
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

    /* Cover the "execveat unavailable on musl" fallback: ENOSYS without
     * incrementing the stub call count. */
    g_chaos_process_real_execveat = NULL;
    errno = 0;
    assert(chaos_process_call_real_execveat(AT_FDCWD, "/bin/echo", argv, envp, 0) == -1);
    assert(errno == ENOSYS);
    assert(g_real_execveat_calls == 1);
    g_chaos_process_real_execveat = stub_execveat;
#endif

    assert(chaos_process_call_real_waitpid(777, NULL, WNOHANG) == 321);
    assert(g_real_waitpid_calls == 1);
    assert(g_last_waitpid_pid == 777);
    assert(g_last_waitpid_options == WNOHANG);
}

/**
 * @brief Invariant: the `pthread_create` wrapper applies guard bypass, latency, ERRNO, and
 *   FAIL_AFTER effects; the ERRNO return code is the error value, not via errno.
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1` (re-entrant bypass).
 * - Wrapper call with LATENCY rule for OP_PTHREAD_CREATE.
 * - Wrapper call with ERRNO rule (EAGAIN) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOMEM) and `g_fail_after_trigger = 1`.
 * - Wrapper call with `g_real_pthread_create_result = EAGAIN` (real-function error passthrough).
 *
 * Expected observable behaviour:
 * - Guard bypass: real stub called; `g_latency_calls == 0`.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EAGAIN): returns EAGAIN directly; `errno` unchanged (0); real stub not called.
 * - FAIL_AFTER (ENOMEM): returns ENOMEM; real stub not called.
 * - Real-function error: returns EAGAIN from stub; call count incremented.
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
 * @brief Invariant: the `fork` wrapper applies guard bypass, latency, ERRNO, and FAIL_AFTER
 *   effects; ERRNO and FAIL_AFTER set errno and return -1.
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1` (re-entrant bypass).
 * - Wrapper call with LATENCY rule for OP_FORK.
 * - Wrapper call with ERRNO rule (EAGAIN) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOMEM) and `g_fail_after_trigger = 1`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 123 (stub value); real stub called.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 123.
 * - ERRNO (EAGAIN): returns -1; `errno == EAGAIN`; real stub not called.
 * - FAIL_AFTER (ENOMEM): returns -1; `errno == ENOMEM`; real stub not called.
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
 * @brief Invariant: the `posix_spawn` wrapper applies guard bypass, latency, ERRNO, and
 *   FAIL_AFTER effects; the ERRNO return code is the error value, not via errno.
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1`.
 * - Wrapper call with LATENCY rule for OP_POSIX_SPAWN.
 * - Wrapper call with ERRNO rule (EAGAIN) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOMEM) and `g_fail_after_trigger = 1`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; pid == 234; real stub called.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EAGAIN): returns EAGAIN; `errno` unchanged (0); real stub not called.
 * - FAIL_AFTER (ENOMEM): returns ENOMEM; real stub not called.
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
 * @brief Invariant: the `posix_spawnp` wrapper applies guard bypass, latency, ERRNO, and
 *   FAIL_AFTER effects; behaviour mirrors `posix_spawn` with different pid sentinel (345).
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1`.
 * - Wrapper call with LATENCY rule for OP_POSIX_SPAWNP.
 * - Wrapper call with ERRNO rule (EAGAIN) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOMEM) and `g_fail_after_trigger = 1`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; pid == 345.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EAGAIN): returns EAGAIN; `errno` unchanged; real stub not called.
 * - FAIL_AFTER (ENOMEM): returns ENOMEM; real stub not called.
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
 * @brief Invariant: the `execve` wrapper applies guard bypass, latency, ERRNO (sets errno),
 *   FAIL_AFTER (sets errno), and real-function error passthrough.
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1`.
 * - Wrapper call with LATENCY rule for OP_EXECVE.
 * - Wrapper call with ERRNO rule (EACCES) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOENT) and `g_fail_after_trigger = 1`.
 * - Wrapper call with `g_real_execve_result = -1`, `g_real_execve_errno = E2BIG`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 0; real stub called.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 0.
 * - ERRNO (EACCES): returns -1; `errno == EACCES`; real stub not called.
 * - FAIL_AFTER (ENOENT): returns -1; `errno == ENOENT`; real stub not called.
 * - Real-function error (E2BIG): returns -1; `errno == E2BIG`.
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
 * @brief Invariant: the `execveat` wrapper (Linux-only) behaves identically to the `execve`
 *   wrapper with the addition of a dirfd and flags argument.
 *
 * Triggering conditions:
 * - Wrapper call with `g_chaos_process_tls_guard = 1`.
 * - Wrapper call with LATENCY rule for OP_EXECVEAT.
 * - Wrapper call with ERRNO rule (EACCES) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ENOENT) and `g_fail_after_trigger = 1`.
 * - Wrapper call with `g_real_execveat_result = -1`, `g_real_execveat_errno = E2BIG`.
 *
 * Expected observable behaviour: same as `test_execve_paths` with `execveat` call counts.
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
 * @brief Invariant: the `waitpid` wrapper applies guard bypass, latency, ERRNO, FAIL_AFTER,
 *   and real-function error passthrough; pid and options are forwarded correctly.
 *
 * Triggering conditions:
 * - Wrapper call `waitpid(456, NULL, WNOHANG)` with `g_chaos_process_tls_guard = 1`.
 * - Wrapper call with LATENCY rule for OP_WAITPID.
 * - Wrapper call with ERRNO rule (EINTR) and `g_errno_trigger = 1`.
 * - Wrapper call with FAIL_AFTER rule (ECHILD) and `g_fail_after_trigger = 1`.
 * - Wrapper call with `g_real_waitpid_result = -1`, `g_real_waitpid_errno = ECHILD`.
 *
 * Expected observable behaviour:
 * - Guard bypass: returns 321; `g_last_waitpid_pid == 456`; real stub called.
 * - LATENCY: `g_latency_calls == 1`; real stub called; returns 321.
 * - ERRNO (EINTR): returns -1; `errno == EINTR`; real stub not called.
 * - FAIL_AFTER (ECHILD): returns -1; `errno == ECHILD`; real stub not called.
 * - Real-function error (ECHILD): returns -1; `errno == ECHILD`.
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
    return 0;
}
