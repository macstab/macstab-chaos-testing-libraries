/**
 * @file chaos_process_hooks.c
 * @brief LD_PRELOAD interposition hooks for all process-lifecycle syscall
 *        wrappers in the libchaos-process fault-injection subsystem.
 *
 * @details
 * This file contains the exported symbols that shadow the real libc
 * implementations via `CHAOS_PROCESS_EXPORT` (`__attribute__((visibility("default")))`).
 * When the library is loaded via `LD_PRELOAD`, the dynamic linker resolves
 * these names ahead of the real libc definitions, routing every call from
 * the target application through the chaos wrappers defined here.
 *
 * ## Interposed symbols
 *
 *   - `pthread_create(3)`
 *   - `fork(2)`
 *   - `posix_spawn(3)` / `posix_spawnp(3)`
 *   - `execve(2)` / `execveat(2)` (Linux only)
 *   - `waitpid(2)`, and `wait(2)`, `wait3(2)`, `wait4(2)`, `waitid(2)` under its rules
 *
 * ## Hook structure
 *
 * Every public hook follows the same pattern:
 *  1. Check the re-entrancy guard (`chaos_process_in_internal()`); if set,
 *     call straight through to the real function and return.
 *  2. Optionally apply LATENCY (delay before the real call).
 *  3. Optionally apply ERRNO (return an injected error without calling real).
 *  4. Optionally apply FAIL_AFTER (return an injected error after N calls).
 *  5. Fall through to the real function.
 *
 * The three chaos effects are independent; at most one of ERRNO and
 * FAIL_AFTER will fire per call (the first one that matches wins and returns
 * immediately).  LATENCY is always applied before the error checks.
 *
 * ## Call-through wrappers
 *
 * Each real function is invoked through a `static` helper
 * (`chaos_process_call_real_*`) that brackets the call with
 * `chaos_process_enter_internal()` / `chaos_process_leave_internal()`.
 * This prevents any libc code invoked by the real implementation from
 * recursing back into the chaos layer.
 *
 * ## posix_spawn / posix_spawnp — glibc/musl cascade gap
 *
 * @note This is the most operationally significant platform divergence in
 *       the entire subsystem.  Read carefully before writing test assertions.
 *
 * **glibc**: `posix_spawn()` and `posix_spawnp()` are implemented via the
 * internal function `__spawnix()`, which calls
 * `clone(CLONE_VFORK|CLONE_VM, ...)` directly.  It does NOT call the libc
 * `fork()` symbol.  Consequently, a rule targeting `fork` (e.g.
 * `fork:ERRNO:EAGAIN`) does NOT affect `posix_spawn` calls on glibc.  Our
 * `posix_spawn` and `posix_spawnp` wrappers here intercept at the
 * `posix_spawn`/`posix_spawnp` ABI boundary, so they fire regardless.
 *
 * **musl**: `posix_spawn()` calls `fork()` then `exec()`.  Because `fork`
 * is also interposed by this library, a `fork:ERRNO:EAGAIN` rule WOULD
 * intercept the internal fork call that musl makes.  However, our
 * `posix_spawn` wrapper fires first (at the outer ABI boundary), so the
 * behaviour is consistent: our direct `posix_spawn` rule fires before musl
 * reaches the (also interposed) `fork`.
 *
 * **Implication**: write rules against `posix_spawn` / `posix_spawnp`
 * explicitly rather than relying on `fork` rules to cover spawn paths.
 *
 * ## fork — parent and child paths
 *
 * The `fork` wrapper applies chaos effects (LATENCY, ERRNO, FAIL_AFTER) in
 * the **parent** before calling the real `fork()`.  After `fork()` returns:
 *
 *   - In the **parent**: `fork()` returns the child PID.  The chaos logic
 *     has already executed.
 *   - In the **child**: the real `fork()` returns 0.  The child inherits the
 *     parent's entire address space (copy-on-write), including all library
 *     state.  The TLS re-entrancy guard in the child starts at whatever value
 *     the parent had at the point of fork (normally 0 since the guard is
 *     restored before `chaos_process_call_real_fork()` returns).  The child
 *     does NOT re-enter the wrapper for the `fork()` call; it simply receives
 *     0 as the return value of the real `fork()`.
 *
 *   FAIL_AFTER counter inheritance: the `g_chaos_process_fail_after_counters`
 *   array is in the data segment and is copied into the child via COW.  The
 *   child starts with the same counter values the parent had at fork time.
 *   There is no post-fork reset in the child.  If the parent had exhausted
 *   the FAIL_AFTER grace window before forking, the child's first call to
 *   the affected operation will also fail immediately.
 *
 * ## vfork — async-signal-safe constraint
 *
 * vfork is not currently interposed by this library.  If it were, any
 * LATENCY injection in the vfork path would be unsafe: the child shares the
 * parent's address space and stack between `vfork()` return and the child's
 * call to `exec`/`_exit`.  In this window only async-signal-safe functions
 * are permitted; `usleep` and `nanosleep` are NOT async-signal-safe and must
 * not be called.  Any future vfork wrapper must either skip LATENCY injection
 * entirely or apply it in the parent before calling the real `vfork()`.
 *
 * ## execve / execveat — process image replacement
 *
 * If the injected ERRNO or FAIL_AFTER effect fires, the real `execve`/
 * `execveat` is never called and the process image is not replaced.  The
 * process continues with this library still loaded.
 *
 * If no fault is injected (or LATENCY fires but not an error), the real
 * `execve`/`execveat` is called.  On success, the kernel replaces the entire
 * process image:
 *   - All library state (config, counters, function pointers, TLS) is
 *     destroyed.
 *   - The library is NOT present in the new process image unless the new
 *     process also has LD_PRELOAD set.
 *   - No cleanup or `__attribute__((destructor))` runs; exec success is
 *     instantaneous from the library's perspective.
 *
 * The LATENCY effect, when applied before a successful `execve`, produces a
 * real and observable delay in the process startup as seen by the parent or
 * by wall-clock measurement.  This is valid and occasionally useful for
 * testing timeout logic.  However, library state is not rolled back after
 * the sleep; exec success destroys it.
 *
 * ## waitpid — LATENCY before blocking
 *
 * LATENCY is applied before calling the real `waitpid`.  Because `waitpid`
 * may itself block for an arbitrarily long time (waiting for a child to
 * exit), the total delay observed by the caller is `latency_ms` PLUS
 * however long `waitpid` blocks.  This can confuse caller-side timeout logic
 * that sets `WNOHANG` or uses a separate timer, because the timeout may
 * expire during the artificial delay, before `waitpid` has had a chance to
 * observe the child state.
 *
 * ## Stability
 * Private implementation — not part of the public API.
 */

#include "chaos_process_actions.h"
#include "chaos_process_config.h"
#include "chaos_process_internal.h"

#include <stdarg.h>

/* -------------------------------------------------------------------------
 * Call-through wrappers (re-entrancy-guarded)
 * ---------------------------------------------------------------------- */

/**
 * @brief Calls the real `pthread_create` under the re-entrancy guard.
 *
 * Setting the guard prevents any `pthread_create` call that libc makes
 * internally during thread creation from recursing back into our wrapper.
 * Note that NPTL's `pthread_create` internally uses `clone(2)` directly;
 * the guard is belt-and-suspenders for other libc implementations.
 */
static int chaos_process_call_real_pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attributes,
    void *(*start_routine)(void *),
    void *argument
)
{
    int previous;
    int rc;

    if (g_chaos_process_real_pthread_create == NULL)
    {
        chaos_process_resolve_pthread_create();
        if (g_chaos_process_real_pthread_create == NULL)
        {
            return EAGAIN;
        }
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_pthread_create(thread, attributes, start_routine, argument);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `fork` under the re-entrancy guard.
 *
 * The guard is active from the call to `chaos_process_enter_internal()`
 * through the real `fork()` and is restored by `chaos_process_leave_internal()`
 * in both parent and child.  In the child the guard is restored to `previous`
 * (0 in normal operation), which is correct: the child's wrapper exits
 * cleanly and the child can subsequently call all interposed functions.
 */
static pid_t chaos_process_call_real_fork(void)
{
    int previous;
    pid_t rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_fork();
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `posix_spawn` under the re-entrancy guard.
 *
 * @note See the file-level note on the glibc/musl posix_spawn cascade gap.
 *       On glibc, the real `posix_spawn` internally uses `clone` directly
 *       and does not call our interposed `fork`, so the guard is sufficient
 *       to prevent any unexpected recursion.
 */
static int chaos_process_call_real_posix_spawn(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_posix_spawn(pid, path, file_actions, attributes, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `posix_spawnp` under the re-entrancy guard.
 *
 * @note Same glibc/musl cascade considerations as `posix_spawn` apply here.
 */
static int chaos_process_call_real_posix_spawnp(
    pid_t *pid,
    const char *file,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_posix_spawnp(pid, file, file_actions, attributes, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `execve` under the re-entrancy guard.
 *
 * On success this function does not return: the kernel has replaced the
 * process image and the library no longer exists in the new address space.
 * `chaos_process_leave_internal` is called before `execve` returns in the
 * error case (exec failed); on the success path it is dead code.
 */
static int chaos_process_call_real_execve(const char *path, char *const argv[], char *const envp[])
{
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_execve(path, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/**
 * @brief Calls the real `execveat` under the re-entrancy guard (Linux only).
 *
 * Returns -1 with `errno = ENOSYS` immediately if
 * `g_chaos_process_real_execveat` is NULL (musl without a public
 * `execveat` export).  On success this function does not return; see the
 * `execve` call-through wrapper for the exec-success/failure explanation.
 */
static int chaos_process_call_real_execveat(
    int directory_fd, const char *path, char *const argv[], char *const envp[], int flags
)
{
    int previous;
    int rc;

    if (g_chaos_process_real_execveat == NULL)
    {
        errno = ENOSYS;
        return -1;
    }

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_execveat(directory_fd, path, argv, envp, flags);
    chaos_process_leave_internal(previous);
    return rc;
}
#endif

/**
 * @brief Calls the real `waitpid` under the re-entrancy guard.
 *
 * The guard prevents `waitpid`'s internal libc machinery from inadvertently
 * triggering another chaos wrapper during the wait.
 */
static pid_t chaos_process_call_real_waitpid(pid_t pid, int *status, int options)
{
    int previous;
    pid_t rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_waitpid(pid, status, options);
    chaos_process_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `wait4` under the re-entrancy guard. */
static pid_t
chaos_process_call_real_wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    int previous;
    pid_t rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_wait4(pid, status, options, usage);
    chaos_process_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `waitid` under the re-entrancy guard. */
static int chaos_process_call_real_waitid(idtype_t type, id_t id, siginfo_t *info, int options)
{
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_waitid(type, id, info, options);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Applies one operation's rules to a call: LATENCY, then ERRNO, then FAIL_AFTER.
 *
 * Shared by every wrapper that follows the rules of another call -- the wait
 * family (waitpid rules), the exec family (execve or execveat rules), system()
 * and popen() (posix_spawn rules) -- so each sees exactly the same faults and the
 * same FAIL_AFTER counter as the call it is a form of.
 *
 * @param operation   Operation whose rules apply.
 * @param error_code  Receives the error to report when the call must fail.
 * @return Non-zero when the call must fail.
 */
static int chaos_process_operation_fault(chaos_process_operation_t operation, int *error_code)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;

    if (chaos_process_config_match(CHAOS_PROCESS_EFFECT_LATENCY, operation, &latency_rule))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    return (chaos_process_config_match(CHAOS_PROCESS_EFFECT_ERRNO, operation, &errno_rule) &&
            chaos_process_rule_error_number(&errno_rule, error_code)) ||
           (chaos_process_config_match(
                CHAOS_PROCESS_EFFECT_FAIL_AFTER, operation, &fail_after_rule
            ) &&
            chaos_process_rule_fail_after_error(&fail_after_rule, operation, error_code));
}

/**
 * @brief Applies the `waitpid` rules to one call of any wait function.
 *
 * waitpid, wait, wait3, wait4 and waitid all reap or observe children; glibc and
 * musl implement each with its own system call, so each has a wrapper, and all of
 * them share these rules (and one FAIL_AFTER counter).
 *
 * @return Non-zero when the call must fail; errno is then set.
 */
static int chaos_process_wait_fault(void)
{
    int error_code;

    if (chaos_process_operation_fault(CHAOS_PROCESS_OP_WAITPID, &error_code))
    {
        errno = error_code;
        return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Public interposition hooks
 * ---------------------------------------------------------------------- */

/**
 * @brief Interposition hook for `pthread_create(3)`.
 *
 * Applies chaos effects before creating the thread.  Returns the error
 * number directly (NOT -1 + errno) on injected failure, matching the POSIX
 * specification for `pthread_create`.  The real `pthread_create` also
 * returns the error number directly.
 *
 * Relevant errno values for injection:
 *   - EAGAIN: thread limit exceeded (`RLIMIT_NPROC` or
 *     `/proc/sys/kernel/threads-max` saturated).
 *   - ENOMEM: stack or TLS allocation failure.
 *
 * NPTL implementation note: on Linux the real `pthread_create` routes
 * through `__pthread_create_2_1` which internally calls
 * `clone(CLONE_THREAD|CLONE_VM|CLONE_SIGHAND|...)`.  Our interception is at
 * the libc ABI level, not at the clone(2) syscall level.
 *
 * @param thread        Output: the new thread handle.
 * @param attributes    Thread attributes, or NULL for defaults.
 * @param start_routine Thread entry point.
 * @param argument      Argument passed to `start_routine`.
 * @return 0 on success; a positive errno value on failure (injected or real).
 */
CHAOS_PROCESS_EXPORT int pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attributes,
    void *(*start_routine)(void *),
    void *argument
)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_pthread_create(thread, attributes, start_routine, argument);
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_PTHREAD_CREATE, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_PTHREAD_CREATE, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        return error_code;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_PTHREAD_CREATE, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(
            &fail_after_rule, CHAOS_PROCESS_OP_PTHREAD_CREATE, &error_code
        ))
    {
        return error_code;
    }

    return chaos_process_call_real_pthread_create(thread, attributes, start_routine, argument);
}

/**
 * @brief Interposition hook for `fork(2)`.
 *
 * All chaos effects are applied in the **parent** before the real `fork()`
 * call.  The child never executes chaos logic for this particular fork call.
 *
 * On injected failure: sets `errno` and returns -1 (standard `fork` error
 * convention, unlike `pthread_create` which returns the error number directly).
 *
 * On successful fork:
 *   - The parent receives the child PID.
 *   - The child receives 0 from the real `fork()`.
 *   - The child inherits all library state at the moment of fork, including
 *     FAIL_AFTER counter values.  There is no post-fork counter reset.
 *
 * @param[out] (implicit) Sets errno on failure.
 * @return Child PID in the parent; 0 in the child; -1 on error with errno set.
 */
CHAOS_PROCESS_EXPORT pid_t fork(void)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_fork();
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_FORK, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        errno = error_code;
        return -1;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_FORK, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(&fail_after_rule, CHAOS_PROCESS_OP_FORK, &error_code))
    {
        errno = error_code;
        return -1;
    }

    return chaos_process_call_real_fork();
}

/**
 * @brief Interposition hook for `posix_spawn(3)`.
 *
 * Direct interposition at the `posix_spawn` ABI boundary.  Fires regardless
 * of the underlying implementation (glibc `__spawnix` via `clone`, or musl
 * `fork` + `exec`).
 *
 * @warning glibc/musl cascade gap: a `fork:ERRNO` rule does NOT affect
 *          `posix_spawn` on glibc because glibc's internal spawn path
 *          bypasses the libc `fork` symbol.  Always write rules against
 *          `posix_spawn` directly.  See the file-level documentation for
 *          the full analysis.
 *
 * On injected failure: returns the error number directly (matches the
 * `posix_spawn` specification; does not set errno).
 *
 * @param pid          Output: child PID on success.
 * @param path         Absolute path to the executable.
 * @param file_actions File descriptor action list, or NULL.
 * @param attributes   Spawn attributes, or NULL.
 * @param argv         Argument vector (NULL-terminated).
 * @param envp         Environment vector (NULL-terminated).
 * @return 0 on success; a positive errno value on failure.
 */
CHAOS_PROCESS_EXPORT int posix_spawn(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_posix_spawn(pid, path, file_actions, attributes, argv, envp);
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_POSIX_SPAWN, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_POSIX_SPAWN, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        return error_code;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_POSIX_SPAWN, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(
            &fail_after_rule, CHAOS_PROCESS_OP_POSIX_SPAWN, &error_code
        ))
    {
        return error_code;
    }

    return chaos_process_call_real_posix_spawn(pid, path, file_actions, attributes, argv, envp);
}

/**
 * @brief Interposition hook for `posix_spawnp(3)`.
 *
 * Identical structure to the `posix_spawn` hook.  Resolves the executable
 * via PATH search rather than an absolute path.
 *
 * @warning Same glibc/musl cascade gap applies; see the `posix_spawn` hook
 *          documentation and the file-level analysis.
 *
 * @param pid          Output: child PID on success.
 * @param file         Filename (resolved via PATH) of the executable.
 * @param file_actions File descriptor action list, or NULL.
 * @param attributes   Spawn attributes, or NULL.
 * @param argv         Argument vector (NULL-terminated).
 * @param envp         Environment vector (NULL-terminated).
 * @return 0 on success; a positive errno value on failure.
 */
CHAOS_PROCESS_EXPORT int posix_spawnp(
    pid_t *pid,
    const char *file,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[]
)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_posix_spawnp(
            pid, file, file_actions, attributes, argv, envp
        );
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_POSIX_SPAWNP, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_POSIX_SPAWNP, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        return error_code;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_POSIX_SPAWNP, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(
            &fail_after_rule, CHAOS_PROCESS_OP_POSIX_SPAWNP, &error_code
        ))
    {
        return error_code;
    }

    return chaos_process_call_real_posix_spawnp(pid, file, file_actions, attributes, argv, envp);
}

/**
 * @brief Interposition hook for `execve(2)`.
 *
 * On injected failure: sets `errno` and returns -1.  The process image is
 * unchanged and the library remains loaded.
 *
 * On passthrough (no fault injected): calls the real `execve`.  If the real
 * `execve` succeeds, the kernel replaces the process image and this function
 * does not return.  All library state (config, counters, function pointers,
 * TLS variables) is destroyed.  No destructor or cleanup runs.
 *
 * LATENCY before a successful exec is observable as a real wall-clock delay
 * in the process startup, visible to the parent via timestamps.  This is
 * valid usage.
 *
 * @param path  Absolute path to the executable.
 * @param argv  Argument vector (NULL-terminated).
 * @param envp  Environment vector (NULL-terminated).
 * @return Does not return on success.  Returns -1 on failure with errno set.
 */
CHAOS_PROCESS_EXPORT int execve(const char *path, char *const argv[], char *const envp[])
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_execve(path, argv, envp);
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_EXECVE, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_EXECVE, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        errno = error_code;
        return -1;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_EXECVE, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(&fail_after_rule, CHAOS_PROCESS_OP_EXECVE, &error_code))
    {
        errno = error_code;
        return -1;
    }

    return chaos_process_call_real_execve(path, argv, envp);
}

/* -------------------------------------------------------------------------
 * The exec family, system() and popen()
 *
 * glibc and musl implement execv, execvp, execvpe, execl, execle, execlp and
 * fexecve on their internal execve/execveat, and system() and popen() on their
 * internal posix_spawn, so none of them passes through the exported symbols.
 * Each follows the rules of the call it is a form of: the exec family the execve
 * rules (fexecve the execveat rules), system() and popen() the posix_spawn rules.
 * execv, execvp and the execl forms forward to execve and execvpe exactly as libc
 * defines them; execvpe, fexecve, system and popen call their real functions, so
 * PATH search and the shell invocation stay libc's own.
 * ------------------------------------------------------------------------- */

/** @brief Interposition hook for `execv(3)`: `execve(path, argv, environ)`. */
CHAOS_PROCESS_EXPORT int execv(const char *path, char *const argv[])
{
    return execve(path, argv, environ);
}

/**
 * @brief Interposition hook for `execvpe(3)`: the execve rules, then the real execvpe.
 *
 * @return -1 with errno set on failure (no return on success).
 */
CHAOS_PROCESS_EXPORT int execvpe(const char *file, char *const argv[], char *const envp[])
{
    int error_code;
    int previous;
    int rc;

    chaos_process_ensure_symbols();
    if (!chaos_process_in_internal() &&
        chaos_process_operation_fault(CHAOS_PROCESS_OP_EXECVE, &error_code))
    {
        errno = error_code;
        return -1;
    }
    if (g_chaos_process_real_execvpe == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_execvpe(file, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/** @brief Interposition hook for `execvp(3)`: `execvpe(file, argv, environ)`. */
CHAOS_PROCESS_EXPORT int execvp(const char *file, char *const argv[])
{
    return execvpe(file, argv, environ);
}

/** @brief Interposition hook for `execl(3)`: the arguments as an array, then execv(). */
CHAOS_PROCESS_EXPORT int execl(const char *path, const char *arg, ...)
{
    va_list args;
    size_t count = 1U;
    size_t index;

    va_start(args, arg);
    while (va_arg(args, const char *) != NULL)
    {
        ++count;
    }
    va_end(args);
    {
        char *argv[count + 1U];

        argv[0] = (char *)arg;
        va_start(args, arg);
        for (index = 1U; index <= count; ++index)
        {
            argv[index] = va_arg(args, char *);
        }
        va_end(args);
        return execv(path, argv);
    }
}

/** @brief Interposition hook for `execlp(3)`: the arguments as an array, then execvp(). */
CHAOS_PROCESS_EXPORT int execlp(const char *file, const char *arg, ...)
{
    va_list args;
    size_t count = 1U;
    size_t index;

    va_start(args, arg);
    while (va_arg(args, const char *) != NULL)
    {
        ++count;
    }
    va_end(args);
    {
        char *argv[count + 1U];

        argv[0] = (char *)arg;
        va_start(args, arg);
        for (index = 1U; index <= count; ++index)
        {
            argv[index] = va_arg(args, char *);
        }
        va_end(args);
        return execvp(file, argv);
    }
}

/**
 * @brief Interposition hook for `execle(3)`: the arguments as an array, then execve().
 *
 * @details The environment follows the terminating NULL argument.
 */
CHAOS_PROCESS_EXPORT int execle(const char *path, const char *arg, ...)
{
    va_list args;
    size_t count = 1U;
    size_t index;

    va_start(args, arg);
    while (va_arg(args, const char *) != NULL)
    {
        ++count;
    }
    va_end(args);
    {
        char *argv[count + 1U];
        char *const *envp;

        argv[0] = (char *)arg;
        va_start(args, arg);
        for (index = 1U; index <= count; ++index)
        {
            argv[index] = va_arg(args, char *);
        }
        envp = va_arg(args, char *const *);
        va_end(args);
        return execve(path, argv, envp);
    }
}

/**
 * @brief Interposition hook for `fexecve(3)`: the execveat rules, then the real fexecve.
 *
 * @return -1 with errno set on failure (no return on success).
 */
CHAOS_PROCESS_EXPORT int fexecve(int fd, char *const argv[], char *const envp[])
{
    int error_code;
    int previous;
    int rc;

    chaos_process_ensure_symbols();
#ifdef __linux__
    if (!chaos_process_in_internal() &&
        chaos_process_operation_fault(CHAOS_PROCESS_OP_EXECVEAT, &error_code))
    {
        errno = error_code;
        return -1;
    }
#else
    (void)error_code;
#endif
    if (g_chaos_process_real_fexecve == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_fexecve(fd, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Interposition hook for `system(3)`: the posix_spawn rules.
 *
 * @details `system(NULL)` only asks whether a shell exists and is forwarded. An
 * injected failure is reported as system() reports a failed spawn: -1 with errno.
 */
CHAOS_PROCESS_EXPORT int system(const char *command)
{
    uintptr_t command_bits = (uintptr_t)(const void *)command;
    int error_code;
    int previous;
    int rc;

    chaos_process_ensure_symbols();
    if (!chaos_process_in_internal() && command_bits != 0U &&
        chaos_process_operation_fault(CHAOS_PROCESS_OP_POSIX_SPAWN, &error_code))
    {
        errno = error_code;
        return -1;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_system(command);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Interposition hook for `popen(3)`: the posix_spawn rules.
 *
 * @return The stream, or NULL with errno set on failure.
 */
CHAOS_PROCESS_EXPORT FILE *popen(const char *command, const char *mode)
{
    int error_code;
    int previous;
    FILE *stream;

    chaos_process_ensure_symbols();
    if (!chaos_process_in_internal() &&
        chaos_process_operation_fault(CHAOS_PROCESS_OP_POSIX_SPAWN, &error_code))
    {
        errno = error_code;
        return NULL;
    }
    previous = chaos_process_enter_internal();
    stream = g_chaos_process_real_popen(command, mode);
    chaos_process_leave_internal(previous);
    return stream;
}

#ifdef __linux__
/**
 * @brief Interposition hook for `execveat(2)` (Linux only).
 *
 * Same process-image-replacement semantics as `execve`.  If the real
 * `execveat` symbol was not available at library load time (musl without a
 * public export), the call-through wrapper returns -1/ENOSYS immediately.
 *
 * On injected failure: sets `errno` and returns -1.
 * On passthrough with exec success: does not return; library state is gone.
 *
 * @param directory_fd Base directory fd for relative path resolution, or
 *                     AT_FDCWD for current-directory-relative paths.
 * @param path         Path to the executable, relative to `directory_fd`.
 * @param argv         Argument vector (NULL-terminated).
 * @param envp         Environment vector (NULL-terminated).
 * @param flags        Flags (AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW).
 * @return Does not return on success.  Returns -1 on failure with errno set.
 */
CHAOS_PROCESS_EXPORT int
execveat(int directory_fd, const char *path, char *const argv[], char *const envp[], int flags)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_execveat(directory_fd, path, argv, envp, flags);
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_EXECVEAT, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_EXECVEAT, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        errno = error_code;
        return -1;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_EXECVEAT, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(
            &fail_after_rule, CHAOS_PROCESS_OP_EXECVEAT, &error_code
        ))
    {
        errno = error_code;
        return -1;
    }

    return chaos_process_call_real_execveat(directory_fd, path, argv, envp, flags);
}
#endif

/**
 * @brief Interposition hook for `waitpid(2)`.
 *
 * Useful injected errno values:
 *   - EINTR:  simulates a signal interrupting waitpid (SA_RESTART test).
 *   - ECHILD: simulates "no such child" (tests orphan-detection paths).
 *
 * LATENCY is applied before the real `waitpid` call.  Because `waitpid` may
 * itself block for an extended period (waiting for the child to change state),
 * the total delay seen by the caller is:
 *
 *   `observed_delay` >= `latency_ms` + `waitpid_block_time`
 *
 * This can confuse caller-side timeout logic.  In particular, callers that
 * set `WNOHANG` to implement a poll-with-timeout may expire their deadline
 * during the artificial pre-call delay, before the real `waitpid` has had
 * a chance to check for an already-exited child.
 *
 * On injected failure: sets `errno` and returns -1.
 *
 * @param pid     Child PID to wait for, or -1 for any child.
 * @param status  Output: child exit status.
 * @param options Flags (WNOHANG, WUNTRACED, etc.).
 * @return Child PID on success; 0 if WNOHANG and child not yet changed; -1
 *         on error with errno set.
 */
CHAOS_PROCESS_EXPORT pid_t waitpid(pid_t pid, int *status, int options)
{
    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_waitpid(pid, status, options);
    }
    if (chaos_process_wait_fault())
    {
        return -1;
    }
    return chaos_process_call_real_waitpid(pid, status, options);
}

/**
 * @brief Interposition hook for `wait(2)`: `waitpid(-1, status, 0)`, the `waitpid` rules.
 */
CHAOS_PROCESS_EXPORT pid_t wait(int *status)
{
    return waitpid(-1, status, 0);
}

/**
 * @brief Interposition hook for `wait4(2)`: the `waitpid` rules.
 *
 * @details The real wait4 runs so that @p usage is still filled.
 */
CHAOS_PROCESS_EXPORT pid_t wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_wait4(pid, status, options, usage);
    }
    if (chaos_process_wait_fault())
    {
        return -1;
    }
    return chaos_process_call_real_wait4(pid, status, options, usage);
}

/**
 * @brief Interposition hook for `wait3(2)`: `wait4(-1, status, options, usage)`.
 */
CHAOS_PROCESS_EXPORT pid_t wait3(int *status, int options, struct rusage *usage)
{
    return wait4(-1, status, options, usage);
}

/**
 * @brief Interposition hook for `waitid(2)`: the `waitpid` rules.
 *
 * @return 0 on success; -1 with errno set on failure.
 */
CHAOS_PROCESS_EXPORT int waitid(idtype_t type, id_t id, siginfo_t *info, int options)
{
    chaos_process_ensure_symbols();

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_waitid(type, id, info, options);
    }
    if (chaos_process_wait_fault())
    {
        return -1;
    }
    return chaos_process_call_real_waitid(type, id, info, options);
}
