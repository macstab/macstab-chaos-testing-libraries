/**
 * @file chaos_process_hooks.c
 * @brief The exported wrappers of libchaos-process: thread and process creation, exec,
 *        system()/popen() and the wait family.
 *
 * @details
 * ### Wrappers and the rules they follow
 *
 * | Wrapper(s)                                           | Rules (selector) | Fails as        |
 * |------------------------------------------------------|------------------|-----------------|
 * | pthread_create                                       | pthread_create   | returns errno   |
 * | fork                                                 | fork             | -1, errno       |
 * | posix_spawn                                          | posix_spawn      | returns errno   |
 * | posix_spawnp                                         | posix_spawnp     | returns errno   |
 * | system, popen                                        | posix_spawn      | -1/NULL, errno  |
 * | execve, execv, execvp, execvpe, execl, execlp, execle| execve           | -1, errno       |
 * | execveat; fexecve (Linux)                            | execveat         | -1, errno       |
 * | waitpid, wait, wait3, wait4, waitid                  | waitpid          | -1, errno       |
 *
 * glibc and musl implement the derived calls on internal symbols that never reach the
 * exported wrappers, so each derived call is wrapped itself and shares the rules and the
 * FAIL_AFTER counter of the call it is a form of. vfork is not wrapped.
 *
 * ### Order within a call
 *
 *  1. Guard set (library code is running): call the real function, inject nothing.
 *  2. LATENCY: sleep before the call if a LATENCY rule fires.
 *  3. ERRNO: fail without calling libc if an ERRNO rule fires.
 *  4. FAIL_AFTER: advance the counter, fail if past the threshold and the rule fires.
 *  5. Call the real function under the guard (chaos_process_call_real_*), so nothing
 *     it calls back into is faulted again.
 *
 * At most one of ERRNO and FAIL_AFTER fails a call; when ERRNO fires, the FAIL_AFTER
 * counter does not advance.
 *
 * ### Platform notes
 *
 * - **posix_spawn and fork rules:** glibc and musl both spawn through
 *   clone(CLONE_VM | CLONE_VFORK), not through the exported fork, so a `fork` rule
 *   never affects posix_spawn, system() or popen(). Name `posix_spawn` /
 *   `posix_spawnp` to fault spawning.
 * - **fork:** effects apply in the parent before the real fork. On success the child
 *   returns from the real fork with the guard restored to its pre-call value (0), and
 *   the atfork child handler resets its hit counts, `@first` claims and FAIL_AFTER
 *   counters (chaos_process_config.c), so a child does not inherit an exhausted
 *   FAIL_AFTER budget.
 * - **vfork:** not wrapped. A vfork child that calls execve passes through the execve
 *   wrapper while it still shares the parent's memory; LATENCY there suspends the
 *   parent as well, for the same time.
 * - **exec:** an injected failure leaves the process image and the library in place. A
 *   successful exec replaces the image without running destructors: library state,
 *   including hits not yet written to the hits file, is gone, and the library is
 *   present in the new image only if its LD_PRELOAD still names it. LATENCY before a
 *   successful exec shows as a slower start-up.
 * - **wait family:** LATENCY comes on top of however long the real call blocks; a
 *   WNOHANG poll still sleeps latency_ms first, which can exhaust a caller's deadline
 *   before the child state is checked.
 *
 * ### Unresolved real functions
 *
 * A pointer can be NULL while resolution runs on this thread or when libc lacks the
 * symbol. Helpers then issue the equivalent system call (execve, execveat, wait4 for
 * waitpid, wait4, waitid) or fail: fork with ENOSYS (a bare clone would skip libc's
 * atfork handlers and caches), pthread_create with EAGAIN, posix_spawn(p) with ENOSYS,
 * execvpe/fexecve/system/popen with ENOSYS.
 */

#include "chaos_process_actions.h"
#include "chaos_process_config.h"
#include "chaos_process_internal.h"

#include <stdarg.h>

/* -------------------------------------------------------------------------
 * Call-through wrappers (re-entrancy-guarded)
 * ---------------------------------------------------------------------- */

/**
 * @brief Calls the real `pthread_create` under the guard.
 *
 * While the pointer is NULL the lookup is retried here (libpthread may have been
 * dlopen()ed since); if it is still absent the call fails with EAGAIN.
 *
 * @return 0, or a positive error number (pthread_create does not set errno).
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
            /* A thread needs libc's own setup (TLS, stack, TID cache): there is
             * no system call to fall back to. EAGAIN, the error pthread_create()
             * documents for a thread it cannot create, is the one callers handle. */
            return EAGAIN;
        }
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_pthread_create(thread, attributes, start_routine, argument);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `fork` under the guard.
 *
 * The guard is held across the fork, including libc's atfork handlers, and restored in
 * parent and child alike, so the child's later calls are wrapped normally.
 *
 * @return As fork(); -1 with ENOSYS while the real fork is unresolved.
 */
static pid_t chaos_process_call_real_fork(void)
{
    int previous;
    pid_t rc;

    if (g_chaos_process_real_fork == NULL)
    {
        /* Not resolved yet (a call from inside the symbol lookup). A bare clone
         * would skip libc's atfork handlers and caches, so fail instead. */
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_fork();
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `posix_spawn` under the guard.
 *
 * @return 0, or a positive error number; ENOSYS while unresolved (no single system call
 *         can stand in).
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

    if (g_chaos_process_real_posix_spawn == NULL)
    {
        return ENOSYS; /* no single system call; reported as posix_spawn reports errors */
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_posix_spawn(pid, path, file_actions, attributes, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `posix_spawnp` under the guard.
 *
 * @return 0, or a positive error number; ENOSYS while unresolved.
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

    if (g_chaos_process_real_posix_spawnp == NULL)
    {
        return ENOSYS;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_posix_spawnp(pid, file, file_actions, attributes, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `execve` under the guard; SYS_execve while unresolved.
 *
 * Does not return on success. The guard is restored only on failure; after a
 * successful exec the TLS holding it no longer exists.
 *
 * @return -1 with errno set on failure.
 */
static int chaos_process_call_real_execve(const char *path, char *const argv[], char *const envp[])
{
    int previous;
    int rc;

    if (g_chaos_process_real_execve == NULL)
    {
        /* Not resolved yet: the system call does what libc would. */
        return (int)syscall(SYS_execve, path, argv, envp);
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_execve(path, argv, envp);
    chaos_process_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/**
 * @brief Calls the real `execveat` under the guard (Linux only).
 *
 * While the pointer is NULL (libc without execveat, or not resolved yet) it issues
 * SYS_execveat directly, or fails with ENOSYS where the headers lack that number. Does
 * not return on success.
 *
 * @return -1 with errno set on failure.
 */
static int chaos_process_call_real_execveat(
    int directory_fd, const char *path, char *const argv[], char *const envp[], int flags
)
{
    int previous;
    int rc;

    if (g_chaos_process_real_execveat == NULL)
    {
#ifdef SYS_execveat
        return (int)syscall(SYS_execveat, directory_fd, path, argv, envp, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
    }

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_execveat(directory_fd, path, argv, envp, flags);
    chaos_process_leave_internal(previous);
    return rc;
}
#endif

/**
 * @brief Calls the real `waitpid` under the guard; SYS_wait4 with a NULL rusage while
 *        unresolved (waitpid has no system call of its own on arm64).
 */
static pid_t chaos_process_call_real_waitpid(pid_t pid, int *status, int options)
{
    int previous;
    pid_t rc;

    if (g_chaos_process_real_waitpid == NULL)
    {
        return (pid_t)syscall(SYS_wait4, pid, status, options, NULL);
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_waitpid(pid, status, options);
    chaos_process_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `wait4` under the guard; SYS_wait4 while unresolved. */
static pid_t
chaos_process_call_real_wait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    int previous;
    pid_t rc;

    if (g_chaos_process_real_wait4 == NULL)
    {
        return (pid_t)syscall(SYS_wait4, pid, status, options, usage);
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_wait4(pid, status, options, usage);
    chaos_process_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `waitid` under the guard; SYS_waitid while unresolved. */
static int chaos_process_call_real_waitid(idtype_t type, id_t id, siginfo_t *info, int options)
{
    int previous;
    int rc;

    if (g_chaos_process_real_waitid == NULL)
    {
        /* The system call takes a fifth argument, the rusage, which libc passes as NULL. */
        return (int)syscall(SYS_waitid, type, id, info, options, NULL);
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_waitid(type, id, info, options);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Applies one operation's rules to a call: LATENCY, then ERRNO, then FAIL_AFTER.
 *
 * Used by the wrappers that follow another call's rules (wait family, exec family,
 * system(), popen()), so each sees the same faults and the same FAIL_AFTER counter as
 * the call it is a form of. The caller checks the guard first.
 *
 * @param operation   Operation whose rules apply.
 * @param error_code  Receives the error when the call must fail; errno is not set.
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
 * waitpid, wait, wait3, wait4 and waitid all reap or observe children; libc implements
 * them on internal symbols, so each has a wrapper, and all share these rules and one
 * FAIL_AFTER counter.
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
 * @brief Wrapper for `pthread_create(3)`: the `pthread_create` rules.
 *
 * An injected failure is returned as the error number, as pthread_create reports
 * errors; errno is untouched. Realistic values: EAGAIN (RLIMIT_NPROC or threads-max
 * reached), ENOMEM. Faults apply at the libc entry point; threads a runtime creates
 * with a raw clone() are not seen.
 *
 * @param thread        Receives the thread handle.
 * @param attributes    Thread attributes, or NULL.
 * @param start_routine Thread entry point.
 * @param argument      Argument for @p start_routine.
 * @return 0 on success; a positive error number (injected or real).
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
 * @brief Wrapper for `fork(2)`: the `fork` rules, applied in the parent before forking.
 *
 * An injected failure sets errno (EAGAIN or ENOMEM are what fork documents) and
 * returns -1; no child exists. After a real fork the atfork child handler gives the
 * child fresh hit counts, `@first` claims and FAIL_AFTER counters.
 *
 * @return Child pid in the parent, 0 in the child, -1 with errno set on failure.
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
 * @brief Wrapper for `posix_spawn(3)`: the `posix_spawn` rules.
 *
 * Sits at the posix_spawn entry point, whatever libc does underneath; a `fork` rule
 * never reaches it (see the file header). An injected failure is returned as the error
 * number and errno is untouched; no child is created and *@p pid is not written.
 *
 * @param pid          Receives the child pid on success.
 * @param path         Path of the executable.
 * @param file_actions File actions, or NULL.
 * @param attributes   Spawn attributes, or NULL.
 * @param argv         NULL-terminated argument vector.
 * @param envp         NULL-terminated environment.
 * @return 0 on success; a positive error number on failure.
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
 * @brief Wrapper for `posix_spawnp(3)`: the `posix_spawnp` rules (not those of
 *        `posix_spawn`); otherwise as posix_spawn(), with libc's PATH search.
 *
 * @param pid          Receives the child pid on success.
 * @param file         Executable name, searched in PATH by libc.
 * @param file_actions File actions, or NULL.
 * @param attributes   Spawn attributes, or NULL.
 * @param argv         NULL-terminated argument vector.
 * @param envp         NULL-terminated environment.
 * @return 0 on success; a positive error number on failure.
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
 * @brief Wrapper for `execve(2)`: the `execve` rules; also the target of execv, execl
 *        and execle.
 *
 * An injected failure sets errno and returns -1 with the image and the library intact.
 * A successful real exec does not return and runs no destructor, so hits not yet
 * written are lost.
 *
 * @param path  Path of the executable.
 * @param argv  NULL-terminated argument vector.
 * @param envp  NULL-terminated environment.
 * @return Only on failure: -1 with errno set.
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
 * internal posix_spawn, so none of them passes through the exported wrappers.
 * Each follows the rules of the call it is a form of: the exec family the execve
 * rules (fexecve the execveat rules), system() and popen() the posix_spawn rules.
 * execv, execvp and the execl forms forward to execve / execvpe exactly as libc
 * defines them, so they are faulted exactly once; execvpe, fexecve, system and popen
 * call their real functions under the guard, so PATH search and the shell invocation
 * stay libc's own and are not faulted a second time.
 * ------------------------------------------------------------------------- */

/** @brief Wrapper for `execv(3)`: `execve(path, argv, environ)`. */
CHAOS_PROCESS_EXPORT int execv(const char *path, char *const argv[])
{
    return execve(path, argv, environ);
}

/**
 * @brief Wrapper for `execvpe(3)`: the execve rules, then the real execvpe (libc's PATH
 *        search).
 *
 * @return Only on failure: -1 with errno set; ENOSYS when libc lacks execvpe.
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

/** @brief Wrapper for `execvp(3)`: `execvpe(file, argv, environ)`. */
CHAOS_PROCESS_EXPORT int execvp(const char *file, char *const argv[])
{
    return execvpe(file, argv, environ);
}

/**
 * @brief Wrapper for `execl(3)`: the arguments as an array, then execv().
 *
 * @details The array is a VLA on the stack sized from the argument count: no
 * allocation, so the call is safe in a child forked from a multithreaded parent.
 */
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

/** @brief Wrapper for `execlp(3)`: the arguments as an array (stack VLA), then execvp(). */
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
 * @brief Wrapper for `execle(3)`: the arguments as an array (stack VLA), then execve().
 *
 * @details The environment pointer follows the terminating NULL argument.
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
 * @brief Wrapper for `fexecve(3)`: the execveat rules (Linux only; elsewhere no rule
 *        applies), then the real fexecve.
 *
 * @return Only on failure: -1 with errno set; ENOSYS when libc lacks fexecve.
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
 * @brief Wrapper for `system(3)`: the posix_spawn rules, sharing posix_spawn's
 *        FAIL_AFTER counter.
 *
 * @details `system(NULL)` only asks whether a shell exists and is forwarded unfaulted.
 * An injected failure is reported as system() reports a failed spawn: -1 with errno.
 *
 * @return As system(); -1 with errno on failure (ENOSYS when unresolved).
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
    if (g_chaos_process_real_system == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_system(command);
    chaos_process_leave_internal(previous);
    return rc;
}

/**
 * @brief Wrapper for `popen(3)`: the posix_spawn rules, sharing posix_spawn's
 *        FAIL_AFTER counter.
 *
 * @return The stream, or NULL with errno set on failure (ENOSYS when unresolved).
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
    if (g_chaos_process_real_popen == NULL)
    {
        errno = ENOSYS;
        return NULL;
    }
    previous = chaos_process_enter_internal();
    stream = g_chaos_process_real_popen(command, mode);
    chaos_process_leave_internal(previous);
    return stream;
}

#ifdef __linux__
/**
 * @brief Wrapper for `execveat(2)` (Linux only): the `execveat` rules.
 *
 * Same semantics as execve(). With no real execveat in libc the helper issues
 * SYS_execveat directly, so the rules still apply.
 *
 * @param directory_fd Directory a relative @p path is resolved against, or AT_FDCWD.
 * @param path         Path of the executable.
 * @param argv         NULL-terminated argument vector.
 * @param envp         NULL-terminated environment.
 * @param flags        AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW.
 * @return Only on failure: -1 with errno set.
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
 * @brief Wrapper for `waitpid(2)`: the `waitpid` rules; also the target of wait().
 *
 * Useful errors: EINTR (a signal interrupted the wait; tests retry loops) and ECHILD
 * (no such child). An injected failure reaps nothing, so the child stays a zombie until
 * a later wait succeeds. LATENCY adds latency_ms to however long the real call blocks,
 * WNOHANG included.
 *
 * @param pid     Child to wait for; -1 for any child.
 * @param status  Receives the child status; may be NULL.
 * @param options WNOHANG, WUNTRACED, ...
 * @return Child pid; 0 under WNOHANG with no state change; -1 with errno set.
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
 * @brief Wrapper for `wait(2)`: `waitpid(-1, status, 0)`, so the `waitpid` rules.
 */
CHAOS_PROCESS_EXPORT pid_t wait(int *status)
{
    return waitpid(-1, status, 0);
}

/**
 * @brief Wrapper for `wait4(2)`: the `waitpid` rules.
 *
 * @details Calls the real wait4 rather than waitpid, so @p usage is still filled.
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
 * @brief Wrapper for `wait3(2)`: `wait4(-1, status, options, usage)`.
 */
CHAOS_PROCESS_EXPORT pid_t wait3(int *status, int options, struct rusage *usage)
{
    return wait4(-1, status, options, usage);
}

/**
 * @brief Wrapper for `waitid(2)`: the `waitpid` rules.
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
