#include "chaos_process_actions.h"
#include "chaos_process_config.h"
#include "chaos_process_internal.h"

static int chaos_process_call_real_pthread_create(
    pthread_t *thread,
    const pthread_attr_t *attributes,
    void *(*start_routine)(void *),
    void *argument
)
{
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_pthread_create(thread, attributes, start_routine, argument);
    chaos_process_leave_internal(previous);
    return rc;
}

static pid_t chaos_process_call_real_fork(void)
{
    int previous;
    pid_t rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_fork();
    chaos_process_leave_internal(previous);
    return rc;
}

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

static pid_t chaos_process_call_real_waitpid(pid_t pid, int *status, int options)
{
    int previous;
    pid_t rc;

    previous = chaos_process_enter_internal();
    rc = g_chaos_process_real_waitpid(pid, status, options);
    chaos_process_leave_internal(previous);
    return rc;
}

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

CHAOS_PROCESS_EXPORT pid_t fork(void)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

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

CHAOS_PROCESS_EXPORT int execve(const char *path, char *const argv[], char *const envp[])
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

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

#ifdef __linux__
CHAOS_PROCESS_EXPORT int
execveat(int directory_fd, const char *path, char *const argv[], char *const envp[], int flags)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

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

CHAOS_PROCESS_EXPORT pid_t waitpid(pid_t pid, int *status, int options)
{
    chaos_process_rule_t latency_rule;
    chaos_process_rule_t errno_rule;
    chaos_process_rule_t fail_after_rule;
    int error_code;

    if (chaos_process_in_internal())
    {
        return chaos_process_call_real_waitpid(pid, status, options);
    }

    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_WAITPID, &latency_rule
        ))
    {
        chaos_process_rule_apply_latency(&latency_rule);
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &errno_rule
        ) &&
        chaos_process_rule_error_number(&errno_rule, &error_code))
    {
        errno = error_code;
        return -1;
    }
    if (chaos_process_config_match(
            CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_WAITPID, &fail_after_rule
        ) &&
        chaos_process_rule_fail_after_error(
            &fail_after_rule, CHAOS_PROCESS_OP_WAITPID, &error_code
        ))
    {
        errno = error_code;
        return -1;
    }

    return chaos_process_call_real_waitpid(pid, status, options);
}
