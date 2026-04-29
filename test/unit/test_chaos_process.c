#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

static chaos_process_rule_t g_stub_rules[3][CHAOS_PROCESS_OP_COUNT];
static int g_stub_match[3][CHAOS_PROCESS_OP_COUNT];
static int g_latency_calls = 0;
static int g_errno_trigger = 0;
static int g_fail_after_trigger = 0;
static int g_real_pthread_create_calls = 0;
static int g_real_fork_calls = 0;
static int g_real_posix_spawn_calls = 0;
static int g_real_posix_spawnp_calls = 0;
static int g_real_execve_calls = 0;
static int g_real_execveat_calls = 0;
static int g_real_waitpid_calls = 0;
static int g_real_pthread_create_result = 0;
static pid_t g_real_fork_result = 123;
static int g_real_posix_spawn_result = 0;
static int g_real_posix_spawnp_result = 0;
static int g_real_execve_result = 0;
static int g_real_execveat_result = 0;
static pid_t g_real_waitpid_result = 321;
static int g_real_execve_errno = 0;
static int g_real_execveat_errno = 0;
static int g_real_waitpid_errno = 0;
static pid_t g_last_waitpid_pid = 0;
static int g_last_waitpid_options = 0;

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

void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

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

static void *stub_start_routine(void *argument)
{
    return argument;
}

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

static pid_t stub_fork(void)
{
    ++g_real_fork_calls;
    return g_real_fork_result;
}

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
#endif

    assert(chaos_process_call_real_waitpid(777, NULL, WNOHANG) == 321);
    assert(g_real_waitpid_calls == 1);
    assert(g_last_waitpid_pid == 777);
    assert(g_last_waitpid_options == WNOHANG);
}

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
