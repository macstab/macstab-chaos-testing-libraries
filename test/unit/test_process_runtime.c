#include "../support/test_process_support.h"

#include "../../src/process/chaos_process_config.h"

#include <setjmp.h>
#include <stdarg.h>

static int g_config_init_calls = 0;
static int g_dlerror_calls = 0;
static const char *g_dlerror_text = NULL;
static jmp_buf g_abort_env;
static int g_expect_abort = 0;
#ifdef __linux__
static int g_syscall_open_calls = 0;
static int g_syscall_read_calls = 0;
static int g_syscall_close_calls = 0;
static int g_force_open_fail = 0;
static int g_force_short_read = 0;
#endif

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

static pid_t stub_fork(void)
{
    return 123;
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
    if (pid != NULL)
    {
        *pid = 234;
    }
    return 0;
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
    if (pid != NULL)
    {
        *pid = 345;
    }
    return 0;
}

static int stub_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)path;
    (void)argv;
    (void)envp;
    return 0;
}

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

static pid_t stub_waitpid(pid_t pid, int *status, int options)
{
    (void)status;
    (void)options;
    return pid;
}

static int stub_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)request;
    (void)remaining;
    return 0;
}

static int stub_usleep(useconds_t usec)
{
    (void)usec;
    return 0;
}

void chaos_process_config_init(void)
{
    ++g_config_init_calls;
}

static char *chaos_process_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

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

static void chaos_process_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

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
