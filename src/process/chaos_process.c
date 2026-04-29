#include "chaos_process_config.h"
#include "chaos_process_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

chaos_process_pthread_create_fn g_chaos_process_real_pthread_create = NULL;
chaos_process_fork_fn g_chaos_process_real_fork = NULL;
chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn = NULL;
chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp = NULL;
chaos_process_execve_fn g_chaos_process_real_execve = NULL;
chaos_process_execveat_fn g_chaos_process_real_execveat = NULL;
chaos_process_waitpid_fn g_chaos_process_real_waitpid = NULL;
chaos_process_nanosleep_fn g_chaos_process_real_nanosleep = NULL;
chaos_process_usleep_fn g_chaos_process_real_usleep = NULL;

__thread int g_chaos_process_tls_guard = 0;
__thread uint64_t g_chaos_process_tls_prng_state = 0U;
uint64_t g_chaos_process_process_seed = UINT64_C(0x2545f4914f6cdd1d);
volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U};

#ifndef CHAOS_PROCESS_CONSTRUCTOR
#define CHAOS_PROCESS_CONSTRUCTOR __attribute__((constructor))
#endif

static void chaos_process_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
    {
        abort();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}

#ifdef __linux__
static void chaos_process_try_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL)
    {
        (void)dlerror();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}
#endif

static uint64_t chaos_process_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_process_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_process_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_process_leave_internal(previous);
    }
#endif

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

CHAOS_PROCESS_CONSTRUCTOR
static void chaos_process_init(void)
{
    chaos_process_resolve_symbol(&g_chaos_process_real_pthread_create, "pthread_create");
    chaos_process_resolve_symbol(&g_chaos_process_real_fork, "fork");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawn, "posix_spawn");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawnp, "posix_spawnp");
    chaos_process_resolve_symbol(&g_chaos_process_real_execve, "execve");
#ifdef __linux__
    /* musl does not consistently expose execveat as a public libc symbol. */
    chaos_process_try_resolve_symbol(&g_chaos_process_real_execveat, "execveat");
#endif
    chaos_process_resolve_symbol(&g_chaos_process_real_waitpid, "waitpid");
    chaos_process_resolve_symbol(&g_chaos_process_real_nanosleep, "nanosleep");
    chaos_process_resolve_symbol(&g_chaos_process_real_usleep, "usleep");

    g_chaos_process_process_seed = chaos_process_read_seed_material();
    chaos_process_prng_seed_thread(g_chaos_process_process_seed);
    chaos_process_config_init();
}
