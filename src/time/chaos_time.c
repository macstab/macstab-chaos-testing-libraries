#include "chaos_time_config.h"
#include "chaos_time_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;
chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;
chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;

__thread int g_chaos_time_tls_guard = 0;
__thread uint64_t g_chaos_time_tls_prng_state = 0U;
uint64_t g_chaos_time_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_TIME_CONSTRUCTOR
#define CHAOS_TIME_CONSTRUCTOR __attribute__((constructor))
#endif

static void chaos_time_resolve_symbol(void *target, const char *symbol)
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

static uint64_t chaos_time_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_time_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_time_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_time_leave_internal(previous);
    }
#endif

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

CHAOS_TIME_CONSTRUCTOR
static void chaos_time_init(void)
{
    chaos_time_resolve_symbol(&g_chaos_time_real_clock_gettime, "clock_gettime");
    chaos_time_resolve_symbol(&g_chaos_time_real_nanosleep, "nanosleep");
    chaos_time_resolve_symbol(&g_chaos_time_real_usleep, "usleep");

    g_chaos_time_process_seed = chaos_time_read_seed_material();
    chaos_time_prng_seed_thread(g_chaos_time_process_seed);
    chaos_time_config_init();
}
