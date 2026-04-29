#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

chaos_memory_mmap_fn g_chaos_memory_real_mmap = NULL;
chaos_memory_munmap_fn g_chaos_memory_real_munmap = NULL;
chaos_memory_mprotect_fn g_chaos_memory_real_mprotect = NULL;
chaos_memory_madvise_fn g_chaos_memory_real_madvise = NULL;
chaos_memory_nanosleep_fn g_chaos_memory_real_nanosleep = NULL;
chaos_memory_usleep_fn g_chaos_memory_real_usleep = NULL;

__thread int g_chaos_memory_tls_guard = 0;
__thread uint64_t g_chaos_memory_tls_prng_state = 0U;
uint64_t g_chaos_memory_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_MEMORY_CONSTRUCTOR
#define CHAOS_MEMORY_CONSTRUCTOR __attribute__((constructor))
#endif

static void chaos_memory_resolve_symbol(void *target, const char *symbol)
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

static uint64_t chaos_memory_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_memory_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_memory_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_memory_leave_internal(previous);
    }
#endif

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

CHAOS_MEMORY_CONSTRUCTOR
static void chaos_memory_init(void)
{
    chaos_memory_resolve_symbol(&g_chaos_memory_real_mmap, "mmap");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_munmap, "munmap");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_mprotect, "mprotect");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_madvise, "madvise");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_nanosleep, "nanosleep");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_usleep, "usleep");

    g_chaos_memory_process_seed = chaos_memory_read_seed_material();
    chaos_memory_prng_seed_thread(g_chaos_memory_process_seed);
    chaos_memory_config_init();
}
