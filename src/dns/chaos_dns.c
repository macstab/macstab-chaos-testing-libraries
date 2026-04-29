#include "chaos_dns_config.h"
#include "chaos_dns_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>

chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;
chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;
chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;

__thread int g_chaos_dns_tls_guard = 0;
__thread uint64_t g_chaos_dns_tls_prng_state = 0U;
uint64_t g_chaos_dns_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_DNS_CONSTRUCTOR
#define CHAOS_DNS_CONSTRUCTOR __attribute__((constructor))
#endif

static void chaos_dns_resolve_symbol(void *target, const char *symbol)
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

static uint64_t chaos_dns_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_dns_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_dns_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_dns_leave_internal(previous);
    }
#endif

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

CHAOS_DNS_CONSTRUCTOR
static void chaos_dns_init(void)
{
    chaos_dns_resolve_symbol(&g_chaos_dns_real_getaddrinfo, "getaddrinfo");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_getnameinfo, "getnameinfo");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_freeaddrinfo, "freeaddrinfo");

    g_chaos_dns_process_seed = chaos_dns_read_seed_material();
    chaos_dns_prng_seed_thread(g_chaos_dns_process_seed);
    chaos_dns_config_init();
}
