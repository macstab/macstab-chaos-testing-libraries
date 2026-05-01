/**
 * @file chaos_dns.c
 * @brief Library constructor, symbol resolution, and global variable definitions.
 *
 * @details
 * This translation unit owns two responsibilities:
 *
 *   1. **Global variable definitions** — the three real-symbol function
 *      pointers, the TLS reentrancy guard, the TLS PRNG state, and the
 *      process-wide PRNG seed.  All other TUs in the subsystem reference
 *      these via the `extern` declarations in chaos_dns_internal.h.
 *
 *   2. **Process initialisation** (`chaos_dns_init`, marked
 *      `__attribute__((constructor))`) — resolves the real libc resolver
 *      symbols via dlsym(RTLD_NEXT), seeds the process-wide and main-thread
 *      PRNG state, and triggers the initial config load.
 *
 * ### Symbol resolution strategy
 * dlsym(RTLD_NEXT, ...) walks the DSO link map starting from the library
 * immediately after libchaos-dns, which is the libc (or resolver library)
 * that provides the real implementations.  Any failure here is fatal —
 * there is no meaningful fallback if the real resolver is absent.
 *
 * ### Seed entropy strategy
 * On Linux, /dev/urandom is opened via raw syscalls (SYS_openat, SYS_read,
 * SYS_close) rather than the libc wrappers.  This avoids any possibility of
 * the open()/read() wrappers being interposed by another LD_PRELOAD library,
 * and also avoids re-entering the reentrancy guard path unnecessarily.  On
 * non-Linux platforms the fallback combines a known constant with the PID.
 *
 * ### Invariants
 * - After chaos_dns_init() returns:
 *     - g_chaos_dns_real_getaddrinfo != NULL
 *     - g_chaos_dns_real_getnameinfo != NULL
 *     - g_chaos_dns_real_freeaddrinfo != NULL
 *     - g_chaos_dns_process_seed != 0 (guaranteed by the fallback constant)
 *     - g_chaos_dns_tls_prng_state != 0 for the main thread
 *
 * @module  libchaos-dns core
 * @stability  Private
 */

#include "chaos_dns_config.h"
#include "chaos_dns_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Global variable definitions
 * See chaos_dns_internal.h for semantics of each variable.
 * ------------------------------------------------------------------------- */

/** @cond INTERNAL */
chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;
chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;
chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;

__thread int g_chaos_dns_tls_guard = 0;
__thread uint64_t g_chaos_dns_tls_prng_state = 0U;
uint64_t g_chaos_dns_process_seed = UINT64_C(0x2545f4914f6cdd1d);
/** @endcond */

#ifndef CHAOS_DNS_CONSTRUCTOR
#define CHAOS_DNS_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * @brief Resolve a single libc symbol via dlsym(RTLD_NEXT) and store it.
 *
 * @details The resolved function pointer is written into @p target using
 * memcpy rather than a direct pointer assignment.  This avoids strict-alias
 * UB that would arise from casting a `void *` to a function-pointer type
 * through an intermediate `void **`; memcpy is well-defined for any object
 * representation.
 *
 * If dlsym returns NULL *and* dlerror() is also non-NULL (indicating a
 * genuine lookup failure rather than a symbol that legitimately resolves to
 * address zero), the process aborts immediately.  There is no recovery path
 * because without the real symbol the interposed entry points cannot delegate
 * to the actual implementation.
 *
 * @param target  Pointer to a function-pointer variable to receive the result
 *                (e.g., `&g_chaos_dns_real_getaddrinfo`).  Must be
 *                `sizeof(void *)` bytes.
 * @param symbol  NUL-terminated name of the symbol to resolve.
 *
 * @pre   @p target and @p symbol must be non-NULL.
 * @post  *target holds the resolved function pointer, or the process has
 *        aborted.
 */
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

/**
 * @brief Read 8 bytes of entropy from /dev/urandom for use as the process seed.
 *
 * @details On Linux the file is opened and read using raw syscalls so that no
 * other LD_PRELOAD library can intercept the I/O, and so that the reentrancy
 * guard is set while the read is in progress (preventing the read from
 * triggering a recursive interposition of any file-related wrapper).
 *
 * The reentrancy guard is saved/restored rather than unconditionally set so
 * that this function can be called safely even if invoked from within an
 * already-internal context (unlikely but defensive).
 *
 * If the read fails for any reason (platform is not Linux, fd < 0, short
 * read), the function falls back to `0x6a09e667f3bcc909 ^ getpid()`.  This
 * constant is the fractional part of sqrt(2) in IEEE-754 double, chosen as
 * an arbitrary non-zero starting point that differs from the initial value of
 * g_chaos_dns_process_seed so the fallback is distinguishable in tests.
 *
 * @return  An entropy value suitable for use as g_chaos_dns_process_seed.
 */
static uint64_t chaos_dns_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    /* Use raw syscalls to avoid re-entering any interposed open/read. */
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

    /* Non-Linux or /dev/urandom unavailable: combine a known constant with the PID. */
    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/**
 * @brief Library constructor: resolve symbols, seed PRNG, load initial config.
 *
 * @details Executed by the dynamic linker before main() (or before the
 * dlopen() call that loads the library).  Three steps:
 *
 *   1. Resolve `getaddrinfo`, `getnameinfo`, and `freeaddrinfo` from the next
 *      DSO in the link map.  Any resolution failure aborts the process.
 *
 *   2. Seed the process-wide PRNG from /dev/urandom (or PID fallback), then
 *      use that seed to initialise the main-thread TLS PRNG state so that
 *      the first call on the main thread does not trigger the lazy-init path.
 *
 *   3. Call chaos_dns_config_init() to zero-initialise the two config
 *      snapshots and set the mtime sentinel to CHAOS_DNS_MTIME_UNKNOWN,
 *      ensuring the first lookup triggers a config file stat(2).
 *
 * @post  All three real-symbol pointers are non-NULL.
 * @post  g_chaos_dns_process_seed is seeded.
 * @post  g_chaos_dns_tls_prng_state is non-zero for the calling thread.
 * @post  Config subsystem is ready for use.
 */
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
