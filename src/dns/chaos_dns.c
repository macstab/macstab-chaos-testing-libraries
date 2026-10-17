/**
 * @file chaos_dns.c
 * @brief libchaos-dns constructor, real-function resolution and global state.
 *
 * @details
 * Owns:
 *   1. **Global state**: the seven g_chaos_dns_real_* pointers, the thread-local guard
 *      and PRNG state, and the process seed, declared in chaos_dns_internal.h.
 *   2. **Initialisation**: chaos_dns_init() (constructor) resolves the real functions,
 *      seeds the PRNG, resets the rule subsystem and loads the rule file once, so a bad
 *      rule file is reported in the status file at start-up.
 *
 * ### Symbol resolution
 * dlsym(RTLD_NEXT, ...) returns the next definition after this DSO in lookup order:
 * libc, or another preloaded library. chaos_dns_ensure_symbols() runs the resolution
 * once (chaos_once()), from whichever wrapper or the constructor comes first. A symbol
 * that cannot be found aborts: a wrapper without a real resolver has nothing to forward
 * to.
 *
 * ### Seed entropy
 * Linux: 8 bytes from /dev/urandom through raw SYS_openat/SYS_read/SYS_close, so no
 * preloaded library (libchaos-io) sees, faults or delays the read. If that fails, or on
 * other platforms, a constant XOR getpid().
 *
 * ### Invariants
 * - Once the resolution has completed, every g_chaos_dns_real_* pointer is non-NULL;
 *   only a call made from inside it, on its own thread, can see NULL.
 * - g_chaos_dns_process_seed is written once, by the constructor.
 * - After chaos_dns_init(), the constructing thread's PRNG state is seeded.
 *
 * ### Fork and exec
 * fork() children inherit pointers and seed; the config atfork handler zeroes the
 * forking thread's PRNG state. exec() runs the constructor again in the new image.
 *
 * @module  libchaos-dns core
 * @stability  Private
 */

#include "chaos_once.h"
#include "chaos_dns_config.h"
#include "chaos_dns_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * Global state; semantics in chaos_dns_internal.h.
 * ------------------------------------------------------------------------- */

/** @cond INTERNAL */
chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;
chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;
chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;
chaos_dns_gethostbyname2_fn g_chaos_dns_real_gethostbyname2 = NULL;
chaos_dns_gethostbyname2_r_fn g_chaos_dns_real_gethostbyname2_r = NULL;
chaos_dns_gethostbyaddr_fn g_chaos_dns_real_gethostbyaddr = NULL;
chaos_dns_gethostbyaddr_r_fn g_chaos_dns_real_gethostbyaddr_r = NULL;

__thread int g_chaos_dns_tls_guard = 0;
__thread uint64_t g_chaos_dns_tls_prng_state = 0U;
uint64_t g_chaos_dns_process_seed = UINT64_C(0x2545f4914f6cdd1d);
/** @endcond */

/** @brief Constructor attribute of chaos_dns_init(); unit tests define it empty. */
#ifndef CHAOS_DNS_CONSTRUCTOR
#define CHAOS_DNS_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * @brief Resolves @p symbol with dlsym(RTLD_NEXT) into the pointer at @p target, once.
 *
 * @details A pointer already set (an earlier call, a test harness) is left alone.
 * dlsym returning NULL with dlerror() set is a genuine lookup failure and aborts the
 * process: without the real function the wrapper cannot delegate. The pointer is copied
 * with memcpy because ISO C does not allow converting between void * and function
 * pointers.
 *
 * @param target  Address of a g_chaos_dns_real_* variable; must not be NULL.
 * @param symbol  Symbol name; must not be NULL.
 *
 * @post  *target is non-NULL, or the process has aborted.
 */
static void chaos_dns_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    /* Fill only what is unset: a pointer already wired (an earlier call, a test harness)
     * is never replaced. */
    (void)memcpy(&current, target, sizeof(current));
    if (current != NULL)
    {
        return;
    }

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
    {
        abort();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief 8 bytes from /dev/urandom for the process seed; a pid-derived fallback.
 *
 * @details Linux: raw SYS_openat/SYS_read/SYS_close, so no other preloaded library
 * (libchaos-io) intercepts, faults or delays the read. The guard is set anyway, for
 * symmetry with every other library call. A failed open, a short read, or a non-Linux
 * build falls back to 0x6a09e667f3bcc909 XOR getpid() (the first 64 fractional bits of
 * sqrt(2), 0x6a09e667f3bcc908, plus 1): weaker, but distinct per process.
 *
 * @return  The seed.
 * @par errno: may be clobbered; see chaos_dns_read_seed_material().
 */
static uint64_t chaos_dns_read_urandom_seed(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    /* Raw system calls: no preloaded library sees this read. */
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

    /* /dev/urandom unavailable, or not Linux: a constant XOR the pid. */
    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/**
 * @brief chaos_dns_read_urandom_seed(), preserving errno.
 *
 * @details Called by the constructor (and by unit tests through chaos_dns_init()); the
 * library's own /dev/urandom read must leave errno as the program had it.
 */
static uint64_t chaos_dns_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_dns_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/**
 * @brief Once-control of the resolution.
 *
 * @details chaos_once(), not pthread_once(): before glibc 2.34 the latter lives in
 * libpthread, which programs such as `cat` and `sh` do not load.
 */
static volatile chaos_once_t g_chaos_dns_symbols_once = CHAOS_ONCE_INIT;

/**
 * @brief Resolves every real function. Runs once, through chaos_dns_ensure_symbols().
 *
 * @details Must not call a wrapper of this library: on this thread a re-entry into
 * chaos_once() returns at once with the pointers still unset. dlsym(RTLD_NEXT, ...)
 * walks the loaded link map and does no file I/O.
 */
static void chaos_dns_resolve_all_symbols(void)
{
    chaos_dns_resolve_symbol(&g_chaos_dns_real_getaddrinfo, "getaddrinfo");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_getnameinfo, "getnameinfo");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_freeaddrinfo, "freeaddrinfo");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_gethostbyname2, "gethostbyname2");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_gethostbyname2_r, "gethostbyname2_r");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_gethostbyaddr, "gethostbyaddr");
    chaos_dns_resolve_symbol(&g_chaos_dns_real_gethostbyaddr_r, "gethostbyaddr_r");
}

void chaos_dns_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_dns_symbols_once, chaos_dns_resolve_all_symbols);
}

/**
 * @brief Library constructor: resolves, seeds, resets the rules, loads the rule file.
 *
 * @details Run by the dynamic linker before main() (or by dlopen()), possibly after
 * another object's constructor has already reached a wrapper. Order:
 *   1. chaos_dns_ensure_symbols(): the seven real resolver functions.
 *   2. Process seed from /dev/urandom (or the fallback), then this thread's PRNG state.
 *   3. chaos_dns_config_init(): empty snapshots, stamp CHAOS_DNS_MTIME_UNKNOWN, fork
 *      handler.
 *   4. chaos_dns_config_prepare(): first load; the status file reports it.
 *
 * @post  Every real-function pointer is non-NULL.
 * @post  g_chaos_dns_process_seed is set; the calling thread's PRNG is seeded.
 * @post  The rule file, if any, is loaded and reported.
 */
CHAOS_DNS_CONSTRUCTOR
static void chaos_dns_init(void)
{
    chaos_dns_ensure_symbols();
    g_chaos_dns_process_seed = chaos_dns_read_seed_material();
    chaos_dns_prng_seed_thread(g_chaos_dns_process_seed);
    chaos_dns_config_init();
    /* Load the rules now so a bad rule file is reported at start-up. */
    (void)chaos_dns_config_prepare();
}
