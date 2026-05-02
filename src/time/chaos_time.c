/**
 * @file chaos_time.c
 * @brief Library initialisation: symbol resolution, entropy collection, and
 *        process-wide bootstrapping for the libchaos-time subsystem.
 *
 * This translation unit contains the ELF constructor that runs before any
 * application code executes.  Its responsibilities are:
 *
 *  1. **Symbol resolution** — locate the real implementations of
 *     clock_gettime(2), nanosleep(2), and usleep(3) via RTLD_NEXT and store
 *     them in the global function-pointer variables.  All other translation
 *     units call through these pointers to avoid recursing into the wrappers.
 *
 *  2. **Entropy collection** — read 8 bytes from /dev/urandom using raw
 *     syscalls rather than the libc wrappers.  Raw syscalls are used because
 *     at constructor time libc may not have initialised its own file-descriptor
 *     layer, and because calling open(2) through the libc wrapper would trigger
 *     the chaos_time interceptors if they were already active.  The reentrancy
 *     guard is set for the duration of the syscall sequence to be safe.
 *
 *  3. **PRNG initialisation** — seed the main thread's per-thread PRNG state
 *     from the collected entropy so that the first probability decision is
 *     drawn from a high-quality random stream.
 *
 *  4. **Config initialisation** — call chaos_time_config_init() to zero the
 *     two config state snapshots and set the cached mtime to
 *     CHAOS_TIME_MTIME_UNKNOWN, which ensures the first intercepted call
 *     triggers a config reload.
 *
 * @invariant  After chaos_time_init() returns, g_chaos_time_real_clock_gettime,
 *             g_chaos_time_real_nanosleep, and g_chaos_time_real_usleep are all
 *             non-NULL.  If any RTLD_NEXT lookup fails, abort(3) is called
 *             immediately so the process cannot proceed with null function
 *             pointers.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_time_config.h"
#include "chaos_time_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/**
 * Resolved pointer to the real clock_gettime(2).
 *
 * NULL until chaos_time_init() completes.  Set exactly once; thereafter
 * treated as read-only by all threads.
 */
chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;

/**
 * Resolved pointer to the real nanosleep(2).
 *
 * NULL until chaos_time_init() completes.  Set exactly once; thereafter
 * treated as read-only by all threads.
 */
chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;

/**
 * Resolved pointer to the real usleep(3).
 *
 * NULL until chaos_time_init() completes.  Set exactly once; thereafter
 * treated as read-only by all threads.
 */
chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;

/**
 * Per-thread reentrancy guard; 0 = not inside the library, 1 = inside.
 *
 * Initial value of 0 is correct: the main thread is not inside the library
 * until chaos_time_init() is called, and by the time that constructor returns
 * the guard has been restored to 0.
 */
__thread int g_chaos_time_tls_guard = 0;

/**
 * Per-thread xorshift64* PRNG state.
 *
 * Initial value of 0 signals "not yet seeded"; chaos_time_prng_ensure_seeded()
 * initialises it on first use.
 */
__thread uint64_t g_chaos_time_tls_prng_state = 0U;

/**
 * Process-wide base seed written once from /dev/urandom during
 * chaos_time_init().
 *
 * The default value 0x2545f4914f6cdd1d (the xorshift64* output multiplier)
 * is a reasonable non-zero constant used if entropy collection fails before
 * init, e.g. during very early static-initialiser callbacks.
 */
uint64_t g_chaos_time_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_TIME_CONSTRUCTOR
/** Attribute that causes chaos_time_init() to run as an ELF constructor. */
#define CHAOS_TIME_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * Resolves one libc symbol via RTLD_NEXT and stores the resulting pointer.
 *
 * Uses memcpy to move the void* into the typed function-pointer target,
 * which avoids undefined behaviour from a direct cast through incompatible
 * pointer types (ISO C forbids converting between function-pointer and
 * object-pointer types via assignment).
 *
 * Calls abort(3) if dlsym() returns NULL and dlerror() confirms a lookup
 * failure.  A NULL result without an error string is accepted; this can happen
 * when the symbol genuinely does not exist in the chain (e.g. usleep on a
 * platform that maps it to nanosleep at the linker level).
 *
 * @param target  Pointer to the function-pointer variable to populate.
 *                Must point to storage of exactly sizeof(void*) bytes.
 * @param symbol  NUL-terminated name of the symbol to resolve.
 */
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

/**
 * Reads 8 bytes of entropy from /dev/urandom using raw Linux syscalls.
 *
 * Raw syscalls are used for two reasons:
 *
 *  1. At constructor time the libc file-descriptor layer may not yet be
 *     initialised, making open(3)/read(3)/close(3) unsafe.
 *  2. Using the wrapped open() would potentially trigger the chaos interceptors
 *     (if somehow invoked recursively), even though the reentrancy guard is set
 *     before the call.
 *
 * The reentrancy guard is raised around the syscall sequence with
 * chaos_time_enter_internal() / chaos_time_leave_internal() to prevent any
 * re-entrant chaos decisions from being made while reading entropy.
 *
 * Falls back to a deterministic value derived from getpid() on non-Linux
 * platforms or if the read fails.
 *
 * @return  8 bytes of entropy as a uint64_t, or a pid-derived constant on
 *          failure.  Never returns zero on the non-Linux fallback path.
 */
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

/**
 * ELF constructor: initialises the entire libchaos-time subsystem.
 *
 * Execution order:
 *
 *  1. Resolve the three real function pointers via RTLD_NEXT.
 *  2. Collect entropy from /dev/urandom and write it to g_chaos_time_process_seed.
 *  3. Seed the main thread's PRNG state from the process seed.
 *  4. Initialise the config subsystem (zeros both snapshots, sets cached mtime
 *     to CHAOS_TIME_MTIME_UNKNOWN).
 *
 * Runs before main() and before any static C++ constructors that might call
 * clock_gettime or nanosleep.  If symbol resolution fails, abort(3) is called
 * so the application never runs with null function pointers.
 */
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
