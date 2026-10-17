/**
 * @file chaos_time.c
 * @brief libchaos-time bootstrap: real-function resolution, seeding and the first load.
 *
 * @details
 * The ELF constructor chaos_time_init() runs, in order:
 *
 *  1. **Resolution:** chaos_time_ensure_symbols() fills the eight real-function pointers
 *     through `dlsym(RTLD_NEXT)`. Wrappers call it too, because another object's
 *     constructor can reach a wrapper before this one runs.
 *  2. **Seeding:** 8 bytes from /dev/urandom become the process seed, read with raw
 *     openat/read/close system calls so that no other preloaded library interposing
 *     open or read (libchaos-io) sees or faults the read. errno is preserved.
 *  3. **PRNG:** the constructing thread is seeded from the process seed; other threads
 *     seed themselves on their first draw.
 *  4. **Rules:** chaos_time_config_init() resets both snapshots and marks the change stamp
 *     unknown, then chaos_time_config_prepare() loads the rule file, so a bad file is
 *     reported in the status file at start-up rather than at the first clock read.
 *
 * @par Failure behaviour
 * A lookup that dlerror() reports as failed calls abort(3): running with a wrong symbol
 * table would be worse than not running. A pointer can still be NULL (a symbol absent
 * from the chain, or a call that arrives while resolution runs); the call helpers in
 * chaos_time_hooks.c then make the system call directly. A failed urandom read falls
 * back to a pid-derived seed; probabilities still work, only less unpredictably.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_once.h"
#include "chaos_time_config.h"
#include "chaos_time_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/** Real clock_gettime(2); NULL until first resolution. */
chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;

/** Real nanosleep(2); NULL until first resolution. */
chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;

/** Real usleep(3); NULL until first resolution. */
chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;

/** Real gettimeofday(2); NULL until first resolution. */
chaos_time_gettimeofday_fn g_chaos_time_real_gettimeofday = NULL;

/** Real time(2); NULL until first resolution. */
chaos_time_time_fn g_chaos_time_real_time = NULL;

/** Real sleep(3); NULL until first resolution. */
chaos_time_sleep_fn g_chaos_time_real_sleep = NULL;

/** Real timespec_get(3); NULL until first resolution. */
chaos_time_timespec_get_fn g_chaos_time_real_timespec_get = NULL;

/** Real clock_nanosleep(2); NULL until first resolution. */
chaos_time_clock_nanosleep_fn g_chaos_time_real_clock_nanosleep = NULL;

/** Reentrancy guard; 0 outside library code. Every new thread starts at 0. */
__thread int g_chaos_time_tls_guard = 0;

/** xorshift64* state; 0 means unseeded, so every new thread seeds itself on first draw. */
__thread uint64_t g_chaos_time_tls_prng_state = 0U;

/**
 * Process seed; overwritten with /dev/urandom bytes by chaos_time_init().
 *
 * The initial constant serves only threads that draw before the constructor has run
 * (another object's constructor calling a wrapper); their thread id and stack address
 * still separate them.
 */
uint64_t g_chaos_time_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_TIME_CONSTRUCTOR
/** Makes chaos_time_init() an ELF constructor; overridable at compile time (test seam). */
#define CHAOS_TIME_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * Stores `dlsym(RTLD_NEXT, symbol)` into the function pointer at @p target, if unset.
 *
 * The pointer is copied with memcpy because ISO C does not define converting an object
 * pointer (`void *`) to a function pointer. A pointer that is already set (by an earlier
 * call, or by a test harness) is left alone.
 *
 * @par Failure behaviour
 * abort(3) when dlsym() returns NULL and dlerror() reports an error. A NULL result
 * without an error leaves the pointer NULL; the call helpers then use raw system calls.
 *
 * @param target  Function-pointer variable of sizeof(void *) bytes.
 * @param symbol  Symbol name.
 */
static void chaos_time_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    /* A pointer already wired (by an earlier call, or by a test harness) stays. */
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
 * Reads 8 bytes from /dev/urandom with raw openat/read/close system calls.
 *
 * Raw system calls keep the read invisible to any other preloaded library that
 * interposes open or read (libchaos-io would otherwise see, and could fault, it). The
 * guard is held anyway, so nothing the read might call reaches this library's wrappers.
 *
 * @return The 8 bytes; on any failure, or off Linux, 0x6a09e667f3bcc909 XOR pid, which
 *         is never 0. errno may be changed (see chaos_time_read_seed_material()).
 */
static uint64_t chaos_time_read_urandom_seed(void)
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
 * @brief chaos_time_read_urandom_seed() with errno preserved.
 *
 * @details Only the constructor calls it; preloading the library must not change the
 * errno a program observes, so a failed openat or read leaves no trace.
 */
static uint64_t chaos_time_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_time_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/**
 * @brief Run-once state of symbol resolution.
 *
 * @details `chaos_once()`, not `pthread_once()`: before glibc 2.34 the latter lives
 * in libpthread, which programs such as `cat` and `sh` do not load.
 */
static volatile chaos_once_t g_chaos_time_symbols_once = CHAOS_ONCE_INIT;

/**
 * @brief Resolves all eight real functions; runs once, through chaos_time_ensure_symbols().
 *
 * @details Calls no wrapper of this library. `dlsym(RTLD_NEXT, ...)` walks the
 * loaded link map without file I/O; if it allocates and the allocator calls back into a
 * wrapper, chaos_once() returns 0 to that nested call and the helper uses a system call.
 */
static void chaos_time_resolve_all_symbols(void)
{
    chaos_time_resolve_symbol(&g_chaos_time_real_clock_gettime, "clock_gettime");
    chaos_time_resolve_symbol(&g_chaos_time_real_nanosleep, "nanosleep");
    chaos_time_resolve_symbol(&g_chaos_time_real_usleep, "usleep");
    chaos_time_resolve_symbol(&g_chaos_time_real_gettimeofday, "gettimeofday");
    chaos_time_resolve_symbol(&g_chaos_time_real_time, "time");
    chaos_time_resolve_symbol(&g_chaos_time_real_clock_nanosleep, "clock_nanosleep");
    chaos_time_resolve_symbol(&g_chaos_time_real_sleep, "sleep");
    chaos_time_resolve_symbol(&g_chaos_time_real_timespec_get, "timespec_get");
}

void chaos_time_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_time_symbols_once, chaos_time_resolve_all_symbols);
}

/**
 * ELF constructor: resolves, seeds, initialises the rule state and loads the rule file.
 *
 * Runs before main(), but not necessarily before every other object's constructor:
 * those may call a wrapper first, which is why each wrapper resolves symbols itself and
 * a rule load also happens lazily. See the file header for the steps and their order.
 */
CHAOS_TIME_CONSTRUCTOR
static void chaos_time_init(void)
{
    chaos_time_ensure_symbols();
    g_chaos_time_process_seed = chaos_time_read_seed_material();
    chaos_time_prng_seed_thread(g_chaos_time_process_seed);
    chaos_time_config_init();
    /* Load now, so a bad rule file shows in the status file at start-up. */
    (void)chaos_time_config_prepare();
}
