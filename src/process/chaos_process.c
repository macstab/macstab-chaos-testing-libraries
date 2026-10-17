/**
 * @file chaos_process.c
 * @brief libchaos-process bootstrap: shared globals, real-function resolution, seeding
 *        and the first load.
 *
 * @details
 * Defines the globals declared in chaos_process_internal.h. The ELF constructor
 * chaos_process_init() runs, in order:
 *
 *  1. **Resolution:** chaos_process_ensure_symbols() fills the real-function pointers
 *     through `dlsym(RTLD_NEXT)`. Wrappers call it too, because another object's
 *     constructor can reach a wrapper before this one runs.
 *  2. **Seeding:** 8 bytes from /dev/urandom become the process seed, read with raw
 *     openat/read/close system calls so that no other preloaded library interposing
 *     open or read (libchaos-io) sees or faults the read. errno is preserved.
 *  3. **PRNG:** the constructing thread is seeded from the process seed; other threads
 *     seed themselves on their first draw.
 *  4. **Rules:** chaos_process_config_init() resets the rule state, then
 *     chaos_process_config_prepare() loads the rule file, so a bad file is reported in
 *     the status file at start-up rather than at the first wrapped call.
 *
 * @par Failure behaviour
 * A required symbol whose lookup dlerror() reports as failed calls abort(3). Optional
 * symbols (pthread_create before glibc 2.34, execveat, execvpe, fexecve) may stay NULL.
 * A pointer can also be NULL while resolution runs; the call helpers in
 * chaos_process_hooks.c then use a raw system call or report ENOSYS / EAGAIN. A failed
 * urandom read falls back to a pid-derived seed.
 */

#include "chaos_once.h"
#include "chaos_process_config.h"
#include "chaos_process_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Global state definitions (declared extern in chaos_process_internal.h)
 * ---------------------------------------------------------------------- */

/** @cond INTERNAL */

chaos_process_pthread_create_fn g_chaos_process_real_pthread_create = NULL;
chaos_process_fork_fn g_chaos_process_real_fork = NULL;
chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn = NULL;
chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp = NULL;
chaos_process_execve_fn g_chaos_process_real_execve = NULL;
chaos_process_execveat_fn g_chaos_process_real_execveat = NULL;
chaos_process_waitpid_fn g_chaos_process_real_waitpid = NULL;
chaos_process_wait4_fn g_chaos_process_real_wait4 = NULL;
chaos_process_execvpe_fn g_chaos_process_real_execvpe = NULL;
chaos_process_fexecve_fn g_chaos_process_real_fexecve = NULL;
chaos_process_system_fn g_chaos_process_real_system = NULL;
chaos_process_popen_fn g_chaos_process_real_popen = NULL;
chaos_process_waitid_fn g_chaos_process_real_waitid = NULL;
__thread int g_chaos_process_tls_guard = 0;
__thread uint64_t g_chaos_process_tls_prng_state = 0U;
uint64_t g_chaos_process_process_seed = UINT64_C(0x2545f4914f6cdd1d);
volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U};

/** @endcond */

/* -------------------------------------------------------------------------
 * Constructor guard
 * ---------------------------------------------------------------------- */

#ifndef CHAOS_PROCESS_CONSTRUCTOR
/** Makes chaos_process_init() an ELF constructor; overridable at compile time (test seam). */
#define CHAOS_PROCESS_CONSTRUCTOR __attribute__((constructor))
#endif

/* -------------------------------------------------------------------------
 * Static helpers
 * ---------------------------------------------------------------------- */

/**
 * @brief Stores `dlsym(RTLD_NEXT, symbol)` into the function pointer at @p target, if
 *        unset.
 *
 * The pointer is copied with memcpy because ISO C does not define converting an object
 * pointer (`void *`) to a function pointer. A pointer already set (by an earlier call,
 * or by a test harness) is left alone.
 *
 * @par Failure behaviour
 * abort(3) when dlsym() returns NULL and dlerror() reports an error: running a required
 * wrapper without its real function would be worse than not running. A NULL result
 * without an error leaves the pointer NULL.
 *
 * @param target  Function-pointer variable of sizeof(void *) bytes.
 * @param symbol  Symbol name.
 */
static void chaos_process_resolve_symbol(void *target, const char *symbol)
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
 * @brief chaos_process_resolve_symbol() for optional symbols: absence leaves the pointer
 *        NULL and clears the dlerror() state instead of aborting.
 *
 * Used for pthread_create, execveat, execvpe and fexecve, which a given libc version
 * may not export.
 *
 * @param target  Function-pointer variable; left unchanged when already set.
 * @param symbol  Symbol name.
 */
static void chaos_process_try_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    (void)memcpy(&current, target, sizeof(current));
    if (current != NULL)
    {
        return;
    }

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL)
    {
        (void)dlerror();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief Reads 8 bytes from /dev/urandom with raw openat/read/close system calls.
 *
 * Raw system calls keep the read invisible to any other preloaded library that
 * interposes open or read. The guard is held anyway, so nothing the read might call
 * reaches this library's wrappers.
 *
 * @return The 8 bytes; 0x6a09e667f3bcc909 XOR pid off Linux, when openat fails (no
 *         /dev/urandom in a sandbox) or on a short read. errno may change (see
 *         chaos_process_read_seed_material()).
 */
static uint64_t chaos_process_read_urandom_seed(void)
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

/**
 * @brief chaos_process_read_urandom_seed() with errno preserved.
 *
 * @details Only the constructor calls it; preloading the library must not change the
 * errno a program observes, so a failed openat or read leaves no trace.
 */
static uint64_t chaos_process_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_process_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/**
 * @brief Resolves `pthread_create`, which may be absent until libpthread is loaded.
 *
 * @details Before glibc 2.34 `pthread_create` lives in libpthread. A program that
 * does not link it never calls it, but resolving it eagerly aborted that program
 * at start-up. Unresolved, the pointer stays NULL and the wrapper retries here: a
 * library loaded later with `dlopen()` can bring libpthread in.
 */
void chaos_process_resolve_pthread_create(void)
{
    chaos_process_try_resolve_symbol(&g_chaos_process_real_pthread_create, "pthread_create");
}

/**
 * @brief Run-once state of symbol resolution.
 *
 * @details `chaos_once()`, not `pthread_once()`: before glibc 2.34 the latter lives
 * in libpthread, which programs such as `cat` and `sh` do not load.
 */
static volatile chaos_once_t g_chaos_process_symbols_once = CHAOS_ONCE_INIT;

/**
 * @brief Resolves all real functions; runs once, through chaos_process_ensure_symbols().
 *
 * @details Calls no wrapper of this library. `dlsym(RTLD_NEXT, ...)` walks the loaded
 * link map without file I/O; if it allocates and the allocator calls back into a
 * wrapper, chaos_once() returns 0 to that nested call and its helper falls back.
 */
static void chaos_process_resolve_all_symbols(void)
{
    chaos_process_resolve_pthread_create();
    chaos_process_resolve_symbol(&g_chaos_process_real_fork, "fork");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawn, "posix_spawn");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawnp, "posix_spawnp");
    chaos_process_resolve_symbol(&g_chaos_process_real_execve, "execve");
#ifdef __linux__
    /* Optional: not every libc version exports execveat (glibc added it in 2.34). */
    chaos_process_try_resolve_symbol(&g_chaos_process_real_execveat, "execveat");
#endif
    chaos_process_resolve_symbol(&g_chaos_process_real_waitpid, "waitpid");
    chaos_process_resolve_symbol(&g_chaos_process_real_wait4, "wait4");
    chaos_process_resolve_symbol(&g_chaos_process_real_waitid, "waitid");
    chaos_process_resolve_symbol(&g_chaos_process_real_system, "system");
    chaos_process_resolve_symbol(&g_chaos_process_real_popen, "popen");
    chaos_process_try_resolve_symbol(&g_chaos_process_real_execvpe, "execvpe");
    chaos_process_try_resolve_symbol(&g_chaos_process_real_fexecve, "fexecve");
}

void chaos_process_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_process_symbols_once, chaos_process_resolve_all_symbols);
}

/**
 * @brief ELF constructor: resolves, seeds, initialises the rule state and loads the rule
 *        file (see the file header for the order).
 *
 * Runs before main(), but not necessarily before every other object's constructor:
 * those may call a wrapper first, which is why each wrapper resolves symbols itself and
 * a rule load also happens lazily.
 */
CHAOS_PROCESS_CONSTRUCTOR
static void chaos_process_init(void)
{
    chaos_process_ensure_symbols();
    g_chaos_process_process_seed = chaos_process_read_seed_material();
    chaos_process_prng_seed_thread(g_chaos_process_process_seed);
    chaos_process_config_init();
    /* Load now, so a bad rule file shows in the status file at start-up. */
    (void)chaos_process_config_prepare();
}
