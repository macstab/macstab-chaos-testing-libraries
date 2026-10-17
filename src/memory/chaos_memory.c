/**
 * @file chaos_memory.c
 * @brief libchaos-memory start-up: storage of the shared state, real function
 *        lookup, seeding and the first load of the rule file.
 *
 * @details
 * Owns:
 *  - the definitions of the state declared `extern` in chaos_memory_internal.h
 *    (real function pointers, reentrancy guard, PRNG state, process seed);
 *  - chaos_memory_ensure_symbols(), the run-once `dlsym(RTLD_NEXT)` lookup every
 *    wrapper calls first;
 *  - the constructor, which resolves the real functions, seeds the PRNG and loads
 *    the rule file so that a bad file is reported in the status file at start-up
 *    rather than on the first intercepted call.
 *
 * @par Ordering hazard
 * A wrapper can run before the constructor: another object's constructor may call
 * mmap(), and dlsym() itself may allocate (`dlsym` -> `calloc` -> a preloaded
 * allocator -> `mmap`). Therefore the lookup is lazy and run-once, and a wrapper
 * that finds its real function pointer still NULL issues the system call directly
 * (chaos_memory_hooks.c).
 *
 * @par Failure behaviour
 * Fail-closed on lookup: a real function that dlsym() cannot find while dlerror()
 * reports an error aborts the process. A missing /dev/urandom falls back to a
 * PID-derived seed.
 *
 * @par Test seams
 * CHAOS_MEMORY_CONSTRUCTOR (empty in unit tests, which then call the steps
 * themselves); resolve_symbol() keeps pointers a test has already set.
 */

#include "chaos_once.h"
#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Storage for the state declared in chaos_memory_internal.h
 * =========================================================================
 */

/** @brief Real mmap(2); NULL until chaos_memory_ensure_symbols() resolves it. */
chaos_memory_mmap_fn g_chaos_memory_real_mmap = NULL;

/** @brief Real munmap(2); NULL until resolved. */
chaos_memory_munmap_fn g_chaos_memory_real_munmap = NULL;

/** @brief Real mprotect(2); NULL until resolved. */
chaos_memory_mprotect_fn g_chaos_memory_real_mprotect = NULL;

/** @brief Real madvise(2); NULL until resolved. */
chaos_memory_madvise_fn g_chaos_memory_real_madvise = NULL;

/** @brief Real posix_madvise(3); NULL until resolved. */
chaos_memory_posix_madvise_fn g_chaos_memory_real_posix_madvise = NULL;

/**
 * @brief Per-thread reentrancy guard (see chaos_memory_internal.h). Zero at thread
 *        start; enter/leave restore the saved value, so it never needs a reset.
 */
__thread int g_chaos_memory_tls_guard = 0;

/** @brief Per-thread xorshift64* state; 0 until the thread's first draw seeds it. */
__thread uint64_t g_chaos_memory_tls_prng_state = 0U;

/**
 * @brief Process seed; replaced by the constructor with /dev/urandom bytes.
 *
 * @details The initial value only matters for a draw made before the constructor
 * (from another object's constructor); it is mixed with the tid and a stack
 * address like any seed.
 */
uint64_t g_chaos_memory_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/* =========================================================================
 * Constructor seam
 * =========================================================================
 */

/**
 * @brief Constructor attribute of chaos_memory_init(); unit tests define it empty
 *        and drive initialisation themselves.
 */
#ifndef CHAOS_MEMORY_CONSTRUCTOR
#define CHAOS_MEMORY_CONSTRUCTOR __attribute__((constructor))
#endif

/* =========================================================================
 * Symbol resolution
 * =========================================================================
 */

/**
 * @brief Resolves @p symbol with `dlsym(RTLD_NEXT)` into the function pointer at
 *        @p target, unless it is already set.
 *
 * @details The pointer is copied with memcpy(): ISO C does not define converting
 * an object pointer (dlsym()'s void *) to a function pointer, POSIX requires the
 * representation to match. dlsym() returning NULL with dlerror() set means the
 * symbol exists in no later object; the process aborts. NULL without an error is
 * stored as is (the wrapper then uses the system call).
 *
 * @param target  Address of a function pointer variable (sizeof(void *) bytes).
 * @param symbol  Symbol name.
 */
static void chaos_memory_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    /* Only fill what is still unset, so a pointer already wired (by an earlier call,
     * or by a test harness) is never replaced. */
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

/* =========================================================================
 * Seeding
 * =========================================================================
 */

/**
 * @brief Reads 8 bytes from /dev/urandom with raw system calls.
 *
 * @details SYS_openat/SYS_read/SYS_close instead of libc: nothing allocates (an
 * allocation could call mmap() and re-enter this library during its own start-up),
 * and no other preloaded library's open()/read() wrapper (libchaos-io) sees or
 * fails the read. The reentrancy guard is held as well, so any wrapper of this
 * library reached in between passes through.
 *
 * @return The random bytes; `0x6a09e667f3bcc909 ^ getpid()` when the device
 *         cannot be opened or a short read occurs (and always on non-Linux builds).
 */
static uint64_t chaos_memory_read_urandom_seed(void)
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

/**
 * @brief chaos_memory_read_urandom_seed() with errno preserved.
 *
 * @details The application's errno must not change because the library read
 * /dev/urandom, whether that happens in the constructor or later.
 */
static uint64_t chaos_memory_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_memory_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/* =========================================================================
 * Real function lookup and constructor
 * =========================================================================
 */

/**
 * @brief Run-once state of the real function lookup.
 *
 * @details chaos_once(), not pthread_once(): before glibc 2.34 the latter lives in
 * libpthread, which programs such as `cat` and `sh` do not load.
 */
static volatile chaos_once_t g_chaos_memory_symbols_once = CHAOS_ONCE_INIT;

/**
 * @brief Resolves all five real functions. Runs once, through
 *        chaos_memory_ensure_symbols().
 *
 * @details Calls no wrapper of this library directly. dlsym() walks the link map
 * already loaded and opens no file, but it may allocate; an mmap() that this
 * causes re-enters the wrapper, which finds its pointer NULL and uses the system
 * call (chaos_once() returns 0 to the nested call instead of deadlocking).
 */
static void chaos_memory_resolve_all_symbols(void)
{
    chaos_memory_resolve_symbol(&g_chaos_memory_real_mmap, "mmap");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_munmap, "munmap");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_mprotect, "mprotect");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_madvise, "madvise");
    chaos_memory_resolve_symbol(&g_chaos_memory_real_posix_madvise, "posix_madvise");
}

void chaos_memory_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_memory_symbols_once, chaos_memory_resolve_all_symbols);
}

/**
 * @brief Library constructor.
 *
 * @details Runs once per process image, with default priority, in the order the
 * dynamic linker runs initialisers (wrappers may have run before; see the file
 * header). Steps:
 *  1. Resolve the real functions (no-op if a wrapper already did).
 *  2. Read the process seed from /dev/urandom and seed the main thread's PRNG.
 *  3. Reset the rule state (both snapshots empty, stamp UNKNOWN), register the
 *     fork child handler and find the vDSO clock.
 *  4. Load the rule file now, so the status file reports a bad file at start-up.
 *
 * `static`: kept out of the dynamic symbol table; the attribute alone makes the
 * linker call it.
 */
CHAOS_MEMORY_CONSTRUCTOR
static void chaos_memory_init(void)
{
    chaos_memory_ensure_symbols();
    g_chaos_memory_process_seed = chaos_memory_read_seed_material();
    chaos_memory_prng_seed_thread(g_chaos_memory_process_seed);
    chaos_memory_config_init();
    /* Load the rules now so a bad rule file is reported at start-up. */
    (void)chaos_memory_config_prepare();
}
