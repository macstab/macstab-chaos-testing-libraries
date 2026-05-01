/**
 * @file chaos_memory.c
 * @brief Module initialisation: symbol resolution, entropy collection, and
 *        subsystem bootstrap for libchaos-memory.
 *
 * @details
 * This translation unit owns three things:
 *
 *  1. **Global storage** for all process-wide and thread-local state declared
 *     as @c extern in chaos_memory_internal.h: the six real-symbol function
 *     pointers, the TLS reentrancy guard, the TLS PRNG state, and the
 *     process-wide seed.
 *
 *  2. **chaos_memory_resolve_symbol()** — a thin wrapper around
 *     dlsym(RTLD_NEXT) that populates a function pointer slot and calls
 *     abort() on hard resolution failure (NULL with a pending dlerror).
 *
 *  3. **chaos_memory_init()** — the GCC constructor that runs before main()
 *     (and before most of the application's own constructors, depending on
 *     link order).  It resolves all six real symbols, reads entropy, seeds
 *     the main-thread PRNG, and initialises the config subsystem.
 *
 * @par Invariants
 * After chaos_memory_init() returns:
 *  - g_chaos_memory_real_mmap, _munmap, _mprotect, _madvise are non-NULL.
 *  - g_chaos_memory_real_nanosleep and _usleep may be NULL only if libc does
 *    not export those symbols (practically never); the latency action handles
 *    NULL gracefully.
 *  - g_chaos_memory_process_seed is non-zero.
 *  - The main thread's TLS PRNG is seeded.
 *  - The config subsystem is in a clean, zero-rule state ready for its first
 *    lazy reload.
 *
 * @par Reentrancy during initialisation
 * chaos_memory_read_seed_material() reads /dev/urandom using raw Linux
 * syscalls (SYS_openat, SYS_read, SYS_close) rather than libc wrappers.
 * This avoids re-entering the mmap hook through glibc's internal FILE
 * allocation or fd-table expansion paths, which can call mmap before the
 * real-symbol pointers have been populated.  The reentrancy guard is set
 * around the syscall block as an additional safety measure even though the
 * hook wrappers in chaos_memory_hooks.c would fall through to the real symbol
 * at that point (since g_chaos_memory_real_mmap is NULL until resolve is
 * complete — hooks check for NULL and abort, so the guard prevents any
 * re-entrant call from reaching that check).
 *
 * @par Stability
 * Internal — do not depend on the symbols or layout of this file from outside
 * the memory chaos module.
 */

#include "chaos_memory_config.h"
#include "chaos_memory_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Global storage for extern-declared state
 * =========================================================================
 * Defined here; declared extern in chaos_memory_internal.h.
 * All NULL / zero until chaos_memory_init() runs.
 */

/** @brief Real mmap(2) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_mmap_fn g_chaos_memory_real_mmap = NULL;

/** @brief Real munmap(2) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_munmap_fn g_chaos_memory_real_munmap = NULL;

/** @brief Real mprotect(2) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_mprotect_fn g_chaos_memory_real_mprotect = NULL;

/** @brief Real madvise(2) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_madvise_fn g_chaos_memory_real_madvise = NULL;

/** @brief Real nanosleep(2) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_nanosleep_fn g_chaos_memory_real_nanosleep = NULL;

/** @brief Real usleep(3) function pointer, resolved via RTLD_NEXT at startup. */
chaos_memory_usleep_fn g_chaos_memory_real_usleep = NULL;

/**
 * @brief Per-thread reentrancy guard.
 *
 * Non-zero while this thread is executing inside any chaos-library internal
 * path.  Zero-initialised by the C runtime at thread creation; never requires
 * explicit reset across calls because enter/leave always restore the previous
 * value.
 */
__thread int g_chaos_memory_tls_guard = 0;

/**
 * @brief Per-thread xorshift64* PRNG state.
 *
 * Zero is the uninitialised sentinel.  chaos_memory_prng_ensure_seeded()
 * lazily populates this on first use without I/O or heap allocation.
 */
__thread uint64_t g_chaos_memory_tls_prng_state = 0U;

/**
 * @brief Process-wide entropy seed shared across threads.
 *
 * Initialised from /dev/urandom in chaos_memory_init() via raw syscalls.
 * Each thread's TLS PRNG derives its own seed by XOR-ing this value with
 * the kernel TID and a stack address, ensuring per-thread independence.
 * The default value (0x2545f4914f6cdd1d, a Weyl constant) is a safe fallback
 * if the constructor has somehow not yet run — it produces a non-zero seed
 * that will be mixed further by chaos_memory_prng_mix().
 */
uint64_t g_chaos_memory_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/* =========================================================================
 * Constructor macro override for testing
 * =========================================================================
 */

/**
 * @brief GCC constructor attribute, overridable at compile time for unit tests.
 *
 * @details
 * Test harnesses that link chaos_memory.c directly can define
 * CHAOS_MEMORY_CONSTRUCTOR to an empty string (or a different priority) to
 * suppress or reorder the automatic constructor call and drive initialisation
 * explicitly.
 */
#ifndef CHAOS_MEMORY_CONSTRUCTOR
#define CHAOS_MEMORY_CONSTRUCTOR __attribute__((constructor))
#endif

/* =========================================================================
 * Symbol resolution
 * =========================================================================
 */

/**
 * @brief Resolve a single libc symbol via RTLD_NEXT and store it in a
 *        function pointer slot.
 *
 * @details
 * Uses memcpy() to transfer the void* returned by dlsym() into the typed
 * function-pointer target, avoiding the ISO C restriction on casting between
 * object and function pointers (technically undefined behaviour, but the
 * only portable approach with POSIX dlsym).
 *
 * Calls abort() if dlsym returns NULL and dlerror() is non-NULL, which
 * indicates a hard link failure (symbol genuinely absent from any loaded
 * library).  A NULL result with a NULL dlerror is treated as "symbol
 * resolved to address zero", which is legitimate for optional symbols but
 * practically never occurs for mmap/munmap/mprotect/madvise.
 *
 * @param target  Pointer to the function-pointer variable to populate.
 *                Must point to a storage of exactly sizeof(void*) bytes.
 * @param symbol  Null-terminated name of the symbol to resolve.
 */
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

/* =========================================================================
 * Entropy collection
 * =========================================================================
 */

/**
 * @brief Read 8 bytes of entropy from /dev/urandom using raw Linux syscalls.
 *
 * @details
 * This function deliberately avoids all libc I/O wrappers to prevent
 * reentrancy through the mmap hook during the constructor.  Specifically:
 *
 *  - glibc's open(2) wrapper may call malloc() for the FILE* structure or the
 *    fd table, and large allocations go through mmap(MAP_ANONYMOUS).  At
 *    constructor time, g_chaos_memory_real_mmap is not yet resolved; a
 *    re-entrant mmap call would hit the hook and find a NULL real pointer.
 *  - Even if the real pointer were already set, a recursive mmap call during
 *    seeding would invoke the hook, the hook would call config_prepare(), and
 *    config_prepare() calls stat() — creating a deep reentrant chain before
 *    the module is fully initialised.
 *
 * The reentrancy guard is set around the entire syscall block as a belt-and-
 * suspenders measure; any intercepted symbol that is somehow called during
 * this window will observe the guard and bypass fault injection.
 *
 * @par Fallback behaviour
 * If SYS_openat fails (e.g., in a container without /dev/urandom), a
 * deterministic but process-unique fallback seed derived from a fixed
 * constant XOR'd with getpid() is returned.  Fault injection remains
 * probabilistic but reproducible for the same PID.
 *
 * @return 64-bit entropy value, or a deterministic fallback on failure.
 *         Never returns zero (the Weyl constant fallback is non-zero, and
 *         getpid() > 0 on Linux so the XOR is non-zero unless pid == constant,
 *         which is astronomically unlikely).
 *
 * @note Linux-only.  On other platforms the function body is empty and the
 *       fallback is always returned.
 */
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

/* =========================================================================
 * Module constructor
 * =========================================================================
 */

/**
 * @brief Module constructor: resolve real symbols, seed entropy, initialise
 *        the config subsystem.
 *
 * @details
 * Executed by the dynamic linker before main() (priority determined by link
 * order; no explicit priority attribute is used, so this runs with default
 * priority after all higher-priority constructors).  It is safe to call
 * only once per process; the dynamic linker guarantees this for shared-library
 * constructors.
 *
 * Sequence:
 *  1. Resolve the six real libc symbols via RTLD_NEXT.  Failure of any
 *     mandatory symbol (mmap, munmap, mprotect, madvise) calls abort().
 *  2. Collect entropy from /dev/urandom via raw syscalls (see
 *     chaos_memory_read_seed_material() for the reentrancy rationale).
 *  3. Seed the main thread's TLS PRNG immediately so that the first
 *     intercepted call on the main thread does not need the lazy seeding
 *     path.
 *  4. Initialise the config subsystem to a clean zero-rule state.  The first
 *     actual config read occurs lazily on the first intercepted call that
 *     reaches chaos_memory_config_prepare().
 *
 * @note The function is declared static to prevent it from appearing in the
 *       library's symbol table.  The constructor attribute ensures it is
 *       called automatically regardless of visibility.
 */
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
