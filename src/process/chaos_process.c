/**
 * @file chaos_process.c
 * @brief Library initialisation: symbol resolution, entropy seeding, and
 *        constructor bootstrapping for the libchaos-process subsystem.
 *
 * @details
 * This translation unit owns the definitions of all shared global state
 * declared as `extern` in `chaos_process_internal.h`, and contains the
 * `__attribute__((constructor))` function `chaos_process_init()` that the
 * dynamic linker runs before any application code executes.
 *
 * ## Responsibilities
 *
 *  1. **Symbol resolution** — locate the real libc implementations of every
 *     interposed function via `dlsym(RTLD_NEXT, ...)` and store them in the
 *     corresponding `g_chaos_process_real_*` function pointers.  A failure to
 *     resolve a mandatory symbol calls `abort()` to prevent silent
 *     passthrough with a NULL function pointer.
 *
 *  2. **Entropy seeding** — read 8 bytes from `/dev/urandom` using raw
 *     syscalls (bypassing our own interposed symbols) and store the result in
 *     `g_chaos_process_process_seed`.  Falls back to a XOR of a compile-time
 *     constant and the PID if the syscall fails.
 *
 *  3. **PRNG bootstrap** — immediately seed the main thread's per-thread
 *     PRNG state so that the first call to any wrapper after construction has
 *     a valid random stream.
 *
 *  4. **Config bootstrap** — call `chaos_process_config_init()` to zero all
 *     config state and set the cached mtime sentinel to `UNKNOWN` so the
 *     first hook invocation triggers a file read.
 *
 * ## Thread safety of initialisation
 *
 * The constructor runs exactly once in a single-threaded context (before
 * `main()` and before any application threads are created).  The
 * `g_chaos_process_real_*` pointers are written here and are thereafter
 * read-only; they need no locking from the hook wrappers.
 *
 * ## Re-entrancy during construction
 *
 * `chaos_process_read_seed_material()` opens `/dev/urandom` via
 * `SYS_openat`/`SYS_read`/`SYS_close` raw syscalls rather than through
 * `open()`/`read()`/`close()`.  This is necessary because at constructor
 * time the `g_chaos_process_real_*` pointers have already been populated and
 * the TLS guard protects internal calls, but using the libc wrappers would
 * invoke our own interposed symbols (which are already live in the PLT) and
 * could, depending on load order, recurse before all pointers are ready.
 * Using the syscall layer avoids this entirely.
 *
 * The `chaos_process_enter_internal()` / `chaos_process_leave_internal()`
 * bracket inside `chaos_process_read_seed_material()` is a belt-and-
 * suspenders guard for any case where the TLS guard matters during seeding.
 *
 * ## Stability
 * Private implementation — not part of the public API.
 */

#include "chaos_process_config.h"
#include "chaos_process_internal.h"

#include <dlfcn.h>
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
chaos_process_nanosleep_fn g_chaos_process_real_nanosleep = NULL;
chaos_process_usleep_fn g_chaos_process_real_usleep = NULL;

__thread int g_chaos_process_tls_guard = 0;
__thread uint64_t g_chaos_process_tls_prng_state = 0U;
uint64_t g_chaos_process_process_seed = UINT64_C(0x2545f4914f6cdd1d);
volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U};

/** @endcond */

/* -------------------------------------------------------------------------
 * Constructor guard
 * ---------------------------------------------------------------------- */

#ifndef CHAOS_PROCESS_CONSTRUCTOR
/** GCC/Clang constructor attribute — runs before main(). */
#define CHAOS_PROCESS_CONSTRUCTOR __attribute__((constructor))
#endif

/* -------------------------------------------------------------------------
 * Static helpers
 * ---------------------------------------------------------------------- */

/**
 * @brief Resolves a libc symbol via RTLD_NEXT and stores the result.
 *
 * Uses `dlsym(RTLD_NEXT, symbol)` to find the next definition of `symbol`
 * in the dynamic linker's search order (i.e. the real libc implementation
 * that lies behind this LD_PRELOAD library).
 *
 * The resolved pointer is written into `target` via `memcpy` to avoid
 * aliasing issues with casting between `void *` and function pointer types
 * (which is technically undefined behaviour in C99 though universally
 * supported by all relevant toolchains).
 *
 * @param target  Pointer to a function-pointer variable to populate.
 * @param symbol  Null-terminated symbol name to resolve.
 *
 * @note Calls `abort()` if the symbol cannot be resolved.  The library
 *       cannot operate without the real implementations; aborting early
 *       is safer than proceeding with a NULL function pointer that would
 *       cause a SIGSEGV in the wrapper at an arbitrary later time.
 */
static void chaos_process_resolve_symbol(void *target, const char *symbol)
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

#ifdef __linux__
/**
 * @brief Like `chaos_process_resolve_symbol()` but does not abort on failure.
 *
 * Used for symbols that may legitimately be absent on some libc
 * implementations.  Specifically, `execveat` is not consistently exported
 * as a public symbol by musl libc.  If the symbol is absent, `target` is
 * set to NULL and callers must guard against this.
 *
 * @param target  Pointer to a function-pointer variable to populate or NULL.
 * @param symbol  Null-terminated symbol name to attempt to resolve.
 */
static void chaos_process_try_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL)
    {
        (void)dlerror();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}
#endif

/**
 * @brief Reads 8 bytes of entropy from `/dev/urandom` using raw syscalls.
 *
 * Uses `SYS_openat`, `SYS_read`, and `SYS_close` directly rather than the
 * libc wrappers to avoid recursing through our own interposed symbols during
 * library construction.  The TLS re-entrancy guard is set for the duration
 * of the syscall sequence as an additional safeguard.
 *
 * Falls back to a compile-time constant XOR PID if:
 *  - The platform is not Linux (raw syscall layer not used there).
 *  - `SYS_openat` fails (e.g. sandboxed environment with no `/dev/urandom`).
 *  - `SYS_read` returns a short read.
 *
 * @return 64 bits of entropy for use as `g_chaos_process_process_seed`.
 */
static uint64_t chaos_process_read_seed_material(void)
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
 * @brief Library constructor: resolves symbols, seeds entropy, and
 *        bootstraps the config subsystem.
 *
 * Executed by the dynamic linker before `main()` via the
 * `__attribute__((constructor))` annotation.  Execution order relative to
 * other constructors in the same library is unspecified, but all libc
 * initialisations (and therefore all libc symbols accessible via
 * `RTLD_NEXT`) are complete before any constructor runs.
 *
 * Steps performed in order:
 *  1. Resolve all mandatory real-symbol pointers (abort on failure).
 *  2. Conditionally resolve `execveat` (Linux only; NULL is acceptable).
 *  3. Read 8 bytes from `/dev/urandom` to populate the process seed.
 *  4. Seed the main thread's per-thread PRNG from the process seed.
 *  5. Initialise the config subsystem (zeroes rules, sets mtime sentinel).
 */
CHAOS_PROCESS_CONSTRUCTOR
static void chaos_process_init(void)
{
    chaos_process_resolve_symbol(&g_chaos_process_real_pthread_create, "pthread_create");
    chaos_process_resolve_symbol(&g_chaos_process_real_fork, "fork");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawn, "posix_spawn");
    chaos_process_resolve_symbol(&g_chaos_process_real_posix_spawnp, "posix_spawnp");
    chaos_process_resolve_symbol(&g_chaos_process_real_execve, "execve");
#ifdef __linux__
    /* musl does not consistently expose execveat as a public libc symbol. */
    chaos_process_try_resolve_symbol(&g_chaos_process_real_execveat, "execveat");
#endif
    chaos_process_resolve_symbol(&g_chaos_process_real_waitpid, "waitpid");
    chaos_process_resolve_symbol(&g_chaos_process_real_nanosleep, "nanosleep");
    chaos_process_resolve_symbol(&g_chaos_process_real_usleep, "usleep");

    g_chaos_process_process_seed = chaos_process_read_seed_material();
    chaos_process_prng_seed_thread(g_chaos_process_process_seed);
    chaos_process_config_init();
}
