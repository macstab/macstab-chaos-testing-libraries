/**
 * @file chaos_io.c
 * @brief Process-global state, symbol resolution, and shared wrapper helpers.
 *
 * @details
 * This translation unit owns three responsibilities:
 *
 * 1. **Storage definitions** for the `g_chaos_io_real_*` function-pointer
 *    globals and the TLS PRNG / guard variables declared in
 *    `chaos_io_internal.h`.
 *
 * 2. **Library constructor** (`chaos_io_init`): called by the dynamic linker
 *    immediately after the shared object is mapped.  It resolves every
 *    downstream libc symbol via `dlsym(RTLD_NEXT)`, seeds the PRNG, and
 *    resets config and fd-cache state.
 *
 * 3. **`chaos_io_match_fd_rule()`**: the single, canonical lookup entry point
 *    shared by all descriptor-based wrappers (`read`, `write`, `close`,
 *    `fsync`, etc.).
 *
 * **Invariants maintained by this file:**
 * - After `chaos_io_init()` returns, every `g_chaos_io_real_*` pointer is
 *   non-NULL.  Any NULL at runtime indicates a constructor ordering bug.
 * - `g_chaos_io_process_seed` is set to a non-trivial value before any
 *   thread's per-thread PRNG is seeded.
 * - `chaos_io_config_init()` and `chaos_io_fdcache_reset()` are called after
 *   the symbol resolution and seed steps, so neither subsystem can observe
 *   a partially initialized library.
 *
 * **Module boundary:** this file does not contain any exported (interposed)
 * symbols.  All `CHAOS_IO_EXPORT` symbols live in the `wrappers/` units.
 */

/*
 * Shared runtime state for libchaos-io.
 *
 * The exported wrappers live in smaller companion translation units:
 *
 * - `wrappers/chaos_io_open.c` for `open()` and `openat()`
 * - `wrappers/chaos_io_rw.c` for `read()` / `write()` style operations
 * - `wrappers/chaos_io_sync.c` for `close()` and sync boundaries
 *
 * This file keeps only the process-global state and helper paths that are
 * genuinely shared across those wrapper families.
 */

#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

/* --- Storage for resolved libc function pointers --------------------------------- */

chaos_io_read_fn g_chaos_io_real_read = NULL;
chaos_io_write_fn g_chaos_io_real_write = NULL;
chaos_io_readv_fn g_chaos_io_real_readv = NULL;
chaos_io_writev_fn g_chaos_io_real_writev = NULL;
chaos_io_open_fn g_chaos_io_real_open = NULL;
chaos_io_openat_fn g_chaos_io_real_openat = NULL;
chaos_io_close_fn g_chaos_io_real_close = NULL;
chaos_io_sync_fn g_chaos_io_real_fsync = NULL;
chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL;
chaos_io_pread_fn g_chaos_io_real_pread = NULL;
chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL;
chaos_io_preadv_fn g_chaos_io_real_preadv = NULL;
chaos_io_pwritev_fn g_chaos_io_real_pwritev = NULL;
chaos_io_ftruncate_fn g_chaos_io_real_ftruncate = NULL;
chaos_io_unlinkat_fn g_chaos_io_real_unlinkat = NULL;
chaos_io_renameat_fn g_chaos_io_real_renameat = NULL;
#ifdef __linux__
chaos_io_fallocate_fn g_chaos_io_real_fallocate = NULL;
chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL;
chaos_io_copy_file_range_fn g_chaos_io_real_copy_file_range = NULL;
#endif

/* --- Thread-local guard and PRNG state ------------------------------------------- */

__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;

/** @brief Process-wide entropy base; set from `/dev/urandom` during construction. */
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/* --- Constructor macro ------------------------------------------------------------ */

#ifndef CHAOS_IO_CONSTRUCTOR
/**
 * @brief Marks a function as a shared-library constructor.
 *
 * @details Overridable so unit tests can call `chaos_io_init` directly
 * without triggering duplicate constructor execution under test harnesses
 * that define their own `CHAOS_IO_CONSTRUCTOR`.
 */
#define CHAOS_IO_CONSTRUCTOR __attribute__((constructor))
#endif

/* --- Internal helpers ------------------------------------------------------------ */

/**
 * @brief Resolves one downstream libc symbol and stores it in typed storage.
 *
 * @details The `memcpy()` step is deliberate. In strict C, function-pointer and object-
 * pointer conversions are awkward. Copying the raw bytes from the `void *`
 * result into the function-pointer storage avoids depending on a compiler-
 * specific cast convention while remaining tiny and explicit.
 *
 * Aborts on resolution failure rather than returning an error, because a
 * missing symbol means the library cannot provide its core guarantee and
 * silent failure would produce mysterious crashes later.
 *
 * @param[out] target   Pointer to the typed storage location
 *                      (e.g. `&g_chaos_io_real_read`).  Must not be NULL.
 * @param[in]  symbol   Null-terminated name of the libc symbol to resolve.
 */
static void chaos_io_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
        abort();

    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief Obtains process-level seed material without depending on the wrapper layer.
 *
 * @details Startup needs a process-unique seed before rule evaluation begins, so this
 * helper uses raw syscalls instead of any interposed libc path.
 *
 * Using `SYS_openat` and `SYS_read` directly prevents reentrancy: the
 * wrappers are not yet fully initialized at constructor time, and calling
 * through `g_chaos_io_real_open` before it has been stored would fault.
 * Even after storage it would be surprising to depend on a wrapper during
 * the constructor's own setup sequence.
 *
 * Falls back to a deterministic constant XOR'd with the PID when
 * `/dev/urandom` is unavailable (e.g. in restricted sandbox environments).
 * The fallback is less random but still process-unique.
 *
 * @return 64 bits of entropy from `/dev/urandom`, or a PID-derived fallback.
 */
static uint64_t chaos_io_read_seed_material(void)
{
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_io_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_io_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_io_leave_internal(previous);
    }

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/* --- Shared wrapper helper ------------------------------------------------------- */

/**
 * @brief Performs the canonical fd-to-rule lookup for descriptor-based wrappers.
 *
 * @details The sequence "refresh config -> resolve fd -> select rule" stays centralized
 * here so every descriptor-based wrapper observes the same behavior.
 *
 * Descriptors 0, 1, and 2 (stdin/stdout/stderr) are always excluded because
 * they are process-wide shared resources whose paths are often synthetic
 * (e.g. `socket:[…]` or `pipe:[…]`) and cannot be meaningfully matched
 * against filesystem path rules.
 *
 * @param[in]  fd         Descriptor to resolve.  Returns 0 immediately for fd ≤ 2.
 * @param[in]  operation  Operation enum value to look up in the config.
 * @param[out] rule       Populated on a successful match.  Must not be NULL.
 * @return Non-zero when a rule matched; zero to pass through without injection.
 */
int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule)
{
    char path[CHAOS_IO_MAX_PATH];

    if (fd <= 2 || rule == NULL)
    {
        return 0;
    }
    if (!chaos_io_config_prepare())
    {
        return 0;
    }
    if (!chaos_io_fdcache_resolve(fd, path, sizeof(path)))
    {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/* --- Library constructor --------------------------------------------------------- */

/**
 * @brief Library constructor executed when the preload object is mapped.
 *
 * @details Initialization order is fixed:
 * - resolve downstream libc symbols first
 * - establish process and current-thread PRNG state second
 * - reset config and fd-cache state last
 *
 * The ordering is required for correctness:
 * 1. `g_chaos_io_real_*` pointers must be set before any helper that calls
 *    through them (including `chaos_io_config_read_file`).
 * 2. `g_chaos_io_process_seed` must be set before `chaos_io_prng_seed_thread`
 *    so the first thread's PRNG starts from real entropy.
 * 3. `chaos_io_config_init()` resets the mtime to `CHAOS_IO_MTIME_UNKNOWN`,
 *    which triggers a fresh config read on the very first wrapper call.
 * 4. `chaos_io_fdcache_reset()` clears any residual fd-cache data from a
 *    previous constructor run (relevant in tests that reload the library).
 */
CHAOS_IO_CONSTRUCTOR
static void chaos_io_init(void)
{
    chaos_io_resolve_symbol(&g_chaos_io_real_read, "read");
    chaos_io_resolve_symbol(&g_chaos_io_real_write, "write");
    chaos_io_resolve_symbol(&g_chaos_io_real_readv, "readv");
    chaos_io_resolve_symbol(&g_chaos_io_real_writev, "writev");
    chaos_io_resolve_symbol(&g_chaos_io_real_open, "open");
    chaos_io_resolve_symbol(&g_chaos_io_real_openat, "openat");
    chaos_io_resolve_symbol(&g_chaos_io_real_close, "close");
    chaos_io_resolve_symbol(&g_chaos_io_real_fsync, "fsync");
    chaos_io_resolve_symbol(&g_chaos_io_real_fdatasync, "fdatasync");
    chaos_io_resolve_symbol(&g_chaos_io_real_pread, "pread");
    chaos_io_resolve_symbol(&g_chaos_io_real_pwrite, "pwrite");
    chaos_io_resolve_symbol(&g_chaos_io_real_preadv, "preadv");
    chaos_io_resolve_symbol(&g_chaos_io_real_pwritev, "pwritev");
    chaos_io_resolve_symbol(&g_chaos_io_real_ftruncate, "ftruncate");
    chaos_io_resolve_symbol(&g_chaos_io_real_unlinkat, "unlinkat");
    chaos_io_resolve_symbol(&g_chaos_io_real_renameat, "renameat");
#ifdef __linux__
    chaos_io_resolve_symbol(&g_chaos_io_real_fallocate, "fallocate");
    chaos_io_resolve_symbol(&g_chaos_io_real_sendfile, "sendfile");
    chaos_io_resolve_symbol(&g_chaos_io_real_copy_file_range, "copy_file_range");
#endif

    g_chaos_io_process_seed = chaos_io_read_seed_material();
    chaos_io_prng_seed_thread(g_chaos_io_process_seed);
    chaos_io_config_init();
    chaos_io_fdcache_reset();
}
