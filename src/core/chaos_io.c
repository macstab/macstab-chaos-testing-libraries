/**
 * @file chaos_io.c
 * @brief libchaos-io process state: real-function table, symbol resolution, PRNG seed,
 *        constructor, and the shared descriptor-to-rule lookup.
 *
 * @details
 * Responsibilities:
 * - Storage for the `g_chaos_io_real_*` real-function pointers and the thread-local
 *   re-entrancy guard and PRNG state declared in chaos_io_internal.h.
 * - Symbol resolution, run exactly once through chaos_io_ensure_symbols() from the
 *   constructor or from whichever wrapper runs first.
 * - The constructor chaos_io_init(): resolve, seed, initialise the rule cache, load the
 *   rule file once (so a bad file is reported in the status file at start-up), and reset
 *   the fd cache.
 * - chaos_io_match_fd_rule(): the lookup every descriptor-based wrapper uses.
 *
 * The wrappers (`CHAOS_IO_EXPORT` symbols) live in `wrappers/`: chaos_io_open.c,
 * chaos_io_rw.c, chaos_io_sync.c, chaos_io_stdio.c and chaos_io_fsops.c. This file exports
 * nothing.
 *
 * @par Invariants
 * - A required real function that `dlsym(RTLD_NEXT)` reports as missing aborts the
 *   process at resolution: without it the library could not even pass calls through.
 * - Optional real functions (`close_range`, `closefrom`, `renameat2`, `__vfprintf_chk`,
 *   `__fread_chk`, `__fgets_chk`) stay NULL when libc lacks them; each wrapper handles
 *   NULL itself (ENOSYS or an own fallback).
 * - A real-function pointer can still be NULL while resolution is in progress (a wrapper
 *   re-entered from inside `dlsym`, chaos_once.h); wrappers then issue the raw system call
 *   (CHAOS_IO_SYSCALL) or fail with ENOSYS.
 * - The process seed is written in the constructor before the constructor thread's PRNG
 *   is seeded; other threads seed lazily from it.
 */

/* Test seam: CHAOS_IO_CONSTRUCTOR may be predefined to call chaos_io_init() by hand. */

#include "chaos_once.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <dlfcn.h>
#include <errno.h>
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
chaos_io_dup2_fn g_chaos_io_real_dup2 = NULL;
chaos_io_close_range_fn g_chaos_io_real_close_range = NULL;
chaos_io_closedir_fn g_chaos_io_real_closedir = NULL;
chaos_io_pclose_fn g_chaos_io_real_pclose = NULL;
chaos_io_closefrom_fn g_chaos_io_real_closefrom = NULL;
chaos_io_sync_fn g_chaos_io_real_fsync = NULL;
chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL;
chaos_io_pread_fn g_chaos_io_real_pread = NULL;
chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL;
chaos_io_preadv_fn g_chaos_io_real_preadv = NULL;
chaos_io_pwritev_fn g_chaos_io_real_pwritev = NULL;
chaos_io_ftruncate_fn g_chaos_io_real_ftruncate = NULL;
chaos_io_unlinkat_fn g_chaos_io_real_unlinkat = NULL;
chaos_io_truncate_fn g_chaos_io_real_truncate = NULL;
chaos_io_fopen_fn g_chaos_io_real_fopen = NULL;
chaos_io_fclose_fn g_chaos_io_real_fclose = NULL;
chaos_io_fread_fn g_chaos_io_real_fread = NULL;
chaos_io_fwrite_fn g_chaos_io_real_fwrite = NULL;
chaos_io_fgets_fn g_chaos_io_real_fgets = NULL;
chaos_io_fputs_fn g_chaos_io_real_fputs = NULL;
chaos_io_fgetc_fn g_chaos_io_real_fgetc = NULL;
chaos_io_fgetc_fn g_chaos_io_real_getc = NULL;
chaos_io_fputc_fn g_chaos_io_real_fputc = NULL;
chaos_io_fputc_fn g_chaos_io_real_putc = NULL;
chaos_io_getdelim_fn g_chaos_io_real_getdelim = NULL;
chaos_io_vfprintf_fn g_chaos_io_real_vfprintf = NULL;
chaos_io_fflush_fn g_chaos_io_real_fflush = NULL;
chaos_io_vfprintf_chk_fn g_chaos_io_real_vfprintf_chk = NULL;
chaos_io_fread_chk_fn g_chaos_io_real_fread_chk = NULL;
chaos_io_fgets_chk_fn g_chaos_io_real_fgets_chk = NULL;
chaos_io_freopen_fn g_chaos_io_real_freopen = NULL;
chaos_io_renameat2_fn g_chaos_io_real_renameat2 = NULL;
chaos_io_posix_fallocate_fn g_chaos_io_real_posix_fallocate = NULL;
chaos_io_renameat_fn g_chaos_io_real_renameat = NULL;
#ifdef __linux__
chaos_io_fallocate_fn g_chaos_io_real_fallocate = NULL;
chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL;
chaos_io_dup3_fn g_chaos_io_real_dup3 = NULL;
chaos_io_copy_file_range_fn g_chaos_io_real_copy_file_range = NULL;
#endif

/* --- Thread-local guard and PRNG state ------------------------------------------- */

__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;

/**
 * @brief Process-wide entropy base; replaced in the constructor by 64 bits from
 *        `/dev/urandom` (or a pid-derived value). The initialiser is a non-zero placeholder.
 */
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/* --- Constructor macro ------------------------------------------------------------ */

#ifndef CHAOS_IO_CONSTRUCTOR
/**
 * @brief Attribute that makes chaos_io_init() an ELF constructor.
 *
 * @details Unit tests predefine it (typically empty) to run chaos_io_init() under their
 * own control instead of at load time.
 */
#define CHAOS_IO_CONSTRUCTOR __attribute__((constructor))
#endif

/* --- Internal helpers ------------------------------------------------------------ */

/**
 * @brief Resolves required real function @p symbol with `dlsym(RTLD_NEXT)` into @p target.
 *
 * @details Fail-closed: when dlsym reports an error (dlerror() non-NULL) the process
 * aborts, because a library that cannot reach the real function cannot even pass the
 * call through; a later NULL call would crash less legibly. A NULL result without a
 * dlerror() (a symbol whose value is genuinely NULL) is stored as is.
 *
 * The result is copied with memcpy because ISO C99 defines no conversion from `void *`
 * to a function pointer; `-pedantic -Werror` rejects the cast. Overwrites @p target
 * unconditionally.
 *
 * @param[out] target  Typed function-pointer storage, e.g. `&g_chaos_io_real_read`.
 * @param[in]  symbol  Symbol name.
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
 * @brief Resolves a real function that some C libraries lack; a missing symbol leaves
 *        @p target NULL instead of aborting.
 *
 * @details The wrapper then behaves as that libc would: `close_range` reports ENOSYS,
 * `closefrom` falls back to the close_range system call. Example: `close_range` and
 * `closefrom` arrived in glibc 2.34, while release builds link against glibc 2.31
 * (`gcc:10` image) and musl lacks both. A pointer that is already set (by a test) is
 * left alone, and the dlerror() state is cleared so no stale error leaks to the caller.
 */
static void chaos_io_resolve_optional_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    /* Unlike chaos_io_resolve_symbol(), never replace a pointer that is already set:
     * unit tests wire stubs before resolution runs. */
    (void)memcpy(&current, target, sizeof(current));
    if (current != NULL)
    {
        return;
    }
    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    (void)dlerror();
    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief Reads 64 bits of seed material from `/dev/urandom` with raw system calls.
 *
 * @details Raw `openat`/`read`/`close` system calls, inside the re-entrancy guard, so
 * neither this library's wrappers nor another preloaded library sees or faults the read.
 * The descriptor is opened without O_CLOEXEC; it is closed again before returning.
 *
 * Fallback when `/dev/urandom` cannot be opened or returns fewer than 8 bytes (e.g. a
 * sandbox without /dev): the SHA-256 IV word 0x6a09e667f3bcc909 XOR the pid. That is
 * distinct per process but predictable, which is acceptable: the PRNG only samples rule
 * probabilities and has no security role.
 *
 * @return The seed. May modify errno; see chaos_io_read_seed_material().
 */
static uint64_t chaos_io_read_urandom_seed(void)
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

/**
 * @brief chaos_io_read_urandom_seed() with errno preserved.
 *
 * @details Called from the constructor; a failed open of `/dev/urandom` must not leave
 * an errno behind for the program's start-up code to see.
 */
static uint64_t chaos_io_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_io_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/* --- Shared wrapper helper ------------------------------------------------------- */

/**
 * @brief Finds the rule for @p operation on descriptor @p fd: refresh rules, resolve the
 *        descriptor's path, select a rule.
 *
 * @details One implementation so every descriptor-based wrapper applies the same order
 * and the same exclusions. Descriptors 0-2 are never matched: they are shared with the
 * parent and usually name a terminal, pipe or socket (`pipe:[N]`, `socket:[N]`), not a
 * file a path rule targets. The rule-file refresh comes first so that an empty rule set
 * returns before any `/proc/self/fd` readlink. Paths that chaos_io_is_excluded_path()
 * rejects never match. errno is preserved by every step.
 *
 * @param[in]  fd         Descriptor; <= 2 returns 0 at once.
 * @param[in]  operation  Operation to look up.
 * @param[out] rule       Receives a copy of the matching rule; NULL returns 0.
 * @return Non-zero when a rule matched (whether it fires is decided later by
 *         chaos_io_rule_should_trigger()); 0 to pass the call through.
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

/** @copydoc chaos_io_match_fd_rule_sized */
int chaos_io_match_fd_rule_sized(
    int fd, chaos_io_operation_t operation, uint64_t size, chaos_io_rule_t *rule
)
{
    if (!chaos_io_match_fd_rule(fd, operation, rule))
    {
        return 0;
    }
    rule->call_size = size;
    return 1;
}

/* --- Symbol resolution ------------------------------------------------------------ */

/**
 * @brief Run-once control of symbol resolution.
 *
 * @details chaos_once() rather than a `volatile int` flag: the flag is read by every
 * wrapper on every thread, and a plain flag orders nothing. On a weakly ordered CPU
 * (aarch64) a second thread could see the flag set before some pointer stores, and call
 * through NULL. chaos_once() pairs a release store with acquire loads, so the complete
 * table is visible to every caller that sees "done". Not `pthread_once()`: see
 * chaos_once.h (libpthread before glibc 2.34).
 */
static volatile chaos_once_t g_chaos_io_symbols_once = CHAOS_ONCE_INIT;

/**
 * @brief Resolves every real function of the library; run once via chaos_io_ensure_symbols().
 *
 * @details `dlsym` may allocate, and a preloaded allocator may then call back into a
 * wrapper of this library on the same thread. That nested chaos_once() returns 0 instead
 * of deadlocking; the wrapper finds its pointer still NULL and uses the raw system call
 * (CHAOS_IO_SYSCALL) or fails with ENOSYS. Pointers are assigned one by one, so such a
 * nested caller may see some already set.
 */
static void chaos_io_resolve_all_symbols(void)
{
    chaos_io_resolve_symbol(&g_chaos_io_real_read, "read");
    chaos_io_resolve_symbol(&g_chaos_io_real_write, "write");
    chaos_io_resolve_symbol(&g_chaos_io_real_readv, "readv");
    chaos_io_resolve_symbol(&g_chaos_io_real_writev, "writev");
    chaos_io_resolve_symbol(&g_chaos_io_real_open, "open");
    chaos_io_resolve_symbol(&g_chaos_io_real_openat, "openat");
    chaos_io_resolve_symbol(&g_chaos_io_real_close, "close");
    chaos_io_resolve_symbol(&g_chaos_io_real_dup2, "dup2");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_close_range, "close_range");
    chaos_io_resolve_symbol(&g_chaos_io_real_closedir, "closedir");
    chaos_io_resolve_symbol(&g_chaos_io_real_pclose, "pclose");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_closefrom, "closefrom");
    chaos_io_resolve_symbol(&g_chaos_io_real_fsync, "fsync");
    chaos_io_resolve_symbol(&g_chaos_io_real_fdatasync, "fdatasync");
    chaos_io_resolve_symbol(&g_chaos_io_real_pread, "pread");
    chaos_io_resolve_symbol(&g_chaos_io_real_pwrite, "pwrite");
    chaos_io_resolve_symbol(&g_chaos_io_real_preadv, "preadv");
    chaos_io_resolve_symbol(&g_chaos_io_real_pwritev, "pwritev");
    chaos_io_resolve_symbol(&g_chaos_io_real_ftruncate, "ftruncate");
    chaos_io_resolve_symbol(&g_chaos_io_real_unlinkat, "unlinkat");
    chaos_io_resolve_symbol(&g_chaos_io_real_truncate, "truncate");
    chaos_io_resolve_symbol(&g_chaos_io_real_fopen, "fopen");
    chaos_io_resolve_symbol(&g_chaos_io_real_freopen, "freopen");
    chaos_io_resolve_symbol(&g_chaos_io_real_fclose, "fclose");
    chaos_io_resolve_symbol(&g_chaos_io_real_fread, "fread");
    chaos_io_resolve_symbol(&g_chaos_io_real_fwrite, "fwrite");
    chaos_io_resolve_symbol(&g_chaos_io_real_fgets, "fgets");
    chaos_io_resolve_symbol(&g_chaos_io_real_fputs, "fputs");
    chaos_io_resolve_symbol(&g_chaos_io_real_fgetc, "fgetc");
    chaos_io_resolve_symbol(&g_chaos_io_real_getc, "getc");
    chaos_io_resolve_symbol(&g_chaos_io_real_fputc, "fputc");
    chaos_io_resolve_symbol(&g_chaos_io_real_putc, "putc");
    chaos_io_resolve_symbol(&g_chaos_io_real_getdelim, "getdelim");
    chaos_io_resolve_symbol(&g_chaos_io_real_vfprintf, "vfprintf");
    chaos_io_resolve_symbol(&g_chaos_io_real_fflush, "fflush");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_vfprintf_chk, "__vfprintf_chk");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_fread_chk, "__fread_chk");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_fgets_chk, "__fgets_chk");
    chaos_io_resolve_symbol(&g_chaos_io_real_posix_fallocate, "posix_fallocate");
    chaos_io_resolve_optional_symbol(&g_chaos_io_real_renameat2, "renameat2");
    chaos_io_resolve_symbol(&g_chaos_io_real_renameat, "renameat");
#ifdef __linux__
    chaos_io_resolve_symbol(&g_chaos_io_real_fallocate, "fallocate");
    chaos_io_resolve_symbol(&g_chaos_io_real_sendfile, "sendfile");
    chaos_io_resolve_symbol(&g_chaos_io_real_dup3, "dup3");
    chaos_io_resolve_symbol(&g_chaos_io_real_copy_file_range, "copy_file_range");
#endif
}

/** @copydoc chaos_io_ensure_symbols */
void chaos_io_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_io_symbols_once, chaos_io_resolve_all_symbols);
}

/* --- Library constructor --------------------------------------------------------- */

/**
 * @brief ELF constructor of libchaos-io.
 *
 * @details Order and why:
 * 1. chaos_io_ensure_symbols(): real functions first, since everything after may call
 *    through them. A wrapper that ran earlier (another object's constructor) may already
 *    have done it.
 * 2. Process seed, then the constructor thread's PRNG from it.
 * 3. chaos_io_config_init(): empty rule set, cached mtime CHAOS_IO_MTIME_UNKNOWN.
 * 4. chaos_io_config_prepare(): load the rule file now, so a rejected file is reported
 *    in the status file at start-up rather than at the first matching call.
 * 5. chaos_io_fdcache_reset(): outdate every fd-cache slot, so nothing cached before the
 *    constructor (or by an earlier init in a unit test) survives.
 */
CHAOS_IO_CONSTRUCTOR
static void chaos_io_init(void)
{
    chaos_io_ensure_symbols();

    g_chaos_io_process_seed = chaos_io_read_seed_material();
    chaos_io_prng_seed_thread(g_chaos_io_process_seed);
    chaos_io_config_init();
    /* Load the rules now so a bad rule file is reported at start-up. */
    (void)chaos_io_config_prepare();
    chaos_io_fdcache_reset();
}
