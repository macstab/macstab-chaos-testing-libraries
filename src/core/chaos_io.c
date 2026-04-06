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
#ifdef __linux__
chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL;
chaos_io_copy_file_range_fn g_chaos_io_real_copy_file_range = NULL;
#endif

__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_IO_CONSTRUCTOR
#define CHAOS_IO_CONSTRUCTOR __attribute__((constructor))
#endif

/*
 * Resolve one downstream libc symbol and store it in typed storage.
 *
 * The `memcpy()` step is deliberate. In strict C, function-pointer and object-
 * pointer conversions are awkward. Copying the raw bytes from the `void *`
 * result into the function-pointer storage avoids depending on a compiler-
 * specific cast convention while remaining tiny and explicit.
 */
static void chaos_io_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL) abort();

    (void)memcpy(target, &resolved, sizeof(resolved));
}

/*
 * Obtain process-level seed material without depending on the wrapper layer.
 *
 * Startup needs a process-unique seed before rule evaluation begins, so this
 * helper uses raw syscalls instead of any interposed libc path.
 */
static uint64_t chaos_io_read_seed_material(void)
{
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_io_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0) {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_io_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed)) {
            return seed;
        }
    } else {
        chaos_io_leave_internal(previous);
    }

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/*
 * Match a rule for an fd-backed operation.
 *
 * The sequence "refresh config -> resolve fd -> select rule" stays centralized
 * here so every descriptor-based wrapper observes the same behavior.
 */
int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule)
{
    char path[CHAOS_IO_MAX_PATH];

    if (fd <= 2 || rule == NULL) {
        return 0;
    }
    if (!chaos_io_config_prepare()) {
        return 0;
    }
    if (!chaos_io_fdcache_resolve(fd, path, sizeof(path))) {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/*
 * Constructor entry point executed when the preload object is loaded.
 *
 * Initialization order is fixed:
 * - resolve downstream libc symbols first
 * - establish process and current-thread PRNG state second
 * - reset config and fd-cache state last
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
#ifdef __linux__
    chaos_io_resolve_symbol(&g_chaos_io_real_sendfile, "sendfile");
    chaos_io_resolve_symbol(&g_chaos_io_real_copy_file_range, "copy_file_range");
#endif

    g_chaos_io_process_seed = chaos_io_read_seed_material();
    chaos_io_prng_seed_thread(g_chaos_io_process_seed);
    chaos_io_config_init();
    chaos_io_fdcache_reset();
}
