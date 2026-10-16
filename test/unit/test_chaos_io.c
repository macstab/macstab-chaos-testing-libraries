/**
 * @file test_chaos_io.c
 * @brief Integration-style unit tests for the IO-domain constructor, open/openat wrappers,
 *   read/write/vectored wrappers, filesystem-lifecycle operations, and positioned I/O.
 *
 * Subsystem under test: `src/core/chaos_io.c`, `src/wrappers/chaos_io_open.c`,
 *   `src/wrappers/chaos_io_rw.c`, `src/wrappers/chaos_io_fsops.c`,
 *   `src/wrappers/chaos_io_sync.c`.
 *
 * Coverage approach:
 * - The entire wrapper layer is compiled into the test binary via
 *   `test_chaos_io_harness.h`, which includes all five production source files
 *   after replacing `dlsym`, `dlerror`, `abort`, and `syscall` with test-local
 *   stubs. The harness also provides stub implementations of all config, fdcache,
 *   and actions functions so that the wrapper layer can be exercised in isolation.
 * - `chaos_test_reset_state()` (defined in the harness) must be called at the start
 *   of every test function to clear all ~100 global counters, captured arguments,
 *   and function-pointer table entries.
 * - `chaos_test_bind_real_functions()` wires the `g_chaos_io_real_*` table to the
 *   harness stubs so the full wrapper call path can be exercised without real syscalls.
 * - `chaos_test_bind_libc_functions_for_exit()` is called at the end of `main()`
 *   so the C runtime's shutdown IO (stdout/stderr flush, file descriptor close) goes
 *   through real libc functions rather than the stubs.
 *
 * Properties under test:
 * - `chaos_io_resolve_symbol()`: successful resolution wires the pointer; failure
 *   (NULL from dlsym) triggers `abort()`.
 * - `chaos_io_read_seed_material()`: full 8-byte read delivers the seed; short read
 *   and failed open both fall back to the PID-XOR seed.
 * - `chaos_io_call_real_open()` / `chaos_io_call_real_openat()`: guard held during
 *   call; mode forwarded when O_CREAT is set; guard restored to 0 after return.
 * - `chaos_io_copy_path()`, `chaos_io_join_paths()`, `chaos_io_resolve_at_path()`,
 *   `chaos_io_getcwd_path()`: NULL/zero/short-buffer inputs return 0; absolute paths
 *   pass through; relative paths are joined with the CWD or fdcache-resolved base.
 * - `chaos_io_match_fd_rule()`: gate on `config_prepare`; skip `/proc` paths; resolve
 *   via fdcache; call `config_match_loaded`; return rule on match.
 * - `chaos_io_init()`: all real-function-pointer globals wired; `config_init` called
 *   once; `fdcache_reset` called once; `process_seed` and `tls_prng_state` non-zero.
 * - `chaos_io_match_loaded_path_rule()` and `chaos_io_match_rename_rule()`: NULL
 *   guards; skip `/proc` paths; two-sided rename rule matching.
 * - `ftruncate` / `fallocate` wrappers: passthrough with guard; latency; errno injection.
 * - `unlinkat` wrapper: fdcache invalidated on success; no invalidation on failure;
 *   latency and errno effects.
 * - `renameat` wrapper: fdcache invalidated on success; rename-from and rename-to
 *   matching with latency and errno effects.
 * - `open` wrapper: guard bypass when `tls_guard == 1`; `/proc` bypass; latency;
 *   errno injection; O_CREAT mode forwarded; relative paths joined with CWD.
 * - `openat` wrapper: guard bypass; relative paths resolved via CWD or fdcache;
 *   non-FDCWD dirfd path; errno and mode forwarding; fdcache_resolve call count.
 * - `read` / `write` wrappers: passthrough with guard; corrupt, torn, latency, errno.
 * - `readv` / `writev` wrappers: passthrough with guard; corrupt, torn, latency, errno;
 *   zero-length iovec TORN fallback.
 * - Vectored helpers: `chaos_io_iovec_total_bytes()` overflow and NULL guards;
 *   `chaos_io_trim_iovecs()` clip and NULL guards;
 *   `chaos_io_build_torn_iovecs()` zero count and excess count guards;
 *   `chaos_io_corrupt_iovecs()` NULL/zero guards; single-segment PRNG routing.
 * - Linux `sendfile` / `copy_file_range` wrappers: guard bypass; torn, latency, errno.
 * - `preadv` / `pwritev` wrappers: passthrough; corrupt, torn, latency, errno; offset
 *   forwarded; zero-iovec TORN fallback.
 * - `close` wrapper: fdcache invalidated on success; no invalidation on failure; errno.
 * - `fsync` / `fdatasync` wrappers: passthrough; latency; errno.
 * - `pread` / `pwrite` wrappers: guard bypass; corrupt, torn, latency, errno; offset
 *   forwarded.
 *
 * What is NOT tested here:
 * - Concurrent access to the TLS guard from multiple threads.
 * - Real OS-level partial read/write or EINTR retry semantics.
 * - Config hot-reload under genuine filesystem mtime changes.
 * - LD_PRELOAD interposition via the dynamic linker (covered by integration tests).
 */

#include "../support/test_chaos_io_harness.h"

#include <dirent.h>
#include <sys/resource.h>

/**
 * @brief Invariant: `chaos_io_resolve_symbol()` wires a pointer and `chaos_io_read_seed_material()`
 *   returns the seeded value or a PID-based fallback.
 *
 * Triggering conditions:
 * - `chaos_io_resolve_symbol(&resolved_read, "read")` with a functioning dlsym stub.
 * - `chaos_io_resolve_symbol()` with `g_dlsym_fail_symbol = "read"` and `g_abort_expected = 1`.
 * - `chaos_io_read_seed_material()` with successful open+full read (`g_sys_read_result ==
 * sizeof(uint64_t)`).
 * - `chaos_io_read_seed_material()` with a short read (`g_sys_read_result == 1`).
 * - `chaos_io_read_seed_material()` with a failed open (`g_sys_open_result == -1`).
 *
 * Expected observable behaviour:
 * - Successful resolve: `resolved_read == chaos_test_real_read_impl`.
 * - Failed resolve: `longjmp` transfers out of `setjmp` block; `g_abort_called == 1`.
 * - Full seed read: `chaos_io_read_seed_material() == 0x0123456789abcdef`; syscall
 *   counts each equal 1; `g_chaos_io_tls_guard == 0` after return.
 * - Short read: returns `0x6a09e667f3bcc909 XOR getpid()`; close syscall still issued.
 * - Failed open: returns `0x6a09e667f3bcc909 XOR getpid()`; no read or close syscall.
 */
static void test_resolve_symbol_and_seed_material(void)
{
    chaos_io_read_fn resolved_read = NULL;

    chaos_test_reset_state();
    chaos_io_resolve_symbol(&resolved_read, "read");
    assert(resolved_read == chaos_test_real_read_impl);

    chaos_test_reset_state();
    g_dlsym_fail_symbol = "read";
    g_abort_expected = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_io_resolve_symbol(&resolved_read, "read");
        assert(0);
    }
    assert(g_abort_called == 1);

    chaos_test_reset_state();
    g_sys_open_result = 9;
    g_sys_read_result = (long)sizeof(uint64_t);
    assert(chaos_io_read_seed_material() == UINT64_C(0x0123456789abcdef));
    assert(g_sys_open_calls == 1);
    assert(g_sys_read_calls == 1);
    assert(g_sys_close_calls == 1);
    assert(g_chaos_io_tls_guard == 0);

    chaos_test_reset_state();
    g_sys_open_result = 9;
    g_sys_read_result = 1;
    assert(chaos_io_read_seed_material() == (UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid()));
    assert(g_sys_close_calls == 1);

    chaos_test_reset_state();
    assert(chaos_io_read_seed_material() == (UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid()));
}

/**
 * @brief Invariant: `chaos_io_call_real_open()`, `chaos_io_call_real_openat()`, and path-resolution
 *   helpers operate correctly; `chaos_io_match_fd_rule()` gates on config and fdcache state.
 *
 * Triggering conditions:
 * - `chaos_io_call_real_open()` with and without O_CREAT to verify mode forwarding and guard state.
 * - `chaos_io_call_real_openat()` with AT_FDCWD and a concrete dirfd, with and without O_CREAT.
 * - `chaos_io_copy_path()`, `chaos_io_join_paths()`, `chaos_io_getcwd_path()`,
 *   `chaos_io_resolve_at_path()` with NULL, zero-length, buffer-too-short, and valid inputs.
 * - `chaos_io_match_fd_rule()` with `config_prepare == 0`; with `fdcache_resolve == 0`;
 *   with `config_match_loaded == 0`; and with a successful match.
 *
 * Expected observable behaviour:
 * - `call_real_open`: `g_real_open_guard == 1` during the call; `g_chaos_io_tls_guard == 0`
 *   after return; mode captured only when O_CREAT is set.
 * - `call_real_openat`: `g_real_openat_guard == 1`; dirfd forwarded; mode captured for O_CREAT.
 * - `copy_path(NULL, ...)`, `copy_path(..., 0, ...)`, `copy_path(..., NULL)` → 0.
 * - `copy_path(..., 4, "/tmp/path")` → 0 (buffer too short including NUL).
 * - `resolve_at_path(AT_FDCWD, "/tmp/absolute.bin", ...)` → 1, path unchanged.
 * - `join_paths(NULL, ...)`, `join_paths(..., "", ...)`, `join_paths(..., ..., "")` → 0.
 * - `join_paths(..., 4, "/tmp", "child.bin")` → 0 (combined path too long).
 * - `resolve_at_path(AT_FDCWD, "relative.bin", ...)` joins with `getcwd()` result.
 * - `match_fd_rule` with `config_prepare == 0` → 0 immediately.
 * - `match_fd_rule` with `fdcache_resolve == 0` → 0 (no path to match against).
 * - `match_fd_rule` with `config_match_loaded == 0` → 0.
 * - `match_fd_rule` with all stubs succeeding → 1; captured operation and path correct.
 */
static void test_call_real_open_and_match_fd_rule(void)
{
    chaos_io_rule_t rule;
    char expected_path[CHAOS_IO_MAX_PATH];
    char path[CHAOS_IO_MAX_PATH];
    char cwd[CHAOS_IO_MAX_PATH];

    chaos_test_reset_state();
    chaos_test_bind_real_functions();

    g_real_open_return = 11;
    assert(chaos_io_call_real_open("/tmp/a", O_RDONLY, 0, 0) == 11);
    assert(g_real_open_calls == 1);
    assert(g_real_open_has_mode == 0);
    assert(g_real_open_guard == 1);
    assert(g_chaos_io_tls_guard == 0);

    g_real_open_return = 12;
    assert(chaos_io_call_real_open("/tmp/b", O_CREAT | O_WRONLY, 1, 0644) == 12);
    assert(g_real_open_has_mode == 1);
    assert(g_real_open_mode == 0644);

    g_real_openat_return = 13;
    assert(chaos_io_call_real_openat(AT_FDCWD, "/tmp/c", O_RDONLY, 0, 0) == 13);
    assert(g_real_openat_calls == 1);
    assert(g_real_openat_dirfd == AT_FDCWD);
    assert(g_real_openat_has_mode == 0);
    assert(g_real_openat_guard == 1);
    assert(g_chaos_io_tls_guard == 0);

    g_real_openat_return = 14;
    assert(chaos_io_call_real_openat(7, "/tmp/d", O_CREAT | O_WRONLY, 1, 0600) == 14);
    assert(g_real_openat_has_mode == 1);
    assert(g_real_openat_mode == 0600);

    assert(chaos_io_copy_path(NULL, sizeof(path), "/tmp/path") == 0);
    assert(chaos_io_copy_path(path, 0U, "/tmp/path") == 0);
    assert(chaos_io_copy_path(path, sizeof(path), NULL) == 0);
    assert(chaos_io_copy_path(path, 4U, "/tmp/path") == 0);
    assert(chaos_io_resolve_at_path(AT_FDCWD, "/tmp/absolute.bin", path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/absolute.bin") == 0);

    assert(chaos_io_join_paths(NULL, sizeof(path), "/tmp", "child.bin") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), "", "child.bin") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), "/tmp", "") == 0);
    assert(chaos_io_join_paths(path, 4U, "/tmp", "child.bin") == 0);

    assert(chaos_io_getcwd_path(NULL, sizeof(path)) == 0);
    assert(chaos_io_getcwd_path(path, 0U) == 0);
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(chaos_io_resolve_at_path(AT_FDCWD, "relative.bin", path, sizeof(path)) == 1);
    assert(chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative.bin") == 1);
    assert(strcmp(path, expected_path) == 0);

    assert(chaos_io_resolve_at_path(AT_FDCWD, NULL, path, sizeof(path)) == 0);
    assert(chaos_io_resolve_at_path(AT_FDCWD, "relative.bin", NULL, sizeof(path)) == 0);
    assert(chaos_io_resolve_at_path(AT_FDCWD, "relative.bin", path, 0U) == 0);
    /* A result that does not fit the buffer: absolute, and joined to the cwd. */
    assert(chaos_io_resolve_at_path(AT_FDCWD, "/tmp/absolute.bin", path, 4U) == 0);
    assert(chaos_io_resolve_at_path(AT_FDCWD, "relative.bin", path, 4U) == 0);
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/base");
    assert(chaos_io_resolve_at_path(9, "child.bin", path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/base/child.bin") == 0);

    g_fdcache_resolve_result = 0;
    assert(chaos_io_resolve_at_path(9, "child.bin", path, sizeof(path)) == 0);

    g_config_prepare_result = 0;
    assert(chaos_io_match_fd_rule(1, CHAOS_IO_OP_READ, &rule) == 0);
    assert(chaos_io_match_fd_rule(3, CHAOS_IO_OP_READ, NULL) == 0);
    assert(chaos_io_match_fd_rule(3, CHAOS_IO_OP_READ, &rule) == 0);

    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 0;
    assert(chaos_io_match_fd_rule(3, CHAOS_IO_OP_READ, &rule) == 0);

    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/path.bin");
    g_config_match_loaded_result = 0;
    assert(chaos_io_match_fd_rule(3, CHAOS_IO_OP_READ, &rule) == 0);

    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    assert(chaos_io_match_fd_rule(3, CHAOS_IO_OP_READ, &rule) == 1);
    assert(g_last_resolve_fd == 3);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_READ);
    assert(strcmp(g_last_match_loaded_path, "/tmp/path.bin") == 0);
}

/**
 * @brief Invariant: `chaos_io_init()` wires all real-function-pointer globals, seeds the PRNG,
 *   and calls both `config_init` and `fdcache_reset` exactly once.
 *
 * Triggering condition: `chaos_io_init()` called after `chaos_test_reset_state()` with
 *   `g_sys_open_result = 5` and `g_sys_read_result = sizeof(uint64_t)` to deliver a
 *   deterministic seed (`0xfeedbeef12345678`).
 *
 * Expected observable behaviour:
 * - Every `g_chaos_io_real_*` pointer is set to the corresponding stub (16 portable + 3 Linux).
 * - `g_chaos_io_process_seed == 0xfeedbeef12345678`.
 * - `g_chaos_io_tls_prng_state != 0` (derived from the process seed).
 * - `g_config_init_calls == 1`.
 * - `g_fdcache_reset_calls == 1`.
 */
static void test_init_runtime(void)
{
    chaos_test_reset_state();
    g_sys_open_result = 5;
    g_sys_read_result = (long)sizeof(uint64_t);
    g_sys_seed_value = UINT64_C(0xfeedbeef12345678);

    chaos_io_init();
    assert(g_chaos_io_real_read == chaos_test_real_read_impl);
    assert(g_chaos_io_real_write == chaos_test_real_write_impl);
    assert(g_chaos_io_real_readv == chaos_test_real_readv_impl);
    assert(g_chaos_io_real_writev == chaos_test_real_writev_impl);
    assert(g_chaos_io_real_open == chaos_test_real_open_impl);
    assert(g_chaos_io_real_openat == chaos_test_real_openat_impl);
    assert(g_chaos_io_real_close == chaos_test_real_close_impl);
    assert(g_chaos_io_real_fsync == chaos_test_real_fsync_impl);
    assert(g_chaos_io_real_fdatasync == chaos_test_real_fdatasync_impl);
    assert(g_chaos_io_real_pread == chaos_test_real_pread_impl);
    assert(g_chaos_io_real_pwrite == chaos_test_real_pwrite_impl);
    assert(g_chaos_io_real_ftruncate == chaos_test_real_ftruncate_impl);
    assert(g_chaos_io_real_unlinkat == chaos_test_real_unlinkat_impl);
    assert(g_chaos_io_real_truncate == chaos_test_real_truncate_impl);
    assert(g_chaos_io_real_fopen == chaos_test_real_fopen_impl);
    assert(g_chaos_io_real_freopen == chaos_test_real_freopen_impl);
    assert(g_chaos_io_real_renameat == chaos_test_real_renameat_impl);
    assert(g_chaos_io_real_preadv == chaos_test_real_preadv_impl);
    assert(g_chaos_io_real_pwritev == chaos_test_real_pwritev_impl);
#ifdef __linux__
    assert(g_chaos_io_real_sendfile == chaos_test_real_sendfile_impl);
    assert(g_chaos_io_real_copy_file_range == chaos_test_real_copy_file_range_impl);
    assert(g_chaos_io_real_fallocate == chaos_test_real_fallocate_impl);
#endif
    assert(g_chaos_io_process_seed == UINT64_C(0xfeedbeef12345678));
    assert(g_chaos_io_tls_prng_state != 0U);
    assert(g_config_init_calls == 1);
    /* The constructor loads the rules at once so a bad rule file is reported. */
    assert(g_config_prepare_calls == 1);
    assert(g_fdcache_reset_calls == 1);
}

/**
 * @brief Invariant: filesystem-lifecycle wrappers (`ftruncate`, `fallocate`, `unlinkat`,
 *   `renameat`) apply effects correctly and manage the fdcache.
 *
 * Triggering conditions:
 * - `chaos_io_match_loaded_path_rule()` and `chaos_io_match_rename_rule()` with NULL,
 *   `/proc` paths, and full-success scenarios.
 * - `ftruncate(fd, length)` in passthrough mode, with LATENCY, and with ERRNO.
 * - `fallocate(fd, mode, offset, length)` (Linux-only) in passthrough, LATENCY, ERRNO modes.
 * - `unlinkat(AT_FDCWD, path, 0)` in passthrough, failed-syscall (no cache invalidation),
 *   LATENCY (with invalidation), and ERRNO (no real call, no invalidation) modes.
 * - `renameat(olddirfd, oldpath, newdirfd, newpath)` analogously.
 *
 * Expected observable behaviour:
 * - `match_loaded_path_rule(op, NULL, rule)` → 0 (no config call).
 * - `match_loaded_path_rule(op, "/proc/self/maps", rule)` → 0 (proc bypass).
 * - Successful path rule match: `g_last_match_loaded_operation` and path captured.
 * - `match_rename_rule(AT_FDCWD, from, AT_FDCWD, to, NULL)` → 0 (NULL rule out pointer).
 * - `match_rename_rule` with both paths NULL → 0.
 * - `match_rename_rule` with `config_prepare == 0` → 0; `g_config_prepare_calls == 1`.
 * - Two-sided rename match tries RENAME_FROM first, then RENAME_TO.
 * - `ftruncate` passthrough: guard == 1; fd and length forwarded; no latency or errno.
 * - `ftruncate` LATENCY: `g_latency_calls == 1`; real call still made.
 * - `ftruncate` ERRNO: `g_rule_apply_errno_result` causes return -1; `g_real_ftruncate_calls == 0`.
 * - `fallocate` passthrough: guard == 1; mode, offset, length forwarded.
 * - `fallocate` LATENCY: `g_latency_calls == 1`.
 * - `fallocate` ERRNO (ENOSPC): return -1; `g_real_fallocate_calls == 0`.
 * - `unlinkat` success: `g_fdcache_reset_calls == 1` (cache cleared after unlink).
 * - `unlinkat` failure: `g_fdcache_reset_calls == 0` (no cache clear on error).
 * - `unlinkat` LATENCY: latency applied; fdcache cleared after real call.
 * - `unlinkat` ERRNO: real call skipped; fdcache not cleared.
 * - `renameat` success: fdcache cleared.
 * - `renameat` failure: fdcache not cleared.
 * - `renameat` LATENCY (RENAME_TO rule): latency applied; fdcache cleared.
 * - `renameat` ERRNO (RENAME_FROM rule): real call skipped; fdcache not cleared.
 */
static void test_fsops_helpers_and_wrappers(void)
{
    chaos_io_rule_t rule;

    chaos_test_reset_state();
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, NULL, &rule) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/tmp/unlink.bin", NULL) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/proc/self/maps", &rule) == 0);
    /* Every library's control files, not only io's own rule file. */
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/tmp/.chaos-io.conf", &rule) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_OPEN, "/tmp/.chaos-net.conf", &rule) == 0);
    assert(
        chaos_io_match_loaded_path_rule(CHAOS_IO_OP_WRITE, "/tmp/.chaos-dns.hits.42", &rule) == 0
    );
    assert(g_config_match_loaded_calls == 0);
    assert(chaos_io_is_excluded_path("/tmp/.chaos") == 0);
    assert(chaos_io_is_excluded_path("/tmp/.chaosx.conf") == 0);

    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_config_rule.path_len = strlen("/tmp/unlink.bin");
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/tmp/unlink.bin", &rule) == 1);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_UNLINK);
    assert(strcmp(g_last_match_loaded_path, "/tmp/unlink.bin") == 0);

    chaos_test_reset_state();
    assert(
        chaos_io_match_rename_rule(AT_FDCWD, "/tmp/from.bin", AT_FDCWD, "/tmp/to.bin", NULL) == 0
    );
    assert(chaos_io_match_rename_rule(AT_FDCWD, NULL, AT_FDCWD, NULL, &rule) == 0);

    g_config_prepare_result = 0;
    assert(
        chaos_io_match_rename_rule(AT_FDCWD, "/tmp/from.bin", AT_FDCWD, "/tmp/to.bin", &rule) == 0
    );
    assert(g_config_prepare_calls == 1);

    chaos_test_reset_state();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 0;
    assert(
        chaos_io_match_rename_rule(AT_FDCWD, "/tmp/from.bin", AT_FDCWD, "/tmp/to.bin", &rule) == 0
    );
    assert(g_config_match_loaded_calls == 2);

    chaos_test_reset_state();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_config_rule.path_len = strlen("/tmp/from.bin");
    assert(
        chaos_io_match_rename_rule(AT_FDCWD, "/tmp/from.bin", AT_FDCWD, "/proc/self/maps", &rule) ==
        1
    );
    assert(rule.effect == CHAOS_IO_EFFECT_ERRNO);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_FROM);
    assert(strcmp(g_last_match_loaded_path, "/tmp/from.bin") == 0);

    chaos_test_reset_state();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_config_rule.latency_ms = 7U;
    g_config_rule.path_len = strlen("/tmp/to.bin");
    assert(
        chaos_io_match_rename_rule(AT_FDCWD, "/proc/self/maps", AT_FDCWD, "/tmp/to.bin", &rule) == 1
    );
    assert(rule.effect == CHAOS_IO_EFFECT_LATENCY);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_TO);
    assert(strcmp(g_last_match_loaded_path, "/tmp/to.bin") == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_ftruncate_return = 0;
    assert(ftruncate(31, 4) == 0);
    assert(g_real_ftruncate_calls == 1);
    assert(g_real_ftruncate_guard == 1);
    assert(g_real_ftruncate_fd == 31);
    assert(g_real_ftruncate_length == 4);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/truncate.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_ftruncate_return = 0;
    assert(ftruncate(9, 3) == 0);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_TRUNCATE);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/truncate-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(ftruncate(9, 1) == -1);
    assert(errno == EIO);
    assert(g_real_ftruncate_calls == 0);

#ifdef __linux__
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fallocate_return = 0;
    assert(fallocate(33, 0, 2, 9) == 0);
    assert(g_real_fallocate_calls == 1);
    assert(g_real_fallocate_guard == 1);
    assert(g_real_fallocate_fd == 33);
    assert(g_real_fallocate_mode == 0);
    assert(g_real_fallocate_offset == 2);
    assert(g_real_fallocate_length == 9);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/allocate.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_fallocate_return = 0;
    assert(fallocate(9, 3, 4, 5) == 0);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_ALLOCATE);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/allocate-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(fallocate(9, 0, 0, 5) == -1);
    assert(errno == ENOSPC);
    assert(g_real_fallocate_calls == 0);
#endif

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_unlinkat_return = 0;
    assert(unlinkat(AT_FDCWD, "/tmp/unlink.bin", 0) == 0);
    assert(g_real_unlinkat_calls == 1);
    assert(g_real_unlinkat_guard == 1);
    assert(g_real_unlinkat_dirfd == AT_FDCWD);
    assert(strcmp(g_real_unlinkat_path, "/tmp/unlink.bin") == 0);
    assert(g_fdcache_reset_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_unlinkat_return = -1;
    assert(unlinkat(AT_FDCWD, "/tmp/unlink-fail.bin", 0) == -1);
    assert(g_fdcache_reset_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_unlinkat_return = 0;
    assert(unlinkat(AT_FDCWD, "/tmp/unlink-latency.bin", 0) == 0);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_UNLINK);
    assert(strcmp(g_last_match_loaded_path, "/tmp/unlink-latency.bin") == 0);
    assert(g_latency_calls == 1);
    assert(g_fdcache_reset_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOENT;
    g_rule_apply_errno_result = 1;
    assert(unlinkat(AT_FDCWD, "/tmp/unlink-errno.bin", 0) == -1);
    assert(errno == ENOENT);
    assert(g_real_unlinkat_calls == 0);
    assert(g_fdcache_reset_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_renameat_return = 0;
    assert(renameat(AT_FDCWD, "/tmp/rename-from.bin", AT_FDCWD, "/tmp/rename-to.bin") == 0);
    assert(g_real_renameat_calls == 1);
    assert(g_real_renameat_guard == 1);
    assert(g_real_renameat_olddirfd == AT_FDCWD);
    assert(g_real_renameat_newdirfd == AT_FDCWD);
    assert(strcmp(g_real_renameat_oldpath, "/tmp/rename-from.bin") == 0);
    assert(strcmp(g_real_renameat_newpath, "/tmp/rename-to.bin") == 0);
    assert(g_fdcache_reset_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_renameat_return = -1;
    assert(
        renameat(AT_FDCWD, "/tmp/rename-from-fail.bin", AT_FDCWD, "/tmp/rename-to-fail.bin") == -1
    );
    assert(g_fdcache_reset_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_renameat_return = 0;
    assert(renameat(AT_FDCWD, "/proc/self/maps", AT_FDCWD, "/tmp/rename-to-latency.bin") == 0);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_TO);
    assert(strcmp(g_last_match_loaded_path, "/tmp/rename-to-latency.bin") == 0);
    assert(g_latency_calls == 1);
    assert(g_fdcache_reset_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EROFS;
    g_rule_apply_errno_result = 1;
    assert(renameat(AT_FDCWD, "/tmp/rename-from-errno.bin", AT_FDCWD, "/proc/self/maps") == -1);
    assert(errno == EROFS);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_FROM);
    assert(strcmp(g_last_match_loaded_path, "/tmp/rename-from-errno.bin") == 0);
    assert(g_real_renameat_calls == 0);
    assert(g_fdcache_reset_calls == 0);
}

/**
 * @brief Invariant: the `open` wrapper bypasses chaos for re-entrant and `/proc` calls,
 *   and applies latency, errno, or passthrough for ordinary paths.
 *
 * Triggering conditions:
 * - `open("/tmp/direct.bin", O_RDONLY)` with `g_chaos_io_tls_guard = 1` set externally
 *   (simulating a re-entrant call from within the interception layer).
 * - `open("/proc/self/maps", O_RDONLY)` (proc filesystem bypass).
 * - `open("/tmp/latency.bin", O_RDONLY)` with LATENCY rule and `config_match_path == 1`.
 * - `open("/tmp/fail.bin", O_RDONLY)` with ERRNO/EIO and `rule_apply_errno_result == 1`.
 * - `open("/tmp/create.bin", O_CREAT | O_WRONLY, 0600)` to verify mode forwarding.
 * - `open("relative-open.bin", O_RDONLY)` with LATENCY rule to verify CWD join and
 *   fdcache store path.
 *
 * Expected observable behaviour:
 * - Guard bypass: `g_config_match_path_calls == 0`; `g_fdcache_store_calls == 0`; real
 *   open called with no chaos applied.
 * - Proc bypass: same as guard bypass (no match attempt, no fdcache store).
 * - LATENCY: `g_latency_calls == 1`; the descriptor's entry is dropped and resolved
 *   anew from the kernel (`/proc/self/fd`), not stored under the caller's string.
 * - ERRNO: returns -1, errno == EIO; `g_real_open_calls == 0`; `g_fdcache_store_calls == 0`.
 * - O_CREAT: `g_real_open_has_mode == 1`; `g_real_open_mode == 0600`.
 * - Relative path: matched path equals `CWD + "/relative-open.bin"`.
 * - `.`, `..` and `//` in an absolute path are normalised before matching.
 */
static void test_open_wrapper(void)
{
    char expected_path[CHAOS_IO_MAX_PATH];
    char cwd[CHAOS_IO_MAX_PATH];

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 13;
    g_chaos_io_tls_guard = 1;
    assert(open("/tmp/direct.bin", O_RDONLY) == 13);
    assert(g_config_match_path_calls == 0);
    assert(g_fdcache_store_calls == 0);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 14;
    assert(open("/proc/self/maps", O_RDONLY) == 14);
    assert(g_config_match_path_calls == 0);
    assert(g_fdcache_store_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 15;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(open("/tmp/latency.bin", O_RDONLY) == 15);
    assert(g_config_match_path_calls == 1);
    assert(g_latency_calls == 1);
    /* The new descriptor is cached under the kernel's name for it, never under a
     * stale entry of an earlier descriptor with that number. */
    assert(g_fdcache_store_calls == 0);
    assert(g_fdcache_invalidate_calls == 1 && g_last_invalidate_fd == 15);
    assert(g_fdcache_resolve_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(open("/tmp/fail.bin", O_RDONLY) == -1);
    assert(errno == EIO);
    assert(g_real_open_calls == 0);
    assert(g_fdcache_store_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 16;
    assert(open("/tmp/create.bin", O_CREAT | O_WRONLY, 0600) == 16);
    assert(g_real_open_has_mode == 1);
    assert(g_real_open_mode == 0600);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 17;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(open("relative-open.bin", O_RDONLY) == 17);
    assert(
        chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative-open.bin") == 1
    );
    assert(strcmp(g_last_match_path, expected_path) == 0);

    /* Matched as the kernel resolves it: `.`, `..` and repeated slashes. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 18;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(open("/tmp/pd/./x//../data/f", O_RDONLY) == 18);
    assert(strcmp(g_last_match_path, "/tmp/pd/data/f") == 0);
}

/**
 * @brief Invariant: paths are normalised lexically: one slash between components,
 *   no `.`, `..` taking the component before it (not above the root), no trailing
 *   slash; relative paths are left alone.
 */
static void test_normalize_path(void)
{
    static const char *const cases[][2] = {
        {"/", "/"},
        {"//", "/"},
        {"/tmp", "/tmp"},
        {"/tmp/", "/tmp"},
        {"/tmp//pd///data", "/tmp/pd/data"},
        {"/tmp/./pd/.", "/tmp/pd"},
        {"/tmp/pd/../data", "/tmp/data"},
        {"/tmp/pd/x/../../data", "/tmp/data"},
        {"/..", "/"},
        {"/../../tmp", "/tmp"},
        {"/tmp/..", "/"},
        {"/a/b/c/../../../..", "/"},
        {"/tmp/.hidden/..x/...", "/tmp/.hidden/..x/..."},
        {"relative/../x", "relative/../x"},
    };
    char path[64];
    size_t index;

    for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index)
    {
        (void)snprintf(path, sizeof(path), "%s", cases[index][0]);
        chaos_io_normalize_path(path);
        assert(strcmp(path, cases[index][1]) == 0);
    }
    chaos_io_normalize_path(NULL);
}

/**
 * @brief Invariant: the `openat` wrapper resolves paths via CWD, fdcache, and dirfd correctly,
 *   and applies effects or bypasses re-entrant calls.
 *
 * Triggering conditions:
 * - `openat(7, "direct.bin", O_RDONLY)` with `g_chaos_io_tls_guard = 1` (re-entrant bypass).
 * - `openat(AT_FDCWD, "relative-openat.bin", O_RDONLY)` with LATENCY and no fdcache match
 *   (path joined with CWD).
 * - `openat(21, "child.bin", O_RDONLY)` with a fdcache hit for dirfd 21 (base "/tmp/openat-base").
 * - `openat(22, "child.bin", O_RDONLY)` with fdcache hit and ERRNO/EIO injection.
 * - `openat(23, "child.bin", O_CREAT | O_WRONLY, 0640)` (mode forwarding; no match because no
 *   path probe with `g_config_match_path_result == 0`).
 *
 * Expected observable behaviour:
 * - Guard bypass: `g_config_match_path_calls == 0`; `g_fdcache_store_calls == 0`.
 * - CWD resolve + LATENCY: matched and stored path equals `CWD + "/relative-openat.bin"`;
 *   `g_latency_calls == 1`.
 * - Fdcache dirfd resolve + LATENCY: matched and stored path == `/tmp/openat-base/child.bin`;
 *   `g_real_openat_dirfd == 21`; real path arg == `"child.bin"`.
 * - ERRNO: returns -1, errno == EIO; `g_real_openat_calls == 0`.
 * - O_CREAT: `g_real_openat_has_mode == 1`; mode == 0640; `g_fdcache_resolve_calls == 2`
 *   (dirfd path probe + store-time path construction attempt).
 */
static void test_openat_wrapper(void)
{
    char expected_path[CHAOS_IO_MAX_PATH];
    char cwd[CHAOS_IO_MAX_PATH];

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_openat_return = 18;
    g_chaos_io_tls_guard = 1;
    assert(openat(7, "direct.bin", O_RDONLY) == 18);
    assert(g_config_match_path_calls == 0);
    assert(g_fdcache_store_calls == 0);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_openat_return = 19;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(openat(AT_FDCWD, "relative-openat.bin", O_RDONLY) == 19);
    assert(
        chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative-openat.bin") == 1
    );
    assert(strcmp(g_last_match_path, expected_path) == 0);
    assert(g_fdcache_invalidate_calls == 1 && g_last_invalidate_fd == 19);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_openat_return = 20;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/openat-base");
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(openat(21, "child.bin", O_RDONLY) == 20);
    assert(strcmp(g_last_match_path, "/tmp/openat-base/child.bin") == 0);
    assert(g_fdcache_store_calls == 0 && g_last_invalidate_fd == 20);
    assert(g_real_openat_dirfd == 21);
    assert(strcmp(g_real_openat_path, "child.bin") == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/openat-fail");
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(openat(22, "child.bin", O_RDONLY) == -1);
    assert(errno == EIO);
    assert(g_real_openat_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_openat_return = 23;
    assert(openat(23, "child.bin", O_CREAT | O_WRONLY, 0640) == 23);
    assert(g_real_openat_has_mode == 1);
    assert(g_real_openat_mode == 0640);
    assert(g_config_match_path_calls == 0);
    assert(g_fdcache_store_calls == 0);
    assert(g_fdcache_resolve_calls == 2);
}

/**
 * @brief Invariant: the `read` and `write` wrappers apply corrupt, torn, latency, and errno
 *   effects, and call through to the real function in passthrough mode.
 *
 * Triggering conditions:
 * - `read(5, buffer, 8)` in passthrough mode (no config match).
 * - `read(9, buffer, 8)` with CORRUPT effect and `rule_should_trigger == 1`.
 * - `read(9, buffer, 8)` with LATENCY effect.
 * - `read(9, buffer, 8)` with ERRNO/ENOSPC and `rule_apply_errno_result == 1`.
 * - `write(7, data, 6)` in passthrough mode.
 * - `write(9, data, 6)` with TORN effect: `g_torn_count_result == 2`.
 * - `write(9, data, 3)` with LATENCY effect.
 * - `write(9, data, 3)` with ERRNO/EROFS.
 *
 * Expected observable behaviour:
 * - Passthrough read: `g_real_read_calls == 1`; `g_real_read_guard == 1`; buffer filled
 *   from `g_real_read_fill`.
 * - CORRUPT read: `g_corrupt_calls == 1`; `g_last_corrupt_size == 4`.
 * - LATENCY read: `g_latency_calls == 1`; real read still made.
 * - ERRNO read: returns -1, errno == ENOSPC; `g_real_read_calls == 0`.
 * - Passthrough write: `g_real_write_calls == 1`; `g_real_write_guard == 1`.
 * - TORN write: returns `g_torn_count_result (2)`; `g_last_torn_requested == 6`;
 *   `g_real_write_count == 2`.
 * - LATENCY write: `g_latency_calls == 1`; real write still made.
 * - ERRNO write: returns -1, errno == EROFS; real write not made.
 */
static void test_read_and_write_wrappers(void)
{
    char buffer[8] = {0};

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    (void)memcpy(g_real_read_fill, "ABCD", 4U);
    g_real_read_return = 4;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(g_real_read_calls == 1);
    assert(g_real_read_guard == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/read.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_CORRUPT;
    g_rule_should_trigger_result = 1;
    (void)memcpy(g_real_read_fill, "WXYZ", 4U);
    g_real_read_return = 4;
    buffer[0] = 'W';
    assert(read(9, buffer, sizeof(buffer)) == 4);
    assert(g_corrupt_calls == 1);
    assert(g_last_corrupt_size == 4U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/read-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_read_return = 2;
    assert(read(9, buffer, sizeof(buffer)) == 2);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/read-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(read(9, buffer, sizeof(buffer)) == -1);
    assert(errno == ENOSPC);
    assert(g_real_read_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_write_return = 6;
    assert(write(7, "abcdef", 6U) == 6);
    assert(g_real_write_calls == 1);
    assert(g_real_write_guard == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/write.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 2U;
    g_real_write_return = 2;
    assert(write(9, "abcdef", 6U) == 2);
    assert(g_rule_should_trigger_calls == 1);
    assert(g_last_torn_requested == 6U);
    assert(g_real_write_count == 2U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/write-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_write_return = 3;
    assert(write(9, "abc", 3U) == 3);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/write-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EROFS;
    g_rule_apply_errno_result = 1;
    assert(write(9, "abc", 3U) == -1);
    assert(errno == EROFS);
}

/**
 * @brief Invariant: iovec helper functions enforce bounds, detect overflow, and route
 *   corruption to the correct iov segment.
 *
 * Triggering conditions:
 * - `chaos_io_iovec_total_bytes()` with NULL iov, NULL total, zero count, and SSIZE_MAX overflow.
 * - `chaos_io_iovec_total_bytes()` with two valid segments totalling 5 bytes.
 * - `chaos_io_trim_iovecs()` with NULL, zero count, zero limit, and valid 3-byte clip.
 * - `chaos_io_build_torn_iovecs()` with zero torn count, zero-length iovecs, count >= total,
 *   and a valid 3-byte result clipping a 5-byte total.
 * - `chaos_io_corrupt_iovecs()` with NULL, zero count, zero size, and various PRNG seeds
 *   to confirm single-segment routing when total == 2 and index picks odd.
 *
 * Expected observable behaviour:
 * - `iovec_total_bytes`: any NULL or zero-count input → 0; SSIZE_MAX + 1 → 0 (overflow); 2+3 → 5.
 * - `trim_iovecs`: any NULL input → 0; limit=3 clips first segment to 2, second to 1.
 * - `build_torn_iovecs`: torn count == 0 → 0; iov total == 0 → 0; torn >= total → 0; valid → 1.
 * - `corrupt_iovecs`: NULL iov, zero count, or zero size → no corrupt call.
 * - `corrupt_iovecs` with two 4-byte segments and size=3: exactly one call;
 * `last_corrupt_sample_size == 3`.
 * - `corrupt_iovecs` with two 1-byte segments and an odd PRNG draw: routes to second segment
 *   with `last_corrupt_sample_size == 1`.
 */
static void test_vectored_helpers(void)
{
    struct iovec source[2];
    struct iovec target[2];
    char first[4] = {'a', 'b', 'c', 'd'};
    char second[4] = {'e', 'f', 'g', 'h'};
    size_t total = 0U;
    int target_count = 0;
    uint64_t seed = 1U;

    source[0].iov_base = first;
    source[0].iov_len = 2U;
    source[1].iov_base = second;
    source[1].iov_len = 3U;

    assert(chaos_io_iovec_total_bytes(source, 2, NULL) == 0);
    assert(chaos_io_iovec_total_bytes(NULL, 2, &total) == 0);
    assert(chaos_io_iovec_total_bytes(source, 0, &total) == 0);
    source[0].iov_len = (size_t)SSIZE_MAX;
    source[1].iov_len = 1U;
    assert(chaos_io_iovec_total_bytes(source, 2, &total) == 0);

    source[0].iov_len = 2U;
    source[1].iov_len = 3U;
    assert(chaos_io_iovec_total_bytes(source, 2, &total) == 1);
    assert(total == 5U);

    assert(chaos_io_trim_iovecs(NULL, 2, 1U, target, &target_count) == 0);
    assert(chaos_io_trim_iovecs(source, 0, 1U, target, &target_count) == 0);
    assert(chaos_io_trim_iovecs(source, 2, 1U, NULL, &target_count) == 0);
    assert(chaos_io_trim_iovecs(source, 2, 1U, target, NULL) == 0);
    assert(chaos_io_trim_iovecs(source, 2, 3U, target, &target_count) == 1);
    assert(target_count == 2);
    assert(target[0].iov_len == 2U);
    assert(target[1].iov_len == 1U);

    chaos_test_reset_state();
    g_torn_count_result = 0U;
    assert(chaos_io_build_torn_iovecs(source, 2, target, &target_count) == 0);
    source[0].iov_len = 0U;
    source[1].iov_len = 0U;
    assert(chaos_io_build_torn_iovecs(source, 2, target, &target_count) == 0);
    source[0].iov_len = 2U;
    source[1].iov_len = 3U;
    g_torn_count_result = 5U;
    assert(chaos_io_build_torn_iovecs(source, 2, target, &target_count) == 0);
    g_torn_count_result = 3U;
    assert(chaos_io_build_torn_iovecs(source, 2, target, &target_count) == 1);
    assert(target_count == 2);
    assert(target[0].iov_len == 2U);
    assert(target[1].iov_len == 1U);

    chaos_test_reset_state();
    chaos_io_corrupt_iovecs(NULL, 2, 1U);
    chaos_io_corrupt_iovecs(source, 0, 1U);
    chaos_io_corrupt_iovecs(source, 2, 0U);
    assert(g_corrupt_sample_calls == 0);

    chaos_test_reset_state();
    source[0].iov_len = 4U;
    source[1].iov_len = 4U;
    chaos_io_corrupt_iovecs(source, 2, 3U);
    assert(g_corrupt_sample_calls == 1);
    assert(g_last_corrupt_sample_size == 3U);

    /* Find a seed that makes the PRNG draw an odd value for the two-segment routing test. */
    chaos_test_reset_state();
    source[0].iov_len = 1U;
    source[1].iov_len = 1U;
    while (seed < 256U)
    {
        chaos_io_prng_seed_thread(seed);
        if ((chaos_io_prng_next_u32() % 2U) == 1U)
        {
            break;
        }
        ++seed;
    }
    assert(seed < 256U);
    chaos_io_prng_seed_thread(seed);
    chaos_io_corrupt_iovecs(source, 2, 2U);
    assert(g_corrupt_sample_calls == 1);
    assert(g_last_corrupt_sample_size == 1U);
}

/**
 * @brief Invariant: `readv` and `writev` wrappers apply corrupt, torn, latency, and errno
 *   effects, and pass through with guard state and iov layout captured.
 *
 * Triggering conditions:
 * - `readv(5, read_iov, 2)` in passthrough mode.
 * - `readv(9, read_iov, 2)` with CORRUPT effect.
 * - `readv(9, read_iov, 2)` with LATENCY effect.
 * - `readv(9, read_iov, 2)` with ERRNO/EIO.
 * - `writev(7, write_iov, 2)` in passthrough mode.
 * - `writev(9, write_iov, 2)` with LATENCY effect.
 * - `writev(9, write_iov, 2)` with TORN effect and `g_torn_count_result == 3`.
 * - `writev(9, empty_iov, 0)` with TORN effect and zero-count iov (fallback to real call).
 * - `writev(9, write_iov, 2)` with ERRNO/EROFS.
 *
 * Expected observable behaviour:
 * - Passthrough readv: `g_real_readv_calls == 1`; `g_real_readv_guard == 1`; iov buffers filled
 *   from `g_real_read_fill` in segment order.
 * - CORRUPT readv: `g_corrupt_sample_calls == 1`; at least one byte in first or second buffer
 *   differs from the fill pattern (one bit flip by the harness corrupt stub).
 * - LATENCY readv: `g_latency_calls == 1`.
 * - ERRNO readv: returns -1, errno == EIO; `g_real_readv_calls == 0`.
 * - Passthrough writev: `g_real_writev_calls == 1`; iov count and lengths captured correctly.
 * - LATENCY writev: `g_latency_calls == 1`.
 * - TORN writev: `g_last_torn_requested == 6`; trimmed iov passed to real call
 *   (`lengths[0] == 2`, `lengths[1] == 1`); operation recorded as OP_WRITE.
 * - Zero-iov TORN fallback: real writev called without torn trimming.
 * - ERRNO writev: returns -1, errno == EROFS; `g_real_writev_calls == 0`.
 */
static void test_readv_and_writev_wrappers(void)
{
    char first[3] = {0};
    char second[3] = {0};
    struct iovec empty_iov[1];
    struct iovec read_iov[2];
    struct iovec write_iov[2];

    read_iov[0].iov_base = first;
    read_iov[0].iov_len = 2U;
    read_iov[1].iov_base = second;
    read_iov[1].iov_len = 2U;
    write_iov[0].iov_base = (void *)"ab";
    write_iov[0].iov_len = 2U;
    write_iov[1].iov_base = (void *)"cdef";
    write_iov[1].iov_len = 4U;
    empty_iov[0].iov_base = first;
    empty_iov[0].iov_len = 0U;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    (void)memcpy(g_real_read_fill, "ABCD", 4U);
    g_real_readv_return = 4;
    assert(readv(5, read_iov, 2) == 4);
    assert(g_real_readv_calls == 1);
    assert(g_real_readv_guard == 1);
    assert(first[0] == 'A');
    assert(second[1] == 'D');

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/readv.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_CORRUPT;
    g_rule_should_trigger_result = 1;
    (void)memcpy(g_real_read_fill, "WXYZ", 4U);
    g_real_readv_return = 4;
    (void)memset(first, 0, sizeof(first));
    (void)memset(second, 0, sizeof(second));
    assert(readv(9, read_iov, 2) == 4);
    assert(g_corrupt_sample_calls == 1);
    assert(memcmp(first, "WX", 2U) != 0 || memcmp(second, "YZ", 2U) != 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/readv-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_readv_return = 4;
    assert(readv(9, read_iov, 2) == 4);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/readv-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(readv(9, read_iov, 2) == -1);
    assert(errno == EIO);
    assert(g_real_readv_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_writev_return = 6;
    assert(writev(7, write_iov, 2) == 6);
    assert(g_real_writev_calls == 1);
    assert(g_real_writev_guard == 1);
    assert(g_real_writev_iovcnt == 2);
    assert(g_real_writev_lengths[0] == 2U);
    assert(g_real_writev_lengths[1] == 4U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/writev-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_writev_return = 6;
    assert(writev(9, write_iov, 2) == 6);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/writev.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 3U;
    g_real_writev_return = 3;
    assert(writev(9, write_iov, 2) == 3);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_WRITE);
    assert(g_last_torn_requested == 6U);
    assert(g_real_writev_iovcnt == 2);
    assert(g_real_writev_lengths[0] == 2U);
    assert(g_real_writev_lengths[1] == 1U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/writev-fallback.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_real_writev_return = 0;
    assert(writev(9, empty_iov, 0) == 0);
    assert(g_real_writev_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/writev-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EROFS;
    g_rule_apply_errno_result = 1;
    assert(writev(9, write_iov, 2) == -1);
    assert(errno == EROFS);
    assert(g_real_writev_calls == 0);
}

/** @brief Arms a matching rule with @p effect for the vectored-input tests. */
static void chaos_test_arm_vector_rule(chaos_io_effect_t effect)
{
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/vector.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = effect;
    g_rule_should_trigger_result = 1;
}

/**
 * @brief Invariant: the vectored wrappers read the caller's iovec array only once a
 *   rule matched, never past IOV_MAX entries, and only through the checked copy; an
 *   array they cannot read reaches the kernel unchanged instead of crashing them.
 *
 * Expected observable behaviour:
 * - No rule: the array is not read at all.
 * - LATENCY: `call_size` is the vector's byte total, also across copy chunks of 64.
 * - Unreadable array (EFAULT), negative or over-IOV_MAX counts, a total past
 *   SSIZE_MAX: `call_size` is unknown and the call is passed through with the
 *   caller's own arguments and errno.
 * - Copy unavailable (ENOSYS, EPERM): the array is copied directly.
 * - TORN: an unreadable array, or one longer than 64 entries, is written whole and
 *   the rule is not counted.
 */
static void test_vectored_input_checks(void)
{
    static struct iovec many[CHAOS_IO_TORN_MAX_IOV + 36];
    static char bytes[CHAOS_IO_TORN_MAX_IOV + 36];
    struct iovec pair[CHAOS_TEST_IOV_SNAPSHOT_COUNT]; /* the stubs snapshot this many */
    int index;
    /* Called through a pointer: libc's attributes would reject the invalid arguments. */
    ssize_t (*volatile writev_unchecked)(int, const struct iovec *, int) = writev;

    (void)memset(pair, 0, sizeof(pair));
    pair[0].iov_base = (void *)"ab";
    pair[0].iov_len = 2U;
    pair[1].iov_base = (void *)"cdef";
    pair[1].iov_len = 4U;
    for (index = 0; index < CHAOS_IO_TORN_MAX_IOV + 36; ++index)
    {
        many[index].iov_base = &bytes[index];
        many[index].iov_len = 1U;
    }

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_config_match_loaded_result = 0;
    g_real_writev_return = 6;
    assert(writev(9, pair, 2) == 6);
    assert(g_vm_readv_calls == 0);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_real_writev_return = 6;
    assert(writev(9, pair, 2) == 6);
    assert(g_last_call_size == 6U);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_real_readv_return = 4; /* the stub fills from a 64-byte pattern */
    assert(readv(9, many, CHAOS_IO_TORN_MAX_IOV + 36) == 4);
    assert(g_vm_readv_calls == 2);
    assert(g_last_call_size == (uint64_t)CHAOS_IO_TORN_MAX_IOV + 36U);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_vm_readv_errno = EFAULT;
    g_real_preadv_return = -1;
    errno = 0;
    assert(preadv(9, pair, 2, 0) == -1);
    assert(errno == 0);
    assert(g_last_call_size == CHAOS_POLICY_NO_SIZE);
    assert(g_real_preadv_calls == 1);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_vm_readv_errno = ENOSYS;
    g_real_pwritev_return = 6;
    errno = 0;
    assert(pwritev(9, pair, 2, 0) == 6);
    assert(errno == 0);
    assert(g_last_call_size == 6U);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_vm_readv_errno = EPERM;
    g_real_writev_return = 6;
    assert(writev(9, pair, 2) == 6);
    assert(g_last_call_size == 6U);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_real_writev_return = -1;
    assert(writev_unchecked(9, pair, CHAOS_IO_MAX_IOV + 1) == -1);
    assert(writev_unchecked(9, pair, -1) == -1);
    assert(writev_unchecked(9, NULL, 2) == -1);
    assert(g_vm_readv_calls == 0);
    assert(g_last_call_size == CHAOS_POLICY_NO_SIZE);
    assert(g_real_writev_calls == 3);
    assert(g_real_writev_iovcnt == 2);

    /* The first chunk of 64 sums to exactly SSIZE_MAX; the second overflows it. */
    many[0].iov_len = (size_t)SSIZE_MAX - (size_t)(CHAOS_IO_TORN_MAX_IOV - 1);
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_real_writev_return = -1;
    assert(writev(9, many, CHAOS_IO_TORN_MAX_IOV + 1) == -1);
    assert(g_vm_readv_calls == 2);
    assert(g_last_call_size == CHAOS_POLICY_NO_SIZE);
    many[0].iov_len = 1U;

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_TORN);
    g_torn_count_result = 1U;
    g_real_writev_return = CHAOS_IO_TORN_MAX_IOV + 1;
    assert(writev(9, many, CHAOS_IO_TORN_MAX_IOV + 1) == CHAOS_IO_TORN_MAX_IOV + 1);
    assert(g_real_writev_iovcnt == CHAOS_IO_TORN_MAX_IOV + 1);
    assert(g_rule_should_trigger_calls == 0);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_TORN);
    g_torn_count_result = 1U;
    g_real_pwritev_return = CHAOS_IO_TORN_MAX_IOV;
    assert(pwritev(9, many, CHAOS_IO_TORN_MAX_IOV, 0) == CHAOS_IO_TORN_MAX_IOV);
    assert(g_real_pwritev_iovcnt == 1);
    assert(g_rule_should_trigger_calls == 1);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_TORN);
    g_torn_count_result = 3U;
    g_vm_readv_errno = EFAULT;
    g_real_pwritev_return = 6;
    assert(pwritev(9, pair, 2, 0) == 6);
    assert(g_real_pwritev_iovcnt == 2);
    assert(g_real_pwritev_lengths[1] == 4U);
    assert(g_rule_should_trigger_calls == 0);
}

#ifdef __linux__
/**
 * @brief Invariant: the `sendfile` wrapper bypasses chaos for re-entrant calls and
 *   applies torn, latency, and errno effects.
 *
 * Triggering conditions:
 * - `sendfile(8, 4, &offset, 5)` with `g_chaos_io_tls_guard = 1` (re-entrant bypass).
 * - `sendfile(9, 4, NULL, 6)` with TORN effect and `g_torn_count_result == 3`.
 * - `sendfile(9, 4, NULL, 2)` with LATENCY effect.
 * - `sendfile(9, 4, NULL, 2)` with ERRNO/EIO.
 *
 * Expected observable behaviour:
 * - Guard bypass: real sendfile called immediately; guard captured as 1; `g_real_sendfile_out_fd ==
 * 8`; `g_real_sendfile_in_fd == 4`; offset pointer forwarded.
 * - TORN: `g_last_torn_requested == 6`; `g_real_sendfile_count == 3`; operation == OP_WRITE.
 * - LATENCY: `g_latency_calls == 1`.
 * - ERRNO: returns -1, errno == EIO; `g_real_sendfile_calls == 0`.
 */
static void test_sendfile_wrapper(void)
{
    off_t offset = 7;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_sendfile_return = 5;
    g_chaos_io_tls_guard = 1;
    assert(sendfile(8, 4, &offset, 5U) == 5);
    assert(g_real_sendfile_calls == 1);
    assert(g_real_sendfile_guard == 1);
    assert(g_real_sendfile_out_fd == 8);
    assert(g_real_sendfile_in_fd == 4);
    assert(g_real_sendfile_offset == &offset);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/sendfile.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 3U;
    g_real_sendfile_return = 3;
    assert(sendfile(9, 4, NULL, 6U) == 3);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_WRITE);
    assert(g_last_torn_requested == 6U);
    assert(g_real_sendfile_count == 3U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/sendfile-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_sendfile_return = 2;
    assert(sendfile(9, 4, NULL, 2U) == 2);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/sendfile-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(sendfile(9, 4, NULL, 2U) == -1);
    assert(errno == EIO);
    assert(g_real_sendfile_calls == 0);
}

/**
 * @brief Invariant: the `copy_file_range` wrapper bypasses chaos for re-entrant calls and
 *   applies torn, latency, and errno effects; flags are forwarded to the real function.
 *
 * Triggering conditions:
 * - `copy_file_range(4, &in_offset, 8, &out_offset, 5, 0)` with `g_chaos_io_tls_guard = 1`.
 * - `copy_file_range(4, NULL, 9, NULL, 6, 0)` with TORN effect and `g_torn_count_result == 3`.
 * - `copy_file_range(4, NULL, 9, NULL, 2, 7)` with LATENCY effect (non-zero flags).
 * - `copy_file_range(4, NULL, 9, NULL, 2, 0)` with ERRNO/EIO.
 *
 * Expected observable behaviour:
 * - Guard bypass: real copy_file_range called; both fd and offset pointers forwarded;
 *   `g_real_copy_file_range_flags == 0`.
 * - TORN: `g_last_torn_requested == 6`; `g_real_copy_file_range_count == 3`; operation == OP_WRITE.
 * - LATENCY: `g_latency_calls == 1`; `g_real_copy_file_range_flags == 7` (non-zero flags
 * preserved).
 * - ERRNO: returns -1, errno == EIO; `g_real_copy_file_range_calls == 0`.
 */
static void test_copy_file_range_wrapper(void)
{
    off_t in_offset = 2;
    off_t out_offset = 5;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_copy_file_range_return = 5;
    g_chaos_io_tls_guard = 1;
    assert(copy_file_range(4, &in_offset, 8, &out_offset, 5U, 0U) == 5);
    assert(g_real_copy_file_range_calls == 1);
    assert(g_real_copy_file_range_guard == 1);
    assert(g_real_copy_file_range_in_fd == 4);
    assert(g_real_copy_file_range_out_fd == 8);
    assert(g_real_copy_file_range_in_offset == &in_offset);
    assert(g_real_copy_file_range_out_offset == &out_offset);
    assert(g_real_copy_file_range_flags == 0U);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/copy-range.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 3U;
    g_real_copy_file_range_return = 3;
    assert(copy_file_range(4, NULL, 9, NULL, 6U, 0U) == 3);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_WRITE);
    assert(g_last_torn_requested == 6U);
    assert(g_real_copy_file_range_count == 3U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/copy-range-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_copy_file_range_return = 2;
    assert(copy_file_range(4, NULL, 9, NULL, 2U, 7U) == 2);
    assert(g_latency_calls == 1);
    assert(g_real_copy_file_range_flags == 7U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/copy-range-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(copy_file_range(4, NULL, 9, NULL, 2U, 0U) == -1);
    assert(errno == EIO);
    assert(g_real_copy_file_range_calls == 0);
}
#endif

/**
 * @brief Invariant: `preadv` and `pwritev` wrappers apply corrupt, torn, latency, and errno
 *   effects; the file offset is forwarded to the real function; and zero-iovec TORN falls back.
 *
 * Triggering conditions:
 * - `preadv(5, read_iov, 2, 11)` in passthrough mode.
 * - `preadv(9, read_iov, 2, 13)` with CORRUPT effect.
 * - `preadv(9, read_iov, 2, 13)` with LATENCY effect.
 * - `preadv(9, read_iov, 2, 13)` with ERRNO/ENOSPC.
 * - `pwritev(7, write_iov, 2, 17)` in passthrough mode.
 * - `pwritev(9, write_iov, 2, 19)` with LATENCY effect.
 * - `pwritev(9, write_iov, 2, 19)` with TORN effect.
 * - `pwritev(9, empty_iov, 0, 19)` with TORN effect and zero-count iov.
 * - `pwritev(9, write_iov, 2, 19)` with ERRNO/EACCES.
 *
 * Expected observable behaviour:
 * - Passthrough preadv: `g_real_preadv_calls == 1`; guard == 1; offset == 11; buffers filled.
 * - CORRUPT preadv: `g_corrupt_sample_calls == 1`; at least one buffer byte changed.
 * - LATENCY preadv: `g_latency_calls == 1`.
 * - ERRNO preadv: returns -1, errno == ENOSPC; `g_real_preadv_calls == 0`.
 * - Passthrough pwritev: `g_real_pwritev_calls == 1`; guard == 1; offset == 17; iov lengths
 * captured.
 * - LATENCY pwritev: `g_latency_calls == 1`.
 * - TORN pwritev: `g_last_torn_requested == 6`; trimmed iov (`lengths[0]==2`, `lengths[1]==1`);
 *   operation == OP_PWRITE; offset == 19.
 * - Zero-iov TORN fallback: real pwritev called once without torn trimming.
 * - ERRNO pwritev: returns -1, errno == EACCES; `g_real_pwritev_calls == 0`.
 */
static void test_preadv_and_pwritev_wrappers(void)
{
    char first[3] = {0};
    char second[3] = {0};
    struct iovec empty_iov[1];
    struct iovec read_iov[2];
    struct iovec write_iov[2];

    read_iov[0].iov_base = first;
    read_iov[0].iov_len = 2U;
    read_iov[1].iov_base = second;
    read_iov[1].iov_len = 2U;
    write_iov[0].iov_base = (void *)"xy";
    write_iov[0].iov_len = 2U;
    write_iov[1].iov_base = (void *)"z123";
    write_iov[1].iov_len = 4U;
    empty_iov[0].iov_base = first;
    empty_iov[0].iov_len = 0U;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    (void)memcpy(g_real_pread_fill, "ABCD", 4U);
    g_real_preadv_return = 4;
    assert(preadv(5, read_iov, 2, 11) == 4);
    assert(g_real_preadv_calls == 1);
    assert(g_real_preadv_guard == 1);
    assert(g_real_preadv_offset == 11);
    assert(first[0] == 'A');
    assert(second[1] == 'D');

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/preadv.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_CORRUPT;
    g_rule_should_trigger_result = 1;
    (void)memcpy(g_real_pread_fill, "QRST", 4U);
    g_real_preadv_return = 4;
    (void)memset(first, 0, sizeof(first));
    (void)memset(second, 0, sizeof(second));
    assert(preadv(9, read_iov, 2, 13) == 4);
    assert(g_corrupt_sample_calls == 1);
    assert(memcmp(first, "QR", 2U) != 0 || memcmp(second, "ST", 2U) != 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/preadv-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_preadv_return = 4;
    assert(preadv(9, read_iov, 2, 13) == 4);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/preadv-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(preadv(9, read_iov, 2, 13) == -1);
    assert(errno == ENOSPC);
    assert(g_real_preadv_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_pwritev_return = 6;
    assert(pwritev(7, write_iov, 2, 17) == 6);
    assert(g_real_pwritev_calls == 1);
    assert(g_real_pwritev_guard == 1);
    assert(g_real_pwritev_offset == 17);
    assert(g_real_pwritev_lengths[0] == 2U);
    assert(g_real_pwritev_lengths[1] == 4U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwritev-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_pwritev_return = 6;
    assert(pwritev(9, write_iov, 2, 19) == 6);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwritev.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 3U;
    g_real_pwritev_return = 3;
    assert(pwritev(9, write_iov, 2, 19) == 3);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_PWRITE);
    assert(g_last_torn_requested == 6U);
    assert(g_real_pwritev_iovcnt == 2);
    assert(g_real_pwritev_lengths[0] == 2U);
    assert(g_real_pwritev_lengths[1] == 1U);
    assert(g_real_pwritev_offset == 19);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwritev-fallback.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_real_pwritev_return = 0;
    assert(pwritev(9, empty_iov, 0, 19) == 0);
    assert(g_real_pwritev_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwritev-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 1;
    assert(pwritev(9, write_iov, 2, 19) == -1);
    assert(errno == EACCES);
    assert(g_real_pwritev_calls == 0);
}

/**
 * @brief Invariant: `close`, `fsync`, `fdatasync`, `pread`, and `pwrite` wrappers apply effects
 *   correctly and manage the fdcache or bypass for re-entrant calls.
 *
 * Triggering conditions:
 * - `close(11)` in passthrough mode (success and failure paths).
 * - `close(11)` with ERRNO/EACCES; `close(11)` with LATENCY effect.
 * - `fsync(12)` in passthrough, LATENCY, and ERRNO/ENOSPC modes.
 * - `fdatasync(13)` in passthrough, LATENCY, and ERRNO/EIO modes.
 * - `pread(13, buffer, 8, 2)` with `g_chaos_io_tls_guard = 1` (guard bypass).
 * - `pread(13, buffer, 8, 5)` with CORRUPT effect.
 * - `pread(13, buffer, 8, 1)` with LATENCY and ERRNO/EIO modes.
 * - `pwrite(13, "xyz", 3, 9)` with `g_chaos_io_tls_guard = 1` (guard bypass).
 * - `pwrite(13, "xyz", 3, 9)` with TORN effect (`g_torn_count_result == 1`).
 * - `pwrite(13, "xyz", 3, 9)` with LATENCY and ERRNO/ENOSPC modes.
 *
 * Expected observable behaviour:
 * - `close` success passthrough: `g_fdcache_invalidate_calls == 1`; `g_last_invalidate_fd == 11`.
 * - `close` failure passthrough: `g_fdcache_invalidate_calls == 0`.
 * - `close` ERRNO: returns -1, errno == EACCES; real close not called.
 * - `close` LATENCY: `g_latency_calls == 1`; fdcache invalidated.
 * - `fsync` passthrough: `g_real_fsync_calls == 1`.
 * - `fsync` LATENCY: `g_latency_calls == 1`.
 * - `fsync` ERRNO: returns -1, errno == ENOSPC.
 * - `fdatasync` passthrough: `g_real_fdatasync_calls == 1`.
 * - `fdatasync` LATENCY: `g_latency_calls == 1`.
 * - `fdatasync` ERRNO: returns -1, errno == EIO.
 * - `pread` guard bypass: real pread called; no config lookup.
 * - `pread` CORRUPT: `g_corrupt_calls == 1`; offset forwarded to real call.
 * - `pread` LATENCY: `g_latency_calls == 1`.
 * - `pread` ERRNO: returns -1, errno == EIO.
 * - `pwrite` guard bypass: real pwrite called immediately.
 * - `pwrite` TORN: real write count == `g_torn_count_result (1)`; offset forwarded.
 * - `pwrite` LATENCY: `g_latency_calls == 1`.
 * - `pwrite` ERRNO: returns -1, errno == ENOSPC.
 */
static void test_close_sync_and_positioned_wrappers(void)
{
    char buffer[8] = {0};

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_close_return = 0;
    assert(close(11) == 0);
    assert(g_fdcache_invalidate_calls == 1);
    assert(g_last_invalidate_fd == 11);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_close_return = -1;
    assert(close(11) == -1);
    /* Linux releases the descriptor even when close reports an error. */
    assert(g_fdcache_invalidate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/close.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 1;
    assert(close(11) == -1);
    assert(errno == EACCES);
    /* The injected error is reported after a real close, as Linux reports EIO. */
    assert(g_real_close_calls == 1);
    assert(g_fdcache_invalidate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/close-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_close_return = 0;
    assert(close(11) == 0);
    assert(g_latency_calls == 1);
    assert(g_fdcache_invalidate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fsync_return = 0;
    assert(fsync(12) == 0);
    assert(g_real_fsync_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/fsync.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(fsync(12) == 0);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/fsync-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(fsync(12) == -1);
    assert(errno == ENOSPC);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fdatasync_return = 0;
    assert(fdatasync(13) == 0);
    assert(g_real_fdatasync_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/fdatasync.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_fdatasync_return = 0;
    assert(fdatasync(13) == 0);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/fdatasync-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(fdatasync(13) == -1);
    assert(errno == EIO);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_pread_return = 2;
    g_chaos_io_tls_guard = 1;
    assert(pread(13, buffer, sizeof(buffer), 2) == 2);
    assert(g_real_pread_calls == 1);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pread.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_CORRUPT;
    g_rule_should_trigger_result = 1;
    (void)memcpy(g_real_pread_fill, "DATA", 4U);
    g_real_pread_return = 4;
    assert(pread(13, buffer, sizeof(buffer), 5) == 4);
    assert(g_real_pread_offset == 5);
    assert(g_corrupt_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pread-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_pread_return = 1;
    assert(pread(13, buffer, sizeof(buffer), 1) == 1);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pread-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    assert(pread(13, buffer, sizeof(buffer), 1) == -1);
    assert(errno == EIO);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_pwrite_return = 2;
    g_chaos_io_tls_guard = 1;
    assert(pwrite(13, "xyz", 3U, 9) == 2);
    assert(g_real_pwrite_calls == 1);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwrite.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_TORN;
    g_rule_should_trigger_result = 1;
    g_torn_count_result = 1U;
    g_real_pwrite_return = 1;
    assert(pwrite(13, "xyz", 3U, 9) == 1);
    assert(g_real_pwrite_offset == 9);
    assert(g_real_pwrite_count == 1U);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwrite-latency.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_real_pwrite_return = 3;
    assert(pwrite(13, "xyz", 3U, 9) == 3);
    assert(g_latency_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/pwrite-fail.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(pwrite(13, "xyz", 3U, 9) == -1);
    assert(errno == ENOSPC);
}

/**
 * @brief Regression: wrappers must survive being reached before the constructor.
 *
 * @details `LD_PRELOAD` maps this object before the executable's own
 * `DT_NEEDED` libraries, but ELF initialisers run in dependency order, so
 * another library's constructor can call an interposed symbol while
 * `chaos_io_init()` is still pending.  `libcap-ng` does exactly this — its
 * initialiser performs file I/O — which made every `setpriv`, `su` and
 * `runuser` invocation under libchaos-io abort with SIGSEGV.
 *
 * Each case below puts the library back into its pre-constructor state
 * (`chaos_test_reset_state()` clears the pointer table and the ready flag),
 * then calls a wrapper directly.  Before the fix these dereferenced NULL.
 */
static void test_wrappers_resolve_symbols_before_constructor(void)
{
    char buffer[4];
    ssize_t transferred;
    int rc;

    /* Results are captured rather than cast to void: glibc marks read() and
     * write() warn_unused_result, and a (void) cast does not suppress that
     * under GCC.  The values themselves are irrelevant here -- the assertion
     * is that the call resolved its symbol instead of faulting. */

    /* close(): the first wrapper libcap-ng's initialiser can reach. */
    chaos_test_reset_state();
    assert(g_chaos_io_real_close == NULL);
    rc = close(13);
    (void)rc;
    assert(g_chaos_io_real_close != NULL);

    /* open(): path-based wrappers take a different entry path. */
    chaos_test_reset_state();
    assert(g_chaos_io_real_open == NULL);
    rc = open("/tmp/chaos-init-order", O_RDONLY);
    (void)rc;
    assert(g_chaos_io_real_open != NULL);

    /* read()/write(): the fd-based hot path. */
    chaos_test_reset_state();
    assert(g_chaos_io_real_read == NULL);
    transferred = read(13, buffer, sizeof(buffer));
    (void)transferred;
    assert(g_chaos_io_real_read != NULL);

    chaos_test_reset_state();
    assert(g_chaos_io_real_write == NULL);
    transferred = write(13, "x", 1U);
    (void)transferred;
    assert(g_chaos_io_real_write != NULL);

    /* Resolution is idempotent: a second call must not re-resolve or fault. */
    chaos_test_reset_state();
    chaos_io_ensure_symbols();
    assert(g_chaos_io_real_read != NULL);
    assert(g_chaos_io_real_close != NULL);
    chaos_io_ensure_symbols();
    assert(g_chaos_io_real_read != NULL);
    assert(g_chaos_io_real_close != NULL);
}

/** @brief Number of threads racing on symbol resolution. */
#define CHAOS_TEST_ENSURE_THREADS 8

/** @brief Per-thread failure slots; slot @c i is written only by thread @c i. */
static int g_ensure_worker_failed[CHAOS_TEST_ENSURE_THREADS];

/** @brief Thread indices, passed by address so each worker knows its slot. */
static int g_ensure_worker_index[CHAOS_TEST_ENSURE_THREADS];

/**
 * @brief Hammers `chaos_io_ensure_symbols()` and checks the table is fully published.
 *
 * @details Observing a NULL pointer after the call has returned means the
 * readiness signal became visible before the pointer stores did — precisely the
 * failure a non-synchronising guard permits.
 */
static void *chaos_test_ensure_worker(void *argument)
{
    const int slot = *(const int *)argument;
    int iteration;

    for (iteration = 0; iteration < 64; ++iteration)
    {
        chaos_io_ensure_symbols();
        if (g_chaos_io_real_read == NULL || g_chaos_io_real_write == NULL ||
            g_chaos_io_real_open == NULL || g_chaos_io_real_close == NULL)
        {
            g_ensure_worker_failed[slot] = 1;
            return NULL;
        }
    }
    return NULL;
}

/**
 * @brief Regression: concurrent resolution must never expose a half-built table.
 *
 * @details `chaos_io_ensure_symbols()` is reached from every interposed wrapper
 * on every thread, so its guard has to order the pointer stores against the
 * readiness signal.  A plain `volatile` flag does not: on a weakly ordered
 * architecture a second thread can observe the flag set while some stores are
 * still invisible to it, and call through NULL.  `pthread_once` supplies the
 * release/acquire pairing that makes this safe.
 *
 * A passing run cannot prove the absence of a race, but the test does fail
 * outright if the guard is replaced by something that publishes readiness
 * without ordering the stores behind it.
 */
static void test_ensure_symbols_is_thread_safe(void)
{
    pthread_t threads[CHAOS_TEST_ENSURE_THREADS];
    int index;

    chaos_test_reset_state();

    for (index = 0; index < CHAOS_TEST_ENSURE_THREADS; ++index)
    {
        g_ensure_worker_failed[index] = 0;
        g_ensure_worker_index[index] = index;
        assert(
            pthread_create(
                &threads[index], NULL, chaos_test_ensure_worker, &g_ensure_worker_index[index]
            ) == 0
        );
    }

    for (index = 0; index < CHAOS_TEST_ENSURE_THREADS; ++index)
    {
        assert(pthread_join(threads[index], NULL) == 0);
    }

    for (index = 0; index < CHAOS_TEST_ENSURE_THREADS; ++index)
    {
        assert(g_ensure_worker_failed[index] == 0);
    }

    assert(g_chaos_io_real_read != NULL);
    assert(g_chaos_io_real_close != NULL);
}

#if defined(__GLIBC__) && defined(__LP64__)
/** Times the stubbed overflow handler of the fortified variants ran. */
static int g_chk_fail_calls = 0;

/** Stands in for glibc's `__chk_fail()`, which would abort the test. */
static void chaos_test_chk_fail(void)
{
    ++g_chk_fail_calls;
}

/**
 * @brief Invariant: glibc's alternate entry points run the same wrappers.
 *
 * Triggering conditions: the large-file names are taken by address, and each
 * fortified variant is called within and beyond its buffer.
 *
 * Expected observable behaviour:
 * - Every large-file name is the base wrapper itself (same address).
 * - A fortified call within the buffer reaches the real function through the wrapper.
 * - A fortified call beyond the buffer, or `__open_2()` with flags that need a mode,
 *   goes to the overflow handler and never reaches the real function.
 */
static void test_glibc_alternate_entries(void)
{
    char buffer[8] = {0};
    int (*open_fn)(const char *, int, ...) = open64;
    int (*openat_fn)(int, const char *, int, ...) = openat64;
    ssize_t (*pread_fn)(int, void *, size_t, off_t) = pread64;
    ssize_t (*pwrite_fn)(int, const void *, size_t, off_t) = pwrite64;
    ssize_t (*preadv_fn)(int, const struct iovec *, int, off_t) = preadv64;
    ssize_t (*pwritev_fn)(int, const struct iovec *, int, off_t) = pwritev64;
    ssize_t (*sendfile_fn)(int, int, off_t *, size_t) = sendfile64;
    int (*ftruncate_fn)(int, off_t) = ftruncate64;
    int (*truncate_fn)(const char *, off_t) = truncate64;
    int (*creat_fn)(const char *, mode_t) = creat64;
    int (*posix_fallocate_fn)(int, off_t, off_t) = posix_fallocate64;
    int (*fallocate_fn)(int, int, off_t, off_t) = fallocate64;
    int (*open2_fn)(const char *, int) = __open64_2;
    int (*openat2_fn)(int, const char *, int) = __openat64_2;
    ssize_t (*pread_chk_fn)(int, void *, size_t, off_t, size_t) = __pread64_chk;

    assert(open_fn == open);
    assert(openat_fn == openat);
    assert(pread_fn == pread);
    assert(pwrite_fn == pwrite);
    assert(preadv_fn == preadv);
    assert(pwritev_fn == pwritev);
    assert(sendfile_fn == sendfile);
    assert(ftruncate_fn == ftruncate);
    assert(truncate_fn == truncate);
    assert(creat_fn == creat);
    assert(posix_fallocate_fn == posix_fallocate);
    assert(fallocate_fn == fallocate);
    assert(open2_fn == __open_2);
    assert(openat2_fn == __openat_2);
    assert(pread_chk_fn == __pread_chk);

    g_chaos_io_rw_chk_fail = chaos_test_chk_fail;
    g_chaos_io_open_chk_fail = chaos_test_chk_fail;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_read_return = 4;
    assert(__read_chk(5, buffer, 4U, sizeof(buffer)) == 4);
    assert(g_real_read_calls == 1);
    g_chk_fail_calls = 0;
    /* The declared buffer size is the check's input: a count beyond it trips the
     * check without writing past the real buffer, which the compiler would reject. */
    assert(__read_chk(5, buffer, 4U, 2U) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_real_read_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_pread_return = 3;
    assert(__pread_chk(5, buffer, 4U, 0, sizeof(buffer)) == 3);
    assert(g_real_pread_calls == 1);
    g_chk_fail_calls = 0;
    assert(__pread_chk(5, buffer, 4U, 0, 2U) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_real_pread_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 21;
    assert(__open_2("/tmp/fortified.bin", O_RDONLY) == 21);
    assert(g_real_open_calls == 1);
    g_chk_fail_calls = 0;
    assert(__open_2("/tmp/fortified.bin", O_RDWR | O_CREAT) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_real_open_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_openat_return = 22;
    assert(__openat_2(AT_FDCWD, "/tmp/fortified.bin", O_RDONLY) == 22);
    assert(g_real_openat_calls == 1);
    g_chk_fail_calls = 0;
    assert(__openat_2(AT_FDCWD, "/tmp/fortified.bin", O_RDWR | O_CREAT) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_real_openat_calls == 1);

    g_chaos_io_rw_chk_fail = __chk_fail;
    g_chaos_io_open_chk_fail = __chk_fail;
}
#endif

/**
 * @brief Invariant: calls that free or reassign a descriptor invalidate its cache entry.
 *
 * Triggering conditions: `dup2`, `dup3` and `close_range` with successful and failing
 * real calls, `close_range` with CLOSE_RANGE_CLOEXEC, a reversed range, a narrow and a
 * wide range, and a C library without `close_range`.
 *
 * Expected observable behaviour:
 * - A successful dup2/dup3 invalidates the target descriptor; dup2 onto itself and a
 *   failed call invalidate nothing.
 * - A successful close_range invalidates each descriptor of a narrow range and resets
 *   the whole cache for a wide one; CLOEXEC, a reversed range and a failure invalidate
 *   nothing.
 * - Without a real close_range the wrapper fails with ENOSYS.
 */
/**
 * @brief Releases what the closedir/pclose test opened, with the C library's own
 *        functions (the interposed ones only reached stubs).
 */
static int closedir_real_release(DIR *directory, FILE *stream)
{
    void *closedir_symbol = dlsym(RTLD_NEXT, "closedir");
    void *fclose_symbol = dlsym(RTLD_NEXT, "fclose");
    int (*real_closedir)(DIR *);
    int (*real_fclose)(FILE *);

    (void)memcpy(&real_closedir, &closedir_symbol, sizeof(real_closedir));
    (void)memcpy(&real_fclose, &fclose_symbol, sizeof(real_fclose));
    return real_closedir(directory) | real_fclose(stream);
}

static void test_descriptor_reassignment_wrappers(void)
{
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_dup_return = 9;
    assert(dup2(4, 9) == 9);
    assert(g_fdcache_invalidate_calls == 1);
    assert(g_last_invalidate_fd == 9);
    assert(dup2(9, 9) == 9);
    assert(g_fdcache_invalidate_calls == 1);
    g_real_dup_return = -1;
    assert(dup2(4, 9) == -1);
    assert(g_fdcache_invalidate_calls == 1);

#ifdef __linux__
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_dup_return = 10;
    assert(dup3(4, 10, 0) == 10);
    assert(g_fdcache_invalidate_calls == 1);
    assert(g_last_invalidate_fd == 10);
    g_real_dup_return = -1;
    assert(dup3(4, 10, 0) == -1);
    assert(g_fdcache_invalidate_calls == 1);
#endif

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_dup_return = 0;
    assert(close_range(5U, 7U, 0) == 0);
    assert(g_fdcache_invalidate_calls == 3);
    assert(close_range(3U, ~0U, 0) == 0);
    assert(g_fdcache_reset_calls == 1);
    assert(close_range(5U, 7U, (int)CLOSE_RANGE_CLOEXEC) == 0);
    assert(close_range(7U, 5U, 0) == 0);
    assert(g_fdcache_invalidate_calls == 3);
    g_real_dup_return = -1;
    assert(close_range(5U, 7U, 0) == -1);
    assert(g_fdcache_invalidate_calls == 3);
    assert(g_real_dup_calls == 5);

    g_chaos_io_real_close_range = NULL;
    errno = 0;
    assert(close_range(5U, 7U, 0) == -1);
    assert(errno == ENOSYS);
    chaos_test_bind_real_functions();

    /* Descriptors the C library closes with its own system calls: forgotten too. */
    {
        /* Through pointers: the compiler knows these free their argument. */
        int (*volatile closedir_wrapper)(DIR *) = closedir;
        int (*volatile pclose_wrapper)(FILE *) = pclose;
        struct rlimit original;
        struct rlimit narrow;
        DIR *directory = opendir("/");
        FILE *stream = tmpfile();
        int directory_fd;
        int stream_fd;

        assert(directory != NULL && stream != NULL);
        directory_fd = dirfd(directory);
        stream_fd = fileno(stream);

        chaos_test_reset_state();
        chaos_test_bind_real_functions();
        errno = 4242;
        assert(closedir_wrapper(directory) == 0);
        assert(errno == 4242);
        assert(g_real_closedir_calls == 1);
        assert(g_fdcache_invalidate_calls == 1 && g_last_invalidate_fd == directory_fd);
        assert(closedir_wrapper(NULL) == 0);
        assert(g_fdcache_invalidate_calls == 2 && g_last_invalidate_fd == -1);

        assert(pclose_wrapper(stream) == 7);
        assert(g_real_pclose_calls == 1);
        assert(g_fdcache_invalidate_calls == 3 && g_last_invalidate_fd == stream_fd);
        assert(pclose_wrapper(NULL) == 7);
        /* The stubs closed nothing: release what the test opened. */
        assert(closedir_real_release(directory, stream) == 0);

        closefrom(9);
        assert(g_real_closefrom_calls == 1 && g_real_closefrom_lowfd == 9);
        assert(g_fdcache_reset_calls == 1);

        /* Without closefrom in the C library: close_range, else each descriptor. */
        g_chaos_io_real_closefrom = NULL;
        g_sys_close_range_result = 0;
        errno = 4242;
        closefrom(-5);
        assert(errno == 4242 && g_sys_close_calls == 0 && g_fdcache_reset_calls == 2);
        g_sys_close_range_result = -1;
        assert(getrlimit(RLIMIT_NOFILE, &original) == 0);
        narrow = original;
        narrow.rlim_cur = 16U;
        assert(setrlimit(RLIMIT_NOFILE, &narrow) == 0);
        closefrom(10);
        assert(setrlimit(RLIMIT_NOFILE, &original) == 0);
        assert(errno == 4242 && g_sys_close_calls == 6 && g_fdcache_reset_calls == 3);
        chaos_test_bind_real_functions();
    }
}

/**
 * @brief Invariant: the path forms reach the same rules as the descriptor and *at forms.
 *
 * Expected observable behaviour:
 * - `unlink(p)` → real unlinkat(AT_FDCWD, p, 0); `rmdir(p)` → flags AT_REMOVEDIR; both
 *   match the `unlink` rules.
 * - `rename(a, b)` → real renameat(AT_FDCWD, a, AT_FDCWD, b) under the rename rules.
 * - `creat(p, m)` → real open(p, O_CREAT | O_WRONLY | O_TRUNC, m) under the open rules.
 * - `truncate(p, n)`: passthrough under the guard, for excluded or unmatched paths;
 *   matched by path against the `truncate` rules; LATENCY then real call; ERRNO fails
 *   without the real call.
 */
static void test_path_form_wrappers(void)
{
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 1;
    assert(unlink("/tmp/path-form.bin") == -1);
    assert(errno == EACCES);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_UNLINK);
    assert(g_real_unlinkat_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(unlink("/tmp/path-form.bin") == 0);
    assert(g_real_unlinkat_dirfd == AT_FDCWD);
    assert(g_real_unlinkat_flags == 0);
    assert(rmdir("/tmp/path-form.d") == 0);
    assert(g_real_unlinkat_flags == AT_REMOVEDIR);
    assert(strcmp(g_real_unlinkat_path, "/tmp/path-form.d") == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(rename("/tmp/path-form.a", "/tmp/path-form.b") == 0);
    assert(g_real_renameat_olddirfd == AT_FDCWD);
    assert(g_real_renameat_newdirfd == AT_FDCWD);
    assert(strcmp(g_real_renameat_newpath, "/tmp/path-form.b") == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 21;
    assert(creat("/tmp/path-form.new", 0640) == 21);
    assert(g_real_open_flags == (O_CREAT | O_WRONLY | O_TRUNC));
    assert(g_real_open_mode == 0640);
    assert(g_last_match_path_operation == CHAOS_IO_OP_OPEN);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_chaos_io_tls_guard = 1;
    assert(truncate("/tmp/path-form.bin", 7) == 0);
    assert(g_real_truncate_calls == 1);
    assert(g_real_truncate_guard == 1);
    assert(g_config_match_path_calls == 0);
    g_chaos_io_tls_guard = 0;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(truncate("/proc/self/fd/0", 0) == 0);
    assert(g_config_match_path_calls == 0);
    assert(truncate("/tmp/path-form.bin", 7) == 0);
    assert(g_last_match_path_operation == CHAOS_IO_OP_TRUNCATE);
    assert(strcmp(g_last_match_path, "/tmp/path-form.bin") == 0);
    assert(g_real_truncate_calls == 2);
    assert(g_real_truncate_length == 7);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(truncate("/tmp/path-form.bin", 3) == 0);
    assert(g_latency_calls == 1);
    assert(g_real_truncate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    assert(truncate("/tmp/path-form.bin", 3) == -1);
    assert(errno == ENOSPC);
    assert(g_real_truncate_calls == 0);

    /* remove(): unlink first; a directory (EISDIR) is retried with AT_REMOVEDIR. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(remove("/tmp/path-form.bin") == 0);
    assert(g_real_unlinkat_calls == 1);
    assert(g_real_unlinkat_flags == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_unlinkat_return = -1;
    errno = EISDIR;
    assert(remove("/tmp/path-form.d") == -1);
    assert(g_real_unlinkat_calls == 2);
    assert(g_real_unlinkat_flags == AT_REMOVEDIR);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 1;
    assert(remove("/tmp/path-form.bin") == -1);
    assert(errno == EACCES);
    assert(g_real_unlinkat_calls == 0);

    /* renameat2(): the rename rules, flags passed through, cache reset on success. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 1U) == 0);
    assert(g_real_renameat2_calls == 1);
    assert(g_real_renameat2_flags == 1U);
    assert(g_fdcache_reset_calls == 1);
    g_chaos_io_tls_guard = 1;
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 0U) == 0);
    g_chaos_io_tls_guard = 0;
    assert(g_real_renameat2_calls == 2);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 0U) == 0);
    assert(g_latency_calls == 1);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_TO);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EROFS;
    g_rule_apply_errno_result = 1;
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 0U) == -1);
    assert(errno == EROFS);
    assert(g_real_renameat2_calls == 0);
    assert(g_fdcache_reset_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_chaos_io_real_renameat2 = NULL;
    errno = 0;
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 0U) == -1);
    assert(errno == ENOSYS);
    assert(g_fdcache_reset_calls == 0);

    /* posix_fallocate(): the allocate rules; errors returned, errno untouched. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_posix_fallocate_return = 0;
    assert(posix_fallocate(9, 0, 4096) == 0);
    assert(g_real_posix_fallocate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/posix-allocate.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(posix_fallocate(9, 0, 4096) == 0);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_ALLOCATE);
    assert(g_latency_calls == 1);
    assert(g_real_posix_fallocate_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/posix-allocate.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = ENOSPC;
    g_rule_apply_errno_result = 1;
    errno = 4242;
    assert(posix_fallocate(9, 0, 4096) == ENOSPC);
    assert(errno == 4242);
    assert(g_real_posix_fallocate_calls == 0);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/posix-allocate.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_rule_apply_errno_result = 0;
    assert(posix_fallocate(9, 0, 4096) == 0);
    assert(g_real_posix_fallocate_calls == 1);
}

/**
 * @brief Invariant: fopen() and freopen() are faulted by the open rules.
 *
 * Expected observable behaviour:
 * - an ERRNO open rule makes fopen() return NULL with that errno, without the real call;
 * - freopen() under the same rule fails the real freopen() (empty path), which closes
 *   the stream the C library's way, and returns NULL with the rule's errno;
 * - LATENCY delays, then opens; an unmatched path, the guard and a NULL freopen()
 *   path reach the real call unchanged;
 * - fopen64 and freopen64 are the same wrappers.
 */
static void test_stdio_open_wrappers(void)
{
    FILE *(*fopen64_fn)(const char *, const char *) = fopen64;
    FILE *(*freopen64_fn)(const char *, const char *, FILE *) = freopen64;
    FILE *stream;

    assert(fopen64_fn == fopen);
    assert(freopen64_fn == freopen);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 1;
    errno = 0;
    assert(fopen("/tmp/stdio-open.txt", "r") == NULL);
    assert(errno == EACCES);
    assert(g_last_match_path_operation == CHAOS_IO_OP_OPEN);
    assert(g_real_fopen_calls == 0);

    stream = tmpfile();
    assert(stream != NULL);
    errno = 0;
    assert(freopen("/tmp/stdio-open.txt", "r", stream) == NULL);
    assert(errno == EACCES);
    assert(g_real_freopen_calls == 1 && strcmp(g_real_fopen_path, "") == 0);
    assert(fclose(stream) == 0); /* the stub reopened nothing and closed nothing */

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    g_config_rule.latency_ms = 5U;
    g_real_fopen_return = stdin;
    assert(fopen("/tmp/stdio-open.txt", "r") == stdin);
    assert(g_latency_calls == 1);
    assert(g_real_fopen_calls == 1);

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fopen_return = stdin;
    assert(fopen("/tmp/stdio-open.txt", "r") == stdin);
    assert(freopen("/tmp/stdio-open.txt", "r", stdin) == stdin);
    assert(freopen(NULL, "r", stdin) == stdin);
    assert(g_real_fopen_path == NULL);
    g_chaos_io_tls_guard = 1;
    assert(fopen("/tmp/stdio-open.txt", "r") == stdin);
    g_chaos_io_tls_guard = 0;
    assert(g_real_fopen_calls == 2);
    assert(g_real_freopen_calls == 2);
}

/**
 * @brief Invariant: data-moving wrappers hand the call's byte count to the matched
 *   rule, so `@size` gates see it; an iovec call reports its total.
 */
static void test_wrappers_record_call_size(void)
{
    char buffer[16] = {0};
    long rc;
    struct iovec iov[2];

    iov[0].iov_base = buffer;
    iov[0].iov_len = 5U;
    iov[1].iov_base = buffer + 5;
    iov[1].iov_len = 6U;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/sized.bin");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    rc = write(9, buffer, 9U);
    assert(g_last_call_size == 9U);
    rc = read(9, buffer, 12U);
    assert(g_last_call_size == 12U);
    rc = writev(9, iov, 2);
    assert(g_last_call_size == 11U);
    rc = preadv(9, iov, 2, 0);
    assert(g_last_call_size == 11U);
    rc = pwrite(9, buffer, 3U, 0);
    assert(g_last_call_size == 3U);
    rc = fallocate(9, 0, 0, 4096);
    assert(g_last_call_size == 4096U);
    rc = readv(9, NULL, 0);
    assert(g_last_call_size == CHAOS_POLICY_NO_SIZE);
    (void)rc;
}

/** @brief Calls the vfprintf wrapper with a real va_list. */
static int chaos_test_call_vfprintf(FILE *stream, const char *format, ...)
{
    va_list arguments;
    int rc;

    va_start(arguments, format);
    rc = vfprintf(stream, format, arguments);
    va_end(arguments);
    return rc;
}

/** @brief Calls the __vfprintf_chk wrapper with a real va_list. */
static int chaos_test_call_vfprintf_chk(FILE *stream, const char *format, ...)
{
    va_list arguments;
    int rc;

    va_start(arguments, format);
    rc = __vfprintf_chk(stream, 1, format, arguments);
    va_end(arguments);
    return rc;
}

/** @brief Arms the config stubs so that every stdio stream matches a rule of @p effect. */
static void chaos_test_stdio_rule(chaos_io_effect_t effect)
{
    chaos_test_reset_state();
    g_config_prepare_result = 1;
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/stdio.txt");
    g_config_match_loaded_result = 1;
    g_config_rule.effect = effect;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 1;
    g_rule_should_trigger_result = 1;
}

/** @brief A temporary stream holding "abc\ndef\n", positioned at the start. */
static FILE *chaos_test_stdio_stream(void)
{
    FILE *stream;

    chaos_test_reset_state();
    stream = tmpfile();
    assert(stream != NULL);
    assert(fputs("abc\ndef\n", stream) >= 0);
    rewind(stream);
    return stream;
}

/**
 * @brief Invariant: the stdio wrappers apply the io read/write rules to the stream's
 *   descriptor: ERRNO fails the call the way the C library does and raises the error
 *   indicator, LATENCY delays it, CORRUPT changes what a read returned, and calls
 *   without a rule, on a NULL stream or on a stream without a descriptor pass through.
 */
static void test_stdio_wrappers(void)
{
    char buffer[16];
    char *line = NULL;
    size_t capacity = 0U;
    FILE *stream;
    FILE *memory;
    /* Passthrough. */
    stream = chaos_test_stdio_stream();
    assert(fgets(buffer, sizeof(buffer), stream) == buffer && strcmp(buffer, "abc\n") == 0);
    assert(fgetc(stream) == 'd' && getc(stream) == 'e');
    assert(fread(buffer, 1U, 2U, stream) == 2U);
    rewind(stream);
    assert(getline(&line, &capacity, stream) == 4);
    assert(fwrite("xy", 1U, 2U, stream) == 2U && fputs("z", stream) >= 0);
    assert(fputc('1', stream) == '1' && putc('2', stream) == '2');
    assert(fprintf(stream, "%d", 3) == 1 && fflush(stream) == 0 && fflush(NULL) == 0);
    assert(chaos_test_call_vfprintf(stream, "%d", 4) == 1);
    assert(chaos_test_call_vfprintf_chk(stream, "%d", 5) == 1);
    assert(__fprintf_chk(stream, 1, "%d", 6) == 1);
    rewind(stream);
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 2U);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == buffer);
    memory = fmemopen(buffer, sizeof(buffer), "w");
    assert(memory != NULL);
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_ERRNO);
    assert(fputs("in memory", memory) >= 0); /* no descriptor: no rule */
    assert(fclose(memory) == 0);
    assert(g_rule_apply_errno_calls == 0);
    assert(fclose(stream) == 0);

    /* ERRNO: every form fails with its C library error value and sets ferror. */
    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_ERRNO);
    errno = 0;
    assert(fread(buffer, 1U, 4U, stream) == 0U && errno == EIO && ferror(stream));
    clearerr(stream);
    assert(fgets(buffer, sizeof(buffer), stream) == NULL && ferror(stream));
    assert(fgetc(stream) == EOF && getc(stream) == EOF);
    assert(getline(&line, &capacity, stream) == -1);
    assert(getdelim(&line, &capacity, ';', stream) == -1);
    assert(__getdelim(&line, &capacity, ';', stream) == -1);
    assert(fwrite("x", 1U, 1U, stream) == 0U);
    assert(fputs("xy", stream) == EOF);
    assert(fputc('x', stream) == EOF && putc('x', stream) == EOF);
    assert(fprintf(stream, "x%d", 1) < 0 && fflush(stream) == EOF);
    assert(__fprintf_chk(stream, 1, "x%d", 1) < 0);
    /* The standard streams are never faulted. */
    assert(fflush(stdout) == 0);
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 4U, stream) == 0U);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == NULL);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    /* LATENCY delays, then runs the real call. */
    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_LATENCY);
    assert(fread(buffer, 1U, 3U, stream) == 3U);
    assert(fwrite("x", 1U, 1U, stream) == 1U);
    assert(g_latency_calls == 2);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    /* CORRUPT changes what reads return; an empty result is left alone. */
    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_CORRUPT);
    assert(fread(buffer, 1U, 2U, stream) == 2U && buffer[0] == ('a' ^ 1));
    assert(fgets(buffer, sizeof(buffer), stream) == buffer && buffer[0] == ('c' ^ 1));
    assert(fgetc(stream) == ('d' ^ 1));
    assert(getline(&line, &capacity, stream) == 3 && line[0] == ('e' ^ 1));
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 0U);
    assert(fgets(buffer, sizeof(buffer), stream) == NULL);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == NULL);
    assert(fgetc(stream) == EOF);
    rewind(stream);
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 2U);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == buffer);
    g_rule_should_trigger_result = 0;
    assert(fread(buffer, 1U, 1U, stream) == 1U);
    assert(g_corrupt_calls == 6);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    /* Without the fortified functions in the C library, the plain ones run. */
    stream = chaos_test_stdio_stream();
    g_chaos_io_real_fread_chk = NULL;
    g_chaos_io_real_fgets_chk = NULL;
    g_chaos_io_real_vfprintf_chk = NULL;
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 2U);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == buffer);
    assert(__fprintf_chk(stream, 1, "%s", "x") == 1);
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_LATENCY);
    g_chaos_io_real_fread_chk = NULL;
    g_chaos_io_real_fgets_chk = NULL;
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 1U, stream) == 1U);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == buffer);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    /* Byte counts for @size gates; a request that overflows has none. */
    assert(chaos_io_stdio_size(4U, 3U) == 12U);
    assert(chaos_io_stdio_size(SIZE_MAX, 3U) == CHAOS_POLICY_NO_SIZE);
    assert(chaos_io_stdio_size(0U, 3U) == 0U);
    free(line);
}

/**
 * @brief Invariant: streams keep the fd-to-path cache right, and stdio lookups leave
 *   errno alone.
 *
 * Expected observable behaviour: fopen drops any entry of the stream's descriptor
 *   and resolves it anew; so does freopen; fclose drops it; nothing is
 *   cached under the guard; a passthrough call on a stream without a descriptor
 *   leaves errno as it was.
 */
static void test_stdio_streams_keep_the_cache_right(void)
{
    char buffer[16];
    FILE *stream;
    FILE *memory;
    int stores;
    int invalidations;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fopen_return = tmpfile();
    assert(g_real_fopen_return != NULL);
    stream = fopen("/tmp/stdio-cache.txt", "w+");
    assert(stream == g_real_fopen_return);
    /* Cached under the kernel's name for the new descriptor, never a stale one. */
    assert(g_fdcache_invalidate_calls == 1 && g_last_invalidate_fd == fileno(stream));
    assert(g_fdcache_resolve_calls == 1 && g_fdcache_store_calls == 0);

    /* Reopened: the descriptor's entry is dropped and resolved again. */
    assert(freopen("/proc/self/status", "r", stream) == stream);
    assert(g_fdcache_invalidate_calls == 2 && g_fdcache_resolve_calls == 2);
    /* A NULL path keeps the file: no change. */
    invalidations = g_fdcache_invalidate_calls;
    assert(freopen(NULL, "r", stream) == stream);
    assert(g_fdcache_invalidate_calls == invalidations);
    /* A stream without a descriptor is not cached. */
    memory = fmemopen(buffer, sizeof(buffer), "w");
    assert(memory != NULL);
    g_real_fopen_return = memory;
    stores = g_fdcache_resolve_calls;
    assert(fopen("/tmp/stdio-cache.txt", "w") == memory);
    assert(g_fdcache_resolve_calls == stores && g_fdcache_invalidate_calls == invalidations);

    /* Under the guard nothing is cached or dropped. */
    g_chaos_io_tls_guard = 1;
    g_real_fopen_return = stream;
    assert(fopen("/tmp/stdio-cache.txt", "r") == stream);
    assert(freopen("/tmp/stdio-cache.txt", "r", stream) == stream);
    assert(fclose(memory) == 0);
    assert(g_fdcache_resolve_calls == stores && g_fdcache_invalidate_calls == invalidations);
    g_chaos_io_tls_guard = 0;

    /* fclose drops the entry of a stream with a descriptor. */
    assert(fclose(stream) == 0);
    assert(g_fdcache_invalidate_calls == invalidations + 1);

    /* A passthrough call on a stream without a descriptor leaves errno alone. */
    memory = fmemopen(buffer, sizeof(buffer), "w");
    assert(memory != NULL);
    errno = 4242;
    assert(fputs("x", memory) >= 0);
    assert(errno == 4242);
    assert(fclose(memory) == 0);
}

int main(void)
{
    test_stdio_streams_keep_the_cache_right();
    test_stdio_wrappers();
    test_wrappers_record_call_size();
    test_stdio_open_wrappers();
    test_resolve_symbol_and_seed_material();
    test_call_real_open_and_match_fd_rule();
    test_wrappers_resolve_symbols_before_constructor();
    test_ensure_symbols_is_thread_safe();
    test_init_runtime();
    test_open_wrapper();
    test_normalize_path();
    test_openat_wrapper();
    test_fsops_helpers_and_wrappers();
    test_path_form_wrappers();
    test_read_and_write_wrappers();
    test_vectored_helpers();
    test_readv_and_writev_wrappers();
    test_vectored_input_checks();
#ifdef __linux__
    test_sendfile_wrapper();
    test_copy_file_range_wrapper();
#endif
    test_preadv_and_pwritev_wrappers();
    test_close_sync_and_positioned_wrappers();
    test_descriptor_reassignment_wrappers();
#if defined(__GLIBC__) && defined(__LP64__)
    test_glibc_alternate_entries();
#endif
    chaos_test_bind_libc_functions_for_exit();
    return 0;
}
