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

/**
 * @brief Invariant: `chaos_io_resolve_symbol()` wires a pointer and `chaos_io_read_seed_material()`
 *   returns the seeded value or a PID-based fallback.
 *
 * Triggering conditions:
 * - `chaos_io_resolve_symbol(&resolved_read, "read")` with a functioning dlsym stub.
 * - `chaos_io_resolve_symbol()` with `g_dlsym_fail_symbol = "read"` and `g_abort_expected = 1`.
 * - `chaos_io_read_seed_material()` with successful open+full read (`g_sys_read_result == sizeof(uint64_t)`).
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
    assert(g_config_match_loaded_calls == 0);

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
 * - LATENCY: `g_latency_calls == 1`; `g_fdcache_store_calls == 1`;
 *   `g_last_store_path == "/tmp/latency.bin"`.
 * - ERRNO: returns -1, errno == EIO; `g_real_open_calls == 0`; `g_fdcache_store_calls == 0`.
 * - O_CREAT: `g_real_open_has_mode == 1`; `g_real_open_mode == 0600`.
 * - Relative path: matched and stored path equals `CWD + "/relative-open.bin"`.
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
    assert(g_fdcache_store_calls == 1);
    assert(strcmp(g_last_store_path, "/tmp/latency.bin") == 0);

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
    assert(strcmp(g_last_store_path, expected_path) == 0);
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
    assert(strcmp(g_last_store_path, expected_path) == 0);
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
    assert(strcmp(g_last_store_path, "/tmp/openat-base/child.bin") == 0);
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
 * - `corrupt_iovecs` with two 4-byte segments and size=3: exactly one call; `last_corrupt_sample_size == 3`.
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
 * - Guard bypass: real sendfile called immediately; guard captured as 1; `g_real_sendfile_out_fd == 8`;
 *   `g_real_sendfile_in_fd == 4`; offset pointer forwarded.
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
 * - LATENCY: `g_latency_calls == 1`; `g_real_copy_file_range_flags == 7` (non-zero flags preserved).
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
 * - Passthrough pwritev: `g_real_pwritev_calls == 1`; guard == 1; offset == 17; iov lengths captured.
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
    assert(g_fdcache_invalidate_calls == 0);

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
    assert(g_real_close_calls == 0);

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

int main(void)
{
    test_resolve_symbol_and_seed_material();
    test_call_real_open_and_match_fd_rule();
    test_init_runtime();
    test_open_wrapper();
    test_openat_wrapper();
    test_fsops_helpers_and_wrappers();
    test_read_and_write_wrappers();
    test_vectored_helpers();
    test_readv_and_writev_wrappers();
#ifdef __linux__
    test_sendfile_wrapper();
    test_copy_file_range_wrapper();
#endif
    test_preadv_and_pwritev_wrappers();
    test_close_sync_and_positioned_wrappers();
    chaos_test_bind_libc_functions_for_exit();
    return 0;
}
