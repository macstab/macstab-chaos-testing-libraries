/**
 * @file test_chaos_io.c
 * @brief Proves the libchaos-io wrapper layer: symbol resolution and the constructor,
 *        path resolution and normalisation, and every wrapper's decision to pass
 *        through, delay, fail, tear or corrupt, together with its fd-cache bookkeeping.
 *
 * @details Units under test, compiled in through `test_chaos_io_harness.h`:
 * `src/core/chaos_io.c` and the wrappers in `src/wrappers/chaos_io_{open,rw,fsops,sync,
 * stdio}.c`.
 *
 * Isolation:
 * - The harness replaces the config, fd-cache and effect modules with recording stubs
 *   (call counters, configurable results, captured arguments), so each test states which
 *   rule matched and which effect fires and asserts exactly what the wrapper did, without
 *   a rule file or a PRNG.
 * - The real functions (`g_chaos_io_real_*`) point at stubs that record their arguments
 *   and the TLS guard value seen during the call; the guard must be 1 there, proving the
 *   wrapper cannot re-enter itself through the real function.
 * - `dlsym`, `dlerror`, `abort`, `syscall` and the process_vm_readv seam are redefined;
 *   `CHAOS_IO_SYSCALL` is defined here to the real system call so the unresolved-symbol
 *   fallbacks act on real files.
 * - Every test starts with `chaos_test_reset_state()`; `main()` rebinds the C library
 *   before returning because the exit path writes and closes through these wrappers.
 *
 * Not covered here: dynamic-linker interposition of the built .so (runtime suites), real
 * partial transfers and EINTR from the kernel, and reload on real rule-file changes
 * (test_config_parse.c).
 */

#include <stdarg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/**
 * @brief The real syscall(2), for the fallbacks a wrapper takes while its symbol is
 *        unresolved; the harness redefines the wrappers' own `syscall` as a stub.
 */
static long chaos_test_raw_syscall(long number, ...)
{
    va_list args;
    long arguments[6];
    int index;

    va_start(args, number);
    for (index = 0; index < 6; ++index)
    {
        arguments[index] = va_arg(args, long);
    }
    va_end(args);
    return syscall(
        number, arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]
    );
}
#define CHAOS_IO_SYSCALL chaos_test_raw_syscall

#include "../support/test_chaos_io_harness.h"

#include <dirent.h>
#include <sys/resource.h>

/**
 * @brief Symbol resolution and seed material.
 *
 * @details A resolved symbol is stored; a symbol dlsym cannot find aborts (the library
 * could not even pass calls through), caught here with setjmp. The seed is 8 bytes from
 * /dev/urandom read with raw system calls under the guard; a short read or a failed open
 * falls back to 0x6a09e667f3bcc909 ^ pid, and an opened descriptor is always closed.
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
 * @brief Real-open helpers, path helpers, and fd rule matching.
 *
 * @details The real open/openat run under the guard and receive a mode only with
 * O_CREAT. copy/join/getcwd/resolve_at reject NULL, zero sizes and results that do not
 * fit, rather than truncating; a relative path joins the cwd, or the fd-cache path of the
 * dirfd. chaos_io_match_fd_rule() needs a loaded rule set (prepare), a resolvable fd
 * (fd 0-2 never are) and a matching rule, in that order.
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
    /* A result that does not fit is rejected, never truncated: absolute and cwd-joined. */
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
 * @brief The constructor resolves every real function, seeds the process and this
 *        thread's PRNG from the seed material, initialises the config once, loads the
 *        rule file once (so a bad file is reported at start-up) and resets the fd cache.
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
 * @brief Path rule helpers and the ftruncate, fallocate, unlinkat and renameat wrappers.
 *
 * @details Path matching skips NULL, /proc and every library's control files
 * (`/tmp/.chaos-<lib>.*`) before any rule lookup. A rename matches rename_from on the
 * source and rename_to on the destination (an excluded side is skipped). Each wrapper
 * passes through under the guard, delays and then calls the real function under LATENCY,
 * and fails with the rule's errno without the real call under ERRNO. A successful
 * unlinkat or renameat resets the whole fd cache (a namespace change can make any cached
 * path stale); a failed or faulted one does not.
 */
static void test_fsops_helpers_and_wrappers(void)
{
    chaos_io_rule_t rule;

    chaos_test_reset_state();
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, NULL, &rule) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/tmp/unlink.bin", NULL) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/proc/self/maps", &rule) == 0);
    /* Every library's control files are excluded, not only io's own rule file. */
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, "/tmp/.chaos-io.conf", &rule) == 0);
    assert(chaos_io_match_loaded_path_rule(CHAOS_IO_OP_OPEN, "/tmp/.chaos-net.conf", &rule) == 0);
    assert(
        chaos_io_match_loaded_path_rule(CHAOS_IO_OP_WRITE, "/tmp/.chaos-dns.hits.42", &rule) == 0
    );
    assert(g_config_match_loaded_calls == 0);
    assert(chaos_io_is_excluded_path("/tmp/.chaos") == 0);
    assert(chaos_io_is_excluded_path("/tmp/.chaosx.conf") == 0);
    assert(chaos_io_is_excluded_path(NULL) == 1);
    assert(chaos_io_is_excluded_path("") == 1);
    assert(chaos_io_is_excluded_path("/tmp/.chaos-io.conf") == 1);
    assert(chaos_io_is_excluded_path("/tmp/.chaos-net.hits.7") == 1);
    assert(chaos_io_has_reserved_prefix(NULL, "/proc") == 0);
    assert(chaos_io_has_reserved_prefix("/proc", NULL) == 0);

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
 * @brief open(): guard and /proc bypass, LATENCY, ERRNO, mode forwarding, relative and
 *        unnormalised paths.
 *
 * @details Under the guard or for /proc no rule is looked up and nothing is cached.
 * LATENCY delays then opens; the new descriptor's cache entry is invalidated and resolved
 * from the kernel, never stored under the caller's string (which may differ from the
 * kernel's name). ERRNO fails without opening. A relative path is matched joined to the
 * cwd; `.`, `..` and `//` are normalised before matching.
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
    /* The new descriptor is cached under the kernel's name for it, never under a stale
     * entry of an earlier descriptor with that number. */
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

    /* Matched as the kernel resolves it: `.`, `..` and repeated slashes removed. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_open_return = 18;
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_LATENCY;
    assert(open("/tmp/pd/./x//../data/f", O_RDONLY) == 18);
    assert(strcmp(g_last_match_path, "/tmp/pd/data/f") == 0);
}

/**
 * @brief Lexical normalisation: one slash between components, no `.`, `..` removes the
 *        preceding component and stops at the root, no trailing slash; names that merely
 *        start with dots are kept, relative paths are left alone, NULL is ignored.
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
        {"/tmp/.x/.y", "/tmp/.x/.y"},
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
 * @brief openat(): guard bypass, path resolution through the cwd or the dirfd's cached
 *        path, ERRNO, and mode forwarding.
 *
 * @details The real call always receives the caller's dirfd and relative path; only the
 * matched string is resolved. When the dirfd cannot be resolved no rule is looked up,
 * yet the new descriptor is still refreshed from the kernel (2 resolutions, no store).
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
 * @brief read() and write(): passthrough under the guard, CORRUPT on the bytes actually
 *        read, TORN writing only the torn count, LATENCY then the real call, ERRNO
 *        without the real call.
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
 * @brief iovec helpers.
 *
 * @details total_bytes rejects NULL, a zero count and totals above SSIZE_MAX; trim clips
 * a vector to a byte budget; build_torn rejects a torn count of 0 or >= the total and an
 * empty vector; corrupt_iovecs ignores NULL/zero input and routes the flip to the segment
 * that holds the chosen byte (a seed drawing an odd index lands in the second segment).
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

    /* Search for a seed whose first draw is odd, so the flip lands in the second of two
     * 1-byte segments; the bound of 256 seeds keeps the search finite. */
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
 * @brief readv() and writev(): passthrough with the iovec layout intact, CORRUPT on the
 *        read data, TORN as a trimmed copy of the vector (6 bytes torn to 3 gives lengths
 *        2 and 1), a zero-count vector written unchanged, LATENCY, and ERRNO without the
 *        real call.
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

/** @brief Arms a matching rule with @p effect on fd 9 (path /tmp/vector.bin). */
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
 * @brief The caller's iovec array is read only after a rule matched, never past IOV_MAX
 *        entries, and only through a checked copy; an unreadable array reaches the kernel
 *        unchanged instead of faulting the wrapper.
 *
 * @details No match: no copy at all. LATENCY: `call_size` is the byte total, also across
 * copy chunks of 64 entries. An unreadable array (EFAULT), a negative or > IOV_MAX count,
 * or a total past SSIZE_MAX gives an unknown size and passes the caller's own arguments
 * and errno through. If the checked copy is unavailable (ENOSYS, EPERM) the array is
 * copied directly. TORN on an unreadable array or one longer than 64 entries writes the
 * vector whole and does not count a hit; exactly 64 entries are torn.
 */
static void test_vectored_input_checks(void)
{
    static struct iovec many[CHAOS_IO_TORN_MAX_IOV + 36];
    static char bytes[CHAOS_IO_TORN_MAX_IOV + 36];
    struct iovec pair[CHAOS_TEST_IOV_SNAPSHOT_COUNT]; /* the stubs snapshot this many */
    int index;
    /* Called through a pointer: libc's fortify attributes would reject the invalid
     * arguments at compile time. */
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

    /* The first chunk of 64 sums to exactly SSIZE_MAX; the second chunk overflows it. */
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
 * @brief sendfile(): guard bypass with all arguments forwarded; matched as a write to the
 *        output fd; TORN sends the torn count, LATENCY then the real call, ERRNO without it.
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
 * @brief copy_file_range(): guard bypass with fds, offset pointers and flags forwarded;
 *        matched as a write to the output fd; TORN, LATENCY (non-zero flags kept), ERRNO.
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
 * @brief preadv() and pwritev(): the offset reaches the real call in every mode; CORRUPT
 *        on read data, TORN as a trimmed vector matched as pwrite, a zero-count vector
 *        written unchanged, LATENCY, and ERRNO without the real call.
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
 * @brief close(), fsync(), fdatasync(), pread() and pwrite().
 *
 * @details close() always invalidates the fd's cache entry once the real close ran, also
 * when it failed (Linux releases the descriptor even then). An ERRNO rule on close runs
 * the real close first and then reports the injected error, as Linux reports a deferred
 * EIO. fsync/fdatasync honour LATENCY and ERRNO. pread/pwrite bypass under the guard and
 * forward the offset under CORRUPT and TORN.
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
    /* Linux releases the descriptor even when close reports an error: invalidate anyway. */
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
    /* The injected error is reported after a real close, as Linux reports a deferred EIO;
     * failing without closing would leak the descriptor. */
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
 * @brief Regression: wrappers reached before the constructor resolve their symbols
 *        instead of calling through NULL.
 *
 * @details LD_PRELOAD maps this object first, but ELF initialisers run in dependency
 * order, so another library's constructor can call an interposed symbol before
 * chaos_io_init(). libcap-ng's initialiser does file I/O, which made every setpriv, su
 * and runuser under libchaos-io crash with SIGSEGV. Each case restores the
 * pre-constructor state (`chaos_test_reset_state()` clears the pointer table and the
 * once-control) and calls one wrapper; resolution is idempotent.
 */
static void test_wrappers_resolve_symbols_before_constructor(void)
{
    char buffer[4];
    ssize_t transferred;
    int rc;

    /* Results are captured rather than cast to void: glibc marks read() and write()
     * warn_unused_result, which a (void) cast does not silence under GCC. The values are
     * irrelevant; the assertion is that the call resolved its symbol. */

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

    /* Resolution is idempotent: a second call neither re-resolves nor faults. */
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
 * @brief Calls chaos_io_ensure_symbols() 64 times and checks the table is fully published
 *        each time.
 *
 * @details A NULL pointer seen after the call returned means the "done" state became
 * visible before the pointer stores, which an unordered guard permits.
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
 * @brief Regression: concurrent first calls never observe a half-built symbol table.
 *
 * @details chaos_io_ensure_symbols() is reached from every wrapper on every thread, so
 * its once-control (chaos_once.h) must order the pointer stores before the "done" state
 * with release/acquire semantics; a plain volatile flag would let another thread on a
 * weakly ordered CPU see "done" and call through NULL. Eight threads race on it. A pass
 * cannot prove the absence of a race, but the test fails when the guard publishes
 * readiness without ordering the stores.
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
/** @brief Calls of the stand-in overflow handler of the fortified variants. */
static int g_chk_fail_calls = 0;

/** @brief Stands in for glibc's `__chk_fail()`, which would abort the test. */
static void chaos_test_chk_fail(void)
{
    ++g_chk_fail_calls;
}

/**
 * @brief glibc's alternate entry points run the same wrappers.
 *
 * @details Every *64 large-file name is the base wrapper itself (same address, an alias).
 * A fortified call within its declared buffer reaches the real function; one beyond it,
 * or __open_2()/__openat_2() with flags that need a mode, goes to the overflow handler
 * and never reaches the real function.
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
    /* The declared buffer size is the check's input: a count beyond it trips the check
     * without writing past the real buffer, which the compiler would reject. */
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
 * @brief Releases what the closedir/pclose test opened, through the C library's own
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

/**
 * @brief Calls that free or reassign a descriptor drop its cache entry.
 *
 * @details A successful dup2/dup3 invalidates the target; dup2 onto itself and a failed
 * call invalidate nothing. A successful close_range invalidates each fd of a narrow range
 * and resets the whole cache for a wide one; CLOSE_RANGE_CLOEXEC, a reversed range and a
 * failure invalidate nothing; without a real close_range the wrapper fails with ENOSYS.
 * closedir/pclose invalidate their stream's fd and keep errno; closefrom resets the cache
 * and, without closefrom in libc, falls back to close_range, else closes each fd up to
 * RLIMIT_NOFILE (16 here, so fds 10..15: 6 closes).
 */
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

    /* Descriptors the C library closes with its own system calls are forgotten too. */
    {
        /* Through pointers: the compiler knows these free their argument and would warn
         * about the later use. */
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

        /* Without closefrom in libc: close_range, else one close per descriptor. */
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
 * @brief The path forms reach the same rules as the descriptor and *at forms.
 *
 * @details unlink and rmdir go to the real unlinkat (rmdir with AT_REMOVEDIR) under the
 * unlink rules; rename to renameat under the rename rules; creat to open with
 * O_CREAT|O_WRONLY|O_TRUNC under the open rules. truncate matches by path. remove()
 * unlinks and retries with AT_REMOVEDIR on EISDIR. renameat2 passes flags through, resets
 * the cache on success and, without renameat2 in libc, makes the system call.
 * posix_fallocate follows the allocate rules but returns the error number and leaves
 * errno untouched, as POSIX specifies.
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
    /* Without renameat2 in the C library: the system call itself. */
    assert(renameat2(AT_FDCWD, "/tmp/path-form.a", AT_FDCWD, "/tmp/path-form.b", 0U) == 0);
    assert(g_sys_renameat2_calls == 1);

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
 * @brief fopen() and freopen() follow the open rules.
 *
 * @details ERRNO makes fopen() return NULL without the real call. Under ERRNO freopen()
 * still calls the real freopen() with an empty path, so the C library closes the stream
 * its own way, then returns NULL with the rule's errno. LATENCY delays then opens; an
 * unmatched path, the guard and a NULL freopen() path reach the real call unchanged.
 * fopen64/freopen64 are the same wrappers.
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
 * @brief Data-moving wrappers pass the call's byte count to the matched rule for `@size`:
 *        the count argument, the iovec total, the fallocate length; an empty vector has
 *        no size.
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

/** @brief Arms the stubs so every stdio stream with a descriptor matches a rule of @p effect. */
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
 * @brief stdio wrappers apply the read/write rules to the stream's descriptor.
 *
 * @details ERRNO fails each form with its own C library failure value and sets the
 * stream's error indicator; LATENCY delays then runs the real call; CORRUPT flips the
 * data a read returned and leaves an empty result alone. The standard streams, streams
 * without a descriptor (fmemopen) and calls without a rule pass through. Without the
 * fortified functions in libc the plain ones run. A size that overflows count * size has
 * no byte count.
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

    /* ERRNO: every form fails with its C library failure value and sets ferror. */
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

    /* Byte counts for `@size`: size * count, none (CHAOS_POLICY_NO_SIZE) on overflow. */
    assert(chaos_io_stdio_size(4U, 3U) == 12U);
    assert(chaos_io_stdio_size(SIZE_MAX, 3U) == CHAOS_POLICY_NO_SIZE);
    assert(chaos_io_stdio_size(0U, 3U) == 0U);
    free(line);
}

/**
 * @brief Streams keep the fd cache right, and stdio lookups leave errno alone.
 *
 * @details fopen and freopen drop the entry of the stream's descriptor and resolve it from
 * the kernel; freopen with a NULL path keeps the file and changes nothing; a stream
 * without a descriptor is never cached; under the guard nothing is cached or dropped;
 * fclose drops the entry; a passthrough call on a descriptor-less stream keeps errno.
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

/**
 * @brief Path filters exclude the control files and the /proc, /sys and /dev trees at a
 *        path boundary only (`/process`, `/system`, `/devices` are not excluded); a join
 *        inserts exactly one separator and fails one byte short; a zero seed is replaced
 *        (xorshift would stay at 0 forever), and maps to the same state as seed 1.
 */
static void test_path_filters_join_and_seed(void)
{
    char path[16];
    uint64_t state_of_zero;

    assert(!chaos_io_is_control_path(NULL));
    assert(chaos_io_is_control_path("/tmp/.chaos-dns.status"));
    assert(chaos_io_has_reserved_prefix("/proc", "/proc"));
    assert(chaos_io_has_reserved_prefix("/proc/self/fd/3", "/proc"));
    assert(!chaos_io_has_reserved_prefix("/process", "/proc"));
    assert(!chaos_io_has_reserved_prefix("/tmp", "/proc"));
    assert(chaos_io_is_excluded_path("/proc"));
    assert(chaos_io_is_excluded_path("/sys/kernel/mm"));
    assert(chaos_io_is_excluded_path("/dev/null"));
    assert(chaos_io_is_excluded_path("/dev"));
    assert(!chaos_io_is_excluded_path("/system/x"));
    assert(!chaos_io_is_excluded_path("/devices/x"));
    assert(!chaos_io_is_excluded_path("/tmp/data.bin"));

    /* A base that ends in a slash gets no second one. */
    assert(chaos_io_join_paths(path, sizeof(path), "/tmp/", "f") == 1);
    assert(strcmp(path, "/tmp/f") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), NULL, "f") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), "/tmp", NULL) == 0);
    assert(chaos_io_join_paths(path, 0U, "/tmp", "f") == 0);
    /* "/tmp" "/" "f1" and the NUL: 8 bytes fit exactly, 7 do not. */
    assert(chaos_io_join_paths(path, 8U, "/tmp", "f1") == 1);
    assert(strcmp(path, "/tmp/f1") == 0);
    assert(chaos_io_join_paths(path, 7U, "/tmp", "f1") == 0);

    chaos_io_prng_seed_thread(0U);
    state_of_zero = g_chaos_io_tls_prng_state;
    assert(state_of_zero != 0U);
    chaos_io_prng_seed_thread(1U);
    assert(g_chaos_io_tls_prng_state == state_of_zero);
}

/* rmdir() and unlinkat() here are the wrappers over the harness stubs, and syscall() is
 * the harness's stand-in: removing a directory for real needs the raw system call. */
#undef syscall
/** @brief Removes the empty directory @p path for real; 0 on success. */
static int chaos_test_remove_directory(const char *path)
{
    return (int)syscall(SYS_unlinkat, AT_FDCWD, path, AT_REMOVEDIR);
}
#define syscall chaos_test_syscall

/**
 * @brief A path that cannot be resolved for matching is never matched, and the call still
 *        reaches the real function unchanged (fail-open).
 *
 * @details Cases: a removed working directory (getcwd fails; errno preserved), a dirfd
 * whose cached path leaves no room for the child, an absolute path longer than
 * CHAOS_IO_MAX_PATH (open and fopen), and /proc through openat.
 */
static void test_unresolvable_paths_pass_through(void)
{
    static char long_path[CHAOS_IO_MAX_PATH + 16U];
    char cwd[CHAOS_IO_MAX_PATH];
    char removed[] = "/tmp/chaos-io-cwd-XXXXXX";
    char path[CHAOS_IO_MAX_PATH];

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(mkdtemp(removed) != NULL);
    assert(chdir(removed) == 0 && chaos_test_remove_directory(removed) == 0);
    errno = 4242;
    assert(chaos_io_resolve_at_path(AT_FDCWD, "relative.bin", path, sizeof(path)) == 0);
    assert(errno == 4242);
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_rule_apply_errno_result = 1;
    g_real_open_return = 5;
    assert(open("relative.bin", O_RDONLY) == 5);
    assert(g_config_match_path_calls == 0);
    assert(chdir(cwd) == 0);

    /* The directory's path fits, the joined one does not. */
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/base");
    assert(chaos_io_resolve_at_path(9, "child.bin", path, 12U) == 0);

    (void)memset(long_path, 'a', sizeof(long_path) - 1U);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1U] = '\0';
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_rule_apply_errno_result = 1;
    g_real_open_return = -1;
    g_real_fopen_return = NULL;
    assert(open(long_path, O_RDONLY) == -1);
    assert(fopen(long_path, "r") == NULL);
    assert(g_real_open_calls == 1 && g_real_fopen_calls == 1);
    assert(g_config_match_path_calls == 0);

    /* openat() never looks /proc up. */
    g_real_openat_return = 6;
    assert(openat(AT_FDCWD, "/proc/self/status", O_RDONLY) == 6);
    assert(g_config_match_path_calls == 0);
}

/**
 * @brief An open rule that matched but whose probability missed opens the file; O_TMPFILE
 *        forwards a mode like O_CREAT; a failed real fopen/freopen caches nothing.
 */
static void test_open_rule_that_does_not_fire(void)
{
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_config_match_path_result = 1;
    g_config_rule.effect = CHAOS_IO_EFFECT_ERRNO;
    g_config_rule.errnum = EACCES;
    g_rule_apply_errno_result = 0;
    g_real_open_return = 7;
    g_real_openat_return = 8;
    assert(open("/tmp/unlucky.bin", O_RDONLY) == 7);
    assert(openat(AT_FDCWD, "/tmp/unlucky.bin", O_RDONLY) == 8);
    assert(g_rule_apply_errno_calls == 2);
    assert(g_config_match_path_calls == 2);

#ifdef O_TMPFILE
    g_config_match_path_result = 0;
    assert(openat(AT_FDCWD, "/tmp", O_TMPFILE | O_RDWR, 0600) == 8);
    assert(g_real_openat_has_mode == 1 && g_real_openat_mode == 0600);
#endif

    /* A failed real fopen()/freopen() caches nothing. */
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_fopen_return = NULL;
    assert(fopen("/tmp/missing/file", "r") == NULL);
    assert(freopen("/tmp/missing/file", "r", stdin) == NULL);
    assert(g_fdcache_invalidate_calls == 0 && g_fdcache_resolve_calls == 0);
}

/**
 * @brief Under the reentrancy guard every descriptor and path wrapper calls the real
 *        function at once: no rule lookup, no fd resolution, no effect, offset untouched.
 */
static void test_descriptor_wrappers_under_guard(void)
{
    char buffer[8] = {0};
    struct iovec iov[1];
    off_t offset = 0;

    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_config_match_path_result = 1;
    g_rule_apply_errno_result = 1;
    g_real_read_return = 1;
    g_real_readv_return = 2;
    g_real_write_return = 3;
    g_real_writev_return = 4;
    g_real_pread_return = 5;
    g_real_preadv_return = 6;
    g_real_pwrite_return = 7;
    g_real_pwritev_return = 8;
    g_real_sendfile_return = 9;
    g_real_copy_file_range_return = 10;

    g_chaos_io_tls_guard = 1;
    assert(read(9, buffer, 1U) == 1);
    assert(readv(9, iov, 1) == 2);
    assert(write(9, buffer, 3U) == 3);
    assert(writev(9, iov, 1) == 4);
    assert(pread(9, buffer, 5U, 0) == 5);
    assert(preadv(9, iov, 1, 0) == 6);
    assert(pwrite(9, buffer, 7U, 0) == 7);
    assert(pwritev(9, iov, 1, 0) == 8);
#ifdef __linux__
    assert(sendfile(9, 4, &offset, 9U) == 9);
    assert(copy_file_range(4, NULL, 9, NULL, 10U, 0U) == 10);
    assert(fallocate(9, 0, 0, 16) == 0);
#endif
    assert(ftruncate(9, 16) == 0);
    assert(posix_fallocate(9, 0, 16) == 0);
    assert(truncate("/tmp/guarded.bin", 16) == 0);
    assert(unlinkat(AT_FDCWD, "/tmp/guarded.bin", 0) == 0);
    assert(renameat(AT_FDCWD, "/tmp/a.bin", AT_FDCWD, "/tmp/b.bin") == 0);
    assert(fsync(9) == 0);
    assert(fdatasync(9) == 0);
    assert(close(9) == 0);
    g_chaos_io_tls_guard = 0;

    assert(g_config_match_loaded_calls == 0);
    assert(g_config_match_path_calls == 0);
    assert(g_fdcache_resolve_calls == 0);
    assert(g_rule_apply_errno_calls == 0);
    assert(g_real_read_guard == 1 && g_real_write_guard == 1 && g_real_close_guard == 1);
    assert(offset == 0);
}

/**
 * @brief A rule that matched but does not fire leaves the call exactly as the real
 *        function made it.
 *
 * @details Covered: ERRNO whose probability missed (also neither failing nor tearing
 * writes), no rule for the descriptor, CORRUPT at end of file (nothing read, nothing
 * checked), CORRUPT and TORN that did not trigger, TORN with a torn count of 0, and a
 * real unlink/rename that failed after LATENCY (no cache reset, the namespace did not
 * change).
 */
static void test_rules_that_do_not_fire(void)
{
    char buffer[8];
    struct iovec iov[2];

    iov[0].iov_base = buffer;
    iov[0].iov_len = 4U;
    iov[1].iov_base = buffer + 4;
    iov[1].iov_len = 4U;

    /* ERRNO whose probability missed: every wrapper runs the real call. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_config_match_path_result = 1;
    g_config_rule.errnum = EIO;
    g_rule_apply_errno_result = 0;
    g_real_writev_return = 8;
    g_real_close_return = 0;
    assert(writev(9, iov, 2) == 8);
    assert(ftruncate(9, 1) == 0);
#ifdef __linux__
    assert(fallocate(9, 0, 0, 1) == 0);
#endif
    assert(truncate("/tmp/unlucky.bin", 1) == 0);
    assert(unlinkat(AT_FDCWD, "/tmp/unlucky.bin", 0) == 0);
    assert(renameat(AT_FDCWD, "/tmp/a.bin", AT_FDCWD, "/tmp/b.bin") == 0);
    assert(renameat2(AT_FDCWD, "/tmp/a.bin", AT_FDCWD, "/tmp/b.bin", 0U) == 0);
    assert(fsync(9) == 0);
    assert(fdatasync(9) == 0);
    assert(close(9) == 0);
#ifdef __linux__
    assert(g_rule_apply_errno_calls == 10);
#else
    assert(g_rule_apply_errno_calls == 9);
#endif
    assert(g_real_writev_calls == 1 && g_real_ftruncate_calls == 1 && g_real_truncate_calls == 1);
    assert(g_real_unlinkat_calls == 1 && g_real_renameat_calls == 1);
    assert(g_real_fsync_calls == 1 && g_real_fdatasync_calls == 1 && g_real_close_calls == 1);
    /* Each real success that changes the namespace (unlinkat, renameat, renameat2) reset
     * the cache. */
    assert(g_fdcache_reset_calls == 3);

    /* Writes under an ERRNO rule that missed are neither failed nor torn. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_rule_apply_errno_result = 0;
    g_torn_count_result = 1U;
    g_real_write_return = 8;
    g_real_pwrite_return = 8;
    g_real_pwritev_return = 8;
    assert(write(9, buffer, 8U) == 8 && g_real_write_count == 8U);
    assert(pwrite(9, buffer, 8U, 0) == 8 && g_real_pwrite_count == 8U);
    assert(pwritev(9, iov, 2, 0) == 8 && g_real_pwritev_iovcnt == 2);
#ifdef __linux__
    g_real_sendfile_return = 8;
    g_real_copy_file_range_return = 8;
    assert(sendfile(9, 4, NULL, 8U) == 8 && g_real_sendfile_count == 8U);
    assert(copy_file_range(4, NULL, 9, NULL, 8U, 0U) == 8);
    assert(g_real_copy_file_range_count == 8U);
    assert(g_rule_apply_errno_calls == 5);
#endif
    assert(g_rule_should_trigger_calls == 0);

    /* No rule for the descriptor: the call goes through untouched. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_config_match_loaded_result = 0;
    g_rule_apply_errno_result = 1;
    g_real_pwrite_return = 8;
    assert(pwrite(9, buffer, 8U, 0) == 8);
#ifdef __linux__
    g_real_sendfile_return = 8;
    g_real_copy_file_range_return = 8;
    assert(sendfile(9, 4, NULL, 8U) == 8);
    assert(copy_file_range(4, NULL, 9, NULL, 8U, 0U) == 8);
#endif
    assert(g_rule_apply_errno_calls == 0);

    /* CORRUPT at end of file: nothing was read, nothing is corrupted. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_CORRUPT);
    g_real_read_return = 0;
    g_real_pread_return = 0;
    assert(read(9, buffer, 4U) == 0);
    assert(pread(9, buffer, 4U, 0) == 0);
    assert(g_rule_should_trigger_calls == 0 && g_corrupt_calls == 0);

    /* CORRUPT that did not trigger: the data comes back as read. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_CORRUPT);
    g_rule_should_trigger_result = 0;
    g_real_read_return = 4;
    g_real_readv_return = 4;
    g_real_pread_return = 4;
    g_real_preadv_return = 4;
    assert(read(9, buffer, 4U) == 4);
    assert(readv(9, iov, 2) == 4);
    assert(pread(9, buffer, 4U, 0) == 4);
    assert(preadv(9, iov, 2, 0) == 4);
    assert(g_rule_should_trigger_calls == 4);
    assert(g_corrupt_calls == 0 && g_corrupt_sample_calls == 0);

    /* TORN that did not trigger: the full count is written. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_TORN);
    g_rule_should_trigger_result = 0;
    g_torn_count_result = 1U;
    g_real_write_return = 8;
    g_real_writev_return = 8;
    g_real_pwrite_return = 8;
    assert(write(9, buffer, 8U) == 8 && g_real_write_count == 8U);
    assert(pwrite(9, buffer, 8U, 0) == 8 && g_real_pwrite_count == 8U);
    assert(writev(9, iov, 2) == 8);
    assert(g_real_writev_iovcnt == 2 && g_real_writev_lengths[1] == 4U);
    g_real_pwritev_return = 8;
    assert(pwritev(9, iov, 2, 0) == 8);
    assert(g_real_pwritev_iovcnt == 2 && g_real_pwritev_lengths[1] == 4U);
#ifdef __linux__
    g_real_sendfile_return = 8;
    g_real_copy_file_range_return = 8;
    assert(sendfile(9, 4, NULL, 8U) == 8 && g_real_sendfile_count == 8U);
    assert(copy_file_range(4, NULL, 9, NULL, 8U, 0U) == 8);
    assert(g_real_copy_file_range_count == 8U);
#endif

    /* TORN that would tear nothing (a torn count of 0): the full vector is written. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_TORN);
    g_torn_count_result = 0U;
    g_real_writev_return = 8;
    g_real_pwritev_return = 8;
    assert(writev(9, iov, 2) == 8 && g_real_writev_iovcnt == 2);
    assert(pwritev(9, iov, 2, 0) == 8 && g_real_pwritev_iovcnt == 2);
    assert(g_rule_should_trigger_calls == 0);

    /* A real call that failed after a LATENCY rule: the namespace did not change. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_LATENCY);
    g_config_match_path_result = 1;
    g_real_unlinkat_return = -1;
    g_real_renameat_return = -1;
    assert(unlinkat(AT_FDCWD, "/tmp/missing.bin", 0) == -1);
    assert(renameat(AT_FDCWD, "/tmp/missing.bin", AT_FDCWD, "/tmp/b.bin") == -1);
    assert(g_latency_calls == 2);
    assert(g_fdcache_reset_calls == 0);
}

/**
 * @brief unlink, truncate and rename rules look only at resolvable, non-excluded paths,
 *        and only once rules are loaded; a rename with one resolvable side is matched on
 *        that side alone, with neither side resolvable no rule is consulted.
 */
static void test_unlink_and_rename_matching_inputs(void)
{
    static char long_path[CHAOS_IO_MAX_PATH + 16U];
    chaos_io_rule_t rule;

    (void)memset(long_path, 'b', sizeof(long_path) - 1U);
    long_path[0] = '/';
    long_path[sizeof(long_path) - 1U] = '\0';

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_rule_apply_errno_result = 1;
    assert(unlinkat(AT_FDCWD, "/proc/self/fd/9", 0) == 0);
    assert(unlinkat(AT_FDCWD, long_path, 0) == 0);
    g_config_prepare_result = 0;
    assert(unlinkat(AT_FDCWD, "/tmp/data.bin", 0) == 0);
    assert(g_config_match_loaded_calls == 0);
    assert(g_real_unlinkat_calls == 3);

    /* truncate(): the same filters before its path rule. */
    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    g_config_match_path_result = 1;
    g_rule_apply_errno_result = 1;
    assert(truncate("/proc/self/status", 0) == 0);
    assert(truncate(long_path, 0) == 0);
    assert(g_config_match_path_calls == 0);
    assert(g_real_truncate_calls == 2);

    chaos_test_arm_vector_rule(CHAOS_IO_EFFECT_ERRNO);
    assert(chaos_io_match_rename_rule(AT_FDCWD, long_path, AT_FDCWD, long_path, &rule) == 0);
    assert(g_config_prepare_calls == 0);
    assert(chaos_io_match_rename_rule(AT_FDCWD, long_path, AT_FDCWD, "/tmp/to.bin", &rule) == 1);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_TO);
    assert(g_config_match_loaded_calls == 1);
    assert(chaos_io_match_rename_rule(AT_FDCWD, "/tmp/from.bin", AT_FDCWD, long_path, &rule) == 1);
    assert(g_last_match_loaded_operation == CHAOS_IO_OP_RENAME_FROM);
    assert(strcmp(g_last_match_loaded_path, "/tmp/from.bin") == 0);
    assert(g_config_match_loaded_calls == 2);
}

/**
 * @brief Empty segments are kept by trimming and skipped by corruption; a vector whose
 *        total does not fit ssize_t is neither torn nor given a size.
 */
static void test_vectored_edge_segments(void)
{
    struct iovec source[3];
    struct iovec target[3];
    char bytes[4] = {'a', 'b', 'c', 'd'};
    int target_count = 0;

    /* An empty segment inside the budget is kept, empty. */
    source[0].iov_base = bytes;
    source[0].iov_len = 0U;
    source[1].iov_base = bytes;
    source[1].iov_len = 4U;
    assert(chaos_io_trim_iovecs(source, 2, 3U, target, &target_count) == 1);
    assert(target_count == 2);
    assert(target[0].iov_len == 0U && target[1].iov_len == 3U);

    /* Corruption lands in the segment that holds the bytes, past the empty one. */
    chaos_test_reset_state();
    chaos_io_corrupt_iovecs(source, 2, 4U);
    assert(g_corrupt_sample_calls == 1);
    assert(g_last_corrupt_sample_size == 4U);

    /* Two segments of SSIZE_MAX bytes: no total, no torn view, no size. */
    source[0].iov_len = (size_t)SSIZE_MAX;
    source[1].iov_len = (size_t)SSIZE_MAX;
    g_torn_count_result = 1U;
    assert(chaos_io_build_torn_iovecs(source, 2, target, &target_count) == 0);
    assert(chaos_io_iovec_size(source, 2) == CHAOS_POLICY_NO_SIZE);
}

/**
 * @brief close_range() invalidates each fd of a narrow range up to INT_MAX and stops there
 *        (no descriptor number exceeds INT_MAX), without wrapping or resetting the cache.
 */
static void test_close_range_at_int_max(void)
{
    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    g_real_dup_return = 0;
    assert(close_range((unsigned int)INT_MAX - 1U, (unsigned int)INT_MAX + 1U, 0) == 0);
    assert(g_fdcache_invalidate_calls == 2);
    assert(g_last_invalidate_fd == INT_MAX);
    assert(g_fdcache_reset_calls == 0);
}

/**
 * @brief stdio calls under a rule that does not fail them run the real function: LATENCY
 *        on the write forms, ERRNO whose probability missed, fortified reads without
 *        their libc variants, CORRUPT at end of file; fgets with no room has no byte count.
 */
static void test_stdio_rules_that_do_not_fail(void)
{
    char buffer[16];
    char *line = NULL;
    size_t capacity = 0U;
    FILE *stream;

    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_LATENCY);
    assert(fputs("x", stream) >= 0);
    assert(fputc('y', stream) == 'y');
    assert(fflush(stream) == 0);
    assert(fprintf(stream, "%d", 7) == 1);
    assert(g_latency_calls == 4);
    /* fgets() with no room: the C library refuses it; no byte count for `@size`. */
    errno = 0;
    assert(fgets(buffer, 0, stream) == NULL);
    assert(g_latency_calls == 5 && g_last_call_size == CHAOS_POLICY_NO_SIZE);
#if defined(__GLIBC__) && defined(__LP64__)
    assert(__fgets_chk(buffer, sizeof(buffer), 0, stream) == NULL);
    assert(g_latency_calls == 6 && g_last_call_size == CHAOS_POLICY_NO_SIZE);
#endif
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_ERRNO);
    g_rule_apply_errno_result = 0;
    assert(fread(buffer, 1U, 4U, stream) == 4U && !ferror(stream));
    assert(fwrite("z", 1U, 1U, stream) == 1U);
    assert(g_rule_apply_errno_calls == 2);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    /* A C library without the fortified reads: a matched call runs the plain one. */
    stream = chaos_test_stdio_stream();
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_LATENCY);
    chaos_io_ensure_symbols();
    g_chaos_io_real_fread_chk = NULL;
    g_chaos_io_real_fgets_chk = NULL;
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 2U);
    assert(strncmp(buffer, "ab", 2U) == 0);
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == buffer);
    assert(strcmp(buffer, "c\n") == 0);
    assert(g_latency_calls == 2);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);

    stream = chaos_test_stdio_stream();
    assert(fseek(stream, 0L, SEEK_END) == 0);
    chaos_test_stdio_rule(CHAOS_IO_EFFECT_CORRUPT);
    assert(getline(&line, &capacity, stream) == -1);
    assert(g_corrupt_calls == 0);
    chaos_test_reset_state();
    assert(fclose(stream) == 0);
    free(line);
}

/** @brief Closes @p fd with the system call (the close wrapper reaches a stub here). */
static void chaos_test_raw_close(int fd)
{
    assert(chaos_test_raw_syscall(SYS_close, (long)fd) == 0);
}

/** @brief Size of the file at @p path, or -1. */
static long chaos_test_file_size(const char *path)
{
    struct stat info;

    return stat(path, &info) == 0 ? (long)info.st_size : -1L;
}

/**
 * @brief A wrapper whose real function is still unresolved (a call arriving during symbol
 *        resolution) makes the system call itself instead of calling through NULL.
 *
 * @details Every call acts on a real temporary file and is checked by its effect: bytes
 * written and read back, creation modes, dup2/dup3 semantics, sizes changed by truncate
 * and fallocate, kernel-side copies, rename and unlink. posix_fallocate returns its error
 * and keeps errno. closedir/pclose cannot be emulated (the stream belongs to libc) and
 * fail with ENOSYS.
 */
static void test_unresolved_symbols_use_system_calls(void)
{
    char path[] = "/tmp/chaos-io-unresolved-XXXXXX";
    char created[64];
    char moved[64];
    char buffer[16];
    struct iovec iov;
    struct stat info;
    int (*volatile closedir_wrapper)(DIR *) = closedir;
    int (*volatile pclose_wrapper)(FILE *) = pclose;
    int fd;
    int other;
    int copy;

    chaos_test_reset_state();
    chaos_test_bind_real_functions();
    chaos_io_ensure_symbols();
    fd = mkstemp(path);
    assert(fd >= 0);
    (void)snprintf(created, sizeof(created), "%s.created", path);
    (void)snprintf(moved, sizeof(moved), "%s.moved", path);

    /* Writes: "abcdef", then "XY" at 1, "gh" appended, "Z" at 0 -> "ZXYdefgh". */
    g_chaos_io_real_write = NULL;
    assert(write(fd, "abcdef", 6U) == 6);
    g_chaos_io_real_pwrite = NULL;
    assert(pwrite(fd, "XY", 2U, 1) == 2);
    g_chaos_io_real_writev = NULL;
    iov.iov_base = (void *)"gh";
    iov.iov_len = 2U;
    assert(writev(fd, &iov, 1) == 2);
    g_chaos_io_real_pwritev = NULL;
    iov.iov_base = (void *)"Z";
    iov.iov_len = 1U;
    assert(pwritev(fd, &iov, 1, 0) == 1);
    g_chaos_io_real_fsync = NULL;
    assert(fsync(fd) == 0);
    g_chaos_io_real_fdatasync = NULL;
    assert(fdatasync(fd) == 0);

    /* Opened for real, and read back. */
    g_chaos_io_real_open = NULL;
    other = open(path, O_RDONLY);
    assert(other >= 0);
    g_chaos_io_real_read = NULL;
    assert(read(other, buffer, 3U) == 3 && memcmp(buffer, "ZXY", 3U) == 0);
    g_chaos_io_real_pread = NULL;
    assert(pread(other, buffer, 2U, 6) == 2 && memcmp(buffer, "gh", 2U) == 0);
    g_chaos_io_real_readv = NULL;
    iov.iov_base = buffer;
    iov.iov_len = 3U;
    assert(readv(other, &iov, 1) == 3 && memcmp(buffer, "def", 3U) == 0);
    g_chaos_io_real_preadv = NULL;
    iov.iov_len = 2U;
    assert(preadv(other, &iov, 1, 1) == 2 && memcmp(buffer, "XY", 2U) == 0);
    g_chaos_io_real_close = NULL;
    assert(close(other) == 0);
    errno = 0;
    assert(close(other) == -1 && errno == EBADF);

    /* The creation mode reaches the kernel; without O_CREAT none is needed. */
    other = open(created, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(other >= 0);
    assert(fstat(other, &info) == 0 && (info.st_mode & 0777) == 0600);
    chaos_test_raw_close(other);
    g_chaos_io_real_openat = NULL;
    other = openat(AT_FDCWD, path, O_RDONLY);
    assert(other >= 0 && read(other, buffer, 1U) == 1 && buffer[0] == 'Z');
    chaos_test_raw_close(other);
    /* unlink() is a wrapper too, on a stub here. */
    assert(chaos_test_raw_syscall(SYS_unlinkat, (long)AT_FDCWD, (long)created, 0L) == 0);
    other = openat(AT_FDCWD, created, O_CREAT | O_EXCL | O_WRONLY, 0640);
    assert(other >= 0);
    assert(fstat(other, &info) == 0 && (info.st_mode & 0777) == 0640);

    /* dup2 onto itself only checks the descriptor, as the C library's does. */
    g_chaos_io_real_dup2 = NULL;
    assert(dup2(fd, fd) == fd);
    errno = 0;
    assert(dup2(-1, -1) == -1 && errno == EBADF);
    assert(dup2(fd, other) == other);
    assert(fstat(other, &info) == 0 && info.st_size == 8);
#ifdef __linux__
    g_chaos_io_real_dup3 = NULL;
    copy = dup3(fd, other, O_CLOEXEC);
    assert(copy == other && (fcntl(copy, F_GETFD) & FD_CLOEXEC) != 0);
#else
    copy = other;
#endif
    chaos_test_raw_close(copy);

    /* Sizes change for real. */
    g_chaos_io_real_ftruncate = NULL;
    assert(ftruncate(fd, 4) == 0 && chaos_test_file_size(path) == 4L);
    g_chaos_io_real_truncate = NULL;
    assert(truncate(path, 2) == 0 && chaos_test_file_size(path) == 2L);
#ifdef __linux__
    g_chaos_io_real_fallocate = NULL;
    assert(fallocate(fd, 0, 0, 64) == 0 && chaos_test_file_size(path) == 64L);
#endif
    /* posix_fallocate returns its error and leaves errno alone. */
    g_chaos_io_real_posix_fallocate = NULL;
    assert(posix_fallocate(fd, 0, 128) == 0 && chaos_test_file_size(path) == 128L);
    errno = 4242;
    assert(posix_fallocate(-1, 0, 1) == EBADF && errno == 4242);

#ifdef __linux__
    /* Kernel-side copies into "created": the first bytes of the file, twice. */
    assert(pwrite(fd, "kl", 2U, 0) == 2);
    other = open(created, O_RDWR | O_TRUNC);
    assert(other >= 0);
    g_chaos_io_real_sendfile = NULL;
    {
        off_t offset = 0;

        assert(sendfile(other, fd, &offset, 2U) == 2 && offset == 2);
    }
    g_chaos_io_real_copy_file_range = NULL;
    {
        off_t in_offset = 0;

        assert(copy_file_range(fd, &in_offset, other, NULL, 2U, 0U) == 2);
    }
    assert(pread(other, buffer, 4U, 0) == 4 && memcmp(buffer, "klkl", 4U) == 0);
    chaos_test_raw_close(other);
#endif

    /* Names change for real. */
    g_chaos_io_real_renameat = NULL;
    assert(renameat(AT_FDCWD, path, AT_FDCWD, moved) == 0);
    assert(chaos_test_file_size(path) == -1L && chaos_test_file_size(moved) == 128L);
    g_chaos_io_real_unlinkat = NULL;
    assert(unlinkat(AT_FDCWD, moved, 0) == 0 && chaos_test_file_size(moved) == -1L);
    assert(unlinkat(AT_FDCWD, created, 0) == 0 && chaos_test_file_size(created) == -1L);
    chaos_test_raw_close(fd);

    /* Directory and pipe streams belong to the C library: ENOSYS, no crash. */
    g_chaos_io_real_closedir = NULL;
    errno = 0;
    assert(closedir_wrapper(NULL) == -1 && errno == ENOSYS);
    g_chaos_io_real_pclose = NULL;
    errno = 0;
    assert(pclose_wrapper(NULL) == -1 && errno == ENOSYS);

    chaos_test_reset_state();
}

/**
 * @brief A stdio wrapper whose real function is unresolved fails the way that function
 *        reports errors, with errno ENOSYS: no system call can operate on libc's stream
 *        object. The stream is left untouched and still usable.
 */
static void test_unresolved_stdio_fails_with_enosys(void)
{
    char buffer[8];
    char *line = NULL;
    size_t capacity = 0U;
    /* Through a pointer: the compiler knows fclose frees its argument. */
    int (*volatile fclose_wrapper)(FILE *) = fclose;
    FILE *stream = chaos_test_stdio_stream();

    chaos_io_ensure_symbols();
    g_chaos_io_real_fread = NULL;
    g_chaos_io_real_fread_chk = NULL;
    g_chaos_io_real_fgets = NULL;
    g_chaos_io_real_fgets_chk = NULL;
    g_chaos_io_real_fgetc = NULL;
    g_chaos_io_real_getc = NULL;
    g_chaos_io_real_getdelim = NULL;
    g_chaos_io_real_fwrite = NULL;
    g_chaos_io_real_fputs = NULL;
    g_chaos_io_real_fputc = NULL;
    g_chaos_io_real_putc = NULL;
    g_chaos_io_real_fflush = NULL;
    g_chaos_io_real_vfprintf = NULL;
    g_chaos_io_real_vfprintf_chk = NULL;
    g_chaos_io_real_fclose = NULL;
    g_chaos_io_real_fopen = NULL;
    g_chaos_io_real_freopen = NULL;

    errno = 0;
    assert(fread(buffer, 1U, 2U, stream) == 0U && errno == ENOSYS);
    errno = 0;
    assert(__fread_chk(buffer, sizeof(buffer), 1U, 2U, stream) == 0U && errno == ENOSYS);
    errno = 0;
    assert(fgets(buffer, (int)sizeof(buffer), stream) == NULL && errno == ENOSYS);
    errno = 0;
    assert(__fgets_chk(buffer, sizeof(buffer), 4, stream) == NULL && errno == ENOSYS);
    errno = 0;
    assert(fgetc(stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(getc(stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(getline(&line, &capacity, stream) == -1 && errno == ENOSYS);
    errno = 0;
    assert(fwrite("x", 1U, 1U, stream) == 0U && errno == ENOSYS);
    errno = 0;
    assert(fputs("x", stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(fputc('x', stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(putc('x', stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(fflush(stream) == EOF && errno == ENOSYS);
    errno = 0;
    assert(fprintf(stream, "%d", 7) == -1 && errno == ENOSYS);
    errno = 0;
    assert(__fprintf_chk(stream, 1, "%d", 7) == -1 && errno == ENOSYS);
    errno = 0;
    assert(fopen("/dev/null", "r") == NULL && errno == ENOSYS);
    errno = 0;
    assert(freopen("/dev/null", "r", stream) == NULL && errno == ENOSYS);
    errno = 0;
    assert(fclose_wrapper(stream) == EOF && errno == ENOSYS);

    /* Nothing was read: the stream is where it was, and still open. */
    chaos_test_reset_state();
    assert(fgets(buffer, (int)sizeof(buffer), stream) == buffer && strcmp(buffer, "abc\n") == 0);
    assert(fclose(stream) == 0);
    free(line);
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
    test_path_filters_join_and_seed();
    test_unresolvable_paths_pass_through();
    test_open_rule_that_does_not_fire();
    test_descriptor_wrappers_under_guard();
    test_rules_that_do_not_fire();
    test_unlink_and_rename_matching_inputs();
    test_vectored_edge_segments();
    test_close_range_at_int_max();
    test_stdio_rules_that_do_not_fail();
    test_unresolved_symbols_use_system_calls();
    test_unresolved_stdio_fails_with_enosys();
    chaos_test_bind_libc_functions_for_exit();
    /* Shutdown I/O, the coverage dump included, bypasses the wrappers: rule lookups made
     * while the line counts are written would skew them. */
    (void)chaos_io_enter_internal();
    return 0;
}
