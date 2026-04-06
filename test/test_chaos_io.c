#include "test_chaos_io_harness.h"

static void test_resolve_symbol_and_seed_material(void)
{
    chaos_io_read_fn resolved_read = NULL;

    chaos_test_reset_state();
    chaos_io_resolve_symbol(&resolved_read, "read");
    assert(resolved_read == chaos_test_real_read_impl);

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
    assert(chaos_io_resolve_open_path(AT_FDCWD, "/tmp/absolute.bin", path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/absolute.bin") == 0);

    assert(chaos_io_join_paths(NULL, sizeof(path), "/tmp", "child.bin") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), "", "child.bin") == 0);
    assert(chaos_io_join_paths(path, sizeof(path), "/tmp", "") == 0);
    assert(chaos_io_join_paths(path, 4U, "/tmp", "child.bin") == 0);

    assert(chaos_io_getcwd_path(NULL, sizeof(path)) == 0);
    assert(chaos_io_getcwd_path(path, 0U) == 0);
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(chaos_io_resolve_open_path(AT_FDCWD, "relative.bin", path, sizeof(path)) == 1);
    assert(chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative.bin") == 1);
    assert(strcmp(path, expected_path) == 0);

    assert(chaos_io_resolve_open_path(AT_FDCWD, NULL, path, sizeof(path)) == 0);
    assert(chaos_io_resolve_open_path(AT_FDCWD, "relative.bin", NULL, sizeof(path)) == 0);
    assert(chaos_io_resolve_open_path(AT_FDCWD, "relative.bin", path, 0U) == 0);
    g_fdcache_resolve_result = 1;
    (void)snprintf(g_resolved_path, sizeof(g_resolved_path), "%s", "/tmp/base");
    assert(chaos_io_resolve_open_path(9, "child.bin", path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/base/child.bin") == 0);

    g_fdcache_resolve_result = 0;
    assert(chaos_io_resolve_open_path(9, "child.bin", path, sizeof(path)) == 0);

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

static void test_init_runtime(void)
{
    chaos_test_reset_state();
    g_sys_open_result = 5;
    g_sys_read_result = (long)sizeof(uint64_t);
    g_sys_seed_value = UINT64_C(0xfeedbeef12345678);

    chaos_io_init();
    assert(g_chaos_io_real_read == chaos_test_real_read_impl);
    assert(g_chaos_io_real_write == chaos_test_real_write_impl);
    assert(g_chaos_io_real_open == chaos_test_real_open_impl);
    assert(g_chaos_io_real_openat == chaos_test_real_openat_impl);
    assert(g_chaos_io_real_close == chaos_test_real_close_impl);
    assert(g_chaos_io_real_fsync == chaos_test_real_fsync_impl);
    assert(g_chaos_io_real_fdatasync == chaos_test_real_fdatasync_impl);
    assert(g_chaos_io_real_pread == chaos_test_real_pread_impl);
    assert(g_chaos_io_real_pwrite == chaos_test_real_pwrite_impl);
#ifdef __linux__
    assert(g_chaos_io_real_sendfile == chaos_test_real_sendfile_impl);
#endif
    assert(g_chaos_io_process_seed == UINT64_C(0xfeedbeef12345678));
    assert(g_chaos_io_tls_prng_state != 0U);
    assert(g_config_init_calls == 1);
    assert(g_fdcache_reset_calls == 1);
}

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
    assert(chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative-open.bin") == 1);
    assert(strcmp(g_last_match_path, expected_path) == 0);
    assert(strcmp(g_last_store_path, expected_path) == 0);
}

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
    assert(chaos_io_join_paths(expected_path, sizeof(expected_path), cwd, "relative-openat.bin") == 1);
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

static void test_read_and_write_wrappers(void)
{
    char buffer[8] = { 0 };

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

#ifdef __linux__
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
#endif

static void test_close_sync_and_positioned_wrappers(void)
{
    char buffer[8] = { 0 };

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
    test_read_and_write_wrappers();
#ifdef __linux__
    test_sendfile_wrapper();
#endif
    test_close_sync_and_positioned_wrappers();
    chaos_test_bind_libc_functions_for_exit();
    return 0;
}
