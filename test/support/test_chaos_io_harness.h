/**
 * @file test_chaos_io_harness.h
 * @brief Wrapper-layer harness for libchaos-io: recording stubs for every dependency, symbol
 *        overrides, and the production wrapper sources compiled in.
 *
 * @details Lets test_chaos_io.c drive each libchaos-io wrapper in-process and assert exactly
 * what it did: which config/fd-cache/effect helpers it consulted, which real function it
 * called with which arguments, and that the reentrancy guard was held (== 1) during that call.
 *
 * This is a header in name only: it defines functions and static state, so include it exactly
 * once per test binary (test_chaos_io.c); a second inclusion is a multiple-definition error.
 *
 * Structure:
 *   1. Recording state: a call counter, a configurable return value and captured arguments
 *      for every stubbed dependency; the guard value seen inside each real-function stub.
 *   2. Non-static stubs for the config, fd-cache and effect (actions) modules, satisfying the
 *      wrappers' `extern` references so no production rule matching or PRNG runs.
 *   3. Static stubs for the real functions (`chaos_test_real_*_impl`), reached through the
 *      `g_chaos_io_real_*` pointers.
 *   4. `#define` overrides of dlsym, dlerror, abort, syscall and CHAOS_IO_PROCESS_VM_READV,
 *      then `#include` of chaos_io.c and the open, rw, fsops, sync and stdio wrapper sources
 *      with CHAOS_IO_CONSTRUCTOR defined empty, so chaos_io_init() runs only when a test calls
 *      it.
 *   5. chaos_test_reset_state(): defaults for all recording state, run-once symbol state
 *      reset, most real functions NULL; every test calls it first.
 *   6. chaos_test_bind_real_functions(): points the real functions at the stubs.
 *   7. chaos_test_bind_libc_functions_for_exit(): points them back at the C library before
 *      main() returns, because the C runtime's exit path writes and closes through the
 *      wrappers compiled into this binary.
 *
 * The stdio real functions always resolve to the C library (chaos_test_bind_real_stdio()),
 * because the test binary's own printf/fputs/fflush go through the stdio wrappers.
 *
 * Not covered: dynamic-linker interposition (the runtime suites load the real .so), the
 * reentrancy guard under concurrency, real partial transfers and EINTR, and reload on real
 * rule-file changes.
 */

#ifndef CHAOS_IO_TEST_HARNESS_H
#define CHAOS_IO_TEST_HARNESS_H

#include "test_support.h"

#include "../../src/effects/chaos_io_actions.h"
#include "../../src/config/chaos_io_config.h"
#include "../../src/config/chaos_io_fdcache.h"

#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <setjmp.h>
#include <sys/syscall.h>

/** @brief iovec lengths captured per stubbed vectored call; later segments are not recorded. */
#define CHAOS_TEST_IOV_SNAPSHOT_COUNT 4

/* -------------------------------------------------------------------------
 * Config subsystem stubs
 * --------------------------------------------------------------------- */

/** @brief Calls of chaos_io_config_init(); the constructor makes exactly one. */
static int g_config_init_calls = 0;
/** @brief Number of times `chaos_io_config_prepare()` was called. */
static int g_config_prepare_calls = 0;
/** @brief Number of times `chaos_io_config_match_loaded()` was called. */
static int g_config_match_loaded_calls = 0;
/** @brief Number of times `chaos_io_config_match_path()` was called. */
static int g_config_match_path_calls = 0;
/** @brief Value to return from the `chaos_io_config_prepare()` stub. */
static int g_config_prepare_result = 0;
/** @brief Value to return from the `chaos_io_config_match_loaded()` stub (non-zero = match). */
static int g_config_match_loaded_result = 0;
/** @brief Value to return from the `chaos_io_config_match_path()` stub (non-zero = match). */
static int g_config_match_path_result = 0;
/** @brief Rule written into the caller's output on a successful config match. */
static chaos_io_rule_t g_config_rule;
/** @brief Operation passed to the most recent chaos_io_config_match_loaded() call. */
static chaos_io_operation_t g_last_match_loaded_operation = CHAOS_IO_OP_INVALID;
/** @brief Operation argument captured from the most recent `chaos_io_config_match_path()` call. */
static chaos_io_operation_t g_last_match_path_operation = CHAOS_IO_OP_INVALID;
/** @brief Path argument captured from the most recent `chaos_io_config_match_loaded()` call. */
static char g_last_match_loaded_path[CHAOS_IO_MAX_PATH];
/** @brief Path argument captured from the most recent `chaos_io_config_match_path()` call. */
static char g_last_match_path[CHAOS_IO_MAX_PATH];

/* -------------------------------------------------------------------------
 * FD-cache subsystem stubs
 * --------------------------------------------------------------------- */

/** @brief Number of times `chaos_io_fdcache_reset()` was called. */
static int g_fdcache_reset_calls = 0;
/** @brief Number of times `chaos_io_fdcache_resolve()` was called. */
static int g_fdcache_resolve_calls = 0;
/** @brief Number of times `chaos_io_fdcache_store()` was called. */
static int g_fdcache_store_calls = 0;
/** @brief Number of times `chaos_io_fdcache_invalidate()` was called. */
static int g_fdcache_invalidate_calls = 0;
/** @brief Value to return from the `chaos_io_fdcache_resolve()` stub (non-zero = success). */
static int g_fdcache_resolve_result = 0;
/** @brief File descriptor captured from the most recent `chaos_io_fdcache_resolve()` call. */
static int g_last_resolve_fd = -1;
/** @brief File descriptor captured from the most recent `chaos_io_fdcache_store()` call. */
static int g_last_store_fd = -1;
/** @brief File descriptor captured from the most recent `chaos_io_fdcache_invalidate()` call. */
static int g_last_invalidate_fd = -1;
/** @brief Path value written into the caller's buffer by `chaos_io_fdcache_resolve()`. */
static char g_resolved_path[CHAOS_IO_MAX_PATH];
/** @brief Path argument captured from the most recent `chaos_io_fdcache_store()` call. */
static char g_last_store_path[CHAOS_IO_MAX_PATH];

/* -------------------------------------------------------------------------
 * Actions subsystem stubs
 * --------------------------------------------------------------------- */

/** @brief Number of times `chaos_io_rule_apply_latency()` was called. */
static int g_latency_calls = 0;
/** @brief `call_size` of the rule copy the latency stub was last given. */
static uint64_t g_last_call_size = 0U;
/** @brief Number of times `chaos_io_rule_apply_errno()` was called. */
static int g_rule_apply_errno_calls = 0;
/** @brief Number of times `chaos_io_rule_should_trigger()` was called. */
static int g_rule_should_trigger_calls = 0;
/** @brief Value to return from the `chaos_io_rule_apply_errno()` stub. */
static int g_rule_apply_errno_result = 0;
/** @brief Value to return from the `chaos_io_rule_should_trigger()` stub. */
static int g_rule_should_trigger_result = 0;
/** @brief Torn-count value to return from the `chaos_io_torn_count()` stub. */
static size_t g_torn_count_result = 0U;
/** @brief `requested` argument captured from the most recent `chaos_io_torn_count()` call. */
static size_t g_last_torn_requested = 0U;
/** @brief Number of times `chaos_io_corrupt_buffer()` was called. */
static int g_corrupt_calls = 0;
/** @brief `size` argument captured from the most recent `chaos_io_corrupt_buffer()` call. */
static size_t g_last_corrupt_size = 0U;
/** @brief Number of times `chaos_io_corrupt_buffer_sample()` was called. */
static int g_corrupt_sample_calls = 0;
/** @brief `size` passed to the most recent chaos_io_corrupt_buffer_sample() call. */
static size_t g_last_corrupt_sample_size = 0U;
/** @brief `index_sample` passed to the most recent chaos_io_corrupt_buffer_sample() call. */
static uint32_t g_last_corrupt_index_sample = 0U;
/** @brief `bit_sample` passed to the most recent chaos_io_corrupt_buffer_sample() call. */
static uint32_t g_last_corrupt_bit_sample = 0U;

/* -------------------------------------------------------------------------
 * Real-function stubs: open / openat
 * --------------------------------------------------------------------- */

/** @brief Number of times the stub open function was called. */
static int g_real_open_calls = 0;
/** @brief File descriptor to return from the stub open function. */
static int g_real_open_return = 0;
/** @brief `flags` argument captured from the most recent stub open call. */
static int g_real_open_flags = 0;
/** @brief Non-zero if the `O_CREAT` path was taken and `mode` was extracted. */
static int g_real_open_has_mode = 0;
/**
 * @brief Reentrancy guard value seen inside the open stub.
 *
 * Wrappers set `g_chaos_io_tls_guard` to 1 around the real-function call so that any I/O the
 * real function performs internally passes straight through. Tests assert this equals 1.
 */
static int g_real_open_guard = 0;
/** @brief `mode` argument captured from an `O_CREAT` open call. */
static mode_t g_real_open_mode = 0;
/** @brief `path` argument captured from the most recent stub open call. */
static char g_real_open_path[CHAOS_IO_MAX_PATH];

/** @brief Number of times the stub openat function was called. */
static int g_real_openat_calls = 0;
/** @brief File descriptor to return from the stub openat function. */
static int g_real_openat_return = 0;
/** @brief `dirfd` argument captured from the most recent stub openat call. */
static int g_real_openat_dirfd = -1;
/** @brief `flags` argument captured from the most recent stub openat call. */
static int g_real_openat_flags = 0;
/** @brief Non-zero if an O_CREAT/O_TMPFILE mode was extracted. */
static int g_real_openat_has_mode = 0;
/** @brief TLS guard value observed inside the stub openat function (must be 1). */
static int g_real_openat_guard = 0;
/** @brief `mode` argument captured from an O_CREAT/O_TMPFILE openat call. */
static mode_t g_real_openat_mode = 0;
/** @brief `path` argument captured from the most recent stub openat call. */
static char g_real_openat_path[CHAOS_IO_MAX_PATH];

/* -------------------------------------------------------------------------
 * Real-function stubs: read / readv / write / writev
 * --------------------------------------------------------------------- */

/** @brief Number of times the stub read function was called. */
static int g_real_read_calls = 0;
/** @brief Return value for the stub read function. */
static ssize_t g_real_read_return = 0;
/** @brief TLS guard value observed inside the stub read function (must be 1). */
static int g_real_read_guard = 0;
/** @brief `fd` argument captured from the most recent stub read call. */
static int g_real_read_fd = -1;
/** @brief `count` argument captured from the most recent stub read call. */
static size_t g_real_read_count = 0U;
/**
 * @brief Bytes the read and readv stubs deliver into the caller's buffer.
 *
 * When the configured return is > 0, that many bytes are copied in, so CORRUPT and TORN
 * effects applied afterwards operate on known data. Capacity 64 bytes: a larger configured
 * read return over-reads this array.
 */
static char g_real_read_fill[64];
/** @brief Number of times the stub readv function was called. */
static int g_real_readv_calls = 0;
/** @brief Return value for the stub readv function. */
static ssize_t g_real_readv_return = 0;
/** @brief TLS guard value observed inside the stub readv function. */
static int g_real_readv_guard = 0;
/** @brief `fd` argument captured from the most recent stub readv call. */
static int g_real_readv_fd = -1;
/** @brief `iovcnt` argument captured from the most recent stub readv call. */
static int g_real_readv_iovcnt = 0;
/** @brief First `CHAOS_TEST_IOV_SNAPSHOT_COUNT` iov lengths from the stub readv call. */
static size_t g_real_readv_lengths[CHAOS_TEST_IOV_SNAPSHOT_COUNT];

/** @brief Number of times the stub write function was called. */
static int g_real_write_calls = 0;
/** @brief Return value for the stub write function. */
static ssize_t g_real_write_return = 0;
/** @brief TLS guard value observed inside the stub write function. */
static int g_real_write_guard = 0;
/** @brief `fd` argument captured from the most recent stub write call. */
static int g_real_write_fd = -1;
/** @brief `count` argument captured from the most recent stub write call. */
static size_t g_real_write_count = 0U;
/** @brief Number of times the stub writev function was called. */
static int g_real_writev_calls = 0;
/** @brief Return value for the stub writev function. */
static ssize_t g_real_writev_return = 0;
/** @brief TLS guard value observed inside the stub writev function. */
static int g_real_writev_guard = 0;
/** @brief `fd` argument captured from the most recent stub writev call. */
static int g_real_writev_fd = -1;
/** @brief `iovcnt` argument captured from the most recent stub writev call. */
static int g_real_writev_iovcnt = 0;
/** @brief First `CHAOS_TEST_IOV_SNAPSHOT_COUNT` iov lengths from the stub writev call. */
static size_t g_real_writev_lengths[CHAOS_TEST_IOV_SNAPSHOT_COUNT];

/* -------------------------------------------------------------------------
 * Real-function stubs: Linux-only (fallocate, sendfile, copy_file_range)
 * --------------------------------------------------------------------- */

#ifdef __linux__
/** @brief Number of times the stub fallocate function was called. */
static int g_real_fallocate_calls = 0;
/** @brief Return value for the stub fallocate function. */
static int g_real_fallocate_return = 0;
/** @brief TLS guard value observed inside the stub fallocate function. */
static int g_real_fallocate_guard = 0;
/** @brief `fd` argument captured from the most recent stub fallocate call. */
static int g_real_fallocate_fd = -1;
/** @brief `mode` argument captured from the most recent stub fallocate call. */
static int g_real_fallocate_mode = 0;
/** @brief `offset` argument captured from the most recent stub fallocate call. */
static off_t g_real_fallocate_offset = 0;
/** @brief `length` argument captured from the most recent stub fallocate call. */
static off_t g_real_fallocate_length = 0;
/** @brief Number of times the stub sendfile function was called. */
static int g_real_sendfile_calls = 0;
/** @brief Return value for the stub sendfile function. */
static ssize_t g_real_sendfile_return = 0;
/** @brief TLS guard value observed inside the stub sendfile function. */
static int g_real_sendfile_guard = 0;
/** @brief `out_fd` argument captured from the most recent stub sendfile call. */
static int g_real_sendfile_out_fd = -1;
/** @brief `in_fd` argument captured from the most recent stub sendfile call. */
static int g_real_sendfile_in_fd = -1;
/** @brief `offset` pointer captured from the most recent stub sendfile call. */
static off_t *g_real_sendfile_offset = NULL;
/** @brief `count` argument captured from the most recent stub sendfile call. */
static size_t g_real_sendfile_count = 0U;
/** @brief Number of times the stub copy_file_range function was called. */
static int g_real_copy_file_range_calls = 0;
/** @brief Return value for the stub copy_file_range function. */
static ssize_t g_real_copy_file_range_return = 0;
/** @brief TLS guard value observed inside the stub copy_file_range function. */
static int g_real_copy_file_range_guard = 0;
/** @brief `in_fd` argument captured from the most recent stub copy_file_range call. */
static int g_real_copy_file_range_in_fd = -1;
/** @brief `out_fd` argument captured from the most recent stub copy_file_range call. */
static int g_real_copy_file_range_out_fd = -1;
/** @brief `in_offset` pointer captured from the most recent stub copy_file_range call. */
static off_t *g_real_copy_file_range_in_offset = NULL;
/** @brief `out_offset` pointer captured from the most recent stub copy_file_range call. */
static off_t *g_real_copy_file_range_out_offset = NULL;
/** @brief `count` argument captured from the most recent stub copy_file_range call. */
static size_t g_real_copy_file_range_count = 0U;
/** @brief `flags` argument captured from the most recent stub copy_file_range call. */
static unsigned int g_real_copy_file_range_flags = 0U;
#endif

/* -------------------------------------------------------------------------
 * Real-function stubs: close / fsync / fdatasync / ftruncate / truncate / unlinkat / renameat
 * --------------------------------------------------------------------- */

/** @brief Number of times the stub close function was called. */
static int g_real_close_calls = 0;
/** @brief Return value for the stub close function. */
static int g_real_close_return = 0;
/** @brief TLS guard value observed inside the stub close function. */
static int g_real_close_guard = 0;
/** @brief `fd` argument captured from the most recent stub close call. */
static int g_real_close_fd = -1;
/** @brief Number of times the stub dup2 / dup3 / close_range functions were called. */
static int g_real_dup_calls = 0;
/** @brief Return value for the stub dup2 / dup3 / close_range functions. */
static int g_real_dup_return = 0;

/** @brief Number of times the stub fsync function was called. */
static int g_real_fsync_calls = 0;
/** @brief Return value for the stub fsync function. */
static int g_real_fsync_return = 0;
/** @brief TLS guard value observed inside the stub fsync function. */
static int g_real_fsync_guard = 0;
/** @brief `fd` argument captured from the most recent stub fsync call. */
static int g_real_fsync_fd = -1;

/** @brief Number of times the stub fdatasync function was called. */
static int g_real_fdatasync_calls = 0;
/** @brief Return value for the stub fdatasync function. */
static int g_real_fdatasync_return = 0;
/** @brief TLS guard value observed inside the stub fdatasync function. */
static int g_real_fdatasync_guard = 0;
/** @brief `fd` argument captured from the most recent stub fdatasync call. */
static int g_real_fdatasync_fd = -1;

/** @brief Number of times the stub ftruncate function was called. */
static int g_real_ftruncate_calls = 0;
/** @brief Return value for the stub ftruncate function. */
static int g_real_ftruncate_return = 0;
/** @brief TLS guard value observed inside the stub ftruncate function. */
static int g_real_ftruncate_guard = 0;
/** @brief `fd` argument captured from the most recent stub ftruncate call. */
static int g_real_ftruncate_fd = -1;
/** @brief `length` argument captured from the most recent stub ftruncate call. */
static off_t g_real_ftruncate_length = 0;

/** @brief Number of times the stub renameat2 function was called. */
static int g_real_renameat2_calls = 0;
/** @brief `flags` argument captured from the most recent stub renameat2 call. */
static unsigned int g_real_renameat2_flags = 0U;
/** @brief Number of times the stub posix_fallocate function was called. */
static int g_real_posix_fallocate_calls = 0;
/** @brief Return value (an error number) for the stub posix_fallocate function. */
static int g_real_posix_fallocate_return = 0;

/** @brief Number of times the stub truncate function was called. */
static int g_real_truncate_calls = 0;
/** @brief Return value for the stub truncate function. */
static int g_real_truncate_return = 0;
/** @brief TLS guard value observed inside the stub truncate function. */
static int g_real_truncate_guard = 0;
/** @brief `length` argument captured from the most recent stub truncate call. */
static off_t g_real_truncate_length = 0;
/** @brief Number of times the stub fopen function was called. */
static int g_real_fopen_calls = 0;
/** @brief Number of times the stub freopen function was called. */
static int g_real_freopen_calls = 0;
/** @brief Stream returned by the stub fopen and freopen functions. */
static FILE *g_real_fopen_return = NULL;
/** @brief Path passed to the most recent stub fopen or freopen call. */
static const char *g_real_fopen_path = NULL;

/** @brief Number of times the stub unlinkat function was called. */
static int g_real_unlinkat_calls = 0;
/** @brief Return value for the stub unlinkat function. */
static int g_real_unlinkat_return = 0;
/** @brief TLS guard value observed inside the stub unlinkat function. */
static int g_real_unlinkat_guard = 0;
/** @brief `dirfd` argument captured from the most recent stub unlinkat call. */
static int g_real_unlinkat_dirfd = -1;
/** @brief `flags` argument captured from the most recent stub unlinkat call. */
static int g_real_unlinkat_flags = 0;
/** @brief `path` argument captured from the most recent stub unlinkat call. */
static char g_real_unlinkat_path[CHAOS_IO_MAX_PATH];

/** @brief Number of times the stub renameat function was called. */
static int g_real_renameat_calls = 0;
/** @brief Return value for the stub renameat function. */
static int g_real_renameat_return = 0;
/** @brief TLS guard value observed inside the stub renameat function. */
static int g_real_renameat_guard = 0;
/** @brief `olddirfd` argument captured from the most recent stub renameat call. */
static int g_real_renameat_olddirfd = -1;
/** @brief `newdirfd` argument captured from the most recent stub renameat call. */
static int g_real_renameat_newdirfd = -1;
/** @brief `oldpath` argument captured from the most recent stub renameat call. */
static char g_real_renameat_oldpath[CHAOS_IO_MAX_PATH];
/** @brief `newpath` argument captured from the most recent stub renameat call. */
static char g_real_renameat_newpath[CHAOS_IO_MAX_PATH];

/* -------------------------------------------------------------------------
 * Real-function stubs: pread / preadv / pwrite / pwritev
 * --------------------------------------------------------------------- */

/** @brief Number of times the stub pread function was called. */
static int g_real_pread_calls = 0;
/** @brief Return value for the stub pread function. */
static ssize_t g_real_pread_return = 0;
/** @brief TLS guard value observed inside the stub pread function. */
static int g_real_pread_guard = 0;
/** @brief `fd` argument captured from the most recent stub pread call. */
static int g_real_pread_fd = -1;
/** @brief `count` argument captured from the most recent stub pread call. */
static size_t g_real_pread_count = 0U;
/** @brief `offset` argument captured from the most recent stub pread call. */
static off_t g_real_pread_offset = 0;
/** @brief Pattern written into the caller's buffer by the stub pread function. */
static char g_real_pread_fill[64];
/** @brief Number of times the stub preadv function was called. */
static int g_real_preadv_calls = 0;
/** @brief Return value for the stub preadv function. */
static ssize_t g_real_preadv_return = 0;
/** @brief TLS guard value observed inside the stub preadv function. */
static int g_real_preadv_guard = 0;
/** @brief `fd` argument captured from the most recent stub preadv call. */
static int g_real_preadv_fd = -1;
/** @brief `iovcnt` argument captured from the most recent stub preadv call. */
static int g_real_preadv_iovcnt = 0;
/** @brief `offset` argument captured from the most recent stub preadv call. */
static off_t g_real_preadv_offset = 0;
/** @brief First `CHAOS_TEST_IOV_SNAPSHOT_COUNT` iov lengths from the stub preadv call. */
static size_t g_real_preadv_lengths[CHAOS_TEST_IOV_SNAPSHOT_COUNT];

/** @brief Number of times the stub pwrite function was called. */
static int g_real_pwrite_calls = 0;
/** @brief Return value for the stub pwrite function. */
static ssize_t g_real_pwrite_return = 0;
/** @brief TLS guard value observed inside the stub pwrite function. */
static int g_real_pwrite_guard = 0;
/** @brief `fd` argument captured from the most recent stub pwrite call. */
static int g_real_pwrite_fd = -1;
/** @brief `count` argument captured from the most recent stub pwrite call. */
static size_t g_real_pwrite_count = 0U;
/** @brief `offset` argument captured from the most recent stub pwrite call. */
static off_t g_real_pwrite_offset = 0;
/** @brief Number of times the stub pwritev function was called. */
static int g_real_pwritev_calls = 0;
/** @brief Return value for the stub pwritev function. */
static ssize_t g_real_pwritev_return = 0;
/** @brief TLS guard value observed inside the stub pwritev function. */
static int g_real_pwritev_guard = 0;
/** @brief `fd` argument captured from the most recent stub pwritev call. */
static int g_real_pwritev_fd = -1;
/** @brief `iovcnt` argument captured from the most recent stub pwritev call. */
static int g_real_pwritev_iovcnt = 0;
/** @brief `offset` argument captured from the most recent stub pwritev call. */
static off_t g_real_pwritev_offset = 0;
/** @brief First `CHAOS_TEST_IOV_SNAPSHOT_COUNT` iov lengths from the stub pwritev call. */
static size_t g_real_pwritev_lengths[CHAOS_TEST_IOV_SNAPSHOT_COUNT];

/* -------------------------------------------------------------------------
 * Syscall / dlsym / abort stubs
 * --------------------------------------------------------------------- */

/** @brief Number of times SYS_openat was dispatched through the syscall stub. */
static int g_sys_open_calls = 0;
/** @brief Number of times SYS_read was dispatched through the syscall stub. */
static int g_sys_read_calls = 0;
/** @brief Number of times SYS_close was dispatched through the syscall stub. */
static int g_sys_close_calls = 0;
/** @brief Return value to emit for SYS_openat; -1 simulates a failed open. */
static long g_sys_open_result = -1;
/**
 * @brief Return value of the SYS_read stub; when positive, also the number of seed bytes
 *        copied out (capped at the caller's size).
 *
 * sizeof(uint64_t) simulates a complete seed read.
 */
static long g_sys_read_result = -1;
/** @brief Return value for SYS_close; 0 is the normal success value. */
static long g_sys_close_result = 0;
/**
 * @brief Seed bytes the SYS_read stub delivers.
 *
 * chaos_io_init() reads 8 bytes from /dev/urandom with raw openat/read/close system calls
 * (raw so no wrapper of this library runs during its own constructor). Tests set this value
 * and assert that `g_chaos_io_process_seed` ends up derived from it.
 */
static uint64_t g_sys_seed_value = 0U;

/**
 * @brief Symbol for which the dlsym stub fails (returns NULL, sets a dlerror message).
 *
 * Drives the constructor's unresolved-symbol path into abort(), which the abort stub turns
 * into a longjmp back to the test.
 */
static const char *g_dlsym_fail_symbol = NULL;
/** @brief Pending error string to return from the `dlerror` stub; NULL means no error. */
static const char *g_dlerror_pending = NULL;
/**
 * @brief Non-zero when the test expects abort().
 *
 * Set: the abort stub longjmp()s to `g_abort_env`, so the test must have called setjmp().
 * Clear: the abort stub calls exit(111), a status distinct from a failed assert() (SIGABRT,
 * shell status 134).
 */
static int g_abort_expected = 0;
/** @brief Set to 1 by the abort stub when it fires with `g_abort_expected` non-zero. */
static int g_abort_called = 0;
/** @brief Jump buffer used by the `abort` stub to transfer control back to the test. */
static jmp_buf g_abort_env;

/* -------------------------------------------------------------------------
 * Config subsystem stub implementations
 * --------------------------------------------------------------------- */

/** @brief Stub for chaos_io_config_init(): counts calls only. */
void chaos_io_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for chaos_io_config_prepare(): counts calls and returns
 *        `g_config_prepare_result`.
 *
 * Production returns non-zero when the active snapshot holds at least one rule; 0 models a
 * missing, empty or rejected rule file, which makes every wrapper pass straight through.
 */
int chaos_io_config_prepare(void)
{
    ++g_config_prepare_calls;
    return g_config_prepare_result;
}

/**
 * @brief Stub for chaos_io_config_match_loaded(): records @p operation and @p path, then
 *        copies `g_config_rule` to @p rule and returns 1 when `g_config_match_loaded_result`
 *        is non-zero and @p rule is not NULL; returns 0 otherwise.
 */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    ++g_config_match_loaded_calls;
    g_last_match_loaded_operation = operation;
    if (path != NULL)
    {
        (void)snprintf(g_last_match_loaded_path, sizeof(g_last_match_loaded_path), "%s", path);
    }
    else
    {
        g_last_match_loaded_path[0] = '\0';
    }

    if (!g_config_match_loaded_result || rule == NULL)
    {
        return 0;
    }

    *rule = g_config_rule;
    return 1;
}

/**
 * @brief Stub for chaos_io_config_match_path(): records @p operation and @p path, then copies
 *        `g_config_rule` to @p rule and returns 1 when `g_config_match_path_result` is
 *        non-zero and @p rule is not NULL; returns 0 otherwise.
 */
int chaos_io_config_match_path(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    ++g_config_match_path_calls;
    g_last_match_path_operation = operation;
    if (path != NULL)
    {
        (void)snprintf(g_last_match_path, sizeof(g_last_match_path), "%s", path);
    }
    else
    {
        g_last_match_path[0] = '\0';
    }

    if (!g_config_match_path_result || rule == NULL)
    {
        return 0;
    }

    *rule = g_config_rule;
    return 1;
}

/* -------------------------------------------------------------------------
 * FD-cache subsystem stub implementations
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for chaos_io_fdcache_reset(): counts calls. The constructor calls it once to
 *        drop fd-cache entries left by an earlier constructor run.
 */
void chaos_io_fdcache_reset(void)
{
    ++g_fdcache_reset_calls;
}

/**
 * @brief Stub for chaos_io_fdcache_resolve(): records @p fd; when `g_fdcache_resolve_result`
 *        is non-zero and @p path is usable, copies `g_resolved_path` (which must fit,
 *        asserted) and returns 1; returns 0 otherwise, modelling an fd with no known path.
 */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size)
{
    ++g_fdcache_resolve_calls;
    g_last_resolve_fd = fd;

    if (!g_fdcache_resolve_result || path == NULL || path_size == 0U)
    {
        return 0;
    }

    assert(strlen(g_resolved_path) + 1U <= path_size);
    (void)memcpy(path, g_resolved_path, strlen(g_resolved_path) + 1U);
    return 1;
}

/**
 * @brief Stub for chaos_io_fdcache_store(): records @p fd and @p path. Wrappers store the path
 *        of a descriptor after a successful open/openat so later fd-based calls can match
 *        path selectors.
 */
void chaos_io_fdcache_store(int fd, const char *path)
{
    ++g_fdcache_store_calls;
    g_last_store_fd = fd;
    if (path != NULL)
    {
        (void)snprintf(g_last_store_path, sizeof(g_last_store_path), "%s", path);
    }
    else
    {
        g_last_store_path[0] = '\0';
    }
}

/**
 * @brief Stub for chaos_io_fdcache_invalidate(): records @p fd. Wrappers invalidate a
 *        descriptor's entry when it is closed or replaced, so a reused fd number cannot
 *        inherit a stale path.
 */
void chaos_io_fdcache_invalidate(int fd)
{
    ++g_fdcache_invalidate_calls;
    g_last_invalidate_fd = fd;
}

/* -------------------------------------------------------------------------
 * Actions subsystem stub implementations
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for chaos_io_rule_apply_latency(): counts calls and records the rule's
 *        `call_size` (the byte count the @size qualifier is matched against); never sleeps.
 */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
    g_last_call_size = rule != NULL ? rule->call_size : 0U;
}

/**
 * @brief Stub for chaos_io_rule_should_trigger(): counts calls and returns
 *        `g_rule_should_trigger_result` (1 = the probability draw hits, 0 = pass through).
 */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_rule_should_trigger_calls;
    return g_rule_should_trigger_result;
}

/**
 * @brief Stub for chaos_io_rule_apply_errno(): when `g_rule_apply_errno_result` is non-zero,
 *        sets errno to `rule->errnum`; returns `g_rule_apply_errno_result` either way.
 */
int chaos_io_rule_apply_errno(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_rule_apply_errno_calls;
    if (g_rule_apply_errno_result != 0)
    {
        errno = rule->errnum;
    }
    return g_rule_apply_errno_result;
}

/**
 * @brief Stub for chaos_io_torn_count(): records @p requested and returns
 *        `g_torn_count_result`, the shortened transfer size a TORN rule passes to the real
 *        function.
 */
size_t chaos_io_torn_count(size_t requested)
{
    g_last_torn_requested = requested;
    return g_torn_count_result;
}

/**
 * @brief Stub for chaos_io_corrupt_buffer(): records @p size and flips bit 0 of byte 0, a
 *        deterministic corruption tests can assert without the PRNG.
 */
void chaos_io_corrupt_buffer(void *buffer, size_t size)
{
    unsigned char *bytes = (unsigned char *)buffer;

    ++g_corrupt_calls;
    g_last_corrupt_size = size;
    if (bytes != NULL && size > 0U)
    {
        bytes[0] ^= 0x01U;
    }
}

/**
 * @brief Stub for chaos_io_corrupt_buffer_sample(): records all arguments and flips the same
 *        bit production does (byte `index_sample % size`, bit `bit_sample & 7`), so tests see
 *        both the samples the wrapper drew and their effect on the buffer.
 */
void chaos_io_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;
    size_t index;

    ++g_corrupt_sample_calls;
    g_last_corrupt_sample_size = size;
    g_last_corrupt_index_sample = index_sample;
    g_last_corrupt_bit_sample = bit_sample;
    if (bytes == NULL || size == 0U)
    {
        return;
    }

    index = (size_t)(index_sample % size);
    bytes[index] ^= (unsigned char)(1U << (bit_sample & 7U));
}

/* -------------------------------------------------------------------------
 * Iovec capture helpers (internal to the harness)
 * --------------------------------------------------------------------- */

/**
 * @brief Records @p iovcnt and the lengths of the first CHAOS_TEST_IOV_SNAPSHOT_COUNT
 *        segments; unused slots are zeroed.
 *
 * Lets tests assert how a wrapper rebuilt or trimmed the iovec array (TORN on readv/writev).
 *
 * @param iov               Source array; NULL or @p iovcnt <= 0 records no lengths.
 * @param iovcnt            Element count as passed to the real function.
 * @param captured_iovcnt   Receives @p iovcnt; must not be NULL.
 * @param captured_lengths  Array of CHAOS_TEST_IOV_SNAPSHOT_COUNT entries; must not be NULL.
 */
static void chaos_test_capture_iov_lengths(
    const struct iovec *iov, int iovcnt, int *captured_iovcnt, size_t *captured_lengths
)
{
    int index;

    assert(captured_iovcnt != NULL);
    assert(captured_lengths != NULL);
    *captured_iovcnt = iovcnt;
    for (index = 0; index < CHAOS_TEST_IOV_SNAPSHOT_COUNT; ++index)
    {
        captured_lengths[index] = 0U;
    }
    if (iov == NULL || iovcnt <= 0)
    {
        return;
    }

    for (index = 0; index < iovcnt && index < CHAOS_TEST_IOV_SNAPSHOT_COUNT; ++index)
    {
        captured_lengths[index] = iov[index].iov_len;
    }
}

/**
 * @brief Scatters the first @p fill_size bytes of @p fill across the iovec buffers in order,
 *        as a vectored read would.
 *
 * @param iov        Destination segments; NULL is a no-op.
 * @param iovcnt     Segment count; <= 0 is a no-op.
 * @param fill       Source bytes; must hold at least @p fill_size bytes.
 * @param fill_size  Bytes to deliver; stops early when the segments are full.
 */
static void
chaos_test_fill_iovecs(const struct iovec *iov, int iovcnt, const char *fill, size_t fill_size)
{
    size_t copied = 0U;
    int index;

    if (iov == NULL || iovcnt <= 0 || fill == NULL || fill_size == 0U)
    {
        return;
    }

    for (index = 0; index < iovcnt && copied < fill_size; ++index)
    {
        size_t segment = iov[index].iov_len;

        if (segment > fill_size - copied)
        {
            segment = fill_size - copied;
        }
        if (segment > 0U)
        {
            (void)memcpy(iov[index].iov_base, fill + copied, segment);
            copied += segment;
        }
    }
}

/* -------------------------------------------------------------------------
 * Real-function stub implementations
 * --------------------------------------------------------------------- */

/**
 * @brief Real-function stub for open: records path, flags, the mode (read only with O_CREAT,
 *        as open(2) does) and the reentrancy guard; returns `g_real_open_return`.
 */
static int chaos_test_real_open_impl(const char *path, int flags, ...)
{
    ++g_real_open_calls;
    g_real_open_flags = flags;
    g_real_open_guard = g_chaos_io_tls_guard;
    if (path != NULL)
    {
        (void)snprintf(g_real_open_path, sizeof(g_real_open_path), "%s", path);
    }
    else
    {
        g_real_open_path[0] = '\0';
    }

    if ((flags & O_CREAT) != 0)
    {
        va_list args;

        g_real_open_has_mode = 1;
        va_start(args, flags);
        g_real_open_mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    else
    {
        g_real_open_has_mode = 0;
        g_real_open_mode = 0;
    }

    return g_real_open_return;
}

/**
 * @brief Real-function stub for openat: records dirfd, path, flags, the mode (read with
 *        O_CREAT or O_TMPFILE, the two flags that carry one) and the reentrancy guard;
 *        returns `g_real_openat_return`.
 */
static int chaos_test_real_openat_impl(int dirfd, const char *path, int flags, ...)
{
    ++g_real_openat_calls;
    g_real_openat_dirfd = dirfd;
    g_real_openat_flags = flags;
    g_real_openat_guard = g_chaos_io_tls_guard;
    if (path != NULL)
    {
        (void)snprintf(g_real_openat_path, sizeof(g_real_openat_path), "%s", path);
    }
    else
    {
        g_real_openat_path[0] = '\0';
    }

    if ((flags & O_CREAT) != 0
#ifdef O_TMPFILE
        || ((flags & O_TMPFILE) == O_TMPFILE)
#endif
    )
    {
        va_list args;

        g_real_openat_has_mode = 1;
        va_start(args, flags);
        g_real_openat_mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    else
    {
        g_real_openat_has_mode = 0;
        g_real_openat_mode = 0;
    }

    return g_real_openat_return;
}

/**
 * @brief Real-function stub for read: records fd, count and guard; when the configured return
 *        is > 0, copies that many bytes of `g_real_read_fill` into @p buffer.
 */
static ssize_t chaos_test_real_read_impl(int fd, void *buffer, size_t count)
{
    ++g_real_read_calls;
    g_real_read_fd = fd;
    g_real_read_count = count;
    g_real_read_guard = g_chaos_io_tls_guard;

    if (buffer != NULL && g_real_read_return > 0)
    {
        (void)memcpy(buffer, g_real_read_fill, (size_t)g_real_read_return);
    }

    return g_real_read_return;
}

/**
 * @brief Real-function stub for readv: records fd, guard and iovec layout; when the configured
 *        return is > 0, scatters that many bytes of `g_real_read_fill` into the segments.
 */
static ssize_t chaos_test_real_readv_impl(int fd, const struct iovec *iov, int iovcnt)
{
    ++g_real_readv_calls;
    g_real_readv_fd = fd;
    g_real_readv_guard = g_chaos_io_tls_guard;
    chaos_test_capture_iov_lengths(iov, iovcnt, &g_real_readv_iovcnt, g_real_readv_lengths);

    if (g_real_readv_return > 0)
    {
        chaos_test_fill_iovecs(iov, iovcnt, g_real_read_fill, (size_t)g_real_readv_return);
    }

    return g_real_readv_return;
}

/** @brief Real-function stub for write: records fd, count and guard; data is discarded. */
static ssize_t chaos_test_real_write_impl(int fd, const void *buffer, size_t count)
{
    (void)buffer;
    ++g_real_write_calls;
    g_real_write_fd = fd;
    g_real_write_count = count;
    g_real_write_guard = g_chaos_io_tls_guard;
    return g_real_write_return;
}

/** @brief Real-function stub for writev: records fd, guard and iovec layout. */
static ssize_t chaos_test_real_writev_impl(int fd, const struct iovec *iov, int iovcnt)
{
    ++g_real_writev_calls;
    g_real_writev_fd = fd;
    g_real_writev_guard = g_chaos_io_tls_guard;
    chaos_test_capture_iov_lengths(iov, iovcnt, &g_real_writev_iovcnt, g_real_writev_lengths);
    return g_real_writev_return;
}

#ifdef __linux__
/** @brief Real-function stub for fallocate: records all arguments and the guard. */
static int chaos_test_real_fallocate_impl(int fd, int mode, off_t offset, off_t length)
{
    ++g_real_fallocate_calls;
    g_real_fallocate_fd = fd;
    g_real_fallocate_mode = mode;
    g_real_fallocate_offset = offset;
    g_real_fallocate_length = length;
    g_real_fallocate_guard = g_chaos_io_tls_guard;
    return g_real_fallocate_return;
}

/** @brief Real-function stub for sendfile: records all arguments and the guard. */
static ssize_t chaos_test_real_sendfile_impl(int out_fd, int in_fd, off_t *offset, size_t count)
{
    ++g_real_sendfile_calls;
    g_real_sendfile_out_fd = out_fd;
    g_real_sendfile_in_fd = in_fd;
    g_real_sendfile_offset = offset;
    g_real_sendfile_count = count;
    g_real_sendfile_guard = g_chaos_io_tls_guard;
    return g_real_sendfile_return;
}

/** @brief Real-function stub for copy_file_range: records all arguments and the guard. */
static ssize_t chaos_test_real_copy_file_range_impl(
    int in_fd, off_t *in_offset, int out_fd, off_t *out_offset, size_t count, unsigned int flags
)
{
    ++g_real_copy_file_range_calls;
    g_real_copy_file_range_in_fd = in_fd;
    g_real_copy_file_range_in_offset = in_offset;
    g_real_copy_file_range_out_fd = out_fd;
    g_real_copy_file_range_out_offset = out_offset;
    g_real_copy_file_range_count = count;
    g_real_copy_file_range_flags = flags;
    g_real_copy_file_range_guard = g_chaos_io_tls_guard;
    return g_real_copy_file_range_return;
}
#endif

/** @brief Real-function stub for close: records fd and guard. */
static int chaos_test_real_close_impl(int fd)
{
    ++g_real_close_calls;
    g_real_close_fd = fd;
    g_real_close_guard = g_chaos_io_tls_guard;
    return g_real_close_return;
}

/** @brief Real-function stub for dup2: counts into `g_real_dup_calls`, returns
 * `g_real_dup_return`. */
static int chaos_test_real_dup2_impl(int oldfd, int newfd)
{
    (void)oldfd;
    (void)newfd;
    ++g_real_dup_calls;
    return g_real_dup_return;
}

/** @brief Calls of the closedir stub. */
static int g_real_closedir_calls = 0;
/** @brief Calls of the pclose stub. */
static int g_real_pclose_calls = 0;
/** @brief Calls of the closefrom stub. */
static int g_real_closefrom_calls = 0;
/** @brief `lowfd` the stub closefrom was last given. */
static int g_real_closefrom_lowfd = -1;
/** @brief Raw renameat2 system calls made through the syscall stub. */
static int g_sys_renameat2_calls = 0;
/** @brief Result the syscall stub returns for close_range (SYS_close_range, or 436 when the
 * headers lack the constant). */
static long g_sys_close_range_result = -1;

/** @brief Real-function stub for closedir: counts calls, returns 0. */
static int chaos_test_real_closedir_impl(DIR *directory)
{
    (void)directory;
    ++g_real_closedir_calls;
    return 0;
}

/** @brief Real-function stub for pclose: counts calls and returns 7, a distinctive exit status
 * tests check is passed through. */
static int chaos_test_real_pclose_impl(FILE *stream)
{
    (void)stream;
    ++g_real_pclose_calls;
    return 7;
}

/** @brief Real-function stub for closefrom: counts calls and records @p lowfd. */
static void chaos_test_real_closefrom_impl(int lowfd)
{
    ++g_real_closefrom_calls;
    g_real_closefrom_lowfd = lowfd;
}

/** @brief Real-function stub for close_range: counts into `g_real_dup_calls`, returns
 * `g_real_dup_return`. */
static int chaos_test_real_close_range_impl(unsigned int first, unsigned int last, int flags)
{
    (void)first;
    (void)last;
    (void)flags;
    ++g_real_dup_calls;
    return g_real_dup_return;
}

#ifdef __linux__
/** @brief Real-function stub for dup3 (Linux): counts into `g_real_dup_calls`, returns
 * `g_real_dup_return`. */
static int chaos_test_real_dup3_impl(int oldfd, int newfd, int flags)
{
    (void)oldfd;
    (void)newfd;
    (void)flags;
    ++g_real_dup_calls;
    return g_real_dup_return;
}
#endif

/** @brief Real-function stub for fsync: records fd and guard. */
static int chaos_test_real_fsync_impl(int fd)
{
    ++g_real_fsync_calls;
    g_real_fsync_fd = fd;
    g_real_fsync_guard = g_chaos_io_tls_guard;
    return g_real_fsync_return;
}

/** @brief Real-function stub for fdatasync: records fd and guard. */
static int chaos_test_real_fdatasync_impl(int fd)
{
    ++g_real_fdatasync_calls;
    g_real_fdatasync_fd = fd;
    g_real_fdatasync_guard = g_chaos_io_tls_guard;
    return g_real_fdatasync_return;
}

/** @brief Real-function stub for ftruncate: records fd, length and guard. */
static int chaos_test_real_ftruncate_impl(int fd, off_t length)
{
    ++g_real_ftruncate_calls;
    g_real_ftruncate_fd = fd;
    g_real_ftruncate_length = length;
    g_real_ftruncate_guard = g_chaos_io_tls_guard;
    return g_real_ftruncate_return;
}

/** @brief Real-function stub for renameat2: records flags, returns 0. */
static int chaos_test_real_renameat2_impl(
    int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags
)
{
    (void)olddirfd;
    (void)oldpath;
    (void)newdirfd;
    (void)newpath;
    ++g_real_renameat2_calls;
    g_real_renameat2_flags = flags;
    return 0;
}

/** @brief Real-function stub for fopen: records the path pointer, returns `g_real_fopen_return`. */
static FILE *chaos_test_real_fopen_impl(const char *path, const char *mode)
{
    (void)mode;
    ++g_real_fopen_calls;
    g_real_fopen_path = path;
    return g_real_fopen_return;
}

/** @brief Real-function stub for freopen: records the path pointer, returns
 * `g_real_fopen_return`. */
static FILE *chaos_test_real_freopen_impl(const char *path, const char *mode, FILE *stream)
{
    (void)mode;
    (void)stream;
    ++g_real_freopen_calls;
    g_real_fopen_path = path;
    return g_real_fopen_return;
}

/** @brief Real-function stub for posix_fallocate: returns `g_real_posix_fallocate_return`, an
 * error number (posix_fallocate reports errors by return value, not errno). */
static int chaos_test_real_posix_fallocate_impl(int fd, off_t offset, off_t length)
{
    (void)fd;
    (void)offset;
    (void)length;
    ++g_real_posix_fallocate_calls;
    return g_real_posix_fallocate_return;
}

/** @brief Real-function stub for truncate: records length and guard. */
static int chaos_test_real_truncate_impl(const char *path, off_t length)
{
    (void)path;
    ++g_real_truncate_calls;
    g_real_truncate_length = length;
    g_real_truncate_guard = g_chaos_io_tls_guard;
    return g_real_truncate_return;
}

/** @brief Real-function stub for unlinkat: records dirfd, path, flags and guard. */
static int chaos_test_real_unlinkat_impl(int dirfd, const char *path, int flags)
{
    ++g_real_unlinkat_calls;
    g_real_unlinkat_dirfd = dirfd;
    g_real_unlinkat_flags = flags;
    g_real_unlinkat_guard = g_chaos_io_tls_guard;
    if (path != NULL)
    {
        (void)snprintf(g_real_unlinkat_path, sizeof(g_real_unlinkat_path), "%s", path);
    }
    else
    {
        g_real_unlinkat_path[0] = '\0';
    }
    return g_real_unlinkat_return;
}

/** @brief Real-function stub for renameat: records both dirfds, both paths and the guard. */
static int
chaos_test_real_renameat_impl(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    ++g_real_renameat_calls;
    g_real_renameat_olddirfd = olddirfd;
    g_real_renameat_newdirfd = newdirfd;
    g_real_renameat_guard = g_chaos_io_tls_guard;
    if (oldpath != NULL)
    {
        (void)snprintf(g_real_renameat_oldpath, sizeof(g_real_renameat_oldpath), "%s", oldpath);
    }
    else
    {
        g_real_renameat_oldpath[0] = '\0';
    }
    if (newpath != NULL)
    {
        (void)snprintf(g_real_renameat_newpath, sizeof(g_real_renameat_newpath), "%s", newpath);
    }
    else
    {
        g_real_renameat_newpath[0] = '\0';
    }
    return g_real_renameat_return;
}

/**
 * @brief Real-function stub for pread: records fd, count, offset and guard; when the
 *        configured return is > 0, copies that many bytes of `g_real_pread_fill` (64 bytes).
 */
static ssize_t chaos_test_real_pread_impl(int fd, void *buffer, size_t count, off_t offset)
{
    ++g_real_pread_calls;
    g_real_pread_fd = fd;
    g_real_pread_count = count;
    g_real_pread_offset = offset;
    g_real_pread_guard = g_chaos_io_tls_guard;

    if (buffer != NULL && g_real_pread_return > 0)
    {
        (void)memcpy(buffer, g_real_pread_fill, (size_t)g_real_pread_return);
    }

    return g_real_pread_return;
}

/** @brief Real-function stub for preadv: records fd, offset, guard and iovec layout; scatters
 * `g_real_pread_fill` when the configured return is > 0. */
static ssize_t
chaos_test_real_preadv_impl(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    ++g_real_preadv_calls;
    g_real_preadv_fd = fd;
    g_real_preadv_guard = g_chaos_io_tls_guard;
    g_real_preadv_offset = offset;
    chaos_test_capture_iov_lengths(iov, iovcnt, &g_real_preadv_iovcnt, g_real_preadv_lengths);

    if (g_real_preadv_return > 0)
    {
        chaos_test_fill_iovecs(iov, iovcnt, g_real_pread_fill, (size_t)g_real_preadv_return);
    }

    return g_real_preadv_return;
}

/** @brief Real-function stub for pwrite: records fd, count, offset and guard. */
static ssize_t chaos_test_real_pwrite_impl(int fd, const void *buffer, size_t count, off_t offset)
{
    (void)buffer;
    ++g_real_pwrite_calls;
    g_real_pwrite_fd = fd;
    g_real_pwrite_count = count;
    g_real_pwrite_offset = offset;
    g_real_pwrite_guard = g_chaos_io_tls_guard;
    return g_real_pwrite_return;
}

/** @brief Real-function stub for pwritev: records fd, offset, guard and iovec layout. */
static ssize_t
chaos_test_real_pwritev_impl(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    ++g_real_pwritev_calls;
    g_real_pwritev_fd = fd;
    g_real_pwritev_guard = g_chaos_io_tls_guard;
    g_real_pwritev_offset = offset;
    chaos_test_capture_iov_lengths(iov, iovcnt, &g_real_pwritev_iovcnt, g_real_pwritev_lengths);
    return g_real_pwritev_return;
}

/* -------------------------------------------------------------------------
 * dlsym / dlerror / abort / syscall override implementations
 * --------------------------------------------------------------------- */

/**
 * @brief Copies a function pointer's bytes into a `void *`.
 *
 * ISO C leaves function-pointer to object-pointer casts undefined; POSIX guarantees the
 * representations match, so a byte copy is the portable way to build a dlsym() result.
 *
 * @param function_bytes  Address of a function-pointer object; must not be NULL (asserted).
 * @param function_size   Size of that object; must be <= sizeof(void *) (asserted).
 * @return A `void *` with the same bit pattern as the function pointer.
 */
static void *chaos_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

/**
 * @brief Yields the `void *` the dlsym stub returns for @p function, e.g.
 *        `CHAOS_TEST_DLSYM_RESULT(chaos_io_read_fn, chaos_test_real_read_impl)`.
 *
 * The compound literal `(type){function}` lives until the end of the enclosing block, which
 * outlasts the memcpy() inside chaos_test_dlsym_pointer(). A @p function whose type does not
 * match @p type draws a compiler diagnostic.
 */
#define CHAOS_TEST_DLSYM_RESULT(type, function)                                                    \
    chaos_test_dlsym_pointer(&(type){function}, sizeof(type))

/** @brief Returns 1 when @p symbol is one of the 15 stdio functions libchaos-io wraps. */
static int chaos_test_is_stdio_symbol(const char *symbol)
{
    static const char *const names[] = {
        "fread",
        "fwrite",
        "fgets",
        "fputs",
        "fgetc",
        "getc",
        "fputc",
        "putc",

        "getdelim",
        "vfprintf",
        "fflush",
        "__vfprintf_chk",
        "__fread_chk",
        "__fgets_chk",
        "fclose"
    };
    size_t index;

    for (index = 0U; index < sizeof(names) / sizeof(names[0]); ++index)
    {
        if (strcmp(symbol, names[index]) == 0)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Replacement for dlsym(RTLD_NEXT, symbol) inside the production sources.
 *
 * Returns the matching `chaos_test_real_*_impl` stub for each descriptor/path symbol and the
 * genuine C library function for the stdio symbols. Returns NULL with a pending dlerror()
 * message for `g_dlsym_fail_symbol` and for any unknown name, so a symbol added to
 * production without a stub here fails loudly instead of resolving to garbage.
 *
 * @param handle  Ignored.
 * @param symbol  Symbol name; must not be NULL.
 * @return The stub, the real stdio function, or NULL.
 */
static void *chaos_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    g_dlerror_pending = NULL;
    if (g_dlsym_fail_symbol != NULL && strcmp(symbol, g_dlsym_fail_symbol) == 0)
    {
        g_dlerror_pending = "missing symbol";
        return NULL;
    }
    if (strcmp(symbol, "read") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_read_fn, chaos_test_real_read_impl);
    }
    if (strcmp(symbol, "write") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_write_fn, chaos_test_real_write_impl);
    }
    if (strcmp(symbol, "readv") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_readv_fn, chaos_test_real_readv_impl);
    }
    if (strcmp(symbol, "writev") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_writev_fn, chaos_test_real_writev_impl);
    }
#ifdef __linux__
    if (strcmp(symbol, "fallocate") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_fallocate_fn, chaos_test_real_fallocate_impl);
    }
    if (strcmp(symbol, "sendfile") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sendfile_fn, chaos_test_real_sendfile_impl);
    }
    if (strcmp(symbol, "copy_file_range") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(
            chaos_io_copy_file_range_fn, chaos_test_real_copy_file_range_impl
        );
    }
#endif
    if (strcmp(symbol, "open") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_open_fn, chaos_test_real_open_impl);
    }
    if (strcmp(symbol, "openat") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_openat_fn, chaos_test_real_openat_impl);
    }
    if (strcmp(symbol, "close") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_close_fn, chaos_test_real_close_impl);
    }
    if (strcmp(symbol, "dup2") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_dup2_fn, chaos_test_real_dup2_impl);
    }
    if (strcmp(symbol, "closedir") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_closedir_fn, chaos_test_real_closedir_impl);
    }
    if (strcmp(symbol, "pclose") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pclose_fn, chaos_test_real_pclose_impl);
    }
    if (strcmp(symbol, "closefrom") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_closefrom_fn, chaos_test_real_closefrom_impl);
    }
    if (strcmp(symbol, "close_range") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_close_range_fn, chaos_test_real_close_range_impl);
    }
#ifdef __linux__
    if (strcmp(symbol, "dup3") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_dup3_fn, chaos_test_real_dup3_impl);
    }
#endif
    if (strcmp(symbol, "fsync") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sync_fn, chaos_test_real_fsync_impl);
    }
    if (strcmp(symbol, "fdatasync") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_sync_fn, chaos_test_real_fdatasync_impl);
    }
    if (strcmp(symbol, "ftruncate") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_ftruncate_fn, chaos_test_real_ftruncate_impl);
    }
    if (strcmp(symbol, "posix_fallocate") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(
            chaos_io_posix_fallocate_fn, chaos_test_real_posix_fallocate_impl
        );
    }
    if (strcmp(symbol, "truncate") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_truncate_fn, chaos_test_real_truncate_impl);
    }
    if (strcmp(symbol, "fopen") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_fopen_fn, chaos_test_real_fopen_impl);
    }
    if (strcmp(symbol, "freopen") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_freopen_fn, chaos_test_real_freopen_impl);
    }
    if (strcmp(symbol, "unlinkat") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_unlinkat_fn, chaos_test_real_unlinkat_impl);
    }
    if (strcmp(symbol, "renameat") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_renameat_fn, chaos_test_real_renameat_impl);
    }
    if (strcmp(symbol, "pread") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pread_fn, chaos_test_real_pread_impl);
    }
    if (strcmp(symbol, "pwrite") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pwrite_fn, chaos_test_real_pwrite_impl);
    }
    if (strcmp(symbol, "preadv") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_preadv_fn, chaos_test_real_preadv_impl);
    }
    if (strcmp(symbol, "pwritev") == 0)
    {
        return CHAOS_TEST_DLSYM_RESULT(chaos_io_pwritev_fn, chaos_test_real_pwritev_impl);
    }

    /* The test binary's own printf/fputs output runs through the stdio wrappers compiled
     * in above, so stdio must resolve to the real C library, never to a stub. */
    if (chaos_test_is_stdio_symbol(symbol))
    {
        return dlsym(RTLD_NEXT, symbol);
    }

    g_dlerror_pending = "unexpected symbol";
    return NULL;
}

/**
 * @brief Replacement for dlerror(): returns the pending message and clears it, so a second
 *        call returns NULL, matching POSIX.
 */
static char *chaos_test_dlerror(void)
{
    char *message = (char *)g_dlerror_pending;
    g_dlerror_pending = NULL;
    return message;
}

/**
 * @brief Replacement for abort() inside the production sources.
 *
 * With `g_abort_expected` set, records the call and longjmp()s to `g_abort_env`, so a test
 * can prove the fatal path is reached and keep running. Otherwise exits with status 111,
 * distinguishable from a failed assert() (SIGABRT, shell status 134). Never returns.
 */
static void chaos_test_abort(void)
{
    if (g_abort_expected)
    {
        g_abort_called = 1;
        longjmp(g_abort_env, 1);
    }
    exit(111);
}

/**
 * @brief Replacement for syscall() inside the production sources.
 *
 * - SYS_openat, SYS_read, SYS_close: the constructor's raw /dev/urandom seed read. Counted;
 *   SYS_read copies up to `g_sys_read_result` bytes of `g_sys_seed_value` when positive.
 * - SYS_renameat2: counted, returns 0.
 * - SYS_close_range (436 where the headers lack the constant): returns
 *   `g_sys_close_range_result`.
 * - Anything else: returns -1 without setting errno.
 */
static long chaos_test_syscall(long number, ...)
{
    va_list args;
    long result = -1;

    va_start(args, number);
    if (number == SYS_openat)
    {
        (void)va_arg(args, int);
        (void)va_arg(args, const char *);
        (void)va_arg(args, int);
        (void)va_arg(args, int);
        ++g_sys_open_calls;
        result = g_sys_open_result;
    }
    else if (number == SYS_read)
    {
        int fd = va_arg(args, int);
        void *buffer = va_arg(args, void *);
        size_t size = va_arg(args, size_t);

        (void)fd;
        ++g_sys_read_calls;
        if (g_sys_read_result > 0)
        {
            size_t copy_size = (size_t)g_sys_read_result;
            if (copy_size > size)
            {
                copy_size = size;
            }
            (void)memcpy(buffer, &g_sys_seed_value, copy_size);
        }
        result = g_sys_read_result;
    }
    else if (number == SYS_close)
    {
        (void)va_arg(args, int);
        ++g_sys_close_calls;
        result = g_sys_close_result;
    }
#ifdef SYS_renameat2
    else if (number == SYS_renameat2)
    {
        ++g_sys_renameat2_calls;
        result = 0;
    }
#endif
#ifdef SYS_close_range
    else if (number == SYS_close_range)
    {
        result = g_sys_close_range_result;
    }
#else
    else if (number == 436)
    {
        result = g_sys_close_range_result;
    }
#endif
    va_end(args);

    return result;
}

/* -------------------------------------------------------------------------
 * Production source inclusion
 *
 * Every override below must be in scope before the production sources are parsed.
 * CHAOS_IO_CONSTRUCTOR is defined empty to drop the constructor attribute, so chaos_io_init()
 * runs only when a test calls it.
 * --------------------------------------------------------------------- */

/** @brief Calls of the checked iovec-array copy (process_vm_readv) by the vectored wrappers. */
static int g_vm_readv_calls = 0;
/** @brief errno the iovec-array copy fails with; 0 makes it succeed. */
static int g_vm_readv_errno = 0;

/**
 * @brief Replacement for CHAOS_IO_PROCESS_VM_READV, the vectored wrappers' fault-safe copy of
 *        the caller's iovec array.
 *
 * Copies @p remote into @p local and returns its length, or fails with -1 and errno
 * `g_vm_readv_errno`: EFAULT models an unreadable array, ENOSYS/EPERM a kernel or seccomp
 * policy without process_vm_readv.
 */
static long chaos_test_process_vm_readv(const struct iovec *local, const struct iovec *remote)
{
    ++g_vm_readv_calls;
    if (g_vm_readv_errno != 0)
    {
        errno = g_vm_readv_errno;
        return -1;
    }
    (void)memcpy(local->iov_base, remote->iov_base, remote->iov_len);
    return (long)remote->iov_len;
}

#define CHAOS_IO_PROCESS_VM_READV(local, remote) chaos_test_process_vm_readv((local), (remote))
#define dlsym chaos_test_dlsym
#define dlerror chaos_test_dlerror
#define abort chaos_test_abort
#define syscall chaos_test_syscall
#define CHAOS_IO_CONSTRUCTOR
#include "../../src/core/chaos_io.c"
#include "../../src/wrappers/chaos_io_open.c"
#include "../../src/wrappers/chaos_io_rw.c"
#include "../../src/wrappers/chaos_io_fsops.c"
#include "../../src/wrappers/chaos_io_sync.c"
#include "../../src/wrappers/chaos_io_stdio.c"
#undef CHAOS_IO_CONSTRUCTOR
#undef syscall
#undef abort
#undef dlerror
#undef dlsym

/* -------------------------------------------------------------------------
 * Test state management
 * --------------------------------------------------------------------- */

/**
 * @brief Points the 15 stdio real functions at the C library via dlsym(RTLD_NEXT).
 *
 * @details The stdio wrappers are compiled into the test binary and therefore replace its own
 * printf, fputs, fflush and friends; their real functions must always reach libc or test
 * output recurses or vanishes. Stdio tests that swap in counting stubs call this afterwards.
 */
static void chaos_test_bind_real_stdio(void)
{
    {
        void *resolved = dlsym(RTLD_NEXT, "fclose");

        (void)memcpy(&g_chaos_io_real_fclose, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fread");

        (void)memcpy(&g_chaos_io_real_fread, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fwrite");

        (void)memcpy(&g_chaos_io_real_fwrite, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fgets");

        (void)memcpy(&g_chaos_io_real_fgets, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fputs");

        (void)memcpy(&g_chaos_io_real_fputs, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fgetc");

        (void)memcpy(&g_chaos_io_real_fgetc, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "getc");

        (void)memcpy(&g_chaos_io_real_getc, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fputc");

        (void)memcpy(&g_chaos_io_real_fputc, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "putc");

        (void)memcpy(&g_chaos_io_real_putc, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "getdelim");

        (void)memcpy(&g_chaos_io_real_getdelim, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "vfprintf");

        (void)memcpy(&g_chaos_io_real_vfprintf, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "fflush");

        (void)memcpy(&g_chaos_io_real_fflush, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "__vfprintf_chk");

        (void)memcpy(&g_chaos_io_real_vfprintf_chk, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "__fread_chk");

        (void)memcpy(&g_chaos_io_real_fread_chk, &resolved, sizeof(resolved));
    }
    {
        void *resolved = dlsym(RTLD_NEXT, "__fgets_chk");

        (void)memcpy(&g_chaos_io_real_fgets_chk, &resolved, sizeof(resolved));
    }
}

/**
 * @brief Returns all harness state and the libchaos-io globals to test defaults.
 *
 * Call first in every test. Effects:
 * - Call counters 0; captured fds -1; captured paths and fill buffers empty.
 * - Stub returns 0, except open/openat (10, a plausible descriptor) and SYS_read/SYS_openat/
 *   close_range (-1, failing).
 * - `g_sys_seed_value` = 0x0123456789abcdef, a known non-zero seed.
 * - `g_chaos_io_symbols_once` back to CHAOS_ONCE_INIT, so chaos_io_ensure_symbols() resolves
 *   again and its lazy path is testable.
 * - The descriptor/path real functions NULL (dup2, dup3, close_range, closedir, pclose and
 *   closefrom are not reset); the stdio ones bound to libc via chaos_test_bind_real_stdio().
 * - Reentrancy guard and PRNG state 0; `g_chaos_io_process_seed` 0 (unseeded, unlike
 *   chaos_test_reset_runtime(), which sets 1).
 */
static void chaos_test_reset_state(void)
{
    g_real_closedir_calls = 0;
    g_real_pclose_calls = 0;
    g_real_closefrom_calls = 0;
    g_real_closefrom_lowfd = -1;
    g_sys_close_range_result = -1;
    g_sys_renameat2_calls = 0;
    g_vm_readv_calls = 0;
    g_vm_readv_errno = 0;
    (void)memset(&g_config_rule, 0, sizeof(g_config_rule));
    g_config_init_calls = 0;
    g_config_prepare_calls = 0;
    g_config_match_loaded_calls = 0;
    g_config_match_path_calls = 0;
    g_config_prepare_result = 0;
    g_config_match_loaded_result = 0;
    g_config_match_path_result = 0;
    g_last_match_loaded_operation = CHAOS_IO_OP_INVALID;
    g_last_match_path_operation = CHAOS_IO_OP_INVALID;
    g_last_match_loaded_path[0] = '\0';
    g_last_match_path[0] = '\0';

    g_fdcache_reset_calls = 0;
    g_fdcache_resolve_calls = 0;
    g_fdcache_store_calls = 0;
    g_fdcache_invalidate_calls = 0;
    g_fdcache_resolve_result = 0;
    g_last_resolve_fd = -1;
    g_last_store_fd = -1;
    g_last_invalidate_fd = -1;
    g_resolved_path[0] = '\0';
    g_last_store_path[0] = '\0';

    g_latency_calls = 0;
    g_rule_apply_errno_calls = 0;
    g_rule_should_trigger_calls = 0;
    g_rule_apply_errno_result = 0;
    g_rule_should_trigger_result = 0;
    g_torn_count_result = 0U;
    g_last_torn_requested = 0U;
    g_corrupt_calls = 0;
    g_last_corrupt_size = 0U;
    g_corrupt_sample_calls = 0;
    g_last_corrupt_sample_size = 0U;
    g_last_corrupt_index_sample = 0U;
    g_last_corrupt_bit_sample = 0U;

    g_real_open_calls = 0;
    g_real_open_return = 10;
    g_real_open_flags = 0;
    g_real_open_has_mode = 0;
    g_real_open_guard = 0;
    g_real_open_mode = 0;
    g_real_open_path[0] = '\0';

    g_real_openat_calls = 0;
    g_real_openat_return = 10;
    g_real_openat_dirfd = -1;
    g_real_openat_flags = 0;
    g_real_openat_has_mode = 0;
    g_real_openat_guard = 0;
    g_real_openat_mode = 0;
    g_real_openat_path[0] = '\0';

    g_real_read_calls = 0;
    g_real_read_return = 0;
    g_real_read_guard = 0;
    g_real_read_fd = -1;
    g_real_read_count = 0U;
    (void)memset(g_real_read_fill, 0, sizeof(g_real_read_fill));
    g_real_readv_calls = 0;
    g_real_readv_return = 0;
    g_real_readv_guard = 0;
    g_real_readv_fd = -1;
    g_real_readv_iovcnt = 0;
    (void)memset(g_real_readv_lengths, 0, sizeof(g_real_readv_lengths));

    g_real_write_calls = 0;
    g_real_write_return = 0;
    g_real_write_guard = 0;
    g_real_write_fd = -1;
    g_real_write_count = 0U;
    g_real_writev_calls = 0;
    g_real_writev_return = 0;
    g_real_writev_guard = 0;
    g_real_writev_fd = -1;
    g_real_writev_iovcnt = 0;
    (void)memset(g_real_writev_lengths, 0, sizeof(g_real_writev_lengths));
#ifdef __linux__
    g_real_fallocate_calls = 0;
    g_real_fallocate_return = 0;
    g_real_fallocate_guard = 0;
    g_real_fallocate_fd = -1;
    g_real_fallocate_mode = 0;
    g_real_fallocate_offset = 0;
    g_real_fallocate_length = 0;
    g_real_sendfile_calls = 0;
    g_real_sendfile_return = 0;
    g_real_sendfile_guard = 0;
    g_real_sendfile_out_fd = -1;
    g_real_sendfile_in_fd = -1;
    g_real_sendfile_offset = NULL;
    g_real_sendfile_count = 0U;
    g_real_copy_file_range_calls = 0;
    g_real_copy_file_range_return = 0;
    g_real_copy_file_range_guard = 0;
    g_real_copy_file_range_in_fd = -1;
    g_real_copy_file_range_out_fd = -1;
    g_real_copy_file_range_in_offset = NULL;
    g_real_copy_file_range_out_offset = NULL;
    g_real_copy_file_range_count = 0U;
    g_real_copy_file_range_flags = 0U;
#endif

    g_real_close_calls = 0;
    g_real_close_return = 0;
    g_real_close_guard = 0;
    g_real_dup_calls = 0;
    g_real_dup_return = 0;
    g_real_close_fd = -1;

    g_real_fsync_calls = 0;
    g_real_fsync_return = 0;
    g_real_fsync_guard = 0;
    g_real_fsync_fd = -1;

    g_real_fdatasync_calls = 0;
    g_real_fdatasync_return = 0;
    g_real_fdatasync_guard = 0;
    g_real_fdatasync_fd = -1;

    g_real_ftruncate_calls = 0;
    g_real_ftruncate_return = 0;
    g_real_ftruncate_guard = 0;
    g_real_ftruncate_fd = -1;
    g_real_ftruncate_length = 0;

    g_real_renameat2_calls = 0;
    g_real_renameat2_flags = 0U;
    g_real_posix_fallocate_calls = 0;
    g_real_posix_fallocate_return = 0;

    g_real_truncate_calls = 0;
    g_real_truncate_return = 0;
    g_real_truncate_guard = 0;
    g_real_truncate_length = 0;
    g_real_fopen_calls = 0;
    g_real_freopen_calls = 0;
    g_real_fopen_return = NULL;
    g_real_fopen_path = NULL;

    g_real_unlinkat_calls = 0;
    g_real_unlinkat_return = 0;
    g_real_unlinkat_guard = 0;
    g_real_unlinkat_dirfd = -1;
    g_real_unlinkat_flags = 0;
    g_real_unlinkat_path[0] = '\0';

    g_real_renameat_calls = 0;
    g_real_renameat_return = 0;
    g_real_renameat_guard = 0;
    g_real_renameat_olddirfd = -1;
    g_real_renameat_newdirfd = -1;
    g_real_renameat_oldpath[0] = '\0';
    g_real_renameat_newpath[0] = '\0';

    g_real_pread_calls = 0;
    g_real_pread_return = 0;
    g_real_pread_guard = 0;
    g_real_pread_fd = -1;
    g_real_pread_count = 0U;
    g_real_pread_offset = 0;
    (void)memset(g_real_pread_fill, 0, sizeof(g_real_pread_fill));
    g_real_preadv_calls = 0;
    g_real_preadv_return = 0;
    g_real_preadv_guard = 0;
    g_real_preadv_fd = -1;
    g_real_preadv_iovcnt = 0;
    g_real_preadv_offset = 0;
    (void)memset(g_real_preadv_lengths, 0, sizeof(g_real_preadv_lengths));

    g_real_pwrite_calls = 0;
    g_real_pwrite_return = 0;
    g_real_pwrite_guard = 0;
    g_real_pwrite_fd = -1;
    g_real_pwrite_count = 0U;
    g_real_pwrite_offset = 0;
    g_real_pwritev_calls = 0;
    g_real_pwritev_return = 0;
    g_real_pwritev_guard = 0;
    g_real_pwritev_fd = -1;
    g_real_pwritev_iovcnt = 0;
    g_real_pwritev_offset = 0;
    (void)memset(g_real_pwritev_lengths, 0, sizeof(g_real_pwritev_lengths));

    g_sys_open_calls = 0;
    g_sys_read_calls = 0;
    g_sys_close_calls = 0;
    g_sys_open_result = -1;
    g_sys_read_result = -1;
    g_sys_close_result = 0;
    g_sys_seed_value = UINT64_C(0x0123456789abcdef);

    g_dlsym_fail_symbol = NULL;
    g_dlerror_pending = NULL;
    g_abort_expected = 0;
    g_abort_called = 0;
    /* Reset alongside the pointer table so the library is returned to its
     * pre-constructor state.  Without this a test cannot exercise the lazy
     * resolution path in chaos_io_ensure_symbols(). */
    {
        g_chaos_io_symbols_once = CHAOS_ONCE_INIT;
    }
    g_chaos_io_real_read = NULL;
    g_chaos_io_real_write = NULL;
    g_chaos_io_real_readv = NULL;
    g_chaos_io_real_writev = NULL;
    g_chaos_io_real_open = NULL;
    g_chaos_io_real_openat = NULL;
    g_chaos_io_real_close = NULL;
    g_chaos_io_real_fsync = NULL;
    g_chaos_io_real_fdatasync = NULL;
    g_chaos_io_real_pread = NULL;
    g_chaos_io_real_pwrite = NULL;
    g_chaos_io_real_preadv = NULL;
    g_chaos_io_real_pwritev = NULL;
    g_chaos_io_real_ftruncate = NULL;
    g_chaos_io_real_unlinkat = NULL;
    g_chaos_io_real_truncate = NULL;
    g_chaos_io_real_fopen = NULL;
    g_chaos_io_real_freopen = NULL;
    g_chaos_io_real_renameat2 = NULL;
    g_chaos_io_real_posix_fallocate = NULL;
    g_chaos_io_real_renameat = NULL;
#ifdef __linux__
    g_chaos_io_real_fallocate = NULL;
    g_chaos_io_real_sendfile = NULL;
    g_chaos_io_real_copy_file_range = NULL;
#endif
    g_chaos_io_tls_guard = 0;
    g_chaos_io_tls_prng_state = 0U;
    g_chaos_io_process_seed = 0U;
    chaos_test_bind_real_stdio();
}

/**
 * @brief Points every real function at its `chaos_test_real_*_impl` stub (stdio stays libc).
 *
 * A wrapper called afterwards runs its full path, guard handling included, and ends in a stub
 * that records the call instead of entering the kernel.
 */
static void chaos_test_bind_real_functions(void)
{
    g_chaos_io_real_read = chaos_test_real_read_impl;
    g_chaos_io_real_write = chaos_test_real_write_impl;
    g_chaos_io_real_readv = chaos_test_real_readv_impl;
    g_chaos_io_real_writev = chaos_test_real_writev_impl;
    g_chaos_io_real_open = chaos_test_real_open_impl;
    g_chaos_io_real_openat = chaos_test_real_openat_impl;
    g_chaos_io_real_close = chaos_test_real_close_impl;
    g_chaos_io_real_dup2 = chaos_test_real_dup2_impl;
    g_chaos_io_real_close_range = chaos_test_real_close_range_impl;
    g_chaos_io_real_closedir = chaos_test_real_closedir_impl;
    g_chaos_io_real_pclose = chaos_test_real_pclose_impl;
    g_chaos_io_real_closefrom = chaos_test_real_closefrom_impl;
#ifdef __linux__
    g_chaos_io_real_dup3 = chaos_test_real_dup3_impl;
#endif
    g_chaos_io_real_fsync = chaos_test_real_fsync_impl;
    g_chaos_io_real_fdatasync = chaos_test_real_fdatasync_impl;
    g_chaos_io_real_pread = chaos_test_real_pread_impl;
    g_chaos_io_real_pwrite = chaos_test_real_pwrite_impl;
    g_chaos_io_real_preadv = chaos_test_real_preadv_impl;
    g_chaos_io_real_pwritev = chaos_test_real_pwritev_impl;
    g_chaos_io_real_ftruncate = chaos_test_real_ftruncate_impl;
    g_chaos_io_real_unlinkat = chaos_test_real_unlinkat_impl;
    g_chaos_io_real_truncate = chaos_test_real_truncate_impl;
    g_chaos_io_real_fopen = chaos_test_real_fopen_impl;
    g_chaos_io_real_freopen = chaos_test_real_freopen_impl;
    g_chaos_io_real_renameat2 = chaos_test_real_renameat2_impl;
    g_chaos_io_real_posix_fallocate = chaos_test_real_posix_fallocate_impl;
    g_chaos_io_real_renameat = chaos_test_real_renameat_impl;
#ifdef __linux__
    g_chaos_io_real_fallocate = chaos_test_real_fallocate_impl;
    g_chaos_io_real_sendfile = chaos_test_real_sendfile_impl;
    g_chaos_io_real_copy_file_range = chaos_test_real_copy_file_range_impl;
#endif
    chaos_test_bind_real_stdio();
}

/**
 * @brief Points the real functions back at the C library before the test binary exits.
 *
 * exit() flushes and closes streams through write/close, which in this binary are libchaos-io
 * wrappers; left on the stubs, buffered output would be discarded. Resolves each real
 * function with dlsym(RTLD_NEXT) (asserting it exists; renameat2 may be NULL on libcs without
 * it) and zeroes the config, fd-cache and effect stub results so no rule applies to shutdown
 * I/O. test_chaos_io.c calls it at the end of main().
 */
static void chaos_test_bind_libc_functions_for_exit(void)
{
    void *resolved;

    resolved = dlsym(RTLD_NEXT, "read");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_read, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "write");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_write, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "readv");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_readv, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "writev");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_writev, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "open");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_open, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "openat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_openat, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "close");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_close, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "fsync");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fsync, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "fdatasync");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fdatasync, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "ftruncate");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_ftruncate, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "posix_fallocate");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_posix_fallocate, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "renameat2");
    (void)memcpy(&g_chaos_io_real_renameat2, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "truncate");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_truncate, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "fopen");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fopen, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "freopen");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_freopen, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "unlinkat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_unlinkat, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "renameat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_renameat, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "dup2");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_dup2, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "pread");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_pread, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "pwrite");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_pwrite, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "preadv");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_preadv, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "pwritev");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_pwritev, &resolved, sizeof(resolved));
#ifdef __linux__
    resolved = dlsym(RTLD_NEXT, "fallocate");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_fallocate, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "sendfile");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_sendfile, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "copy_file_range");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_copy_file_range, &resolved, sizeof(resolved));
#endif

    g_config_prepare_result = 0;
    g_config_match_loaded_result = 0;
    g_config_match_path_result = 0;
    g_fdcache_resolve_result = 0;
    g_rule_apply_errno_result = 0;
    g_rule_should_trigger_result = 0;
    chaos_test_bind_real_stdio();
}

#endif
