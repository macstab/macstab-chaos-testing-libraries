/**
 * @file test_chaos_io_harness.h
 * @brief Full IO-domain wrapper harness: stubs, global state, and production source inclusion.
 *
 * Subsystem under test: chaos-io wrapper layer (chaos_io.c, chaos_io_open.c,
 *   chaos_io_rw.c, chaos_io_fsops.c, chaos_io_sync.c).
 *
 * This header is intentionally structured as a combined header+implementation unit. It
 * must be included exactly once per test binary (inside `test_chaos_io.c`). Including it
 * a second time in the same link unit causes multiple-definition errors on the many static
 * globals declared here.
 *
 * Architecture overview:
 *
 *   1. Static global variables (roughly 100+) track every call into every stubbed
 *      dependency. Each intercepted function has at minimum a call counter and a
 *      configurable return value. Functions that receive pointer arguments also capture
 *      those arguments for post-call assertions.
 *
 *   2. Stub implementations of config, fdcache, and actions functions replace the
 *      production implementations. All stubs are non-static so they satisfy the `extern`
 *      declarations used by the production wrappers that are linked in below.
 *
 *   3. Symbol overrides (`#define dlsym`, `dlerror`, `abort`, `syscall`) intercept the
 *      dynamic resolution calls made by the production `chaos_io_init()` constructor.
 *      After the overrides, the five production source files are included directly.
 *
 *   4. `chaos_test_reset_state()` resets all ~100 globals to known-good defaults
 *      (call counters to 0, return values to their safe defaults, captured arguments
 *      cleared). Every test function must call this first to prevent cross-test
 *      contamination.
 *
 *   5. `chaos_test_bind_real_functions()` wires the `g_chaos_io_real_*` table to the
 *      stub implementations for tests that need the full wrapper call path.
 *
 *   6. `chaos_test_bind_libc_functions_for_exit()` replaces the stubs with real libc
 *      symbols via `dlsym(RTLD_NEXT, ...)` before process exit. This is necessary because
 *      the C runtime calls `write`, `close`, and other IO functions during shutdown and
 *      must not go through stubs that return zero.
 *
 * Coverage approach:
 * - Production source files are compiled directly into the test binary. This gives
 *   access to all `static` helpers without LD_PRELOAD.
 * - The LD_PRELOAD interposition path (dynamic linker symbol resolution) is NOT tested
 *   here. Its correctness is verified by the integration test suite that loads the real
 *   `.so` files into a target process.
 *
 * What is NOT tested by this harness:
 * - Concurrent access to the TLS guard from multiple threads.
 * - OS-level read/write semantics (partial transfers, signals, EINTR retry loops).
 * - Config hot-reload under real filesystem mtime changes.
 */

#ifndef CHAOS_IO_TEST_HARNESS_H
#define CHAOS_IO_TEST_HARNESS_H

#include "test_support.h"

#include "../../src/effects/chaos_io_actions.h"
#include "../../src/config/chaos_io_config.h"
#include "../../src/config/chaos_io_fdcache.h"

#include <dlfcn.h>
#include <setjmp.h>
#include <sys/syscall.h>

/** @brief Maximum number of iovec lengths captured in a single stubbed vectored call. */
#define CHAOS_TEST_IOV_SNAPSHOT_COUNT 4

/* -------------------------------------------------------------------------
 * Config subsystem stubs
 * --------------------------------------------------------------------- */

/** @brief Number of times the config subsystem initializer was called. */
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
/** @brief Operation argument captured from the most recent `chaos_io_config_match_loaded()` call.
 */
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
/** @brief `size` argument captured from the most recent `chaos_io_corrupt_buffer_sample()` call. */
static size_t g_last_corrupt_sample_size = 0U;
/** @brief `index_sample` argument captured from the most recent `chaos_io_corrupt_buffer_sample()`
 * call. */
static uint32_t g_last_corrupt_index_sample = 0U;
/** @brief `bit_sample` argument captured from the most recent `chaos_io_corrupt_buffer_sample()`
 * call. */
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
 * @brief TLS guard value observed inside the stub open function.
 *
 * The production wrapper sets `g_chaos_io_tls_guard = 1` before dispatching to the
 * real function and restores it to 0 on return. This field captures the guard value
 * as seen by the stub, which must equal 1 to prove the guard is held during the
 * real-function call.
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
 * @brief Pattern written into the caller's buffer by the stub read function.
 *
 * When `g_real_read_return > 0`, this array is `memcpy`'d into the buffer
 * supplied by the caller, allowing tests to verify that corrupt/torn effects are
 * applied to data that was actually "read".
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
 * Real-function stubs: close / fsync / fdatasync / ftruncate / unlinkat / renameat
 * --------------------------------------------------------------------- */

/** @brief Number of times the stub close function was called. */
static int g_real_close_calls = 0;
/** @brief Return value for the stub close function. */
static int g_real_close_return = 0;
/** @brief TLS guard value observed inside the stub close function. */
static int g_real_close_guard = 0;
/** @brief `fd` argument captured from the most recent stub close call. */
static int g_real_close_fd = -1;

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
 * @brief Return value for SYS_read; also controls how many bytes are copied.
 *
 * When positive, the stub copies exactly `g_sys_read_result` bytes from
 * `g_sys_seed_value` into the caller's buffer. Set to sizeof(uint64_t) to
 * simulate a successful seed read.
 */
static long g_sys_read_result = -1;
/** @brief Return value for SYS_close; 0 is the normal success value. */
static long g_sys_close_result = 0;
/**
 * @brief Seed material value returned by the SYS_read stub.
 *
 * The production `chaos_io_init()` reads 8 bytes from `/dev/urandom` via a raw
 * SYS_read syscall to seed the per-process PRNG. This field provides the seed
 * bytes that the stub delivers, allowing tests to assert on the exact seed value
 * stored by `chaos_io_init()`.
 */
static uint64_t g_sys_seed_value = 0U;

/**
 * @brief Symbol name for which the `dlsym` stub returns NULL to exercise failure paths.
 *
 * Set to the name of a symbol that the production constructor will try to resolve.
 * The `dlsym` stub returns NULL and sets `g_dlerror_pending` for that symbol, triggering
 * the `abort()` path that the test catches via `setjmp`.
 */
static const char *g_dlsym_fail_symbol = NULL;
/** @brief Pending error string to return from the `dlerror` stub; NULL means no error. */
static const char *g_dlerror_pending = NULL;
/**
 * @brief Non-zero when the test expects `abort()` to be called.
 *
 * When set, the `chaos_test_abort()` stub invokes `longjmp(g_abort_env, 1)`
 * instead of calling `exit(111)`. Tests that exercise fatal-error paths must
 * set this flag and protect the call site with `setjmp`.
 */
static int g_abort_expected = 0;
/** @brief Set to 1 by the `abort` stub when it is triggered and `g_abort_expected == 1`. */
static int g_abort_called = 0;
/** @brief Jump buffer used by the `abort` stub to transfer control back to the test. */
static jmp_buf g_abort_env;

/* -------------------------------------------------------------------------
 * Config subsystem stub implementations
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for `chaos_io_config_init()`.
 *
 * Increments the call counter so tests can assert the constructor called this
 * exactly once.
 */
void chaos_io_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for `chaos_io_config_prepare()`.
 *
 * Returns `g_config_prepare_result`. Tests set this to 1 to simulate a
 * successful config load and to 0 to simulate a missing or unparseable file.
 */
int chaos_io_config_prepare(void)
{
    ++g_config_prepare_calls;
    return g_config_prepare_result;
}

/**
 * @brief Stub for `chaos_io_config_match_loaded()`.
 *
 * Captures @p operation and @p path for post-call assertions. When
 * `g_config_match_loaded_result != 0`, copies `g_config_rule` into @p rule and
 * returns 1. Returns 0 otherwise.
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
 * @brief Stub for `chaos_io_config_match_path()`.
 *
 * Captures @p operation and @p path. When `g_config_match_path_result != 0`,
 * copies `g_config_rule` into @p rule and returns 1.
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
 * @brief Stub for `chaos_io_fdcache_reset()`.
 *
 * Increments the call counter. The production constructor calls this once to
 * invalidate any stale cache entries from a previous `dlopen` invocation.
 */
void chaos_io_fdcache_reset(void)
{
    ++g_fdcache_reset_calls;
}

/**
 * @brief Stub for `chaos_io_fdcache_resolve()`.
 *
 * Captures @p fd. When `g_fdcache_resolve_result != 0`, copies `g_resolved_path`
 * into @p path and returns 1. Returns 0 if `g_fdcache_resolve_result == 0` or
 * if @p path is NULL.
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
 * @brief Stub for `chaos_io_fdcache_store()`.
 *
 * Captures @p fd and @p path for post-call assertions. The production wrappers
 * call this after a successful `open` or `openat` to populate the path cache.
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
 * @brief Stub for `chaos_io_fdcache_invalidate()`.
 *
 * Captures @p fd. The production wrappers call this after a successful `close`
 * or filesystem-mutation operation to remove stale cache entries.
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
 * @brief Stub for `chaos_io_rule_apply_latency()`.
 *
 * Increments the call counter. The production wrappers call this when the
 * matched rule has effect LATENCY; this stub avoids actual sleeps in tests.
 */
void chaos_io_rule_apply_latency(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_io_rule_should_trigger()`.
 *
 * Returns `g_rule_should_trigger_result`. Set to 1 in tests that want to
 * exercise the triggered path (errno/latency applied) and leave it 0 to
 * exercise the passthrough path.
 */
int chaos_io_rule_should_trigger(const chaos_io_rule_t *rule)
{
    assert(rule != NULL);
    ++g_rule_should_trigger_calls;
    return g_rule_should_trigger_result;
}

/**
 * @brief Stub for `chaos_io_rule_apply_errno()`.
 *
 * When `g_rule_apply_errno_result != 0`, sets `errno` to `rule->errnum` and
 * returns 1, simulating a successful errno injection. Returns 0 otherwise.
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
 * @brief Stub for `chaos_io_torn_count()`.
 *
 * Captures @p requested and returns `g_torn_count_result`. A torn-count of 0
 * simulates the passthrough path; a non-zero value triggers the torn-read/write
 * logic in the wrappers.
 */
size_t chaos_io_torn_count(size_t requested)
{
    g_last_torn_requested = requested;
    return g_torn_count_result;
}

/**
 * @brief Stub for `chaos_io_corrupt_buffer()`.
 *
 * Increments the call counter, captures @p size, and flips the low bit of the
 * first byte to produce a deterministic one-bit corruption observable in tests.
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
 * @brief Stub for `chaos_io_corrupt_buffer_sample()`.
 *
 * Captures all four arguments and performs the same index+bit-flip calculation
 * as the production implementation, so tests can verify that the production
 * wrapper passes the right samples to the corruption function.
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
 * @brief Capture iov lengths from up to CHAOS_TEST_IOV_SNAPSHOT_COUNT segments.
 *
 * Used by stub readv/writev/preadv/pwritev to record the iov layout so tests
 * can assert that the wrapper correctly builds or trims the iovec array.
 *
 * @param iov              Source iovec array (may be NULL).
 * @param iovcnt           Number of elements in @p iov.
 * @param captured_iovcnt  Output: receives the value of @p iovcnt.
 * @param captured_lengths Output: receives the first CHAOS_TEST_IOV_SNAPSHOT_COUNT
 *                         element lengths; extras are zeroed.
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
 * @brief Fill iovec buffers from a pattern array, stopping at `fill_size` bytes.
 *
 * Used by stub readv/preadv to simulate data delivery so that corrupt/torn
 * effects applied afterwards have actual bytes to operate on.
 *
 * @param iov       Iovec array whose buffers are to be filled.
 * @param iovcnt    Number of elements.
 * @param fill      Source pattern.
 * @param fill_size How many bytes from @p fill to distribute across the iovecs.
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
 * @brief Stub for the real `open` syscall wrapper.
 *
 * Records the call, captures path/flags/mode, and captures the TLS guard value.
 * Returns `g_real_open_return`.
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
 * @brief Stub for the real `openat` syscall wrapper.
 *
 * Records the call, captures dirfd/path/flags/mode, and captures the TLS guard.
 * Returns `g_real_openat_return`.
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
 * @brief Stub for the real `read` syscall wrapper.
 *
 * Fills the caller's buffer from `g_real_read_fill` when `g_real_read_return > 0`,
 * simulating data delivery for subsequent corruption/torn checks.
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
 * @brief Stub for the real `readv` syscall wrapper.
 *
 * Fills the iov buffers from `g_real_read_fill` when `g_real_readv_return > 0`.
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

/** @brief Stub for the real `write` syscall wrapper. Captures fd and count. */
static ssize_t chaos_test_real_write_impl(int fd, const void *buffer, size_t count)
{
    (void)buffer;
    ++g_real_write_calls;
    g_real_write_fd = fd;
    g_real_write_count = count;
    g_real_write_guard = g_chaos_io_tls_guard;
    return g_real_write_return;
}

/** @brief Stub for the real `writev` syscall wrapper. Captures fd and iov layout. */
static ssize_t chaos_test_real_writev_impl(int fd, const struct iovec *iov, int iovcnt)
{
    ++g_real_writev_calls;
    g_real_writev_fd = fd;
    g_real_writev_guard = g_chaos_io_tls_guard;
    chaos_test_capture_iov_lengths(iov, iovcnt, &g_real_writev_iovcnt, g_real_writev_lengths);
    return g_real_writev_return;
}

#ifdef __linux__
/** @brief Stub for the real `fallocate` syscall wrapper. Captures fd, mode, offset, length. */
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

/** @brief Stub for the real `sendfile` syscall wrapper. Captures out_fd, in_fd, offset, count. */
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

/** @brief Stub for the real `copy_file_range` syscall wrapper. Captures all arguments. */
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

/** @brief Stub for the real `close` syscall wrapper. Captures fd and TLS guard. */
static int chaos_test_real_close_impl(int fd)
{
    ++g_real_close_calls;
    g_real_close_fd = fd;
    g_real_close_guard = g_chaos_io_tls_guard;
    return g_real_close_return;
}

/** @brief Stub for the real `fsync` syscall wrapper. Captures fd and TLS guard. */
static int chaos_test_real_fsync_impl(int fd)
{
    ++g_real_fsync_calls;
    g_real_fsync_fd = fd;
    g_real_fsync_guard = g_chaos_io_tls_guard;
    return g_real_fsync_return;
}

/** @brief Stub for the real `fdatasync` syscall wrapper. Captures fd and TLS guard. */
static int chaos_test_real_fdatasync_impl(int fd)
{
    ++g_real_fdatasync_calls;
    g_real_fdatasync_fd = fd;
    g_real_fdatasync_guard = g_chaos_io_tls_guard;
    return g_real_fdatasync_return;
}

/** @brief Stub for the real `ftruncate` syscall wrapper. Captures fd, length, TLS guard. */
static int chaos_test_real_ftruncate_impl(int fd, off_t length)
{
    ++g_real_ftruncate_calls;
    g_real_ftruncate_fd = fd;
    g_real_ftruncate_length = length;
    g_real_ftruncate_guard = g_chaos_io_tls_guard;
    return g_real_ftruncate_return;
}

/** @brief Stub for the real `unlinkat` syscall wrapper. Captures dirfd, path, flags. */
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

/** @brief Stub for the real `renameat` syscall wrapper. Captures all four path/dirfd arguments. */
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
 * @brief Stub for the real `pread` syscall wrapper.
 *
 * Fills the caller's buffer from `g_real_pread_fill` when `g_real_pread_return > 0`.
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

/** @brief Stub for the real `preadv` syscall wrapper. Fills iov buffers from `g_real_pread_fill`.
 */
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

/** @brief Stub for the real `pwrite` syscall wrapper. Captures fd, count, and offset. */
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

/** @brief Stub for the real `pwritev` syscall wrapper. Captures fd, iov layout, and offset. */
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
 * @brief Type-safe helper to convert a typed function pointer to `void *`.
 *
 * The production `dlsym` returns `void *` which callers then cast to a typed
 * function pointer. Direct casting between data and function pointers is
 * undefined behaviour in C99. This helper uses `memcpy` through a compound
 * literal to perform the conversion without violating strict aliasing.
 *
 * @param function_bytes  Address of a function-pointer-typed compound literal.
 * @param function_size   `sizeof` the function pointer type.
 * @return `void *` carrying the same bit pattern as the function pointer.
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
 * @brief Macro to produce the `void *` result expected by the `dlsym` stub for a given stub
 * function.
 *
 * Usage: `CHAOS_TEST_DLSYM_RESULT(chaos_io_read_fn, chaos_test_real_read_impl)`
 * returns a `void *` that the production constructor will store in `g_chaos_io_real_read`.
 *
 * The compound literal `(type){function}` is valid C99 and has automatic storage
 * duration; the `memcpy` in `chaos_test_dlsym_pointer` copies the bits before the
 * literal goes out of scope.
 */
#define CHAOS_TEST_DLSYM_RESULT(type, function)                                                    \
    chaos_test_dlsym_pointer(&(type){function}, sizeof(type))

/**
 * @brief Stub for `dlsym(RTLD_NEXT, symbol)` called by the production constructor.
 *
 * Maps each expected symbol name to the corresponding stub function using the
 * CHAOS_TEST_DLSYM_RESULT macro. If `g_dlsym_fail_symbol` equals @p symbol,
 * returns NULL and sets `g_dlerror_pending` to trigger the abort path.
 *
 * An unexpected symbol also returns NULL with `g_dlerror_pending` set; this acts
 * as a test-authoring guard against typos in symbol names.
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

    g_dlerror_pending = "unexpected symbol";
    return NULL;
}

/**
 * @brief Stub for `dlerror()` called by the production constructor error path.
 *
 * Returns `g_dlerror_pending` and clears it (POSIX semantics: a second call
 * without an intervening error returns NULL). Used by the constructor to format
 * the abort message after a failed `dlsym` call.
 */
static char *chaos_test_dlerror(void)
{
    char *message = (char *)g_dlerror_pending;
    g_dlerror_pending = NULL;
    return message;
}

/**
 * @brief Stub for `abort()` called when the production constructor cannot resolve a symbol.
 *
 * When `g_abort_expected != 0`, transfers control back to the nearest enclosing
 * `setjmp` frame via `longjmp(g_abort_env, 1)` after recording the call. This
 * allows the test to verify that the fatal-error path is reached without
 * actually terminating the process.
 *
 * When `g_abort_expected == 0` (an unexpected abort), calls `exit(111)` with a
 * distinctive status code to distinguish it from an assertion failure (exit code 134).
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
 * @brief Stub for `syscall()` called by the production constructor to read seed material.
 *
 * Intercepts SYS_openat, SYS_read, and SYS_close. For SYS_read, copies
 * `g_sys_seed_value` bytes into the caller's buffer when `g_sys_read_result > 0`,
 * simulating a successful `/dev/urandom` read. This lets tests assert the exact
 * seed value stored by `chaos_io_init()`.
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
    va_end(args);

    return result;
}

/* -------------------------------------------------------------------------
 * Production source inclusion
 *
 * Symbol overrides must be in scope before the source files are parsed.
 * CHAOS_IO_CONSTRUCTOR is defined to suppress the constructor attribute so
 * the init function can be called explicitly from tests instead of
 * automatically at library load time.
 * --------------------------------------------------------------------- */

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
#undef CHAOS_IO_CONSTRUCTOR
#undef syscall
#undef abort
#undef dlerror
#undef dlsym

/* -------------------------------------------------------------------------
 * Test state management
 * --------------------------------------------------------------------- */

/**
 * @brief Reset all harness globals to their default test-safe state.
 *
 * Must be called at the start of every test function to prevent state leakage.
 * Resets all call counters to 0, all return values to safe defaults (fd
 * returns default to 10 so tests that need a valid fd do not need to configure
 * them explicitly), all captured arguments to their null/zero values, and all
 * `g_chaos_io_real_*` function pointers to NULL.
 *
 * The `g_sys_seed_value` default is `0x0123456789abcdef` so tests that exercise
 * the seed read path get a deterministic non-zero seed without extra setup.
 */
static void chaos_test_reset_state(void)
{
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
    g_chaos_io_real_renameat = NULL;
#ifdef __linux__
    g_chaos_io_real_fallocate = NULL;
    g_chaos_io_real_sendfile = NULL;
    g_chaos_io_real_copy_file_range = NULL;
#endif
    g_chaos_io_tls_guard = 0;
    g_chaos_io_tls_prng_state = 0U;
    g_chaos_io_process_seed = 0U;
}

/**
 * @brief Wire the `g_chaos_io_real_*` table to the stub implementations.
 *
 * After calling this function, invoking a production wrapper (e.g. `read()`)
 * calls through the chaos interception layer and eventually reaches the
 * corresponding `chaos_test_real_*_impl` stub. Use this in tests that need
 * to verify the full wrapper call path including guard state and argument
 * capture, without performing actual system calls.
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
    g_chaos_io_real_fsync = chaos_test_real_fsync_impl;
    g_chaos_io_real_fdatasync = chaos_test_real_fdatasync_impl;
    g_chaos_io_real_pread = chaos_test_real_pread_impl;
    g_chaos_io_real_pwrite = chaos_test_real_pwrite_impl;
    g_chaos_io_real_preadv = chaos_test_real_preadv_impl;
    g_chaos_io_real_pwritev = chaos_test_real_pwritev_impl;
    g_chaos_io_real_ftruncate = chaos_test_real_ftruncate_impl;
    g_chaos_io_real_unlinkat = chaos_test_real_unlinkat_impl;
    g_chaos_io_real_renameat = chaos_test_real_renameat_impl;
#ifdef __linux__
    g_chaos_io_real_fallocate = chaos_test_real_fallocate_impl;
    g_chaos_io_real_sendfile = chaos_test_real_sendfile_impl;
    g_chaos_io_real_copy_file_range = chaos_test_real_copy_file_range_impl;
#endif
}

/**
 * @brief Replace all stub function pointers with real libc symbols for safe process exit.
 *
 * The C runtime calls `write`, `close`, and other IO functions during `exit()`.
 * If `g_chaos_io_real_*` still points to the stubs at exit time, those calls
 * will return 0 (or whatever the stub return value is), potentially causing
 * stdout/stderr flush failures and corrupted output.
 *
 * This function resolves the real libc symbols via `dlsym(RTLD_NEXT, ...)` and
 * stores them in the function-pointer globals. It also resets the config/fdcache
 * match results to 0 so no chaos effects are applied to shutdown IO.
 *
 * Call this as the last statement in `main()` before returning.
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

    resolved = dlsym(RTLD_NEXT, "unlinkat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_unlinkat, &resolved, sizeof(resolved));

    resolved = dlsym(RTLD_NEXT, "renameat");
    assert(resolved != NULL);
    (void)memcpy(&g_chaos_io_real_renameat, &resolved, sizeof(resolved));

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
}

#endif
