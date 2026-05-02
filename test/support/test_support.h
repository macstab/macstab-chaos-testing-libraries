/**
 * @file test_support.h
 * @brief IO-domain test globals, real-IO wrappers, and file-backup utilities.
 *
 * Subsystem under test: chaos-io (LD_PRELOAD IO fault injection).
 *
 * This header is included by every unit test that exercises the IO domain. It
 * provides three categories of support:
 *
 *   1. `CHAOS_IO_DEFINE_TEST_GLOBALS()` -- a macro that instantiates all
 *      translation-unit-scoped global variables declared `extern` in the
 *      production internal headers. Each test `.c` file must expand this macro
 *      exactly once at file scope to satisfy the linker.
 *
 *   2. Real-IO thin wrappers (`chaos_test_real_open`, `chaos_test_real_read`,
 *      etc.) -- inline functions that call the actual libc symbols. These are
 *      used by tests that need to exercise the production wrappers with a real
 *      file system, or to set up test fixtures without triggering the chaos
 *      interception layer.
 *
 *   3. File backup/restore utilities (`chaos_test_backup_file`,
 *      `chaos_test_restore_file`, `chaos_test_free_backup`) -- used by config
 *      tests that must modify the live config file path and clean up afterwards.
 *
 * Coverage approach:
 * - Tests include production `.c` source files directly and call static helpers
 *   as ordinary functions. The LD_PRELOAD intercept path itself is NOT exercised
 *   here; it is verified separately by the integration test suite.
 *
 * What is NOT tested via this header:
 * - Dynamic linker interposition behaviour (symbol resolution via RTLD_NEXT).
 * - Concurrent config reload races under real multi-thread load.
 * - Signal safety of the wrappers.
 */

#ifndef CHAOS_IO_TEST_SUPPORT_H
#define CHAOS_IO_TEST_SUPPORT_H

#include "../../src/core/chaos_io_internal.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @defgroup chaos_io_test_linux_copy_globals Linux copy-operation test globals
 * @{
 *
 * Platform-conditional macros that instantiate the real-function-pointer globals
 * for Linux-only copy operations: `fallocate`, `sendfile`, and `copy_file_range`.
 * On non-Linux platforms these expand to nothing, which keeps the portable test
 * suite compiling cleanly.
 *
 * `CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()` -- declares the globals (used once
 *   per translation unit at file scope).
 * `CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()` -- wires the globals to the real libc
 *   functions (used inside `chaos_test_use_real_io()`).
 * `CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()` -- sets all three globals back to NULL
 *   (used inside `chaos_test_reset_runtime()`).
 */
#ifdef __linux__
#define CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()                                                  \
    chaos_io_fallocate_fn g_chaos_io_real_fallocate = NULL;                                        \
    chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL;                                          \
    chaos_io_copy_file_range_fn g_chaos_io_real_copy_file_range = NULL;
#define CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()                                                     \
    g_chaos_io_real_fallocate = fallocate;                                                         \
    g_chaos_io_real_sendfile = sendfile;                                                           \
    g_chaos_io_real_copy_file_range = copy_file_range;
#define CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()                                                      \
    g_chaos_io_real_fallocate = NULL;                                                              \
    g_chaos_io_real_sendfile = NULL;                                                               \
    g_chaos_io_real_copy_file_range = NULL;
#else
#define CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()
#define CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()
#define CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()
#endif
/** @} */

/**
 * @brief Instantiate all IO-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope in each test `.c` file that
 * exercises the IO domain. Expanding it more than once in the same link unit
 * causes a multiple-definition link error.
 *
 * The macro defines:
 * - All `g_chaos_io_real_*` function-pointer globals (NULL-initialised so that
 *   tests that do not need real IO calls fail loudly on the first NULL deref
 *   rather than silently calling an uninitialised pointer).
 * - `__thread int g_chaos_io_tls_guard` -- the per-thread re-entrancy guard.
 * - `__thread uint64_t g_chaos_io_tls_prng_state` -- the per-thread PRNG state.
 * - `uint64_t g_chaos_io_process_seed` -- the process-wide PRNG seed; initialised
 *   to 1 (non-zero) so PRNG operations are defined without needing a constructor.
 * - Platform-conditional Linux copy operation globals via
 *   `CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()`.
 */
#define CHAOS_IO_DEFINE_TEST_GLOBALS()                                                             \
    chaos_io_read_fn g_chaos_io_real_read = NULL;                                                  \
    chaos_io_write_fn g_chaos_io_real_write = NULL;                                                \
    chaos_io_readv_fn g_chaos_io_real_readv = NULL;                                                \
    chaos_io_writev_fn g_chaos_io_real_writev = NULL;                                              \
    chaos_io_open_fn g_chaos_io_real_open = NULL;                                                  \
    chaos_io_openat_fn g_chaos_io_real_openat = NULL;                                              \
    chaos_io_close_fn g_chaos_io_real_close = NULL;                                                \
    chaos_io_sync_fn g_chaos_io_real_fsync = NULL;                                                 \
    chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL;                                             \
    chaos_io_pread_fn g_chaos_io_real_pread = NULL;                                                \
    chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL;                                              \
    chaos_io_preadv_fn g_chaos_io_real_preadv = NULL;                                              \
    chaos_io_pwritev_fn g_chaos_io_real_pwritev = NULL;                                            \
    chaos_io_ftruncate_fn g_chaos_io_real_ftruncate = NULL;                                        \
    chaos_io_unlinkat_fn g_chaos_io_real_unlinkat = NULL;                                          \
    chaos_io_renameat_fn g_chaos_io_real_renameat = NULL;                                          \
    CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()                                                      \
    __thread int g_chaos_io_tls_guard = 0;                                                         \
    __thread uint64_t g_chaos_io_tls_prng_state = 0U;                                              \
    uint64_t g_chaos_io_process_seed = 1U

/**
 * @brief Backup record for a file that may need to be restored after a test.
 *
 * Populated by `chaos_test_backup_file()` and consumed by
 * `chaos_test_restore_file()`. The `data` field is heap-allocated and must be
 * freed with `chaos_test_free_backup()` after the restore is complete.
 *
 * @var chaos_test_file_backup_t::existed
 *      Non-zero if the file was present at backup time. Zero means the file did
 *      not exist; `chaos_test_restore_file()` will delete it if it was created
 *      during the test.
 * @var chaos_test_file_backup_t::data
 *      Heap-allocated copy of the file contents, or NULL if `existed == 0`.
 * @var chaos_test_file_backup_t::size
 *      Byte length of `data`; zero when `existed == 0`.
 */
typedef struct chaos_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_test_file_backup_t;

/**
 * @brief Open a file path, handling the optional `mode` argument for O_CREAT.
 *
 * Thin wrapper around `open(2)` that forwards the variadic `mode` argument only
 * when the `O_CREAT` flag is set, matching the POSIX signature convention.
 * Used by `chaos_test_use_real_io()` to populate `g_chaos_io_real_open`.
 *
 * @param path   File path to open.
 * @param flags  Open flags (O_RDONLY, O_WRONLY, etc.).
 * @param ...    Optional `mode_t` mode argument, required when O_CREAT is set.
 * @return File descriptor on success, -1 on failure with `errno` set.
 */
static inline int chaos_test_real_open(const char *path, int flags, ...)
{
    int result;

    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        mode_t mode;

        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        result = open(path, flags, mode);
    }
    else
    {
        result = open(path, flags);
    }

    return result;
}

/**
 * @brief Read from a file descriptor using the real libc `read`.
 * @param fd      Open file descriptor.
 * @param buffer  Destination buffer.
 * @param count   Maximum bytes to read.
 * @return Bytes read, 0 on EOF, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_read(int fd, void *buffer, size_t count)
{
    return read(fd, buffer, count);
}

/**
 * @brief Write to a file descriptor using the real libc `write`.
 * @param fd      Open file descriptor.
 * @param buffer  Source data.
 * @param count   Bytes to write.
 * @return Bytes written, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_write(int fd, const void *buffer, size_t count)
{
    return write(fd, buffer, count);
}

/**
 * @brief Scatter-read from a file descriptor using the real libc `readv`.
 * @param fd     Open file descriptor.
 * @param iov    Scatter/gather vector.
 * @param iovcnt Number of elements in @p iov.
 * @return Total bytes read, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    return readv(fd, iov, iovcnt);
}

/**
 * @brief Gather-write to a file descriptor using the real libc `writev`.
 * @param fd     Open file descriptor.
 * @param iov    Gather vector.
 * @param iovcnt Number of elements in @p iov.
 * @return Total bytes written, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    return writev(fd, iov, iovcnt);
}

/**
 * @brief Close a file descriptor using the real libc `close`.
 * @param fd  File descriptor to close.
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int chaos_test_real_close(int fd)
{
    return close(fd);
}

/**
 * @brief Positioned read using the real libc `pread`.
 * @param fd      Open file descriptor.
 * @param buffer  Destination buffer.
 * @param count   Maximum bytes to read.
 * @param offset  File offset at which to start reading (file position unchanged).
 * @return Bytes read, 0 on EOF, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_pread(int fd, void *buffer, size_t count, off_t offset)
{
    return pread(fd, buffer, count, offset);
}

/**
 * @brief Positioned write using the real libc `pwrite`.
 * @param fd      Open file descriptor.
 * @param buffer  Source data.
 * @param count   Bytes to write.
 * @param offset  File offset at which to start writing (file position unchanged).
 * @return Bytes written, or -1 on error with `errno` set.
 */
static inline ssize_t chaos_test_real_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    return pwrite(fd, buffer, count, offset);
}

/**
 * @brief Positioned scatter-read using the real libc `preadv`.
 * @param fd     Open file descriptor.
 * @param iov    Scatter vector.
 * @param iovcnt Number of elements in @p iov.
 * @param offset File offset (file position unchanged).
 * @return Total bytes read, or -1 on error with `errno` set.
 */
static inline ssize_t
chaos_test_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return preadv(fd, iov, iovcnt, offset);
}

/**
 * @brief Positioned gather-write using the real libc `pwritev`.
 * @param fd     Open file descriptor.
 * @param iov    Gather vector.
 * @param iovcnt Number of elements in @p iov.
 * @param offset File offset (file position unchanged).
 * @return Total bytes written, or -1 on error with `errno` set.
 */
static inline ssize_t
chaos_test_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return pwritev(fd, iov, iovcnt, offset);
}

/**
 * @brief Flush file data to storage using the real libc `fsync`.
 * @param fd  Open file descriptor.
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int chaos_test_real_fsync(int fd)
{
    return fsync(fd);
}

/**
 * @brief Flush file data (but not metadata) using the real libc `fdatasync`.
 * @param fd  Open file descriptor.
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int chaos_test_real_fdatasync(int fd)
{
    return fdatasync(fd);
}

/**
 * @brief Truncate a file to a specified length using the real libc `ftruncate`.
 * @param fd     Open file descriptor.
 * @param length Target length in bytes.
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int chaos_test_real_ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

/**
 * @brief Remove a directory entry using the real libc `unlinkat`.
 * @param dirfd  Directory file descriptor or AT_FDCWD.
 * @param path   Path to the entry to remove.
 * @param flags  AT_REMOVEDIR to remove directories; 0 for files.
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int chaos_test_real_unlinkat(int dirfd, const char *path, int flags)
{
    return unlinkat(dirfd, path, flags);
}

/**
 * @brief Rename a directory entry using the real libc `renameat`.
 * @param olddirfd  Source directory fd or AT_FDCWD.
 * @param oldpath   Current entry name (relative to @p olddirfd).
 * @param newdirfd  Destination directory fd or AT_FDCWD.
 * @param newpath   New entry name (relative to @p newdirfd).
 * @return 0 on success, -1 on error with `errno` set.
 */
static inline int
chaos_test_real_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

/**
 * @brief Wire all real-function-pointer globals to actual libc functions.
 *
 * Call this from a test function that needs the production wrapper code to
 * exercise a real file system path (e.g. end-to-end read/write tests). After
 * calling this function, the chaos wrappers forward through the real functions
 * instead of through test stubs.
 *
 * The function also sets the Linux-only copy-operation globals via
 * `CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()` on Linux builds.
 */
static inline void chaos_test_use_real_io(void)
{
    g_chaos_io_real_read = chaos_test_real_read;
    g_chaos_io_real_write = chaos_test_real_write;
    g_chaos_io_real_readv = chaos_test_real_readv;
    g_chaos_io_real_writev = chaos_test_real_writev;
    g_chaos_io_real_open = chaos_test_real_open;
    g_chaos_io_real_openat = openat;
    g_chaos_io_real_close = chaos_test_real_close;
    g_chaos_io_real_fsync = chaos_test_real_fsync;
    g_chaos_io_real_fdatasync = chaos_test_real_fdatasync;
    g_chaos_io_real_pread = chaos_test_real_pread;
    g_chaos_io_real_pwrite = chaos_test_real_pwrite;
    g_chaos_io_real_preadv = chaos_test_real_preadv;
    g_chaos_io_real_pwritev = chaos_test_real_pwritev;
    g_chaos_io_real_ftruncate = chaos_test_real_ftruncate;
    g_chaos_io_real_unlinkat = chaos_test_real_unlinkat;
    g_chaos_io_real_renameat = chaos_test_real_renameat;
    CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()
}

/**
 * @brief Reset all IO-domain runtime globals to their initial (NULL/zero) state.
 *
 * Call this at the start of every test function that uses the IO domain globals.
 * Resetting prevents state leakage between test functions that share the same
 * translation unit. After this call all `g_chaos_io_real_*` pointers are NULL and
 * both TLS fields are zero; `g_chaos_io_process_seed` is reset to 1.
 */
static inline void chaos_test_reset_runtime(void)
{
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
    CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()
    g_chaos_io_tls_guard = 0;
    g_chaos_io_tls_prng_state = 0U;
    g_chaos_io_process_seed = 1U;
}

/**
 * @brief Write all bytes of @p data to @p fd, retrying on partial writes.
 *
 * Helper used internally by `chaos_test_write_text_file()` and
 * `chaos_test_restore_file()`. Asserts that every `write(2)` call returns a
 * positive byte count; any short write that is not a partial write causes an
 * assertion failure rather than silent data truncation.
 *
 * @param fd    Open writable file descriptor.
 * @param data  Buffer to write.
 * @param size  Total bytes to write.
 */
static inline void chaos_test_write_all(int fd, const char *data, size_t size)
{
    size_t written = 0U;

    while (written < size)
    {
        ssize_t rc = write(fd, data + written, size - written);
        assert(rc > 0);
        written += (size_t)rc;
    }
}

/**
 * @brief Create or overwrite a file with the given text content.
 *
 * Opens @p path for creation/truncation, writes the full contents of @p text,
 * and closes the file. Used by config tests to set up a known-good config file
 * state before calling config-parse functions.
 *
 * @param path  Filesystem path of the file to write.
 * @param text  Null-terminated string to write as file content.
 */
static inline void chaos_test_write_text_file(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

    assert(fd >= 0);
    chaos_test_write_all(fd, text, strlen(text));
    assert(close(fd) == 0);
}

/**
 * @brief Delete a file if it exists; do nothing if it does not.
 *
 * Used by config tests in their cleanup phase to ensure the test did not leave
 * a stale config file behind. The only tolerated `unlink` failure is ENOENT.
 *
 * @param path  File to remove.
 */
static inline void chaos_test_remove_file_if_exists(const char *path)
{
    if (unlink(path) != 0)
    {
        assert(errno == ENOENT);
    }
}

/**
 * @brief Read and preserve the current contents of a file for later restoration.
 *
 * Populates @p backup with the file's current content. If the file does not
 * exist, sets `backup->existed = 0` and leaves `data == NULL`. Asserts on any
 * unexpected read error (anything other than ENOENT on open).
 *
 * Callers are responsible for calling `chaos_test_free_backup()` after the
 * corresponding `chaos_test_restore_file()` call.
 *
 * @param path    Path to the file to back up.
 * @param backup  Output struct to populate. Must point to valid (possibly
 *                uninitialised) storage; all fields are overwritten.
 */
static inline void chaos_test_backup_file(const char *path, chaos_test_file_backup_t *backup)
{
    int fd;

    assert(path != NULL);
    assert(backup != NULL);

    backup->existed = 0;
    backup->data = NULL;
    backup->size = 0U;

    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        assert(errno == ENOENT);
        return;
    }

    backup->existed = 1;
    for (;;)
    {
        char buffer[256];
        ssize_t rc = read(fd, buffer, sizeof(buffer));
        char *next;

        assert(rc >= 0);
        if (rc == 0)
        {
            break;
        }

        next = (char *)realloc(backup->data, backup->size + (size_t)rc);
        assert(next != NULL);
        backup->data = next;
        (void)memcpy(backup->data + backup->size, buffer, (size_t)rc);
        backup->size += (size_t)rc;
    }

    assert(close(fd) == 0);
}

/**
 * @brief Restore a file to the state captured by `chaos_test_backup_file()`.
 *
 * If `backup->existed == 0`, the file at @p path is removed (if present). If
 * `backup->existed != 0`, the file is created/overwritten with the backed-up
 * content. This is typically called from an `atexit` handler or at the end of a
 * test block to ensure the config file is left unchanged after the test runs.
 *
 * @param path    Filesystem path to restore.
 * @param backup  Backup record previously populated by `chaos_test_backup_file()`.
 */
static inline void chaos_test_restore_file(const char *path, const chaos_test_file_backup_t *backup)
{
    assert(path != NULL);
    assert(backup != NULL);

    if (!backup->existed)
    {
        chaos_test_remove_file_if_exists(path);
        return;
    }

    chaos_test_write_text_file(path, "");
    {
        int fd = open(path, O_TRUNC | O_WRONLY, 0600);
        assert(fd >= 0);
        if (backup->size != 0U)
        {
            chaos_test_write_all(fd, backup->data, backup->size);
        }
        assert(close(fd) == 0);
    }
}

/**
 * @brief Release heap memory owned by a backup record.
 *
 * Frees `backup->data` and zeroes all fields. Safe to call on a backup record
 * that was never populated (all fields are already zero/NULL). A NULL @p backup
 * pointer is silently ignored.
 *
 * @param backup  Backup record to release.
 */
static inline void chaos_test_free_backup(chaos_test_file_backup_t *backup)
{
    if (backup == NULL)
    {
        return;
    }

    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

#endif
