/**
 * @file test_support.h
 * @brief Unit-test scaffolding for libchaos-io: runtime globals, pass-through real functions,
 *        reset helper and rule-file backup/restore.
 *
 * @details Unit tests compile libchaos-io sources directly into the test binary instead of
 * loading the shared object, so the globals libchaos-io defines in its own translation units
 * must be supplied by the test. This header provides:
 *
 *   1. CHAOS_IO_DEFINE_TEST_GLOBALS(): defines the real-function pointers, the reentrancy
 *      guard, the PRNG state and the process seed. Expand exactly once per test binary.
 *   2. chaos_test_real_*(): thin pass-throughs to the C library, and
 *      chaos_test_use_real_io(), which installs them as real functions so config code can
 *      read a real rule file.
 *   3. chaos_test_reset_runtime(): returns the globals to their initial state.
 *   4. File helpers (write, remove, backup, restore, free) for tests that must replace the
 *      live rule file and leave it as they found it.
 *
 * The pass-throughs call read(), open() and friends by name. They reach the C library only in
 * binaries that do not also compile the libchaos-io wrappers (which define those names);
 * test_chaos_io_harness.h covers that case with its own stubs.
 *
 * Not covered by tests built on this header: dlsym(RTLD_NEXT) interposition (the runtime
 * suites cover it), reload races under real multi-thread load, and async-signal-safety of the
 * wrappers.
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
 * @defgroup chaos_io_test_linux_copy_globals Linux-only copy-operation test globals
 * @{
 *
 * fallocate, sendfile and copy_file_range exist only on Linux, where libchaos-io declares
 * real functions for them; elsewhere all three macros expand to nothing.
 *
 * - CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS() defines the three pointers as NULL; expanded
 *   inside CHAOS_IO_DEFINE_TEST_GLOBALS().
 * - CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY() points them at the C library; expanded inside
 *   chaos_test_use_real_io().
 * - CHAOS_IO_TEST_RESET_REAL_LINUX_COPY() sets them back to NULL; expanded inside
 *   chaos_test_reset_runtime().
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
 * @brief Defines the libchaos-io runtime globals for one test binary.
 *
 * Expand exactly once at file scope; a second expansion in the same link unit is a
 * multiple-definition error. Defines:
 * - Every `g_chaos_io_real_*` pointer for the descriptor, path and stdio operations, NULL, so
 *   a test that forgets to bind a real function crashes on the first call instead of
 *   reaching an arbitrary address.
 * - The Linux-only copy pointers via CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS().
 * - `__thread int g_chaos_io_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_io_tls_prng_state` = 0, which makes the per-thread PRNG seed
 *   itself on first use.
 * - `uint64_t g_chaos_io_process_seed` = 1, non-zero so probability draws work without the
 *   constructor.
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
    chaos_io_truncate_fn g_chaos_io_real_truncate = NULL;                                          \
    chaos_io_fopen_fn g_chaos_io_real_fopen = NULL;                                                \
    chaos_io_fclose_fn g_chaos_io_real_fclose = NULL;                                              \
    chaos_io_fread_fn g_chaos_io_real_fread = NULL;                                                \
    chaos_io_fwrite_fn g_chaos_io_real_fwrite = NULL;                                              \
    chaos_io_fgets_fn g_chaos_io_real_fgets = NULL;                                                \
    chaos_io_fputs_fn g_chaos_io_real_fputs = NULL;                                                \
    chaos_io_fgetc_fn g_chaos_io_real_fgetc = NULL;                                                \
    chaos_io_fgetc_fn g_chaos_io_real_getc = NULL;                                                 \
    chaos_io_fputc_fn g_chaos_io_real_fputc = NULL;                                                \
    chaos_io_fputc_fn g_chaos_io_real_putc = NULL;                                                 \
    chaos_io_getdelim_fn g_chaos_io_real_getdelim = NULL;                                          \
    chaos_io_vfprintf_fn g_chaos_io_real_vfprintf = NULL;                                          \
    chaos_io_fflush_fn g_chaos_io_real_fflush = NULL;                                              \
    chaos_io_vfprintf_chk_fn g_chaos_io_real_vfprintf_chk = NULL;                                  \
    chaos_io_fread_chk_fn g_chaos_io_real_fread_chk = NULL;                                        \
    chaos_io_fgets_chk_fn g_chaos_io_real_fgets_chk = NULL;                                        \
    chaos_io_freopen_fn g_chaos_io_real_freopen = NULL;                                            \
    chaos_io_renameat2_fn g_chaos_io_real_renameat2 = NULL;                                        \
    chaos_io_posix_fallocate_fn g_chaos_io_real_posix_fallocate = NULL;                            \
    chaos_io_renameat_fn g_chaos_io_real_renameat = NULL;                                          \
    CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()                                                      \
    __thread int g_chaos_io_tls_guard = 0;                                                         \
    __thread uint64_t g_chaos_io_tls_prng_state = 0U;                                              \
    uint64_t g_chaos_io_process_seed = 1U

/**
 * @brief Snapshot of a file taken by chaos_test_backup_file() for chaos_test_restore_file().
 *
 * Owns `data` (heap); release it with chaos_test_free_backup() after restoring.
 *
 * @var chaos_test_file_backup_t::existed
 *      1 if the file existed at backup time; 0 makes chaos_test_restore_file() delete
 *      whatever the test created at that path.
 * @var chaos_test_file_backup_t::data
 *      Copy of the file contents; NULL when the file did not exist or was empty.
 * @var chaos_test_file_backup_t::size
 *      Length of `data` in bytes; 0 when the file did not exist or was empty.
 */
typedef struct chaos_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_test_file_backup_t;

/**
 * @brief Pass-through to open(2) with the real-function signature libchaos-io expects.
 *
 * Reads the variadic `mode` only when O_CREAT is set, as open(2) does; reading it otherwise
 * would consume an argument the caller never passed. chaos_test_use_real_io() installs this
 * as `g_chaos_io_real_open`. O_TMPFILE is not treated as mode-bearing here.
 *
 * @param path   Path to open.
 * @param flags  open(2) flags.
 * @param ...    `mode_t` mode (promoted to int), read only with O_CREAT.
 * @return The new descriptor, or -1 with errno set by open(2).
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

/** @brief Pass-through to read(2); returns its result and errno unchanged. */
static inline ssize_t chaos_test_real_read(int fd, void *buffer, size_t count)
{
    return read(fd, buffer, count);
}

/** @brief Pass-through to write(2); returns its result and errno unchanged. */
static inline ssize_t chaos_test_real_write(int fd, const void *buffer, size_t count)
{
    return write(fd, buffer, count);
}

/** @brief Pass-through to readv(2); returns its result and errno unchanged. */
static inline ssize_t chaos_test_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    return readv(fd, iov, iovcnt);
}

/** @brief Pass-through to writev(2); returns its result and errno unchanged. */
static inline ssize_t chaos_test_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    return writev(fd, iov, iovcnt);
}

/** @brief Pass-through to close(2); returns its result and errno unchanged. */
static inline int chaos_test_real_close(int fd)
{
    return close(fd);
}

/** @brief Pass-through to pread(2); the file offset is not moved. */
static inline ssize_t chaos_test_real_pread(int fd, void *buffer, size_t count, off_t offset)
{
    return pread(fd, buffer, count, offset);
}

/** @brief Pass-through to pwrite(2); the file offset is not moved. */
static inline ssize_t chaos_test_real_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    return pwrite(fd, buffer, count, offset);
}

/** @brief Pass-through to preadv(2); the file offset is not moved. */
static inline ssize_t
chaos_test_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return preadv(fd, iov, iovcnt, offset);
}

/** @brief Pass-through to pwritev(2); the file offset is not moved. */
static inline ssize_t
chaos_test_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return pwritev(fd, iov, iovcnt, offset);
}

/** @brief Pass-through to fsync(2); returns its result and errno unchanged. */
static inline int chaos_test_real_fsync(int fd)
{
    return fsync(fd);
}

/** @brief Pass-through to fdatasync(2); returns its result and errno unchanged. */
static inline int chaos_test_real_fdatasync(int fd)
{
    return fdatasync(fd);
}

/** @brief Pass-through to ftruncate(2); returns its result and errno unchanged. */
static inline int chaos_test_real_ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

/** @brief Pass-through to truncate(2); returns its result and errno unchanged. */
static inline int chaos_test_real_truncate(const char *path, off_t length)
{
    return truncate(path, length);
}

/** @brief Pass-through to fopen(3); returns its result and errno unchanged. */
static inline FILE *chaos_test_real_fopen(const char *path, const char *mode)
{
    return fopen(path, mode);
}

/** @brief Pass-through to freopen(3); returns its result and errno unchanged. */
static inline FILE *chaos_test_real_freopen(const char *path, const char *mode, FILE *stream)
{
    return freopen(path, mode, stream);
}

/** @brief Pass-through to unlinkat(2); returns its result and errno unchanged. */
static inline int chaos_test_real_unlinkat(int dirfd, const char *path, int flags)
{
    return unlinkat(dirfd, path, flags);
}

/** @brief Pass-through to renameat(2); returns its result and errno unchanged. */
static inline int
chaos_test_real_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

/**
 * @brief Installs the C library as the real function for the descriptor and path operations.
 *
 * Binds read, write, readv, writev, open, openat, close, fsync, fdatasync, pread, pwrite,
 * preadv, pwritev, ftruncate, unlinkat, truncate, fopen, freopen, renameat and, on Linux,
 * fallocate, sendfile and copy_file_range. The stdio pointers (fread, fwrite, fgets, ...),
 * renameat2 and posix_fallocate are left as they are. Config tests call this before reading
 * a real rule file through the library's own I/O path.
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
    g_chaos_io_real_truncate = chaos_test_real_truncate;
    g_chaos_io_real_fopen = chaos_test_real_fopen;
    g_chaos_io_real_freopen = chaos_test_real_freopen;
    g_chaos_io_real_renameat = chaos_test_real_renameat;
    CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()
}

/**
 * @brief Restores the descriptor/path real functions and the PRNG globals to their initial
 *        state.
 *
 * Sets to NULL every pointer chaos_test_use_real_io() binds, plus renameat2 and
 * posix_fallocate. The stdio pointers are not touched. Zeroes the calling thread's
 * reentrancy guard and PRNG state and resets the process seed to 1. Call at the start of
 * every test that touches libchaos-io globals.
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
    g_chaos_io_real_truncate = NULL;
    g_chaos_io_real_fopen = NULL;
    g_chaos_io_real_freopen = NULL;
    g_chaos_io_real_renameat2 = NULL;
    g_chaos_io_real_posix_fallocate = NULL;
    g_chaos_io_real_renameat = NULL;
    CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()
    g_chaos_io_tls_guard = 0;
    g_chaos_io_tls_prng_state = 0U;
    g_chaos_io_process_seed = 1U;
}

/**
 * @brief Writes all @p size bytes of @p data to @p fd, looping over short writes.
 *
 * Every write(2) must return > 0 (asserted): an error, EINTR included, or a 0-byte write
 * aborts the test instead of truncating the file silently.
 *
 * @param fd    Writable descriptor.
 * @param data  Bytes to write; may be NULL only when @p size is 0.
 * @param size  Number of bytes.
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
 * @brief Creates or truncates @p path (mode 0600 when created) and writes @p text to it.
 *
 * Config tests use it to install a known rule file. open(2) and close(2) failures abort the
 * test (asserted).
 *
 * @param path  Destination path.
 * @param text  NUL-terminated contents; the NUL is not written.
 */
static inline void chaos_test_write_text_file(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

    assert(fd >= 0);
    chaos_test_write_all(fd, text, strlen(text));
    assert(close(fd) == 0);
}

/**
 * @brief Unlinks @p path; a missing file is not an error, any other unlink(2) failure aborts
 *        the test (asserted errno == ENOENT).
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
 * @brief Captures the current contents of @p path into @p backup.
 *
 * A missing file yields `existed == 0`, `data == NULL`, `size == 0`. Any other open(2) error,
 * any read(2) error and any allocation failure abort the test (asserted). Reads in 256-byte
 * chunks and grows `data` with realloc(), so arbitrarily large files are captured.
 *
 * @param path    File to capture; must not be NULL.
 * @param backup  Output; all fields are overwritten, so it may be uninitialised. The caller
 *                owns `data` and releases it with chaos_test_free_backup().
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
 * @brief Returns @p path to the state captured by chaos_test_backup_file().
 *
 * A file that did not exist is removed again. Otherwise the file is truncated (created with
 * mode 0600 if it is gone) and rewritten with the captured bytes. Failures abort the test
 * (asserted).
 *
 * @param path    File to restore; must not be NULL.
 * @param backup  Snapshot from chaos_test_backup_file(); must not be NULL. Not freed here.
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
 * @brief Frees `backup->data` and zeroes every field.
 *
 * NULL @p backup is a no-op. Calling it twice is safe; calling it on a never-initialised
 * record is not, because `data` would be an indeterminate pointer.
 *
 * @param backup  Snapshot to release, or NULL.
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
