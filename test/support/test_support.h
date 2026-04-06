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

#ifdef __linux__
#define CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS() \
    chaos_io_fallocate_fn g_chaos_io_real_fallocate = NULL; \
    chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL; \
    chaos_io_copy_file_range_fn g_chaos_io_real_copy_file_range = NULL;
#define CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY() \
    g_chaos_io_real_fallocate = fallocate; \
    g_chaos_io_real_sendfile = sendfile; \
    g_chaos_io_real_copy_file_range = copy_file_range;
#define CHAOS_IO_TEST_RESET_REAL_LINUX_COPY() \
    g_chaos_io_real_fallocate = NULL; \
    g_chaos_io_real_sendfile = NULL; \
    g_chaos_io_real_copy_file_range = NULL;
#else
#define CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS()
#define CHAOS_IO_TEST_ASSIGN_REAL_LINUX_COPY()
#define CHAOS_IO_TEST_RESET_REAL_LINUX_COPY()
#endif

#define CHAOS_IO_DEFINE_TEST_GLOBALS() \
    chaos_io_read_fn g_chaos_io_real_read = NULL; \
    chaos_io_write_fn g_chaos_io_real_write = NULL; \
    chaos_io_readv_fn g_chaos_io_real_readv = NULL; \
    chaos_io_writev_fn g_chaos_io_real_writev = NULL; \
    chaos_io_open_fn g_chaos_io_real_open = NULL; \
    chaos_io_openat_fn g_chaos_io_real_openat = NULL; \
    chaos_io_close_fn g_chaos_io_real_close = NULL; \
    chaos_io_sync_fn g_chaos_io_real_fsync = NULL; \
    chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL; \
    chaos_io_pread_fn g_chaos_io_real_pread = NULL; \
    chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL; \
    chaos_io_preadv_fn g_chaos_io_real_preadv = NULL; \
    chaos_io_pwritev_fn g_chaos_io_real_pwritev = NULL; \
    chaos_io_ftruncate_fn g_chaos_io_real_ftruncate = NULL; \
    chaos_io_unlinkat_fn g_chaos_io_real_unlinkat = NULL; \
    chaos_io_renameat_fn g_chaos_io_real_renameat = NULL; \
    CHAOS_IO_DEFINE_TEST_LINUX_COPY_GLOBALS() \
    __thread int g_chaos_io_tls_guard = 0; \
    __thread uint64_t g_chaos_io_tls_prng_state = 0U; \
    uint64_t g_chaos_io_process_seed = 1U

typedef struct chaos_test_file_backup {
    int existed;
    char *data;
    size_t size;
} chaos_test_file_backup_t;

static inline int chaos_test_real_open(const char *path, int flags, ...)
{
    int result;

    if ((flags & O_CREAT) != 0) {
        va_list args;
        mode_t mode;

        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        result = open(path, flags, mode);
    } else {
        result = open(path, flags);
    }

    return result;
}

static inline ssize_t chaos_test_real_read(int fd, void *buffer, size_t count)
{
    return read(fd, buffer, count);
}

static inline ssize_t chaos_test_real_write(int fd, const void *buffer, size_t count)
{
    return write(fd, buffer, count);
}

static inline ssize_t chaos_test_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    return readv(fd, iov, iovcnt);
}

static inline ssize_t chaos_test_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    return writev(fd, iov, iovcnt);
}

static inline int chaos_test_real_close(int fd)
{
    return close(fd);
}

static inline ssize_t chaos_test_real_pread(int fd, void *buffer, size_t count, off_t offset)
{
    return pread(fd, buffer, count, offset);
}

static inline ssize_t chaos_test_real_pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    return pwrite(fd, buffer, count, offset);
}

static inline ssize_t chaos_test_real_preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return preadv(fd, iov, iovcnt, offset);
}

static inline ssize_t chaos_test_real_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    return pwritev(fd, iov, iovcnt, offset);
}

static inline int chaos_test_real_fsync(int fd)
{
    return fsync(fd);
}

static inline int chaos_test_real_fdatasync(int fd)
{
    return fdatasync(fd);
}

static inline int chaos_test_real_ftruncate(int fd, off_t length)
{
    return ftruncate(fd, length);
}

static inline int chaos_test_real_unlinkat(int dirfd, const char *path, int flags)
{
    return unlinkat(dirfd, path, flags);
}

static inline int chaos_test_real_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    return renameat(olddirfd, oldpath, newdirfd, newpath);
}

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

static inline void chaos_test_write_all(int fd, const char *data, size_t size)
{
    size_t written = 0U;

    while (written < size) {
        ssize_t rc = write(fd, data + written, size - written);
        assert(rc > 0);
        written += (size_t)rc;
    }
}

static inline void chaos_test_write_text_file(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);

    assert(fd >= 0);
    chaos_test_write_all(fd, text, strlen(text));
    assert(close(fd) == 0);
}

static inline void chaos_test_remove_file_if_exists(const char *path)
{
    if (unlink(path) != 0) {
        assert(errno == ENOENT);
    }
}

static inline void chaos_test_backup_file(const char *path, chaos_test_file_backup_t *backup)
{
    int fd;

    assert(path != NULL);
    assert(backup != NULL);

    backup->existed = 0;
    backup->data = NULL;
    backup->size = 0U;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        assert(errno == ENOENT);
        return;
    }

    backup->existed = 1;
    for (;;) {
        char buffer[256];
        ssize_t rc = read(fd, buffer, sizeof(buffer));
        char *next;

        assert(rc >= 0);
        if (rc == 0) {
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

static inline void chaos_test_restore_file(const char *path, const chaos_test_file_backup_t *backup)
{
    assert(path != NULL);
    assert(backup != NULL);

    if (!backup->existed) {
        chaos_test_remove_file_if_exists(path);
        return;
    }

    chaos_test_write_text_file(path, "");
    {
        int fd = open(path, O_TRUNC | O_WRONLY, 0600);
        assert(fd >= 0);
        if (backup->size != 0U) {
            chaos_test_write_all(fd, backup->data, backup->size);
        }
        assert(close(fd) == 0);
    }
}

static inline void chaos_test_free_backup(chaos_test_file_backup_t *backup)
{
    if (backup == NULL) {
        return;
    }

    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

#endif
