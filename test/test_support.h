#ifndef CHAOS_IO_TEST_SUPPORT_H
#define CHAOS_IO_TEST_SUPPORT_H

#include "../src/chaos_io_internal.h"

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#define CHAOS_IO_DEFINE_TEST_SENDFILE_GLOBAL() chaos_io_sendfile_fn g_chaos_io_real_sendfile = NULL;
#define CHAOS_IO_TEST_ASSIGN_REAL_SENDFILE() g_chaos_io_real_sendfile = sendfile;
#define CHAOS_IO_TEST_RESET_REAL_SENDFILE() g_chaos_io_real_sendfile = NULL;
#else
#define CHAOS_IO_DEFINE_TEST_SENDFILE_GLOBAL()
#define CHAOS_IO_TEST_ASSIGN_REAL_SENDFILE()
#define CHAOS_IO_TEST_RESET_REAL_SENDFILE()
#endif

#define CHAOS_IO_DEFINE_TEST_GLOBALS() \
    chaos_io_read_fn g_chaos_io_real_read = NULL; \
    chaos_io_write_fn g_chaos_io_real_write = NULL; \
    chaos_io_open_fn g_chaos_io_real_open = NULL; \
    chaos_io_openat_fn g_chaos_io_real_openat = NULL; \
    chaos_io_close_fn g_chaos_io_real_close = NULL; \
    chaos_io_sync_fn g_chaos_io_real_fsync = NULL; \
    chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL; \
    chaos_io_pread_fn g_chaos_io_real_pread = NULL; \
    chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL; \
    CHAOS_IO_DEFINE_TEST_SENDFILE_GLOBAL() \
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

static inline int chaos_test_real_fsync(int fd)
{
    return fsync(fd);
}

static inline int chaos_test_real_fdatasync(int fd)
{
    return fdatasync(fd);
}

static inline void chaos_test_use_real_io(void)
{
    g_chaos_io_real_read = chaos_test_real_read;
    g_chaos_io_real_write = chaos_test_real_write;
    g_chaos_io_real_open = chaos_test_real_open;
    g_chaos_io_real_openat = openat;
    g_chaos_io_real_close = chaos_test_real_close;
    g_chaos_io_real_fsync = chaos_test_real_fsync;
    g_chaos_io_real_fdatasync = chaos_test_real_fdatasync;
    g_chaos_io_real_pread = chaos_test_real_pread;
    g_chaos_io_real_pwrite = chaos_test_real_pwrite;
    CHAOS_IO_TEST_ASSIGN_REAL_SENDFILE()
}

static inline void chaos_test_reset_runtime(void)
{
    g_chaos_io_real_read = NULL;
    g_chaos_io_real_write = NULL;
    g_chaos_io_real_open = NULL;
    g_chaos_io_real_openat = NULL;
    g_chaos_io_real_close = NULL;
    g_chaos_io_real_fsync = NULL;
    g_chaos_io_real_fdatasync = NULL;
    g_chaos_io_real_pread = NULL;
    g_chaos_io_real_pwrite = NULL;
    CHAOS_IO_TEST_RESET_REAL_SENDFILE()
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
