/*
 * Thread-local fd-to-path cache implementation.
 *
 * Fd-backed wrappers would otherwise need to readlink `/proc/self/fd/<fd>` on
 * every call before they could match path-based rules. A tiny direct-mapped
 * cache is enough for the expected usage while keeping the shared object small.
 */

#include "chaos_io_fdcache.h"

#include <stdio.h>
#include <string.h>

typedef struct chaos_io_fd_cache_entry {
    int valid;
    int fd;
    char path[CHAOS_IO_MAX_PATH];
} chaos_io_fd_cache_entry_t;

static __thread chaos_io_fd_cache_entry_t g_chaos_io_fd_cache[CHAOS_IO_FD_CACHE_SLOTS];

/* Returns the direct-mapped cache slot for an fd. */
static chaos_io_fd_cache_entry_t *chaos_io_fdcache_slot(int fd)
{
    unsigned int slot = (unsigned int)fd % CHAOS_IO_FD_CACHE_SLOTS;
    return &g_chaos_io_fd_cache[slot];
}

/* Clears the current thread fd cache. */
void chaos_io_fdcache_reset(void)
{
    (void)memset(g_chaos_io_fd_cache, 0, sizeof(g_chaos_io_fd_cache));
}

/* Looks up an fd path in the current thread cache. */
int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size)
{
    chaos_io_fd_cache_entry_t *entry;
    size_t length;

    if (fd < 0 || path == NULL || path_size == 0U) {
        return 0;
    }

    entry = chaos_io_fdcache_slot(fd);
    if (entry->valid == 0 || entry->fd != fd) {
        return 0;
    }

    length = strlen(entry->path);
    if (length + 1U > path_size) {
        return 0;
    }

    (void)memcpy(path, entry->path, length + 1U);
    return 1;
}

/* Stores a resolved path in the current thread cache. */
void chaos_io_fdcache_store(int fd, const char *path)
{
    chaos_io_fd_cache_entry_t *entry;
    size_t length;

    if (fd < 0 || path == NULL || chaos_io_is_excluded_path(path)) {
        return;
    }

    length = strlen(path);
    if (length >= CHAOS_IO_MAX_PATH) {
        return;
    }

    entry = chaos_io_fdcache_slot(fd);
    entry->fd = fd;
    entry->valid = 1;
    (void)memcpy(entry->path, path, length + 1U);
}

/* Invalidates an fd entry in the current thread cache. */
void chaos_io_fdcache_invalidate(int fd)
{
    chaos_io_fd_cache_entry_t *entry;

    if (fd < 0) {
        return;
    }

    entry = chaos_io_fdcache_slot(fd);
    if (entry->valid != 0 && entry->fd == fd) {
        entry->valid = 0;
        entry->fd = -1;
        entry->path[0] = '\0';
    }
}

/* Resolves an fd path through the cache or /proc/self/fd. */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size)
{
    char proc_path[64];
    int previous;
    int written;
    ssize_t length;

    if (fd <= 2 || path == NULL || path_size < 2U) {
        return 0;
    }
    if (chaos_io_fdcache_lookup(fd, path, path_size)) {
        return 1;
    }

    written = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (written < 0) return 0;

    previous = chaos_io_enter_internal();
    length = readlink(proc_path, path, path_size - 1U);
    chaos_io_leave_internal(previous);
    if (length <= 0 || (size_t)length >= path_size) {
        return 0;
    }

    path[length] = '\0';
    if (chaos_io_is_excluded_path(path)) {
        return 0;
    }

    chaos_io_fdcache_store(fd, path);
    return 1;
}
