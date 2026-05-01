/**
 * @file chaos_io_fdcache.c
 * @brief Thread-local fd-to-path cache implementation.
 *
 * @details
 * Fd-backed wrappers would otherwise need to readlink `/proc/self/fd/<fd>` on
 * every call before they could match path-based rules. A tiny direct-mapped
 * cache is enough for the expected usage while keeping the shared object small.
 *
 * **Invariants maintained by this file:**
 * - `g_chaos_io_fd_cache` is thread-local; no cross-thread locking is needed.
 * - A slot is "valid" only when both `entry->valid != 0` and
 *   `entry->fd == fd`.  Storing the fd alongside the path is the mechanism
 *   that detects natural evictions without needing a generation counter.
 * - Excluded paths (config file, `/proc`, `/sys`, `/dev`) are never stored
 *   and are never returned by `chaos_io_fdcache_resolve()`.
 * - Cache invalidation after `close` happens only on a successful real close,
 *   preserving the mapping for a descriptor that libc has not yet released.
 *
 * **Module ownership:** config/
 * **Stability:** internal
 */

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

/**
 * @brief One slot in the per-thread direct-mapped fd cache.
 *
 * @details Storing the `fd` alongside `path` provides O(1) collision
 * detection: a lookup that finds `entry->fd != fd` knows the slot belongs to
 * a different descriptor (natural eviction) without any extra bookkeeping.
 * The `valid` flag lets `chaos_io_fdcache_invalidate()` distinguish between
 * "slot holds a real entry for fd N" and "slot is empty" without requiring a
 * sentinel fd value (e.g. -1) that could theoretically alias a real fd on
 * pathological systems.
 */
typedef struct chaos_io_fd_cache_entry
{
    int valid;                      /**< Non-zero when this slot holds a live mapping. */
    int fd;                         /**< The descriptor whose path is cached here. */
    char path[CHAOS_IO_MAX_PATH];   /**< Null-terminated resolved filesystem path. */
} chaos_io_fd_cache_entry_t;

/** @brief The per-thread cache array; zero-initialized by the TLS runtime. */
static __thread chaos_io_fd_cache_entry_t g_chaos_io_fd_cache[CHAOS_IO_FD_CACHE_SLOTS];

/**
 * @brief Returns the direct-mapped cache slot for an fd.
 *
 * @details The slot index is `(unsigned int)fd % CHAOS_IO_FD_CACHE_SLOTS`.
 * The cast to `unsigned int` avoids undefined behavior for the negative fd
 * case, though callers are expected to validate `fd >= 0` before calling.
 *
 * @param[in] fd  File descriptor to map.
 * @return Pointer into the per-thread cache array.  Always non-NULL.
 */
static chaos_io_fd_cache_entry_t *chaos_io_fdcache_slot(int fd)
{
    unsigned int slot = (unsigned int)fd % CHAOS_IO_FD_CACHE_SLOTS;
    return &g_chaos_io_fd_cache[slot];
}

/**
 * @brief Clears the current thread fd cache.
 */
void chaos_io_fdcache_reset(void)
{
    (void)memset(g_chaos_io_fd_cache, 0, sizeof(g_chaos_io_fd_cache));
}

/**
 * @brief Looks up an fd path in the current thread cache.
 *
 * @details Returns 0 without touching `path` if the path string would not fit
 * in `path_size` bytes.  This prevents a partial copy that could produce a
 * non-null-terminated buffer at the call site.
 */
int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size)
{
    chaos_io_fd_cache_entry_t *entry;
    size_t length;

    if (fd < 0 || path == NULL || path_size == 0U)
    {
        return 0;
    }

    entry = chaos_io_fdcache_slot(fd);
    if (entry->valid == 0 || entry->fd != fd)
    {
        return 0;
    }

    length = strlen(entry->path);
    if (length + 1U > path_size)
    {
        return 0;
    }

    (void)memcpy(path, entry->path, length + 1U);
    return 1;
}

/**
 * @brief Stores a resolved path in the current thread cache.
 *
 * @details Excluded paths and oversized paths are silently dropped so the
 * cache only holds entries that can ever produce a rule match.  The slot
 * is overwritten unconditionally; the evicted entry (if any) is simply lost.
 */
void chaos_io_fdcache_store(int fd, const char *path)
{
    chaos_io_fd_cache_entry_t *entry;
    size_t length;

    if (fd < 0 || path == NULL || chaos_io_is_excluded_path(path))
    {
        return;
    }

    length = strlen(path);
    if (length >= CHAOS_IO_MAX_PATH)
    {
        return;
    }

    entry = chaos_io_fdcache_slot(fd);
    entry->fd = fd;
    entry->valid = 1;
    (void)memcpy(entry->path, path, length + 1U);
}

/**
 * @brief Invalidates an fd entry in the current thread cache.
 *
 * @details The explicit `entry->fd = -1` write ensures the slot cannot
 * accidentally match a subsequent lookup for a new fd that happens to map to
 * the same slot before `valid` is checked.  It is a belt-and-suspenders
 * measure since `entry->valid = 0` is already sufficient for correctness,
 * but the explicit -1 makes the cleared state immediately obvious in a
 * debugger.
 */
void chaos_io_fdcache_invalidate(int fd)
{
    chaos_io_fd_cache_entry_t *entry;

    if (fd < 0)
    {
        return;
    }

    entry = chaos_io_fdcache_slot(fd);
    if (entry->valid != 0 && entry->fd == fd)
    {
        entry->valid = 0;
        entry->fd = -1;
        entry->path[0] = '\0';
    }
}

/**
 * @brief Resolves an fd path through the cache or /proc/self/fd.
 *
 * @details The internal guard is set around the `readlink` call to prevent
 * that call from being intercepted by this library's own wrappers.
 * `readlink` is not itself interposed, but it can internally invoke `open`
 * or `read` depending on the kernel version or libc implementation; the
 * guard closes that window.
 *
 * `path_size - 1` is passed to `readlink` to reserve one byte for the NUL
 * terminator that `readlink` does not write.  After a successful `readlink`,
 * `path[length] = '\0'` makes the buffer a valid C string.
 *
 * The exclusion check on the resolved path prevents storing entries like
 * `socket:[12345]` or `anon_inode:[eventfd]` (virtual paths that appear in
 * `/proc/self/fd` for non-regular-file descriptors) into the cache, since
 * those paths cannot match any filesystem rule prefix.
 */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size)
{
    char proc_path[64];
    int previous;
    int written;
    ssize_t length;

    if (fd <= 2 || path == NULL || path_size < 2U)
    {
        return 0;
    }
    if (chaos_io_fdcache_lookup(fd, path, path_size))
    {
        return 1;
    }

    written = snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    if (written < 0)
        return 0;

    /* Enter internal mode: readlink must not be re-intercepted. */
    previous = chaos_io_enter_internal();
    length = readlink(proc_path, path, path_size - 1U);
    chaos_io_leave_internal(previous);
    if (length <= 0 || (size_t)length >= path_size)
    {
        return 0;
    }

    path[length] = '\0';
    if (chaos_io_is_excluded_path(path))
    {
        return 0;
    }

    chaos_io_fdcache_store(fd, path);
    return 1;
}
