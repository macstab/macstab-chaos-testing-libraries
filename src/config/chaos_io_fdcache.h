/**
 * @file chaos_io_fdcache.h
 * @brief Process-wide fd-to-path cache declarations.
 *
 * @details
 * Config matching is path-based, but most interposed operations arrive as
 * file descriptors.  Resolving a descriptor to its filesystem path on every
 * call via `readlink("/proc/self/fd/<fd>")` would be prohibitively expensive.
 * This module provides a tiny direct-mapped cache shared by all threads of the
 * process, mapped lazily on first use.
 *
 * **Cache design.**
 * The cache is a fixed-size array of `CHAOS_IO_FD_CACHE_SLOTS` entries
 * indexed by `fd % CHAOS_IO_FD_CACHE_SLOTS`.  Each entry holds the fd value
 * and its resolved path.  A lookup validates the stored fd matches the
 * requested fd; a mismatch is a natural eviction (the slot was used by a
 * different fd that mapped to the same slot modulo the table size).
 *
 * **Excluded paths.**
 * Entries for excluded paths (config file, `/proc`, `/sys`, `/dev`) are
 * never stored.  The resolve path falls back to `/proc/self/fd` on every call
 * for those paths, but the internal guard prevents reentrancy.
 *
 * **Cache invalidation discipline.**
 * - Every call that frees or reassigns a descriptor invalidates it: `close(2)`
 *   (after the real close, whatever it returned, because Linux releases the
 *   descriptor even when close reports an error), `dup2(2)` and `dup3(2)` for
 *   the target descriptor, and `close_range(2)` for the closed range.
 * - `unlinkat(2)` and `renameat(2)` call `chaos_io_fdcache_reset()` on
 *   success rather than trying to identify which entries may have become
 *   stale: a rename can change an arbitrary path alias.
 * - Invalidation bumps a per-slot generation; it is one atomic increment and
 *   takes effect for every thread at once.
 *
 * **Module ownership:** config/
 * **Stability:** internal – not part of any public ABI
 * **Thread-safety:** safe from any thread; readers use a per-slot seqlock and
 * never block, writers skip a slot another writer holds.
 */

#ifndef CHAOS_IO_FDCACHE_H
#define CHAOS_IO_FDCACHE_H

#include "chaos_io_internal.h"

/**
 * @brief Clears the current thread's fd-cache table.
 *
 * @details Zeros all entries via `memset`.  Called from the library
 * constructor and on successful `unlinkat`/`renameat` to discard any paths
 * that may have become stale.
 *
 * @note Not safe to call from a different thread targeting this thread's TLS;
 *       callers must always invoke it on the thread whose cache they want to
 *       reset.
 */
void chaos_io_fdcache_reset(void);

/**
 * @brief Looks up an fd in the current thread's cache.
 *
 * @details Computes the slot index `fd % CHAOS_IO_FD_CACHE_SLOTS`, checks
 * that the entry is valid and that the stored fd value matches, then copies
 * the path into the caller's buffer.
 *
 * @param[in]  fd         File descriptor to look up.  Negative values always
 *                        return 0.
 * @param[out] path       Buffer to receive the cached path string.
 *                        Must not be NULL.
 * @param[in]  path_size  Byte capacity of `path`, including the NUL.
 *
 * @return Non-zero on a cache hit (path copied to `*path`); zero on a miss
 *         or when the stored path would not fit in `path_size` bytes.
 *
 * @post On a hit, `path` contains a null-terminated string of length less
 *       than `path_size`.
 */
int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size);

/**
 * @brief Stores one resolved fd-to-path mapping in the current thread cache.
 *
 * @details Silently discards entries for negative fds, NULL paths, excluded
 * paths, and paths that would not fit in `CHAOS_IO_MAX_PATH` bytes.  This
 * keeps the cache free of paths that would never match a user rule.
 *
 * The store always overwrites the slot unconditionally (i.e. a collision
 * evicts the previous occupant); there is no eviction policy beyond the
 * modular slot assignment.
 *
 * @param[in] fd    File descriptor to cache.  Negative values are ignored.
 * @param[in] path  Null-terminated resolved path.  May be NULL (no-op).
 */
void chaos_io_fdcache_store(int fd, const char *path);

/**
 * @brief Invalidates any cache entry associated with an fd.
 *
 * @details Checks whether the slot for `fd % CHAOS_IO_FD_CACHE_SLOTS` holds
 * an entry for exactly `fd`, and if so marks it invalid.  Called after a
 * successful `close(2)` so that a later `open(2)` that reuses the same
 * descriptor number does not inherit an unrelated cached path.
 *
 * @param[in] fd  Descriptor to invalidate.  Negative values are ignored.
 *
 * @note This function is intentionally not called on a failed close; see the
 *       file-level documentation for the rationale.
 */
void chaos_io_fdcache_invalidate(int fd);

/**
 * @brief Resolves an fd to a stable path string via the cache or `/proc/self/fd`.
 *
 * @details Resolution sequence:
 * 1. Rejects `fd <= 2` (stdin/stdout/stderr are excluded from injection).
 * 2. Attempts `chaos_io_fdcache_lookup()`; returns immediately on a hit.
 * 3. Formats `/proc/self/fd/<fd>` and calls `readlink()` inside the internal
 *    guard.
 * 4. Checks the resolved path against `chaos_io_is_excluded_path()`; returns
 *    0 without caching if excluded.
 * 5. Stores the resolved path in the cache via `chaos_io_fdcache_store()` and
 *    returns 1.
 *
 * @param[in]  fd         File descriptor to resolve.
 * @param[out] path       Buffer to receive the resolved path.  Must not be NULL.
 * @param[in]  path_size  Byte capacity of `path`, including the NUL.  Must be
 *                        at least 2.
 *
 * @return Non-zero when resolution succeeded and `*path` contains a valid
 *         null-terminated string; zero otherwise.
 *
 * @note The `readlink` call uses `path_size - 1` as the buffer length to
 *       leave room for the NUL terminator that `readlink` does not append.
 */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size);

#endif
