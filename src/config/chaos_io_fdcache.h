/**
 * @file chaos_io_fdcache.h
 * @brief Process-wide descriptor-to-path cache of libchaos-io.
 *
 * @details
 * Rules match paths, but most intercepted calls carry only a descriptor. Resolving it with
 * `readlink("/proc/self/fd/<fd>")` on every call costs a system call plus a path walk; the
 * cache makes the common case a seqlock-protected copy from memory.
 *
 * @par Design
 * A direct-mapped table of CHAOS_IO_FD_CACHE_SLOTS (32) entries indexed by
 * `fd % 32`, mapped on first store (about 128 KiB), shared by all threads. An entry
 * holds the descriptor and the kernel's path for it. A lookup for a different descriptor
 * in the same slot misses; the next store evicts.
 *
 * @par Excluded paths
 * Paths chaos_io_is_excluded_path() rejects (control files, `/proc`, `/sys`, `/dev`) are
 * never stored, so those descriptors are re-resolved on every call (inside the guard) and
 * never matched.
 *
 * @par Invalidation
 * - Every call that frees or retargets a descriptor invalidates it: close() (always,
 *   after the real close, whatever it returned, because Linux releases the descriptor
 *   even when close reports an error), the target of dup2()/dup3(), the range of
 *   close_range(), and the descriptors of fclose(), closedir(), pclose() and a failed
 *   injected freopen(). Each new descriptor from open/openat/fopen/freopen is invalidated
 *   before it is resolved.
 * - unlinkat()/renameat()/renameat2() (and their path forms) and closefrom() reset the
 *   whole cache on success: a rename or unlink changes the kernel's name of every open
 *   descriptor of the file (`<path> (deleted)` after unlink, the new name after rename),
 *   and finding those entries would need a reverse index.
 * - Invalidation is one atomic increment of a per-slot generation, effective for every
 *   thread at once and never waiting.
 *
 * @par Thread safety
 * Safe from any thread and from signal handlers that interrupt a wrapper: readers use a
 * per-slot seqlock and never block; a writer that finds a slot busy skips the store.
 * errno is preserved.
 */

#ifndef CHAOS_IO_FDCACHE_H
#define CHAOS_IO_FDCACHE_H

#include "chaos_io_internal.h"

/**
 * @brief Outdates every cache entry by bumping all 32 slot generations.
 *
 * @details No memory is cleared and nothing is unmapped; entries simply stop validating.
 * Called from the constructor, after a successful unlink or rename, after closefrom(),
 * and by close_range() for a range of 32 or more descriptors. Safe from any thread.
 */
void chaos_io_fdcache_reset(void);

/**
 * @brief Copies the cached path of @p fd into @p path.
 *
 * @details Lock-free: the copy is accepted only when the slot's sequence was even and
 * unchanged across it and the slot generation still equals the entry's, so a concurrent
 * store or an invalidation since the store makes the lookup miss rather than return a
 * torn or stale path. Before the first store (no table) every lookup misses.
 *
 * @param[in]  fd         Descriptor; negative misses.
 * @param[out] path       Buffer; NULL misses. May be written even on a miss.
 * @param[in]  path_size  Capacity in bytes, NUL included; 0 misses.
 * @return Non-zero on a hit with a NUL-terminated path; 0 on a miss or when the path does
 *         not fit.
 */
int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size);

/**
 * @brief Caches @p path for @p fd under the slot's current generation.
 *
 * @details Maps the table on first use. Overwrites whatever the slot held (a colliding
 * descriptor is evicted). Skipped silently for a negative @p fd, a NULL, excluded or
 * over-long (>= CHAOS_IO_MAX_PATH) path, a failed mapping, or a slot another writer holds.
 *
 * Prefer chaos_io_fdcache_resolve(), which samples the generation before resolving and so
 * cannot cache a path a concurrent close() made stale; this function samples it at store
 * time.
 *
 * @param[in] fd    Descriptor.
 * @param[in] path  Kernel path of @p fd; NULL is a no-op.
 */
void chaos_io_fdcache_store(int fd, const char *path);

/**
 * @brief Outdates the slot of @p fd by bumping its generation.
 *
 * @details Invalidates the whole slot, so an entry of another descriptor that shares it
 * (fd + 32k) is outdated too and simply re-resolved. Works before the table exists (the
 * generations live outside it), so a close before the first store is not lost. Called
 * after every close(), whatever it returned, so a reused descriptor number never
 * inherits the old path.
 *
 * @param[in] fd  Descriptor; negative is a no-op.
 */
void chaos_io_fdcache_invalidate(int fd);

/**
 * @brief Resolves @p fd to the kernel's path for it: cache hit, else
 *        `readlink("/proc/self/fd/<fd>")` and a store.
 *
 * @details The slot generation is sampled before the readlink, so a close() racing with
 * the resolution outdates the store and the stale path is never cached. The readlink runs
 * inside the re-entrancy guard with errno preserved. Excluded paths return 0 and are not
 * cached.
 *
 * Limits: a link target of `path_size - 1` bytes or more is indistinguishable from a
 * truncated one and is accepted as read. Without `/proc` mounted every uncached lookup
 * fails and the descriptor is never matched.
 *
 * @param[in]  fd         Descriptor; <= 2 returns 0 (the standard streams are never
 *                        faulted).
 * @param[out] path       Buffer; NULL returns 0.
 * @param[in]  path_size  Capacity in bytes, NUL included; less than 2 returns 0.
 * @return Non-zero with a NUL-terminated path on success; 0 otherwise.
 */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size);

#endif
