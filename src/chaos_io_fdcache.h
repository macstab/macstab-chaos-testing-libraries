#ifndef CHAOS_IO_FDCACHE_H
#define CHAOS_IO_FDCACHE_H

/*
 * Thread-local fd-to-path cache declarations.
 *
 * Most interposed operations arrive as file descriptors, but config matching is
 * path-based. This module bridges that mismatch with a very small per-thread
 * cache so hot paths do not repeatedly readlink `/proc/self/fd/<fd>`.
 */

#include "chaos_io_internal.h"

/*
 * Clears the current thread's fd-cache table.
 *
 * Startup and tests use this to guarantee a known empty cache state.
 */
void chaos_io_fdcache_reset(void);

/*
 * Looks up an fd in the current thread's cache.
 *
 * A successful hit copies the cached path into the caller buffer and avoids any
 * filesystem round-trip.
 */
int chaos_io_fdcache_lookup(int fd, char *path, size_t path_size);

/*
 * Stores one resolved fd-to-path mapping in the current thread cache.
 *
 * Invalid, excluded, or oversized paths are ignored so the cache only contains
 * matchable user-space file targets.
 */
void chaos_io_fdcache_store(int fd, const char *path);

/*
 * Invalidates any cache entry associated with an fd.
 *
 * This is called after a successful close so later fd reuse does not inherit an
 * unrelated cached path.
 */
void chaos_io_fdcache_invalidate(int fd);

/*
 * Resolves an fd to a stable path string.
 *
 * The helper first checks the thread-local cache and falls back to
 * `/proc/self/fd/<fd>` only on a miss. Successful resolutions are cached for
 * later calls.
 */
int chaos_io_fdcache_resolve(int fd, char *path, size_t path_size);

#endif
