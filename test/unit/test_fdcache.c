/**
 * @file test_fdcache.c
 * @brief Unit tests for the IO-domain file-descriptor path cache.
 *
 * Subsystem under test: `src/config/chaos_io_fdcache.c`
 *
 * Coverage approach:
 * - The production source file is included directly after replacing two symbols via
 *   `#define`: `snprintf` and `readlink`. This allows precise control over path-format
 *   construction (snprintf) and the `proc` filesystem path resolution (readlink) without
 *   touching the filesystem.
 * - The `snprintf` stub delegates to `vsnprintf` when `g_snprintf_result == 0`; when set
 *   to a non-zero value it returns that value directly, simulating a format error or
 *   truncation before the readlink call.
 * - The `readlink` stub records call counts, copies at most `g_readlink_result` bytes from
 *   `g_readlink_target` into the output buffer, and returns -1 with `g_readlink_errno`
 *   when `g_readlink_result < 0`.
 * - `CHAOS_IO_DEFINE_TEST_GLOBALS()` instantiates the real-function-pointer globals; the
 *   fdcache itself does not dispatch through those pointers, but they are required to
 *   compile the production config module.
 *
 * Properties under test:
 * - Store and lookup: invalid fd (-1) is rejected; NULL path, NULL buffer, zero buffer
 *   size are rejected; the config-path sentinel (`CHAOS_IO_CONFIG_PATH`) causes the entry
 *   to be silently dropped; paths exceeding `CHAOS_IO_MAX_PATH - 1` bytes are dropped;
 *   buffer smaller than the stored path returns 0; valid store + valid lookup returns 1
 *   with the correct path.
 * - Invalidate: invalid fd (-1) and unknown fd (8) are no-ops; invalidating the stored fd
 *   causes subsequent lookup to return 0.
 * - Resolve with cache hit: if the fd is already cached, `chaos_io_fdcache_resolve` returns
 *   the cached path without calling readlink.
 * - Resolve after invalidation: invalid fd (2) → 0; NULL buffer → 0; too-small buffer → 0.
 * - Resolve with snprintf failure: `g_snprintf_result = -1` causes resolve to return 0 and
 *   readlink to not be called.
 * - Resolve with readlink failure: `g_readlink_result = -1` → 0; TLS re-entrancy guard
 *   `g_chaos_io_tls_guard` must be 0 after the call (guard must be released on error path).
 * - Resolve success: readlink returns the full path; entry is stored; subsequent lookup
 *   returns the path without calling readlink again.
 * - Resolve with proc-internal path: resolved path beginning with `/proc/` is silently
 *   discarded (not stored); subsequent lookup returns 0.
 * - Resolve with buffer too small for the resulting path (4-byte buffer for "/tmp") → 0.
 *
 * What is NOT tested here:
 * - Thread-safety of concurrent store/invalidate/resolve operations.
 * - Wrapper call paths that invoke fdcache on open/close (tested in `test_chaos_io.c`).
 */

#include "../support/test_support.h"

CHAOS_IO_DEFINE_TEST_GLOBALS();

/**
 * @brief Path string that the readlink stub copies into the output buffer.
 *
 * Must point to a string of at least `g_readlink_result` bytes. NULL when the stub is
 * configured to return an error.
 */
static const char *g_readlink_target = NULL;

/**
 * @brief Number of bytes the readlink stub copies and returns; -1 triggers an error.
 *
 * Set to `strlen(g_readlink_target)` for a successful resolution. Set to -1 to simulate
 * a readlink failure.
 */
static ssize_t g_readlink_result = -1;

/**
 * @brief errno value set by the readlink stub when returning -1.
 *
 * Defaults to ENOENT. Represents a typical "file descriptor has no proc entry" error.
 */
static int g_readlink_errno = ENOENT;

/**
 * @brief Number of times `chaos_test_readlink` has been called since the last reset.
 *
 * Used to verify that the cache hit path does not call readlink again after a path has
 * already been resolved and stored.
 */
static size_t g_readlink_calls = 0U;

/**
 * @brief When non-zero, the snprintf stub returns this value directly without formatting.
 *
 * Set to -1 to simulate a format error before any readlink call, verifying that the
 * resolve function returns 0 without ever invoking readlink.
 */
static int g_snprintf_result = 0;

/**
 * @brief Stub readlink that records calls, copies at most `g_readlink_result` bytes, and
 *   injects configurable errors.
 *
 * When `g_readlink_result < 0`: sets errno to `g_readlink_errno` and returns -1.
 * Otherwise: copies exactly `g_readlink_result` bytes from `g_readlink_target` into
 * `buffer` (asserts `g_readlink_target != NULL` and that the result does not exceed
 * `strlen(target)`), then returns `g_readlink_result`.
 *
 * @param path    Ignored (the `/proc/self/fd/<fd>` path constructed by the production code).
 * @param buffer  Destination for the resolved path bytes.
 * @param size    Maximum bytes to write; ignored (the stub writes exactly `g_readlink_result`).
 * @return Number of bytes written, or -1 on error.
 */
static ssize_t chaos_test_readlink(const char *path, char *buffer, size_t size)
{
    (void)path;
    (void)size;
    ++g_readlink_calls;

    if (g_readlink_result < 0)
    {
        errno = g_readlink_errno;
        return -1;
    }

    assert(g_readlink_target != NULL);
    assert((size_t)g_readlink_result <= strlen(g_readlink_target));
    (void)memcpy(buffer, g_readlink_target, (size_t)g_readlink_result);
    return g_readlink_result;
}

/**
 * @brief Stub snprintf that either delegates to vsnprintf or returns `g_snprintf_result`.
 *
 * When `g_snprintf_result == 0`: calls `vsnprintf(buffer, size, format, args)` and returns
 * its result (normal formatting behaviour). When non-zero: returns `g_snprintf_result`
 * directly without writing to `buffer`, allowing the test to simulate format failures.
 *
 * @param buffer  Destination buffer.
 * @param size    Buffer capacity.
 * @param format  printf-style format string.
 * @param ...     Format arguments.
 * @return Characters written (or would have been written), or `g_snprintf_result` when forced.
 */
static int chaos_test_snprintf(char *buffer, size_t size, const char *format, ...)
{
    va_list args;
    int rc;

    if (g_snprintf_result != 0)
    {
        return g_snprintf_result;
    }

    va_start(args, format);
    rc = vsnprintf(buffer, size, format, args);
    va_end(args);
    return rc;
}

#ifdef snprintf
#undef snprintf
#endif
#define snprintf chaos_test_snprintf
#define readlink chaos_test_readlink
#include "../../src/config/chaos_io_fdcache.c"
#undef readlink
#undef snprintf

/**
 * @brief Reset the readlink and snprintf stub state to defaults.
 *
 * Clears `g_readlink_target`, sets `g_readlink_result` to -1, `g_readlink_errno` to
 * ENOENT, zeroes `g_readlink_calls`, and zeroes `g_snprintf_result`.
 */
static void chaos_test_reset_readlink_state(void)
{
    g_readlink_target = NULL;
    g_readlink_result = -1;
    g_readlink_errno = ENOENT;
    g_readlink_calls = 0U;
    g_snprintf_result = 0;
}

/**
 * @brief Invariant: store, lookup, and invalidate operations respect all documented
 *   constraints and update cache state correctly.
 *
 * Triggering condition: `chaos_io_fdcache_reset()` followed by a sequence of store,
 *   lookup, and invalidate calls with valid and invalid arguments.
 *
 * Expected observable behaviour:
 * - `lookup(-1, ...)`, `lookup(7, NULL, ...)`, `lookup(7, ..., 0)` → 0.
 * - `store(-1, ...)` and `store(7, NULL)` are silent no-ops.
 * - `store(7, CHAOS_IO_CONFIG_PATH)` stores nothing (config-path entries are excluded).
 * - Storing a path of exactly `CHAOS_IO_MAX_PATH` bytes (one byte over the maximum length
 *   for a null-terminated string) → entry dropped; subsequent lookup returns 0.
 * - `store(7, "/tmp/data.bin")` followed by `lookup(7, ..., 4)` (buffer too small) → 0.
 * - `lookup(7, path, sizeof(path))` after a valid store → 1, path="/tmp/data.bin".
 * - `invalidate(-1)` and `invalidate(8)` are no-ops; fd 7 still lookups.
 * - `invalidate(7)` → subsequent lookup returns 0.
 */
static void test_store_lookup_and_invalidate(void)
{
    char path[CHAOS_IO_MAX_PATH];
    char *too_long_path;

    chaos_io_fdcache_reset();
    assert(chaos_io_fdcache_lookup(-1, path, sizeof(path)) == 0);
    assert(chaos_io_fdcache_lookup(7, NULL, sizeof(path)) == 0);
    assert(chaos_io_fdcache_lookup(7, path, 0U) == 0);

    chaos_io_fdcache_store(-1, "/tmp/data.bin");
    chaos_io_fdcache_store(7, NULL);
    chaos_io_fdcache_store(7, "/proc/1/maps");
    chaos_io_fdcache_store(7, CHAOS_IO_CONFIG_PATH);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 0);

    too_long_path = (char *)malloc(CHAOS_IO_MAX_PATH + 1U);
    assert(too_long_path != NULL);
    (void)memset(too_long_path, 'x', CHAOS_IO_MAX_PATH);
    too_long_path[0] = '/';
    too_long_path[CHAOS_IO_MAX_PATH] = '\0';
    chaos_io_fdcache_store(7, too_long_path);
    free(too_long_path);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 0);

    chaos_io_fdcache_store(7, "/tmp/data.bin");
    assert(chaos_io_fdcache_lookup(7, path, 4U) == 0);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/data.bin") == 0);

    chaos_io_fdcache_invalidate(-1);
    chaos_io_fdcache_invalidate(8);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 1);
    chaos_io_fdcache_invalidate(7);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 0);
}

/**
 * @brief Invariant: `chaos_io_fdcache_resolve` returns cached paths without calling
 *   readlink, correctly resolves paths via readlink, discards proc-internal paths,
 *   and handles all failure modes cleanly.
 *
 * Triggering condition: `chaos_io_fdcache_resolve` called with various fd/buffer/size
 *   combinations; cache is manipulated between calls via store and invalidate.
 *
 * Expected observable behaviour:
 * - `resolve(2, ...)` (reserved/stdin-class fd) → 0 immediately.
 * - `resolve(3, NULL, ...)` and `resolve(3, ..., 1)` → 0 (argument validation).
 * - Cached fd 9: `resolve(9, ...)` returns 1 with "/tmp/cached.bin" and `g_readlink_calls == 0`.
 * - After invalidating fd 9, readlink failure (`g_readlink_result = -1`) → 0;
 *   `g_chaos_io_tls_guard == 0` (guard released on error path).
 * - snprintf failure (`g_snprintf_result = -1`) → 0 and readlink not called.
 * - Successful readlink for "/tmp/short.bin": `resolve` → 1; path filled; entry stored
 *   (second lookup returns 1 without calling readlink again).
 * - Resolved path starting with "/proc/self/maps": entry is not stored; subsequent lookup
 *   returns 0.
 * - Buffer size 4 for a 4-character path "/tmp" (plus null terminator > 4) → 0.
 */
static void test_resolve_paths(void)
{
    char path[CHAOS_IO_MAX_PATH];

    chaos_io_fdcache_reset();
    chaos_test_reset_readlink_state();

    assert(chaos_io_fdcache_resolve(2, path, sizeof(path)) == 0);
    assert(chaos_io_fdcache_resolve(3, NULL, sizeof(path)) == 0);
    assert(chaos_io_fdcache_resolve(3, path, 1U) == 0);

    chaos_io_fdcache_store(9, "/tmp/cached.bin");
    assert(chaos_io_fdcache_resolve(9, path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/cached.bin") == 0);
    assert(g_readlink_calls == 0U);

    chaos_io_fdcache_invalidate(9);

    g_readlink_result = -1;
    assert(chaos_io_fdcache_resolve(9, path, sizeof(path)) == 0);
    assert(g_chaos_io_tls_guard == 0);

    chaos_test_reset_readlink_state();
    g_snprintf_result = -1;
    assert(chaos_io_fdcache_resolve(9, path, sizeof(path)) == 0);
    assert(g_readlink_calls == 0U);

    chaos_test_reset_readlink_state();
    g_readlink_target = "/tmp/short.bin";
    g_readlink_result = (ssize_t)strlen(g_readlink_target);
    assert(chaos_io_fdcache_resolve(9, path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/short.bin") == 0);
    assert(g_readlink_calls == 1U);
    assert(chaos_io_fdcache_lookup(9, path, sizeof(path)) == 1);

    chaos_io_fdcache_invalidate(9);
    chaos_test_reset_readlink_state();
    g_readlink_target = "/proc/self/maps";
    g_readlink_result = (ssize_t)strlen(g_readlink_target);
    assert(chaos_io_fdcache_resolve(9, path, sizeof(path)) == 0);
    assert(chaos_io_fdcache_lookup(9, path, sizeof(path)) == 0);

    chaos_test_reset_readlink_state();
    g_readlink_target = "/tmp";
    g_readlink_result = 4;
    assert(chaos_io_fdcache_resolve(10, path, 4U) == 0);
}

int main(void)
{
    test_store_lookup_and_invalidate();
    test_resolve_paths();
    return 0;
}
