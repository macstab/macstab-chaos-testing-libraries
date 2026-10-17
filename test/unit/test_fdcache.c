/**
 * @file test_fdcache.c
 * @brief Proves the libchaos-io fd-to-path cache: argument validation, path exclusion,
 *        seqlock and generation invalidation, `/proc/self/fd` resolution, and safe
 *        degradation when the lazily mapped table cannot be created or is contended.
 *
 * @details Unit under test: `src/config/chaos_io_fdcache.c`, compiled in by `#include`.
 *
 * Isolation:
 * - `readlink` and `snprintf` are redefined around the include. The readlink stub
 *   returns a configured target (or -1 with a configured errno) and counts calls, so the
 *   suite proves when the cache is hit without touching `/proc`; the snprintf stub can
 *   force a negative result to cover the format-failure branch.
 * - The table allocator hooks `g_chaos_io_fdcache_map` / `g_chaos_io_fdcache_unmap` are
 *   swapped to simulate a failed mapping and a lost publication race.
 * - Slot sequence counters are written directly to simulate a concurrent writer; real
 *   multi-threaded races are not exercised here.
 * - `CHAOS_IO_DEFINE_TEST_GLOBALS()` provides the TLS guard and real-function pointers
 *   the module links against.
 *
 * Not covered here: wrapper call paths that store and invalidate on open/close
 * (test_chaos_io.c).
 */

#include "../support/test_support.h"

#include <sys/mman.h>
#include <sys/resource.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

/** @brief Link target the readlink stub copies from; NULL while it is set to fail. */
static const char *g_readlink_target = NULL;

/** @brief Byte count the readlink stub returns; negative makes it fail. */
static ssize_t g_readlink_result = -1;

/** @brief errno the readlink stub sets on failure (default ENOENT). */
static int g_readlink_errno = ENOENT;

/** @brief readlink stub calls since the last reset; 0 proves a cache hit. */
static size_t g_readlink_calls = 0U;

/** @brief Non-zero: the snprintf stub returns it without formatting (-1 forces failure). */
static int g_snprintf_result = 0;

/**
 * @brief readlink(2) stand-in: copies `g_readlink_result` bytes of `g_readlink_target`
 *        (no NUL, like readlink) or fails with `g_readlink_errno`.
 *
 * @details Ignores @p size on purpose: the code under test must reject a result that
 * fills its buffer, and every buffer passed here is large enough to absorb the copy.
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

/** @brief snprintf stand-in: vsnprintf, or `g_snprintf_result` when that is non-zero. */
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

/** @brief Restores the stubs to "readlink fails with ENOENT, snprintf formats". */
static void chaos_test_reset_readlink_state(void)
{
    g_readlink_target = NULL;
    g_readlink_result = -1;
    g_readlink_errno = ENOENT;
    g_readlink_calls = 0U;
    g_snprintf_result = 0;
}

/**
 * @brief store/lookup/invalidate contract.
 *
 * @details Lookup rejects fd < 0, a NULL buffer and size 0. Store ignores fd < 0, a NULL
 * path, excluded paths (`/proc/...`, the rule file) and a path of CHAOS_IO_MAX_PATH bytes
 * or more (no room for the NUL). Lookup into a buffer too small for the path misses
 * rather than truncating. Invalidating fd < 0 or another fd leaves the entry; invalidating
 * its fd makes it miss.
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
 * @brief resolve(): cache first, then `/proc/self/fd/<fd>`.
 *
 * @details fd 0-2 are never resolved; a NULL buffer or size < 2 is rejected. A cached fd
 * is answered without readlink. After invalidation: a readlink failure returns 0 and
 * releases the TLS re-entrancy guard; a snprintf failure returns 0 before readlink runs;
 * a successful readlink returns and stores the path, so the next lookup hits. A resolved
 * excluded path (`/proc/self/maps`) is neither returned nor stored. A link that fills the
 * whole buffer (4 bytes into 4) is rejected as possibly truncated.
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

/** @brief The table a simulated rival thread publishes first (lost-race path). */
static chaos_io_fd_cache_entry_t g_test_rival_table[CHAOS_IO_FD_CACHE_SLOTS];

/** @brief Calls of the counting unmap hook. */
static int g_test_unmap_calls = 0;

/** @brief Map hook that fails, as mmap(2) would under memory pressure. */
static void *chaos_test_map_fails(void)
{
    return MAP_FAILED;
}

/** @brief Map hook that maps for real, then publishes the rival table before the CAS. */
static void *chaos_test_map_loses_race(void)
{
    void *mapping = chaos_io_fdcache_default_map();

    g_chaos_io_fd_cache = g_test_rival_table;
    return mapping;
}

/** @brief Unmap hook that counts, then releases the losing mapping for real. */
static void chaos_test_count_unmap(void *mapping)
{
    ++g_test_unmap_calls;
    chaos_io_fdcache_default_unmap(mapping);
}

/**
 * @brief The lazily mapped table degrades to "no cache" instead of failing.
 *
 * @details
 * - Mapping fails: the store is dropped, the table stays NULL, lookups miss, and a later
 *   call may retry.
 * - Lost publication race: the loser's mapping is unmapped exactly once and the rival's
 *   table is used.
 * - Slot held by a writer (odd sequence): the store is skipped and the lookup misses;
 *   once the sequence is even again the original entry is returned, proving the skipped
 *   store wrote nothing.
 * - Stale resolution: a path resolved under a generation that an invalidation has since
 *   bumped is stored but never returned, so a racing close() cannot be undone.
 *
 * The real table pointer and hooks are restored at the end.
 */
static void test_lazy_table_contention_and_failure(void)
{
    chaos_io_fd_cache_entry_t *saved = g_chaos_io_fd_cache;
    char path[CHAOS_IO_MAX_PATH];
    unsigned int generation;

    g_chaos_io_fd_cache = NULL;
    g_chaos_io_fdcache_map = chaos_test_map_fails;
    chaos_io_fdcache_store(7, "/tmp/data.bin");
    assert(g_chaos_io_fd_cache == NULL);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 0);

    (void)memset(g_test_rival_table, 0, sizeof(g_test_rival_table));
    g_chaos_io_fdcache_map = chaos_test_map_loses_race;
    g_chaos_io_fdcache_unmap = chaos_test_count_unmap;
    chaos_io_fdcache_store(7, "/tmp/data.bin");
    assert(g_test_unmap_calls == 1);
    assert(g_chaos_io_fd_cache == g_test_rival_table);
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 1);

    g_test_rival_table[7].sequence |= 1U;
    chaos_io_fdcache_store(7, "/tmp/other.bin");
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 0);
    g_test_rival_table[7].sequence += 1U;
    assert(chaos_io_fdcache_lookup(7, path, sizeof(path)) == 1);
    assert(strcmp(path, "/tmp/data.bin") == 0);

    generation = chaos_io_fdcache_generation(chaos_io_fdcache_slot(8));
    chaos_io_fdcache_invalidate(8);
    chaos_io_fdcache_store_at(8, "/tmp/stale.bin", generation);
    assert(chaos_io_fdcache_lookup(8, path, sizeof(path)) == 0);

    g_chaos_io_fdcache_map = chaos_io_fdcache_default_map;
    g_chaos_io_fdcache_unmap = chaos_io_fdcache_default_unmap;
    g_chaos_io_fd_cache = saved;
}

/**
 * @brief The default map hook returns MAP_FAILED when mmap fails and preserves errno.
 *
 * @details RLIMIT_AS is lowered to 1 MiB, below what the process already uses, so any new
 * mapping fails with ENOMEM; the limit is restored before asserting. A mapping after the
 * restore succeeds.
 */
static void test_default_map_failure(void)
{
    struct rlimit saved;
    struct rlimit tight;
    void *mapping;

    assert(getrlimit(RLIMIT_AS, &saved) == 0);
    tight = saved;
    tight.rlim_cur = (rlim_t)1 << 20;
    assert(setrlimit(RLIMIT_AS, &tight) == 0);
    errno = 4242;
    mapping = chaos_io_fdcache_default_map();
    assert(setrlimit(RLIMIT_AS, &saved) == 0);
    assert(mapping == MAP_FAILED);
    assert(errno == 4242);

    mapping = chaos_io_fdcache_default_map();
    assert(mapping != MAP_FAILED);
    chaos_io_fdcache_default_unmap(mapping);
}

int main(void)
{
    test_store_lookup_and_invalidate();
    test_resolve_paths();
    test_lazy_table_contention_and_failure();
    test_default_map_failure();
    return 0;
}
