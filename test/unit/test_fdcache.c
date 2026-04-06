#include "../support/test_support.h"

CHAOS_IO_DEFINE_TEST_GLOBALS();

static const char *g_readlink_target = NULL;
static ssize_t g_readlink_result = -1;
static int g_readlink_errno = ENOENT;
static size_t g_readlink_calls = 0U;

static ssize_t chaos_test_readlink(const char *path, char *buffer, size_t size)
{
    (void)path;
    (void)size;
    ++g_readlink_calls;

    if (g_readlink_result < 0) {
        errno = g_readlink_errno;
        return -1;
    }

    assert(g_readlink_target != NULL);
    assert((size_t)g_readlink_result <= strlen(g_readlink_target));
    (void)memcpy(buffer, g_readlink_target, (size_t)g_readlink_result);
    return g_readlink_result;
}

#define readlink chaos_test_readlink
#include "../../src/config/chaos_io_fdcache.c"
#undef readlink

static void chaos_test_reset_readlink_state(void)
{
    g_readlink_target = NULL;
    g_readlink_result = -1;
    g_readlink_errno = ENOENT;
    g_readlink_calls = 0U;
}

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
