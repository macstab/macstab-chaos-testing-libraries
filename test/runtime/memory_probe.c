/**
 * @file memory_probe.c
 * @brief Runtime validation probe for libchaos-memory under LD_PRELOAD.
 *
 * @details
 * Standalone C program compiled inside a Docker container and executed under
 * `LD_PRELOAD=libchaos-memory.so`. Validates end-to-end fault injection for
 * the memory library's interposed symbols: `mmap`, `mprotect`, `madvise`,
 * and `munmap`.
 *
 * Each subtest writes a config rule with a future-mtime timestamp to
 * `/tmp/.chaos-memory.conf`, then exercises the interposed symbol and asserts
 * the expected behavior. The future-mtime pattern guarantees a config reload
 * cycle on the first post-write invocation, ensuring the new rule is active.
 *
 * Subtests cover:
 * - `ERRNO` injection on anonymous `mmap` (`mmap/anon` selector, synthetic `ENOMEM`)
 * - `ERRNO` injection on file-backed `mmap` (`mmap/file` selector, synthetic `EACCES`)
 * - `LATENCY` injection on `mmap` (≥ 120 ms added sleep on anonymous mapping)
 * - `ERRNO` injection on `mprotect` (synthetic `EACCES`)
 * - `LATENCY` injection on `mprotect` (≥ 90 ms added sleep)
 * - `ERRNO` injection on `madvise` (synthetic `EINVAL`)
 * - `LATENCY` injection on `madvise` (≥ 80 ms added sleep)
 * - `ERRNO` injection on `munmap` (synthetic `EINVAL`; chaos cleared before cleanup)
 * - `LATENCY` injection on `munmap` (≥ 80 ms added sleep)
 *
 * The `MAP_ANONYMOUS` portability shim (`MAP_ANON` fallback) allows the probe
 * to compile on macOS for development, though the library itself targets Linux.
 *
 * The `munmap` ERRNO subtest requires a two-phase config pattern: inject the
 * error, confirm it fires, then clear the config and call `munmap` again to
 * release the intentionally retained mapping without triggering another fault.
 *
 * Returns 0 on success; returns a non-zero numbered exit code identifying
 * the failing subtest.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

static time_t g_config_stamp = 9000;

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

static int write_config(const char *text)
{
    struct timespec times[2];
    FILE *config = fopen("/tmp/.chaos-memory.conf", "w");

    if (config == NULL)
    {
        return 200;
    }
    if (fprintf(config, "%s\n", text) < 0)
    {
        fclose(config);
        return 201;
    }
    if (fflush(config) != 0)
    {
        fclose(config);
        return 202;
    }

    times[0].tv_sec = g_config_stamp++;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    if (futimens(fileno(config), times) != 0)
    {
        fclose(config);
        return 203;
    }
    if (fclose(config) != 0)
    {
        return 204;
    }

    return 0;
}

static size_t page_size_value(void)
{
    long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? (size_t)value : 4096U;
}

static void *map_rw_page(size_t *length_out)
{
    size_t length = page_size_value();
    void *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (length_out != NULL)
    {
        *length_out = length;
    }
    return mapping;
}

static int probe_mmap_anon_errno(void)
{
    size_t length;
    void *mapping;
    int rc = write_config("mmap/anon:ERRNO:ENOMEM");

    if (rc != 0)
    {
        return rc;
    }

    length = page_size_value();
    errno = 0;
    mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mapping == MAP_FAILED && errno == ENOMEM ? 0 : 10;
}

static int probe_mmap_file_errno(void)
{
    char path[] = "/tmp/chaos-memory-probe.XXXXXX";
    size_t length = page_size_value();
    void *mapping;
    int fd;
    int rc;

    fd = mkstemp(path);
    if (fd < 0)
    {
        return 20;
    }
    (void)unlink(path);
    if (ftruncate(fd, (off_t)length) != 0)
    {
        (void)close(fd);
        return 21;
    }

    rc = write_config("mmap/file:ERRNO:EACCES");
    if (rc != 0)
    {
        (void)close(fd);
        return rc;
    }

    errno = 0;
    mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    (void)close(fd);
    return mapping == MAP_FAILED && errno == EACCES ? 0 : 22;
}

static int probe_mmap_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    size_t length = page_size_value();
    void *mapping;
    int rc = write_config("mmap:LATENCY:150");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 30;
    }
    mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        if (mapping != MAP_FAILED)
        {
            (void)munmap(mapping, length);
        }
        return 31;
    }
    if (mapping == MAP_FAILED)
    {
        return 32;
    }
    (void)munmap(mapping, length);

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 120LL ? 0 : 33;
}

static int probe_mprotect_errno(void)
{
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 40;
    }
    rc = write_config("mprotect:ERRNO:EACCES");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }

    errno = 0;
    rc = mprotect(mapping, length, PROT_READ);
    (void)munmap(mapping, length);
    return rc == -1 && errno == EACCES ? 0 : 41;
}

static int probe_mprotect_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 50;
    }
    rc = write_config("mprotect:LATENCY:120");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        (void)munmap(mapping, length);
        return 51;
    }
    rc = mprotect(mapping, length, PROT_READ);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        (void)munmap(mapping, length);
        return 52;
    }
    (void)munmap(mapping, length);
    if (rc != 0)
    {
        return 53;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 90LL ? 0 : 54;
}

static int probe_madvise_errno(void)
{
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 60;
    }
    rc = write_config("madvise:ERRNO:EINVAL");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }

    errno = 0;
    rc = madvise(mapping, length, MADV_DONTNEED);
    (void)munmap(mapping, length);
    return rc == -1 && errno == EINVAL ? 0 : 61;
}

static int probe_madvise_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 70;
    }
    rc = write_config("madvise:LATENCY:100");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        (void)munmap(mapping, length);
        return 71;
    }
    rc = madvise(mapping, length, MADV_DONTNEED);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        (void)munmap(mapping, length);
        return 72;
    }
    (void)munmap(mapping, length);
    if (rc != 0)
    {
        return 73;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 74;
}

static int probe_munmap_errno(void)
{
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 80;
    }

    rc = write_config("munmap:ERRNO:EINVAL");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }

    errno = 0;
    rc = munmap(mapping, length);
    if (rc != -1 || errno != EINVAL)
    {
        (void)write_config("");
        (void)munmap(mapping, length);
        return 81;
    }

    /* Disable chaos before cleanup so the intentionally retained mapping is released. */
    rc = write_config("");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }

    return munmap(mapping, length) == 0 ? 0 : 82;
}

static int probe_munmap_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 90;
    }
    rc = write_config("munmap:LATENCY:100");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        (void)munmap(mapping, length);
        return 91;
    }
    rc = munmap(mapping, length);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        return 92;
    }
    if (rc != 0)
    {
        return 93;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 94;
}

int main(void)
{
    int rc;

    rc = probe_mmap_anon_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_mmap_file_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_mmap_latency();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_mprotect_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_mprotect_latency();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_madvise_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_madvise_latency();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_munmap_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_munmap_latency();
    if (rc != 0)
    {
        return rc;
    }

    (void)unlink("/tmp/.chaos-memory.conf");
    return 0;
}
