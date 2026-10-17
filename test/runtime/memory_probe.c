/**
 * @file memory_probe.c
 * @brief End-to-end probe for libchaos-memory in LD_PRELOAD mode on glibc and musl.
 *
 * @details
 * Proves that rules in the rule file `/tmp/.chaos-memory.conf` fault the memory-mapping entry
 * points with the documented result and errno contract. Exit code of each check, its rule, and
 * the behaviour proven:
 *
 * - 10      mmap/anon:ERRNO:ENOMEM; an anonymous mmap returns MAP_FAILED, errno ENOMEM.
 * - 20-22   mmap/file:ERRNO:EACCES; a MAP_SHARED file mapping returns MAP_FAILED/EACCES.
 *           Together with 10 this proves the anon/file target split.
 * - 30-33   mmap:LATENCY:150; an anonymous mapping succeeds and takes >= 120 ms.
 * - 40-41   mprotect:ERRNO:EACCES; -1 with errno EACCES.
 * - 50-54   mprotect:LATENCY:120; succeeds and takes >= 90 ms.
 * - 60-61   madvise:ERRNO:EINVAL; -1 with errno EINVAL.
 * - 62-63   madvise:ERRNO:EINVAL also fails posix_madvise, which returns EINVAL and leaves
 *           errno untouched.
 * - 70-74   madvise:LATENCY:100; succeeds and takes >= 80 ms.
 * - 80-82   munmap:ERRNO:EINVAL; -1/EINVAL and the mapping stays mapped: after clearing the
 *           rule a second munmap of the same range succeeds.
 * - 90-94   munmap:LATENCY:100; succeeds and takes >= 80 ms.
 * - 200-204 the rule file could not be written.
 *
 * Lower bounds sit 20-30 ms under the configured latency so a loaded or emulated (QEMU) runner
 * does not flake. The allocator differences (glibc mmaps only above M_MMAP_THRESHOLD, 128 KiB
 * by default; musl mallocng mmaps for every size class) do not matter here: the probe calls
 * mmap directly.
 *
 * Run by test_memory_glibc.sh (gcc:bookworm) and test_memory_alpine.sh (alpine:3.20), which
 * build the library, compile this file in the container and run it with
 * `LD_PRELOAD=/tmp/libchaos-memory.so`. Checks run in main()'s order and stop at the first
 * failure. The MAP_ANON fallback only lets the file compile on BSD/macOS for editing.
 *
 * Exit: 0 when every check passes (the rule file is removed); otherwise the code of the first
 * failing check above. The probe never skips.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
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

/**
 * @brief Sleeps 2 ms so the next intercepted call re-checks the rule file.
 *
 * With rules loaded, a library stats its rule file at most once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms); a rewrite is seen by the first call after that, not necessarily the next call. The
 * sleep is a raw clock_nanosleep system call, restarted on EINTR, so no wrapper (libchaos-time
 * faults nanosleep) can fail or stretch it.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

/**
 * @brief Replaces the rule file `/tmp/.chaos-memory.conf` with @p text plus a newline and stamps a
 *        fresh mtime.
 *
 * The mtime is set explicitly to 9000, 9001, ... seconds since the epoch, so each write
 * changes the reload change stamp even when two writes land within one filesystem timestamp
 * tick.
 *
 * @return 0, or 200 (fopen), 201 (fprintf), 202 (fflush), 203 (futimens), 204 (fclose).
 */
static int write_config_now(const char *text)
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

/** @brief write_config_now(), then wait_for_rule_check(); returns write_config_now()'s code. */
static int write_config(const char *text)
{
    const int rc = write_config_now(text);

    wait_for_rule_check();
    return rc;
}

/** @brief sysconf(_SC_PAGESIZE), or 4096 when it fails. */
static size_t page_size_value(void)
{
    long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? (size_t)value : 4096U;
}

/** @brief Maps one private anonymous read-write page; MAP_FAILED on error. */
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

/*
 * posix_madvise() issues the madvise system call itself instead of calling madvise(), so it
 * has its own wrapper. It must follow the madvise rules while keeping its own error contract:
 * the error number is the return value and errno stays untouched (sentinel 4242).
 */
static int probe_posix_madvise_errno(void)
{
    size_t length;
    void *mapping = map_rw_page(&length);
    int rc;

    if (mapping == MAP_FAILED)
    {
        return 62;
    }
    rc = write_config("madvise:ERRNO:EINVAL");
    if (rc != 0)
    {
        (void)munmap(mapping, length);
        return rc;
    }

    errno = 4242;
    rc = posix_madvise(mapping, length, POSIX_MADV_SEQUENTIAL);
    (void)munmap(mapping, length);
    return rc == EINVAL && errno == 4242 ? 0 : 63;
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

    /* The faulted munmap left the page mapped; clear the rule so this munmap really unmaps. */
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
    rc = probe_posix_madvise_errno();
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
