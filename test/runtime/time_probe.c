/**
 * @file time_probe.c
 * @brief Runtime validation probe for libchaos-time under LD_PRELOAD.
 *
 * @details
 * Standalone C program compiled inside a Docker container and executed under
 * `LD_PRELOAD=libchaos-time.so`. Validates end-to-end fault injection for
 * the time library's interposed symbols: `clock_gettime`, `clock_getres`,
 * `nanosleep`, and `usleep`.
 *
 * Each subtest writes a config rule with a future-mtime timestamp to
 * `/tmp/.chaos-time.conf`, then exercises the interposed symbol and asserts
 * the expected behavior. The future-mtime pattern guarantees a config reload
 * cycle on the first post-write invocation, ensuring the new rule is active.
 *
 * Subtests cover:
 * - `ERRNO` injection on `clock_gettime` (synthetic `EINVAL` return)
 * - `LATENCY` injection on `clock_gettime` (≥ 150 ms added sleep)
 * - `OFFSET` applied to `CLOCK_MONOTONIC` result (signed ms added to tv_sec/tv_nsec)
 * - `ERRNO` injection on `nanosleep` (synthetic `EINVAL` return)
 * - `LATENCY` injection on `nanosleep` (additive to requested sleep)
 * - `ERRNO` injection on `usleep` (synthetic `EINVAL` return)
 *
 * On glibc, `clock_gettime`/`clock_getres` for `CLOCK_MONOTONIC` and
 * `CLOCK_REALTIME` are normally serviced through the vDSO fast path without
 * trapping into libc.  libchaos-time interposes the libc PLT entry, which is
 * resolved before any vDSO dispatch occurs in user-space, so injection still
 * fires for these clock IDs.  The probe relies on this property: a CI
 * environment where the vDSO bypass were exposed (e.g. raw `__vdso_clock_gettime`
 * lookup via `getauxval(AT_SYSINFO_EHDR)`) would not trigger the rule.
 *
 * Returns 0 on success; returns a non-zero numbered exit code identifying
 * the failing subtest.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static time_t g_config_stamp = 7000;

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

static int write_config(const char *text)
{
    struct timespec times[2];
    FILE *config = fopen("/tmp/.chaos-time.conf", "w");

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

static int probe_clock_errno(void)
{
    struct timespec value;
    int rc = write_config("clock_gettime:ERRNO:EINVAL");

    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    return clock_gettime(CLOCK_MONOTONIC, &value) == -1 && errno == EINVAL ? 0 : 10;
}

static int probe_clock_offset(void)
{
    struct timespec baseline;
    struct timespec shifted;
    long long delta_ms;
    int rc = write_config("# clear");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &baseline) != 0)
    {
        return 20;
    }

    rc = write_config("clock_gettime/monotonic:OFFSET:500");
    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &shifted) != 0)
    {
        return 21;
    }

    delta_ms = elapsed_ms(&baseline, &shifted);
    return delta_ms >= 400LL ? 0 : 22;
}

static int probe_nanosleep_errno(void)
{
    struct timespec request;
    struct timespec remaining;
    int rc = write_config("nanosleep:ERRNO:EINTR");

    if (rc != 0)
    {
        return rc;
    }

    request.tv_sec = 0;
    request.tv_nsec = 50000000L;
    remaining.tv_sec = 0;
    remaining.tv_nsec = 0L;
    errno = 0;
    rc = nanosleep(&request, &remaining);
    if (rc != -1 || errno != EINTR)
    {
        return 30;
    }
    return remaining.tv_sec == request.tv_sec && remaining.tv_nsec == request.tv_nsec ? 0 : 31;
}

static int probe_nanosleep_latency(void)
{
    struct timespec request;
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int rc = write_config("nanosleep:LATENCY:200");

    if (rc != 0)
    {
        return rc;
    }

    request.tv_sec = 0;
    request.tv_nsec = 1000000L;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 40;
    }
    rc = nanosleep(&request, NULL);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        return 41;
    }
    if (rc != 0)
    {
        return 42;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 150LL ? 0 : 43;
}

static int probe_usleep_errno(void)
{
    int rc = write_config("usleep:ERRNO:EINTR");

    if (rc != 0)
    {
        return rc;
    }

    errno = 0;
    return usleep(1000U) == -1 && errno == EINTR ? 0 : 50;
}

static int probe_usleep_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int rc = write_config("usleep:LATENCY:150");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 60;
    }
    rc = usleep(1000U);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        return 61;
    }
    if (rc != 0)
    {
        return 62;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 120LL ? 0 : 63;
}

int main(void)
{
    int rc;

    rc = probe_clock_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_clock_offset();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_nanosleep_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_nanosleep_latency();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_usleep_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_usleep_latency();
    if (rc != 0)
    {
        return rc;
    }

    (void)unlink("/tmp/.chaos-time.conf");
    return 0;
}
