/**
 * @file time_probe.c
 * @brief End-to-end probe for libchaos-time in LD_PRELOAD mode on glibc and musl.
 *
 * @details
 * Proves that rules written to the rule file `/tmp/.chaos-time.conf` reach every time entry
 * point a program can call, with the documented result and errno contract. Exit code of each
 * check, its rule, and the behaviour proven:
 *
 * - 10      clock_gettime:ERRNO:EINVAL; -1 with errno EINVAL.
 * - 20-22   clock_gettime/monotonic:OFFSET:500; the clock reads >= 400 ms ahead.
 * - 120-122 clock_gettime/monotonic:REGRESS:5000; the 2nd read is 4.9-5.1 s back, then the
 *           clock advances again.
 * - 130-132 monotonic OFFSET:3000; an absolute (TIMER_ABSTIME) deadline is converted to the
 *           real clock: 50-1000 ms instead of 3.1 s.
 * - 30-31   nanosleep:ERRNO:EINTR; -1/EINTR with the whole request left in `*remaining`.
 * - 40-43   nanosleep:LATENCY:200; a 1 ms sleep takes >= 150 ms.
 * - 50      usleep:ERRNO:EINTR; -1 with errno EINTR.
 * - 60-63   usleep:LATENCY:150; a 1 ms sleep takes >= 120 ms.
 * - 70-74   clock_gettime/realtime:OFFSET:86400000; clock_gettime, gettimeofday and time
 *           agree on +1 day.
 * - 80-82   nanosleep:ERRNO:EINTR; clock_nanosleep returns EINTR, errno untouched.
 * - 90-93   nanosleep ERRNO / realtime OFFSET; sleep(2) returns 2 at once with EINTR,
 *           timespec_get is +1 day.
 * - 200-204 the rule file could not be written.
 *
 * gettimeofday, time, sleep, clock_nanosleep and timespec_get are separate checks because libc
 * implements them without calling the public clock_gettime/nanosleep (vDSO or internal
 * paths), so each needs its own wrapper; a rule on clock_gettime or nanosleep must still
 * govern them. Interposition happens at symbol binding: a program that calls the vDSO
 * directly (`__vdso_clock_gettime` via getauxval(AT_SYSINFO_EHDR)) bypasses libchaos-time.
 *
 * Margins: lower bounds sit 30-100 ms under the configured value so a loaded or emulated
 * (QEMU) runner does not flake; the regress window is +-100 ms.
 *
 * Run by test_time_glibc.sh (gcc:bookworm) and test_time_alpine.sh (alpine:3.20), which build
 * the library, compile this file in the container and run it with
 * `LD_PRELOAD=/tmp/libchaos-time.so`. Checks run in main()'s order and stop at the first
 * failure.
 *
 * Exit: 0 when every check passes (the rule file is removed); otherwise the code of the
 * first failing check above. The probe never skips.
 */
#include <errno.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static time_t g_config_stamp = 7000;

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
 * sleep is a raw clock_nanosleep system call, restarted on EINTR, because the active rule may
 * be faulting nanosleep itself.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

/**
 * @brief Replaces the rule file with @p text plus a newline and stamps a fresh mtime.
 *
 * The mtime is set explicitly to 7000, 7001, ... seconds since the epoch. Each write therefore
 * changes the reload change stamp even when two writes land within one filesystem timestamp
 * tick, which an unchanged size and inode would otherwise hide.
 *
 * @return 0, or 200 (fopen), 201 (fprintf), 202 (fflush), 203 (futimens), 204 (fclose).
 */
static int write_config_now(const char *text)
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

/** @brief write_config_now(), then wait_for_rule_check(); returns write_config_now()'s code. */
static int write_config(const char *text)
{
    const int rc = write_config_now(text);

    wait_for_rule_check();
    return rc;
}

/** @brief ERRNO on clock_gettime: -1 with errno EINVAL (exit 10). */
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

/**
 * @brief OFFSET:500 on clock_gettime/monotonic: a read after the rule is >= 400 ms past a read
 *        before it (exit 20-22). The 100 ms slack absorbs reload and scheduling jitter.
 */
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

/**
 * @brief ERRNO:EINTR on nanosleep: -1/EINTR without sleeping, and `*remaining` holds the whole
 *        request, as an interruption before any sleep would report (exit 30-31).
 */
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

/** @brief LATENCY:200 on nanosleep: a 1 ms sleep succeeds and takes >= 150 ms (exit 40-43). */
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

/** @brief ERRNO:EINTR on usleep: -1 with errno EINTR (exit 50). */
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

/** @brief LATENCY:150 on usleep: a 1 ms sleep succeeds and takes >= 120 ms (exit 60-63). */
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

/*
 * OFFSET:86400000 on clock_gettime/realtime shifts all three wall-clock readers by one day
 * (exit 70-74). gettimeofday and time read the realtime clock through the vDSO without calling
 * clock_gettime, so this proves their own wrappers apply the realtime rule: a program mixing
 * them must never see two different wall clocks.
 */
static int probe_wall_clocks_agree(void)
{
    struct timespec realtime;
    struct timeval timeofday;
    time_t baseline;
    time_t seconds;
    int rc = write_config("# clear");

    if (rc != 0)
    {
        return rc;
    }
    baseline = time(NULL);

    rc = write_config("clock_gettime/realtime:OFFSET:86400000");
    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_REALTIME, &realtime) != 0)
    {
        return 70;
    }
    if (gettimeofday(&timeofday, NULL) != 0)
    {
        return 71;
    }
    seconds = time(NULL);

    if (realtime.tv_sec < baseline + 86400 - 5 || realtime.tv_sec > baseline + 86400 + 5)
    {
        return 72;
    }
    if (timeofday.tv_sec < realtime.tv_sec - 2 || timeofday.tv_sec > realtime.tv_sec + 2)
    {
        return 73;
    }
    if (seconds < realtime.tv_sec - 2 || seconds > realtime.tv_sec + 2)
    {
        return 74;
    }
    return 0;
}

/*
 * A nanosleep ERRNO rule also fails clock_nanosleep (exit 80-82), honouring its different
 * error contract: the error number is the return value and errno must stay untouched
 * (sentinel 4242). A relative sleep interrupted before sleeping reports the whole request as
 * remaining.
 */
static int probe_clock_nanosleep_errno(void)
{
    struct timespec request = {1, 0L};
    struct timespec remaining = {0, 0L};
    int rc = write_config("nanosleep:ERRNO:EINTR");

    if (rc != 0)
    {
        return rc;
    }
    errno = 4242;
    if (clock_nanosleep(CLOCK_MONOTONIC, 0, &request, &remaining) != EINTR)
    {
        return 80;
    }
    if (errno != 4242)
    {
        return 81;
    }
    return remaining.tv_sec == request.tv_sec && remaining.tv_nsec == request.tv_nsec ? 0 : 82;
}

/*
 * sleep() and timespec_get() reach the kernel on internal libc paths in glibc and musl, so they
 * have their own wrappers (exit 90-93). Under nanosleep:ERRNO:EINTR, sleep(2) must return
 * the full 2 s as unslept, set EINTR and return in < 1000 ms; under a realtime OFFSET of one
 * day, timespec_get(TIME_UTC) must be one day ahead (+-5 s).
 */
static int probe_sleep_and_timespec_get(void)
{
    struct timespec before;
    struct timespec after;
    struct timespec utc;
    time_t baseline;
    int rc = write_config("nanosleep:ERRNO:EINTR");

    if (rc != 0)
    {
        return rc;
    }
    (void)clock_gettime(CLOCK_MONOTONIC, &before);
    errno = 0;
    if (sleep(2U) != 2U || errno != EINTR)
    {
        return 90;
    }
    (void)clock_gettime(CLOCK_MONOTONIC, &after);
    if (elapsed_ms(&before, &after) >= 1000LL)
    {
        return 91;
    }

    rc = write_config("# clear");
    if (rc != 0)
    {
        return rc;
    }
    baseline = time(NULL);
    rc = write_config("clock_gettime/realtime:OFFSET:86400000");
    if (rc != 0)
    {
        return rc;
    }
    if (timespec_get(&utc, TIME_UTC) != TIME_UTC)
    {
        return 92;
    }
    return utc.tv_sec >= baseline + 86400 - 5 && utc.tv_sec <= baseline + 86400 + 5 ? 0 : 93;
}

/**
 * @brief REGRESS:5000 on clock_gettime/monotonic steps the clock back once (exit 120-122).
 *
 * The first read is real, the second is 4.9-5.1 s earlier, and the third is not earlier than
 * the second: the step is a one-time discontinuity, after which the clock advances normally
 * instead of regressing on every read. Clears the rule on success.
 */
static int probe_clock_regress(void)
{
    struct timespec first;
    struct timespec jumped;
    struct timespec later;
    int rc = write_config("clock_gettime/monotonic:REGRESS:5000");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &first) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &jumped) != 0 || clock_gettime(CLOCK_MONOTONIC, &later) != 0)
    {
        return 120;
    }
    if (elapsed_ms(&first, &jumped) > -4900LL || elapsed_ms(&first, &jumped) < -5100LL)
    {
        return 121;
    }
    if (elapsed_ms(&jumped, &later) < 0LL)
    {
        return 122;
    }
    return write_config("# clear");
}

/** @brief CLOCK_MONOTONIC via a raw system call, so no OFFSET or REGRESS rule applies. */
static void raw_monotonic(struct timespec *now)
{
    (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, now);
}

/**
 * @brief clock_nanosleep(TIMER_ABSTIME) to "shifted now + 100 ms" sleeps about 100 ms under
 *        OFFSET:3000 (exit 130-132).
 *
 * The program computes its deadline from the shifted clock, 3 s ahead of the kernel's. The
 * wrapper must translate the deadline back to the real clock; unconverted, the sleep would
 * last 3.1 s. Elapsed time is measured on the raw clock and must be 50-1000 ms. Clears the
 * rule on success.
 */
static int probe_absolute_sleep_offset(void)
{
    struct timespec deadline;
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int rc = write_config("clock_gettime/monotonic:OFFSET:3000");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0)
    {
        return 130;
    }
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L)
    {
        deadline.tv_nsec -= 1000000000L;
        ++deadline.tv_sec;
    }
    raw_monotonic(&start);
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL) != 0)
    {
        return 131;
    }
    raw_monotonic(&end);
    duration_ms = elapsed_ms(&start, &end);
    if (duration_ms < 50LL || duration_ms > 1000LL)
    {
        (void)fprintf(stderr, "absolute sleep under OFFSET took %lld ms\n", duration_ms);
        return 132;
    }
    return write_config("# clear");
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
    rc = probe_clock_regress();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_absolute_sleep_offset();
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
    rc = probe_wall_clocks_agree();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_clock_nanosleep_errno();
    if (rc != 0)
    {
        return rc;
    }
    rc = probe_sleep_and_timespec_get();
    if (rc != 0)
    {
        return rc;
    }

    (void)unlink("/tmp/.chaos-time.conf");
    return 0;
}
