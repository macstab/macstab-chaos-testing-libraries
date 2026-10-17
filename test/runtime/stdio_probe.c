/**
 * @file stdio_probe.c
 * @brief Proves that libchaos-io read and write rules fault buffered stdio the way the C
 *        library reports a real I/O error.
 *
 * @details
 * glibc and musl fill and flush FILE buffers with internal system calls, not through the
 * exported read()/write(), so without dedicated stdio wrappers these calls would never be
 * faulted. Each call runs under a rule for its operation on /tmp/stdio-probe and must fail as
 * libc fails on a real error (short count or EOF/NULL/-1, errno set, ferror() set where
 * checked), then work again once the rule is gone:
 * - read:EIO: fread, fgets, fgetc, getline.
 * - read:CORRUPT: fread returns all 5 bytes, altered.
 * - write:ENOSPC: fwrite, fputs, fprintf, fflush.
 * - fd reuse: after fclose of a cached stream, /proc/self/status opened under the same fd
 *   number is read normally, proving fclose drops libchaos-io's fd-to-path cache entry.
 *
 * Results go to stderr. Usage: stdio_probe, under LD_PRELOAD of libchaos-io; run by
 * test_stdio.sh on glibc (plain and _FORTIFY_SOURCE=2) and musl.
 *
 * Exit: 0 when every check passed; 1 when any failed (all run); 2 on a setup failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define DIR "/tmp/stdio-probe"
#define FILE_PATH DIR "/data.txt"
#define CONF "/tmp/.chaos-io.conf"

static int g_failures = 0;

/** @brief Prints ok, or FAIL with errno and records a failure (both to stderr). */
static void expect(const char *what, int ok)
{
    if (!ok)
    {
        (void)fprintf(stderr, "FAIL %s (errno %d)\n", what, errno);
        g_failures++;
        return;
    }
    (void)fprintf(stderr, "ok   %s\n", what);
}

/**
 * @brief Replaces `/tmp/.chaos-io.conf` atomically (write `.staging`, rename) and sleeps 2 ms
 *        with a raw clock_nanosleep so the 1 ms rule-file check throttle has elapsed. Exits 2
 *        on an I/O error.
 */
static void write_rules(const char *rules)
{
    struct timespec delay = {0, 2000000L};
    FILE *file = fopen(CONF ".staging", "w");

    if (file == NULL || fputs(rules, file) < 0 || fclose(file) != 0 ||
        rename(CONF ".staging", CONF) != 0)
    {
        perror("write_rules");
        exit(2);
    }
    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

int main(void)
{
    char buffer[64];
    char *line = NULL;
    size_t capacity = 0U;
    FILE *stream;

    (void)mkdir(DIR, 0700);
    write_rules("# idle\n");
    stream = fopen(FILE_PATH, "w+");
    if (stream == NULL || fputs("hello\nworld\n", stream) < 0 || fflush(stream) != 0)
    {
        perror("setup");
        return 2;
    }

    write_rules(DIR ":read:EIO:1.0\n");
    rewind(stream);
    errno = 0;
    expect("fread faulted", fread(buffer, 1U, 5U, stream) == 0U && errno == EIO && ferror(stream));
    clearerr(stream);
    errno = 0;
    expect("fgets faulted", fgets(buffer, sizeof(buffer), stream) == NULL && errno == EIO);
    expect("fgetc faulted", fgetc(stream) == EOF && ferror(stream));
    clearerr(stream);
    expect("getline faulted", getline(&line, &capacity, stream) == -1 && errno == EIO);
    {
        /* fclose() must drop the fd's cached path: a stream that reuses the number for an
         * unmatched file must not inherit the old file's read:EIO rule. */
        FILE *first = fopen(DIR "/other.txt", "w");
        FILE *proc;
        int first_fd = first != NULL ? fileno(first) : -1;

        /* The fwrite makes libchaos-io resolve and cache this fd's path. */
        expect(
            "fclose of a matched file",
            first != NULL && fwrite("x", 1U, 1U, first) == 1U && fclose(first) == 0
        );
        proc = fopen("/proc/self/status", "r");
        expect(
            "a reused descriptor is not faulted for the old path",
            proc != NULL && fileno(proc) == first_fd && fgets(buffer, sizeof(buffer), proc) != NULL
        );
        if (proc != NULL)
        {
            (void)fclose(proc);
        }
        (void)unlink(DIR "/other.txt");
    }

    write_rules(DIR ":read:CORRUPT:1.0\n");
    clearerr(stream);
    rewind(stream);
    expect(
        "fread corrupted", fread(buffer, 1U, 5U, stream) == 5U && memcmp(buffer, "hello", 5U) != 0
    );

    write_rules(DIR ":write:ENOSPC:1.0\n");
    clearerr(stream);
    errno = 0;
    expect(
        "fwrite faulted", fwrite("x", 1U, 1U, stream) == 0U && errno == ENOSPC && ferror(stream)
    );
    clearerr(stream);
    expect("fputs faulted", fputs("text", stream) == EOF && errno == ENOSPC);
    expect("fprintf faulted", fprintf(stream, "%d", 42) < 0 && errno == ENOSPC);
    expect("fflush faulted", fflush(stream) == EOF && ferror(stream));

    write_rules("# idle\n");
    clearerr(stream);
    rewind(stream);
    expect("fread real", fread(buffer, 1U, 5U, stream) == 5U && memcmp(buffer, "hello", 5U) == 0);
    expect("fgets real", fgets(buffer, sizeof(buffer), stream) == buffer);
    expect("getline real", getline(&line, &capacity, stream) == 6 && strcmp(line, "world\n") == 0);
    expect("fprintf real", fprintf(stream, "%d", 42) == 2 && fflush(stream) == 0);
    expect("fwrite real", fwrite("x", 1U, 1U, stream) == 1U && fclose(stream) == 0);

    free(line);
    (void)unlink(FILE_PATH);
    (void)unlink(CONF);
    (void)rmdir(DIR);
    return g_failures == 0 ? 0 : 1;
}
