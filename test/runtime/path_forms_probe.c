/**
 * @file path_forms_probe.c
 * @brief Runtime probe: the path forms of file operations are faulted like the *at forms.
 *
 * glibc and musl implement unlink(), rmdir(), remove(), rename(), renameat2() (glibc),
 * truncate(), creat(), fopen(), freopen() and posix_fallocate() with
 * their own system calls rather than through unlinkat(), renameat(), ftruncate(),
 * open() or fallocate(). They are the forms most programs use (the JDK deletes with unlink() and
 * moves with rename()), so each must reach the same rule as its *at or descriptor
 * form. Every call below runs under a rule that fails its operation, then once more
 * without a rule to show the real call still works.
 *
 * Vectored writes under a matching rule also get the kernel's answer for an array
 * the kernel rejects (unmapped, longer than IOV_MAX) instead of a crash in the
 * wrapper, and a vector too long to tear is written whole.
 *
 * Usage: path_forms_probe   (under LD_PRELOAD of libchaos-io)
 * Exit code 0 when every call was faulted and then succeeded, 1 otherwise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define DIR "/tmp/path-forms-probe"
#define CONF "/tmp/.chaos-io.conf"

static int g_failures = 0;

static void expect(const char *what, int ok)
{
    if (!ok)
    {
        (void)fprintf(stderr, "FAIL %s (errno %d)\n", what, errno);
        g_failures++;
        return;
    }
    (void)printf("ok   %s\n", what);
}

/** Replaces the rule file atomically (new inode), as the framework's writers do. */
/**
 * @brief Waits until the library is due to look at its rule file again.
 *
 * Once rules are loaded the libraries look at the rule file at most every
 * millisecond, so a change takes effect within that time, not on the very next
 * call. The sleep is a raw system call: libchaos-time may be faulting nanosleep.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

static void write_rules_now(const char *rules)
{
    FILE *file = fopen(CONF ".staging", "w");

    if (file == NULL || fputs(rules, file) < 0 || fclose(file) != 0 ||
        rename(CONF ".staging", CONF) != 0)
    {
        perror("write_rules");
        exit(2);
    }
}

/** @brief Writes the rules, then waits until the library looks at them. */
static void write_rules(const char *rules)
{
    write_rules_now(rules);
    wait_for_rule_check();
}

static void make_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);

    if (fd < 0 || write(fd, "payload", 7U) != 7 || close(fd) != 0)
    {
        perror(path);
        exit(2);
    }
}

/** @brief writev through a pointer, so libc's attributes accept invalid arguments. */
static ssize_t (*volatile g_writev)(int, const struct iovec *, int) = writev;

/** @brief Vectored writes with arrays the wrapper must not walk or cannot tear. */
static void check_vectored_writes(void)
{
    static struct iovec many[100];
    static char bytes[100];
    struct iovec pair[2] = {{bytes, 1U}, {bytes + 1, 1U}};
    int index;
    int fd;

    for (index = 0; index < 100; ++index)
    {
        many[index].iov_base = &bytes[index];
        many[index].iov_len = 1U;
    }
    write_rules(DIR ":write:TORN:1.0\n");
    fd = open(DIR "/vector.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    errno = 0;
    expect(
        "writev unmapped array",
        fd >= 0 && g_writev(fd, (const struct iovec *)(uintptr_t)8U, 2) == -1 && errno == EFAULT
    );
    errno = 0;
    expect("writev past IOV_MAX", g_writev(fd, pair, IOV_MAX + 1) == -1 && errno == EINVAL);
    expect("writev too long to tear", g_writev(fd, many, 100) == 100);
    expect("writev torn", g_writev(fd, pair, 2) == 1 && close(fd) == 0);
    expect("vector file removed", unlink(DIR "/vector.bin") == 0);
}

int main(void)
{
    struct stat info;
    int fd;

    (void)mkdir(DIR, 0700);
    write_rules("# idle\n");
    make_file(DIR "/victim.bin");
    make_file(DIR "/source.bin");
    (void)mkdir(DIR "/empty.d", 0700);

    write_rules(DIR ":unlink:EACCES:1.0\n");
    errno = 0;
    expect("unlink faulted", unlink(DIR "/victim.bin") == -1 && errno == EACCES);
    expect("unlink left the file", stat(DIR "/victim.bin", &info) == 0);
    errno = 0;
    expect("rmdir faulted", rmdir(DIR "/empty.d") == -1 && errno == EACCES);

    write_rules(DIR "/dest.bin:rename_to:ENOSPC:1.0\n");
    errno = 0;
    expect("rename faulted", rename(DIR "/source.bin", DIR "/dest.bin") == -1 && errno == ENOSPC);
    expect("rename left the source", stat(DIR "/source.bin", &info) == 0);

    write_rules(DIR ":truncate:EIO:1.0\n");
    errno = 0;
    expect("truncate faulted", truncate(DIR "/source.bin", 2) == -1 && errno == EIO);
    expect("truncate left the size", stat(DIR "/source.bin", &info) == 0 && info.st_size == 7);

    write_rules(DIR "/new.bin:open:EROFS:1.0\n");
    errno = 0;
    expect("creat faulted", creat(DIR "/new.bin", 0600) == -1 && errno == EROFS);
    errno = 0;
    expect("fopen faulted", fopen(DIR "/new.bin", "w") == NULL && errno == EROFS);
#ifdef __GLIBC__
    errno = 0;
    expect("fopen64 faulted", fopen64(DIR "/new.bin", "w") == NULL && errno == EROFS);
#endif
    {
        FILE *stream = fopen(DIR "/source.bin", "r");

        errno = 0;
        expect(
            "freopen faulted",
            stream != NULL && freopen(DIR "/new.bin", "w", stream) == NULL && errno == EROFS
        );
    }

    write_rules(DIR ":unlink:EACCES:1.0\n");
    errno = 0;
    expect("remove file faulted", remove(DIR "/victim.bin") == -1 && errno == EACCES);
    errno = 0;
    expect("remove dir faulted", remove(DIR "/empty.d") == -1 && errno == EACCES);

    write_rules(DIR ":allocate:ENOSPC:1.0\n");
    fd = open(DIR "/source.bin", O_WRONLY);
    errno = 4242;
    expect(
        "posix_fallocate faulted",
        fd >= 0 && posix_fallocate(fd, 0, 4096) == ENOSPC && errno == 4242 && close(fd) == 0
    );

#ifdef __GLIBC__
    write_rules(DIR "/dest.bin:rename_to:ENOSPC:1.0\n");
    errno = 0;
    expect(
        "renameat2 faulted",
        renameat2(AT_FDCWD, DIR "/source.bin", AT_FDCWD, DIR "/dest.bin", 0U) == -1 &&
            errno == ENOSPC
    );
#endif

    check_vectored_writes();

    write_rules("# idle\n");
    fd = open(DIR "/source.bin", O_WRONLY);
    expect("posix_fallocate real", fd >= 0 && posix_fallocate(fd, 0, 4096) == 0 && close(fd) == 0);
#ifdef __GLIBC__
    expect(
        "renameat2 real",
        renameat2(AT_FDCWD, DIR "/source.bin", AT_FDCWD, DIR "/moved.bin", 0U) == 0 &&
            renameat2(AT_FDCWD, DIR "/moved.bin", AT_FDCWD, DIR "/source.bin", 0U) == 0
    );
#endif
    expect("truncate real", truncate(DIR "/source.bin", 2) == 0);
    expect("rename real", rename(DIR "/source.bin", DIR "/dest.bin") == 0);
    expect("unlink real", unlink(DIR "/victim.bin") == 0 && unlink(DIR "/dest.bin") == 0);
    expect("rmdir real", rmdir(DIR "/empty.d") == 0);
    make_file(DIR "/removed.bin");
    (void)mkdir(DIR "/removed.d", 0700);
    expect("remove real", remove(DIR "/removed.bin") == 0 && remove(DIR "/removed.d") == 0);
    fd = creat(DIR "/new.bin", 0600);
    expect("creat real", fd >= 0 && close(fd) == 0 && unlink(DIR "/new.bin") == 0);
    {
        FILE *stream = fopen(DIR "/new.bin", "w");

        expect("fopen real", stream != NULL && fclose(stream) == 0);
        stream = fopen(DIR "/new.bin", "r");
        expect(
            "freopen real",
            stream != NULL && (stream = freopen(DIR "/new.bin", "r", stream)) != NULL &&
                fclose(stream) == 0 && unlink(DIR "/new.bin") == 0
        );
    }

    (void)unlink(CONF);
    (void)rmdir(DIR);
    return g_failures == 0 ? 0 : 1;
}
