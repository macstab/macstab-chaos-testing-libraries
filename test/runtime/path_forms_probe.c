/**
 * @file path_forms_probe.c
 * @brief Proves that libchaos-io faults the path forms of file operations like their *at and
 *        descriptor forms, matches paths as the kernel resolves them, and keeps its descriptor
 *        bookkeeping and vectored writes safe.
 *
 * @details
 * glibc and musl implement unlink(), rmdir(), remove(), rename(), renameat2() (glibc),
 * truncate(), creat(), fopen(), fopen64() (glibc), freopen() and posix_fallocate() with their
 * own system calls instead of calling unlinkat(), renameat(), ftruncate(), open() or
 * fallocate(). These are the forms most programs use (the JDK deletes with unlink() and moves
 * with rename()), so each needs its own wrapper reaching the same rule. Each call runs under a
 * rule that fails its operation, the file system must be unchanged afterwards, and the real
 * call must work once the rule is gone. posix_fallocate must return the error and keep errno.
 *
 * Further checks:
 * - check_path_spellings: `.`, `..`, `//` and relative paths reach a path rule; a descriptor
 *   opened through a symlink is matched by its real path, and a rule naming the symlink
 *   covers the file under its real name.
 * - check_unseen_close: a descriptor libc closes internally (closedir) is dropped from the
 *   fd cache, so a pipe that reuses the number is not mistaken for the directory.
 * - check_wildcard_spares_non_files: `*:write:TORN` tears a regular file but writes an
 *   eventfd, a pipe and a socket whole; tearing an 8-byte eventfd write would be EINVAL.
 * - check_vectored_writes: under a matching TORN rule, writev with an unmapped iovec array
 *   gets the kernel's EFAULT and with IOV_MAX + 1 entries the kernel's EINVAL instead of a
 *   crash in the wrapper; a 100-entry vector too long to tear is written whole; a 2-entry
 *   vector is torn to 1 byte.
 *
 * Usage: path_forms_probe, under LD_PRELOAD of libchaos-io; run by test_path_forms.sh on glibc
 * and musl. Works in /tmp/path-forms-probe.
 *
 * Exit: 0 when every check passed; 1 when any failed (all run; each prints ok/FAIL); 2 on a
 * setup failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define PROBE_DIR "/tmp/path-forms-probe"
#define CONF "/tmp/.chaos-io.conf"

static int g_failures = 0;

/** @brief Prints ok, or FAIL with errno and records a failure. */
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
 * @brief Replaces `/tmp/.chaos-io.conf` atomically: writes its `.staging` sibling, then
 *        rename()s it over the rule file.
 *
 * The rename gives the file a new inode, which changes the reload change stamp regardless of
 * mtime granularity, and a library never reads a half-written file. This is how the framework's
 * own writers update rule files. Exits the probe with status 2 on any I/O error.
 */
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

/** @brief write_rules_now(), then wait_for_rule_check(). */
static void write_rules(const char *rules)
{
    write_rules_now(rules);
    wait_for_rule_check();
}

/** @brief Creates @p path holding the 7 bytes "payload"; exits 2 on failure. */
static void make_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);

    if (fd < 0 || write(fd, "payload", 7U) != 7 || close(fd) != 0)
    {
        perror(path);
        exit(2);
    }
}

/** @brief Opens @p path read-only; 1 when it failed with EIO. */
static int open_fails_eio(const char *path)
{
    const int fd = open(path, O_RDONLY);

    if (fd >= 0)
    {
        (void)close(fd);
        return 0;
    }
    return errno == EIO;
}

/**
 * @brief Paths are matched as the kernel resolves them: `.`, `..`, repeated slashes and
 *        relative forms reach a path rule, and a descriptor opened through a symlink is known
 *        by its real path to descriptor rules. Without this, any spelling other than the
 *        rule's would bypass it.
 */
static void check_path_spellings(void)
{
    char buffer[4];
    int fd;

    write_rules("# idle\n");
    (void)mkdir(PROBE_DIR "/data", 0700);
    (void)mkdir(PROBE_DIR "/other", 0700);
    make_file(PROBE_DIR "/data/f");
    (void)unlink(PROBE_DIR "/link");
    if (symlink(PROBE_DIR "/data", PROBE_DIR "/link") != 0)
    {
        perror("symlink");
        exit(2);
    }

    write_rules(PROBE_DIR "/data:open:EIO:1.0\n");
    expect("open as written", open_fails_eio(PROBE_DIR "/data/f"));
    expect("open through ./", open_fails_eio(PROBE_DIR "/./data/f"));
    expect("open through //", open_fails_eio(PROBE_DIR "//data///f"));
    expect("open through ..", open_fails_eio(PROBE_DIR "/other/../data/f"));
    expect("open relative ..", chdir(PROBE_DIR "/other") == 0 && open_fails_eio("../data/f"));
    expect("chdir back", chdir("/") == 0);

    write_rules(PROBE_DIR "/data:read:EIO:1.0\n");
    fd = open(PROBE_DIR "/link/f", O_RDONLY);
    errno = 0;
    expect(
        "read through a link",
        fd >= 0 && read(fd, buffer, sizeof(buffer)) == -1 && errno == EIO && close(fd) == 0
    );

    /* The rule's own path is resolved too: a rule naming the symlink covers the real file. */
    write_rules(PROBE_DIR "/link:read:EIO:1.0\n");
    fd = open(PROBE_DIR "/data/f", O_RDONLY);
    errno = 0;
    expect(
        "read rule on a link's name",
        fd >= 0 && read(fd, buffer, sizeof(buffer)) == -1 && errno == EIO && close(fd) == 0
    );

    write_rules("# idle\n");
    expect(
        "spellings cleaned up",
        unlink(PROBE_DIR "/link") == 0 && unlink(PROBE_DIR "/data/f") == 0 &&
            rmdir(PROBE_DIR "/data") == 0 && rmdir(PROBE_DIR "/other") == 0
    );
}

/**
 * @brief A descriptor libc closes internally (closedir) is dropped from the fd cache: a pipe
 *        that reuses the number is read normally instead of matching the directory's
 *        read:EIO rule.
 */
static void check_unseen_close(void)
{
    char byte = 'x';
    int pipe_fds[2];
    DIR *directory;
    int number;

    (void)mkdir(PROBE_DIR "/cached", 0700);
    write_rules(PROBE_DIR "/cached:read:EIO:1.0\n");
    directory = opendir(PROBE_DIR "/cached");
    if (directory == NULL)
    {
        perror("opendir");
        exit(2);
    }
    number = dirfd(directory);
    (void)fsync(number); /* the directory's descriptor is now known by its path */
    expect("closedir", closedir(directory) == 0);
    expect("pipe takes the number", pipe(pipe_fds) == 0 && pipe_fds[0] == number);
    errno = 0;
    expect(
        "pipe read after closedir",
        write(pipe_fds[1], &byte, 1U) == 1 && read(pipe_fds[0], &byte, 1U) == 1
    );
    (void)close(pipe_fds[0]);
    (void)close(pipe_fds[1]);
    write_rules("# idle\n");
    expect("cached dir removed", rmdir(PROBE_DIR "/cached") == 0);
}

/**
 * @brief A `*` selector covers files only: under `*:write:TORN` an eventfd, a pipe and a socket
 *        are written whole (an eventfd write shorter than 8 bytes is EINVAL) while a regular
 *        file is torn.
 */
static void check_wildcard_spares_non_files(void)
{
    const uint64_t one = 1U;
    int pipe_fds[2];
    int pair[2];
    int counter;
    int fd;

    write_rules("*:write:TORN:1.0\n");
    counter = eventfd(0U, 0);
    expect("eventfd written whole", counter >= 0 && write(counter, &one, sizeof(one)) == 8);
    expect("pipe written whole", pipe(pipe_fds) == 0 && write(pipe_fds[1], "data", 4U) == 4);
    expect(
        "socket written whole",
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0 && write(pair[0], "data", 4U) == 4
    );
    fd = open(PROBE_DIR "/torn.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    expect("file torn", fd >= 0 && write(fd, "data", 4U) < 4);
    (void)close(counter);
    (void)close(pipe_fds[0]);
    (void)close(pipe_fds[1]);
    (void)close(pair[0]);
    (void)close(pair[1]);
    (void)close(fd);
    write_rules("# idle\n");
    expect("torn file removed", unlink(PROBE_DIR "/torn.bin") == 0);
}

/** @brief writev called through a volatile pointer, so the compiler cannot reject or fold the
 * deliberately invalid arguments using libc's declaration attributes. */
static ssize_t (*volatile g_writev)(int, const struct iovec *, int) = writev;

/**
 * @brief writev under a matching TORN rule with arrays the wrapper must not walk (unmapped:
 *        EFAULT; IOV_MAX + 1 entries: EINVAL, both from the kernel) or cannot tear (100
 *        entries, written whole); a 2-entry vector is torn to 1 byte.
 */
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
    write_rules(PROBE_DIR ":write:TORN:1.0\n");
    fd = open(PROBE_DIR "/vector.bin", O_CREAT | O_WRONLY | O_TRUNC, 0600);
    errno = 0;
    expect(
        "writev unmapped array",
        fd >= 0 && g_writev(fd, (const struct iovec *)(uintptr_t)8U, 2) == -1 && errno == EFAULT
    );
    errno = 0;
    expect("writev past IOV_MAX", g_writev(fd, pair, IOV_MAX + 1) == -1 && errno == EINVAL);
    expect("writev too long to tear", g_writev(fd, many, 100) == 100);
    expect("writev torn", g_writev(fd, pair, 2) == 1 && close(fd) == 0);
    expect("vector file removed", unlink(PROBE_DIR "/vector.bin") == 0);
}

int main(void)
{
    struct stat info;
    int fd;

    (void)mkdir(PROBE_DIR, 0700);
    write_rules("# idle\n");
    make_file(PROBE_DIR "/victim.bin");
    make_file(PROBE_DIR "/source.bin");
    (void)mkdir(PROBE_DIR "/empty.d", 0700);

    write_rules(PROBE_DIR ":unlink:EACCES:1.0\n");
    errno = 0;
    expect("unlink faulted", unlink(PROBE_DIR "/victim.bin") == -1 && errno == EACCES);
    expect("unlink left the file", stat(PROBE_DIR "/victim.bin", &info) == 0);
    errno = 0;
    expect("rmdir faulted", rmdir(PROBE_DIR "/empty.d") == -1 && errno == EACCES);

    write_rules(PROBE_DIR "/dest.bin:rename_to:ENOSPC:1.0\n");
    errno = 0;
    expect(
        "rename faulted",
        rename(PROBE_DIR "/source.bin", PROBE_DIR "/dest.bin") == -1 && errno == ENOSPC
    );
    expect("rename left the source", stat(PROBE_DIR "/source.bin", &info) == 0);

    write_rules(PROBE_DIR ":truncate:EIO:1.0\n");
    errno = 0;
    expect("truncate faulted", truncate(PROBE_DIR "/source.bin", 2) == -1 && errno == EIO);
    expect(
        "truncate left the size", stat(PROBE_DIR "/source.bin", &info) == 0 && info.st_size == 7
    );

    write_rules(PROBE_DIR "/new.bin:open:EROFS:1.0\n");
    errno = 0;
    expect("creat faulted", creat(PROBE_DIR "/new.bin", 0600) == -1 && errno == EROFS);
    errno = 0;
    expect("fopen faulted", fopen(PROBE_DIR "/new.bin", "w") == NULL && errno == EROFS);
#ifdef __GLIBC__
    errno = 0;
    expect("fopen64 faulted", fopen64(PROBE_DIR "/new.bin", "w") == NULL && errno == EROFS);
#endif
    {
        FILE *stream = fopen(PROBE_DIR "/source.bin", "r");

        errno = 0;
        expect(
            "freopen faulted",
            stream != NULL && freopen(PROBE_DIR "/new.bin", "w", stream) == NULL && errno == EROFS
        );
    }

    write_rules(PROBE_DIR ":unlink:EACCES:1.0\n");
    errno = 0;
    expect("remove file faulted", remove(PROBE_DIR "/victim.bin") == -1 && errno == EACCES);
    errno = 0;
    expect("remove dir faulted", remove(PROBE_DIR "/empty.d") == -1 && errno == EACCES);

    write_rules(PROBE_DIR ":allocate:ENOSPC:1.0\n");
    fd = open(PROBE_DIR "/source.bin", O_WRONLY);
    errno = 4242;
    expect(
        "posix_fallocate faulted",
        fd >= 0 && posix_fallocate(fd, 0, 4096) == ENOSPC && errno == 4242 && close(fd) == 0
    );

#ifdef __GLIBC__
    write_rules(PROBE_DIR "/dest.bin:rename_to:ENOSPC:1.0\n");
    errno = 0;
    expect(
        "renameat2 faulted",
        renameat2(AT_FDCWD, PROBE_DIR "/source.bin", AT_FDCWD, PROBE_DIR "/dest.bin", 0U) == -1 &&
            errno == ENOSPC
    );
#endif

    check_vectored_writes();
    check_path_spellings();
    check_unseen_close();
    check_wildcard_spares_non_files();

    write_rules("# idle\n");
    fd = open(PROBE_DIR "/source.bin", O_WRONLY);
    expect("posix_fallocate real", fd >= 0 && posix_fallocate(fd, 0, 4096) == 0 && close(fd) == 0);
#ifdef __GLIBC__
    expect(
        "renameat2 real",
        renameat2(AT_FDCWD, PROBE_DIR "/source.bin", AT_FDCWD, PROBE_DIR "/moved.bin", 0U) == 0 &&
            renameat2(AT_FDCWD, PROBE_DIR "/moved.bin", AT_FDCWD, PROBE_DIR "/source.bin", 0U) == 0
    );
#endif
    expect("truncate real", truncate(PROBE_DIR "/source.bin", 2) == 0);
    expect("rename real", rename(PROBE_DIR "/source.bin", PROBE_DIR "/dest.bin") == 0);
    expect(
        "unlink real", unlink(PROBE_DIR "/victim.bin") == 0 && unlink(PROBE_DIR "/dest.bin") == 0
    );
    expect("rmdir real", rmdir(PROBE_DIR "/empty.d") == 0);
    make_file(PROBE_DIR "/removed.bin");
    (void)mkdir(PROBE_DIR "/removed.d", 0700);
    expect(
        "remove real", remove(PROBE_DIR "/removed.bin") == 0 && remove(PROBE_DIR "/removed.d") == 0
    );
    fd = creat(PROBE_DIR "/new.bin", 0600);
    expect("creat real", fd >= 0 && close(fd) == 0 && unlink(PROBE_DIR "/new.bin") == 0);
    {
        FILE *stream = fopen(PROBE_DIR "/new.bin", "w");

        expect("fopen real", stream != NULL && fclose(stream) == 0);
        stream = fopen(PROBE_DIR "/new.bin", "r");
        expect(
            "freopen real",
            stream != NULL && (stream = freopen(PROBE_DIR "/new.bin", "r", stream)) != NULL &&
                fclose(stream) == 0 && unlink(PROBE_DIR "/new.bin") == 0
        );
    }

    (void)unlink(CONF);
    (void)rmdir(PROBE_DIR);
    return g_failures == 0 ? 0 : 1;
}
