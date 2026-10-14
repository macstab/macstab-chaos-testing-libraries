/**
 * @file path_forms_probe.c
 * @brief Runtime probe: the path forms of file operations are faulted like the *at forms.
 *
 * glibc and musl implement unlink(), rmdir(), rename(), truncate() and creat() with
 * their own system calls rather than through unlinkat(), renameat(), ftruncate() or
 * open(). They are the forms most programs use (the JDK deletes with unlink() and
 * moves with rename()), so each must reach the same rule as its *at or descriptor
 * form. Every call below runs under a rule that fails its operation, then once more
 * without a rule to show the real call still works.
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
static void write_rules(const char *rules)
{
    FILE *file = fopen(CONF ".staging", "w");

    if (file == NULL || fputs(rules, file) < 0 || fclose(file) != 0 ||
        rename(CONF ".staging", CONF) != 0)
    {
        perror("write_rules");
        exit(2);
    }
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

    write_rules("# idle\n");
    expect("truncate real", truncate(DIR "/source.bin", 2) == 0);
    expect("rename real", rename(DIR "/source.bin", DIR "/dest.bin") == 0);
    expect("unlink real", unlink(DIR "/victim.bin") == 0 && unlink(DIR "/dest.bin") == 0);
    expect("rmdir real", rmdir(DIR "/empty.d") == 0);
    fd = creat(DIR "/new.bin", 0600);
    expect("creat real", fd >= 0 && close(fd) == 0 && unlink(DIR "/new.bin") == 0);

    (void)unlink(CONF);
    (void)rmdir(DIR);
    return g_failures == 0 ? 0 : 1;
}
