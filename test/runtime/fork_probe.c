/**
 * @file fork_probe.c
 * @brief Drives an `@first` budget and the per-thread PRNG across vfork, fork and posix_spawn
 *        children for test_fork.sh, which judges the result.
 *
 * @details
 * Usage: fork_probe vfork|fork|spawn|open|draws|faults, under LD_PRELOAD of libchaos-io with
 * an open rule on /tmp/fork-data (faults: any preloads, no rule needed).
 *
 * - vfork|fork|spawn: the parent opens /tmp/fork-data/file, starts a child of that kind which
 *   opens it once, then opens it again, and prints which opens failed with EIO, e.g.
 *   `parent=EIO child=ok parent=ok` ("error" when the child could not be started or reaped).
 *   With `@first=1` this shows whose budget each process used; test_fork.sh also counts the
 *   hits files and hits.
 * - open: one open; exit status 1 on EIO, 0 otherwise. The spawn mode posix_spawn()s the probe
 *   itself in this mode.
 * - draws: parent and a forked child each open 64 times under a probability rule and the probe
 *   prints "same" when both saw the identical failure pattern, "different" otherwise. A child
 *   that inherited the parent's PRNG state would print "same" (1 in 2^64 by chance at p = 0.5).
 * - faults: forks 50 children that `_exit(0)` at once and prints their mean minor page faults
 *   (wait4's ru_minflt). Every page an atfork child handler writes costs the child a
 *   copy-on-write fault, so the count shows what the preloaded libraries' fork handling costs,
 *   deterministically, unlike a timing.
 *
 * Exit: 0 after printing (open mode: 1 on EIO); 2 on bad usage or a pipe/fork failure in
 * draws mode.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

/** @brief Opens the faulted file; 1 when the open failed with EIO. */
static int open_fails(void)
{
    const int fd = open("/tmp/fork-data/file", O_RDONLY);

    if (fd >= 0)
    {
        (void)close(fd);
        return 0;
    }
    return errno == EIO;
}

/** @brief Reaps @p child; 1 when it exited 1 (faulted open), 0 otherwise, -1 when it could
 * not be reaped or did not exit normally. */
static int child_failed(pid_t child)
{
    int status = 0;

    if (child <= 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status))
    {
        return -1;
    }
    return WEXITSTATUS(status) == 1;
}

/** @brief "EIO" for 1, "ok" for 0, "error" for anything else. */
static const char *word(int failed)
{
    return failed == 1 ? "EIO" : failed == 0 ? "ok" : "error";
}

/** @brief Opens the faulted file 64 times and records each outcome as '1' (EIO) or '0' in
 * @p pattern (65 bytes, NUL-terminated). */
static void draw(char *pattern)
{
    int index;

    for (index = 0; index < 64; ++index)
    {
        pattern[index] = open_fails() == 1 ? '1' : '0';
    }
    pattern[64] = '\0';
}

int main(int argc, char **argv)
{
    int first;
    int child = -1;
    pid_t pid = -1;

    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s vfork|fork|spawn|open|draws|faults\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "open") == 0)
    {
        return open_fails();
    }
    if (strcmp(argv[1], "faults") == 0)
    {
        long faults = 0L;
        int round;

        for (round = 0; round < 50; ++round)
        {
            struct rusage usage;
            int status;

            pid = fork();
            if (pid == 0)
            {
                _exit(0);
            }
            if (pid < 0 || wait4(pid, &status, 0, &usage) != pid)
            {
                return 2;
            }
            faults += usage.ru_minflt;
        }
        (void)printf("%ld\n", faults / 50L);
        return 0;
    }

    if (strcmp(argv[1], "draws") == 0)
    {
        char parent[65];
        char forked[65] = "";
        int pipe_fds[2];

        if (pipe(pipe_fds) != 0)
        {
            return 2;
        }
        pid = fork();
        if (pid == 0)
        {
            draw(forked);
            _exit(write(pipe_fds[1], forked, 64U) == 64 ? 0 : 1);
        }
        draw(parent);
        (void)close(pipe_fds[1]);
        if (pid < 0 || read(pipe_fds[0], forked, 64U) != 64)
        {
            return 2;
        }
        (void)waitpid(pid, NULL, 0);
        (void)printf("%s\n", strcmp(parent, forked) == 0 ? "same" : "different");
        return 0;
    }

    first = open_fails();
    if (strcmp(argv[1], "vfork") == 0)
    {
        /* The child runs the wrapper in the parent's memory, as a JDK VFORK launch or a
         * shell's vfork does before exec: it sees the parent's claimed budget and must not
         * consume or reset it. */
        pid = vfork();
        if (pid == 0)
        {
            _exit(open_fails());
        }
    }
    else if (strcmp(argv[1], "fork") == 0)
    {
        pid = fork();
        if (pid == 0)
        {
            _exit(open_fails());
        }
    }
    else if (strcmp(argv[1], "spawn") == 0)
    {
        char *child_argv[] = {argv[0], (char *)"open", NULL};

        if (posix_spawn(&pid, argv[0], NULL, NULL, child_argv, environ) != 0)
        {
            pid = -1;
        }
    }
    child = child_failed(pid);
    (void)printf("parent=%s child=%s parent=%s\n", word(first), word(child), word(open_fails()));
    return 0;
}
