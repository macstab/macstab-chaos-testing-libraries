/**
 * @file fork_probe.c
 * @brief Runtime probe: an @first budget across vfork, fork and posix_spawn children.
 *
 * Usage: fork_probe vfork|fork|spawn|open|draws   (under LD_PRELOAD of libchaos-io)
 *
 * The parent opens /tmp/fork-data/file, starts a child that opens it too, then opens
 * it again, and prints which of the three opens failed with EIO:
 *
 *   parent=EIO child=ok parent=ok
 *
 * `open` only opens the file once and exits 1 on EIO; `spawn` runs the probe itself
 * in that mode. test_fork.sh compares the line and the hits files.
 *
 * `draws` opens 64 times in the parent and in a forked child under a rule with a
 * probability, and prints "same" when both saw the same failures, "different"
 * otherwise: a child must not repeat its parent's random numbers.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
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

/** @brief Waits for @p child; 1 when it reported a faulted open. */
static int child_failed(pid_t child)
{
    int status = 0;

    if (child <= 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status))
    {
        return -1;
    }
    return WEXITSTATUS(status) == 1;
}

static const char *word(int failed)
{
    return failed == 1 ? "EIO" : failed == 0 ? "ok" : "error";
}

/** @brief Opens the faulted file 64 times; which opens failed, as '0'/'1'. */
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
        (void)fprintf(stderr, "usage: %s vfork|fork|spawn|open|draws\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "open") == 0)
    {
        return open_fails();
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
        /* The child runs the wrapper in the parent's memory, as a JDK VFORK launch or
         * a shell's vfork does before exec. */
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
