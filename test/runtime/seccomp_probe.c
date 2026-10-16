/**
 * @file seccomp_probe.c
 * @brief Runtime probe for test_seccomp.sh: a static program under chaos-init.
 *
 * Usage: seccomp_probe open <path>    prints "ok" or the errno name
 *        seccomp_probe openms <path>  prints how long the open took, in ms
 *        seccomp_probe first <path>   opens twice, then once in a forked child:
 *                                     "parent=<1st>,<2nd> child=<1st>"
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *try_open(const char *path)
{
    const int fd = open(path, O_RDONLY | O_CREAT, 0644);

    if (fd >= 0)
    {
        (void)close(fd);
        return "ok";
    }
    switch (errno)
    {
    case EIO:
        return "EIO";
    case EACCES:
        return "EACCES";
    default:
        return strerror(errno);
    }
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "open") == 0)
    {
        (void)printf("%s\n", try_open(argv[2]));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "openms") == 0)
    {
        struct timespec start;
        struct timespec end;

        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        (void)try_open(argv[2]);
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        (void)printf("%ld\n", (long)((end.tv_sec - start.tv_sec) * 1000L +
                                     (end.tv_nsec - start.tv_nsec) / 1000000L));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "first") == 0)
    {
        char child_result[32] = "";
        int pipe_fds[2];
        const char *first = try_open(argv[2]);
        const char *second = try_open(argv[2]);
        pid_t child;

        if (pipe(pipe_fds) != 0)
        {
            return 1;
        }
        child = fork();
        if (child == 0)
        {
            const char *result = try_open(argv[2]);

            (void)write(pipe_fds[1], result, strlen(result));
            _exit(0);
        }
        (void)close(pipe_fds[1]);
        (void)waitpid(child, NULL, 0);
        (void)read(pipe_fds[0], child_result, sizeof(child_result) - 1U);
        (void)printf("parent=%s,%s child=%s\n", first, second, child_result);
        return 0;
    }
    (void)fprintf(stderr, "usage: %s open|openms|first <path>\n", argv[0]);
    return 2;
}
