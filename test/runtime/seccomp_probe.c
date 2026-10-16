/**
 * @file seccomp_probe.c
 * @brief Runtime probe for test_seccomp.sh: a static program under chaos-init.
 *
 * Usage: seccomp_probe open <path>    prints "ok" or the errno name
 *        seccomp_probe openms <path>  prints how long the open took, in ms
 *        seccomp_probe signalled <path> the same, with a SIGALRM (SA_RESTART)
 *                                     every 20 ms interrupting the open
 *        seccomp_probe first <path>   opens twice, then once in a forked child:
 *                                     "parent=<1st>,<2nd> child=<1st>"
 *        seccomp_probe connect <port> listens on 127.0.0.1:<port>, connects to it:
 *                                     "ok" or the errno name
 *        seccomp_probe mmap <bytes>   maps that many anonymous bytes
 *        seccomp_probe waits <port>   a readable socket waited on by select and poll
 *                                     with 200 ms, and by select without a timeout:
 *                                     "select=<rc>,<set>,<ms> poll=<rc>,<revents>
 *                                     forever=<rc>"
 *        seccomp_probe orphan <path> <out> exits 3 at once, leaving a child that
 *                                     opens <path> 300 ms later and writes the
 *                                     result ("ok" or the errno name) to <out>
 *        seccomp_probe fork           forks a child that exits at once
 *        seccomp_probe exec           executes /bin/true (prints only on failure)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *try_open_errno_name(int error)
{
    switch (error)
    {
    case EIO:
        return "EIO";
    case EACCES:
        return "EACCES";
    case ECONNREFUSED:
        return "ECONNREFUSED";
    case ENOMEM:
        return "ENOMEM";
    default:
        return strerror(error);
    }
}

static const char *try_open(const char *path)
{
    const int fd = open(path, O_RDONLY | O_CREAT, 0644);

    if (fd >= 0)
    {
        (void)close(fd);
        return "ok";
    }
    return try_open_errno_name(errno);
}

static void on_alarm(int signal_number)
{
    (void)signal_number;
}

/** @brief Prints how long opening @p path takes, in ms. */
static void print_open_ms(const char *path)
{
    struct timespec start;
    struct timespec end;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);
    (void)try_open(path);
    (void)clock_gettime(CLOCK_MONOTONIC, &end);
    (void)printf(
        "%ld\n",
        (long)((end.tv_sec - start.tv_sec) * 1000L + (end.tv_nsec - start.tv_nsec) / 1000000L)
    );
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
        print_open_ms(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "signalled") == 0)
    {
        struct sigaction action;
        struct itimerval every = {{0, 20000}, {0, 20000}};

        memset(&action, 0, sizeof(action));
        action.sa_handler = on_alarm;
        action.sa_flags = SA_RESTART;
        if (sigaction(SIGALRM, &action, NULL) != 0 || setitimer(ITIMER_REAL, &every, NULL) != 0)
        {
            return 1;
        }
        print_open_ms(argv[2]);
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
    if (argc == 4 && strcmp(argv[1], "orphan") == 0)
    {
        const pid_t child = fork();

        if (child == 0)
        {
            const struct timespec wait = {0, 300000000L};
            const char *result;
            int out;

            (void)nanosleep(&wait, NULL);
            result = try_open(argv[2]);
            out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out >= 0)
            {
                (void)write(out, result, strlen(result));
                (void)close(out);
            }
            _exit(0);
        }
        return child > 0 ? 3 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "waits") == 0)
    {
        struct sockaddr_in address;
        struct timespec start;
        struct timespec end;
        struct timeval wait = {0, 200000};
        struct pollfd polled;
        fd_set readable;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        int selected;
        int polled_rc;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0 || write(client, "x", 1U) != 1)
        {
            return 1;
        }
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        selected = select(server + 1, &readable, NULL, NULL, &wait);
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        polled.fd = server;
        polled.events = POLLIN;
        polled.revents = POLLIN;
        polled_rc = poll(&polled, 1U, 200);
        (void)printf(
            "select=%d,%d,%s poll=%d,%d ",
            selected,
            FD_ISSET(server, &readable) ? 1 : 0,
            (end.tv_sec - start.tv_sec) * 1000L + (end.tv_nsec - start.tv_nsec) / 1000000L >= 150L
                ? "waited"
                : "early",
            polled_rc,
            (int)polled.revents
        );
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        (void)printf("forever=%d\n", select(server + 1, &readable, NULL, NULL, NULL));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "connect") == 0)
    {
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0)
        {
            return 1;
        }
        (void)printf(
            "%s\n",
            connect(client, (struct sockaddr *)&address, sizeof(address)) == 0
                ? "ok"
                : try_open_errno_name(errno)
        );
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "mmap") == 0)
    {
        const size_t length = (size_t)strtoul(argv[2], NULL, 10);
        void *mapping =
            mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        (void)printf("%s\n", mapping != MAP_FAILED ? "ok" : try_open_errno_name(errno));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "fork") == 0)
    {
        const pid_t child = fork();

        if (child == 0)
        {
            _exit(0);
        }
        if (child > 0)
        {
            (void)waitpid(child, NULL, 0);
        }
        (void)printf("%s\n", child > 0 ? "ok" : try_open_errno_name(errno));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "exec") == 0)
    {
        (void)execl("/bin/true", "true", (char *)NULL);
        (void)printf("%s\n", try_open_errno_name(errno));
        return 0;
    }
    (void)fprintf(
        stderr,
        "usage: %s open|openms|first <path> | connect <port> | mmap <bytes> | "
        "fork | exec\n",
        argv[0]
    );
    return 2;
}
