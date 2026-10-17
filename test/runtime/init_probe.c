/**
 * @file init_probe.c
 * @brief The tracee test_init.sh starts under chaos-init in SECCOMP mode; each mode exercises
 *        one part of the process model chaos-init must keep transparent.
 *
 * @details
 * Usage: init_probe status|work|exit <n>|selfkill|term|orphans. Built -static, so it also
 * proves the mode for programs with no dynamic loader (LD_PRELOAD mode cannot reach them).
 *
 * - status:   prints /tmp/.chaos-init.status; exit 1 when it is missing or empty.
 * - work:     file write/pread, loopback TCP connect/accept/send/recv, mmap/munmap, fork +
 *             exec of itself; prints "work ok (0)" or "work failed (<step>)" and exits with
 *             the failing step number (1 file, 2 listen, 3 connect, 4 accept/send/recv,
 *             5 mmap, 6 fork/exec/wait).
 * - exit <n>: exits with n (exit-status pass-through).
 * - selfkill: raise(SIGKILL) (death-by-signal pass-through, shell status 137).
 * - term:     prints "ready", then exits 42 on SIGTERM (signal forwarding).
 * - orphans:  leaves a grandchild that outlives its parent by 200 ms, so chaos-init (PID 1 of
 *             the tracee tree) inherits it; prints "zombies=<n>" after waiting up to 5 s and
 *             exits 0 only when no zombie is left in the PID namespace.
 *
 * Exit: as listed per mode; 2 on bad usage.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/** @brief Sleeps @p ms milliseconds with nanosleep(); EINTR ends the sleep early. */
static void pause_ms(long ms)
{
    struct timespec delay = {ms / 1000L, (ms % 1000L) * 1000000L};

    (void)nanosleep(&delay, NULL);
}

/** @brief Exercises files, sockets, mmap, fork and exec; 0 or the failing step (1-6). */
static int work(void)
{
    char buffer[8] = {0};
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    int fd = open("/tmp/init-probe", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int listener;
    int client;
    int server;
    pid_t child;
    int status = 0;
    void *mapping;

    if (fd < 0 || write(fd, "data", 4) != 4 || pread(fd, buffer, 4, 0) != 4 || close(fd) != 0 ||
        strcmp(buffer, "data") != 0)
    {
        return 1;
    }
    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0)
    {
        return 2;
    }
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        return 3;
    }
    server = accept(listener, NULL, NULL);
    if (server < 0 || send(client, "ping", 4, 0) != 4 || recv(server, buffer, 4, 0) != 4)
    {
        return 4;
    }
    mapping = mmap(NULL, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || munmap(mapping, 4096U) != 0)
    {
        return 5;
    }
    child = fork();
    if (child == 0)
    {
        execl("/proc/self/exe", "init_probe", "exit", "0", (char *)NULL);
        _exit(9);
    }
    if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
    {
        return 6;
    }
    return 0;
}

/** @brief SIGTERM handler: exits 42 so the caller can tell forwarding from a default kill. */
static void on_term(int signal_number)
{
    (void)signal_number;
    _exit(42);
}

/** @brief Counts processes in state Z in /proc, i.e. zombies in this PID namespace. */
static int zombies(void)
{
    DIR *proc = opendir("/proc");
    struct dirent *entry;
    int count = 0;

    while (proc != NULL && (entry = readdir(proc)) != NULL)
    {
        char path[300];
        char line[256];
        FILE *stat;

        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
        {
            continue;
        }
        (void)snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        stat = fopen(path, "r");
        if (stat != NULL && fgets(line, sizeof(line), stat) != NULL)
        {
            const char *state = strrchr(line, ')');

            count += state != NULL && state[1] == ' ' && state[2] == 'Z';
        }
        if (stat != NULL)
        {
            (void)fclose(stat);
        }
    }
    if (proc != NULL)
    {
        (void)closedir(proc);
    }
    return count;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "status") == 0)
    {
        char text[512] = {0};
        int fd = open("/tmp/.chaos-init.status", O_RDONLY);

        if (fd < 0 || read(fd, text, sizeof(text) - 1U) <= 0)
        {
            return 1;
        }
        (void)fputs(text, stdout);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "work") == 0)
    {
        const int rc = work();

        (void)printf("work %s (%d)\n", rc == 0 ? "ok" : "failed", rc);
        return rc;
    }
    if (argc >= 3 && strcmp(argv[1], "exit") == 0)
    {
        return atoi(argv[2]);
    }
    if (argc >= 2 && strcmp(argv[1], "selfkill") == 0)
    {
        (void)raise(SIGKILL);
    }
    if (argc >= 2 && strcmp(argv[1], "term") == 0)
    {
        (void)signal(SIGTERM, on_term);
        (void)printf("ready\n");
        (void)fflush(stdout);
        for (;;)
        {
            pause_ms(1000L);
        }
    }
    if (argc >= 2 && strcmp(argv[1], "orphans") == 0)
    {
        pid_t child = fork();

        if (child == 0)
        {
            if (fork() == 0)
            {
                pause_ms(200L); /* outlives its parent: chaos-init inherits it */
                _exit(0);
            }
            _exit(0);
        }
        (void)waitpid(child, NULL, 0);
        /* The grandchild ends after 200 ms and chaos-init must reap it; on a loaded or emulated
         * machine that is not bounded, so poll for up to 50 x 100 ms = 5 s. */
        {
            int tries = 0;

            pause_ms(200L);
            while (zombies() != 0 && tries++ < 50)
            {
                pause_ms(100L);
            }
        }
        (void)printf("zombies=%d\n", zombies());
        return zombies() == 0 ? 0 : 1;
    }
    (void)fprintf(stderr, "usage: %s status|work|exit <n>|selfkill|term|orphans\n", argv[0]);
    return 2;
}
