/**
 * @file hits_probe.c
 * @brief Calls the faulted operation of one library's test rule a fixed number of times so
 *        test_hits.sh can check the hits files the library writes.
 *
 * @details
 * Usage, under LD_PRELOAD of the named library:
 * - hits_probe io|net|dns|time|memory|process: two calls of the library's operation
 *   (open of /tmp/hits-data/file, connect to 127.0.0.1:9, getaddrinfo("api.example.com"),
 *   a 1 us nanosleep, a 4096-byte anonymous mmap, fork + waitpid). Results are ignored.
 * - hits_probe burst (libchaos-io): 100 faulted opens, a 200 ms sleep (past
 *   CHAOS_HITS_INTERVAL_MS, 100 ms), one unmatched open so a rule-file check runs, then
 *   prints the sum of its own `/tmp/.chaos-io.hits.<pid>` file. The first 64 hits are
 *   written eagerly; 100 proves the interval write happened while the process still runs,
 *   not only at exit.
 * - hits_probe exec (libchaos-io): 3 faulted opens, then execs itself as `hits_probe io`
 *   (2 more) under the same pid; the old image's hits file must survive beside the new one.
 *
 * Exit: 0; 1 when the exec fails; 2 on bad usage.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/** @brief One call of @p lib's test operation; the outcome is ignored. */
static void call_once(const char *lib)
{
    if (strcmp(lib, "io") == 0)
    {
        const int fd = open("/tmp/hits-data/file", O_RDONLY);

        if (fd >= 0)
        {
            (void)close(fd);
        }
    }
    else if (strcmp(lib, "net") == 0)
    {
        struct sockaddr_in address;
        const int fd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(9);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        (void)connect(fd, (struct sockaddr *)&address, sizeof(address));
        (void)close(fd);
    }
    else if (strcmp(lib, "dns") == 0)
    {
        struct addrinfo *result = NULL;

        if (getaddrinfo("api.example.com", NULL, NULL, &result) == 0)
        {
            freeaddrinfo(result);
        }
    }
    else if (strcmp(lib, "time") == 0)
    {
        struct timespec delay = {0, 1000L};

        (void)nanosleep(&delay, NULL);
    }
    else if (strcmp(lib, "memory") == 0)
    {
        void *mapping =
            mmap(NULL, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (mapping != MAP_FAILED)
        {
            (void)munmap(mapping, 4096U);
        }
    }
    else if (strcmp(lib, "process") == 0)
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
    }
}

/** @brief Burst mode: prints the hits this process's own hits file reports while it runs. */
static int burst(void)
{
    const struct timespec past_interval = {0, 200000000L};
    char path[64];
    char line[512];
    unsigned long total = 0UL;
    FILE *hits;
    int index;

    for (index = 0; index < 100; ++index)
    {
        call_once("io");
    }
    (void)nanosleep(&past_interval, NULL);
    index = open("/tmp/elsewhere-unmatched", O_RDONLY);
    if (index >= 0)
    {
        (void)close(index);
    }
    (void)snprintf(path, sizeof(path), "/tmp/.chaos-io.hits.%ld", (long)getpid());
    hits = fopen(path, "r");
    while (hits != NULL && fgets(line, sizeof(line), hits) != NULL)
    {
        total += strtoul(line, NULL, 10);
    }
    if (hits != NULL)
    {
        (void)fclose(hits);
    }
    (void)printf("%lu\n", total);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s io|net|dns|time|memory|process\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "burst") == 0)
    {
        return burst();
    }
    if (strcmp(argv[1], "exec") == 0)
    {
        call_once("io");
        call_once("io");
        call_once("io");
        (void)execl("/proc/self/exe", argv[0], "io", (char *)NULL);
        return 1;
    }
    call_once(argv[1]);
    call_once(argv[1]);
    return 0;
}
