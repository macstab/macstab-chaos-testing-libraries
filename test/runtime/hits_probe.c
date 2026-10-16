/**
 * @file hits_probe.c
 * @brief Runtime probe: calls the operation of one library's test rule twice.
 *
 * Usage: hits_probe io|net|dns|time|memory|process   (under LD_PRELOAD of that library)
 *        hits_probe burst   (libchaos-io) opens the faulted file 100 times, waits
 *                           past the hits interval, makes one unrelated call and
 *                           prints the hits its own file reports while it runs
 *
 * Results are ignored; test_hits.sh checks the hits files the library wrote.
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

/** @brief The burst mode: the hits this process's file reports while it still runs. */
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
    call_once(argv[1]);
    call_once(argv[1]);
    return 0;
}
