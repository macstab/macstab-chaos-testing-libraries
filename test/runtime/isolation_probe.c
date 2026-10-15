/**
 * @file isolation_probe.c
 * @brief Runtime probe: one library's rules never change another library's effects.
 *
 * Each library implements LATENCY by sleeping. If that sleep went through the
 * exported usleep or nanosleep, libchaos-time would intercept it: a time rule
 * such as `usleep:ERRNO:EINTR` would end the delay at once, and `usleep:LATENCY`
 * would add to it. The probe loads libchaos-time with rules that fail every
 * sleep, sets a 300 ms LATENCY rule in the library under test, and checks the
 * call still takes the full 300 ms. Time is measured with the raw system call so
 * the measurement itself cannot be affected.
 *
 * Usage: isolation_probe io|net|dns|memory|process
 *        (under LD_PRELOAD of that library and libchaos-time, in either order)
 * Exit code 0 when the delay was intact, 1 otherwise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LATENCY_MS 300LL

/** Replaces a rule file atomically (new inode), as the framework's writers do. */
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

static void write_rules_now(const char *path, const char *rules)
{
    char staging[256];
    FILE *file;

    (void)snprintf(staging, sizeof(staging), "%s.staging", path);
    file = fopen(staging, "w");
    if (file == NULL || fputs(rules, file) < 0 || fclose(file) != 0 || rename(staging, path) != 0)
    {
        perror("write_rules");
        exit(2);
    }
}

/** @brief Writes the rules, then waits until the library looks at them. */
static void write_rules(const char *path, const char *rules)
{
    write_rules_now(path, rules);
    wait_for_rule_check();
}

static long long now_ms(void)
{
    struct timespec now;

    (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + (long long)now.tv_nsec / 1000000LL;
}

static void trigger_io(void)
{
    int fd = open("/tmp/isolation-probe.bin", O_CREAT | O_RDWR | O_TRUNC, 0600);

    write_rules("/tmp/.chaos-io.conf", "/tmp/isolation-probe.bin:fsync:LATENCY:300\n");
    if (fd < 0 || fsync(fd) != 0)
    {
        perror("io");
        exit(2);
    }
    (void)close(fd);
}

static void trigger_net(void)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    char rules[128];
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || client < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0 ||
        connect(client, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        perror("net setup");
        exit(2);
    }
    (void)snprintf(
        rules, sizeof(rules), "tcp4://127.0.0.1:%u:send:LATENCY:300\n", ntohs(address.sin_port)
    );
    write_rules("/tmp/.chaos-net.conf", rules);
    if (send(client, "x", 1U, 0) != 1)
    {
        perror("net");
        exit(2);
    }
}

static void trigger_dns(void)
{
    struct addrinfo *result = NULL;

    write_rules("/tmp/.chaos-dns.conf", "dns://localhost:LATENCY:300\n");
    (void)getaddrinfo("localhost", NULL, NULL, &result);
    if (result != NULL)
    {
        freeaddrinfo(result);
    }
}

static void trigger_memory(void)
{
    void *mapping = mmap(NULL, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    write_rules("/tmp/.chaos-memory.conf", "madvise:LATENCY:300\n");
    if (mapping == MAP_FAILED || madvise(mapping, 4096U, MADV_NORMAL) != 0)
    {
        perror("memory");
        exit(2);
    }
}

static void trigger_process(void)
{
    pid_t child = fork();
    int status;

    if (child == 0)
    {
        _exit(0);
    }
    write_rules("/tmp/.chaos-process.conf", "waitpid:LATENCY:300\n");
    if (child < 0 || waitpid(child, &status, 0) != child)
    {
        perror("process");
        exit(2);
    }
}

int main(int argc, char **argv)
{
    long long start;
    long long elapsed;

    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s io|net|dns|memory|process\n", argv[0]);
        return 2;
    }

    /* Every sleep that reaches libchaos-time fails at once. */
    write_rules("/tmp/.chaos-time.conf", "usleep:ERRNO:EINTR\nnanosleep:ERRNO:EINTR\n");

    start = now_ms();
    if (strcmp(argv[1], "io") == 0)
        trigger_io();
    else if (strcmp(argv[1], "net") == 0)
        trigger_net();
    else if (strcmp(argv[1], "dns") == 0)
        trigger_dns();
    else if (strcmp(argv[1], "memory") == 0)
        trigger_memory();
    else if (strcmp(argv[1], "process") == 0)
        trigger_process();
    else
        return 2;
    elapsed = now_ms() - start;

    (void)unlink("/tmp/.chaos-time.conf");
    if (elapsed < LATENCY_MS - 20LL)
    {
        (void)fprintf(
            stderr,
            "FAIL %s: LATENCY 300 ms took %lld ms with time rules loaded\n",
            argv[1],
            elapsed
        );
        return 1;
    }
    (void)printf("ok   %s: LATENCY 300 ms took %lld ms\n", argv[1], elapsed);
    return 0;
}
