/**
 * @file isolation_probe.c
 * @brief Proves that one library's rules never alter another library's effects or its access to
 *        its own rule file.
 *
 * @details
 * Default mode (`<lib>`): every library implements LATENCY with chaos_sleep_ms(), a raw
 * clock_nanosleep system call. Had it gone through the exported usleep/nanosleep, libchaos-time
 * would intercept it: `usleep:ERRNO:EINTR` would end the delay at once and `usleep:LATENCY`
 * would stretch it. The probe loads libchaos-time rules that fail every usleep and nanosleep
 * with EINTR, triggers a 300 ms LATENCY rule in the library under test, and requires the call
 * to take >= 280 ms. Elapsed time comes from a raw clock_gettime system call, so no rule can
 * skew the measurement.
 *
 * Control mode (`control:<lib>`): libchaos-io fails every open (EACCES), read, write and
 * rename target (EIO) under /tmp. The rule files `/tmp/.chaos-*` are exempt from libchaos-io's
 * rules, so the probe can still write the other library's rules and that library can still
 * read them; the 300 ms LATENCY firing proves it.
 *
 * Triggers (each a 300 ms LATENCY rule): io fsync, net send, dns getaddrinfo("localhost"),
 * memory madvise, process waitpid.
 *
 * Usage: isolation_probe [control:]io|net|dns|memory|process, under LD_PRELOAD of that library
 * plus libchaos-time (or libchaos-io in control mode), in either order; run by
 * test_isolation_glibc.sh.
 *
 * Exit: 0 when the delay lasted >= 280 ms; 1 when it was shorter; 2 on bad usage or a setup
 * failure.
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
 * @brief Replaces the rule file at @p path atomically: writes `<path>.staging`, then
 *        rename()s it over @p path.
 *
 * The rename gives the file a new inode, which changes the reload change stamp regardless of
 * mtime granularity, and a library never reads a half-written file. This is how the framework's
 * own writers update rule files. Exits the probe with status 2 on any I/O error.
 */
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

/** @brief write_rules_now(), then wait_for_rule_check(). */
static void write_rules(const char *path, const char *rules)
{
    write_rules_now(path, rules);
    wait_for_rule_check();
}

/** @brief CLOCK_MONOTONIC in ms via a raw system call, immune to libchaos-time rules. */
static long long now_ms(void)
{
    struct timespec now;

    (void)syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + (long long)now.tv_nsec / 1000000LL;
}

/** @brief io: fsync under LATENCY:300 on the file. Exits 2 when the call fails. */
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

/** @brief net: send on a loopback connection under send:LATENCY:300. Exits 2 on failure. */
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

/** @brief dns: getaddrinfo("localhost") under LATENCY:300; its result is not checked. */
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

/** @brief memory: madvise under madvise:LATENCY:300. Exits 2 on failure. */
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

/** @brief process: waitpid on an exited child under waitpid:LATENCY:300. Exits 2 on failure. */
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
    const char *other_rules = "/tmp/.chaos-time.conf";
    const char *lib;
    long long start;
    long long elapsed;

    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s [control:]io|net|dns|memory|process\n", argv[0]);
        return 2;
    }

    lib = argv[1];
    if (strncmp(lib, "control:", 8U) == 0)
    {
        /* Every file access under /tmp fails; the rule files /tmp/.chaos-* are exempt. */
        lib += 8;
        other_rules = "/tmp/.chaos-io.conf";
        write_rules(
            other_rules,
            "/tmp:open:EACCES:1.0\n/tmp:read:EIO:1.0\n/tmp:write:EIO:1.0\n"
            "/tmp:rename_to:EIO:1.0\n"
        );
    }
    else
    {
        /* Any sleep that goes through libchaos-time returns EINTR at once. */
        write_rules(other_rules, "usleep:ERRNO:EINTR\nnanosleep:ERRNO:EINTR\n");
    }

    start = now_ms();
    if (strcmp(lib, "io") == 0)
        trigger_io();
    else if (strcmp(lib, "net") == 0)
        trigger_net();
    else if (strcmp(lib, "dns") == 0)
        trigger_dns();
    else if (strcmp(lib, "memory") == 0)
        trigger_memory();
    else if (strcmp(lib, "process") == 0)
        trigger_process();
    else
        return 2;
    elapsed = now_ms() - start;

    (void)unlink(other_rules);
    if (elapsed < LATENCY_MS - 20LL)
    {
        (void)fprintf(
            stderr,
            "FAIL %s: LATENCY 300 ms took %lld ms with the other library's rules loaded\n",
            argv[1],
            elapsed
        );
        return 1;
    }
    (void)printf("ok   %s: LATENCY 300 ms took %lld ms\n", argv[1], elapsed);
    return 0;
}
