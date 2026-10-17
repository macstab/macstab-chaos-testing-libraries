/**
 * @file sharing_probe.c
 * @brief Proves that libchaos-io and libchaos-net share read/write/readv/writev/close safely in
 *        any preload order.
 *
 * @details
 * Both libraries wrap read, write, readv, writev and close: libchaos-io acts on files,
 * libchaos-net on sockets, and each forwards every other descriptor to the next definition in
 * the chain. A wrong classification would fault a file with a network rule (or the reverse),
 * or swallow the call. The probe also checks the descriptor bookkeeping the sharing relies on:
 * libchaos-io's fd-to-path cache must follow close, fd reuse and dup2 across threads.
 *
 * Usage: sharing_probe <scenario>
 * - socket-rules   net recv/send rules fault read/readv/write/writev on a socket, a file is
 *                  untouched, and the socket works again once the rule file is removed.
 * - file-rules     io read/write rules fault a file; a socket is untouched.
 * - close-reset    net close:RESET: close() succeeds and the peer reads ECONNRESET, not EOF.
 * - close-errno    an injected close error (net EINTR, io EIO) is returned only after the
 *                  descriptor was really closed (F_GETFD then fails with EBADF), as Linux
 *                  close(2) semantics require: retrying close must never hit a reused fd.
 * - cache-threads  a close on one thread and reuse of the fd number for another file make a
 *                  second thread's next pread match the new file's rule.
 * - cache-dup2     dup2() onto a cached descriptor makes it match the new file's rule.
 * - no-rules       without rule files, file and socket I/O and close behave normally and the
 *                  peer sees an orderly end of stream.
 *
 * A scenario that needs a library not named in LD_PRELOAD prints "skip" and passes, so every
 * preload combination can run every scenario. Run by test_sharing_glibc.sh under io, net,
 * "io net" and "net io".
 *
 * Exit: 0 when every check of the scenario passed (or it skipped); 1 when any check failed
 * (all run; each prints ok/FAIL); 2 on bad usage or a setup failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define DATA_DIR "/tmp/sharing-probe-data"
#define OTHER_DIR "/tmp/sharing-probe-other"
#define NET_CONF "/tmp/.chaos-net.conf"
#define IO_CONF "/tmp/.chaos-io.conf"

static int g_failures = 0;

/** @brief Prints ok, or FAIL with errno and records a failure. */
static void check(const char *what, int ok)
{
    if (!ok)
    {
        (void)fprintf(stderr, "FAIL %s (errno %d: %s)\n", what, errno, strerror(errno));
        g_failures++;
        return;
    }
    (void)printf("ok   %s\n", what);
}

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

/** @brief Non-zero when LD_PRELOAD contains @p name. */
static int preloaded(const char *name)
{
    const char *preload = getenv("LD_PRELOAD");

    return preload != NULL && strstr(preload, name) != NULL;
}

/** @brief Connected loopback TCP pair on an ephemeral port; exits 2 on failure. */
static void tcp_pair(int *client, int *server, unsigned int *port)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0)
    {
        perror("listen");
        exit(2);
    }
    *client = socket(AF_INET, SOCK_STREAM, 0);
    if (*client < 0 || connect(*client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        (*server = accept(listener, NULL, NULL)) < 0)
    {
        perror("connect");
        exit(2);
    }
    *port = ntohs(address.sin_port);
    (void)close(listener);
}

/**
 * @brief Creates @p dir (0700) and @p dir/@p name holding "abcdefgh", offset rewound to 0;
 *        exits 2 on failure.
 */
static int open_data_file(const char *dir, const char *name)
{
    char path[256];
    int fd;

    (void)mkdir(dir, 0700);
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "abcdefgh", 8U) != 8 || lseek(fd, 0, SEEK_SET) != 0)
    {
        perror("open data file");
        exit(2);
    }
    return fd;
}

static void scenario_socket_rules(void)
{
    char rules[256];
    char buffer[8];
    struct iovec iov;
    unsigned int port;
    int client;
    int server;
    int file;

    if (!preloaded("libchaos-net"))
    {
        (void)printf("skip socket-rules (libchaos-net not preloaded)\n");
        return;
    }
    tcp_pair(&client, &server, &port);
    file = open_data_file(DATA_DIR, "plain.bin");
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.1:%u:recv:ECONNRESET:1.0\ntcp4://127.0.0.1:%u:send:EPIPE:1.0\n",
        port,
        port
    );
    write_rules(NET_CONF, rules);
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    errno = 0;
    check(
        "read on a socket gets the net recv error",
        read(server, buffer, 4U) == -1 && errno == ECONNRESET
    );
    errno = 0;
    check(
        "readv on a socket gets the net recv error",
        readv(server, &iov, 1) == -1 && errno == ECONNRESET
    );
    errno = 0;
    check(
        "write on a socket gets the net send error",
        write(client, "ping", 4U) == -1 && errno == EPIPE
    );
    errno = 0;
    check(
        "writev on a socket gets the net send error",
        writev(client, &iov, 1) == -1 && errno == EPIPE
    );
    check("a file is untouched by net rules", read(file, buffer, 4U) == 4);

    (void)unlink(NET_CONF);
    wait_for_rule_check();
    check("the socket works again once the rules are gone", write(client, "ping", 4U) == 4);
    check("and reads", read(server, buffer, 4U) == 4);
    (void)close(file);
    (void)close(client);
    (void)close(server);
}

static void scenario_file_rules(void)
{
    char buffer[8];
    unsigned int port;
    int client;
    int server;
    int file;

    if (!preloaded("libchaos-io"))
    {
        (void)printf("skip file-rules (libchaos-io not preloaded)\n");
        return;
    }
    tcp_pair(&client, &server, &port);
    file = open_data_file(DATA_DIR, "faulted.bin");
    write_rules(IO_CONF, DATA_DIR ":read:EIO:1.0\n" DATA_DIR ":write:ENOSPC:1.0\n");

    errno = 0;
    check("read on a file gets the io error", read(file, buffer, 4U) == -1 && errno == EIO);
    errno = 0;
    check("write on a file gets the io error", write(file, "zz", 2U) == -1 && errno == ENOSPC);
    check("a socket is untouched by io rules (write)", write(client, "ping", 4U) == 4);
    check("a socket is untouched by io rules (read)", read(server, buffer, 4U) == 4);

    (void)unlink(IO_CONF);
    (void)close(file);
    (void)close(client);
    (void)close(server);
}

static void scenario_close_reset(void)
{
    char rules[128];
    char buffer[8];
    unsigned int port;
    int client;
    int server;
    ssize_t rc;

    if (!preloaded("libchaos-net"))
    {
        (void)printf("skip close-reset (libchaos-net not preloaded)\n");
        return;
    }
    tcp_pair(&client, &server, &port);
    (void)snprintf(rules, sizeof(rules), "tcp4://127.0.0.1:%u:close:RESET:1.0\n", port);
    write_rules(NET_CONF, rules);
    check("close with a RESET rule succeeds", close(server) == 0);
    (void)unlink(NET_CONF);

    errno = 0;
    rc = read(client, buffer, sizeof(buffer));
    check("the peer sees a reset, not an end of stream", rc == -1 && errno == ECONNRESET);
    (void)close(client);
}

static void scenario_close_errno(void)
{
    char rules[128];
    unsigned int port;
    int client;
    int server;
    int file;

    if (preloaded("libchaos-net"))
    {
        tcp_pair(&client, &server, &port);
        (void)snprintf(rules, sizeof(rules), "tcp4://127.0.0.1:%u:close:EINTR:1.0\n", port);
        write_rules(NET_CONF, rules);
        errno = 0;
        check("socket close reports the injected error", close(server) == -1 && errno == EINTR);
        errno = 0;
        check("and the socket is really closed", fcntl(server, F_GETFD) == -1 && errno == EBADF);
        (void)unlink(NET_CONF);
        (void)close(client);
    }
    if (preloaded("libchaos-io"))
    {
        file = open_data_file(DATA_DIR, "close.bin");
        write_rules(IO_CONF, DATA_DIR ":close:EIO:1.0\n");
        errno = 0;
        check("file close reports the injected error", close(file) == -1 && errno == EIO);
        errno = 0;
        check("and the file is really closed", fcntl(file, F_GETFD) == -1 && errno == EBADF);
        (void)unlink(IO_CONF);
    }
}

static int g_shared_fd = -1;
static pthread_mutex_t g_step_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_step_cond = PTHREAD_COND_INITIALIZER;
static int g_step = 0;

/** @brief Blocks until the shared step counter reaches @p step (orders the two threads). */
static void wait_step(int step)
{
    (void)pthread_mutex_lock(&g_step_lock);
    while (g_step < step)
    {
        (void)pthread_cond_wait(&g_step_cond, &g_step_lock);
    }
    (void)pthread_mutex_unlock(&g_step_lock);
}

/** @brief Sets the shared step counter to @p step and wakes the waiter. */
static void advance_step(int step)
{
    (void)pthread_mutex_lock(&g_step_lock);
    g_step = step;
    (void)pthread_cond_broadcast(&g_step_cond);
    (void)pthread_mutex_unlock(&g_step_lock);
}

/**
 * @brief Reader thread: preads the shared descriptor before and after the main thread closed
 *        it and reused the number for a file under a rule.
 */
static void *cache_reader(void *unused)
{
    char buffer[4];
    (void)unused;

    /* This pread makes libchaos-io cache the fd as DATA_DIR/a.bin, which no rule covers. */
    check(
        "reader thread: first read of a.bin is untouched", pread(g_shared_fd, buffer, 2U, 0) == 2
    );
    advance_step(1);
    wait_step(2);
    /* The number now names OTHER_DIR/b.bin; a stale cache entry would let this pass. */
    errno = 0;
    check(
        "reader thread: the reused descriptor matches the new file's rule",
        pread(g_shared_fd, buffer, 2U, 0) == -1 && errno == EIO
    );
    return NULL;
}

static void scenario_cache_threads(void)
{
    pthread_t reader;
    int number;
    int reopened;

    if (!preloaded("libchaos-io"))
    {
        (void)printf("skip cache-threads (libchaos-io not preloaded)\n");
        return;
    }
    write_rules(IO_CONF, OTHER_DIR ":pread:EIO:1.0\n");
    g_shared_fd = open_data_file(DATA_DIR, "a.bin");
    number = g_shared_fd;
    (void)pthread_create(&reader, NULL, cache_reader, NULL);
    wait_step(1);
    /* POSIX open() returns the lowest free number, so the reopen reuses the closed fd. */
    (void)close(g_shared_fd);
    reopened = open_data_file(OTHER_DIR, "b.bin");
    check("the descriptor number was reused", reopened == number);
    advance_step(2);
    (void)pthread_join(reader, NULL);
    (void)close(reopened);
    (void)unlink(IO_CONF);
}

static void scenario_cache_dup2(void)
{
    char buffer[4];
    int target;
    int source;

    if (!preloaded("libchaos-io"))
    {
        (void)printf("skip cache-dup2 (libchaos-io not preloaded)\n");
        return;
    }
    write_rules(IO_CONF, OTHER_DIR ":pread:EIO:1.0\n");
    target = open_data_file(DATA_DIR, "target.bin");
    source = open_data_file(OTHER_DIR, "source.bin");
    check("before dup2 the target is untouched", pread(target, buffer, 2U, 0) == 2);
    check("dup2 succeeds", dup2(source, target) == target);
    errno = 0;
    check(
        "after dup2 the target matches the new file's rule",
        pread(target, buffer, 2U, 0) == -1 && errno == EIO
    );
    (void)close(target);
    (void)close(source);
    (void)unlink(IO_CONF);
}

static void scenario_no_rules(void)
{
    char buffer[8];
    unsigned int port;
    int client;
    int server;
    int file;

    (void)unlink(NET_CONF);
    (void)unlink(IO_CONF);
    wait_for_rule_check();
    tcp_pair(&client, &server, &port);
    file = open_data_file(DATA_DIR, "plain.bin");
    check("socket write without rules", write(client, "ping", 4U) == 4);
    check("socket read without rules", read(server, buffer, 4U) == 4);
    check("file read without rules", read(file, buffer, 4U) == 4);
    check("file close without rules", close(file) == 0);
    check("socket close without rules", close(server) == 0);
    errno = 0;
    check("the peer sees an orderly end of stream", read(client, buffer, sizeof(buffer)) == 0);
    (void)close(client);
}

int main(int argc, char **argv)
{
    static const struct
    {
        const char *name;
        void (*run)(void);
    } scenarios[] = {
        {"socket-rules", scenario_socket_rules},
        {"file-rules", scenario_file_rules},
        {"close-reset", scenario_close_reset},
        {"close-errno", scenario_close_errno},
        {"cache-threads", scenario_cache_threads},
        {"cache-dup2", scenario_cache_dup2},
        {"no-rules", scenario_no_rules},
    };
    size_t index;

    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s <scenario>\n", argv[0]);
        return 2;
    }
    for (index = 0U; index < sizeof(scenarios) / sizeof(scenarios[0]); ++index)
    {
        if (strcmp(argv[1], scenarios[index].name) == 0)
        {
            scenarios[index].run();
            return g_failures == 0 ? 0 : 1;
        }
    }
    return 2;
}
