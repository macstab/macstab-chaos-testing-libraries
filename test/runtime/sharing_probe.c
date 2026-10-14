/**
 * @file sharing_probe.c
 * @brief Runtime probe: libchaos-io and libchaos-net share read/write/close safely.
 *
 * Both libraries interpose read, write, readv, writev and close: io acts on files,
 * net on sockets, each forwarding everything else down the chain. This probe checks
 * that the right library's rules apply to the right descriptor whichever libraries
 * are preloaded and in whichever order, and checks the descriptor bookkeeping the
 * sharing depends on.
 *
 * Usage: sharing_probe <scenario>
 *   socket-rules     net rules fault socket read/write/readv/writev; files untouched
 *   file-rules       io rules fault file read/write/close; sockets untouched
 *   close-reset      a net close:RESET rule makes the peer see ECONNRESET
 *   close-errno      an injected close error is reported after a real close (io and net)
 *   cache-threads    a close on one thread invalidates the path another thread cached
 *   cache-dup2       dup2 onto a cached descriptor makes it match the new file
 *   no-rules         nothing changes without rules
 *
 * Scenarios that need a library check for its rule file being honoured and report
 * "skip" when that library is not preloaded, so every preload combination can run
 * every scenario. Exit code 0 on success, 1 on the first failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
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

/** Replaces a rule file atomically (new inode), as the framework's writers do. */
static void write_rules(const char *path, const char *rules)
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

static int preloaded(const char *name)
{
    const char *preload = getenv("LD_PRELOAD");

    return preload != NULL && strstr(preload, name) != NULL;
}

/** A connected loopback TCP pair: *client and *server, listening port in *port. */
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

static void wait_step(int step)
{
    (void)pthread_mutex_lock(&g_step_lock);
    while (g_step < step)
    {
        (void)pthread_cond_wait(&g_step_cond, &g_step_lock);
    }
    (void)pthread_mutex_unlock(&g_step_lock);
}

static void advance_step(int step)
{
    (void)pthread_mutex_lock(&g_step_lock);
    g_step = step;
    (void)pthread_cond_broadcast(&g_step_cond);
    (void)pthread_mutex_unlock(&g_step_lock);
}

/** Reads the shared descriptor twice: before and after the main thread swapped its file. */
static void *cache_reader(void *unused)
{
    char buffer[4];
    (void)unused;

    /* Caches the descriptor as DATA_DIR/a.bin; no rule covers that directory. */
    check(
        "reader thread: first read of a.bin is untouched", pread(g_shared_fd, buffer, 2U, 0) == 2
    );
    advance_step(1);
    wait_step(2);
    /* The number now refers to OTHER_DIR/b.bin, which the rule covers. */
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
    /* Close on this thread, reopen another file: the lowest free number comes back. */
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
