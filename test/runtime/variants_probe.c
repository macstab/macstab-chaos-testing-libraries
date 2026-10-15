/**
 * @file variants_probe.c
 * @brief Runtime probe: glibc's alternate entry points are faulted like the base calls.
 *
 * On 64-bit glibc the large-file names (`open64`, `pread64`, `mmap64`, ...) are
 * separate symbols, and `_FORTIFY_SOURCE` builds call `__read_chk`, `__open_2`,
 * `__recv_chk` and friends instead of the base functions. Programs bind to whichever
 * name their build chose, so each must be intercepted on its own. Every call below
 * runs under a rule that fails its operation and must report the injected errno.
 *
 * Usage: variants_probe io|memory|net   (under LD_PRELOAD of the matching library)
 * Exit code 0 when every variant was faulted, 1 otherwise.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

/* Fortified entry points; glibc declares them only for _FORTIFY_SOURCE builds. */
extern ssize_t __read_chk(int fd, void *buffer, size_t count, size_t buffer_size);
extern ssize_t __pread_chk(int fd, void *buffer, size_t count, off_t offset, size_t buffer_size);
extern ssize_t __pread64_chk(int fd, void *buffer, size_t count, off_t offset, size_t buffer_size);
extern int __open_2(const char *path, int flags);
extern int __open64_2(const char *path, int flags);
extern int __openat_2(int dirfd, const char *path, int flags);
extern int __openat64_2(int dirfd, const char *path, int flags);
extern ssize_t __recv_chk(int fd, void *buffer, size_t size, size_t buffer_size, int flags);
extern int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fds_size);
extern int __ppoll_chk(
    struct pollfd *fds,
    nfds_t nfds,
    const struct timespec *timeout,
    const sigset_t *mask,
    size_t fds_size
);
extern ssize_t __recvfrom_chk(
    int fd,
    void *buffer,
    size_t size,
    size_t buffer_size,
    int flags,
    struct sockaddr *address,
    socklen_t *address_length
);

#define DATA_DIR "/tmp/variants-probe-data"
#define DATA_FILE DATA_DIR "/data.bin"

static int g_failures = 0;

static void expect_fault(const char *what, long rc, int expected_errno)
{
    if (rc != -1 || errno != expected_errno)
    {
        (void)fprintf(
            stderr, "FAIL %s: rc=%ld errno=%d, expected -1 / %d\n", what, rc, errno, expected_errno
        );
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

static void probe_io(void)
{
    const char *conf = "/tmp/.chaos-io.conf";
    struct iovec iov;
    char buffer[8];
    int fd;
    int other;

    (void)mkdir(DATA_DIR, 0700);
    write_rules(conf, "# idle\n");
    fd = open(DATA_FILE, O_CREAT | O_RDWR | O_TRUNC, 0600);
    other = open("/tmp/variants-probe-source.bin", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0 || other < 0 || write(fd, "abcdefgh", 8U) != 8 || write(other, "xyz", 3U) != 3)
    {
        perror("setup");
        exit(2);
    }
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    write_rules(conf, DATA_DIR ":open:EIO:1.0\n");
    expect_fault("open64", open64(DATA_FILE, O_RDONLY), EIO);
    expect_fault("openat64", openat64(AT_FDCWD, DATA_FILE, O_RDONLY), EIO);
    expect_fault("__open_2", __open_2(DATA_FILE, O_RDONLY), EIO);
    expect_fault("__open64_2", __open64_2(DATA_FILE, O_RDONLY), EIO);
    expect_fault("__openat_2", __openat_2(AT_FDCWD, DATA_FILE, O_RDONLY), EIO);
    expect_fault("__openat64_2", __openat64_2(AT_FDCWD, DATA_FILE, O_RDONLY), EIO);

    write_rules(conf, DATA_DIR ":read:EIO:1.0\n");
    expect_fault("__read_chk", __read_chk(fd, buffer, 4U, sizeof(buffer)), EIO);

    write_rules(conf, DATA_DIR ":pread:EIO:1.0\n");
    expect_fault("pread64", pread64(fd, buffer, 4U, 0), EIO);
    expect_fault("preadv64", preadv64(fd, &iov, 1, 0), EIO);
    expect_fault("__pread_chk", __pread_chk(fd, buffer, 4U, 0, sizeof(buffer)), EIO);
    expect_fault("__pread64_chk", __pread64_chk(fd, buffer, 4U, 0, sizeof(buffer)), EIO);

    write_rules(conf, DATA_DIR ":pwrite:EIO:1.0\n");
    expect_fault("pwrite64", pwrite64(fd, "zz", 2U, 0), EIO);
    expect_fault("pwritev64", pwritev64(fd, &iov, 1, 0), EIO);

    write_rules(conf, DATA_DIR ":truncate:EIO:1.0\n");
    expect_fault("ftruncate64", ftruncate64(fd, 4), EIO);

    write_rules(conf, DATA_DIR ":allocate:EIO:1.0\n");
    expect_fault("fallocate64", fallocate64(fd, 0, 0, 4096), EIO);

    write_rules(conf, DATA_DIR ":write:EIO:1.0\n");
    expect_fault("sendfile64", sendfile64(fd, other, NULL, 3U), EIO);

    (void)unlink(conf);
    (void)close(fd);
    (void)close(other);
    (void)unlink(DATA_FILE);
    (void)unlink("/tmp/variants-probe-source.bin");
}

static void probe_memory(void)
{
    void *mapping;

    write_rules("/tmp/.chaos-memory.conf", "mmap/anon:ERRNO:ENOMEM\n");
    mapping = mmap64(NULL, 1U << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    expect_fault("mmap64", mapping == MAP_FAILED ? -1L : 0L, ENOMEM);
    (void)unlink("/tmp/.chaos-memory.conf");
}

static void probe_net(void)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    char rules[128];
    char buffer[8];
    int listener;
    int client;
    int server;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0)
    {
        perror("setup");
        exit(2);
    }
    client = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        (server = accept(listener, NULL, NULL)) < 0 || send(client, "ping", 4U, 0) != 4)
    {
        perror("connect");
        exit(2);
    }

    (void)snprintf(
        rules, sizeof(rules), "tcp4://127.0.0.1:%u:recv:ECONNRESET:1.0\n", ntohs(address.sin_port)
    );
    write_rules("/tmp/.chaos-net.conf", rules);
    expect_fault("__recv_chk", __recv_chk(server, buffer, 4U, sizeof(buffer), 0), ECONNRESET);
    expect_fault(
        "__recvfrom_chk",
        __recvfrom_chk(server, buffer, 4U, sizeof(buffer), 0, NULL, NULL),
        ECONNRESET
    );
    /* A fortified read on a socket reaches libchaos-net even without libchaos-io. */
    expect_fault("__read_chk (socket)", __read_chk(server, buffer, 4U, sizeof(buffer)), ECONNRESET);

    /* Data is pending, so only an injected TIMEOUT makes the fortified polls return 0. */
    (void)snprintf(
        rules, sizeof(rules), "tcp4://127.0.0.1:%u:poll:TIMEOUT:1.0\n", ntohs(address.sin_port)
    );
    write_rules("/tmp/.chaos-net.conf", rules);
    {
        struct pollfd pfd;
        struct timespec timeout = {1, 0L};

        if (send(client, "pong", 4U, 0) != 4)
        {
            perror("send");
            exit(2);
        }
        pfd.fd = server;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (__poll_chk(&pfd, 1U, 1000, sizeof(pfd)) == 0)
            (void)printf("ok   __poll_chk\n");
        else
        {
            (void)fprintf(stderr, "FAIL __poll_chk: not timed out\n");
            g_failures++;
        }
        pfd.revents = 0;
        if (__ppoll_chk(&pfd, 1U, &timeout, NULL, sizeof(pfd)) == 0)
            (void)printf("ok   __ppoll_chk\n");
        else
        {
            (void)fprintf(stderr, "FAIL __ppoll_chk: not timed out\n");
            g_failures++;
        }
    }
    (void)unlink("/tmp/.chaos-net.conf");
    (void)close(server);
    (void)close(client);
    (void)close(listener);
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        (void)fprintf(stderr, "usage: %s io|memory|net\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "io") == 0)
    {
        probe_io();
    }
    else if (strcmp(argv[1], "memory") == 0)
    {
        probe_memory();
    }
    else if (strcmp(argv[1], "net") == 0)
    {
        probe_net();
    }
    else
    {
        return 2;
    }
    return g_failures == 0 ? 0 : 1;
}
