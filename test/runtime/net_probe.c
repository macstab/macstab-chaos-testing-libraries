/**
 * @file net_probe.c
 * @brief End-to-end probe for libchaos-net in LD_PRELOAD mode on glibc and musl.
 *
 * @details
 * Proves that rules in the rule file `/tmp/.chaos-net.conf`
 * (`<selector>:<operation>:<ERRNO-name | effect>:<value>`) are matched against real loopback
 * sockets and fault every wrapped socket call with the documented result. Each check uses its
 * own 127.0.0.1 port (41001-41036) so a rule can only match the socket under test. Exit code of
 * each check, in main()'s order:
 *
 * - 10-11   bind:EMFILE; bind returns -1/EMFILE.
 * - 20-26   listen:LATENCY:200; listen succeeds after >= 150 ms.
 * - 30-32   connect:EHOSTUNREACH; -1/EHOSTUNREACH although a listener exists.
 * - 210-213 the tcp4:// connect rule also matches an AF_INET6 socket connecting to
 *           ::ffff:127.0.0.1 (dual-stack sockets, as Java and Go use them).
 * - 40-41   accept:EAGAIN; accept returns -1/EAGAIN.
 * - 50-51   the accept rule also fails accept4 (one operation covers both).
 * - 60-64   send:LATENCY:200; send in a forked client takes >= 150 ms, the data arrives.
 * - 70-75   recv:CORRUPT:1.0; 4 bytes arrive but differ from what was sent.
 * - 180-183 recv:TRICKLE:3; recv, read, readv and recvmsg each return 1-3 bytes and the pieces
 *           reassemble to the sent bytes exactly.
 * - 190-194 recv:DUP:1.0; a payload is delivered, then delivered again on the next read
 *           (read() included), then the next real payload follows.
 * - 220-222 a kept DUP payload is replayed only on the socket it came from: after dup2() puts
 *           another connection under the same fd number, that connection is read for real.
 * - 230-233 a recv rule for the server's address also fires on the client, where that address
 *           is the peer: for TCP and for an unbound unix-socket client.
 * - 240-241 unix://@name selects an abstract unix socket, written as Linux shows it.
 * - 200-202 recv:TRICKLE:1 on a UDP socket changes nothing: shortening the buffer would truncate
 *           the datagram and the kernel would drop the rest. (Overlaps the rule-file codes.)
 * - 80-81   udp4 send:EHOSTUNREACH fails sendto.
 * - 90-94   udp4 recv:CORRUPT corrupts recvfrom (forked sender).
 * - 100-101 udp4 send:EHOSTUNREACH fails sendmsg.
 * - 110-114 udp4 recv:CORRUPT corrupts recvmsg (forked sender).
 * - 140     tcp4://\*:0 socket:EAFNOSUPPORT fails socket(); socket rules accept only wildcard
 *           selectors because no address exists yet.
 * - 141     unix://\* socket:EMFILE fails socketpair(AF_UNIX).
 * - 142-143 shutdown:ENOTCONN fails shutdown on a connected socket.
 * - 144-149 poll:TIMEOUT:1.0 makes poll and ppoll report 0 with revents cleared although data
 *           is queued.
 * - 150-153 the poll rule makes select wait out its 200 ms (>= 150 ms), report 0, clear the fd
 *           and leave no time in the timeval; a select without timeout still reports the ready
 *           fd, because a wait that cannot time out must not be faked.
 * - 153-155 the same for pselect (153 is reused).
 * - 156-165 the poll rule makes epoll_wait and epoll_pwait return 0 with data queued.
 * - 166-167 udp4 send:EHOSTUNREACH fails sendmmsg.
 * - 168-172 udp4 recv:CORRUPT corrupts recvmmsg.
 * - 200-204 the rule file could not be written.
 *
 * SIGPIPE is ignored so a faulted connection cannot kill the probe. Fork-based checks keep the
 * client in a child so the client's and server's calls are separate processes' wrappers.
 *
 * Run by test_net_glibc.sh (gcc:bookworm) and test_net_alpine.sh (alpine:3.20), which build
 * the library, compile this file in the container and run it with
 * `LD_PRELOAD=/tmp/libchaos-net.so`. Needs loopback TCP/UDP, AF_INET6 and unix sockets.
 *
 * Exit: 0 when every check passes; otherwise the code of the first failing check above. The
 * rule file is left in place. The probe never skips.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static time_t g_config_stamp = 1000;

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
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
 * @brief Replaces the rule file `/tmp/.chaos-net.conf` with @p line plus a newline and stamps a
 *        fresh mtime.
 *
 * The mtime is set explicitly to 1000, 1001, ... seconds since the epoch, so each write
 * changes the reload change stamp even when two writes land within one filesystem timestamp
 * tick.
 *
 * @return 0, or 200 (fopen), 201 (fprintf), 202 (fflush), 203 (futimens), 204 (fclose).
 */
static int write_config_now(const char *line)
{
    struct timespec times[2];
    FILE *config = fopen("/tmp/.chaos-net.conf", "w");

    if (config == NULL)
    {
        return 200;
    }
    if (fprintf(config, "%s\n", line) < 0)
    {
        fclose(config);
        return 201;
    }
    if (fflush(config) != 0)
    {
        fclose(config);
        return 202;
    }

    times[0].tv_sec = g_config_stamp++;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    if (futimens(fileno(config), times) != 0)
    {
        fclose(config);
        return 203;
    }
    if (fclose(config) != 0)
    {
        return 204;
    }

    return 0;
}

/** @brief write_config_now(), then wait_for_rule_check(); returns write_config_now()'s code. */
static int write_config(const char *line)
{
    const int rc = write_config_now(line);

    wait_for_rule_check();
    return rc;
}

/** @brief Sets SO_REUSEADDR so a port in TIME_WAIT from a previous run can be rebound; 1 on
 * failure. */
static int set_reuseaddr(int fd)
{
    int enabled = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, (socklen_t)sizeof(enabled)) != 0)
    {
        return 1;
    }
    return 0;
}

/** @brief Fills @p address with 127.0.0.1:@p port. */
static void set_loopback_v4(struct sockaddr_in *address, unsigned short port)
{
    (void)memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) != 1)
    {
        abort();
    }
}

/** @brief Listening TCP socket on 127.0.0.1:@p port (backlog 16); -1 on failure. */
static int create_tcp_listener(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return -1;
    }
    set_loopback_v4(&address, port);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

/** @brief TCP socket connected to 127.0.0.1:@p port; -1 on failure. */
static int connect_tcp(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    set_loopback_v4(&address, port);
    if (connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * @brief Connected loopback TCP pair on @p port; the listener is closed afterwards.
 * @return 0, or -1 with nothing left open.
 */
static int create_tcp_pair(unsigned short port, int *server_fd, int *client_fd)
{
    int listener = create_tcp_listener(port);
    int client;
    int server;

    if (listener < 0 || server_fd == NULL || client_fd == NULL)
    {
        if (listener >= 0)
        {
            close(listener);
        }
        return -1;
    }

    client = connect_tcp(port);
    if (client < 0)
    {
        close(listener);
        return -1;
    }

    server = accept(listener, NULL, NULL);
    close(listener);
    if (server < 0)
    {
        close(client);
        return -1;
    }

    *server_fd = server;
    *client_fd = client;
    return 0;
}

/** @brief UDP socket bound to 127.0.0.1:@p port; -1 on failure. */
static int create_udp_bound(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return -1;
    }
    set_loopback_v4(&address, port);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * @brief Reaps @p pid; 0 if it exited 0, @p failure_code if waitpid failed, @p failure_code + 1
 *        for any other status.
 */
static int wait_child_ok(pid_t pid, int failure_code)
{
    int status;

    if (waitpid(pid, &status, 0) < 0)
    {
        return failure_code;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return failure_code + 1;
    }
    return 0;
}

static int probe_bind_errno(void)
{
    struct sockaddr_in address;
    int rc;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return 10;
    }
    rc = write_config("tcp4://127.0.0.1:41001:bind:EMFILE:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41001U);
    errno = 0;
    rc = bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    if (rc != -1 || errno != EMFILE)
    {
        return 11;
    }
    return 0;
}

static int probe_listen_latency(void)
{
    struct sockaddr_in address;
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int rc;

    if (fd < 0)
    {
        return 20;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return 21;
    }
    set_loopback_v4(&address, 41002U);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return 22;
    }
    rc = write_config("tcp4://127.0.0.1:41002:listen:LATENCY:200");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        close(fd);
        return 23;
    }
    if (listen(fd, 16) != 0)
    {
        close(fd);
        return 24;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        close(fd);
        return 25;
    }
    close(fd);
    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 150LL ? 0 : 26;
}

static int probe_connect_errno(void)
{
    struct sockaddr_in address;
    int listener = create_tcp_listener(41003U);
    int fd;
    int rc;

    if (listener < 0)
    {
        return 30;
    }
    rc = write_config("tcp4://127.0.0.1:41003:connect:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        close(listener);
        return 31;
    }
    set_loopback_v4(&address, 41003U);
    errno = 0;
    rc = connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    close(listener);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 32;
    }
    return 0;
}

/**
 * @brief A dual-stack AF_INET6 socket connecting to ::ffff:127.0.0.1, as Java and Go do, is
 *        matched by the tcp4:// rule for 127.0.0.1 (exit 210-213).
 *
 * Without unmapping v4-mapped addresses, every tcp4:// rule would silently miss JVM and Go
 * clients.
 */
static int probe_connect_v4_mapped(void)
{
    struct sockaddr_in6 address;
    int listener = create_tcp_listener(41033U);
    int fd;
    int rc;

    if (listener < 0)
    {
        return 210;
    }
    rc = write_config("tcp4://127.0.0.1:41033:connect:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
    {
        close(listener);
        return 211;
    }
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(41033U);
    if (inet_pton(AF_INET6, "::ffff:127.0.0.1", &address.sin6_addr) != 1)
    {
        close(fd);
        close(listener);
        return 212;
    }
    errno = 0;
    rc = connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    close(listener);
    return rc == -1 && errno == EHOSTUNREACH ? 0 : 213;
}

static int probe_accept_errno(void)
{
    int listener = create_tcp_listener(41004U);
    int rc;

    if (listener < 0)
    {
        return 40;
    }
    rc = write_config("tcp4://127.0.0.1:41004:accept:EAGAIN:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    errno = 0;
    rc = accept(listener, NULL, NULL);
    close(listener);
    if (rc != -1 || errno != EAGAIN)
    {
        return 41;
    }
    return 0;
}

static int probe_accept4_errno(void)
{
    int listener = create_tcp_listener(41011U);
    int rc;

    if (listener < 0)
    {
        return 50;
    }
    rc = write_config("tcp4://127.0.0.1:41011:accept:EAGAIN:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    errno = 0;
    rc = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    if (rc != -1 || errno != EAGAIN)
    {
        return 51;
    }
    return 0;
}

static int probe_send_latency(void)
{
    int listener = create_tcp_listener(41005U);
    pid_t child;
    int accepted;
    char buffer[8];
    int rc;

    if (listener < 0)
    {
        return 60;
    }
    rc = write_config("tcp4://127.0.0.1:41005:send:LATENCY:200");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(listener);
        return 61;
    }
    if (child == 0)
    {
        struct timespec start;
        struct timespec end;
        long long duration_ms;
        int fd = connect_tcp(41005U);

        if (fd < 0)
        {
            _exit(1);
        }
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        {
            _exit(2);
        }
        if (send(fd, "ping", 4U, 0) != 4)
        {
            _exit(3);
        }
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
        {
            _exit(4);
        }
        close(fd);
        duration_ms = elapsed_ms(&start, &end);
        _exit(duration_ms >= 150LL ? 0 : 5);
    }

    accepted = accept(listener, NULL, NULL);
    if (accepted < 0)
    {
        close(listener);
        (void)wait_child_ok(child, 62);
        return 62;
    }
    if (recv(accepted, buffer, sizeof(buffer), 0) != 4)
    {
        close(accepted);
        close(listener);
        (void)wait_child_ok(child, 63);
        return 63;
    }
    close(accepted);
    close(listener);
    return wait_child_ok(child, 64);
}

static int probe_recv_corrupt(void)
{
    int listener = create_tcp_listener(41006U);
    pid_t child;
    int accepted;
    char buffer[8];
    int rc;

    if (listener < 0)
    {
        return 70;
    }
    rc = write_config("tcp4://127.0.0.1:41006:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(listener);
        return 71;
    }
    if (child == 0)
    {
        int fd = connect_tcp(41006U);

        if (fd < 0)
        {
            _exit(1);
        }
        if (send(fd, "ABCD", 4U, 0) != 4)
        {
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    accepted = accept(listener, NULL, NULL);
    if (accepted < 0)
    {
        close(listener);
        (void)wait_child_ok(child, 72);
        return 72;
    }
    if (recv(accepted, buffer, sizeof(buffer), 0) != 4)
    {
        close(accepted);
        close(listener);
        (void)wait_child_ok(child, 73);
        return 73;
    }
    close(accepted);
    close(listener);
    if (memcmp(buffer, "ABCD", 4U) == 0)
    {
        (void)wait_child_ok(child, 74);
        return 74;
    }
    return wait_child_ok(child, 75);
}

static int probe_sendto_errno(void)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 80;
    }
    rc = write_config("udp4://127.0.0.1:41007:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41007U);
    errno = 0;
    rc = (int
    )sendto(fd, "udp", 3U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 81;
    }
    return 0;
}

static int probe_recvfrom_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41008U);
    pid_t child;
    char buffer[8];
    int rc;

    if (receiver < 0)
    {
        return 90;
    }
    rc = write_config("udp4://127.0.0.1:41008:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(receiver);
        return 91;
    }
    if (child == 0)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0)
        {
            _exit(1);
        }
        set_loopback_v4(&address, 41008U);
        if (sendto(
                fd, "WXYZ", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
            ) != 4)
        {
            close(fd);
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    if (recvfrom(receiver, buffer, sizeof(buffer), 0, NULL, NULL) != 4)
    {
        close(receiver);
        (void)wait_child_ok(child, 92);
        return 92;
    }
    close(receiver);
    if (memcmp(buffer, "WXYZ", 4U) == 0)
    {
        (void)wait_child_ok(child, 93);
        return 93;
    }
    return wait_child_ok(child, 94);
}

static int probe_sendmsg_errno(void)
{
    struct sockaddr_in address;
    struct iovec iov;
    struct msghdr message;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 100;
    }
    rc = write_config("udp4://127.0.0.1:41009:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41009U);
    iov.iov_base = (void *)"msg";
    iov.iov_len = 3U;
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    errno = 0;
    rc = (int)sendmsg(fd, &message, 0);
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 101;
    }
    return 0;
}

static int probe_recvmsg_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41010U);
    pid_t child;
    char buffer[8];
    struct iovec iov;
    struct msghdr message;
    int rc;

    if (receiver < 0)
    {
        return 110;
    }
    rc = write_config("udp4://127.0.0.1:41010:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(receiver);
        return 111;
    }
    if (child == 0)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0)
        {
            _exit(1);
        }
        set_loopback_v4(&address, 41010U);
        if (sendto(
                fd, "LMNO", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
            ) != 4)
        {
            close(fd);
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (recvmsg(receiver, &message, 0) != 4)
    {
        close(receiver);
        (void)wait_child_ok(child, 112);
        return 112;
    }
    close(receiver);
    if (memcmp(buffer, "LMNO", 4U) == 0)
    {
        (void)wait_child_ok(child, 113);
        return 113;
    }
    return wait_child_ok(child, 114);
}

static int probe_socket_errno(void)
{
    int fd;
    int rc = write_config("tcp4://*:0:socket:EAFNOSUPPORT:1.0");

    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd != -1 || errno != EAFNOSUPPORT)
    {
        if (fd >= 0)
        {
            close(fd);
        }
        return 140;
    }
    return 0;
}

static int probe_socketpair_errno(void)
{
    int sv[2];
    int rc = write_config("unix://*:socket:EMFILE:1.0");

    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc != -1 || errno != EMFILE)
    {
        if (rc == 0)
        {
            close(sv[0]);
            close(sv[1]);
        }
        return 141;
    }
    return 0;
}

static int probe_shutdown_errno(void)
{
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41012U, &server_fd, &client_fd) != 0)
    {
        return 142;
    }
    rc = write_config("tcp4://127.0.0.1:41012:shutdown:ENOTCONN:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    errno = 0;
    rc = shutdown(server_fd, SHUT_RDWR);
    close(server_fd);
    close(client_fd);
    if (rc != -1 || errno != ENOTCONN)
    {
        return 143;
    }
    return 0;
}

static int probe_poll_timeout(void)
{
    struct pollfd pfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41013U, &server_fd, &client_fd) != 0)
    {
        return 144;
    }
    rc = write_config("tcp4://127.0.0.1:41013:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "poll", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 145;
    }

    pfd.fd = server_fd;
    pfd.events = POLLIN;
    pfd.revents = POLLIN;
    rc = poll(&pfd, 1U, 200);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || pfd.revents != 0)
    {
        return 146;
    }
    return 0;
}

static int probe_ppoll_timeout(void)
{
    struct pollfd pfd;
    struct timespec timeout;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41014U, &server_fd, &client_fd) != 0)
    {
        return 147;
    }
    rc = write_config("tcp4://127.0.0.1:41014:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "ppol", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 148;
    }

    pfd.fd = server_fd;
    pfd.events = POLLIN;
    pfd.revents = POLLIN;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 200000000L;
    rc = ppoll(&pfd, 1U, &timeout, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || pfd.revents != 0)
    {
        return 149;
    }
    return 0;
}

static int probe_select_timeout(void)
{
    struct timeval wait;
    struct timespec start;
    struct timespec end;
    fd_set readfds;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41015U, &server_fd, &client_fd) != 0)
    {
        return 150;
    }
    rc = write_config("tcp4://127.0.0.1:41015:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "sele", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 151;
    }

    /* TIMEOUT waits out the caller's 200 ms, then reports nothing ready and, as Linux select
     * does on timeout, zero time left in the timeval. */
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    wait.tv_sec = 0;
    wait.tv_usec = 200000;
    clock_gettime(CLOCK_MONOTONIC, &start);
    rc = select(server_fd + 1, &readfds, NULL, NULL, &wait);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (rc != 0 || FD_ISSET(server_fd, &readfds) || wait.tv_usec != 0 ||
        elapsed_ms(&start, &end) < 150LL)
    {
        close(server_fd);
        close(client_fd);
        return 152;
    }
    /* A wait without a timeout cannot time out, so TIMEOUT must not fake one: the ready
     * socket is reported. */
    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    rc = select(server_fd + 1, &readfds, NULL, NULL, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 1 || !FD_ISSET(server_fd, &readfds))
    {
        return 153;
    }
    return 0;
}

static int probe_pselect_timeout(void)
{
    fd_set readfds;
    struct timespec timeout;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41016U, &server_fd, &client_fd) != 0)
    {
        return 153;
    }
    rc = write_config("tcp4://127.0.0.1:41016:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "psel", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 154;
    }

    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    timeout.tv_sec = 0;
    timeout.tv_nsec = 200000000L;
    rc = pselect(server_fd + 1, &readfds, NULL, NULL, &timeout, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || FD_ISSET(server_fd, &readfds))
    {
        return 155;
    }
    return 0;
}

static int probe_epoll_wait_timeout(void)
{
    struct epoll_event event;
    struct epoll_event events[1];
    int epfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41017U, &server_fd, &client_fd) != 0)
    {
        return 156;
    }
    rc = write_config("tcp4://127.0.0.1:41017:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    epfd = epoll_create1(0);
    if (epfd < 0)
    {
        close(server_fd);
        close(client_fd);
        return 157;
    }
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &event) != 0)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 158;
    }
    if (send(client_fd, "epol", 4U, 0) != 4)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 159;
    }

    rc = epoll_wait(epfd, events, 1, 200);
    close(epfd);
    close(server_fd);
    close(client_fd);
    return rc == 0 ? 0 : 160;
}

static int probe_epoll_pwait_timeout(void)
{
    struct epoll_event event;
    struct epoll_event events[1];
    int epfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41018U, &server_fd, &client_fd) != 0)
    {
        return 161;
    }
    rc = write_config("tcp4://127.0.0.1:41018:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    epfd = epoll_create1(0);
    if (epfd < 0)
    {
        close(server_fd);
        close(client_fd);
        return 162;
    }
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &event) != 0)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 163;
    }
    if (send(client_fd, "epwt", 4U, 0) != 4)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 164;
    }

    rc = epoll_pwait(epfd, events, 1, 200, NULL);
    close(epfd);
    close(server_fd);
    close(client_fd);
    return rc == 0 ? 0 : 165;
}

static int probe_sendmmsg_errno(void)
{
    struct sockaddr_in address;
    struct iovec iov;
    struct mmsghdr message;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 166;
    }
    rc = write_config("udp4://127.0.0.1:41019:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41019U);
    iov.iov_base = (void *)"bat";
    iov.iov_len = 3U;
    (void)memset(&message, 0, sizeof(message));
    message.msg_hdr.msg_name = &address;
    message.msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    message.msg_hdr.msg_iov = &iov;
    message.msg_hdr.msg_iovlen = 1;

    errno = 0;
    rc = sendmmsg(fd, &message, 1U, 0U);
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 167;
    }
    return 0;
}

static int probe_recvmmsg_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41020U);
    int sender;
    char buffer[8];
    struct iovec iov;
    struct mmsghdr message;
    int rc;

    if (receiver < 0)
    {
        return 168;
    }
    rc = write_config("udp4://127.0.0.1:41020:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0)
    {
        close(receiver);
        return 169;
    }
    set_loopback_v4(&address, 41020U);
    if (sendto(
            sender, "BULK", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
        ) != 4)
    {
        close(sender);
        close(receiver);
        return 170;
    }
    close(sender);

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_hdr.msg_iov = &iov;
    message.msg_hdr.msg_iovlen = 1;
    rc = recvmmsg(receiver, &message, 1U, 0U, NULL);
    close(receiver);
    if (rc != 1)
    {
        return 171;
    }
    if (memcmp(buffer, "BULK", 4U) == 0)
    {
        return 172;
    }
    return 0;
}

/**
 * @brief TRICKLE:3 on recv: recv, read, readv (split 2+6 iovec) and recvmsg, in rotation, each
 *        return 1-3 bytes, and the pieces reassemble to the sent bytes (exit 180-183).
 */
static int probe_recv_trickle(void)
{
    static const char sent[] = "HELLOWORLD!";
    char received[sizeof(sent)] = {0};
    size_t total = 0U;
    int server;
    int client;
    int round = 0;
    int rc;

    rc = write_config("tcp4://127.0.0.1:41030:recv:TRICKLE:3");
    if (rc != 0)
    {
        return rc;
    }
    if (create_tcp_pair(41030U, &server, &client) != 0)
    {
        return 180;
    }
    if (send(client, sent, sizeof(sent) - 1U, 0) != (ssize_t)(sizeof(sent) - 1U))
    {
        return 181;
    }
    while (total < sizeof(sent) - 1U)
    {
        char chunk[8];
        struct iovec iov[2];
        struct msghdr message;
        ssize_t got;

        iov[0].iov_base = chunk;
        iov[0].iov_len = 2U;
        iov[1].iov_base = chunk + 2;
        iov[1].iov_len = 6U;
        memset(&message, 0, sizeof(message));
        message.msg_iov = iov;
        message.msg_iovlen = 2U;
        switch (round++ % 4)
        {
        case 0:
            got = recv(server, chunk, sizeof(chunk), 0);
            break;
        case 1:
            got = read(server, chunk, sizeof(chunk));
            break;
        case 2:
            got = readv(server, iov, 2);
            break;
        default:
            got = recvmsg(server, &message, 0);
            break;
        }
        if (got <= 0 || got > 3)
        {
            return 182;
        }
        memcpy(received + total, chunk, (size_t)got);
        total += (size_t)got;
    }
    close(client);
    close(server);
    return memcmp(received, sent, sizeof(sent) - 1U) == 0 ? 0 : 183;
}

/**
 * @brief DUP:1.0 on recv: a payload is delivered, replayed once on the next read (via read()),
 *        and then the next real payload follows, in order (exit 190-194).
 */
static int probe_recv_dup(void)
{
    char buffer[8];
    int server;
    int client;
    int rc;

    rc = write_config("tcp4://127.0.0.1:41031:recv:DUP:1.0");
    if (rc != 0)
    {
        return rc;
    }
    if (create_tcp_pair(41031U, &server, &client) != 0)
    {
        return 190;
    }
    if (send(client, "one", 3U, 0) != 3 || recv(server, buffer, sizeof(buffer), 0) != 3 ||
        memcmp(buffer, "one", 3U) != 0)
    {
        return 191;
    }
    if (send(client, "two", 3U, 0) != 3)
    {
        return 192;
    }
    memset(buffer, 0, sizeof(buffer));
    if (read(server, buffer, sizeof(buffer)) != 3 || memcmp(buffer, "one", 3U) != 0)
    {
        return 193;
    }
    memset(buffer, 0, sizeof(buffer));
    if (recv(server, buffer, sizeof(buffer), 0) != 3 || memcmp(buffer, "two", 3U) != 0)
    {
        return 194;
    }
    close(client);
    close(server);
    return 0;
}

/**
 * @brief A recv rule written for the server's address also fires on the client side, where
 *        that address is the socket's peer: for TCP, and for a unix socket the client never
 *        bound (its only name is the peer's path) (exit 230-233).
 */
static int probe_recv_rule_on_client_side(void)
{
    struct sockaddr_un address;
    char buffer[8];
    int server;
    int client;
    int listener;
    int rc = write_config("tcp4://127.0.0.1:41036:recv:ECONNRESET:1.0");

    if (rc != 0)
    {
        return rc;
    }
    if (create_tcp_pair(41036U, &server, &client) != 0 || send(server, "data", 4U, 0) != 4)
    {
        return 230;
    }
    errno = 0;
    if (recv(client, buffer, sizeof(buffer), 0) != -1 || errno != ECONNRESET)
    {
        return 231;
    }
    close(client);
    close(server);

    rc = write_config("unix:///tmp/net-probe-client.sock:recv:ECONNRESET:1.0");
    if (rc != 0)
    {
        return rc;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", "/tmp/net-probe-client.sock");
    (void)unlink(address.sun_path);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 ||
        bind(listener, (struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        connect(client, (struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0 ||
        (server = accept(listener, NULL, NULL)) < 0 || send(server, "data", 4U, 0) != 4)
    {
        return 232;
    }
    errno = 0;
    if (recv(client, buffer, sizeof(buffer), 0) != -1 || errno != ECONNRESET)
    {
        return 233;
    }
    close(client);
    close(server);
    close(listener);
    (void)unlink(address.sun_path);
    return 0;
}

/**
 * @brief unix://@name selects an abstract unix socket (leading NUL in sun_path), the form
 *        /proc/net/unix shows; connect fails with ECONNREFUSED (exit 240-241).
 */
static int probe_abstract_unix_connect(void)
{
    struct sockaddr_un address;
    const socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 12U);
    int listener;
    int client;
    int rc = write_config("unix://@chaos-probe:connect:ECONNREFUSED:1.0");

    if (rc != 0)
    {
        return rc;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, "\0chaos-probe", 12U);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 || client < 0 || bind(listener, (struct sockaddr *)&address, length) != 0 ||
        listen(listener, 1) != 0)
    {
        return 240;
    }
    errno = 0;
    rc = connect(client, (struct sockaddr *)&address, length);
    close(client);
    close(listener);
    return rc == -1 && errno == ECONNREFUSED ? 0 : 241;
}

/**
 * @brief A kept DUP payload is replayed only on the socket it came from (exit 220-222).
 *
 * After dup2() puts a second connection under the first one's fd number, a read must return
 * the second connection's real data, not the first one's pending duplicate: replay state is
 * bound to the socket, not to the descriptor number.
 */
static int probe_recv_dup_after_dup2(void)
{
    char buffer[8];
    int first_server;
    int first_client;
    int second_server;
    int second_client;
    int rc = write_config("tcp4://127.0.0.1:41034:recv:DUP:1.0");

    if (rc != 0)
    {
        return rc;
    }
    if (create_tcp_pair(41034U, &first_server, &first_client) != 0 ||
        create_tcp_pair(41034U, &second_server, &second_client) != 0)
    {
        return 220;
    }
    if (send(first_client, "AAAA", 4U, 0) != 4 ||
        recv(first_server, buffer, sizeof(buffer), 0) != 4 ||
        send(second_client, "BBBB", 4U, 0) != 4 || dup2(second_server, first_server) < 0)
    {
        return 221;
    }
    memset(buffer, 0, sizeof(buffer));
    if (recv(first_server, buffer, sizeof(buffer), 0) != 4 || memcmp(buffer, "BBBB", 4U) != 0)
    {
        return 222;
    }
    close(first_client);
    close(first_server);
    close(second_client);
    close(second_server);
    return 0;
}

/**
 * @brief TRICKLE on a UDP socket is a no-op (exit 200-202): shortening the receive buffer would
 *        truncate the datagram and the kernel would discard the rest, which is data loss, not
 *        a slow peer.
 */
static int probe_recv_trickle_datagram(void)
{
    struct sockaddr_in address;
    char buffer[16];
    int receiver;
    int sender;
    int rc;

    rc = write_config("udp4://127.0.0.1:41032:recv:TRICKLE:1");
    if (rc != 0)
    {
        return rc;
    }
    receiver = create_udp_bound(41032U);
    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (receiver < 0 || sender < 0)
    {
        return 200;
    }
    set_loopback_v4(&address, 41032U);
    if (sendto(sender, "abcd", 4U, 0, (struct sockaddr *)&address, sizeof(address)) != 4)
    {
        return 201;
    }
    if (recv(receiver, buffer, sizeof(buffer), 0) != 4 || memcmp(buffer, "abcd", 4U) != 0)
    {
        return 202;
    }
    close(sender);
    close(receiver);
    return 0;
}

int main(void)
{
    int rc;

    signal(SIGPIPE, SIG_IGN);

    rc = probe_bind_errno();
    if (rc != 0)
        return rc;
    rc = probe_listen_latency();
    if (rc != 0)
        return rc;
    rc = probe_connect_errno();
    if (rc != 0)
        return rc;
    rc = probe_connect_v4_mapped();
    if (rc != 0)
        return rc;
    rc = probe_accept_errno();
    if (rc != 0)
        return rc;
    rc = probe_accept4_errno();
    if (rc != 0)
        return rc;
    rc = probe_send_latency();
    if (rc != 0)
        return rc;
    rc = probe_recv_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_recv_trickle();
    if (rc != 0)
        return rc;
    rc = probe_recv_dup();
    if (rc != 0)
        return rc;
    rc = probe_recv_dup_after_dup2();
    if (rc != 0)
        return rc;
    rc = probe_recv_rule_on_client_side();
    if (rc != 0)
        return rc;
    rc = probe_abstract_unix_connect();
    if (rc != 0)
        return rc;
    rc = probe_recv_trickle_datagram();
    if (rc != 0)
        return rc;
    rc = probe_sendto_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvfrom_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_sendmsg_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvmsg_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_socket_errno();
    if (rc != 0)
        return rc;
    rc = probe_socketpair_errno();
    if (rc != 0)
        return rc;
    rc = probe_shutdown_errno();
    if (rc != 0)
        return rc;
    rc = probe_poll_timeout();
    if (rc != 0)
        return rc;
    rc = probe_ppoll_timeout();
    if (rc != 0)
        return rc;
    rc = probe_select_timeout();
    if (rc != 0)
        return rc;
    rc = probe_pselect_timeout();
    if (rc != 0)
        return rc;
    rc = probe_epoll_wait_timeout();
    if (rc != 0)
        return rc;
    rc = probe_epoll_pwait_timeout();
    if (rc != 0)
        return rc;
    rc = probe_sendmmsg_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvmmsg_corrupt();
    if (rc != 0)
        return rc;

    return 0;
}
