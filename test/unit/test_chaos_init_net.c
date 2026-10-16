/**
 * @file test_chaos_init_net.c
 * @brief Unit tests for chaos-init's net decisions.
 *
 * Subsystem under test: `src/init/chaos_init_net.c` (with the net rule core it
 * includes, `chaos_init_proc.c` and `chaos_init_tracee.c`).
 *
 * Coverage approach:
 * - Real sockets of this test process (a TCP listener, a connected pair, an
 *   unbound socket, a bound UDP socket, a UNIX socket) are looked up the way a
 *   supervised process's are: by xattr and /proc/<pid>/net. Calls are built as a
 *   notification carries them, with this process as the caller.
 * - Seams make the xattr report an unknown protocol and the process lookup fail;
 *   the /proc/net address parser is also fed IPv6 and malformed text directly.
 *
 * Properties under test:
 * - getsockopt(SO_TYPE), getsockname() and getpeername() answer for another
 *   process's descriptor like the kernel would, also for unbound and UNIX sockets.
 * - Every way a net call names its endpoint (socket spec, sockaddr argument, own
 *   address, peer, msg_name, poll/select/epoll sets) reaches the rule core.
 * - ERRNO fails, LATENCY delays, TIMEOUT returns 0 from the poll family; CORRUPT,
 *   RESET and ERRNO on close are not applied; read/write/close on a non-socket are
 *   left to io.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

static int g_fail_process = 0;
static const char *g_fake_protocol = NULL;
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    return g_fail_process ? -1 : chaos_init_process_of(tid, tgid, start);
}
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

#include <sys/xattr.h>
static ssize_t test_getxattr(const char *path, const char *name, void *value, size_t size)
{
    if (g_fake_protocol != NULL)
    {
        const size_t length = strlen(g_fake_protocol);

        memcpy(value, g_fake_protocol, length);
        return (ssize_t)length;
    }
    return getxattr(path, name, value, size);
}
#define CHAOS_INIT_NET_GETXATTR test_getxattr

#include "../../src/init/chaos_init_net.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <arpa/inet.h>
#include <assert.h>
#include <sys/epoll.h>

static chaos_init_verdict_t
decide(int nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    call.tid = getpid();
    call.nr = nr;
    call.args[0] = a0;
    call.args[1] = a1;
    call.args[2] = a2;
    call.args[3] = a3;
    call.args[4] = a4;
    call.args[5] = a5;
    verdict.action = CHAOS_INIT_FAIL;
    verdict.error = -1;
    assert(chaos_init_net_decide(&call, &verdict) == 1);
    return verdict;
}

static int FAILS(chaos_init_verdict_t verdict, int error)
{
    return verdict.action == CHAOS_INIT_FAIL && verdict.error == error;
}

static int PASSES(chaos_init_verdict_t verdict)
{
    return verdict.action == CHAOS_INIT_PASS;
}

#define P(pointer) ((uint64_t)(uintptr_t)(pointer))

/** @brief A TCP or UDP socket bound to 127.0.0.1 on a free port. */
static int bound_socket(int type, struct sockaddr_in *address)
{
    socklen_t length = (socklen_t)sizeof(*address);
    const int fd = socket(AF_INET, type, 0);

    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(fd >= 0 && bind(fd, (struct sockaddr *)address, sizeof(*address)) == 0);
    assert(getsockname(fd, (struct sockaddr *)address, &length) == 0);
    return fd;
}

static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-net.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-net.conf.new", "/tmp/.chaos-net.conf") == 0);
}

static void test_socket_queries(
    int listener,
    int client,
    int unbound,
    int udp,
    int unix_fd,
    int pipe_fd,
    const struct sockaddr_in *server_address
)
{
    struct sockaddr_storage name;
    struct sockaddr_in *in = (struct sockaddr_in *)&name;
    struct sockaddr_un *un = (struct sockaddr_un *)&name;
    socklen_t length;
    int type = 0;

    g_chaos_init_net_tid = getpid();

    /* SO_TYPE of TCP and UDP sockets; other options and non-sockets are refused. */
    length = (socklen_t)sizeof(type);
    assert(
        chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
        type == SOCK_STREAM
    );
    assert(
        chaos_init_net_getsockopt(udp, SOL_SOCKET, SO_TYPE, &type, &length) == 0 &&
        type == SOCK_DGRAM
    );
    assert(
        chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_RCVBUF, &type, &length) == -1 &&
        errno == ENOPROTOOPT
    );
    assert(
        chaos_init_net_getsockopt(pipe_fd, SOL_SOCKET, SO_TYPE, &type, &length) == -1 &&
        errno == ENOTSOCK
    );

    /* Own address and peer from /proc/<pid>/net. */
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getsockname(listener, (struct sockaddr *)&name, &length) == 0);
    assert(
        in->sin_family == AF_INET && in->sin_port == server_address->sin_port &&
        in->sin_addr.s_addr == htonl(INADDR_LOOPBACK)
    );
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getpeername(listener, (struct sockaddr *)&name, &length) == -1 &&
        errno == ENOTCONN
    );
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getpeername(client, (struct sockaddr *)&name, &length) == 0 &&
        in->sin_port == server_address->sin_port
    );

    /* Not bound yet: the unspecified address, and no peer. */
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unbound, (struct sockaddr *)&name, &length) == 0 &&
        in->sin_family == AF_INET && in->sin_port == 0 &&
        length == (socklen_t)sizeof(struct sockaddr_in)
    );
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getpeername(unbound, (struct sockaddr *)&name, &length) == -1);

    /* UNIX: the bound path; the peer is not in /proc. */
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unix_fd, (struct sockaddr *)&name, &length) == 0 &&
        un->sun_family == AF_UNIX && strcmp(un->sun_path, "/tmp/initnet.sock") == 0
    );
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getpeername(unix_fd, (struct sockaddr *)&name, &length) == -1);
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(pipe_fd, (struct sockaddr *)&name, &length) == -1 &&
        errno == ENOTSOCK
    );

    /* Kernel names: an unknown protocol, the old "UNIX", a failed lookup. */
    g_fake_protocol = "RAW";
    assert(chaos_init_net_protocol(listener) == NULL);
    g_fake_protocol = "UNIX";
    assert(chaos_init_net_protocol(listener)->family == AF_UNIX);
    g_fake_protocol = NULL;
    assert(chaos_init_net_protocol(-1) == NULL);

    /* A descriptor that claims to be a socket but has no socket inode; a UNIX
     * socket that is in no table is unnamed. */
    g_fake_protocol = "TCP";
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getsockname(pipe_fd, (struct sockaddr *)&name, &length) == -1);
    g_fake_protocol = "UNIX-STREAM";
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unbound, (struct sockaddr *)&name, &length) == 0 &&
        name.ss_family == AF_UNIX && length == (socklen_t)sizeof(sa_family_t)
    );
    g_fake_protocol = NULL;
}

static void test_parse_address(void)
{
    struct sockaddr_storage out;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&out;
    socklen_t length = 0;
    char text[INET6_ADDRSTRLEN];

    assert(
        chaos_init_net_parse_address(
            "00000000000000000000000001000000:1F90", AF_INET6, &out, &length
        ) == 1
    );
    assert(length == (socklen_t)sizeof(*in6) && ntohs(in6->sin6_port) == 8080U);
    assert(
        inet_ntop(AF_INET6, &in6->sin6_addr, text, sizeof(text)) != NULL && strcmp(text, "::1") == 0
    );
    assert(chaos_init_net_parse_address("0100007F", AF_INET, &out, &length) == 0);
    assert(chaos_init_net_parse_address("0100007:1F90", AF_INET, &out, &length) == 0);
    assert(chaos_init_net_parse_address("0100007F:zz", AF_INET, &out, &length) == 0);
}

int main(void)
{
    struct sockaddr_in server_address;
    struct sockaddr_in udp_address;
    struct sockaddr_in other_address;
    struct sockaddr_un unix_address;
    struct sockaddr_in6 v6;
    struct pollfd polled[2];
    struct epoll_event event;
    struct iovec vector[2];
    struct msghdr message;
    struct mmsghdr messages[1];
    char rules[2048];
    char buffer[64] = "0123456789abcdefghij";
    fd_set readable;
    int pipe_fds[2];
    int listener;
    int client;
    int server;
    int unbound;
    int udp;
    int unix_fd;
    int epoll_fd;
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    (void)unlink("/tmp/.chaos-net.conf");
    (void)unlink("/tmp/initnet.sock");
    chaos_init_net_start();
    g_chaos_net_check_interval_ns = 0U;

    listener = bound_socket(SOCK_STREAM, &server_address);
    assert(listen(listener, 4) == 0);
    client = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(client, (struct sockaddr *)&server_address, sizeof(server_address)) == 0);
    server = accept(listener, NULL, NULL);
    assert(server >= 0);
    unbound = socket(AF_INET, SOCK_STREAM, 0);
    udp = bound_socket(SOCK_DGRAM, &udp_address);
    unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&unix_address, 0, sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    strcpy(unix_address.sun_path, "/tmp/initnet.sock");
    assert(bind(unix_fd, (struct sockaddr *)&unix_address, sizeof(unix_address)) == 0);
    assert(pipe(pipe_fds) == 0);

    test_socket_queries(listener, client, unbound, udp, unix_fd, pipe_fds[0], &server_address);
    test_parse_address();

    /* Not a net call; read/write/close on a pipe are io's. */
    memset(&call, 0, sizeof(call));
    call.tid = getpid();
    call.nr = __NR_getpid;
    assert(chaos_init_net_decide(&call, &verdict) == 0);
    call.nr = __NR_read;
    call.args[0] = (uint64_t)pipe_fds[0];
    assert(chaos_init_net_decide(&call, &verdict) == 0);

    /* Without a rule file every call runs. */
    assert(PASSES(
        decide(__NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0)
    ));

    other_address = server_address;
    other_address.sin_port = htons((uint16_t)(ntohs(server_address.sin_port) + 1U));
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.1:%u:connect:ECONNREFUSED:1.0\n"
        "tcp4://127.0.0.1:%u:bind:EADDRINUSE:1.0\n"
        "tcp4://127.0.0.1:%u:listen:EADDRINUSE:1.0\n"
        "tcp4://127.0.0.1:%u:accept:EMFILE:1.0\n"
        "tcp4://127.0.0.1:%u:recv:LATENCY:30\n"
        "tcp4://127.0.0.1:%u:send:EPIPE:1.0 @size>10\n"
        "tcp4://127.0.0.1:%u:shutdown:ENOTCONN:1.0\n"
        "tcp4://127.0.0.1:%u:poll:TIMEOUT:1.0\n"
        "tcp4://127.0.0.1:%u:close:ECONNRESET:1.0\n"
        "udp4://127.0.0.1:%u:send:ECONNREFUSED:1.0\n"
        "udp4://127.0.0.1:%u:recv:CORRUPT:1.0\n"
        "tcp6://*:0:socket:EMFILE:1.0\n",
        ntohs(server_address.sin_port),
        ntohs(other_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(udp_address.sin_port),
        ntohs(udp_address.sin_port)
    );
    write_rules(rules);

    /* By socket spec and by sockaddr argument. */
    assert(FAILS(decide(__NR_socket, AF_INET6, SOCK_STREAM, 0, 0, 0, 0), EMFILE));
    assert(PASSES(decide(__NR_socketpair, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0)));
    assert(FAILS(
        decide(
            __NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0
        ),
        ECONNREFUSED
    ));
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, 0U, sizeof(server_address), 0, 0, 0)));
    assert(FAILS(
        decide(__NR_bind, (uint64_t)unbound, P(&other_address), sizeof(other_address), 0, 0, 0),
        EADDRINUSE
    ));
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, P(&v6), sizeof(v6), 0, 0, 0)));

    /* By the socket's own address. */
    assert(FAILS(decide(__NR_listen, (uint64_t)listener, 4U, 0, 0, 0, 0), EADDRINUSE));
    assert(FAILS(decide(__NR_accept4, (uint64_t)listener, 0, 0, 0, 0, 0), EMFILE));
    verdict = decide(__NR_read, (uint64_t)server, P(buffer), 8U, 0, 0, 0);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 30U);
    assert(
        decide(__NR_recvfrom, (uint64_t)server, P(buffer), 8U, 0, 0, 0).action == CHAOS_INIT_DELAY
    );
    vector[0].iov_base = buffer;
    vector[0].iov_len = 10U;
    vector[1].iov_base = buffer + 10;
    vector[1].iov_len = 10U;
    assert(decide(__NR_readv, (uint64_t)server, P(vector), 2U, 0, 0, 0).action == CHAOS_INIT_DELAY);
    /* An iovec array too long or unreadable has no size; the rule has no @size. */
    assert(
        decide(__NR_readv, (uint64_t)server, P(vector), 2000U, 0, 0, 0).action == CHAOS_INIT_DELAY
    );
    assert(decide(__NR_readv, (uint64_t)server, 0U, 2U, 0, 0, 0).action == CHAOS_INIT_DELAY);
    memset(&message, 0, sizeof(message));
    message.msg_iov = vector;
    message.msg_iovlen = 2U;
    assert(
        decide(__NR_recvmsg, (uint64_t)server, P(&message), 0, 0, 0, 0).action == CHAOS_INIT_DELAY
    );
    assert(PASSES(decide(__NR_recvfrom, (uint64_t)udp, P(buffer), 8U, 0, 0, 0))); /* CORRUPT */

    /* By the peer, with the byte count for @size. */
    assert(PASSES(decide(__NR_write, (uint64_t)client, P(buffer), 5U, 0, 0, 0)));
    assert(FAILS(decide(__NR_write, (uint64_t)client, P(buffer), 20U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_writev, (uint64_t)client, P(vector), 2U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_sendto, (uint64_t)client, P(buffer), 20U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_sendmsg, (uint64_t)client, P(&message), 0, 0, 0, 0), EPIPE));
    assert(PASSES(decide(__NR_sendmsg, (uint64_t)client, 0U, 0, 0, 0, 0))); /* size unknown */

    /* By the destination argument or msg_name. */
    assert(FAILS(
        decide(__NR_sendto, (uint64_t)udp, P(buffer), 4U, 0, P(&udp_address), sizeof(udp_address)),
        ECONNREFUSED
    ));
    message.msg_name = &udp_address;
    message.msg_namelen = sizeof(udp_address);
    assert(FAILS(decide(__NR_sendmsg, (uint64_t)udp, P(&message), 0, 0, 0, 0), ECONNREFUSED));
    memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr = message;
    assert(FAILS(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 1U, 0, 0, 0), ECONNREFUSED));
    message.msg_name = NULL;
    assert(PASSES(decide(__NR_sendmsg, (uint64_t)udp, P(&message), 0, 0, 0, 0))); /* no peer */

    /* Own address, else peer. */
    assert(FAILS(decide(__NR_shutdown, (uint64_t)server, SHUT_RDWR, 0, 0, 0, 0), ENOTCONN));

    /* The poll family: any socket in the set with a rule; TIMEOUT returns 0. */
    polled[0].fd = pipe_fds[0];
    polled[1].fd = server;
    verdict = decide(__NR_ppoll, P(polled), 2U, 0, 0, 0, 0);
    assert(verdict.action == CHAOS_INIT_RETURN && verdict.value == 0);
    assert(PASSES(decide(__NR_ppoll, P(polled), 1U, 0, 0, 0, 0)));
    assert(PASSES(decide(__NR_ppoll, 0U, 2U, 0, 0, 0, 0)));
    FD_ZERO(&readable);
    FD_SET(server, &readable);
    assert(
        decide(__NR_pselect6, (uint64_t)server + 1U, 0U, P(&readable), 0, 0, 0).action ==
        CHAOS_INIT_RETURN
    );
    epoll_fd = epoll_create1(0);
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    assert(epoll_fd >= 0 && epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server, &event) == 0);
    assert(
        decide(__NR_epoll_pwait, (uint64_t)epoll_fd, 0, 1U, 0, 0, 0).action == CHAOS_INIT_RETURN
    );
    assert(PASSES(decide(__NR_epoll_pwait, 999U, 0, 1U, 0, 0, 0)));

    /* Not applied in SECCOMP mode: ERRNO on close. A process that ended is not counted. */
    assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
    g_fail_process = 1;
    assert(PASSES(decide(__NR_listen, (uint64_t)listener, 4U, 0, 0, 0, 0)));
    g_fail_process = 0;

    (void)unlink("/tmp/.chaos-net.conf");
    (void)unlink("/tmp/initnet.sock");
    (void)snprintf(rules, sizeof(rules), "/tmp/.chaos-net.hits.%ld", (long)getpid());
    (void)unlink(rules);
    return 0;
}
