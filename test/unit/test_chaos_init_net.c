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
#include <sys/mman.h>

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
    /* A path with spaces is read whole; an abstract name reads '@name', the text
     * libchaos-net gives it; an unnamed socket has an empty one. */
    {
        struct sockaddr_un bound;
        int spaced = socket(AF_UNIX, SOCK_STREAM, 0);
        int abstract = socket(AF_UNIX, SOCK_DGRAM, 0);
        int unnamed = socket(AF_UNIX, SOCK_STREAM, 0);

        memset(&bound, 0, sizeof(bound));
        bound.sun_family = AF_UNIX;
        strcpy(bound.sun_path, "/tmp/init net sock");
        (void)unlink(bound.sun_path);
        assert(bind(spaced, (struct sockaddr *)&bound, sizeof(bound)) == 0);
        assert(listen(spaced, 1) == 0);
        memset(&bound, 0, sizeof(bound));
        bound.sun_family = AF_UNIX;
        memcpy(bound.sun_path, "\0initnet-abstract", 17U);
        assert(
            bind(
                abstract, (struct sockaddr *)&bound, offsetof(struct sockaddr_un, sun_path) + 17U
            ) == 0
        );
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(spaced, (struct sockaddr *)&name, &length) == 0 &&
            strcmp(un->sun_path, "/tmp/init net sock") == 0
        );
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(abstract, (struct sockaddr *)&name, &length) == 0 &&
            strcmp(un->sun_path, "@initnet-abstract") == 0
        );
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(unnamed, (struct sockaddr *)&name, &length) == 0 &&
            un->sun_path[0] == '\0'
        );
        /* An abstract name that fills sun_path, without a NUL, at its full length. */
        (void)close(abstract);
        abstract = socket(AF_UNIX, SOCK_DGRAM, 0);
        memset(bound.sun_path, 'x', sizeof(bound.sun_path));
        bound.sun_path[0] = '\0';
        assert(bind(abstract, (struct sockaddr *)&bound, sizeof(bound)) == 0);
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(abstract, (struct sockaddr *)&name, &length) == 0 &&
            length == (socklen_t)sizeof(bound) && un->sun_path[0] == '@' &&
            memcmp(un->sun_path + 1, bound.sun_path + 1, sizeof(bound.sun_path) - 1U) == 0
        );
        (void)close(spaced);
        (void)close(abstract);
        (void)close(unnamed);
        (void)unlink("/tmp/init net sock");
    }
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
    struct mmsghdr messages[3];
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
        "udp4://127.0.0.1:%u:send:ECONNREFUSED:1.0\n"
        "tcp6://*:0:socket:EMFILE:1.0\n",
        ntohs(server_address.sin_port),
        ntohs(other_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
        ntohs(server_address.sin_port),
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
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 0U, 0, 0, 0))); /* no message */
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)udp, 0U, 1U, 0, 0, 0)));          /* unreadable */
    /* Every message of a batch is looked at, not only the first, as in the library. */
    messages[0].msg_hdr.msg_name = &other_address;
    messages[1].msg_hdr.msg_name = &other_address;
    messages[1].msg_hdr.msg_namelen = sizeof(other_address);
    messages[2].msg_hdr = message;
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 2U, 0, 0, 0)));
    assert(FAILS(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 3U, 0, 0, 0), ECONNREFUSED));
    /* A message without a destination goes to the connection: the client's peer,
     * whose send rule needs @size>10 over the whole batch. */
    memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_iov = vector;
    messages[0].msg_hdr.msg_iovlen = 1U; /* 10 bytes */
    messages[1].msg_hdr.msg_iov = vector;
    messages[1].msg_hdr.msg_iovlen = 1U;
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 1U, 0, 0, 0)));
    assert(FAILS(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 2U, 0, 0, 0), EPIPE));
    messages[1].msg_hdr.msg_iov = (struct iovec *)8; /* unreadable: no size, no @size match */
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 2U, 0, 0, 0)));
    /* A named destination that does not resolve matches nothing: the connection's
     * rule is not used in its place, as in the library. */
    {
        struct sockaddr bad;

        memset(&bad, 0, sizeof(bad));
        bad.sa_family = AF_APPLETALK;
        assert(PASSES(decide(__NR_sendto, (uint64_t)client, P(buffer), 20U, 0, P(&bad), sizeof(bad))
        ));
        message.msg_name = &bad;
        message.msg_namelen = sizeof(bad);
        assert(PASSES(decide(__NR_sendmsg, (uint64_t)client, P(&message), 0, 0, 0, 0)));
    }
    message.msg_name = NULL;
    /* No destination and no peer: matched by the socket's own address, the other end. */
    assert(FAILS(decide(__NR_sendmsg, (uint64_t)udp, P(&message), 0, 0, 0, 0), ECONNREFUSED));

    /* Own address, else peer. */
    assert(FAILS(decide(__NR_shutdown, (uint64_t)server, SHUT_RDWR, 0, 0, 0, 0), ENOTCONN));

    /* The poll family: any socket in the set with a rule. TIMEOUT waits out the
     * call's timeout and returns 0, with nothing ready in the caller's buffers; a
     * wait without a timeout never times out. */
    {
        struct timespec wait = {0, 5000000L};
        struct timespec now = {0, 0L};

        polled[0].fd = pipe_fds[0];
        polled[1].fd = server;
        polled[0].revents = POLLIN;
        polled[1].revents = POLLIN | POLLOUT;
        verdict = decide(__NR_ppoll, P(polled), 2U, P(&wait), 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 5U);
        assert(verdict.returns == 1 && verdict.value == 0);
        assert(polled[0].revents == 0 && polled[1].revents == 0);
        verdict = decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_RETURN && verdict.value == 0);
        assert(PASSES(decide(__NR_ppoll, P(polled), 2U, 0U, 0, 0, 0))); /* no timeout */
        assert(PASSES(decide(__NR_ppoll, P(polled), 1U, P(&wait), 0, 0, 0)));
        assert(PASSES(decide(__NR_ppoll, 0U, 2U, P(&wait), 0, 0, 0)));
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        verdict = decide(__NR_pselect6, (uint64_t)server + 1U, 0U, P(&readable), 0, P(&wait), 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.returns == 1);
        assert(!FD_ISSET(server, &readable));
        FD_SET(server, &readable);
        assert(PASSES(decide(__NR_pselect6, (uint64_t)server + 1U, 0U, P(&readable), 0, 0, 0)));
        assert(FD_ISSET(server, &readable));
#ifdef __NR_select
        {
            struct timeval tick = {0, 1500};

            verdict = decide(__NR_select, (uint64_t)server + 1U, 0U, P(&readable), 0, P(&tick), 0);
            assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 2U);
            assert(!FD_ISSET(server, &readable) && tick.tv_usec == 0);
        }
#endif
#ifdef __NR_poll
        verdict = decide(__NR_poll, P(polled), 2U, 7U, 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 7U);
        assert(PASSES(decide(__NR_poll, P(polled), 2U, (uint64_t)-1, 0, 0, 0)));
#endif
        /* A pollfd array the caller cannot have written to: cleared as far as it goes. */
        {
            struct pollfd *locked =
                mmap(NULL, 4096U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            assert(locked != MAP_FAILED);
            memcpy(locked, polled, 2U * sizeof(*polled));
            locked[1].revents = POLLIN;
            assert(mprotect(locked, 4096U, PROT_READ) == 0);
            verdict = decide(__NR_ppoll, P(locked), 2U, P(&wait), 0, 0, 0);
            assert(verdict.action == CHAOS_INIT_DELAY && locked[1].revents == POLLIN);
            (void)munmap(locked, 4096U);
        }
        now.tv_sec = -1;
        verdict = decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_RETURN);
        now.tv_sec = (time_t)INT32_MAX;
        verdict = decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == (unsigned)INT32_MAX);
    }
    epoll_fd = epoll_create1(0);
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    assert(epoll_fd >= 0 && epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server, &event) == 0);
    assert(
        decide(__NR_epoll_pwait, (uint64_t)epoll_fd, 0, 1U, 0, 0, 0).action == CHAOS_INIT_RETURN
    );
    assert(PASSES(decide(__NR_epoll_pwait, 999U, 0, 1U, 0, 0, 0)));
    assert(PASSES(decide(__NR_epoll_pwait, (uint64_t)epoll_fd, 0, 1U, (uint64_t)-1, 0, 0)));
#ifdef __NR_epoll_pwait2
    {
        struct timespec wait = {0, 3000000L};

        verdict = decide(__NR_epoll_pwait2, (uint64_t)epoll_fd, 0, 1U, P(&wait), 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 3U);
    }
#endif

    /* A process that ended is not counted, and its call runs. */
    g_fail_process = 1;
    assert(PASSES(decide(__NR_listen, (uint64_t)listener, 4U, 0, 0, 0, 0)));
    g_fail_process = 0;

    /* Rules SECCOMP mode cannot apply reject the whole file: data effects, RESET,
     * ERRNO on close. */
    write_rules("*:connect:ECONNREFUSED:1.0\n*:recv:CORRUPT:1.0\n");
    assert(PASSES(
        decide(__NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0)
    ));
    {
        char status[256] = {0};
        FILE *file = fopen("/tmp/.chaos-net.status", "r");

        assert(file != NULL && fread(status, 1U, sizeof(status) - 1U, file) > 0U);
        (void)fclose(file);
        assert(strstr(status, "line=2\nreason=unsupported in seccomp mode\n") != NULL);
    }
    write_rules("*:close:ECONNRESET:1.0\n");
    assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
    write_rules("*:close:RESET:1.0\n");
    assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
    write_rules("*:close:LATENCY:5\n");
    assert(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0).action == CHAOS_INIT_DELAY);

    (void)unlink("/tmp/.chaos-net.conf");
    (void)unlink("/tmp/initnet.sock");
    (void)snprintf(rules, sizeof(rules), "/tmp/.chaos-net.hits.%ld", (long)getpid());
    (void)unlink(rules);
    return 0;
}
