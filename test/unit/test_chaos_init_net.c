/**
 * @file test_chaos_init_net.c
 * @brief Proves chaos-init resolves the endpoints of a tracee's socket calls without
 *        access to its descriptors, and applies ERRNO, LATENCY and TIMEOUT to them as
 *        libchaos-net would.
 *
 * @details Unit under test: `chaos_init_net_decide()` / `chaos_init_net_commit()` in
 * `src/init/chaos_init_net.c`, compiled in by `#include` with the libchaos-net rule core,
 * its endpoint resolution, `chaos_init_proc.c` and `chaos_init_tracee.c`. The rule core
 * asks descriptors through getsockopt(SO_TYPE)/getsockname()/getpeername() function
 * pointers; chaos-init answers them from the `system.sockprotoname` xattr of
 * `/proc/<pid>/fd/<fd>` and the socket's row (by inode) in `/proc/<pid>/net/{tcp,udp,...}`,
 * or from sock_diag netlink for MPTCP, which no /proc/net table lists.
 *
 * Isolation: no supervisor and no seccomp filter. Real sockets of this process stand in
 * for a tracee's (TCP listener, accepted pair, unbound TCP, bound UDP, bound UNIX, a
 * pipe), so the real /proc and netlink paths run. Calls are `chaos_init_call_t` values
 * with this process as the caller; `decide()` also runs the commit step chaos-init runs
 * after confirming the notification is still live.
 *
 * Seams, all defined before the include:
 * - `CHAOS_INIT_PROCESS_OF`: `g_fail_process` makes the caller unresolvable;
 * - `CHAOS_INIT_NET_GETXATTR`: `g_fake_protocol` overrides the kernel's protocol name;
 *   `g_protocol_lookups` counts lookups to prove the /proc work is skipped when no rule
 *   targets the operation;
 * - `CHAOS_INIT_NET_DIAG_SOCKET`: `g_diag_socket_fails` makes the netlink socket fail;
 * - `CHAOS_INIT_NET_MPTCP_SOCKET` / `CHAOS_INIT_NET_MPTCP_DIAG`: the MPTCP probe uses a
 *   TCP socket (MPTCP may be absent on the test host) and asks sock_diag under protocol
 *   `g_test_mptcp_diag`; `g_mptcp_absent` simulates a kernel without MPTCP.
 *
 * Properties proven:
 * - the SO_TYPE/getsockname/getpeername substitutes answer as the kernel would, for
 *   bound, unbound, IPv6, IPv4-mapped, UNIX (path, spaces, abstract, unnamed) and MPTCP
 *   sockets, with ENOTSOCK, ENOTCONN and ENOPROTOOPT where the kernel returns them;
 * - every way a call names its endpoint reaches the rule core: socket spec, sockaddr
 *   argument, local end, peer, sendto destination, msg_name, sendmmsg batch, pollfd
 *   array, fd_sets, epoll interest list;
 * - read/write/close on a non-socket are left to io (decide returns 0);
 * - a connected socket is matched over both ends in one search, so a wildcard on one end
 *   does not shadow a more specific rule on the other;
 * - batches and wait sets are scanned past non-matching entries, up to 1024 messages
 *   (UIO_MAXIOV) and 1024 descriptors (CHAOS_INIT_NET_MAX_WAIT);
 * - ERRNO gives FAIL, LATENCY gives DELAY; TIMEOUT waits out the call's own timeout
 *   (rounded up to ms, capped at INT32_MAX) and returns 0 with the ready sets cleared at
 *   commit; a wait without a timeout, or with one the kernel would refuse (EINVAL), is
 *   left to the real call;
 * - CORRUPT, RESET and ERRNO on close reject the whole rule file in SECCOMP mode.
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
static unsigned g_protocol_lookups = 0U;
static ssize_t test_getxattr(const char *path, const char *name, void *value, size_t size)
{
    ++g_protocol_lookups;
    if (g_fake_protocol != NULL)
    {
        const size_t length = strlen(g_fake_protocol);

        memcpy(value, g_fake_protocol, length);
        return (ssize_t)length;
    }
    return getxattr(path, name, value, size);
}
#define CHAOS_INIT_NET_GETXATTR test_getxattr

/* Seam: the sock_diag netlink socket is real unless `g_diag_socket_fails` (EACCES). */
static int g_diag_socket_fails = 0;
static int test_diag_socket(void);
#define CHAOS_INIT_NET_DIAG_SOCKET() test_diag_socket()

/* Seam: the MPTCP probe. `g_mptcp_absent` fails it with EPROTONOSUPPORT; otherwise a TCP
 * socket stands in and sock_diag is asked under `g_test_mptcp_diag` (262 = IPPROTO_MPTCP,
 * which the TCP stand-in is not, or IPPROTO_TCP, which finds it). */
static int g_mptcp_absent = 0;
static int g_test_mptcp_diag = 262;
static int test_mptcp_socket(void);
#define CHAOS_INIT_NET_MPTCP_SOCKET() test_mptcp_socket()
#define CHAOS_INIT_NET_MPTCP_DIAG g_test_mptcp_diag

#include "../../src/init/chaos_init_net.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

static int test_mptcp_socket(void)
{
    if (g_mptcp_absent)
    {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    return socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
}

static int test_diag_socket(void)
{
    if (g_diag_socket_fails)
    {
        errno = EACCES;
        return -1;
    }
    return socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
}

#include <arpa/inet.h>
#include <assert.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>

/**
 * @brief Decides net system call @p nr made by this process and commits the verdict;
 *        asserts net owns the call. The verdict is pre-set to FAIL/-1 so a PASS proves
 *        it was written.
 */
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
    memset(&verdict, 0, sizeof(verdict));
    verdict.action = CHAOS_INIT_FAIL;
    verdict.error = -1;
    assert(chaos_init_net_decide(&call, &verdict) == 1);
    /* Mirrors chaos-init: writes into the caller's memory (clearing ready sets) happen
     * only in the commit, after the notification is confirmed still pending. */
    chaos_init_net_commit(&call, &verdict);
    return verdict;
}

/* Functions, not macros: a macro would evaluate the decide() argument twice. */
static int FAILS(chaos_init_verdict_t verdict, int error)
{
    return verdict.action == CHAOS_INIT_FAIL && verdict.error == error;
}

static int PASSES(chaos_init_verdict_t verdict)
{
    return verdict.action == CHAOS_INIT_PASS;
}

#define P(pointer) ((uint64_t)(uintptr_t)(pointer))

/** @brief A TCP or UDP socket bound to 127.0.0.1 on a kernel-chosen port. */
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

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-net.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-net.conf.new", "/tmp/.chaos-net.conf") == 0);
}

/**
 * @brief Address lookup through sock_diag, the path for MPTCP sockets that no /proc/net
 *        table lists.
 *
 * @details Exercised with TCP sockets, whose inet_diag answers have the same layout, so
 * the test does not depend on MPTCP support in the host kernel. The answer parser is also
 * fed hand-built netlink messages for the terminal and malformed cases.
 */
static void test_sock_diag(int listener, int client, const struct sockaddr_in *server_address)
{
    struct sockaddr_storage found;
    struct sockaddr_in *in = (struct sockaddr_in *)&found;
    socklen_t found_length = 0;
    struct stat info;

    /* By inode: the listener's own address (peer 0) and the client's peer (peer 1). */
    assert(fstat(listener, &info) == 0);
    assert(chaos_init_net_diag_name(
        AF_INET, IPPROTO_TCP, (unsigned long)info.st_ino, 0, &found, &found_length
    ));
    assert(in->sin_family == AF_INET && in->sin_port == server_address->sin_port);
    assert(in->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
    assert(found_length == (socklen_t)sizeof(struct sockaddr_in));
    assert(fstat(client, &info) == 0);
    assert(chaos_init_net_diag_name(
        AF_INET, IPPROTO_TCP, (unsigned long)info.st_ino, 1, &found, &found_length
    ));
    assert(in->sin_port == server_address->sin_port);
    /* IPv6: the answer is decoded as sockaddr_in6 with the bound port. */
    {
        struct sockaddr_in6 any6;
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&found;
        const int six = socket(AF_INET6, SOCK_STREAM, 0);

        memset(&any6, 0, sizeof(any6));
        any6.sin6_family = AF_INET6;
        assert(six >= 0 && bind(six, (struct sockaddr *)&any6, sizeof(any6)) == 0);
        assert(listen(six, 1) == 0 && fstat(six, &info) == 0);
        assert(chaos_init_net_diag_name(
            AF_INET6, IPPROTO_TCP, (unsigned long)info.st_ino, 0, &found, &found_length
        ));
        assert(in6->sin6_family == AF_INET6 && in6->sin6_port != 0);
        assert(found_length == (socklen_t)sizeof(struct sockaddr_in6));
        (void)close(six);
    }
    /* An inode no socket has, and a netlink socket that cannot be opened: both 0. */
    assert(!chaos_init_net_diag_name(AF_INET, IPPROTO_TCP, 1UL, 0, &found, &found_length));
    g_diag_socket_fails = 1;
    assert(fstat(listener, &info) == 0);
    assert(!chaos_init_net_diag_name(
        AF_INET, IPPROTO_TCP, (unsigned long)info.st_ino, 0, &found, &found_length
    ));
    g_diag_socket_fails = 0;

    /* Parser: NLMSG_DONE or NLMSG_ERROR ends the dump (-1); a message shorter than an
     * inet_diag_msg, or for another inode, is skipped (0). */
    {
        struct
        {
            struct nlmsghdr header;
            struct inet_diag_msg message;
        } answer;

        memset(&answer, 0, sizeof(answer));
        answer.header.nlmsg_len = (uint32_t)NLMSG_LENGTH(0);
        answer.header.nlmsg_type = NLMSG_DONE;
        assert(
            chaos_init_net_diag_parse(&answer, sizeof(answer), 7UL, 0, &found, &found_length) == -1
        );
        answer.header.nlmsg_type = NLMSG_ERROR;
        assert(
            chaos_init_net_diag_parse(&answer, sizeof(answer), 7UL, 0, &found, &found_length) == -1
        );
        answer.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        assert(
            chaos_init_net_diag_parse(
                &answer, answer.header.nlmsg_len, 7UL, 0, &found, &found_length
            ) == 0
        );
        answer.header.nlmsg_len = (uint32_t)sizeof(answer);
        answer.message.idiag_inode = 8U;
        assert(
            chaos_init_net_diag_parse(&answer, sizeof(answer), 7UL, 0, &found, &found_length) == 0
        );
    }

    /* MPTCP resolvability probe: without MPTCP in the kernel there is nothing to
     * resolve (0); with it, sock_diag must find the probe's own listener, else the
     * sockets are unresolvable (1). */
    g_mptcp_absent = 1;
    assert(!chaos_init_net_mptcp_unresolvable());
    g_mptcp_absent = 0;
    assert(chaos_init_net_mptcp_unresolvable()); /* TCP stand-in: no MPTCP socket of it */
    g_test_mptcp_diag = IPPROTO_TCP;
    assert(!chaos_init_net_mptcp_unresolvable()); /* found when asked as what it is */
    g_test_mptcp_diag = 262;

    /* A socket named "MPTCP" reports SOCK_STREAM and takes its addresses from sock_diag.
     * The socket is really TCP, so sock_diag has no MPTCP entry for its inode and it
     * reads as unbound in the family the name implies (MPTCPv6 -> AF_INET6). */
    {
        socklen_t length = (socklen_t)sizeof(found);
        int type = 0;
        socklen_t type_length = (socklen_t)sizeof(type);

        g_fake_protocol = "MPTCP";
        assert(
            chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
            type == SOCK_STREAM
        );
        assert(chaos_init_net_getsockname(listener, (struct sockaddr *)&found, &length) == 0);
        assert(in->sin_family == AF_INET && in->sin_port == 0);
        g_fake_protocol = "MPTCPv6";
        length = (socklen_t)sizeof(found);
        assert(chaos_init_net_getsockname(listener, (struct sockaddr *)&found, &length) == 0);
        assert(found.ss_family == AF_INET6);
        g_fake_protocol = NULL;
    }
}

/**
 * @brief The getsockopt(SO_TYPE)/getsockname()/getpeername() substitutes chaos-init
 *        gives the rule core, answered from /proc for descriptors of `g_chaos_init_net_tid`.
 */
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

    /* SO_TYPE for TCP and UDP. Any other level or option, a NULL value or length, or a
     * length below sizeof(int) is ENOPROTOOPT; a non-socket is ENOTSOCK. */
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
    assert(
        chaos_init_net_getsockopt(listener, IPPROTO_TCP, SO_TYPE, &type, &length) == -1 &&
        errno == ENOPROTOOPT
    );
    assert(chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_TYPE, NULL, &length) == -1);
    assert(chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_TYPE, &type, NULL) == -1);
    length = (socklen_t)sizeof(type) - 1;
    assert(
        chaos_init_net_getsockopt(listener, SOL_SOCKET, SO_TYPE, &type, &length) == -1 &&
        errno == ENOPROTOOPT
    );

    /* Own address and peer from /proc/<pid>/net/tcp; a listener has no peer (ENOTCONN). */
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

    /* An unbound socket has no /proc row: getsockname reports the unspecified address of
     * its family with the family's full sockaddr length, getpeername fails. */
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unbound, (struct sockaddr *)&name, &length) == 0 &&
        in->sin_family == AF_INET && in->sin_port == 0 &&
        length == (socklen_t)sizeof(struct sockaddr_in)
    );
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getpeername(unbound, (struct sockaddr *)&name, &length) == -1);

    /* UNIX: the bound path from /proc/<pid>/net/unix; the peer is not in /proc, so
     * getpeername fails. */
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unix_fd, (struct sockaddr *)&name, &length) == 0 &&
        un->sun_family == AF_UNIX && strcmp(un->sun_path, "/tmp/initnet.sock") == 0
    );
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getpeername(unix_fd, (struct sockaddr *)&name, &length) == -1);
    /* The path is the rest of the /proc line, so spaces survive; an abstract name reads
     * '@name' (the text libchaos-net uses for it); an unnamed socket reports only the
     * family, as getsockname(2) does. */
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
            length == (socklen_t)sizeof(sa_family_t)
        );
        /* ...so its endpoint text is empty, as in libchaos-net, and no `unix://@` rule
         * can select it. */
        {
            chaos_net_endpoint_t endpoint;

            assert(chaos_net_endpoint_from_local_fd(unnamed, &endpoint));
            assert(endpoint.value.text[0] == '\0');
        }
        /* An abstract name that fills sun_path has no terminating NUL; the reported
         * length is the full sockaddr_un, as getsockname(2) reports it. */
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

    /* Protocol names: an unknown one ("RAW") is not a socket chaos-init resolves; the
     * pre-5.x kernel name "UNIX" maps to AF_UNIX; a failed xattr read gives NULL. */
    g_fake_protocol = "RAW";
    assert(chaos_init_net_protocol(listener) == NULL);
    g_fake_protocol = "UNIX";
    assert(chaos_init_net_protocol(listener)->family == AF_UNIX);
    g_fake_protocol = NULL;
    assert(chaos_init_net_protocol(-1) == NULL);

    /* A protocol name without a `socket:[inode]` link (the pipe) is ENOTSOCK; a UNIX
     * socket absent from /proc/net/unix reads as unnamed. */
    g_fake_protocol = "TCP";
    length = (socklen_t)sizeof(name);
    assert(chaos_init_net_getsockname(pipe_fd, (struct sockaddr *)&name, &length) == -1);
    g_fake_protocol = "UNIX-STREAM";
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(unbound, (struct sockaddr *)&name, &length) == 0 &&
        name.ss_family == AF_UNIX && length == (socklen_t)sizeof(sa_family_t)
    );
    /* A socket closed between the protocol lookup and the inode lookup (fd 999 is not
     * open) is ENOTSOCK; NULL address or length fails. */
    g_fake_protocol = "TCP";
    length = (socklen_t)sizeof(name);
    assert(
        chaos_init_net_getsockname(999, (struct sockaddr *)&name, &length) == -1 &&
        errno == ENOTSOCK
    );
    g_fake_protocol = NULL;
    assert(chaos_init_net_getsockname(listener, NULL, &length) == -1);
    assert(chaos_init_net_getsockname(listener, (struct sockaddr *)&name, NULL) == -1);

    /* IPv6 without needing an IPv6 interface: unbound; bound but unconnected (peer port
     * 0 means ENOTCONN); connected to an IPv4-mapped address of the TCP listener's port
     * (UDP connect needs no listener). */
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&name;
        struct sockaddr_in6 address;
        const int v6_unbound = socket(AF_INET6, SOCK_STREAM, 0);
        const int v6_udp = socket(AF_INET6, SOCK_DGRAM, 0);

        assert(v6_unbound >= 0 && v6_udp >= 0);
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(v6_unbound, (struct sockaddr *)&name, &length) == 0 &&
            in6->sin6_family == AF_INET6 && length == (socklen_t)sizeof(struct sockaddr_in6)
        );
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getpeername(v6_unbound, (struct sockaddr *)&name, &length) == -1 &&
            errno == ENOTCONN
        );
        memset(&address, 0, sizeof(address));
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_any;
        assert(bind(v6_udp, (struct sockaddr *)&address, sizeof(address)) == 0);
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getsockname(v6_udp, (struct sockaddr *)&name, &length) == 0 &&
            in6->sin6_family == AF_INET6 && in6->sin6_port != 0
        );
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getpeername(v6_udp, (struct sockaddr *)&name, &length) == -1 &&
            errno == ENOTCONN
        );
        address.sin6_port = server_address->sin_port;
        address.sin6_addr.s6_addr[10] = 0xffU;
        address.sin6_addr.s6_addr[11] = 0xffU;
        memcpy(&address.sin6_addr.s6_addr[12], &server_address->sin_addr, 4U);
        assert(connect(v6_udp, (struct sockaddr *)&address, sizeof(address)) == 0);
        length = (socklen_t)sizeof(name);
        assert(
            chaos_init_net_getpeername(v6_udp, (struct sockaddr *)&name, &length) == 0 &&
            in6->sin6_port == server_address->sin_port &&
            memcmp(&in6->sin6_addr, &address.sin6_addr, sizeof(address.sin6_addr)) == 0
        );
        (void)close(v6_unbound);
        (void)close(v6_udp);
    }
}

/**
 * @brief The /proc/net address parser: IPv6 is four host-order 32-bit words, and the
 *        hex digit count must be exact (8 for IPv4, 32 for IPv6) with a hex port.
 */
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
    test_sock_diag(listener, client, &server_address);
    test_parse_address();

    /* Not net's: a non-net system call, and the shared read/write/close on a pipe or an
     * unopened fd (no `socket:` link) are left to io. */
    memset(&call, 0, sizeof(call));
    call.tid = getpid();
    call.nr = __NR_getpid;
    assert(chaos_init_net_decide(&call, &verdict) == 0);
    call.nr = __NR_read;
    call.args[0] = (uint64_t)pipe_fds[0];
    assert(chaos_init_net_decide(&call, &verdict) == 0);
    call.args[0] = 999U; /* not open */
    assert(chaos_init_net_decide(&call, &verdict) == 0);

    /* No rule file: every call passes. */
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

    /* socket/socketpair match by (domain, type, protocol); connect/bind by the sockaddr
     * argument. A NULL, zero-length, unreadable or wrong-family sockaddr matches nothing. */
    assert(FAILS(decide(__NR_socket, AF_INET6, SOCK_STREAM, 0, 0, 0, 0), EMFILE));
    assert(PASSES(decide(__NR_socketpair, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0)));
    assert(FAILS(
        decide(
            __NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0
        ),
        ECONNREFUSED
    ));
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, 0U, sizeof(server_address), 0, 0, 0)));
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, P(&server_address), 0U, 0, 0, 0)));
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, 8U, sizeof(server_address), 0, 0, 0)));
    assert(FAILS(
        decide(__NR_bind, (uint64_t)unbound, P(&other_address), sizeof(other_address), 0, 0, 0),
        EADDRINUSE
    ));
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    assert(PASSES(decide(__NR_connect, (uint64_t)unbound, P(&v6), sizeof(v6), 0, 0, 0)));

    /* listen, accept and the recv family match on the local end first, then the peer.
     * read, recvfrom, readv and recvmsg on the accepted socket hit the recv rule. */
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
    /* An iovec array too long or unreadable has unknown size; the recv rule has no
     * `@size`, so it still matches. */
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
    /* The client's local end (ephemeral port) matches no rule; its peer does. */
    assert(decide(__NR_read, (uint64_t)client, P(buffer), 8U, 0, 0, 0).action == CHAOS_INIT_DELAY);
    /* No peer and an unmatched local end: nothing matches. */
    assert(PASSES(decide(__NR_read, (uint64_t)unbound, P(buffer), 8U, 0, 0, 0)));

    /* The send family matches on the peer first, with the byte count for `@size>10`:
     * write/sendto count args[2], writev sums the iovec, sendmsg sums msg_iov. A NULL
     * msghdr has unknown size and does not satisfy `@size`. */
    assert(PASSES(decide(__NR_write, (uint64_t)client, P(buffer), 5U, 0, 0, 0)));
    assert(FAILS(decide(__NR_write, (uint64_t)client, P(buffer), 20U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_writev, (uint64_t)client, P(vector), 2U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_sendto, (uint64_t)client, P(buffer), 20U, 0, 0, 0), EPIPE));
    assert(FAILS(decide(__NR_sendmsg, (uint64_t)client, P(&message), 0, 0, 0, 0), EPIPE));
    assert(PASSES(decide(__NR_sendmsg, (uint64_t)client, 0U, 0, 0, 0, 0))); /* size unknown */
    /* The accepted socket's peer (client port) matches nothing; its local end does. */
    assert(FAILS(decide(__NR_write, (uint64_t)server, P(buffer), 20U, 0, 0, 0), EPIPE));
    /* A socket of a protocol chaos-init does not resolve (netlink): neither end
     * resolves, so nothing matches and the call passes. */
    {
        const int netlink = socket(AF_NETLINK, SOCK_RAW, 0);

        assert(netlink >= 0);
        assert(PASSES(decide(__NR_write, (uint64_t)netlink, P(buffer), 20U, 0, 0, 0)));
        (void)close(netlink);
    }

    /* An explicit destination decides: sendto's dest_addr, sendmsg's msg_name, and
     * sendmmsg's per-message msg_name. vlen 0 sends nothing; an unreadable batch
     * matches nothing (the kernel fails it with EFAULT). */
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
    /* Every message of a batch is scanned, not only the first, as in libchaos-net:
     * messages 0 and 1 name an unmatched port, message 2 the UDP rule's. */
    messages[0].msg_hdr.msg_name = &other_address;
    messages[1].msg_hdr.msg_name = &other_address;
    messages[1].msg_hdr.msg_namelen = sizeof(other_address);
    messages[2].msg_hdr = message;
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 2U, 0, 0, 0)));
    assert(FAILS(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 3U, 0, 0, 0), ECONNREFUSED));
    /* Messages without a destination go to the connection, matched once over both
     * ends; `@size>10` applies to the bytes of the whole batch (10 per message here).
     * One unreadable msg_iov makes the batch size unknown, so `@size` fails. */
    memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_iov = vector;
    messages[0].msg_hdr.msg_iovlen = 1U; /* 10 bytes */
    messages[1].msg_hdr.msg_iov = vector;
    messages[1].msg_hdr.msg_iovlen = 1U;
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 1U, 0, 0, 0)));
    assert(FAILS(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 2U, 0, 0, 0), EPIPE));
    messages[1].msg_hdr.msg_iov = (struct iovec *)8; /* unreadable: no size, no @size match */
    assert(PASSES(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 2U, 0, 0, 0)));
    /* A named destination that does not resolve (AF_APPLETALK) matches nothing; the
     * connection's rule is not used in its place, as in libchaos-net. */
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
    /* No destination and no peer (unconnected UDP): the local end, which the UDP send
     * rule names, decides. */
    assert(FAILS(decide(__NR_sendmsg, (uint64_t)udp, P(&message), 0, 0, 0, 0), ECONNREFUSED));
    /* For a socket whose connection matches nothing, destination-less messages are
     * checked against the connection once, and the scan continues to a message that
     * names a matching destination (index 2). */
    {
        struct sockaddr_in spare_address;
        const int spare = bound_socket(SOCK_DGRAM, &spare_address);

        memset(messages, 0, sizeof(messages));
        messages[2].msg_hdr.msg_name = &udp_address;
        messages[2].msg_hdr.msg_namelen = sizeof(udp_address);
        assert(PASSES(decide(__NR_sendmmsg, (uint64_t)spare, P(messages), 2U, 0, 0, 0)));
        assert(FAILS(decide(__NR_sendmmsg, (uint64_t)spare, P(messages), 3U, 0, 0, 0), ECONNREFUSED)
        );
        /* Connected to an unmatched port from an unmatched port: nothing matches. */
        assert(connect(spare, (struct sockaddr *)&other_address, sizeof(other_address)) == 0);
        assert(PASSES(decide(__NR_read, (uint64_t)spare, P(buffer), 8U, 0, 0, 0)));
        (void)close(spare);
    }
    /* A batch whose byte total would exceed UINT64_MAX / 2 has unknown size instead of
     * wrapping to a small number, so `@size>10` does not match. */
    {
        struct iovec huge;

        huge.iov_base = buffer;
        huge.iov_len = (size_t)(UINT64_MAX / 2U + 1U);
        memset(messages, 0, sizeof(messages));
        messages[0].msg_hdr.msg_iov = vector;
        messages[0].msg_hdr.msg_iovlen = 2U; /* 20 bytes */
        messages[1].msg_hdr.msg_iov = &huge;
        messages[1].msg_hdr.msg_iovlen = 1U;
        assert(FAILS(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 1U, 0, 0, 0), EPIPE));
        assert(PASSES(decide(__NR_sendmmsg, (uint64_t)client, P(messages), 2U, 0, 0, 0)));
    }

    /* shutdown matches the local address if it resolves, else the peer (activity fd). */
    assert(FAILS(decide(__NR_shutdown, (uint64_t)server, SHUT_RDWR, 0, 0, 0, 0), ENOTCONN));

    /* Poll family: the first descriptor in the set with a matching poll rule decides
     * (the pipe at index 0 is skipped). TIMEOUT delays by the call's own timeout and
     * returns 0 with nothing ready; a zero timeout returns at once (RETURN, no DELAY). */
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
        /* decide() writes nothing into the caller; only commit() clears revents, and only
         * when clear_ready is set. Writing earlier could corrupt the memory of a thread
         * that has already moved on (notification no longer valid). */
        {
            chaos_init_call_t wait_call;
            chaos_init_verdict_t decided;

            memset(&wait_call, 0, sizeof(wait_call));
            memset(&decided, 0, sizeof(decided));
            wait_call.tid = getpid();
            wait_call.nr = __NR_ppoll;
            wait_call.args[0] = P(polled);
            wait_call.args[1] = 2U;
            wait_call.args[2] = P(&wait);
            polled[1].revents = POLLIN;
            assert(chaos_init_net_decide(&wait_call, &decided) == 1 && decided.clear_ready);
            assert(polled[1].revents == POLLIN);
            chaos_init_net_commit(&wait_call, &decided);
            assert(polled[1].revents == 0);
            polled[1].revents = POLLIN;
            decided.clear_ready = 0;
            chaos_init_net_commit(&wait_call, &decided);
            assert(polled[1].revents == POLLIN);
        }
        /* No timeout means the wait never times out, so TIMEOUT does not apply; a set
         * without the socket, or an unreadable pollfd array, matches nothing. pselect6
         * clears the fd_set; without a timeout it is untouched. */
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
            /* select: 1500 us rounds up to 2 ms and the commit zeroes the timeval as a
             * real timeout does. No timeout, or an unreadable one, never times out. */
            FD_SET(server, &readable);
            assert(PASSES(decide(__NR_select, (uint64_t)server + 1U, 0U, P(&readable), 0, 0, 0)));
            assert(PASSES(decide(__NR_select, (uint64_t)server + 1U, 0U, P(&readable), 0, 8U, 0)));
            /* A timeval the kernel refuses with EINVAL (negative, or tv_usec >= 10^6) is
             * left to the real call so the caller sees the kernel's error. */
            tick.tv_sec = 0;
            tick.tv_usec = -5;
            assert(
                PASSES(decide(__NR_select, (uint64_t)server + 1U, 0U, P(&readable), 0, P(&tick), 0))
            );
            tick.tv_usec = 1000000L;
            assert(
                PASSES(decide(__NR_select, (uint64_t)server + 1U, 0U, P(&readable), 0, P(&tick), 0))
            );
            assert(FD_ISSET(server, &readable));
        }
#endif
#ifdef __NR_poll
        verdict = decide(__NR_poll, P(polled), 2U, 7U, 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 7U);
        assert(PASSES(decide(__NR_poll, P(polled), 2U, (uint64_t)-1, 0, 0, 0)));
#endif
        /* A read-only pollfd array: process_vm_writev(2) honours page protection, so the
         * clear fails and stops without error; the verdict is unaffected. */
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
        /* Negative descriptors (poll's "ignore this entry") and unmatched sockets are
         * skipped; only the third entry matches. */
        {
            struct pollfd set[3];

            memset(set, 0, sizeof(set));
            set[0].fd = -1;
            set[1].fd = udp;
            set[2].fd = server;
            assert(decide(__NR_ppoll, P(set), 3U, P(&wait), 0, 0, 0).action == CHAOS_INIT_DELAY);
            assert(PASSES(decide(__NR_ppoll, P(set), 2U, P(&wait), 0, 0, 0)));
        }
        /* An unreadable timespec is no timeout; tv_nsec < 0 or >= 10^9 is refused by the
         * kernel (EINVAL) and left to the real call. */
        assert(PASSES(decide(__NR_ppoll, P(polled), 2U, 8U, 0, 0, 0)));
        now.tv_sec = 0;
        now.tv_nsec = -1L;
        assert(PASSES(decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0)));
        now.tv_nsec = 1000000000L;
        assert(PASSES(decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0)));
        now.tv_nsec = 0L;
        /* select sets: nfds 0 reads no set; an unreadable set is skipped while the
         * others are scanned; at most CHAOS_INIT_NET_MAX_WAIT (1024) descriptors are
         * collected across all sets, so the server socket matches as the 1024th entry
         * and is ignored as the 1025th. */
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        assert(PASSES(decide(__NR_pselect6, 0U, P(&readable), 0U, 0, P(&wait), 0)));
        verdict = decide(__NR_pselect6, (uint64_t)server + 1U, 8U, P(&readable), 0, P(&wait), 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.returns == 1);
        {
            fd_set many;
            fd_set last;

            memset(&many, 0xff, sizeof(many));
            FD_CLR(listener, &many);
            FD_CLR(server, &many);
            FD_CLR(client, &many); /* 1021 descriptors that match nothing */
            FD_ZERO(&last);
            FD_SET(0, &last);
            FD_SET(1, &last);
            FD_SET(server, &last); /* the 1024th */
            verdict = decide(__NR_pselect6, FD_SETSIZE, P(&many), P(&last), 0, P(&wait), 0);
            assert(verdict.action == CHAOS_INIT_DELAY);
            memset(&many, 0xff, sizeof(many));
            FD_CLR(listener, &many);
            FD_CLR(server, &many);
            FD_CLR(client, &many);
            FD_ZERO(&last);
            FD_SET(0, &last);
            FD_SET(1, &last);
            FD_SET(2, &last);
            FD_SET(server, &last); /* the 1025th: not looked at */
            assert(PASSES(decide(__NR_pselect6, FD_SETSIZE, P(&many), P(&last), 0, P(&wait), 0)));
        }
        /* A negative tv_sec is EINVAL for the real call; a huge one caps at INT32_MAX ms
         * instead of overflowing the millisecond conversion. */
        now.tv_sec = -1; /* refused by the kernel: the real call reports it */
        assert(PASSES(decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0)));
        now.tv_sec = (time_t)INT32_MAX;
        verdict = decide(__NR_ppoll, P(polled), 2U, P(&now), 0, 0, 0);
        assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == (unsigned)INT32_MAX);
    }
    /* epoll: descriptors come from /proc/<pid>/fdinfo/<epfd> `tfd:` lines. Timeout 0
     * returns at once; an fd that is not an epoll instance matches nothing; -1 waits
     * forever, so TIMEOUT does not apply; epoll_pwait2 takes a timespec. */
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

    /* Fail-open for a vanished caller: the listen rule matches, but with no hit slot the
     * call passes uncounted. */
    g_fail_process = 1;
    assert(PASSES(decide(__NR_listen, (uint64_t)listener, 4U, 0, 0, 0, 0)));
    g_fail_process = 0;

    /* With rules only for connect, recv and poll calls must not touch /proc at all
     * (zero protocol lookups), so a busy event loop costs nothing; connect still does. */
    write_rules("*:connect:ECONNREFUSED:1.0\n");
    polled[0].fd = server;
    polled[1].fd = client;
    g_protocol_lookups = 0U;
    assert(PASSES(decide(__NR_recvfrom, (uint64_t)server, P(buffer), 8U, 0, 0, 0)));
    assert(PASSES(decide(__NR_ppoll, P(polled), 2U, 0, 0, 0, 0)));
    assert(g_protocol_lookups == 0U);
    assert(FAILS(
        decide(
            __NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0
        ),
        ECONNREFUSED
    ));
    assert(g_protocol_lookups > 0U);

    /* Both ends are searched in one pass for the most specific rule: the catch-all that
     * matches the client's local end does not shadow the exact rule for its peer. An
     * unconnected socket still gets the catch-all. */
    (void)snprintf(
        rules,
        sizeof(rules),
        "*:recv:LATENCY:10\ntcp4://127.0.0.1:%u:recv:ECONNRESET:1.0\n",
        ntohs(server_address.sin_port)
    );
    write_rules(rules);
    assert(FAILS(decide(__NR_recvfrom, (uint64_t)client, P(buffer), 8U, 0, 0, 0), ECONNRESET));
    assert(
        decide(__NR_recvfrom, (uint64_t)unbound, P(buffer), 8U, 0, 0, 0).action == CHAOS_INIT_DELAY
    );

    /* Effects SECCOMP mode cannot apply reject the whole rule file, status naming the
     * line: CORRUPT (rewrites received data), ERRNO on close (would need close and fail
     * at once), RESET (needs the socket itself). LATENCY on close is allowed. */
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
