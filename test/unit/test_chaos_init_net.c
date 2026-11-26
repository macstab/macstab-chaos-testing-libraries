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
 * - TRICKLE shortens a receive in the register, CORRUPT flips a bit of what one
 *   delivered and DUP delivers a kept payload again, all through a trace stop;
 * - RESET and ERRNO on close reject the whole rule file in SECCOMP mode.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

static int g_fail_process = 0;
static pid_t g_fake_tgid = 0;
static const char *g_fake_protocol = NULL;
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    if (g_fail_process)
    {
        return -1;
    }
    if (g_fake_tgid != 0)
    {
        /* A process that does not exist: its descriptor table cannot be read, so the
         * ownership of a socket cannot be established. */
        *tgid = g_fake_tgid;
        *start = 0U;
        return 0;
    }
    return chaos_init_process_of(tid, tgid, start);
}
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

/* Seam of the ownership scan (chaos_net_owner.c): a directory it cannot read may hide a
 * holder of the socket, which no test can provoke from outside. With `g_deaf_proc` set,
 * every directory but the one named in `g_own_fd_dir` refuses to open, with EACCES: the
 * errno matters, because ENOENT is the one failure the scan skips instead of counting.
 *
 * `g_lone_proc` is the other direction, and it is what makes these checks independent of
 * the host they run on: every process but this one reports ENOENT, so the scan concludes
 * SOLE whatever else is running. Without it, an ordinary user beside a root process whose
 * descriptors cannot be read -- a CI runner -- gets UNKNOWN and every RESET here is
 * suppressed. That answer is correct, and test_net_owner.c is where it is tested; here it
 * would only hide what these assertions are about. */
static int g_deaf_proc = 0;
static int g_lone_proc = 0;
static char g_own_fd_dir[32] = "";
static int test_owner_open(const char *path)
{
    if (g_deaf_proc && strcmp(path, g_own_fd_dir) != 0)
    {
        errno = EACCES;
        return -1;
    }
    if (g_lone_proc && strcmp(path, "/proc") != 0 && strcmp(path, g_own_fd_dir) != 0)
    {
        errno = ENOENT;
        return -1;
    }
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}
#define CHAOS_NET_OWNER_OPEN(path) test_owner_open(path)

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

/* The seed source lives in chaos_init_core.c, which this test does not include; the
 * declaration comes from chaos_init_core.h, so the definition may follow the include. A
 * fixed value keeps the rules' draw keys the same in every run. */
uint64_t chaos_init_seed(void)
{
    return UINT64_C(0x5eed5eed5eed5eed);
}

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

/** @brief Whether every byte of @p area still holds @p fill, i.e. nothing was corrupted. */
static int untouched(const unsigned char *area, size_t size, unsigned char fill)
{
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        if (area[index] != fill)
        {
            return 0;
        }
    }
    return 1;
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

    /* MPTCP probes. Unresolvable: whenever the kernel offers MPTCP (a fallback connection
     * is never resolvable), never without it. Diag available: only when sock_diag finds the
     * probe's own listener. */
    g_mptcp_absent = 1;
    assert(!chaos_init_net_mptcp_unresolvable());
    assert(!chaos_init_net_mptcp_diag_available());
    g_mptcp_absent = 0;
    assert(chaos_init_net_mptcp_unresolvable());
    assert(!chaos_init_net_mptcp_diag_available()); /* TCP stand-in: no MPTCP socket of it */
    g_test_mptcp_diag = IPPROTO_TCP;
    assert(chaos_init_net_mptcp_unresolvable());
    assert(chaos_init_net_mptcp_diag_available()); /* found when asked as what it is */
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
    /* So is a total above SSIZE_MAX: the call returns ssize_t and the kernel rejects it,
     * and a wrapping sum would have handed `@size>10` a small number for a request larger
     * than the address space. */
    {
        struct iovec huge[2];

        huge[0].iov_base = buffer;
        huge[0].iov_len = (size_t)SSIZE_MAX;
        huge[1].iov_base = buffer;
        huge[1].iov_len = (size_t)SSIZE_MAX;
        assert(PASSES(decide(__NR_writev, (uint64_t)client, P(huge), 2U, 0, 0, 0)));
    }
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

    /* DROP: a datagram send is answered with its byte count and never runs, while the
     * same rule leaves a stream send alone -- the supervisor decides the two cases exactly
     * as the library does. sendmmsg reports a message count, so it is left alone too. */
    (void)snprintf(
        rules, sizeof(rules), "udp4://127.0.0.1:%u:send:DROP:1.0\n", ntohs(udp_address.sin_port)
    );
    write_rules(rules);
    {
        chaos_init_verdict_t dropped = decide(
            __NR_sendto, (uint64_t)udp, P(buffer), 20U, 0, P(&udp_address), sizeof(udp_address)
        );

        assert(dropped.action == CHAOS_INIT_RETURN && dropped.value == 20L);
        memset(messages, 0, sizeof(messages));
        messages[0].msg_hdr.msg_name = &udp_address;
        messages[0].msg_hdr.msg_namelen = sizeof(udp_address);
        assert(PASSES(decide(__NR_sendmmsg, (uint64_t)udp, P(messages), 1U, 0, 0, 0)));
    }
    (void)snprintf(
        rules, sizeof(rules), "tcp4://127.0.0.1:%u:send:DROP:1.0\n", ntohs(server_address.sin_port)
    );
    write_rules(rules);
    assert(PASSES(decide(__NR_write, (uint64_t)server, P(buffer), 8U, 0, 0, 0)));

    /* A `/N` prefix selector works here too: the supervisor reads the sockaddr out of the
     * tracee and matches it with the same code the library uses, so the Docker bridge
     * network a container is given can be named without knowing its address. */
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.0/8:%u:connect:EHOSTUNREACH:1.0\n",
        ntohs(server_address.sin_port)
    );
    write_rules(rules);
    assert(FAILS(
        decide(
            __NR_connect, (uint64_t)unbound, P(&server_address), sizeof(server_address), 0, 0, 0
        ),
        EHOSTUNREACH
    ));
    /* Outside the prefix, nothing matches: the port alone does not carry the rule. */
    {
        struct sockaddr_in outside = server_address;

        assert(inet_pton(AF_INET, "10.1.2.3", &outside.sin_addr) == 1);
        assert(PASSES(decide(__NR_connect, (uint64_t)unbound, P(&outside), sizeof(outside), 0, 0, 0)
        ));
    }

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
     * line: ERRNO on close (would need close and fail at once) and RESET (needs a second
     * call to run inside the tracee). LATENCY on close is allowed. */
    write_rules("*:connect:ECONNREFUSED:1.0\n*:close:ECONNRESET:1.0\n");
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
    /* CORRUPT is applied here too, but only at the exit stop: the entry stop cannot know
     * how many bytes a receive will deliver, so it asks to be called again and draws
     * nothing. Over twelve rounds exactly one byte inside the received length changes each
     * time, nothing beyond it does, and both the byte and its bit vary -- they are drawn.
     * A MSG_TRUNC receive on a stream socket wrote nothing and is left alone, and so is a
     * receive that returned nothing. */
    write_rules("*:recv:CORRUPT:1.0\n");
    {
        unsigned char area[128];
        chaos_init_call_t after;
        size_t round;
        size_t first_offset = sizeof(area);
        unsigned char first_mask = 0U;
        int saw_another = 0;
        int saw_another_bit = 0;

        assert(
            decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        assert(PASSES(decide(__NR_recvmsg, (uint64_t)server, P(&message), 0, 0, 0, 0)));

        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_recvfrom;
        after.args[0] = (uint64_t)server;
        after.args[1] = P(area);
        after.args[2] = sizeof(area);
        /* Nothing delivered: nothing to corrupt and no draw. */
        (void)memset(area, 'A', sizeof(area));
        assert(chaos_init_net_decide_result(&after, 0) == 1);
        assert(chaos_init_net_decide_result(&after, -1) == 1);
        assert(untouched(area, sizeof(area), 'A'));
        /* MSG_TRUNC on a stream socket discards the data instead of writing it. */
        after.args[3] = (uint64_t)MSG_TRUNC;
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(untouched(area, sizeof(area), 'A'));
        /* A receive that reports more than the buffer could hold -- what MSG_TRUNC does on
         * a datagram socket -- with no buffer at all. The byte to corrupt would be drawn
         * out of a length of zero: SIGFPE on x86-64, where the supervisor is PID 1, and a
         * write into a buffer the call never touched on aarch64, which does not trap. */
        {
            chaos_init_call_t empty = after;
            char hits[256] = {0};
            char path[64];
            FILE *file;

            empty.args[2] = 0U;
            empty.args[3] = 0U;
            (void)memset(area, 'A', sizeof(area));
            assert(chaos_init_net_decide_result(&empty, 8) == 1);
            assert(untouched(area, sizeof(area), 'A'));
            /* The buffer alone does not settle it: on aarch64 a modulo by zero yields the
             * dividend rather than trapping, so the byte would be written at a drawn
             * offset far outside this buffer -- somewhere else in the tracee. What both
             * architectures show is the draw itself: the guard sits before it, so no hit
             * may have been counted, and a hit rewrites the file. */
            (void)snprintf(path, sizeof(path), "/tmp/.chaos-net.hits.%ld", (long)getpid());
            file = fopen(path, "r");
            if (file != NULL)
            {
                hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
                (void)fclose(file);
            }
            assert(strstr(hits, "*:recv:CORRUPT:1.0") == NULL);
        }
        after.args[3] = 0U;
        for (round = 0U; round < 12U; ++round)
        {
            size_t index;
            size_t offset = sizeof(area);
            unsigned char mask = 0U;
            int differences = 0;

            (void)memset(area, 'A', sizeof(area));
            assert(chaos_init_net_decide_result(&after, 8) == 1);
            for (index = 0U; index < sizeof(area); ++index)
            {
                const unsigned char changed = (unsigned char)(area[index] ^ 'A');

                if (changed != 0U)
                {
                    ++differences;
                    offset = index;
                    mask = changed;
                    assert(index < 8U);
                    assert((changed & (unsigned char)(changed - 1U)) == 0U);
                }
            }
            assert(differences == 1);
            if (round == 0U)
            {
                first_offset = offset;
                first_mask = mask;
            }
            saw_another = saw_another || offset != first_offset;
            saw_another_bit = saw_another_bit || mask != first_mask;
        }
        assert(saw_another);
        assert(saw_another_bit);

        /* An effect other than CORRUPT can only reach the exit stop if the rule file
         * changed between the two stops. It must do nothing there: the call has already
         * run, and drawing again would charge a hit for an effect nobody can apply. */
        write_rules("*:recv:ECONNRESET:1.0\n");
        (void)memset(area, 'A', sizeof(area));
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(untouched(area, sizeof(area), 'A'));
        /* One real hit through the entry stop, and the two exit-stop calls above added
         * none: a count of three here would mean the guard let them draw. The hits file is
         * rewritten by each hit, so it is current without a flush. */
        assert(FAILS(decide(__NR_recvfrom, (uint64_t)server, P(area), 8U, 0, 0, 0), ECONNRESET));
        {
            char hits[256] = {0};
            char path[64];
            FILE *file;

            (void)snprintf(path, sizeof(path), "/tmp/.chaos-net.hits.%ld", (long)getpid());
            file = fopen(path, "r");
            assert(file != NULL);
            hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
            (void)fclose(file);
            /* The file leads with the tab-free header lines the library writes there
             * (generation, RESET suppressions), so the count line is looked up rather
             * than compared against the whole file. */
            assert(strstr(hits, "\n1\t*:recv:ECONNRESET:1.0\n") != NULL);
        }
    }

    /* TRICKLE is applied here now: the requested length sits in a register, so the filter
     * answers the call with TRACE and the stop shortens it to the chunk. The library's
     * limits hold -- a stream socket only, not MSG_WAITALL, and only a request larger than
     * the chunk -- and the forms that keep their length in memory stay notified. */
    write_rules("*:recv:TRICKLE:4\n");
    {
        const chaos_init_verdict_t shortened =
            decide(__NR_recvfrom, (uint64_t)server, P(buffer), 32U, 0, 0, 0);

        assert(shortened.action == CHAOS_INIT_SHORTEN);
        assert(shortened.arg_index == 2U);
        assert(shortened.value == 4);
    }
    /* read on a socket is a recv, and carries its length in a register too. */
    assert(
        decide(__NR_read, (uint64_t)server, P(buffer), 32U, 0, 0, 0).action == CHAOS_INIT_SHORTEN
    );
    /* A request already within the chunk is left alone, as is MSG_WAITALL. */
    assert(PASSES(decide(__NR_recvfrom, (uint64_t)server, P(buffer), 4U, 0, 0, 0)));
    assert(
        PASSES(decide(__NR_recvfrom, (uint64_t)server, P(buffer), 32U, (uint64_t)MSG_WAITALL, 0, 0))
    );
    /* A datagram socket is left alone: a shorter buffer truncates the datagram. */
    assert(PASSES(decide(__NR_recvfrom, (uint64_t)udp, P(buffer), 32U, 0, 0, 0)));
    /* recvmsg keeps its length in the message, so one argument cannot shorten it. */
    assert(PASSES(decide(__NR_recvmsg, (uint64_t)server, P(&message), 0, 0, 0, 0)));
    /* The traced set names exactly the register-length receives, each once. Three rules on
     * purpose: a second recv rule must not name the same calls twice, and the connect rule
     * must not contribute at all. */
    write_rules("*:recv:TRICKLE:4\n"
                "tcp4://127.0.0.1:9999:recv:TRICKLE:8\n"
                "*:connect:ECONNREFUSED:1.0\n");
    {
        long traced[8];
        const size_t count =
            chaos_init_net_traced_calls(traced, sizeof(traced) / sizeof(traced[0]));
        size_t index;
        int saw_recvfrom = 0;
        int saw_read = 0;
        int saw_recvmsg = 0;

        for (index = 0U; index < count; ++index)
        {
            saw_recvfrom = saw_recvfrom || traced[index] == __NR_recvfrom;
            saw_read = saw_read || traced[index] == __NR_read;
            saw_recvmsg = saw_recvmsg || traced[index] == __NR_recvmsg;
        }
        assert(count == 2U && saw_recvfrom && saw_read && !saw_recvmsg);
        assert(chaos_init_net_traced_calls(traced, 1U) == 1U);
        assert(chaos_init_net_traced_calls(traced, 0U) == 0U);
        assert(chaos_init_net_traced_calls(NULL, 4U) == 0U);
    }
    /* With nothing traced the set is empty, so the filter stays the one it always was. */
    /* DUP keeps what a receive delivered and hands it to the next one: the entry stop
     * lets the call run because nothing is kept yet, the exit stop keeps the bytes, and
     * the next entry stop returns them without the call running. Each payload replays
     * once. Only the replay is a hit -- keeping is not. */
    write_rules("*:recv:DUP:1.0\n");
    {
        unsigned char area[16];
        chaos_init_call_t after;
        chaos_init_verdict_t replay;

        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_recvfrom;
        after.args[0] = (uint64_t)server;
        after.args[1] = P(area);
        after.args[2] = sizeof(area);

        assert(
            decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        /* Nothing delivered is nothing to keep, so the next receive still finds no
         * payload. */
        assert(chaos_init_net_decide_result(&after, 0) == 1);
        assert(
            decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        memcpy(area, "payload!", 8U);
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        (void)memset(area, 'A', sizeof(area));
        replay = decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), 0, 0, 0);
        assert(replay.action == CHAOS_INIT_RETURN && replay.value == 8);
        assert(memcmp(area, "payload!", 8U) == 0 && area[8] == 'A');
        /* Replayed once: the slot is empty, so the next receive runs again. */
        assert(
            decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        /* The forms DUP does not take, each counting no hit: MSG_PEEK (consumes nothing),
         * a zero-length request (a replay into it would read as EOF), recvmsg (its buffer
         * is an iovec) and a descriptor without a socket behind it. */
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(PASSES(decide(__NR_recvfrom, (uint64_t)server, P(area), sizeof(area), MSG_PEEK, 0, 0)
        ));
        assert(PASSES(decide(__NR_recvfrom, (uint64_t)server, P(area), 0, 0, 0, 0)));
        assert(PASSES(decide(__NR_recvmsg, (uint64_t)server, P(&message), 0, 0, 0, 0)));
        {
            char hits[256] = {0};
            char path[64];
            FILE *file;

            (void)snprintf(path, sizeof(path), "/tmp/.chaos-net.hits.%ld", (long)getpid());
            file = fopen(path, "r");
            assert(file != NULL);
            hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
            (void)fclose(file);
            assert(strstr(hits, "\n1\t*:recv:DUP:1.0\n") != NULL);
        }
        /* A buffer the supervisor cannot read keeps nothing, and one it cannot write
         * leaves the verdict at AFTER: the receive runs for real. */
        after.args[1] = 0U;
        after.args[2] = 8U;
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(decide(__NR_recvfrom, (uint64_t)server, 0, 8U, 0, 0, 0).action == CHAOS_INIT_AFTER);
        after.args[1] = P(area);
        after.args[2] = sizeof(area);
        memcpy(area, "payload!", 8U);
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(decide(__NR_recvfrom, (uint64_t)server, 0, 8U, 0, 0, 0).action == CHAOS_INIT_AFTER);
    }
    /* A stream payload longer than the cap is kept cut, a datagram that long is not kept
     * at all: replayed cut it would be another message. */
    {
        static unsigned char wide[CHAOS_INIT_NET_DUP_MAX_BYTES * 2U];
        chaos_init_call_t after;
        chaos_init_verdict_t replay;

        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_read;
        after.args[0] = (uint64_t)server;
        after.args[1] = P(wide);
        after.args[2] = sizeof(wide);
        (void)memset(wide, 'B', sizeof(wide));
        assert(chaos_init_net_decide_result(&after, (long)sizeof(wide)) == 1);
        replay = decide(__NR_read, (uint64_t)server, P(wide), sizeof(wide), 0, 0, 0);
        assert(
            replay.action == CHAOS_INIT_RETURN && replay.value == (long)CHAOS_INIT_NET_DUP_MAX_BYTES
        );

        after.args[0] = (uint64_t)udp;
        assert(chaos_init_net_decide_result(&after, (long)sizeof(wide)) == 1);
        assert(
            decide(__NR_read, (uint64_t)udp, P(wide), sizeof(wide), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
    }
    /* A datagram replay carries the sender address the kept receive reported, truncated to
     * the caller's capacity with the full length reported, as the kernel does. */
    {
        unsigned char area[16];
        struct sockaddr_in sender;
        socklen_t sender_length = sizeof(sender);
        chaos_init_call_t after;
        chaos_init_verdict_t replay;

        sender = udp_address;
        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_recvfrom;
        after.args[0] = (uint64_t)udp;
        after.args[1] = P(area);
        after.args[2] = sizeof(area);
        after.args[4] = P(&sender);
        after.args[5] = P(&sender_length);
        memcpy(area, "datagram", 8U);
        assert(chaos_init_net_decide_result(&after, 8) == 1);

        memset(&sender, 0, sizeof(sender));
        sender_length = sizeof(sender);
        replay = decide(
            __NR_recvfrom, (uint64_t)udp, P(area), sizeof(area), 0, P(&sender), P(&sender_length)
        );
        assert(replay.action == CHAOS_INIT_RETURN && replay.value == 8);
        assert(sender_length == (socklen_t)sizeof(struct sockaddr_in));
        assert(sender.sin_port == udp_address.sin_port);
        /* Room for half the address gets half of it and nothing past that, and the full
         * length is reported all the same. */
        memcpy(area, "datagram", 8U);
        sender_length = sizeof(sender);
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        {
            unsigned char room[sizeof(struct sockaddr_in) * 2U];
            const socklen_t half = (socklen_t)(sizeof(struct sockaddr_in) / 2U);

            (void)memset(room, 'Z', sizeof(room));
            sender_length = half;
            replay = decide(
                __NR_recvfrom, (uint64_t)udp, P(area), sizeof(area), 0, P(room), P(&sender_length)
            );
            assert(replay.action == CHAOS_INIT_RETURN);
            assert(sender_length == (socklen_t)sizeof(struct sockaddr_in));
            assert(memcmp(room, &udp_address, (size_t)half) == 0);
            assert(untouched(room + half, sizeof(room) - (size_t)half, 'Z'));
        }
        /* No room at all for the address: the length is still reported. */
        memcpy(area, "datagram", 8U);
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        sender_length = 0;
        replay = decide(
            __NR_recvfrom, (uint64_t)udp, P(area), sizeof(area), 0, P(&sender), P(&sender_length)
        );
        assert(replay.action == CHAOS_INIT_RETURN);
        assert(sender_length == (socklen_t)sizeof(struct sockaddr_in));
    }
    /* More sockets with a payload at once than there are slots: the oldest gives way, so
     * the newest payloads are the ones that replay. */
    {
        unsigned char area[16];
        int sockets[CHAOS_INIT_NET_DUP_SLOTS + 1U];
        chaos_init_call_t after;
        size_t index;

        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_read;
        after.args[1] = P(area);
        after.args[2] = sizeof(area);
        memcpy(area, "payload!", 8U);
        for (index = 0U; index < sizeof(sockets) / sizeof(sockets[0]); ++index)
        {
            sockets[index] = socket(AF_INET, SOCK_DGRAM, 0);
            assert(sockets[index] >= 0);
            after.args[0] = (uint64_t)sockets[index];
            assert(chaos_init_net_decide_result(&after, 8) == 1);
        }
        /* The first socket's payload was evicted by the last one's. */
        assert(
            decide(__NR_read, (uint64_t)sockets[0], P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        index = sizeof(sockets) / sizeof(sockets[0]) - 1U;
        assert(
            decide(__NR_read, (uint64_t)sockets[index], P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_RETURN
        );
        /* Age decides, not position: the first socket's slot is the newest again once it
         * keeps another payload, so the next store takes the second socket's. */
        memcpy(area, "payload!", 8U);
        after.args[0] = (uint64_t)sockets[0];
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        after.args[0] = (uint64_t)sockets[index];
        assert(chaos_init_net_decide_result(&after, 8) == 1);
        assert(
            decide(__NR_read, (uint64_t)sockets[1], P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_AFTER
        );
        assert(
            decide(__NR_read, (uint64_t)sockets[0], P(area), sizeof(area), 0, 0, 0).action ==
            CHAOS_INIT_RETURN
        );
        for (index = 0U; index < sizeof(sockets) / sizeof(sockets[0]); ++index)
        {
            (void)close(sockets[index]);
        }
    }

    write_rules("*:close:ECONNRESET:1.0\n");
    {
        long traced[8];

        assert(chaos_init_net_traced_calls(traced, sizeof(traced) / sizeof(traced[0])) == 0U);
    }
    assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
    /* RESET aborts the connection, which is a setsockopt(SO_LINGER{1,0}) on the socket
     * before the close -- a call of its own, run inside the tracee, with its argument in
     * the tracee's stack scratch. The close itself still runs, so the verdict is BEFORE
     * and not INSTEAD. Only the close is traced for it: the option needs no register of
     * the call. */
    write_rules("*:close:RESET:1.0\n");
    (void)snprintf(g_own_fd_dir, sizeof(g_own_fd_dir), "/proc/%ld/fd", (long)getpid());
    g_lone_proc = 1;
    {
        long traced[8];
        struct linger expected;
        chaos_init_verdict_t aborting = decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0);

        assert(chaos_init_net_traced_calls(traced, sizeof(traced) / sizeof(traced[0])) == 1U);
        assert(traced[0] == __NR_close);
        assert(aborting.action == CHAOS_INIT_BEFORE);
        assert(aborting.instead_nr == __NR_setsockopt);
        assert(aborting.instead_args[0] == (uint64_t)server);
        assert(aborting.instead_args[1] == (uint64_t)SOL_SOCKET);
        assert(aborting.instead_args[2] == (uint64_t)SO_LINGER);
        assert(aborting.instead_args[4] == sizeof(struct linger));
        assert(aborting.instead_size == (unsigned)sizeof(struct linger));
        assert(aborting.instead_arg == 3U);
        (void)memcpy(&expected, aborting.instead_data, sizeof(expected));
        assert(expected.l_onoff == 1 && expected.l_linger == 0);

        /* A socket a second descriptor still holds is not reset: the option would reset it
         * later, when no rule is looking. The suppression is counted instead of passed
         * over, and spends no hit. A table that cannot be read leaves the ownership
         * unknown, which is counted apart -- that is an environment problem, not a
         * pre-forking server. */
        {
            const int shared_fd = dup(server);

            assert(shared_fd > 2);
            assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
            (void)close(shared_fd);
        }
        g_fake_tgid = 0x7ffffff;
        assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
        g_fake_tgid = 0;
        /* A /proc directory the supervisor cannot read may hide a second holder, so the
         * ownership is unknown rather than sole. */
        g_deaf_proc = 1;
        assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
        g_deaf_proc = 0;
        g_fail_process = 1;
        assert(PASSES(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0)));
        g_fail_process = 0;
        /* The two counts are apart and go into the header lines of the hits file, which
         * chaos-init writes on the hits cadence (chaos_init_rules_t::header) -- a rule
         * that only ever gets suppressed reports nothing otherwise. */
        {
            char header[CHAOS_HITS_HEADER_MAX];
            const char *lines = chaos_net_hits_header(header, sizeof(header));

            assert(lines != NULL);
            assert(strstr(lines, "suppressed.shared=1\n") != NULL);
            assert(strstr(lines, "suppressed.unknown=3\n") != NULL);
        }
    }
    g_lone_proc = 0;
    /* REDIRECT: the address `connect` was given is in the tracee, and a notification
     * answered with CONTINUE makes the kernel read it from there again -- so the verdict
     * carries the new address and the call is let through. Here the tracee is this
     * process, so the write can be read back from the buffer that was passed. */
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.1:%u:connect:REDIRECT:10.0.0.7:5433\n",
        ntohs(server_address.sin_port)
    );
    write_rules(rules);
    {
        struct sockaddr_in wanted = server_address;
        struct in_addr target;
        chaos_net_redirect_t rule_target;
        chaos_init_call_t call;
        chaos_init_verdict_t verdict;

        assert(inet_pton(AF_INET, "10.0.0.7", &target) == 1);
        memset(&rule_target, 0, sizeof(rule_target));
        rule_target.family = AF_INET;
        rule_target.port = 5433U;
        rule_target.value.ipv4 = target;
        memset(&call, 0, sizeof(call));
        call.tid = getpid();
        call.nr = __NR_connect;
        call.args[0] = (uint64_t)unbound;
        call.args[1] = P(&wanted);
        call.args[2] = sizeof(wanted);
        memset(&verdict, 0, sizeof(verdict));
        verdict.action = CHAOS_INIT_FAIL;
        verdict.error = -1;
        assert(chaos_init_net_decide(&call, &verdict) == 1);
        /* The call runs: the kernel is to connect to the address the commit writes. */
        assert(verdict.action == CHAOS_INIT_PASS);
        assert(verdict.redirect_size == sizeof(wanted));
        /* Nothing is written before the notification is confirmed, which the supervisor
         * does between the decision and the commit. */
        assert(wanted.sin_addr.s_addr == server_address.sin_addr.s_addr);
        chaos_init_net_commit(&call, &verdict);
        assert(memcmp(&wanted.sin_addr, &target, sizeof(target)) == 0);
        assert(ntohs(wanted.sin_port) == 5433U);
        /* An address the supervisor cannot read builds nothing. Not reachable through a
         * decision -- the endpoint the rule matched was resolved from that same sockaddr
         * -- so the guard is proved by calling the builder itself, as the io tests prove
         * theirs. */
        {
            unsigned char built[sizeof(struct sockaddr_storage)];
            unsigned built_size = 1U;
            chaos_init_call_t unreadable = call;

            unreadable.args[1] = 8U;
            assert(chaos_init_net_redirect(&unreadable, &rule_target, built, &built_size) == 0);
            assert(built_size == 0U);
            /* And an address that would not fit the length the caller passed. */
            unreadable = call;
            unreadable.args[2] = 1U;
            assert(chaos_init_net_redirect(&unreadable, &rule_target, built, &built_size) == 0);
        }
    }
    /* Each process the supervisor decides for draws with a lineage of its own, or the
     * backends of a pre-forking server would all make the same decision at `p<1`. Serial 1
     * is the application itself and keeps lineage 0, so a single process decides exactly as
     * it would under LD_PRELOAD. */
    {
        chaos_init_net_lineage(1U);
        assert(g_chaos_net_lineage == 0U);
        chaos_init_net_lineage(2U);
        {
            const uint64_t second = g_chaos_net_lineage;

            assert(second != 0U);
            chaos_init_net_lineage(3U);
            assert(g_chaos_net_lineage != second && g_chaos_net_lineage != 0U);
            chaos_init_net_lineage(2U);
            assert(g_chaos_net_lineage == second);
        }
        chaos_init_net_lineage(1U);
    }

    /* A target of the other family fits no sockaddr this socket can pass: the rule does
     * not fire, and the draw is not spent on it. */
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.1:%u:connect:REDIRECT:[2001:db8::7]:5433\n",
        ntohs(server_address.sin_port)
    );
    write_rules(rules);
    {
        struct sockaddr_in wanted = server_address;

        assert(PASSES(decide(__NR_connect, (uint64_t)unbound, P(&wanted), sizeof(wanted), 0, 0, 0))
        );
        assert(wanted.sin_addr.s_addr == server_address.sin_addr.s_addr);
    }

    /* THROTTLE: the same bucket arithmetic as the library's, applied through the
     * registers. Ten bytes per second, so the bucket holds ten and a byte takes 100 ms to
     * arrive -- slow enough that the test does not depend on how fast this machine is. */
    (void)snprintf(
        rules,
        sizeof(rules),
        "tcp4://127.0.0.1:%u:send:THROTTLE:10\n",
        ntohs(server_address.sin_port)
    );
    write_rules(rules);
    {
        chaos_init_verdict_t held;

        /* A full bucket covers the whole send: it passes, and the rule is not even asked,
         * so an allowance that changes nothing spends no hit. */
        assert(PASSES(decide(__NR_write, (uint64_t)server, P(buffer), 7U, 0, 0, 0)));
        /* Three bytes left of the ten: a stream send is shortened to exactly those. */
        held = decide(__NR_write, (uint64_t)server, P(buffer), 10U, 0, 0, 0);
        assert(held.action == CHAOS_INIT_SHORTEN);
        assert(held.arg_index == 2U && held.value == 3L);
        /* Nothing left: the call is parked rather than slept in, so the tracee's other
         * threads keep being served, and the answer when it is due shortens it to the one
         * byte the wait bought.
         *
         * A range, not 100 exactly: the bucket keeps the part of a millisecond it could
         * not turn into a token, so the wait is what is left of the byte's 100 ms after
         * the few milliseconds these calls themselves took. Pinning 100 would pin the
         * loss of that remainder, which is the defect the bucket test now covers. */
        held = decide(__NR_write, (uint64_t)server, P(buffer), 10U, 0, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY);
        assert(held.delay_ms > 50U && held.delay_ms <= 100U);
        assert(held.shortens && held.value == 1L);
        assert(held.arg_index == 2U);
        /* The byte is charged when the call is parked, so the next caller waits for the
         * one after it rather than for the same one: a second wait on top of what is left
         * of the first. Without the charge both would be told 100 ms and the rate would
         * come out double. */
        held = decide(__NR_write, (uint64_t)server, P(buffer), 10U, 0, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY);
        assert(held.delay_ms > 100U && held.delay_ms <= 200U);
        /* sendmsg keeps its length in the message, so no register can shorten it: left
         * alone and charged nothing, as in the library. */
        assert(PASSES(decide(__NR_sendmsg, (uint64_t)server, P(&message), 0, 0, 0, 0)));

        /* A send the rate lets through whole spends neither a hit nor a `@first` claim,
         * as in the library: with `@first=1` the untouched send must leave the claim for
         * the one that is actually held back. */
        (void)snprintf(
            rules,
            sizeof(rules),
            "tcp4://127.0.0.1:%u:send:THROTTLE:13 @first=1\n",
            ntohs(server_address.sin_port)
        );
        write_rules(rules);
        assert(PASSES(decide(__NR_write, (uint64_t)server, P(buffer), 13U, 0, 0, 0)));
        held = decide(__NR_write, (uint64_t)server, P(buffer), 13U, 0, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY && held.shortens);
        (void)snprintf(
            rules,
            sizeof(rules),
            "tcp4://127.0.0.1:%u:send:THROTTLE:10\n",
            ntohs(server_address.sin_port)
        );
        write_rules(rules);
    }
    /* A datagram is never cut -- half a datagram is not a datagram -- so it waits for its
     * whole message and then sends it whole. Five bytes per second: the first message
     * takes three of the five in the bucket, the second waits for the eight it is short
     * of, 1600 ms, and keeps its length. */
    (void)snprintf(
        rules, sizeof(rules), "udp4://127.0.0.1:%u:send:THROTTLE:5\n", ntohs(udp_address.sin_port)
    );
    write_rules(rules);
    {
        chaos_init_verdict_t held = decide(
            __NR_sendto, (uint64_t)udp, P(buffer), 3U, 0, P(&udp_address), sizeof(udp_address)
        );

        assert(PASSES(held));
        held = decide(
            __NR_sendto, (uint64_t)udp, P(buffer), 10U, 0, P(&udp_address), sizeof(udp_address)
        );
        assert(held.action == CHAOS_INIT_DELAY);
        assert(held.delay_ms == 1600U);
        /* And no shortening: the message goes out as the caller wrote it. */
        assert(!held.shortens);
        /* A non-blocking socket is told EAGAIN instead of being parked, as in the
         * library: its event loop is written for that answer. */
        {
            const int impatient = (int)syscall(SYS_socket, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            struct sockaddr_in bound;
            socklen_t bound_length = sizeof(bound);

            assert(impatient > 2);
            memset(&bound, 0, sizeof(bound));
            bound.sin_family = AF_INET;
            bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            assert(bind(impatient, (struct sockaddr *)&bound, sizeof(bound)) == 0);
            assert(getsockname(impatient, (struct sockaddr *)&bound, &bound_length) == 0);
            (void)snprintf(
                rules,
                sizeof(rules),
                "udp4://127.0.0.1:%u:send:THROTTLE:20\n",
                ntohs(bound.sin_port)
            );
            write_rules(rules);
            assert(PASSES(decide(
                __NR_sendto, (uint64_t)impatient, P(buffer), 20U, 0, P(&bound), sizeof(bound)
            )));
            assert(FAILS(
                decide(
                    __NR_sendto, (uint64_t)impatient, P(buffer), 20U, 0, P(&bound), sizeof(bound)
                ),
                EAGAIN
            ));
            (void)close(impatient);
            /* The descriptor is closed now, so its flags cannot be read: that counts as
             * blocking rather than as non-blocking, so a rate holds the call back instead
             * of refusing a socket whose mode nobody knows. */
            assert(chaos_init_net_nonblocking(getpid(), (uint64_t)impatient) == 0);
        }
    }

    write_rules("*:close:LATENCY:5\n");
    assert(decide(__NR_close, (uint64_t)server, 0, 0, 0, 0, 0).action == CHAOS_INIT_DELAY);

    (void)unlink("/tmp/.chaos-net.conf");
    (void)unlink("/tmp/initnet.sock");
    (void)snprintf(rules, sizeof(rules), "/tmp/.chaos-net.hits.%ld", (long)getpid());
    (void)unlink(rules);
    /* A reload without a call: what the inotify watch of chaos_init.c asks for when a
     * rule file is put in place, so that the status file reports the rules before anything
     * has called into them. Two rules, because every file loaded above has one or none: a
     * status that said anything else would mean the reload did nothing. */
    write_rules("*:close:LATENCY:5\n*:connect:ECONNREFUSED:1.0\n");
    chaos_init_net_reload();
    {
        FILE *reloaded = fopen("/tmp/.chaos-net.status", "r");
        char text[256] = {0};

        assert(reloaded != NULL);
        text[fread(text, 1U, sizeof(text) - 1U, reloaded)] = '\0';
        (void)fclose(reloaded);
        assert(strncmp(text, "state=ok\nrules=2\n", strlen("state=ok\nrules=2\n")) == 0);
    }

    return 0;
}
