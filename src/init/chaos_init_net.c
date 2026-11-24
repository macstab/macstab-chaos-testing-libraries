/**
 * @file chaos_init_net.c
 * @brief `chaos-init`: libchaos-net rules applied to tracee system calls.
 *
 * @details The libchaos-net rule core (parsing, reload, status file, endpoint selectors,
 * matching, qualifiers) and its endpoint resolution (chaos_net_endpoint.c) are compiled in
 * by `#include`, unchanged. The resolution queries a descriptor through three function
 * pointers that the preload library fills with getsockopt(SO_TYPE), getsockname() and
 * getpeername() as real functions. Here they answer for the tracee's descriptor from
 * outside, because the supervisor cannot hold it: pidfd_getfd() needs CAP_SYS_PTRACE,
 * which Docker's default profile withholds.
 *
 * - **Type:** the socket inode's `system.sockprotoname` xattr, read through
 *   `/proc/<tid>/fd/<fd>` (TCP, UDP, TCPv6, UDPv6, UNIX-STREAM, UNIX-DGRAM, UNIX, MPTCP,
 *   MPTCPv6).
 * - **Addresses:** the socket's row in `/proc/<tid>/net/{tcp,tcp6,udp,udp6,unix}`, found
 *   by inode. These tables follow the tracee's network namespace. MPTCP sockets are in
 *   no table and are looked up through sock_diag instead (as `ss` does), which answers for
 *   the supervisor's namespace, the container's.
 * - **Unbound/unconnected:** no row means the unspecified address and no peer, as
 *   getsockname()/getpeername() would report. A UNIX socket's peer is not in /proc and is
 *   reported as ENOTCONN, so peer selectors never match UNIX sockets.
 *
 * Wait calls scan their descriptors as the library does: the pollfd array and fd_sets
 * from tracee memory, an epoll instance's registered fds from `/proc/<tid>/fdinfo/<epfd>`,
 * at most CHAOS_INIT_NET_MAX_WAIT (1024) per call.
 *
 * @par Supported effects
 * ERRNO (not on close), LATENCY, TIMEOUT on the poll family, DROP on a datagram send, and
 * TRICKLE and CORRUPT through a ptrace stop.
 * DUP needs a payload kept from an earlier call; RESET needs the socket itself (SO_LINGER);
 * ERRNO on close would have to close and fail at once. A rule file with any of them is
 * rejected at parse time via CHAOS_NET_RULE_SUPPORTED (`unsupported in seccomp mode`).
 * DROP needs nothing from the data: the reply carries the byte count and the call does not
 * run, which is the whole effect. It is left to the real call for a stream socket, as in
 * the library, and for `sendmmsg`, whose result is a message count rather than a byte
 * count.
 *
 * @par Cost
 * Endpoint lookups read /proc files per descriptor, so they run only when a loaded rule
 * targets the call's operation (chaos_init_net_targeted()).
 *
 * @par Failure behaviour
 * Fail-open: an unreadable argument, fd or /proc row means no endpoint and no match.
 *
 * @par Thread safety
 * The query callbacks read the tracee tid from a file-scope variable set per decision;
 * the supervisor is single-threaded.
 *
 * Test seams: CHAOS_INIT_NET_GETXATTR, CHAOS_INIT_NET_MPTCP_SOCKET,
 * CHAOS_INIT_NET_MPTCP_DIAG, CHAOS_INIT_NET_DIAG_SOCKET.
 */

#include "chaos_init_net.h"

/** @brief Test seam: the /proc identity lookup, as in chaos_init_tracee.c. */
#ifndef CHAOS_INIT_PROCESS_OF
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) chaos_init_process_of((tid), (tgid), (start))
#endif

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_net_rule;
static int chaos_init_net_supported(const struct chaos_net_rule *rule);
#define CHAOS_NET_RULE_SUPPORTED(rule) chaos_init_net_supported(rule)

#include "../net/chaos_net_actions.c"
#include "../net/chaos_net_config.c"
#include "../net/chaos_net_endpoint.c"
#include "../net/chaos_net_owner.c"
#include "chaos_init_proc.h"
#include "chaos_init_core.h"
#include "chaos_init_tracee.h"

#include <limits.h>
#include <poll.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <sys/random.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/xattr.h>

/**
 * @brief Whether @p rule's effect needs the tracee's registers rather than a reply.
 *
 * @details TRICKLE shortens the requested length before the kernel reads it; CORRUPT
 * changes a byte the receive wrote and DUP keeps the bytes it wrote, both of which need
 * the stop after it; RESET needs a `setsockopt` to run in the tracee before its close. A
 * notification can do none of them. The predicate decides the filter's traced group
 * (chaos_init_net_traced_calls()), so adding an effect here without teaching the trace
 * path to apply it would load a rule that never fires.
 */
static int chaos_init_net_traced_effect(const struct chaos_net_rule *rule)
{
    return rule->effect == CHAOS_NET_EFFECT_TRICKLE || rule->effect == CHAOS_NET_EFFECT_CORRUPT ||
           rule->effect == CHAOS_NET_EFFECT_DUP || rule->effect == CHAOS_NET_EFFECT_RESET;
}

/* CHAOS_NET_RULE_SUPPORTED: ERRNO on anything but close, LATENCY, TIMEOUT, DROP, and the
 * traced effects TRICKLE, CORRUPT, DUP and RESET, which the trace path applies through the
 * registers, the tracee's memory and a call of its own. ERRNO on close stays out: the
 * library closes and then reports the error, which is two answers to one call. */
static int chaos_init_net_supported(const struct chaos_net_rule *rule)
{
    return (rule->effect == CHAOS_NET_EFFECT_ERRNO && rule->operation != CHAOS_NET_OP_CLOSE) ||
           rule->effect == CHAOS_NET_EFFECT_LATENCY || rule->effect == CHAOS_NET_EFFECT_TIMEOUT ||
           rule->effect == CHAOS_NET_EFFECT_DROP || chaos_init_net_traced_effect(rule);
}

/**
 * @brief The tracee thread whose descriptors the query callbacks answer for. Set at the
 *        start of every decision and commit: the callbacks' signatures (fd only) leave no
 *        other way to pass it.
 */
static pid_t g_chaos_init_net_tid = 0;

/** @brief Test seam: the xattr reader for `system.sockprotoname`. */
#ifndef CHAOS_INIT_NET_GETXATTR
#define CHAOS_INIT_NET_GETXATTR getxattr
#endif

/* For libc headers older than MPTCP support (Linux 5.6 UAPI value). */
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

/**
 * @brief Maps the kernel's protocol name (`system.sockprotoname`) to what getsockopt()
 *        and the address lookups need.
 */
typedef struct chaos_init_net_protocol
{
    const char *name;  /**< system.sockprotoname */
    int type;          /**< SOCK_STREAM or SOCK_DGRAM */
    int family;        /**< AF_INET, AF_INET6 or AF_UNIX */
    const char *table; /**< /proc/<pid>/net/<table>; NULL: asked through sock_diag */
    int diag;          /**< The protocol to ask sock_diag for when there is no table. */
} chaos_init_net_protocol_t;

static const chaos_init_net_protocol_t g_chaos_init_net_protocols[] = {
    {"TCP", SOCK_STREAM, AF_INET, "tcp", 0},
    {"UDP", SOCK_DGRAM, AF_INET, "udp", 0},
    {"TCPv6", SOCK_STREAM, AF_INET6, "tcp6", 0},
    {"UDPv6", SOCK_DGRAM, AF_INET6, "udp6", 0},
    {"UNIX-STREAM", SOCK_STREAM, AF_UNIX, "unix", 0},
    {"UNIX-DGRAM", SOCK_DGRAM, AF_UNIX, "unix", 0},
    {"UNIX", SOCK_STREAM, AF_UNIX, "unix", 0}, /* kernels before 5.x name every UNIX socket so */
    /* Multipath TCP (Go 1.24+ listens with it by default): a stream socket in no
     * /proc/net table, looked up through sock_diag. */
    {"MPTCP", SOCK_STREAM, AF_INET, NULL, IPPROTO_MPTCP},
    {"MPTCPv6", SOCK_STREAM, AF_INET6, NULL, IPPROTO_MPTCP},
};

/** @brief Test seams of the MPTCP probes (chaos_init_net_mptcp_unresolvable(),
 *         chaos_init_net_mptcp_diag_available()): the probe socket, and the protocol
 *         sock_diag is asked for (unit tests force either outcome). */
#ifndef CHAOS_INIT_NET_MPTCP_SOCKET
#define CHAOS_INIT_NET_MPTCP_SOCKET() socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_MPTCP)
#endif
#ifndef CHAOS_INIT_NET_MPTCP_DIAG
#define CHAOS_INIT_NET_MPTCP_DIAG IPPROTO_MPTCP
#endif

/** @brief Test seam: the NETLINK_SOCK_DIAG socket; unit tests make its creation fail. */
#ifndef CHAOS_INIT_NET_DIAG_SOCKET
#define CHAOS_INIT_NET_DIAG_SOCKET() socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG)
#endif

/**
 * @brief Scans one recv() worth (@p length bytes) of a sock_diag dump for socket @p inode
 *        and stores its own address (@p peer 0) or its peer's in @p found.
 *
 * @details inet_diag_msg carries addresses as four 32-bit words in network order and
 * ports in network order, so they are copied into the sockaddr unchanged. Messages
 * shorter than inet_diag_msg are skipped.
 *
 * @return 1 found; 0 not in this chunk (read the next); -1 the dump ended (NLMSG_DONE)
 *         or failed (NLMSG_ERROR).
 */
static int chaos_init_net_diag_parse(
    const void *answer,
    size_t length,
    unsigned long inode,
    int peer,
    struct sockaddr_storage *found,
    socklen_t *found_length
)
{
    const struct nlmsghdr *header = answer;
    int left = (int)length;

    for (; NLMSG_OK(header, left); header = NLMSG_NEXT(header, left))
    {
        const struct inet_diag_msg *message = NLMSG_DATA(header);
        const uint32_t *address;

        if (header->nlmsg_type == NLMSG_DONE || header->nlmsg_type == NLMSG_ERROR)
        {
            return -1;
        }
        if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*message)) || message->idiag_inode != inode)
        {
            continue;
        }
        address = peer ? message->id.idiag_dst : message->id.idiag_src;
        memset(found, 0, sizeof(*found));
        if (message->idiag_family == AF_INET6)
        {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)found;

            in6->sin6_family = AF_INET6;
            in6->sin6_port = peer ? message->id.idiag_dport : message->id.idiag_sport;
            memcpy(&in6->sin6_addr, address, sizeof(in6->sin6_addr));
            *found_length = (socklen_t)sizeof(*in6);
        }
        else
        {
            struct sockaddr_in *in = (struct sockaddr_in *)found;

            in->sin_family = AF_INET;
            in->sin_port = peer ? message->id.idiag_dport : message->id.idiag_sport;
            in->sin_addr.s_addr = address[0];
            *found_length = (socklen_t)sizeof(*in);
        }
        return 1;
    }
    return 0;
}

/**
 * @brief Looks up the own address (@p peer 0) or peer of socket @p inode through a
 *        sock_diag dump (SOCK_DIAG_BY_FAMILY, all states), as `ss` does: for sockets no
 *        /proc/net table lists.
 *
 * @details The 8-bit sdiag_protocol cannot hold IPPROTO_MPTCP (262), so the protocol also
 * goes in an INET_DIAG_REQ_PROTOCOL attribute (5.10+), with sdiag_protocol 0 for values
 * >= 256. The dump covers the supervisor's network namespace, which is the container's;
 * a tracee in a namespace of its own is not found. A netlink socket is opened and closed
 * per lookup. The 16 KiB static receive buffer makes this non-reentrant.
 *
 * @return 1 with the address in @p found, else 0 (not found, or any netlink failure).
 */
static int chaos_init_net_diag_name(
    int family,
    int protocol,
    unsigned long inode,
    int peer,
    struct sockaddr_storage *found,
    socklen_t *found_length
)
{
    static long answer[2048];
    struct
    {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
        struct rtattr attribute;
        uint32_t protocol;
    } query;
    const int link = CHAOS_INIT_NET_DIAG_SOCKET();
    int result = 0;
    ssize_t length;

    if (link < 0)
    {
        return 0;
    }
    memset(&query, 0, sizeof(query));
    query.header.nlmsg_len = (uint32_t)sizeof(query);
    query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    query.request.sdiag_family = (uint8_t)family;
    query.request.sdiag_protocol = (uint8_t)(protocol < 256 ? protocol : 0);
    query.request.idiag_states = ~0U;
    query.attribute.rta_len = (unsigned short)RTA_LENGTH(sizeof(query.protocol));
    query.attribute.rta_type = INET_DIAG_REQ_PROTOCOL;
    query.protocol = (uint32_t)protocol;
    if (send(link, &query, sizeof(query), 0) == (ssize_t)sizeof(query))
    {
        while (result == 0 && (length = recv(link, answer, sizeof(answer), 0)) > 0)
        {
            result =
                chaos_init_net_diag_parse(answer, (size_t)length, inode, peer, found, found_length);
        }
    }
    (void)close(link);
    return result > 0;
}

/**
 * @brief The protocol entry of descriptor @p fd of g_chaos_init_net_tid, from the socket's
 *        `system.sockprotoname` xattr (getxattr() follows the /proc fd magic link to the
 *        socket inode). @return NULL for a non-socket or an unlisted protocol.
 */
static const chaos_init_net_protocol_t *chaos_init_net_protocol(int fd)
{
    char path[64];
    char name[32];
    ssize_t length;
    size_t index;

    (void)snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)g_chaos_init_net_tid, fd);
    length = CHAOS_INIT_NET_GETXATTR(path, "system.sockprotoname", name, sizeof(name) - 1U);
    if (length <= 0)
    {
        return NULL;
    }
    name[length] = '\0';
    for (index = 0U;
         index < sizeof(g_chaos_init_net_protocols) / sizeof(g_chaos_init_net_protocols[0]);
         ++index)
    {
        if (strcmp(name, g_chaos_init_net_protocols[index].name) == 0)
        {
            return &g_chaos_init_net_protocols[index];
        }
    }
    return NULL;
}

/** @brief Socket inode of descriptor @p fd of g_chaos_init_net_tid (`socket:[N]`); 0 if none. */
static unsigned long chaos_init_net_inode(int fd)
{
    char name[32];
    char link[64];
    unsigned long inode = 0U;

    (void)snprintf(name, sizeof(name), "fd/%d", fd);
    if (chaos_init_proc_link(g_chaos_init_net_tid, name, link, sizeof(link)) <= 0 ||
        sscanf(link, "socket:[%lu]", &inode) != 1)
    {
        return 0U;
    }
    return inode;
}

/**
 * @brief Parses a `/proc/net/{tcp,udp}{,6}` address column: `0100007F:1F90`, or 32 hex
 *        digits for IPv6.
 *
 * @details The kernel prints each 32-bit address word as the hex of its in-memory value
 * (%08X of a __be32 read as a host integer), so parsing the hex back yields the exact
 * bytes of s_addr / each s6_addr word. The port is printed in host order and gets htons().
 *
 * @return 1 with the address in @p out; 0 on a malformed column.
 */
static int chaos_init_net_parse_address(
    const char *text, int family, struct sockaddr_storage *out, socklen_t *length
)
{
    char word[9];
    unsigned port = 0U;
    const char *colon = strchr(text, ':');
    size_t digits = colon != NULL ? (size_t)(colon - text) : 0U;
    size_t index;

    memset(out, 0, sizeof(*out));
    if (colon == NULL || sscanf(colon + 1, "%x", &port) != 1 ||
        digits != (family == AF_INET ? 8U : 32U))
    {
        return 0;
    }
    if (family == AF_INET)
    {
        struct sockaddr_in *in = (struct sockaddr_in *)out;

        memcpy(word, text, 8U);
        word[8] = '\0';
        in->sin_family = AF_INET;
        in->sin_port = htons((uint16_t)port);
        in->sin_addr.s_addr = (uint32_t)strtoul(word, NULL, 16);
        *length = (socklen_t)sizeof(*in);
        return 1;
    }
    {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)out;

        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons((uint16_t)port);
        for (index = 0U; index < 4U; ++index)
        {
            uint32_t value;

            memcpy(word, text + index * 8U, 8U);
            word[8] = '\0';
            value = (uint32_t)strtoul(word, NULL, 16);
            memcpy(&in6->sin6_addr.s6_addr[index * 4U], &value, sizeof(value));
        }
        *length = (socklen_t)sizeof(*in6);
        return 1;
    }
}

/**
 * @brief Emulates getsockname() (@p peer 0) or getpeername() (@p peer 1) for descriptor
 *        @p fd of g_chaos_init_net_tid, from its row in `/proc/<tid>/net/<table>` (found
 *        by inode) or, for MPTCP, from sock_diag.
 *
 * @details Semantics follow the real calls: @p address receives at most *@p length bytes
 * and *@p length the full size. Not found as own address: the family's unspecified
 * address (an unbound socket). Peer not found, port 0, or any UNIX socket: ENOTCONN.
 *
 * @return 0, or -1 with errno ENOTSOCK (not a known socket, or NULL arguments) or
 *         ENOTCONN.
 */
static int chaos_init_net_name(int fd, struct sockaddr *address, socklen_t *length, int peer)
{
    const chaos_init_net_protocol_t *protocol = chaos_init_net_protocol(fd);
    const unsigned long inode = protocol != NULL ? chaos_init_net_inode(fd) : 0U;
    struct sockaddr_storage found;
    socklen_t found_length = 0;
    char path[64];
    char line[512];
    int have = 0;
    FILE *table;

    if (inode == 0U || address == NULL || length == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }
    memset(&found, 0, sizeof(found));
    if (protocol->table == NULL)
    {
        have = chaos_init_net_diag_name(
            protocol->family, protocol->diag, inode, peer, &found, &found_length
        );
        table = NULL;
    }
    else
    {
        (void)snprintf(
            path, sizeof(path), "/proc/%ld/net/%s", (long)g_chaos_init_net_tid, protocol->table
        );
        table = fopen(path, "r");
    }
    while (table != NULL && !have && fgets(line, sizeof(line), table) != NULL)
    {
        char local[64];
        char remote[64];
        unsigned long row_inode = 0U;
        int end = 0;

        /* IP tables: sl local rem st tx:rx tr:tm retrnsmt uid timeout inode; the header
         * line fails either scan. */
        if (protocol->family == AF_UNIX)
        {
            /* Columns: Num RefCount Protocol Flags Type St Inode Path. The path is the rest
             * of the line, spaces included; an abstract name shows as '@name', the same
             * text the library derives for it. */
            if (sscanf(line, "%*s %*s %*s %*s %*s %*s %lu%n", &row_inode, &end) >= 1 &&
                row_inode == inode)
            {
                struct sockaddr_un *un = (struct sockaddr_un *)&found;
                const char *name = line + end + (line[end] == ' ' ? 1 : 0);
                const size_t name_length = strcspn(name, "\n") < sizeof(un->sun_path)
                                               ? strcspn(name, "\n")
                                               : sizeof(un->sun_path);

                /* Length as getsockname() reports it: family only for an unnamed socket,
                 * a terminating NUL counted unless the name fills sun_path. */
                un->sun_family = AF_UNIX;
                memcpy(un->sun_path, name, name_length);
                found_length =
                    (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_length +
                                (name_length > 0U && name_length < sizeof(un->sun_path) ? 1U : 0U));
                have = 1;
            }
        }
        else if (sscanf(
                     line, "%*s %63s %63s %*s %*s %*s %*s %*s %*s %lu", local, remote, &row_inode
                 ) == 3 &&
                 row_inode == inode)
        {
            have = chaos_init_net_parse_address(
                peer ? remote : local, protocol->family, &found, &found_length
            );
        }
    }
    if (table != NULL)
    {
        (void)fclose(table);
    }
    if (peer)
    {
        /* A UNIX peer is not in /proc; an IP peer with port 0 means not connected. */
        const struct sockaddr_in *in = (const struct sockaddr_in *)&found;
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)&found;

        if (!have || protocol->family == AF_UNIX ||
            (protocol->family == AF_INET && in->sin_port == 0) ||
            (protocol->family == AF_INET6 && in6->sin6_port == 0))
        {
            errno = ENOTCONN;
            return -1;
        }
    }
    else if (!have)
    {
        /* No row: not bound yet, so the unspecified address of its family. */
        found.ss_family = (sa_family_t)protocol->family;
        found_length = protocol->family == AF_INET    ? (socklen_t)sizeof(struct sockaddr_in)
                       : protocol->family == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6)
                                                      : (socklen_t)sizeof(sa_family_t);
    }
    memcpy(address, &found, (size_t)(found_length < *length ? found_length : *length));
    *length = found_length;
    return 0;
}

/* The three "real functions" handed to the endpoint resolution (see the file header). */
static int chaos_init_net_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    return chaos_init_net_name(fd, address, length, 0);
}

static int chaos_init_net_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    return chaos_init_net_name(fd, address, length, 1);
}

/* Emulates getsockopt(SOL_SOCKET, SO_TYPE) only: ENOPROTOOPT for any other option or a
 * buffer under sizeof(int), ENOTSOCK for a non-socket. */
static int chaos_init_net_getsockopt(int fd, int level, int name, void *value, socklen_t *length)
{
    const chaos_init_net_protocol_t *protocol;

    if (level != SOL_SOCKET || name != SO_TYPE || value == NULL || length == NULL ||
        *length < (socklen_t)sizeof(int))
    {
        errno = ENOPROTOOPT;
        return -1;
    }
    protocol = chaos_init_net_protocol(fd);
    if (protocol == NULL)
    {
        errno = ENOTSOCK;
        return -1;
    }
    memcpy(value, &protocol->type, sizeof(int));
    *length = (socklen_t)sizeof(int);
    return 0;
}

/* Symbols the rule core expects from the preload library: the real functions point at
 * the /proc emulations above; the seed is replaced from getrandom() at start. */
chaos_net_getsockname_fn g_chaos_net_real_getsockname = chaos_init_net_getsockname;
chaos_net_getpeername_fn g_chaos_net_real_getpeername = chaos_init_net_getpeername;
chaos_net_getsockopt_fn g_chaos_net_real_getsockopt = chaos_init_net_getsockopt;
__thread int g_chaos_net_tls_guard = 0;
uint64_t g_chaos_net_lineage = 0U;
uint64_t g_chaos_net_process_seed = UINT64_C(0x9e3779b97f4a7c15);

/** @brief Whether the tracee's descriptor @p fd is a datagram socket; 0 when unknown. */
static int chaos_init_net_is_datagram(uint64_t fd)
{
    const chaos_init_net_protocol_t *protocol = chaos_init_net_protocol((int)fd);

    return protocol != NULL && protocol->type == SOCK_DGRAM;
}

/** @brief Whether the tracee's descriptor @p fd is a stream socket; 0 when unknown. */
static int chaos_init_net_is_stream(uint64_t fd)
{
    const chaos_init_net_protocol_t *protocol = chaos_init_net_protocol((int)fd);

    return protocol != NULL && protocol->type == SOCK_STREAM;
}

/** @brief How a system call names the socket(s) it acts on, i.e. which endpoint is matched. */
typedef enum chaos_init_net_kind
{
    CHAOS_INIT_NET_SPEC,     /**< socket()/socketpair(): domain, type, protocol. */
    CHAOS_INIT_NET_ADDRESS,  /**< bind()/connect(): fd, sockaddr, length. */
    CHAOS_INIT_NET_LOCAL,    /**< Own address first, then the peer. */
    CHAOS_INIT_NET_PEER,     /**< Peer first, then the own address. */
    CHAOS_INIT_NET_ACTIVITY, /**< Own address, else the peer. */
    CHAOS_INIT_NET_SENDTO,   /**< sendto(): the destination argument, else the peer. */
    CHAOS_INIT_NET_SENDMSG,  /**< sendmsg(): msg_name, else the peer. */
    CHAOS_INIT_NET_SENDMMSG, /**< sendmmsg(): the first message whose msg_name or peer matches. */
    CHAOS_INIT_NET_POLL,     /**< poll()/ppoll(): every descriptor of the pollfd array. */
    CHAOS_INIT_NET_SELECT,   /**< select()/pselect6(): every descriptor of the sets. */
    CHAOS_INIT_NET_EPOLL     /**< epoll_wait()/epoll_pwait(): the instance's descriptors. */
} chaos_init_net_kind_t;

/** @brief One row of the net decode table: system call number to wrapper semantics. */
typedef struct chaos_init_net_call
{
    long nr;
    chaos_net_operation_t operation;
    chaos_init_net_kind_t kind;
    int shared; /**< Also an io call: a net call only on a socket. */
    int size;   /**< Argument index of the byte count; -1 none, -2 iovec (args 1-2),
                     -3 a msghdr (arg 1), -4 an mmsghdr batch (args 1-2). */
} chaos_init_net_call_t;

/* Must list exactly the numbers of g_chaos_init_net_calls in chaos_init_core.c. */
static const chaos_init_net_call_t g_chaos_init_net_calls[] = {
    {__NR_socket, CHAOS_NET_OP_SOCKET, CHAOS_INIT_NET_SPEC, 0, -1},
    {__NR_socketpair, CHAOS_NET_OP_SOCKET, CHAOS_INIT_NET_SPEC, 0, -1},
    {__NR_bind, CHAOS_NET_OP_BIND, CHAOS_INIT_NET_ADDRESS, 0, -1},
    {__NR_connect, CHAOS_NET_OP_CONNECT, CHAOS_INIT_NET_ADDRESS, 0, -1},
    {__NR_listen, CHAOS_NET_OP_LISTEN, CHAOS_INIT_NET_LOCAL, 0, -1},
    {__NR_accept4, CHAOS_NET_OP_ACCEPT, CHAOS_INIT_NET_LOCAL, 0, -1},
    {__NR_shutdown, CHAOS_NET_OP_SHUTDOWN, CHAOS_INIT_NET_ACTIVITY, 0, -1},
    {__NR_sendto, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_SENDTO, 0, 2},
    {__NR_sendmsg, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_SENDMSG, 0, -3},
    {__NR_sendmmsg, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_SENDMMSG, 0, -4},
    {__NR_recvfrom, CHAOS_NET_OP_RECV, CHAOS_INIT_NET_LOCAL, 0, 2},
    {__NR_recvmsg, CHAOS_NET_OP_RECV, CHAOS_INIT_NET_LOCAL, 0, -3},
    {__NR_recvmmsg, CHAOS_NET_OP_RECV, CHAOS_INIT_NET_LOCAL, 0, -1},
    {__NR_read, CHAOS_NET_OP_RECV, CHAOS_INIT_NET_LOCAL, 1, 2},
    {__NR_readv, CHAOS_NET_OP_RECV, CHAOS_INIT_NET_LOCAL, 1, -2},
    {__NR_write, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_PEER, 1, 2},
    {__NR_writev, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_PEER, 1, -2},
    {__NR_close, CHAOS_NET_OP_CLOSE, CHAOS_INIT_NET_ACTIVITY, 1, -1},
    {__NR_ppoll, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_POLL, 0, -1},
    {__NR_pselect6, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_SELECT, 0, -1},
    {__NR_epoll_pwait, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_EPOLL, 0, -1},
#ifdef __NR_accept
    {__NR_accept, CHAOS_NET_OP_ACCEPT, CHAOS_INIT_NET_LOCAL, 0, -1},
#endif
#ifdef __NR_poll
    {__NR_poll, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_POLL, 0, -1},
#endif
#ifdef __NR_select
    {__NR_select, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_SELECT, 0, -1},
#endif
#ifdef __NR_epoll_wait
    {__NR_epoll_wait, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_EPOLL, 0, -1},
#endif
#ifdef __NR_epoll_pwait2
    {__NR_epoll_pwait2, CHAOS_NET_OP_POLL, CHAOS_INIT_NET_EPOLL, 0, -1},
#endif
};

/**
 * @brief Whether @p rule needs a trace stop for @p entry in particular.
 *
 * @details TRICKLE, CORRUPT and DUP need the length or the buffer in a register, which
 * recvmsg and the batches keep in memory: they stay notified, as the library leaves them
 * alone too. RESET needs no register of the close, only a stop to run a `setsockopt`
 * before it.
 */
static int
chaos_init_net_traced_call(const struct chaos_net_rule *rule, const chaos_init_net_call_t *entry)
{
    if (rule->operation != entry->operation)
    {
        return 0;
    }
    return rule->effect == CHAOS_NET_EFFECT_RESET || entry->size >= 0;
}

/** @copydoc chaos_init_net_traced_calls */
size_t chaos_init_net_traced_calls(long *out, size_t capacity)
{
    const chaos_net_config_state_t *state;
    size_t count = 0U;
    size_t rule_index;

    if (out == NULL || !chaos_net_config_prepare())
    {
        return 0U;
    }
    state = chaos_net_config_active_state();
    for (rule_index = 0U; rule_index < state->rule_count; ++rule_index)
    {
        size_t entry;

        if (!chaos_init_net_traced_effect(&state->rules[rule_index]))
        {
            continue;
        }
        for (entry = 0U; entry < sizeof(g_chaos_init_net_calls) / sizeof(g_chaos_init_net_calls[0]);
             ++entry)
        {
            size_t seen;

            if (!chaos_init_net_traced_call(
                    &state->rules[rule_index], &g_chaos_init_net_calls[entry]
                ))
            {
                continue;
            }
            for (seen = 0U; seen < count; ++seen)
            {
                if (out[seen] == g_chaos_init_net_calls[entry].nr)
                {
                    break;
                }
            }
            if (seen < count)
            {
                continue;
            }
            if (count == capacity)
            {
                return count;
            }
            out[count++] = g_chaos_init_net_calls[entry].nr;
        }
    }
    return count;
}

/* Per-process hit slots of the net rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_net, CHAOS_NET_MAX_RULES);

static uint64_t g_chaos_init_net_load = 0U;
static const chaos_net_config_state_t *g_chaos_init_net_seen_state = NULL;
static uint64_t g_chaos_init_net_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for net; reload detection as in chaos_init_io.c. */
static size_t chaos_init_net_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();

    if (g_chaos_init_net_load == 0U || state != g_chaos_init_net_seen_state ||
        g_chaos_net_cached_mtime != g_chaos_init_net_seen_stamp)
    {
        g_chaos_init_net_seen_state = state;
        g_chaos_init_net_seen_stamp = g_chaos_net_cached_mtime;
        ++g_chaos_init_net_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_net_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_net_rules = {
    CHAOS_NET_HITS_PREFIX,
    CHAOS_NET_MAX_RULES,
    chaos_init_net_snapshot,
    /* The same header the library writes: the reload generation, and the RESET
     * suppressions, which are the one thing a rule reports without a hit. */
    chaos_net_hits_header,
    g_chaos_init_net_slots,
    g_chaos_init_net_hashes,
    g_chaos_init_net_generation,
    g_chaos_init_net_count,
    g_chaos_init_net_total,
    g_chaos_init_net_pending,
    g_chaos_init_net_buffer,
    g_chaos_init_net_file,
};

void chaos_init_net_start(void)
{

    chaos_net_config_init();
    g_chaos_net_process_seed = chaos_init_seed();
    (void)chaos_init_tracee_register(&g_chaos_init_net_rules);
}

/**
 * @brief Total bytes of an iovec array of g_chaos_init_net_tid, for `@size`; more than
 *        1024 entries (UIO_MAXIOV) or an unreadable array yields CHAOS_POLICY_NO_SIZE.
 */
static uint64_t chaos_init_net_iov_size(uint64_t address, uint64_t count)
{
    struct iovec vector[64];
    uint64_t total = 0U;
    uint64_t done = 0U;

    if (count > 1024U)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    while (done < count)
    {
        const uint64_t chunk = count - done < 64U ? count - done : 64U;
        uint64_t index;

        if (chaos_init_read_memory(
                g_chaos_init_net_tid,
                address + done * sizeof(struct iovec),
                vector,
                chunk * sizeof(struct iovec)
            ) != 0)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        for (index = 0U; index < chunk; ++index)
        {
            /* A total above SSIZE_MAX is no byte count: the call returns ssize_t, so the
             * kernel rejects it with EINVAL. Summing it anyway would wrap and hand the
             * gates a small number for a huge request. Checked before the addition. */
            if ((uint64_t)vector[index].iov_len > (uint64_t)SSIZE_MAX - total)
            {
                return CHAOS_POLICY_NO_SIZE;
            }
            total += (uint64_t)vector[index].iov_len;
        }
        done += chunk;
    }
    return total;
}

/**
 * @brief Endpoint of a sockaddr in tracee memory (at most sizeof(sockaddr_storage) bytes
 *        read), with the socket type taken from descriptor @p fd.
 * @return 1 resolved; 0 for a NULL/empty address, an unreadable one, or no endpoint.
 */
static int
chaos_init_net_sockaddr(int fd, uint64_t address, uint64_t length, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage copy;
    const size_t size = length < sizeof(copy) ? (size_t)length : sizeof(copy);

    if (address == 0U || size == 0U ||
        chaos_init_read_memory(g_chaos_init_net_tid, address, &copy, size) != 0)
    {
        return 0;
    }
    return chaos_net_endpoint_from_sockaddr_fd(
        fd, (const struct sockaddr *)&copy, (socklen_t)size, endpoint
    );
}

/** @brief Payload bytes of a msghdr in tracee memory; CHAOS_POLICY_NO_SIZE if unknown. */
static uint64_t chaos_init_net_message_size(uint64_t address)
{
    struct msghdr message;

    if (chaos_init_read_memory(g_chaos_init_net_tid, address, &message, sizeof(message)) != 0)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    return chaos_init_net_iov_size(
        (uint64_t)(uintptr_t)message.msg_iov, (uint64_t)message.msg_iovlen
    );
}

/** @brief Messages of one sendmmsg the kernel processes (UIO_MAXIOV); the library caps alike. */
#define CHAOS_INIT_NET_MMSG_MAX 1024U

/**
 * @brief Payload bytes of a sendmmsg batch (first CHAOS_INIT_NET_MMSG_MAX messages); one
 *        tracee read per message plus its iovecs. CHAOS_POLICY_NO_SIZE if any message is
 *        unreadable or the sum would exceed UINT64_MAX / 2.
 */
static uint64_t chaos_init_net_batch_size(uint64_t address, uint64_t vlen)
{
    const uint64_t count = vlen < CHAOS_INIT_NET_MMSG_MAX ? vlen : CHAOS_INIT_NET_MMSG_MAX;
    uint64_t total = 0U;
    uint64_t index;

    for (index = 0U; index < count; ++index)
    {
        const uint64_t part = chaos_init_net_message_size(address + index * sizeof(struct mmsghdr));

        if (part == CHAOS_POLICY_NO_SIZE || part > UINT64_MAX / 2U - total)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        total += part;
    }
    return total;
}

/**
 * @brief The destination a msghdr in tracee memory names (msg_name).
 * @return 1 resolved, 0 named but not resolved, -1 none named (use the connection),
 *         -2 the msghdr itself is unreadable.
 */
static int chaos_init_net_message(int fd, uint64_t address, chaos_net_endpoint_t *endpoint)
{
    struct msghdr message;

    if (chaos_init_read_memory(g_chaos_init_net_tid, address, &message, sizeof(message)) != 0)
    {
        return -2;
    }
    if (message.msg_name == NULL)
    {
        return -1;
    }
    return chaos_init_net_sockaddr(
        fd, (uint64_t)(uintptr_t)message.msg_name, (uint64_t)message.msg_namelen, endpoint
    );
}

/**
 * @brief Matches @p operation on socket @p fd against either end of its connection, as the
 *        library does (chaos_net_match_connected()): the preferred end first (@p peer_first
 *        selects the peer), then the other. A missing end is skipped.
 * @return 1 with the rule in @p rule, else 0.
 */
static int chaos_init_net_match_ends(
    int fd, chaos_net_operation_t operation, int peer_first, chaos_net_rule_t *rule
)
{
    chaos_net_endpoint_t local;
    chaos_net_endpoint_t peer;
    const int have_local = chaos_net_endpoint_from_local_fd(fd, &local);
    const int have_peer = chaos_net_endpoint_from_peer_fd(fd, &peer);

    return peer_first ? chaos_net_config_match_either_loaded(
                            operation, have_peer ? &peer : NULL, have_local ? &local : NULL, rule
                        )
                      : chaos_net_config_match_either_loaded(
                            operation, have_local ? &local : NULL, have_peer ? &peer : NULL, rule
                        );
}

/**
 * @brief The SEND rule for a sendmmsg batch, scanned as the library does
 *        (chaos_net_extra.c): the first message whose msg_name matches wins; the
 *        connection's ends stand for every message without msg_name and are checked once.
 *        An unreadable message ends the scan with no match (the kernel fails the call).
 */
static int
chaos_init_net_match_batch(int fd, uint64_t address, uint64_t vlen, chaos_net_rule_t *rule)
{
    const uint64_t count = vlen < CHAOS_INIT_NET_MMSG_MAX ? vlen : CHAOS_INIT_NET_MMSG_MAX;
    int connected_checked = 0;
    uint64_t index;

    for (index = 0U; index < count; ++index)
    {
        chaos_net_endpoint_t endpoint;
        const int named =
            chaos_init_net_message(fd, address + index * sizeof(struct mmsghdr), &endpoint);

        if (named == -2)
        {
            return 0; /* the kernel fails the call (EFAULT) */
        }
        if (named > 0 && chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_SEND, &endpoint, rule))
        {
            return 1;
        }
        if (named < 0 && !connected_checked)
        {
            connected_checked = 1;
            if (chaos_init_net_match_ends(fd, CHAOS_NET_OP_SEND, 1, rule))
            {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief POLL rule for a wait call: the first of @p fds (negative entries skipped, as poll
 *        ignores them) whose activity endpoint matches. One /proc lookup per descriptor.
 */
static int chaos_init_net_match_any(const int *fds, size_t count, chaos_net_rule_t *rule)
{
    size_t index;

    for (index = 0U; index < count; ++index)
    {
        chaos_net_endpoint_t endpoint;

        if (fds[index] >= 0 && chaos_net_endpoint_from_activity_fd(fds[index], &endpoint) &&
            chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_POLL, &endpoint, rule))
        {
            return 1;
        }
    }
    return 0;
}

/** @brief Descriptors examined per wait call; the rest are ignored (bounds cost and buffers). */
#define CHAOS_INIT_NET_MAX_WAIT 1024U

/**
 * @brief Copies the fds of a pollfd array in tracee memory into @p fds (capacity
 *        CHAOS_INIT_NET_MAX_WAIT), 64 entries per read; stops early at an unreadable
 *        chunk. @return The number copied.
 */
static size_t chaos_init_net_poll_fds(uint64_t address, uint64_t count, int *fds)
{
    struct pollfd entries[64];
    size_t found = 0U;
    uint64_t done = 0U;

    count = count < CHAOS_INIT_NET_MAX_WAIT ? count : CHAOS_INIT_NET_MAX_WAIT;
    while (done < count)
    {
        const uint64_t chunk = count - done < 64U ? count - done : 64U;
        uint64_t index;

        if (chaos_init_read_memory(
                g_chaos_init_net_tid,
                address + done * sizeof(struct pollfd),
                entries,
                chunk * sizeof(struct pollfd)
            ) != 0)
        {
            break;
        }
        for (index = 0U; index < chunk; ++index)
        {
            fds[found++] = entries[index].fd;
        }
        done += chunk;
    }
    return found;
}

/**
 * @brief Bytes of an fd_set the kernel touches for @p nfds descriptors: whole 64-bit
 *        words, as the kernel reads and writes them on LP64.
 */
static size_t chaos_init_net_set_bytes(int nfds)
{
    return nfds <= 0 ? 0U : ((size_t)nfds + 63U) / 64U * 8U;
}

/**
 * @brief Collects the fds set in the read, write and except sets (args 1-3) of a
 *        select/pselect6 call, nfds capped at FD_SETSIZE (1024). A NULL or unreadable set
 *        is skipped; an fd in several sets is listed once per set.
 */
static size_t chaos_init_net_select_fds(const chaos_init_call_t *call, int *fds)
{
    const int count = (int)call->args[0] < FD_SETSIZE ? (int)call->args[0] : FD_SETSIZE;
    size_t found = 0U;
    int set;

    for (set = 1; set <= 3; ++set)
    {
        fd_set bits;
        int fd;

        /* Only the bytes nfds covers: a caller's smaller set may end where its mapping
         * does, and the kernel itself reads no more. */
        memset(&bits, 0, sizeof(bits));
        if (call->args[set] == 0U ||
            chaos_init_read_memory(
                g_chaos_init_net_tid, call->args[set], &bits, chaos_init_net_set_bytes(count)
            ) != 0)
        {
            continue;
        }
        for (fd = 0; fd < count && found < CHAOS_INIT_NET_MAX_WAIT; ++fd)
        {
            if (FD_ISSET(fd, &bits))
            {
                fds[found++] = fd;
            }
        }
    }
    return found;
}

/**
 * @brief The fds registered in epoll instance @p epfd of the tracee, from the `tfd:` lines
 *        of `/proc/<tid>/fdinfo/<epfd>` (numbers in the registering process's table).
 */
static size_t chaos_init_net_epoll_fds(int epfd, int *fds)
{
    char path[64];
    char line[256];
    size_t found = 0U;
    FILE *info;

    (void)snprintf(path, sizeof(path), "/proc/%ld/fdinfo/%d", (long)g_chaos_init_net_tid, epfd);
    info = fopen(path, "r");
    while (info != NULL && found < CHAOS_INIT_NET_MAX_WAIT && fgets(line, sizeof(line), info))
    {
        int fd;

        if (sscanf(line, "tfd: %d", &fd) == 1)
        {
            fds[found++] = fd;
        }
    }
    if (info != NULL)
    {
        (void)fclose(info);
    }
    return found;
}

/**
 * @brief Resolves the endpoint(s) @p entry's kind prescribes for @p call and matches them.
 *        Precondition: g_chaos_init_net_tid is the caller and the rules are prepared.
 *        The static fd buffer makes this non-reentrant.
 * @return 1 with the rule in @p rule, else 0.
 */
static int chaos_init_net_match(
    const chaos_init_net_call_t *entry, const chaos_init_call_t *call, chaos_net_rule_t *rule
)
{
    static int fds[CHAOS_INIT_NET_MAX_WAIT];
    const int fd = (int)call->args[0];
    chaos_net_endpoint_t endpoint;
    int found = 0;

    switch (entry->kind)
    {
    case CHAOS_INIT_NET_SPEC:
        found = chaos_net_endpoint_from_socket_spec(
            (int)call->args[0], (int)call->args[1], (int)call->args[2], &endpoint
        );
        break;
    case CHAOS_INIT_NET_ADDRESS:
        found = chaos_init_net_sockaddr(fd, call->args[1], call->args[2], &endpoint);
        break;
    case CHAOS_INIT_NET_LOCAL:
    case CHAOS_INIT_NET_PEER:
        return chaos_init_net_match_ends(
            fd, entry->operation, entry->kind == CHAOS_INIT_NET_PEER, rule
        );
    case CHAOS_INIT_NET_ACTIVITY:
        found = chaos_net_endpoint_from_activity_fd(fd, &endpoint);
        break;
    case CHAOS_INIT_NET_SENDTO:
    case CHAOS_INIT_NET_SENDMSG:
    {
        /* The destination named in the call (sendto args[4..5], msg_name), else either
         * end of the connection, peer first. A named destination that does not resolve
         * matches nothing, as in the library. */
        const int named =
            entry->kind == CHAOS_INIT_NET_SENDTO
                ? (call->args[4] == 0U
                       ? -1
                       : chaos_init_net_sockaddr(fd, call->args[4], call->args[5], &endpoint))
                : chaos_init_net_message(fd, call->args[1], &endpoint);

        if (named >= 0)
        {
            found = named;
            break;
        }
        return chaos_init_net_match_ends(fd, entry->operation, 1, rule);
    }
    case CHAOS_INIT_NET_SENDMMSG:
        return chaos_init_net_match_batch(fd, call->args[1], call->args[2], rule);
    case CHAOS_INIT_NET_POLL:
        return chaos_init_net_match_any(
            fds, chaos_init_net_poll_fds(call->args[0], call->args[1], fds), rule
        );
    case CHAOS_INIT_NET_SELECT:
        return chaos_init_net_match_any(fds, chaos_init_net_select_fds(call, fds), rule);
    case CHAOS_INIT_NET_EPOLL:
        return chaos_init_net_match_any(fds, chaos_init_net_epoll_fds(fd, fds), rule);
    }
    return found && chaos_net_config_match_endpoint_loaded(entry->operation, &endpoint, rule);
}

/**
 * @brief Whether any loaded rule targets @p operation. Endpoint lookups (/proc reads, per
 *        descriptor for wait calls) run only then, so recv or epoll on many sockets stays
 *        at the base notification cost while the rules target only connect.
 */
static int chaos_init_net_targeted(chaos_net_operation_t operation)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();
    size_t index;

    for (index = 0U; index < state->rule_count; ++index)
    {
        if (state->rules[index].operation == operation)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Whether descriptor @p fd of thread @p tid is a socket (`/proc/<tid>/fd/<fd>` reads
 *        `socket:[...]`). Decides whether read/write/close belong to net or io; an
 *        unreadable link counts as not a socket.
 */
static int chaos_init_net_is_socket(pid_t tid, uint64_t fd)
{
    char name[32];
    char link[64];

    (void)snprintf(name, sizeof(name), "fd/%d", (int)fd);
    return chaos_init_proc_link(tid, name, link, sizeof(link)) > 0 &&
           strncmp(link, "socket:", 7U) == 0;
}

/**
 * @brief A timespec in tracee memory as milliseconds, rounded up and capped at INT32_MAX.
 * @return The value, or -1 for NULL (wait forever), unreadable, or invalid (the kernel
 *         fails it with EINVAL; the real call is left to report that).
 */
static int64_t chaos_init_net_timespec_ms(uint64_t address)
{
    struct timespec timeout;

    if (address == 0U ||
        chaos_init_read_memory(g_chaos_init_net_tid, address, &timeout, sizeof(timeout)) != 0)
    {
        return -1;
    }
    if (timeout.tv_sec < 0 || timeout.tv_nsec < 0 || timeout.tv_nsec >= 1000000000L)
    {
        return -1; /* the kernel refuses it (EINVAL): left to the real call */
    }
    if (timeout.tv_sec > (time_t)(INT32_MAX / 1000))
    {
        return INT32_MAX;
    }
    return (int64_t)timeout.tv_sec * 1000 + (timeout.tv_nsec + 999999L) / 1000000L;
}

/**
 * @brief The timeout of wait call @p call in milliseconds, as the library reads it:
 *        ppoll/pselect6/epoll_pwait2 timespec, select timeval, poll/epoll_wait/epoll_pwait
 *        int milliseconds. @return -1 when it waits without one, or the timeout is
 *        unreadable or invalid.
 */
static int64_t chaos_init_net_wait_timeout(const chaos_init_call_t *call)
{
    switch (call->nr)
    {
    case __NR_ppoll:
        return chaos_init_net_timespec_ms(call->args[2]);
    case __NR_pselect6:
        return chaos_init_net_timespec_ms(call->args[4]);
#ifdef __NR_epoll_pwait2
    case __NR_epoll_pwait2:
        return chaos_init_net_timespec_ms(call->args[3]);
#endif
#ifdef __NR_select
    case __NR_select:
    {
        struct timeval timeout;

        if (call->args[4] == 0U ||
            chaos_init_read_memory(
                g_chaos_init_net_tid, call->args[4], &timeout, sizeof(timeout)
            ) != 0)
        {
            return -1;
        }
        return timeout.tv_sec < 0 || timeout.tv_usec < 0 || timeout.tv_usec >= 1000000L
                   ? -1 /* the kernel refuses it (EINVAL): left to the real call */
               : timeout.tv_sec > (time_t)(INT32_MAX / 1000)
                   ? INT32_MAX
                   : (int64_t)timeout.tv_sec * 1000 + (timeout.tv_usec + 999L) / 1000L;
    }
#endif
#ifdef __NR_poll
    case __NR_poll:
        return (int)call->args[2] < 0 ? -1 : (int64_t)(int)call->args[2];
#endif
    default: /* epoll_wait, epoll_pwait: milliseconds in the fourth argument */
        return (int)call->args[3] < 0 ? -1 : (int64_t)(int)call->args[3];
    }
}

/**
 * @brief Writes "nothing ready" into the tracee buffers of wait call @p call, as a real
 *        timeout leaves them: every revents cleared (up to CHAOS_INIT_NET_MAX_WAIT
 *        entries), the fd_sets emptied over the bytes nfds covers, and select()'s timeval
 *        zeroed (Linux select() writes back the remaining time). epoll returns 0 events
 *        and writes nothing.
 *
 * @details Runs at decision time via chaos_init_net_commit(), before a TIMEOUT's delay
 * has elapsed. The waiting thread cannot observe the difference; another thread sharing
 * the buffers could. Write failures are ignored.
 */
static void chaos_init_net_clear_ready(const chaos_init_call_t *call)
{
    static const char zeros[sizeof(fd_set)];
    const int nr = call->nr;

    if (nr == __NR_ppoll
#ifdef __NR_poll
        || nr == __NR_poll
#endif
    )
    {
        const uint64_t count =
            call->args[1] < CHAOS_INIT_NET_MAX_WAIT ? call->args[1] : CHAOS_INIT_NET_MAX_WAIT;
        uint64_t index;

        for (index = 0U; index < count; ++index)
        {
            const uint64_t address =
                call->args[0] + index * sizeof(struct pollfd) + offsetof(struct pollfd, revents);
            const short none = 0;

            if (chaos_init_write_memory(g_chaos_init_net_tid, address, &none, sizeof(none)) != 0)
            {
                break;
            }
        }
        return;
    }
    if (nr == __NR_pselect6
#ifdef __NR_select
        || nr == __NR_select
#endif
    )
    {
        const int nfds = (int)call->args[0] < FD_SETSIZE ? (int)call->args[0] : FD_SETSIZE;
        int set;

        for (set = 1; set <= 3; ++set)
        {
            if (call->args[set] != 0U)
            {
                (void)chaos_init_write_memory(
                    g_chaos_init_net_tid, call->args[set], zeros, chaos_init_net_set_bytes(nfds)
                );
            }
        }
#ifdef __NR_select
        if (nr == __NR_select && call->args[4] != 0U)
        {
            const struct timeval none = {0, 0};

            (void)chaos_init_write_memory(g_chaos_init_net_tid, call->args[4], &none, sizeof(none));
        }
#endif
    }
}

/**
 * @brief Who holds the socket behind descriptor @p fd of thread @p tid.
 *
 * @details The same scan the library makes (chaos_net_socket_ownership()), from the other
 * side: the inode comes from the `/proc/<tid>/fd/<fd>` link rather than from an `fstat`,
 * and the descriptor table searched first is the tracee's process, not the supervisor's.
 * A process is what owns descriptors, so the thread's group leader is the one to look
 * under -- `/proc` lists no threads, so a search that excluded the tid would find the
 * group's own link again and read it as somebody else's.
 *
 * @return SOLE when this descriptor is the only one anywhere, SHARED when another holds
 *         the same socket, UNKNOWN when the scan could establish neither.
 */
static chaos_net_ownership_t chaos_init_net_ownership(pid_t tid, uint64_t fd)
{
    char target[CHAOS_NET_OWNER_TARGET_MAX];
    char directory[32];
    char owner[16];
    const unsigned long inode = chaos_init_net_inode((int)fd);
    uint64_t image = 0U;
    pid_t tgid = 0;
    size_t own = 0U;
    int other;

    if (inode == 0U || CHAOS_INIT_PROCESS_OF(tid, &tgid, &image) != 0)
    {
        return CHAOS_NET_OWNER_UNKNOWN;
    }
    (void)snprintf(target, sizeof(target), "socket:[%lu]", inode);
    (void)snprintf(directory, sizeof(directory), "/proc/%ld/fd", (long)tgid);
    (void)snprintf(owner, sizeof(owner), "%ld", (long)tgid);
    /* The link was there a moment ago, so a scan that does not find it did not see what
     * must be there: nothing may be concluded from it. */
    if (chaos_net_owner_count(directory, target, &own) != 0 || own == 0U)
    {
        return CHAOS_NET_OWNER_UNKNOWN;
    }
    if (own > 1U)
    {
        return CHAOS_NET_OWNER_SHARED;
    }
    other = chaos_net_owner_other_holder(target, owner);
    return other > 0 ? CHAOS_NET_OWNER_SHARED
                     : (other == 0 ? CHAOS_NET_OWNER_SOLE : CHAOS_NET_OWNER_UNKNOWN);
}

/*---------------------------------------------------------------------------*
 * DUP: keep what a receive delivered and deliver it again
 *---------------------------------------------------------------------------*/

/** @brief Sockets whose last payload the supervisor keeps at once. */
#define CHAOS_INIT_NET_DUP_SLOTS 16U

/** @brief Longest kept payload, as in the library (CHAOS_NET_DUP_MAX_BYTES). */
#define CHAOS_INIT_NET_DUP_MAX_BYTES 4096U

/** @brief Receive flags that bypass DUP, as in the library (CHAOS_NET_DUP_SKIP_FLAGS). */
#ifdef MSG_ERRQUEUE
#define CHAOS_INIT_NET_DUP_SKIP (MSG_PEEK | MSG_TRUNC | MSG_OOB | MSG_WAITALL | MSG_ERRQUEUE)
#else
#define CHAOS_INIT_NET_DUP_SKIP (MSG_PEEK | MSG_TRUNC | MSG_OOB | MSG_WAITALL)
#endif

/**
 * @brief The last payload received on one socket, kept for a DUP rule.
 *
 * @details Keyed by the socket inode rather than by descriptor and process: the inode
 * names the socket itself, so a descriptor that was closed and reused no longer finds the
 * payload, and two processes that share the socket share one -- they share the byte stream
 * too. The library keeps its table per address space instead, which is the one difference
 * (NETWORK.md).
 */
typedef struct chaos_init_net_dup
{
    unsigned long inode;   /**< The socket the payload came from; 0 when the slot is empty. */
    uint64_t stamp;        /**< Store order, for evicting the oldest slot. */
    size_t length;         /**< Bytes kept in `data`. */
    socklen_t name_length; /**< Sender address length (datagrams); 0 when none. */
    struct sockaddr_storage name;
    unsigned char data[CHAOS_INIT_NET_DUP_MAX_BYTES];
} chaos_init_net_dup_t;

static chaos_init_net_dup_t g_chaos_init_net_dups[CHAOS_INIT_NET_DUP_SLOTS];
static uint64_t g_chaos_init_net_dup_stamp = 0U;

/** @brief The slot holding @p inode's payload, or NULL when none does. */
static chaos_init_net_dup_t *chaos_init_net_dup_find(unsigned long inode)
{
    size_t index;

    for (index = 0U; index < CHAOS_INIT_NET_DUP_SLOTS; ++index)
    {
        if (g_chaos_init_net_dups[index].inode == inode)
        {
            return &g_chaos_init_net_dups[index];
        }
    }
    return NULL;
}

/**
 * @brief Keeps the bytes @p result reports as @p inode's payload.
 *
 * @details Called at the exit stop of a receive the entry stop let run, which is where
 * @p inode was established as a socket's. A datagram longer
 * than the cap is not kept at all (replayed cut it would be another message), a stream
 * payload is kept cut, exactly as in the library. The oldest slot gives way when all are
 * taken, so a container with more such sockets than slots keeps the newest payloads.
 */
static void chaos_init_net_dup_store(
    const chaos_init_call_t *call,
    const chaos_init_net_call_t *entry,
    unsigned long inode,
    long result,
    uint64_t size
)
{
    chaos_init_net_dup_t *slot;
    uint64_t length;
    size_t index;

    if (result <= 0)
    {
        return;
    }
    length = (uint64_t)result < size ? (uint64_t)result : size;
    if (length > CHAOS_INIT_NET_DUP_MAX_BYTES)
    {
        if (!chaos_init_net_is_stream(call->args[0]))
        {
            return;
        }
        length = CHAOS_INIT_NET_DUP_MAX_BYTES;
    }
    slot = chaos_init_net_dup_find(inode);
    if (slot == NULL)
    {
        slot = chaos_init_net_dup_find(0U);
    }
    if (slot == NULL)
    {
        slot = &g_chaos_init_net_dups[0];
        for (index = 1U; index < CHAOS_INIT_NET_DUP_SLOTS; ++index)
        {
            if (g_chaos_init_net_dups[index].stamp < slot->stamp)
            {
                slot = &g_chaos_init_net_dups[index];
            }
        }
    }
    slot->inode = 0U;
    if (chaos_init_read_memory(call->tid, call->args[1], slot->data, (size_t)length) != 0)
    {
        return;
    }
    slot->length = (size_t)length;
    slot->name_length = 0;
    /* The sender address of a datagram, for a recvfrom replay. The kernel reports the
     * full length even when it cut the address to the caller's buffer, so only what it
     * wrote is kept. Of the traced calls only recvfrom has an address at all. */
    if (entry->nr == __NR_recvfrom && call->args[4] != 0U && call->args[5] != 0U)
    {
        socklen_t reported = 0;

        if (chaos_init_read_memory(call->tid, call->args[5], &reported, sizeof(reported)) == 0 &&
            reported > 0 && (size_t)reported <= sizeof(slot->name) &&
            chaos_init_read_memory(call->tid, call->args[4], &slot->name, (size_t)reported) == 0)
        {
            slot->name_length = reported;
        }
    }
    slot->inode = inode;
    slot->stamp = ++g_chaos_init_net_dup_stamp;
}

/**
 * @brief Delivers @p slot's payload into the receive's buffer and empties the slot.
 *
 * @details Each payload replays at most once, so the next receive reads the socket again.
 * The sender address is written back truncated to the caller's capacity with the full
 * length reported, as the kernel does.
 *
 * @return The bytes delivered, or -1 when the tracee's buffer could not be written, in
 *         which case the call has to run for real.
 */
static long chaos_init_net_dup_replay(
    const chaos_init_call_t *call,
    const chaos_init_net_call_t *entry,
    chaos_init_net_dup_t *slot,
    uint64_t size
)
{
    const uint64_t delivered = (uint64_t)slot->length < size ? (uint64_t)slot->length : size;

    if (chaos_init_write_memory(call->tid, call->args[1], slot->data, (size_t)delivered) != 0)
    {
        return -1;
    }
    if (entry->nr == __NR_recvfrom && call->args[4] != 0U && call->args[5] != 0U)
    {
        const void *name = &slot->name;
        socklen_t capacity = 0;

        if (chaos_init_read_memory(call->tid, call->args[5], &capacity, sizeof(capacity)) == 0)
        {
            const socklen_t copied = capacity < slot->name_length ? capacity : slot->name_length;

            if (copied > 0)
            {
                (void)chaos_init_write_memory(call->tid, call->args[4], name, (size_t)copied);
            }
            (void)chaos_init_write_memory(
                call->tid, call->args[5], &slot->name_length, sizeof(slot->name_length)
            );
        }
    }
    slot->inode = 0U;
    return (long)delivered;
}

/** @brief Result value that means "the call has not run yet" (the entry stop). */
#define CHAOS_INIT_NET_NO_RESULT LONG_MIN

/* Decode by table; shared calls only on sockets; cheap rejections (no rule for the
 * operation) before any endpoint lookup; then match, measure, and trigger on the
 * per-process slot.
 *
 * chaos_init_net_decide() and chaos_init_net_decide_result() share this body: the two stops
 * of a traced call have to select the same rule. @p result is CHAOS_INIT_NET_NO_RESULT at
 * the entry stop and the call's return value at the exit stop. */
static int
chaos_init_net_decide_at(const chaos_init_call_t *call, long result, chaos_init_verdict_t *verdict)
{
    const chaos_init_net_call_t *entry = NULL;
    const chaos_net_config_state_t *state;
    chaos_net_rule_t rule;
    chaos_init_net_dup_t *kept = NULL;
    uint64_t size = CHAOS_POLICY_NO_SIZE;
    int64_t timeout_ms = -1;
    size_t index;

    for (index = 0U; index < sizeof(g_chaos_init_net_calls) / sizeof(g_chaos_init_net_calls[0]);
         ++index)
    {
        if (g_chaos_init_net_calls[index].nr == call->nr)
        {
            entry = &g_chaos_init_net_calls[index];
            break;
        }
    }
    if (entry == NULL || (entry->shared && !chaos_init_net_is_socket(call->tid, call->args[0])))
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;
    g_chaos_init_net_tid = call->tid;
    if (!chaos_net_config_prepare() || !chaos_init_net_targeted(entry->operation) ||
        !chaos_init_net_match(entry, call, &rule))
    {
        return 1;
    }
    /* `@size` input, measured only after a match: a batch costs a read per message. */
    if (entry->size >= 0)
    {
        size = call->args[entry->size];
    }
    else if (entry->size == -2)
    {
        size = chaos_init_net_iov_size(call->args[1], call->args[2]);
    }
    else if (entry->size == -3)
    {
        size = chaos_init_net_message_size(call->args[1]);
    }
    else if (entry->size == -4)
    {
        size = chaos_init_net_batch_size(call->args[1], call->args[2]);
    }
    /* A loaded rule is ERRNO, LATENCY, TIMEOUT or DROP only (chaos_init_net_supported()).
     * A wait without a timeout never times out, so TIMEOUT does not apply to it; checked
     * before triggering, so such a call counts no hit. */
    if (rule.effect == CHAOS_NET_EFFECT_TIMEOUT &&
        (timeout_ms = chaos_init_net_wait_timeout(call)) < 0)
    {
        return 1;
    }
    /* DROP answers with the byte count, so it needs a count the call could have returned
     * and a datagram socket (chaos_net_drops() in the library decides the same two things).
     * A batch reports a message count instead, which is why sendmmsg is left alone. Also
     * checked before triggering, so a call it leaves alone counts no hit. */
    if (rule.effect == CHAOS_NET_EFFECT_DROP && (size > (uint64_t)SSIZE_MAX || entry->size == -4 ||
                                                 !chaos_init_net_is_datagram(call->args[0])))
    {
        return 1;
    }
    if (rule.effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        /* How many bytes there are to corrupt is the receive's result, so the entry stop
         * only asks to be called again; the draw then happens after the call, as the
         * library's does. The forms that keep their buffer in memory are left alone and
         * count no hit. */
        if (result == CHAOS_INIT_NET_NO_RESULT)
        {
            verdict->action = entry->size < 0 ? CHAOS_INIT_PASS : CHAOS_INIT_AFTER;
            return 1;
        }
        /* chaos_net_received_bytes(): nothing written means nothing to corrupt, and a
         * MSG_TRUNC receive on a stream socket discards the data instead of writing it. */
        if (result <= 0 || size == CHAOS_POLICY_NO_SIZE ||
            ((entry->nr == __NR_recvfrom && (call->args[3] & (uint64_t)MSG_TRUNC) != 0U) &&
             chaos_init_net_is_stream(call->args[0])))
        {
            return 1;
        }
    }
    else if (rule.effect == CHAOS_NET_EFFECT_RESET)
    {
        /* Ownership is settled before the draw, as in the library: SO_LINGER on a socket
         * another descriptor still holds would reset nothing now and reset it later, out
         * of any rule's reach. A suppression is counted for the hits file's header rather
         * than passed over in silence, and spends neither a hit nor a `@first` claim. */
        const chaos_net_ownership_t ownership = chaos_init_net_ownership(call->tid, call->args[0]);

        if (ownership != CHAOS_NET_OWNER_SOLE)
        {
            chaos_net_reset_suppressed(ownership);
            return 1;
        }
    }
    else if (rule.effect == CHAOS_NET_EFFECT_DUP)
    {
        /* chaos_net_dups(): a request of zero or unknown length, the forms that keep their
         * buffer in an iovec, and the flags that are not the plain data stream are left
         * alone. An unreadable descriptor is too -- the payload belongs to a socket, and
         * without its inode there is nothing to tie it to. All checked before the draw, so
         * such a call counts no hit. */
        const uint64_t flags = entry->nr == __NR_recvfrom ? call->args[3] : 0U;
        const unsigned long inode = chaos_init_net_inode((int)call->args[0]);

        if (entry->size < 0 || size == CHAOS_POLICY_NO_SIZE || size == 0U || inode == 0U ||
            (flags & (uint64_t)CHAOS_INIT_NET_DUP_SKIP) != 0U)
        {
            return 1;
        }
        if (result != CHAOS_INIT_NET_NO_RESULT)
        {
            /* The exit stop of a receive that ran: keep what it delivered and draw
             * nothing. A hit is a delivered duplicate, and only a replay is one. */
            chaos_init_net_dup_store(call, entry, inode, result, size);
            return 1;
        }
        /* Let the receive run whatever the draw decides: it either replaces the payload it
         * did not get, or leaves the first one behind. */
        verdict->action = CHAOS_INIT_AFTER;
        kept = chaos_init_net_dup_find(inode);
        if (kept == NULL)
        {
            return 1;
        }
    }
    else if (result != CHAOS_INIT_NET_NO_RESULT)
    {
        /* Every other effect was applied at the entry stop; the exit stop must not draw
         * again. Reachable when the rule file changed between the two stops. */
        return 1;
    }
    /* TRICKLE shortens the requested length where it sits in a register, and only where
     * the library shortens it: a stream socket (a shorter buffer truncates a datagram),
     * not MSG_WAITALL (the caller asked for the whole count), and only a request larger
     * than the chunk. Of the traced calls only recvfrom carries flags; read has none.
     * Checked before the draw, so a call it leaves alone counts no hit. */
    if (rule.effect == CHAOS_NET_EFFECT_TRICKLE)
    {
        const uint64_t flags = entry->nr == __NR_recvfrom ? call->args[3] : 0U;

        if (entry->size < 0 || size == CHAOS_POLICY_NO_SIZE || size <= rule.chunk_bytes ||
            (flags & (uint64_t)MSG_WAITALL) != 0U || !chaos_init_net_is_stream(call->args[0]))
        {
            return 1;
        }
    }
    /* Swap the snapshot's shared slot for the calling process's (see chaos_init_io.c). */
    state = chaos_net_config_active_state();
    rule.call_size = size;
    rule.hit = chaos_init_tracee_hit(
        &g_chaos_init_net_rules, call->tid, state->hits, state->rule_count, rule.hit
    );
    rule.hit_generation = rule.hit != NULL ? rule.hit->generation : 0U;
    if (rule.hit == NULL || !chaos_net_rule_should_trigger(&rule))
    {
        return 1;
    }
    if (rule.effect == CHAOS_NET_EFFECT_ERRNO)
    {
        verdict->action = CHAOS_INIT_FAIL;
        verdict->error = rule.errnum;
    }
    else if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    else if (rule.effect == CHAOS_NET_EFFECT_DROP)
    {
        verdict->action = CHAOS_INIT_RETURN;
        verdict->value = (long)size;
    }
    else if (rule.effect == CHAOS_NET_EFFECT_TRICKLE)
    {
        /* Always the chunk, never a draw: TRICKLE carries a byte count, not a
         * probability, and fires on every call it applies to. */
        verdict->action = CHAOS_INIT_SHORTEN;
        verdict->arg_index = (unsigned)entry->size;
        verdict->value = (long)rule.chunk_bytes;
    }
    else if (rule.effect == CHAOS_NET_EFFECT_RESET)
    {
        /* The close has to abort the connection, which means a
         * `setsockopt(SO_LINGER{1,0})` on the same socket first: the option lives on the
         * file description, so only a call inside the tracee can set it. Its argument goes
         * into the tracee's stack scratch, and the close itself runs afterwards. */
        const struct linger abort_linger = {1, 0};

        verdict->action = CHAOS_INIT_BEFORE;
        verdict->instead_nr = __NR_setsockopt;
        verdict->instead_args[0] = call->args[0];
        verdict->instead_args[1] = (uint64_t)SOL_SOCKET;
        verdict->instead_args[2] = (uint64_t)SO_LINGER;
        verdict->instead_args[4] = (uint64_t)sizeof(abort_linger);
        (void)memcpy(verdict->instead_data, &abort_linger, sizeof(abort_linger));
        verdict->instead_size = (unsigned)sizeof(abort_linger);
        verdict->instead_arg = 3U;
    }
    else if (rule.effect == CHAOS_NET_EFFECT_DUP)
    {
        /* The kept payload instead of a receive, which the reply can return without the
         * call running. A buffer the supervisor cannot write leaves the verdict at AFTER:
         * the receive then runs for real, as a busy slot makes it in the library. */
        const long delivered = chaos_init_net_dup_replay(call, entry, kept, size);

        if (delivered >= 0)
        {
            verdict->action = CHAOS_INIT_RETURN;
            verdict->value = delivered;
        }
    }
    else if (rule.effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        /* One byte of what the receive delivered, capped at the buffer: with MSG_TRUNC a
         * datagram receive reports the whole datagram, which can be longer than what it
         * wrote. The byte is read out of the tracee, one bit flipped, written back. */
        const uint64_t length = (uint64_t)result < size ? (uint64_t)result : size;
        const uint64_t offset =
            (uint64_t)chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_FIRST_EFFECT) % length;
        const unsigned bit = chaos_net_rule_draw(&rule, CHAOS_NET_DRAW_SECOND_EFFECT) & 7U;
        unsigned char byte = 0U;

        if (chaos_init_read_memory(call->tid, call->args[1] + offset, &byte, sizeof(byte)) == 0)
        {
            byte ^= (unsigned char)(1U << bit);
            (void)chaos_init_write_memory(call->tid, call->args[1] + offset, &byte, sizeof(byte));
        }
    }
    else
    {
        /* Simulate "nothing became ready": hold the call for its own timeout (RETURN at
         * once for a zero timeout), then return 0 with the buffers cleared. Signals do not
         * cut the wait short, unlike a real timeout's EINTR. */
        verdict->clear_ready = 1;
        verdict->action = timeout_ms > 0 ? CHAOS_INIT_DELAY : CHAOS_INIT_RETURN;
        verdict->delay_ms = (unsigned)timeout_ms;
        verdict->returns = 1;
        verdict->value = 0;
    }
    return 1;
}

void chaos_init_net_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict)
{
    if (verdict->clear_ready)
    {
        g_chaos_init_net_tid = call->tid;
        chaos_init_net_clear_ready(call);
    }
}

int chaos_init_net_mptcp_unresolvable(void)
{
    const int probe = CHAOS_INIT_NET_MPTCP_SOCKET();

    if (probe < 0)
    {
        return 0; /* no MPTCP: Go uses plain TCP */
    }
    (void)close(probe);
    return 1;
}

int chaos_init_net_mptcp_diag_available(void)
{
    const int probe = CHAOS_INIT_NET_MPTCP_SOCKET();
    struct sockaddr_in loopback;
    struct sockaddr_storage found;
    socklen_t found_length = 0;
    struct stat info;
    int unresolvable;

    if (probe < 0)
    {
        return 0;
    }
    /* A listening loopback socket on an ephemeral port is what sock_diag would have to
     * find for an MPTCP server; any failure on the way counts as unresolvable. */
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    unresolvable =
        bind(probe, (struct sockaddr *)&loopback, sizeof(loopback)) != 0 || listen(probe, 1) != 0 ||
        fstat(probe, &info) != 0 ||
        !chaos_init_net_diag_name(
            AF_INET, CHAOS_INIT_NET_MPTCP_DIAG, (unsigned long)info.st_ino, 0, &found, &found_length
        );
    (void)close(probe);
    return !unresolvable;
}

/** @copydoc chaos_init_net_decide */
int chaos_init_net_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    return chaos_init_net_decide_at(call, CHAOS_INIT_NET_NO_RESULT, verdict);
}

/** @copydoc chaos_init_net_decide_result */
int chaos_init_net_decide_result(const chaos_init_call_t *call, long result)
{
    chaos_init_verdict_t verdict;

    return chaos_init_net_decide_at(call, result, &verdict);
}
