/**
 * @file chaos_init_net.c
 * @brief chaos-init: libchaos-net rules for system calls of supervised processes.
 *
 * @details The net rule core (parsing, reload, status file, endpoint selectors,
 * matching, qualifiers) and its endpoint resolution are compiled in unchanged. The
 * resolution asks a descriptor three things through function pointers the preload
 * library fills with getsockopt(SO_TYPE), getsockname() and getpeername(); here
 * they answer for the supervised thread's descriptor instead, without access to it
 * (pidfd_getfd() needs CAP_SYS_PTRACE under Docker's default profile):
 *
 * - the type, from the socket's `system.sockprotoname` attribute, read through
 *   /proc/<pid>/fd/<fd> (TCP, UDP, TCPv6, UDPv6, UNIX-STREAM, UNIX-DGRAM);
 * - the addresses, from the socket's row in /proc/<pid>/net/{tcp,tcp6,udp,udp6,unix},
 *   found by inode. A socket not bound yet has no row: its name is the unspecified
 *   address and it has no peer, as getsockname()/getpeername() would say. A UNIX
 *   socket's peer is not in /proc and is reported as unknown.
 *
 * The wait calls scan their descriptors like the library does: the pollfd array
 * and fd_sets from the thread's memory, an epoll instance's descriptors from
 * /proc/<pid>/fdinfo. SECCOMP mode applies ERRNO, LATENCY and (poll family)
 * TIMEOUT. CORRUPT, TRICKLE and DUP change received data, RESET needs the socket
 * itself, and ERRNO on close would have to close and fail at once: a rule file with
 * any of them is rejected while it is parsed (`unsupported in seccomp mode`).
 */

#include "chaos_init_net.h"

struct chaos_net_rule;
static int chaos_init_net_supported(const struct chaos_net_rule *rule);
#define CHAOS_NET_RULE_SUPPORTED(rule) chaos_init_net_supported(rule)

#include "../net/chaos_net_actions.c"
#include "../net/chaos_net_config.c"
#include "../net/chaos_net_endpoint.c"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <poll.h>
#include <sys/random.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/xattr.h>

static int chaos_init_net_supported(const struct chaos_net_rule *rule)
{
    return (rule->effect == CHAOS_NET_EFFECT_ERRNO && rule->operation != CHAOS_NET_OP_CLOSE) ||
           rule->effect == CHAOS_NET_EFFECT_LATENCY || rule->effect == CHAOS_NET_EFFECT_TIMEOUT;
}

/** @brief The thread whose descriptors the socket queries below answer for. */
static pid_t g_chaos_init_net_tid = 0;

/** @brief How /proc files and links are read; unit tests replace them. */
#ifndef CHAOS_INIT_NET_GETXATTR
#define CHAOS_INIT_NET_GETXATTR getxattr
#endif

/** @brief A socket's protocol as the kernel names it, mapped to what getsockopt says. */
typedef struct chaos_init_net_protocol
{
    const char *name;  /**< system.sockprotoname */
    int type;          /**< SOCK_STREAM or SOCK_DGRAM */
    int family;        /**< AF_INET, AF_INET6 or AF_UNIX */
    const char *table; /**< /proc/<pid>/net/<table> */
} chaos_init_net_protocol_t;

static const chaos_init_net_protocol_t g_chaos_init_net_protocols[] = {
    {"TCP", SOCK_STREAM, AF_INET, "tcp"},
    {"UDP", SOCK_DGRAM, AF_INET, "udp"},
    {"TCPv6", SOCK_STREAM, AF_INET6, "tcp6"},
    {"UDPv6", SOCK_DGRAM, AF_INET6, "udp6"},
    {"UNIX-STREAM", SOCK_STREAM, AF_UNIX, "unix"},
    {"UNIX-DGRAM", SOCK_DGRAM, AF_UNIX, "unix"},
    {"UNIX", SOCK_STREAM, AF_UNIX, "unix"}, /* kernels before 5.x name every UNIX socket so */
};

/** @brief The protocol of descriptor @p fd of the current thread; NULL if not a known socket. */
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

/** @brief The socket inode of descriptor @p fd of the current thread; 0 if none. */
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
 * @brief Parses an address of /proc/net/{tcp,udp}{,6}: "0100007F:1F90" or the
 *        IPv6 form with 32 hex digits, each 8 of them a word in host order.
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
 * @brief getsockname() (@p peer 0) or getpeername() (@p peer 1) of descriptor @p fd
 *        of the current thread, from its row in /proc/<pid>/net.
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
    (void
    )snprintf(path, sizeof(path), "/proc/%ld/net/%s", (long)g_chaos_init_net_tid, protocol->table);
    table = fopen(path, "r");
    while (table != NULL && !have && fgets(line, sizeof(line), table) != NULL)
    {
        char local[64];
        char remote[64];
        char unix_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
        unsigned long row_inode = 0U;

        if (protocol->family == AF_UNIX)
        {
            unix_path[0] = '\0';
            if (sscanf(line, "%*s %*s %*s %*s %*s %*s %lu %107s", &row_inode, unix_path) >= 1 &&
                row_inode == inode)
            {
                struct sockaddr_un *un = (struct sockaddr_un *)&found;

                un->sun_family = AF_UNIX;
                memcpy(un->sun_path, unix_path, strlen(unix_path) + 1U);
                found_length = (socklen_t)sizeof(*un);
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
        /* A UNIX peer is not in /proc; an IP peer of 0 means not connected. */
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
        /* Not bound yet: the unspecified address of its family. */
        found.ss_family = (sa_family_t)protocol->family;
        found_length = protocol->family == AF_INET    ? (socklen_t)sizeof(struct sockaddr_in)
                       : protocol->family == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6)
                                                      : (socklen_t)sizeof(sa_family_t);
    }
    memcpy(address, &found, (size_t)(found_length < *length ? found_length : *length));
    *length = found_length;
    return 0;
}

static int chaos_init_net_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    return chaos_init_net_name(fd, address, length, 0);
}

static int chaos_init_net_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    return chaos_init_net_name(fd, address, length, 1);
}

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

/* What the rule core expects the preload library to provide. */
chaos_net_getsockname_fn g_chaos_net_real_getsockname = chaos_init_net_getsockname;
chaos_net_getpeername_fn g_chaos_net_real_getpeername = chaos_init_net_getpeername;
chaos_net_getsockopt_fn g_chaos_net_real_getsockopt = chaos_init_net_getsockopt;
__thread int g_chaos_net_tls_guard = 0;
__thread uint64_t g_chaos_net_tls_prng_state = 0U;
uint64_t g_chaos_net_process_seed = UINT64_C(0x9e3779b97f4a7c15);

/** @brief How a system call names the socket(s) it acts on. */
typedef enum chaos_init_net_kind
{
    CHAOS_INIT_NET_SPEC,     /**< socket()/socketpair(): domain, type, protocol. */
    CHAOS_INIT_NET_ADDRESS,  /**< bind()/connect(): fd, sockaddr, length. */
    CHAOS_INIT_NET_LOCAL,    /**< The socket's own address. */
    CHAOS_INIT_NET_PEER,     /**< The socket's peer. */
    CHAOS_INIT_NET_ACTIVITY, /**< Own address, else the peer. */
    CHAOS_INIT_NET_SENDTO,   /**< sendto(): the destination argument, else the peer. */
    CHAOS_INIT_NET_SENDMSG,  /**< sendmsg(): msg_name, else the peer. */
    CHAOS_INIT_NET_SENDMMSG, /**< sendmmsg(): the first message's msg_name, else the peer. */
    CHAOS_INIT_NET_POLL,     /**< poll()/ppoll(): every descriptor of the pollfd array. */
    CHAOS_INIT_NET_SELECT,   /**< select()/pselect6(): every descriptor of the sets. */
    CHAOS_INIT_NET_EPOLL     /**< epoll_wait()/epoll_pwait(): the instance's descriptors. */
} chaos_init_net_kind_t;

typedef struct chaos_init_net_call
{
    long nr;
    chaos_net_operation_t operation;
    chaos_init_net_kind_t kind;
    int shared; /**< Also an io call: a net call only on a socket. */
    int size;   /**< Argument index of the byte count; -1 none, -2 iovec (args 1-2),
                     -3 a msghdr (arg 1). */
} chaos_init_net_call_t;

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
    {__NR_sendmmsg, CHAOS_NET_OP_SEND, CHAOS_INIT_NET_SENDMMSG, 0, -1},
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

/* Per-process hit slots of the net rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_net, CHAOS_NET_MAX_RULES);

static uint64_t g_chaos_init_net_load = 0U;
static const chaos_net_config_state_t *g_chaos_init_net_seen_state = NULL;
static uint64_t g_chaos_init_net_seen_stamp = 0U;

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
    g_chaos_init_net_slots,
    g_chaos_init_net_hashes,
    g_chaos_init_net_generation,
    g_chaos_init_net_count,
    g_chaos_init_net_total,
    g_chaos_init_net_pending,
    g_chaos_init_net_buffer,
};

void chaos_init_net_start(void)
{
    uint64_t seed;

    chaos_net_config_init();
    if (getrandom(&seed, sizeof(seed), 0) == (ssize_t)sizeof(seed))
    {
        g_chaos_net_process_seed = seed;
    }
    (void)chaos_init_tracee_register(&g_chaos_init_net_rules);
}

/** @brief Bytes an iovec array of the current thread describes; CHAOS_POLICY_NO_SIZE if unknown. */
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
            total += (uint64_t)vector[index].iov_len;
        }
        done += chunk;
    }
    return total;
}

/** @brief Endpoint of a sockaddr in the thread's memory, typed by descriptor @p fd. */
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

/** @brief Bytes a msghdr in the thread's memory describes; CHAOS_POLICY_NO_SIZE if unknown. */
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

/** @brief The destination of a message in the thread's memory: its msg_name, else the peer. */
static int chaos_init_net_message(int fd, uint64_t address, chaos_net_endpoint_t *endpoint)
{
    struct msghdr message;

    if (chaos_init_read_memory(g_chaos_init_net_tid, address, &message, sizeof(message)) != 0)
    {
        return chaos_net_endpoint_from_peer_fd(fd, endpoint);
    }
    if (message.msg_name != NULL &&
        chaos_init_net_sockaddr(
            fd, (uint64_t)(uintptr_t)message.msg_name, (uint64_t)message.msg_namelen, endpoint
        ))
    {
        return 1;
    }
    return chaos_net_endpoint_from_peer_fd(fd, endpoint);
}

/** @brief Matches the first descriptor of @p fds with an endpoint and a POLL rule. */
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

/** @brief Most descriptors of one wait call that are looked at. */
#define CHAOS_INIT_NET_MAX_WAIT 1024U

/** @brief The descriptors of a pollfd array in the thread's memory. */
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

/** @brief The descriptors set in the fd_sets of a select call. */
static size_t chaos_init_net_select_fds(const chaos_init_call_t *call, int *fds)
{
    const int count = (int)call->args[0] < FD_SETSIZE ? (int)call->args[0] : FD_SETSIZE;
    size_t found = 0U;
    int set;

    for (set = 1; set <= 3; ++set)
    {
        fd_set bits;
        int fd;

        if (call->args[set] == 0U ||
            chaos_init_read_memory(g_chaos_init_net_tid, call->args[set], &bits, sizeof(bits)) != 0)
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

/** @brief The descriptors registered in epoll instance @p epfd (its fdinfo "tfd:" lines). */
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

/** @brief Finds the rule for @p call of @p entry; 0 when none matches. */
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
        found = chaos_net_endpoint_from_local_fd(fd, &endpoint);
        break;
    case CHAOS_INIT_NET_PEER:
        found = chaos_net_endpoint_from_peer_fd(fd, &endpoint);
        break;
    case CHAOS_INIT_NET_ACTIVITY:
        found = chaos_net_endpoint_from_activity_fd(fd, &endpoint);
        break;
    case CHAOS_INIT_NET_SENDTO:
        found = chaos_init_net_sockaddr(fd, call->args[4], call->args[5], &endpoint) ||
                chaos_net_endpoint_from_peer_fd(fd, &endpoint);
        break;
    case CHAOS_INIT_NET_SENDMSG:
    case CHAOS_INIT_NET_SENDMMSG:
        /* For sendmmsg the first message stands for the batch, as in the library: its
         * msghdr opens the first mmsghdr. */
        found = chaos_init_net_message(fd, call->args[1], &endpoint);
        break;
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

/** @brief Whether descriptor @p fd of thread @p tid is a socket. */
static int chaos_init_net_is_socket(pid_t tid, uint64_t fd)
{
    char name[32];
    char link[64];

    (void)snprintf(name, sizeof(name), "fd/%d", (int)fd);
    return chaos_init_proc_link(tid, name, link, sizeof(link)) > 0 &&
           strncmp(link, "socket:", 7U) == 0;
}

int chaos_init_net_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_init_net_call_t *entry = NULL;
    const chaos_net_config_state_t *state;
    chaos_net_rule_t rule;
    uint64_t size = CHAOS_POLICY_NO_SIZE;
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
    if (!chaos_net_config_prepare() || !chaos_init_net_match(entry, call, &rule))
    {
        return 1;
    }
    /* Only ERRNO, LATENCY and TIMEOUT rules get here (see chaos_init_net_supported). */
    /* The rule's counters are the calling process's, not the snapshot's. */
    state = chaos_net_config_active_state();
    rule.call_size = size;
    rule.hit = chaos_init_tracee_hit(
        &g_chaos_init_net_rules, call->tid, state->hits, state->rule_count, rule.hit
    );
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
    else
    {
        verdict->action = CHAOS_INIT_RETURN;
        verdict->value = 0;
    }
    return 1;
}
