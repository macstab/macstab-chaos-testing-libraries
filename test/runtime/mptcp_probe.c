/*
 * mptcp_probe.c — chaos-init's view of Multipath TCP sockets, on the host.
 *
 * Builds the chaos-init socket queries (src/init/chaos_init_net.c) into this
 * program and asks them, for this process's own sockets, what the kernel answers
 * directly: an MPTCP listener, an MPTCP client and the connection accepted for
 * it, and a plain TCP client of the MPTCP listener and its accepted connection
 * (which the kernel may hand out as a TCP socket). Prints one line per socket
 * and query, and exits 1 when chaos-init's answer differs, 77 when the kernel
 * has no MPTCP. Where MPTCP sockets cannot be looked up at all (no mptcp_diag),
 * chaos-init must say so, and only the TCP sockets have to match.
 */

#include "../../src/init/chaos_init_net.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/stat.h>

static int g_failures = 0;

/* Where MPTCP sockets cannot be looked up, chaos-init turns MPTCP off for Go: their
 * lookups failing is then expected, and only that chaos-init says so is checked. */
static int g_unresolvable = 0;

/** @brief The port of a sockaddr, or -1 for another family. */
static int port_of(const struct sockaddr_storage *address)
{
    if (address->ss_family == AF_INET)
    {
        return ntohs(((const struct sockaddr_in *)address)->sin_port);
    }
    if (address->ss_family == AF_INET6)
    {
        return ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
    }
    return -1;
}

/** @brief Compares chaos-init's own address and peer of @p fd with the kernel's. */
static void check(const char *what, int fd)
{
    struct sockaddr_storage real;
    struct sockaddr_storage seen;
    char path[64];
    char protocol[32] = "";
    struct stat info;
    int peer;

    (void)snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    (void)getxattr(path, "system.sockprotoname", protocol, sizeof(protocol) - 1U);
    (void)fstat(fd, &info);
    for (peer = 0; peer <= 1; ++peer)
    {
        socklen_t real_length = (socklen_t)sizeof(real);
        socklen_t seen_length = (socklen_t)sizeof(seen);
        const int real_rc = peer ? getpeername(fd, (struct sockaddr *)&real, &real_length)
                                 : getsockname(fd, (struct sockaddr *)&real, &real_length);
        const int seen_rc =
            peer ? chaos_init_net_getpeername(fd, (struct sockaddr *)&seen, &seen_length)
                 : chaos_init_net_getsockname(fd, (struct sockaddr *)&seen, &seen_length);
        const int same = real_rc == seen_rc && (real_rc != 0 || (real.ss_family == seen.ss_family &&
                                                                 port_of(&real) == port_of(&seen)));

        (void)printf(
            "%s %-24s %-8s inode %-8lu %s: kernel %d port %d, chaos-init %d port %d\n",
            same ? "ok  " : "FAIL",
            what,
            protocol,
            (unsigned long)info.st_ino,
            peer ? "peer" : "own ",
            real_rc,
            real_rc == 0 ? port_of(&real) : 0,
            seen_rc,
            seen_rc == 0 ? port_of(&seen) : 0
        );
        g_failures += same || (g_unresolvable && strncmp(protocol, "MPTCP", 5U) == 0) ? 0 : 1;
    }
}

int main(void)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    int listener;
    int client;
    int server;
    int plain;
    int fallback;

    g_chaos_init_net_tid = getpid();
    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (listener < 0)
    {
        (void)printf("skip: no MPTCP here (%s)\n", strerror(errno));
        return 77;
    }
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 4) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0)
    {
        perror("mptcp listener");
        return 1;
    }
    client = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    plain = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client < 0 || plain < 0 ||
        connect(client, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        perror("mptcp client");
        return 1;
    }
    server = accept(listener, NULL, NULL);
    if (connect(plain, (struct sockaddr *)&address, sizeof(address)) != 0)
    {
        perror("tcp client");
        return 1;
    }
    fallback = accept(listener, NULL, NULL);
    if (server < 0 || fallback < 0)
    {
        perror("accept");
        return 1;
    }
    /* What sock_diag answers when asked for MPTCP sockets at all. */
    {
        struct
        {
            struct nlmsghdr header;
            struct inet_diag_req_v2 request;
            struct rtattr attribute;
            uint32_t protocol;
        } query;
        static long answer[2048];
        const int link = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        ssize_t got;

        memset(&query, 0, sizeof(query));
        query.header.nlmsg_len = (uint32_t)sizeof(query);
        query.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
        query.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        query.request.sdiag_family = AF_INET;
        query.request.idiag_states = ~0U;
        query.attribute.rta_len = (unsigned short)RTA_LENGTH(sizeof(query.protocol));
        query.attribute.rta_type = INET_DIAG_REQ_PROTOCOL;
        query.protocol = IPPROTO_MPTCP;
        if (link >= 0 && send(link, &query, sizeof(query), 0) == (ssize_t)sizeof(query) &&
            (got = recv(link, answer, sizeof(answer), 0)) > 0)
        {
            const struct nlmsghdr *first = (const struct nlmsghdr *)(const void *)answer;

            (void)printf(
                "sock_diag for MPTCP: %ld bytes, first message type %u%s%d\n",
                (long)got,
                (unsigned)first->nlmsg_type,
                first->nlmsg_type == NLMSG_ERROR ? ", error " : ", ",
                first->nlmsg_type == NLMSG_ERROR
                    ? ((const struct nlmsgerr *)NLMSG_DATA(first))->error
                    : 0
            );
        }
        if (link >= 0)
        {
            (void)close(link);
        }
    }
    g_unresolvable = chaos_init_net_mptcp_unresolvable();
    (void)printf(
        "%s\n",
        g_unresolvable ? "MPTCP sockets cannot be looked up here: chaos-init turns MPTCP off for Go"
                       : "MPTCP sockets can be looked up here"
    );
    check("MPTCP listener", listener);
    check("MPTCP client", client);
    check("MPTCP accepted", server);
    check("TCP client", plain);
    check("accepted from TCP client", fallback);
    return g_failures == 0 ? 0 : 1;
}
