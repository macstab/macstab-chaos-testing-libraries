/**
 * @file mptcp_probe.c
 * @brief Proves that chaos-init's socket-address queries answer for Multipath TCP sockets
 *        exactly as the kernel does, on the host kernel.
 *
 * @details
 * Go listens and dials with MPTCP by default from Go 1.24 where the kernel offers it. MPTCP
 * sockets appear in no /proc/net table, so chaos-init (which must read a tracee's socket
 * addresses from outside to match net selectors) asks NETLINK_SOCK_DIAG for them. A wrong
 * answer would make every net rule miss Go programs.
 *
 * The probe compiles chaos-init's query code (chaos_init_net.c, chaos_init_proc.c,
 * chaos_init_tracee.c) into itself and creates an MPTCP listener, an MPTCP client with its
 * accepted connection, and a plain TCP client of the MPTCP listener with its accepted
 * connection (the kernel may hand that one out as a TCP socket). For each socket it compares
 * chaos_init_net_getsockname()/getpeername() with the kernel's getsockname()/getpeername()
 * (return code, family, port) and prints one ok/FAIL line per socket and side, plus the raw
 * sock_diag answer for diagnosis.
 *
 * Where MPTCP sockets cannot be looked up at all (no mptcp_diag module),
 * chaos_init_net_mptcp_unresolvable() must report it (chaos-init then turns MPTCP off for Go);
 * MPTCP lookups then print "n/a" and only the TCP sockets must match.
 *
 * Run by test_mptcp.sh on the host (Docker Desktop's kernel has no MPTCP).
 *
 * Exit: 0 when every comparison matched; 1 on a mismatch or a setup failure; 77 when the
 * kernel has no MPTCP (socket(IPPROTO_MPTCP) fails), which test_mptcp.sh turns into a skip.
 */

#include "../../src/init/chaos_init_net.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <arpa/inet.h>
#include <stdio.h>
#include <sys/stat.h>

static int g_failures = 0;

/* Set when chaos-init reports MPTCP sockets unresolvable (it then turns MPTCP off for Go):
 * failed MPTCP lookups are expected and reported as "n/a" instead of FAIL. */
static int g_unresolvable = 0;

/** @brief Port of an AF_INET/AF_INET6 address in host order, or -1 for another family. */
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

/**
 * @brief Compares chaos-init's local and peer address of @p fd with the kernel's (return code,
 *        family, port), prints one line per side and counts mismatches.
 */
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
        const int expected = g_unresolvable && strncmp(protocol, "MPTCP", 5U) == 0;
        const int same = real_rc == seen_rc && (real_rc != 0 || (real.ss_family == seen.ss_family &&
                                                                 port_of(&real) == port_of(&seen)));

        (void)printf(
            "%s %-24s %-8s inode %-8lu %s: kernel %d port %d, chaos-init %d port %d\n",
            same       ? "ok  "
            : expected ? "n/a "
                       : "FAIL",
            what,
            protocol,
            (unsigned long)info.st_ino,
            peer ? "peer" : "own ",
            real_rc,
            real_rc == 0 ? port_of(&real) : 0,
            seen_rc,
            seen_rc == 0 ? port_of(&seen) : 0
        );
        g_failures += same || expected ? 0 : 1;
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
    /* Diagnostic only: print what sock_diag answers to an MPTCP dump request (an NLMSG_ERROR
     * here means no mptcp_diag), so a failure can be attributed to the kernel. */
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
