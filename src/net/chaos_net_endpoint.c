/**
 * @file chaos_net_endpoint.c
 * @brief Selector parsing, endpoint resolution from sockets, and rank-based matching.
 *
 * @details
 * Implements chaos_net_endpoint.h in both directions:
 *
 *   **Text to endpoint** (chaos_net_endpoint_parse_selector()): the scheme prefix
 *   (`tcp4://`, `tcp6://`, `udp4://`, `udp6://`, `unix://`) selects the kind and the
 *   family parser. IPv4 splits host and port at the last `:`; IPv6 requires
 *   `[addr]:port` because the address contains colons.
 *
 *   **Socket to endpoint** (chaos_net_endpoint_from_sockaddr_fd(), _from_local_fd(),
 *   _from_peer_fd()): the address comes from a sockaddr (argument, getsockname or
 *   getpeername) and the transport from getsockopt(SO_TYPE); both are needed for the
 *   kind.
 *
 * @par Invariants:
 *   - Every getsockname/getpeername/getsockopt runs with the reentrancy guard set and
 *     errno saved and restored on every path: resolution is invisible to the caller.
 *   - Ports are stored in host byte order.
 *   - sun_path is never read beyond address_length: it may be absent (unnamed sockets
 *     report address_length == sizeof(sa_family_t)) and need not be NUL-terminated.
 *   - Abstract UNIX names (sun_path[0] == '\0') are written as /proc/net/unix shows them,
 *     `@` for each NUL, so `unix://@name` selects them.
 *   - SOCK_CLOEXEC and SOCK_NONBLOCK are masked off before comparing with SOCK_STREAM /
 *     SOCK_DGRAM: socket() takes them in its type argument; for SO_TYPE the mask is
 *     defensive.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_endpoint.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

/**
 * @brief Compile-time proof that a full sun_path fits in chaos_net_endpoint_t::value.text.
 *
 * @details chaos_net_endpoint_from_sockaddr() bounds a UNIX path by sizeof(sun_path) and
 * appends a NUL, so the destination must be strictly larger. sun_path is 108 bytes on
 * Linux and 104 on the BSDs, against CHAOS_NET_MAX_TEXT (256). Shrinking
 * CHAOS_NET_MAX_TEXT below that fails the build (negative array size) instead of
 * truncating paths at run time.
 */
typedef char chaos_net_sun_path_fits_endpoint_text
    [sizeof(((struct sockaddr_un *)0)->sun_path) < sizeof(((chaos_net_endpoint_t *)0)->value.text)
         ? 1
         : -1];

/**
 * @brief Parses a decimal port in [0, 65535].
 *
 * @details strtoul, then nothing may follow the digits (not even a blank). strtoul skips
 * leading blanks and accepts a sign; "-1" wraps far above 65535 and is rejected.
 *
 * @param text  NUL-terminated port text; NULL or empty yields 0.
 * @param port  Output in host byte order; NULL yields 0.
 * @return 1 on success; 0 if empty, non-numeric, trailing characters, or out of range.
 */
static int chaos_net_parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || port == NULL || *text == '\0')
    {
        return 0;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value > 65535UL)
    {
        return 0;
    }

    *port = (uint16_t)value;
    return 1;
}

/**
 * @brief Parses the part of a `tcp4://` or `udp4://` selector after the scheme.
 *
 * @details `HOST:PORT`, split at the last `:`. HOST is `*` (wildcard host) or a
 * dotted-quad address accepted by inet_pton(AF_INET); an empty HOST is rejected.
 *
 * @param body      Text after the scheme.
 * @param kind      CHAOS_NET_ENDPOINT_TCP4 or CHAOS_NET_ENDPOINT_UDP4.
 * @param endpoint  Output (already zeroed); kind, wildcard_host or value.ipv4, and port.
 * @return 1 on success; 0 on any parse error.
 */
static int chaos_net_parse_ipv4_selector(
    const char *body, chaos_net_endpoint_kind_t kind, chaos_net_endpoint_t *endpoint
)
{
    const char *port_text;
    size_t host_len;
    char host[INET_ADDRSTRLEN];

    port_text = strrchr(body, ':');
    if (port_text == NULL || port_text == body)
    {
        return 0;
    }

    host_len = (size_t)(port_text - body);
    if (host_len == 1U && body[0] == '*')
    {
        endpoint->wildcard_host = 1;
    }
    else
    {
        if (host_len >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, body, host_len);
        host[host_len] = '\0';
        if (inet_pton(AF_INET, host, &endpoint->value.ipv4) != 1)
        {
            return 0;
        }
    }

    endpoint->kind = kind;
    return chaos_net_parse_port(port_text + 1, &endpoint->port);
}

/**
 * @brief Parses the part of a `tcp6://` or `udp6://` selector after the scheme.
 *
 * @details Two forms:
 *   - `*:PORT`      -- wildcard host.
 *   - `[ADDR]:PORT` -- an address accepted by inet_pton(AF_INET6); the `]` must be
 *                      followed directly by `:`.
 * A bare `*` (no port) is rejected: there is no port wildcard.
 *
 * @param body      Text after the scheme.
 * @param kind      CHAOS_NET_ENDPOINT_TCP6 or CHAOS_NET_ENDPOINT_UDP6.
 * @param endpoint  Output (already zeroed); kind is set first, before any early return.
 * @return 1 on success; 0 on any parse error.
 */
static int chaos_net_parse_ipv6_selector(
    const char *body, chaos_net_endpoint_kind_t kind, chaos_net_endpoint_t *endpoint
)
{
    const char *port_text;
    char host[INET6_ADDRSTRLEN];
    size_t host_len;

    endpoint->kind = kind;
    if (strcmp(body, "*") == 0)
    {
        /* A family needs a port: bare "*" is not a selector here. */
        return 0;
    }
    if (body[0] == '*')
    {
        if (body[1] != ':')
        {
            return 0;
        }
        endpoint->wildcard_host = 1;
        return chaos_net_parse_port(body + 2, &endpoint->port);
    }
    if (body[0] != '[')
    {
        return 0;
    }

    port_text = strchr(body, ']');
    if (port_text == NULL || port_text[1] != ':')
    {
        return 0;
    }

    host_len = (size_t)(port_text - (body + 1));
    if (host_len == 0U || host_len >= sizeof(host))
    {
        return 0;
    }

    (void)memcpy(host, body + 1, host_len);
    host[host_len] = '\0';
    if (inet_pton(AF_INET6, host, &endpoint->value.ipv6) != 1)
    {
        return 0;
    }

    return chaos_net_parse_port(port_text + 2, &endpoint->port);
}

/**
 * @brief Parses a selector (format in chaos_net_endpoint.h).
 *
 * @details Zeroes @p endpoint first so every failure leaves it clean, and records
 * selector_len before dispatching so ties are broken on the text as written. A
 * `unix://` path is stored verbatim; `*` there means any UNIX socket.
 */
int chaos_net_endpoint_parse_selector(const char *text, chaos_net_endpoint_t *endpoint)
{
    const char *body;

    if (text == NULL || endpoint == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
    endpoint->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        endpoint->kind = CHAOS_NET_ENDPOINT_ANY;
        return 1;
    }
    if (strncmp(text, "tcp4://", 7) == 0)
    {
        return chaos_net_parse_ipv4_selector(text + 7, CHAOS_NET_ENDPOINT_TCP4, endpoint);
    }
    if (strncmp(text, "tcp6://", 7) == 0)
    {
        return chaos_net_parse_ipv6_selector(text + 7, CHAOS_NET_ENDPOINT_TCP6, endpoint);
    }
    if (strncmp(text, "udp4://", 7) == 0)
    {
        return chaos_net_parse_ipv4_selector(text + 7, CHAOS_NET_ENDPOINT_UDP4, endpoint);
    }
    if (strncmp(text, "udp6://", 7) == 0)
    {
        return chaos_net_parse_ipv6_selector(text + 7, CHAOS_NET_ENDPOINT_UDP6, endpoint);
    }
    if (strncmp(text, "unix://", 7) == 0)
    {
        body = text + 7;
        if (*body == '\0' || strlen(body) >= sizeof(endpoint->value.text))
        {
            return 0;
        }
        endpoint->kind = CHAOS_NET_ENDPOINT_UNIX;
        (void)memcpy(endpoint->value.text, body, strlen(body) + 1U);
        return 1;
    }
    return 0;
}

/**
 * @brief Matches a selector against a runtime endpoint (ranks in chaos_net_endpoint.h).
 *
 * @details Kinds must be equal unless the selector is ANY. For IP kinds the port is
 * compared first (it rejects most candidates), then the wildcard flag, then the address
 * bytes with memcmp: in_addr and in6_addr have no padding, so a byte comparison is an
 * address comparison.
 *
 * @return Non-zero on a match (rank >= 1); 0 otherwise.
 */
int chaos_net_endpoint_matches(
    const chaos_net_endpoint_t *selector,
    const chaos_net_endpoint_t *endpoint,
    unsigned int *rank_out
)
{
    unsigned int rank = 0U;

    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL || endpoint == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_ANY)
    {
        rank = 1U;
    }
    else if (selector->kind == CHAOS_NET_ENDPOINT_UNIX && endpoint->kind == CHAOS_NET_ENDPOINT_UNIX)
    {
        if (strcmp(selector->value.text, "*") == 0)
        {
            rank = 2U;
        }
        else
        {
            if (strcmp(selector->value.text, endpoint->value.text) != 0)
            {
                return 0;
            }
            rank = 4U;
        }
    }
    else if (selector->kind == endpoint->kind)
    {
        switch (selector->kind)
        {
        case CHAOS_NET_ENDPOINT_TCP4:
        case CHAOS_NET_ENDPOINT_UDP4:
            if (selector->port != endpoint->port)
            {
                return 0;
            }
            if (selector->wildcard_host != 0)
            {
                rank = 2U;
                break;
            }
            if (memcmp(
                    &selector->value.ipv4, &endpoint->value.ipv4, sizeof(selector->value.ipv4)
                ) != 0)
            {
                return 0;
            }
            rank = 3U;
            break;
        case CHAOS_NET_ENDPOINT_TCP6:
        case CHAOS_NET_ENDPOINT_UDP6:
            if (selector->port != endpoint->port)
            {
                return 0;
            }
            if (selector->wildcard_host != 0)
            {
                rank = 2U;
                break;
            }
            /* in6_addr is 16 bytes without padding: memcmp compares the address. */
            if (memcmp(
                    &selector->value.ipv6, &endpoint->value.ipv6, sizeof(selector->value.ipv6)
                ) != 0)
            {
                return 0;
            }
            rank = 3U;
            break;
        default:
            return 0;
        }
    }
    else
    {
        return 0;
    }

    if (rank_out != NULL)
    {
        *rank_out = rank;
    }
    return 1;
}

unsigned int chaos_net_endpoint_selector_rank(const chaos_net_endpoint_t *selector)
{
    if (selector == NULL)
    {
        return 0U;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_ANY)
    {
        return 1U;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_UNIX)
    {
        return strcmp(selector->value.text, "*") == 0 ? 2U : 4U;
    }
    return selector->wildcard_host != 0 ? 2U : 3U;
}

/**
 * @brief Builds the endpoint of a not-yet-addressed socket from socket() arguments.
 *
 * @details IP families: kind from (domain, type), wildcard_host = 1, port 0, so SOCKET
 * rules with `tcp4://\*:0`-style selectors match. AF_UNIX: path `*`, matched by
 * `unix://\*`. SOCK_CLOEXEC and SOCK_NONBLOCK are masked off @p type because Linux
 * accepts them ORed in and they say nothing about stream vs datagram. AF_UNIX accepts
 * any type.
 */
int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
)
{
    (void)protocol;

    if (endpoint == NULL)
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
#ifdef SOCK_CLOEXEC
    type &= ~SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    type &= ~SOCK_NONBLOCK;
#endif
    if (domain == AF_INET)
    {
        if (type == SOCK_STREAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_TCP4;
            endpoint->wildcard_host = 1;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_UDP4;
            endpoint->wildcard_host = 1;
            return 1;
        }
        return 0;
    }
    if (domain == AF_INET6)
    {
        if (type == SOCK_STREAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_TCP6;
            endpoint->wildcard_host = 1;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_UDP6;
            endpoint->wildcard_host = 1;
            return 1;
        }
        return 0;
    }
    if (domain == AF_UNIX)
    {
        endpoint->kind = CHAOS_NET_ENDPOINT_UNIX;
        /* Two bytes: "*" and its NUL. */
        (void)memcpy(endpoint->value.text, "*", 2U);
        return 1;
    }

    return 0;
}

/**
 * @brief Local address first, then the peer address.
 *
 * @details getsockname fails only on a non-socket; it succeeds on an unbound socket too,
 * with a wildcard address and port 0 (IP) or an empty path (UNIX), in which case the peer
 * is never asked. The peer fallback matters only where getsockname fails or the local
 * address does not normalise.
 */
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    if (endpoint == NULL)
    {
        return 0;
    }

    if (chaos_net_endpoint_from_local_fd(fd, endpoint))
    {
        return 1;
    }
    return chaos_net_endpoint_from_peer_fd(fd, endpoint);
}

/**
 * @brief The endpoint kind for @p family on socket @p fd, from getsockopt(SO_TYPE).
 *
 * @details Shared by every resolution path. Calls g_chaos_net_real_getsockopt with the
 * guard set and errno preserved. AF_UNIX yields UNIX for every socket type; IP families
 * need SOCK_STREAM (TCP) or SOCK_DGRAM (UDP), so raw and SCTP sockets do not resolve.
 *
 * @param fd     Socket to query.
 * @param family sa_family of the address being resolved.
 * @param kind   Output; NULL yields 0.
 * @return 1 on success; 0 if getsockopt is unresolved or fails (ENOTSOCK), or the type
 *         does not map.
 */
static int
chaos_net_endpoint_kind_from_socket(int fd, sa_family_t family, chaos_net_endpoint_kind_t *kind)
{
    int type = 0;
    socklen_t type_len = (socklen_t)sizeof(type);
    int previous;
    int saved_errno;
    int rc;

    if (kind == NULL || g_chaos_net_real_getsockopt == NULL)
    {
        return 0;
    }

    /* The guard keeps this out of libchaos-net's own wrappers; the lookup is the
     * library's business, so its failure must not leak into errno. */
    saved_errno = errno;
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len);
    chaos_net_leave_internal(previous);
    errno = saved_errno;
    if (rc != 0)
    {
        return 0;
    }

    /* Defensive: SO_TYPE reports the bare type, but the creation flags must not count. */
#ifdef SOCK_CLOEXEC
    type &= ~SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    type &= ~SOCK_NONBLOCK;
#endif
    if (family == AF_INET)
    {
        if (type == SOCK_STREAM)
        {
            *kind = CHAOS_NET_ENDPOINT_TCP4;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            *kind = CHAOS_NET_ENDPOINT_UDP4;
            return 1;
        }
        return 0;
    }
    if (family == AF_INET6)
    {
        if (type == SOCK_STREAM)
        {
            *kind = CHAOS_NET_ENDPOINT_TCP6;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            *kind = CHAOS_NET_ENDPOINT_UDP6;
            return 1;
        }
        return 0;
    }
    if (family == AF_UNIX)
    {
        *kind = CHAOS_NET_ENDPOINT_UNIX;
        return 1;
    }

    return 0;
}

/**
 * @brief Resolves a sockaddr plus the socket's SO_TYPE into an endpoint.
 *
 * @details By sa_family:
 *   - AF_INET: needs sizeof(sockaddr_in); address and port (ntohs).
 *   - AF_INET6: needs sizeof(sockaddr_in6); address and port. An IPv4-mapped address
 *     (::ffff:a.b.c.d) becomes TCP4/UDP4 with the IPv4 address, so IPv4 rules match a
 *     dual-stack socket's IPv4 traffic. Flow label and scope id are not kept.
 *   - AF_UNIX: the path, bounded by address_length and sizeof(sun_path), terminated
 *     explicitly. Abstract name: `@` for each NUL (as in /proc/net/unix). No path byte
 *     (unnamed socket, e.g. socketpair()): an empty path, which only wildcards match.
 *   - Anything else: 0.
 *
 * @param fd              Socket asked for SO_TYPE.
 * @param address         sockaddr; NULL, or shorter than sa_family_t, yields 0.
 * @param address_length  Bytes valid at @p address.
 * @param endpoint        Output; zeroed on entry.
 * @param fd_is_socket    Non-zero when @p address came from getsockname or getpeername on
 *                        @p fd, which proves it a socket: an AF_UNIX address then needs no
 *                        SO_TYPE query (its kind is UNIX for every type), saving a system
 *                        call per lookup. Zero for a caller's address, where the query also
 *                        rejects a non-socket @p fd.
 * @return 1 on success; 0 on any validation or SO_TYPE failure.
 */
static int chaos_net_endpoint_from_sockaddr(
    int fd,
    const struct sockaddr *address,
    socklen_t address_length,
    chaos_net_endpoint_t *endpoint,
    int fd_is_socket
)
{
    const struct sockaddr_in *ipv4;
    const struct sockaddr_in6 *ipv6;
    const struct sockaddr_un *unix_address;
    const char *path_end;
    size_t path_max;
    size_t path_len;

    if (address == NULL || endpoint == NULL || address_length < (socklen_t)sizeof(sa_family_t))
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
    switch (address->sa_family)
    {
    case AF_INET:
        if (address_length < (socklen_t)sizeof(*ipv4))
        {
            return 0;
        }
        ipv4 = (const struct sockaddr_in *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_INET, &endpoint->kind))
        {
            return 0;
        }
        /* Selectors hold ports in host byte order. */
        endpoint->port = ntohs(ipv4->sin_port);
        endpoint->value.ipv4 = ipv4->sin_addr;
        return 1;
    case AF_INET6:
        if (address_length < (socklen_t)sizeof(*ipv6))
        {
            return 0;
        }
        ipv6 = (const struct sockaddr_in6 *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_INET6, &endpoint->kind))
        {
            return 0;
        }
        endpoint->port = ntohs(ipv6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr))
        {
            /* A dual-stack socket talking to an IPv4 address (::ffff:a.b.c.d), as
             * Java, Go and most servers do: the traffic is IPv4, so it is matched
             * by tcp4:// and udp4:// rules. */
            endpoint->kind = endpoint->kind == CHAOS_NET_ENDPOINT_TCP6 ? CHAOS_NET_ENDPOINT_TCP4
                                                                       : CHAOS_NET_ENDPOINT_UDP4;
            (void)memcpy(&endpoint->value.ipv4, &ipv6->sin6_addr.s6_addr[12], 4U);
            return 1;
        }
        /* Flow label and scope id are not kept: selectors cannot express them, and an
         * address compare that included them would never match. */
        endpoint->value.ipv6 = ipv6->sin6_addr;
        return 1;
    case AF_UNIX:
        unix_address = (const struct sockaddr_un *)address;
        /* sun_path is neither guaranteed to be present nor NUL-terminated, so it is
         * scanned within address_length, never with strlen():
         *   1. Unnamed sockets (socketpair(2), or an AF_UNIX socket never bound):
         *      getsockname/getpeername return address_length == sizeof(sa_family_t) and
         *      write no sun_path byte. The caller's sockaddr_storage is uninitialised
         *      stack; strlen() would read garbage and could run past the object.
         *   2. A caller may pass a sun_path that fills the field without a terminator,
         *      with address_length covering exactly the path bytes. Linux accepts this,
         *      and strlen() would read past the caller's buffer.
         * Lengths at or below the sun_path offset carry no path. */
        path_max = (size_t)address_length > offsetof(struct sockaddr_un, sun_path)
                       ? (size_t)address_length - offsetof(struct sockaddr_un, sun_path)
                       : 0U;
        if (path_max > sizeof(unix_address->sun_path))
        {
            path_max = sizeof(unix_address->sun_path);
        }
        if (fd_is_socket)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_UNIX;
        }
        else if (!chaos_net_endpoint_kind_from_socket(fd, AF_UNIX, &endpoint->kind))
        {
            return 0;
        }
        /* An unnamed socket (socketpair(), a client never bound) has no name: the empty
         * name, which only the wildcards match. */
        if (path_max == 0U)
        {
            return 1;
        }
        /* An abstract name starts with a NUL and may contain more. It is written as
         * Linux shows it in /proc/net/unix, '@' for each NUL, so unix://@name selects
         * it. */
        if (unix_address->sun_path[0] == '\0')
        {
            size_t index;

            for (index = 0U; index < path_max; ++index)
            {
                const char ch = unix_address->sun_path[index];

                endpoint->value.text[index] = ch == '\0' ? '@' : ch;
            }
            endpoint->value.text[path_max] = '\0';
            return 1;
        }
        /* memchr rather than strnlen: C89, so no feature-test macro question across the
         * glibc/musl build matrix. */
        path_end = (const char *)memchr(unix_address->sun_path, '\0', path_max);
        path_len = path_end != NULL ? (size_t)(path_end - unix_address->sun_path) : path_max;
        /* No length check: path_len <= sizeof(sun_path), which
         * chaos_net_sun_path_fits_endpoint_text proves smaller than value.text. */
        (void)memcpy(endpoint->value.text, unix_address->sun_path, path_len);
        endpoint->value.text[path_len] = '\0';
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief Exported name of chaos_net_endpoint_from_sockaddr() (contract in the header).
 */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    return chaos_net_endpoint_from_sockaddr(fd, address, address_length, endpoint, 0);
}

/**
 * @brief getsockname on @p fd, then sockaddr resolution (contract in the header).
 *
 * @details sockaddr_storage on the stack fits every family. errno is saved and restored
 * around the lookup.
 */
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;
    int saved_errno;

    if (endpoint == NULL || g_chaos_net_real_getsockname == NULL)
    {
        return 0;
    }

    saved_errno = errno;
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getsockname(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    errno = saved_errno;
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint, 1
    );
}

/**
 * @brief getpeername on @p fd, then sockaddr resolution (contract in the header).
 *
 * @details An unconnected socket fails with ENOTCONN; this returns 0 with errno
 * restored, and the caller forwards without injection for this end.
 */
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;
    int saved_errno;

    if (endpoint == NULL || g_chaos_net_real_getpeername == NULL)
    {
        return 0;
    }

    saved_errno = errno;
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getpeername(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    errno = saved_errno;
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint, 1
    );
}
