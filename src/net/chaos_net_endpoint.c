/**
 * @file chaos_net_endpoint.c
 * @brief Endpoint normalisation: parsing selectors and deriving endpoints from sockets.
 *
 * @details
 * This file implements the two-direction translation described in chaos_net_endpoint.h:
 *
 *   **Text → endpoint** (chaos_net_endpoint_parse_selector):
 *   A config selector string is parsed left-to-right. The scheme prefix
 *   (tcp4://, tcp6://, udp4://, udp6://, unix://) determines the endpoint kind and
 *   dispatches to a family-specific parser. IPv4 parsing uses a simple strrchr(':')
 *   to split host and port. IPv6 parsing requires square-bracket notation
 *   ([addr]:port) because the address itself contains colons.
 *
 *   **Socket → endpoint** (chaos_net_endpoint_from_sockaddr_fd, *_from_local_fd,
 *   *_from_peer_fd):
 *   Normalisation combines two pieces of information that are available separately:
 *     1. The address bytes (IP + port) from the sockaddr struct or getsockname/getpeername.
 *     2. The socket type (SOCK_STREAM vs SOCK_DGRAM) from getsockopt(SO_TYPE).
 *   Both are required to produce the final endpoint kind (TCP4/UDP4/etc.).
 *
 * @par Invariants maintained by this file:
 *   - All functions that call getsockname, getpeername, or getsockopt set the
 *     reentrancy guard before the call and restore it on all exit paths,
 *     preventing libchaos-net from intercepting its own internal queries.
 *   - Port values are always stored in host byte order (ntohs applied on input).
 *   - Abstract UNIX socket paths (sun_path[0] == '\0') are rejected because they
 *     cannot be represented as a printable config selector string.
 *   - SOCK_CLOEXEC and SOCK_NONBLOCK flags are masked off the SO_TYPE result on
 *     Linux before comparing to SOCK_STREAM / SOCK_DGRAM, because some kernels
 *     return these bits set via getsockopt.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_endpoint.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

/**
 * @brief Parses a decimal port number from a NUL-terminated string.
 *
 * @details Uses strtoul with strict validation: the entire string must consist of
 * decimal digits and the value must fit in [0, 65535]. Any trailing non-digit
 * characters (including whitespace) cause a parse failure, enforcing the contract
 * that config port fields are exact numeric tokens with no surrounding space.
 *
 * @param text  NUL-terminated string containing a decimal port number. Must not be NULL.
 * @param port  Output: receives the parsed port in host byte order. Must not be NULL.
 * @return 1 on success; 0 if @p text is NULL, empty, non-numeric, or out of range.
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
 * @brief Parses the body of a tcp4:// or udp4:// selector (the part after the scheme).
 *
 * @details The expected format is `HOST:PORT` where HOST is either a dotted-decimal
 * IPv4 address or the single character `*` (wildcard host). The port is found by
 * strrchr(':'), so IPv4 addresses (which cannot themselves contain colons) are split
 * correctly. An empty host field (selector starts with ':') is rejected.
 *
 * @param body      Pointer into the selector text after the `tcp4://` or `udp4://` prefix.
 * @param kind      CHAOS_NET_ENDPOINT_TCP4 or CHAOS_NET_ENDPOINT_UDP4.
 * @param endpoint  Output endpoint; kind, wildcard_host / value.ipv4, and port are set.
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
 * @brief Parses the body of a tcp6:// or udp6:// selector (the part after the scheme).
 *
 * @details Two formats are accepted:
 *   - `*:PORT`     — wildcard host, specific port.
 *   - `[ADDR]:PORT` — specific IPv6 address (brackets required to avoid ambiguity
 *                     with the colons in the address itself).
 *
 * The bare `"*"` without a port is explicitly rejected (the scheme prefix alone
 * provides no useful selector). The bracket/colon structure is validated strictly:
 * the closing `]` must be immediately followed by `:`.
 *
 * @param body      Pointer after the `tcp6://` or `udp6://` prefix.
 * @param kind      CHAOS_NET_ENDPOINT_TCP6 or CHAOS_NET_ENDPOINT_UDP6.
 * @param endpoint  Output; kind is set first to simplify early-return paths.
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
        /* Bare "*" without a port is not a valid selector for an address family. */
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
 * @brief Parses a config selector string into a chaos_net_endpoint_t.
 *
 * @details See chaos_net_endpoint.h for the full format specification. This function
 * zeroes @p endpoint before dispatch to ensure a consistent state on all exit paths.
 * selector_len is recorded from strlen(text) before any parsing, so it reflects the
 * original string length and can be used as a tie-breaker in rule selection.
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
 * @brief Tests whether a selector endpoint matches a runtime endpoint, with specificity rank.
 *
 * @details The matching logic implements a four-level specificity hierarchy:
 *   - Rank 1: ANY wildcard selector (`"*"`). Matches everything.
 *   - Rank 2: UNIX selector with `"*"` path, or IPv4/IPv6 with wildcard_host (port must match).
 *   - Rank 3: IPv4 or IPv6 with exact IP and exact port match.
 *   - Rank 4: UNIX with exact path match.
 *
 * Kind must match exactly (TCP4 ≠ UDP4, TCP4 ≠ TCP6) except that ANY matches all.
 * For IPv4/IPv6, port is checked before the address bytes to short-circuit early.
 * memcmp is used for address comparison because in_addr/in6_addr have no padding
 * bytes on any supported platform and the structs are compared in full.
 *
 * @return Non-zero if the selector matches (rank >= 1); 0 if no match.
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
            /* in6_addr is 16 bytes with no padding; memcmp is correct and portable. */
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
    return rank != 0U;
}

/**
 * @brief Constructs a wildcard endpoint from socket creation parameters.
 *
 * @details At socket() time there is no bound or connected address, so the
 * resulting endpoint uses wildcard_host=1 and port=0 for IP families, or
 * the path text `"*"` for UNIX. This allows socket-creation rules to use
 * selectors such as `tcp4://\*:0` (match any TCP4 socket creation) or `"*"`.
 *
 * SOCK_CLOEXEC and SOCK_NONBLOCK are masked from @p type before inspection
 * because Linux allows these flags to be OR'd into the type argument of
 * socket(2) and they have no bearing on the stream vs. datagram distinction.
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
        /* Two-byte copy includes the NUL terminator. */
        (void)memcpy(endpoint->value.text, "*", 2U);
        return 1;
    }

    return 0;
}

/**
 * @brief Tries local address first, then peer address, for shutdown-style operations.
 *
 * @details shutdown() may be called on a socket that is bound but not connected
 * (server-side), connected but not bound to a specific local port (client-side),
 * or fully connected. Trying getsockname first covers the server case; falling
 * back to getpeername covers connected-only sockets.
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
 * @brief Maps (sa_family, SO_TYPE) to a chaos_net_endpoint_kind_t.
 *
 * @details This internal helper factors out the getsockopt(SO_TYPE) call shared
 * by chaos_net_endpoint_from_sockaddr() and the fd-based resolution functions.
 * It is called with the reentrancy guard already set by the caller, so the
 * g_chaos_net_real_getsockopt call will not re-enter the interposition layer.
 *
 * @param fd     Socket fd to query.
 * @param family sa_family_t from the sockaddr (AF_INET, AF_INET6, or AF_UNIX).
 * @param kind   Output: receives the resulting endpoint kind.
 * @return 1 on success; 0 if getsockopt fails, kind is NULL, or the type is
 *         not SOCK_STREAM/SOCK_DGRAM.
 */
static int
chaos_net_endpoint_kind_from_socket(int fd, sa_family_t family, chaos_net_endpoint_kind_t *kind)
{
    int type = 0;
    socklen_t type_len = (socklen_t)sizeof(type);
    int previous;

    if (kind == NULL || g_chaos_net_real_getsockopt == NULL)
    {
        return 0;
    }

    /* Guard: getsockopt must not re-enter the interposition layer. */
    previous = chaos_net_enter_internal();
    if (g_chaos_net_real_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0)
    {
        chaos_net_leave_internal(previous);
        return 0;
    }
    chaos_net_leave_internal(previous);

    /* Mask Linux-specific creation-time flags; they are not relevant to stream/dgram. */
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
 * @brief Core normalisation function: converts a struct sockaddr + fd into an endpoint.
 *
 * @details Dispatches on address->sa_family:
 *   - AF_INET: validates address_length >= sizeof(sockaddr_in), extracts
 *     sin_addr and sin_port (ntohs applied). Uses @p fd to query SO_TYPE for kind.
 *   - AF_INET6: validates address_length >= sizeof(sockaddr_in6), extracts
 *     sin6_addr and sin6_port. sin6_flowinfo and sin6_scope_id are not stored;
 *     they are not relevant for config-file matching.
 *   - AF_UNIX: copies sun_path; rejects abstract paths (sun_path[0] == '\0')
 *     and paths that would overflow value.text.
 *   - Other families: rejected (return 0).
 *
 * @param fd              Used for SO_TYPE query; must be a valid socket fd.
 * @param address         Sockaddr to normalise. Must not be NULL and must be at
 *                        least sizeof(sa_family_t) bytes.
 * @param address_length  Size of the buffer at @p address in bytes.
 * @param endpoint        Output; zeroed on entry to this function.
 * @return 1 on success; 0 on any validation or query failure.
 */
static int chaos_net_endpoint_from_sockaddr(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    const struct sockaddr_in *ipv4;
    const struct sockaddr_in6 *ipv6;
    const struct sockaddr_un *unix_address;

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
        /* ntohs: config selectors use host byte order; ensure consistent comparison. */
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
        /* sin6_flowinfo and sin6_scope_id are intentionally not stored;
         * config selectors cannot express them and they would break matching. */
        endpoint->value.ipv6 = ipv6->sin6_addr;
        return 1;
    case AF_UNIX:
        unix_address = (const struct sockaddr_un *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_UNIX, &endpoint->kind))
        {
            return 0;
        }
        /* Abstract UNIX sockets have a NUL as the first byte of sun_path.
         * They cannot be represented as a config selector string, so reject them. */
        if (unix_address->sun_path[0] == '\0')
        {
            return 0;
        }
        if (strlen(unix_address->sun_path) >= sizeof(endpoint->value.text))
        {
            return 0;
        }
        (void
        )memcpy(endpoint->value.text, unix_address->sun_path, strlen(unix_address->sun_path) + 1U);
        return 1;
    default:
        return 0;
    }
}

/**
 * @brief Public wrapper around the internal sockaddr normaliser.
 *
 * @details Provides a stable external interface that the socket interceptors
 * (bind, connect, sendto, sendmsg) can call when a sockaddr is already available
 * as a function argument. The fd is still required to resolve SO_TYPE.
 */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    return chaos_net_endpoint_from_sockaddr(fd, address, address_length, endpoint);
}

/**
 * @brief Resolves an endpoint from the local address of a socket fd.
 *
 * @details Uses a stack-allocated sockaddr_storage (large enough for any address
 * family) to receive the getsockname result. The reentrancy guard is set before
 * and restored after the getsockname call to prevent looping.
 */
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;

    if (endpoint == NULL || g_chaos_net_real_getsockname == NULL)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getsockname(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint
    );
}

/**
 * @brief Resolves an endpoint from the remote peer address of a connected socket fd.
 *
 * @details Uses stack-allocated sockaddr_storage. The reentrancy guard is set
 * around the getpeername call. If the socket is not connected, getpeername
 * returns ENOTCONN and this function returns 0, causing the caller to fall
 * through to the real syscall without fault injection.
 */
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;

    if (endpoint == NULL || g_chaos_net_real_getpeername == NULL)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getpeername(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint
    );
}
