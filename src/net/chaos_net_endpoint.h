/**
 * @file chaos_net_endpoint.h
 * @brief Selector parsing, endpoint resolution and selector matching for libchaos-net.
 *
 * @details
 * Translates between the two forms of chaos_net_endpoint_t:
 *
 *   1. **Selectors** from the rule file: `tcp4://127.0.0.1:8080`, `tcp6://[::1]:443`,
 *      `udp4://\*:53`, `unix:///run/app.sock`, `unix://@abstract`, or the bare `*`.
 *      Parsed by chaos_net_endpoint_parse_selector().
 *
 *   2. **Runtime endpoints** from socket state: the sockaddr argument of bind, connect,
 *      sendto or sendmsg, or getsockname/getpeername on a descriptor; for socket() and
 *      socketpair(), the (domain, type) pair.
 *
 * Resolution from a sockaddr:
 *   - Family from sa_family; transport from getsockopt(SO_TYPE), because a sockaddr_in
 *     belongs to a TCP or a UDP socket alike. Only SOCK_STREAM and SOCK_DGRAM resolve.
 *   - Port converted to host byte order; address bytes kept as they are.
 *   - IPv4-mapped IPv6 addresses become TCP4/UDP4.
 *   - UNIX: the path, bounded by the address length. Abstract names are written with
 *     `@` for each NUL; unnamed sockets get an empty path.
 *
 * Every lookup the library makes (getsockname, getpeername, getsockopt) runs with the
 * reentrancy guard set and saves and restores errno, so resolution never changes what
 * the caller's call reports. A descriptor that is not a socket fails resolution
 * (ENOTSOCK, swallowed) and its call is forwarded untouched.
 *
 * @par accept / accept4:
 * Their sockaddr is an output, uninitialised before the call. The endpoint is the
 * listening socket's local address, so a rule names the server's port, not the client's
 * ephemeral one that exists only after the call.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#ifndef CHAOS_NET_ENDPOINT_H
#define CHAOS_NET_ENDPOINT_H

#include "chaos_net_config.h"

/**
 * @brief Parses a rule-file selector.
 *
 * @details Formats:
 *   - `*` -- any endpoint (kind ANY).
 *   - `tcp4://HOST:PORT`, `udp4://HOST:PORT` -- HOST is dotted-quad IPv4 or `*`.
 *   - `tcp6://[ADDR]:PORT`, `udp6://[ADDR]:PORT`, or with `*` for `[ADDR]` -- the
 *     brackets are required around a literal address because it contains colons.
 *   - `unix://PATH` -- PATH as getsockname reports it (`@` for each NUL of an abstract
 *     name), or `*` for any UNIX socket; 1 to 255 bytes.
 *
 * PORT is decimal in [0, 65535], parsed with strtoul (leading blanks and a `+` are
 * accepted, trailing characters are not). `tcp6://\*` without a port is rejected.
 *
 * @param text      NUL-terminated selector; NULL or empty yields 0.
 * @param endpoint  Output; zeroed first, so a failed parse leaves no partial address.
 *                  selector_len is set to strlen(@p text) for tie-breaking.
 * @return 1 on success; 0 for an unknown scheme or a malformed selector.
 * @par Thread-safety: caller-supplied buffers only.
 */
int chaos_net_endpoint_parse_selector(const char *text, chaos_net_endpoint_t *endpoint);

/**
 * @brief Whether @p selector matches @p endpoint, and how specifically.
 *
 * @details
 *   | Rank | Condition |
 *   |------|-----------|
 *   | 4    | UNIX: equal path |
 *   | 3    | IPv4/IPv6: equal address and equal port |
 *   | 2    | IPv4/IPv6: wildcard host and equal port; or UNIX selector `*` |
 *   | 1    | Selector `*` (kind ANY) |
 *   | 0    | No match |
 *
 * Kinds must be equal (TCP4 != UDP4, TCP4 != TCP6) unless the selector is ANY. A wildcard
 * host still requires the port to match; there is no port wildcard.
 *
 * @param selector   Parsed selector; NULL yields 0.
 * @param endpoint   Runtime endpoint; NULL yields 0.
 * @param rank_out   Optional; receives the rank (1-4), or 0 when there is no match.
 * @return Non-zero if @p selector matches @p endpoint; 0 otherwise.
 * @par Thread-safety: read-only on both inputs.
 */
int chaos_net_endpoint_matches(
    const chaos_net_endpoint_t *selector,
    const chaos_net_endpoint_t *endpoint,
    unsigned int *rank_out
);

/**
 * @brief Resolves a runtime endpoint from @p address, with the transport of @p fd.
 *
 * @details Interprets @p address by sa_family, then asks SO_TYPE of @p fd (through
 * g_chaos_net_real_getsockopt, guard set, errno preserved) to choose TCP or UDP. For
 * bind, connect, and sendto/sendmsg with an explicit destination.
 *
 * @param fd              Socket whose SO_TYPE decides the transport.
 * @param address         sockaddr to resolve; NULL yields 0.
 * @param address_length  Bytes valid at @p address.
 * @param endpoint        Output; must not be NULL.
 * @return 1 on success; 0 if @p address_length is too short for the family, the family
 *         is not AF_INET/AF_INET6/AF_UNIX, SO_TYPE fails (ENOTSOCK) or is neither stream
 *         nor datagram (IP families).
 * @par Thread-safety: safe; stack and thread-local state only.
 */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
);

/**
 * @brief Builds the endpoint of a socket that has no address yet, from socket() arguments.
 *
 * @details For socket() and socketpair(). IP families yield the wildcard-host form with
 * port 0 (matched by `tcp4://\*:0` and the like, or `*`); AF_UNIX yields the path `*`
 * (matched by `unix://\*` or `*`). SOCK_CLOEXEC and SOCK_NONBLOCK are masked off @p type
 * first, since Linux lets callers OR them in.
 *
 * @param domain    AF_INET, AF_INET6 or AF_UNIX; anything else yields 0.
 * @param type      SOCK_STREAM or SOCK_DGRAM (for IP), optionally with the flags above.
 * @param protocol  Ignored; the transport is already in @p type.
 * @param endpoint  Output; NULL yields 0.
 * @return 1 on success; 0 for an unsupported domain/type.
 * @par Thread-safety: no shared state.
 */
int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
);

/**
 * @brief Resolves @p fd's local address, or its peer address if that fails.
 *
 * @details For shutdown, close and the poll family. getsockname succeeds on every socket,
 * bound or not (an unbound IP socket reports the wildcard address and port 0, an unnamed
 * UNIX socket an empty path), so in practice these operations match on the local end: a
 * client socket's ephemeral port, not its server's. The peer is used only when the local
 * address does not normalise.
 *
 * @param fd        Descriptor to resolve.
 * @param endpoint  Output; NULL yields 0.
 * @return 1 if either address resolved; 0 otherwise (e.g. not a socket).
 */
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint);

/**
 * @brief Resolves the local address of @p fd (getsockname).
 *
 * @details Calls g_chaos_net_real_getsockname with the guard set and errno preserved,
 * then chaos_net_endpoint_from_sockaddr_fd(). Used for listen and accept (the listening
 * port), and as one of the two ends in chaos_net_match_connected().
 *
 * @param fd        Socket descriptor.
 * @param endpoint  Output; NULL yields 0.
 * @return 1 on success; 0 if getsockname is unresolved or fails, or the address does not
 *         normalise.
 * @par Thread-safety: safe; no shared state.
 */
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint);

/**
 * @brief Resolves the peer address of @p fd (getpeername).
 *
 * @details Calls g_chaos_net_real_getpeername with the guard set and errno preserved,
 * then chaos_net_endpoint_from_sockaddr_fd(). Fails with ENOTCONN (swallowed) on an
 * unconnected socket. Used as one of the two ends in chaos_net_match_connected() and as
 * the fallback of chaos_net_endpoint_from_activity_fd().
 *
 * @param fd        Socket descriptor.
 * @param endpoint  Output; NULL yields 0.
 * @return 1 on success; 0 if getpeername is unresolved or fails, or the address does not
 *         normalise.
 * @par Thread-safety: safe; no shared state.
 */
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint);

#endif
