/**
 * @file chaos_net_endpoint.h
 * @brief Endpoint normalisation and selector matching API for libchaos-net.
 *
 * @details
 * This module is responsible for translating between two representations of
 * network addresses:
 *
 *   1. **Text selectors** (from the config file): strings such as
 *      `tcp4://127.0.0.1:8080`, `tcp6://[::1]:443`, `udp4://\*:53`, `unix:///run/foo.sock`,
 *      or the bare wildcard `*`. Parsed by chaos_net_endpoint_parse_selector().
 *
 *   2. **Runtime endpoints** (derived from socket state): concrete addresses
 *      built from a `struct sockaddr` passed to bind/connect/accept, or from
 *      getsockname/getpeername on an existing fd. Populated by
 *      chaos_net_endpoint_from_sockaddr_fd(), chaos_net_endpoint_from_local_fd(),
 *      and chaos_net_endpoint_from_peer_fd().
 *
 * The normalisation algorithm converts a raw sockaddr into a chaos_net_endpoint_t
 * by:
 *   - Extracting the address-family from sa_family.
 *   - Calling getsockopt(SO_TYPE) on the fd to determine SOCK_STREAM vs SOCK_DGRAM
 *     (needed because the sockaddr itself does not encode the transport protocol;
 *     a struct sockaddr_in can belong to either a TCP or a UDP socket).
 *   - Converting the port from network byte order to host byte order.
 *   - Storing the address bytes as-is (in_addr / in6_addr).
 *   - For UNIX sockets, copying sun_path; abstract (NUL-prefixed) paths are rejected
 *     since they have no meaningful string representation for config matching.
 *
 * @par One-symbol-one-owner invariant:
 * This module does NOT intercept or inspect write(2). Write on a socket fd is
 * owned exclusively by libchaos-io. libchaos-net intercepts only the socket-
 * specific symbols (send, recv, connect, etc.), so there is no overlap between
 * the two libraries. This is enforced by design at the symbol-ownership level,
 * not at runtime.
 *
 * @par accept / accept4 direction note:
 * For accept and accept4, the sockaddr parameter is an *output* filled in by the
 * kernel after the call succeeds. libchaos-net cannot use it as a selector before
 * the call (it is uninitialised). Instead, the listening socket's local address
 * (obtained via getsockname on sockfd) is used as the endpoint for rule matching.
 * This matches the intuition that "inject a fault on accept for the server listening
 * on port 8080" should use the server's port as the selector, not the ephemeral
 * client port that only becomes available post-call.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#ifndef CHAOS_NET_ENDPOINT_H
#define CHAOS_NET_ENDPOINT_H

#include "chaos_net_config.h"

/**
 * @brief Parses a config-file selector string into a chaos_net_endpoint_t.
 *
 * @details Recognises the following formats:
 *   - `"*"` — wildcard matching any endpoint (kind = ANY).
 *   - `"tcp4://HOST:PORT"` — IPv4 TCP; HOST is a dotted-decimal address or `*`.
 *   - `"tcp6://[ADDR]:PORT"` or `"tcp6://\*:PORT"` — IPv6 TCP.
 *   - `"udp4://HOST:PORT"` — IPv4 UDP.
 *   - `"udp6://[ADDR]:PORT"` or `"udp6://\*:PORT"` — IPv6 UDP.
 *   - `"unix://PATH"` — UNIX-domain socket with a specific path.
 *
 * For IPv4 selectors, `HOST` must be a valid dotted-decimal IPv4 address or the
 * single character `*`. For IPv6 selectors, the address must be enclosed in
 * square brackets (`[...]`) unless the host portion is `*`. The bare IPv6 wildcard
 * `"tcp6://\*"` (without a port) is rejected.
 *
 * PORT must be a decimal integer in [0, 65535] with no trailing non-numeric characters.
 *
 * The function zeroes @p endpoint before populating it, so partial-parse failures
 * leave a consistent zero state rather than partial data.
 *
 * @param text      NUL-terminated selector string. Must not be NULL or empty.
 * @param endpoint  Output parameter. Must not be NULL. Zeroed on entry; populated
 *                  on success with kind, port, wildcard_host, and address fields.
 *                  selector_len is set to strlen(text) to support tie-breaking.
 * @return 1 on success; 0 if @p text is NULL, empty, or has an unrecognised or
 *         malformed format.
 * @par Thread-safety: operates on caller-supplied buffers; no shared state.
 */
int chaos_net_endpoint_parse_selector(const char *text, chaos_net_endpoint_t *endpoint);

/**
 * @brief Tests whether a config selector endpoint matches a concrete runtime endpoint.
 *
 * @details Matching rules by specificity rank (higher rank = more specific):
 *
 *   | Rank | Condition |
 *   |------|-----------|
 *   | 4    | UNIX: exact sun_path match |
 *   | 3    | IPv4/IPv6: exact IP address + port match |
 *   | 2    | IPv4/IPv6: wildcard host + port match; or UNIX with selector text `"*"` |
 *   | 1    | Selector kind is ANY (bare `"*"`) |
 *   | 0    | No match |
 *
 * Kind must match exactly between selector and endpoint (TCP4 != UDP4, TCP4 != TCP6).
 * ANY selectors match any kind. Port must be equal for IPv4/IPv6 matches before
 * wildcard_host is checked.
 *
 * @param selector   Parsed config selector. Must not be NULL.
 * @param endpoint   Runtime endpoint derived from socket state. Must not be NULL.
 * @param rank_out   If non-NULL and a match is found, receives the specificity rank
 *                   (1–4). Set to 0 if no match. May be NULL if rank is not needed.
 * @return Non-zero if @p selector matches @p endpoint; 0 otherwise.
 * @par Thread-safety: read-only on both inputs; safe.
 */
int chaos_net_endpoint_matches(
    const chaos_net_endpoint_t *selector,
    const chaos_net_endpoint_t *endpoint,
    unsigned int *rank_out
);

/**
 * @brief Constructs a runtime endpoint from a sockaddr and a socket fd.
 *
 * @details Interprets @p address according to sa_family, then calls
 * getsockopt(SO_TYPE) on @p fd to determine whether the socket is SOCK_STREAM
 * or SOCK_DGRAM, which is needed to produce the correct TCP4/UDP4/TCP6/UDP6 kind.
 *
 * getsockopt is called through g_chaos_net_real_getsockopt with the reentrancy
 * guard set, so it does not recurse through the interposition layer.
 *
 * This function is appropriate for bind, connect, and sendto/sendmsg when a
 * destination address is explicitly provided by the caller.
 *
 * @param fd              Socket file descriptor; used to query SO_TYPE.
 * @param address         Pointer to the sockaddr struct. May be NULL (returns 0).
 * @param address_length  Length of the sockaddr struct in bytes.
 * @param endpoint        Output: populated on success. Must not be NULL.
 * @return 1 on success; 0 if @p address or @p endpoint is NULL, the address_length
 *         is too small, the family is unrecognised, SO_TYPE query fails, or for
 *         UNIX sockets with abstract (NUL-prefixed) or overlong paths.
 * @par Thread-safety: uses the reentrancy guard internally; safe.
 * @par Blocking: may block on getsockopt if the fd is in an unusual state.
 */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
);

/**
 * @brief Constructs a selector-compatible endpoint from socket creation parameters.
 *
 * @details Used by the socket() and socketpair() interceptors where no address
 * is available yet. The resulting endpoint is always a wildcard-host form (suitable
 * for matching against config selectors that use the wildcard-host or ANY form),
 * because the socket has not been bound or connected at creation time.
 *
 * SOCK_CLOEXEC and SOCK_NONBLOCK flags are masked off before inspecting @p type,
 * because callers may set them via the type argument on Linux.
 *
 * Only AF_INET, AF_INET6, and AF_UNIX are supported. Other domains return 0.
 *
 * @param domain    Socket domain (e.g., AF_INET, AF_INET6, AF_UNIX).
 * @param type      Socket type (SOCK_STREAM or SOCK_DGRAM, optionally OR'd with
 *                  SOCK_CLOEXEC / SOCK_NONBLOCK on Linux).
 * @param protocol  Ignored (passed for ABI completeness; the TCP/UDP distinction
 *                  is already captured in type).
 * @param endpoint  Output: populated on success. Must not be NULL.
 * @return 1 on success; 0 if @p endpoint is NULL or the domain/type combination
 *         is not supported.
 * @par Thread-safety: no shared state; safe.
 */
int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
);

/**
 * @brief Derives a runtime endpoint for a socket fd that already has an address,
 *        trying local address first, then peer address.
 *
 * @details Calls chaos_net_endpoint_from_local_fd() first. If that fails (e.g., the
 * socket is not bound), falls back to chaos_net_endpoint_from_peer_fd(). This
 * "try local then peer" strategy is used for shutdown(), where either the local or
 * the peer address may be informative depending on which side initiated the
 * connection.
 *
 * @param fd        Socket file descriptor to query.
 * @param endpoint  Output: populated with whichever address resolves first. Must not be NULL.
 * @return 1 if either address was resolved successfully; 0 if both fail.
 * @par Thread-safety: see chaos_net_endpoint_from_local_fd and chaos_net_endpoint_from_peer_fd.
 */
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint);

/**
 * @brief Derives a runtime endpoint from the local address of a socket fd.
 *
 * @details Calls getsockname(2) via g_chaos_net_real_getsockname (with the
 * reentrancy guard set) to obtain the local address, then invokes
 * chaos_net_endpoint_from_sockaddr_fd() to normalise it.
 *
 * Used by listen(), accept(), accept4(), recv(), recvfrom(), recvmsg(), recvmmsg(),
 * and send(). Note the distinction:
 *   - For listen/accept/recv: the local address identifies the port the server is
 *     listening on, which is what users write in config selectors.
 *   - For send on a connected socket: the local address is used as a fallback when
 *     the peer address is not available (send() vs sendto() semantics).
 *
 * @param fd        Socket file descriptor. Must be a valid, open socket.
 * @param endpoint  Output: populated on success. Must not be NULL.
 * @return 1 on success; 0 if @p endpoint is NULL, g_chaos_net_real_getsockname is
 *         NULL, getsockname fails, or the address cannot be normalised.
 * @par Thread-safety: uses the reentrancy guard; safe.
 * @par Blocking: getsockname should not block, but is subject to kernel scheduling.
 */
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint);

/**
 * @brief Derives a runtime endpoint from the remote peer address of a connected socket fd.
 *
 * @details Calls getpeername(2) via g_chaos_net_real_getpeername (with the
 * reentrancy guard set) to obtain the peer address, then invokes
 * chaos_net_endpoint_from_sockaddr_fd() to normalise it.
 *
 * Used by send() and sendto()/sendmsg() when no explicit destination address is
 * provided (connected-mode send). Using the peer address ensures that send-side
 * rules match on the remote endpoint — consistent with how connect/bind rules match.
 *
 * @param fd        Socket file descriptor. Must be connected (getpeername must succeed).
 * @param endpoint  Output: populated on success. Must not be NULL.
 * @return 1 on success; 0 if @p endpoint is NULL, g_chaos_net_real_getpeername is
 *         NULL, getpeername fails (e.g., socket not connected), or the address
 *         cannot be normalised.
 * @par Thread-safety: uses the reentrancy guard; safe.
 * @par Blocking: getpeername should not block.
 */
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint);

#endif
