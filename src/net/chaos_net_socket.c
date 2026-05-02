/**
 * @file chaos_net_socket.c
 * @brief LD_PRELOAD interposition wrappers for connection-lifecycle and I/O socket syscalls.
 *
 * @details
 * This file provides the exported interposition symbols for:
 *   - Connection lifecycle: bind, listen, connect, accept, accept4 (Linux).
 *   - Send path: send, sendto, sendmsg.
 *   - Receive path: recv, recvfrom, recvmsg.
 *
 * Each wrapper follows an identical three-phase pattern:
 *   1. **Guard check**: if chaos_net_in_internal() is non-zero, the call originated
 *      from within libchaos-net itself (e.g., getsockname called during endpoint
 *      resolution). Fast-path directly to the real symbol.
 *   2. **Endpoint resolution**: translate the syscall arguments (sockaddr parameter
 *      or fd-based getsockname/getpeername) into a chaos_net_endpoint_t. If
 *      resolution fails (unsupported socket type, abstract UNIX path, etc.), the
 *      call is passed through without injection.
 *   3. **Rule matching and effect application**: look up the config rule for
 *      (operation, endpoint). Apply pre-call effects (latency, errno-injection)
 *      before the real call; apply post-call effects (corruption) after.
 *
 * @par accept / accept4 endpoint direction:
 * For accept and accept4, the sockaddr parameter is an *output* — it is filled in
 * by the kernel after the call and is uninitialised before it. Using the sockaddr
 * from the argument as a selector would read uninitialised memory. Instead, the
 * listening socket's local address (obtained via getsockname on @p sockfd) is used
 * as the matching endpoint. This is consistent with user intent: a rule saying
 * "inject on accept for port 8080" refers to the listening port, not the ephemeral
 * client port that only becomes known after the call.
 *
 * @par write() exclusion:
 * write(2) on a socket file descriptor is owned by libchaos-io, not libchaos-net.
 * This file deliberately does not intercept write(). Intercepting write() here would
 * violate the one-symbol-one-owner invariant and could cause double-injection when
 * both libraries are loaded simultaneously. The send* family covers all socket-
 * specific send operations.
 *
 * @par Receive-side CORRUPT application:
 * Corruption is applied only when:
 *   - The real recv call returned a positive byte count (rc > 0).
 *   - The matched rule has effect == CORRUPT.
 *   - chaos_net_rule_should_trigger() fires (probability check).
 * Applying corruption to a return value of 0 (EOF) or -1 (error) is meaningless
 * and could write past the actual data in the buffer.
 *
 * @par sendto / sendmsg endpoint resolution:
 * These functions carry an optional explicit destination address. When present
 * (address_ptr != NULL for sendto, message->msg_name != NULL for sendmsg), the
 * destination address is used as the endpoint. When absent (connected-mode send),
 * getpeername is used to resolve the peer address. This matches how applications
 * use these calls: datagram sends include the destination; stream sends do not.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <string.h>

/**
 * @brief Flips one bit in a scattered I/O vector using pre-drawn PRNG samples.
 *
 * @details Treats the iovec array as a logically contiguous buffer of @p size bytes
 * and selects the target byte by walking through segments until the cumulative
 * offset equals `index_sample % size`. The bit within the byte is selected by
 * `bit_sample & 7`. This is the recvmsg counterpart of chaos_net_corrupt_buffer():
 * the caller's data lives in multiple disjoint segments and cannot be corrupted
 * with a single pointer + offset.
 *
 * Only one bit is flipped across the entire scatter, consistent with the flat-buffer
 * contract in chaos_net_actions.h. After the bit is flipped, the function returns
 * immediately without examining further segments.
 *
 * @param iov     Scatter array describing the receive buffers.
 * @param iovcnt  Number of entries in @p iov. Must be > 0.
 * @param size    Total byte count to consider (typically the recvmsg return value).
 *                Must be > 0 and <= the sum of iov_len values.
 */
static void chaos_net_corrupt_iovecs(const struct iovec *iov, int iovcnt, size_t size)
{
    uint32_t index_sample;
    uint32_t bit_sample;
    size_t remaining = size;
    size_t index;
    int entry;

    if (iov == NULL || iovcnt <= 0 || size == 0U)
    {
        return;
    }

    index_sample = chaos_net_prng_next_u32();
    bit_sample = chaos_net_prng_next_u32();
    index = (size_t)(index_sample % size);
    for (entry = 0; entry < iovcnt && remaining > 0U; ++entry)
    {
        size_t segment_len = iov[entry].iov_len;

        if (segment_len > remaining)
        {
            segment_len = remaining;
        }
        if (index < segment_len)
        {
            /* The target byte falls within this segment. */
            chaos_net_corrupt_buffer_sample(
                iov[entry].iov_base, segment_len, (uint32_t)index, bit_sample
            );
            return;
        }

        if (segment_len > 0U)
        {
            /* Advance past this segment and continue searching. */
            index -= segment_len;
            remaining -= segment_len;
        }
    }
}

/*---------------------------------------------------------------------------
 * Real-symbol call wrappers
 *
 * These wrappers set the reentrancy guard, invoke the real symbol, and restore
 * the guard. They exist to centralise the guard management so that the interposition
 * wrappers themselves read clearly without guard boilerplate on every call site.
 *---------------------------------------------------------------------------*/

/**
 * @brief Calls the real bind(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_bind(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real listen(2) with reentrancy guard set.
 */
static int chaos_net_call_real_listen(int sockfd, int backlog)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_listen(sockfd, backlog);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real connect(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_connect(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real accept(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

#ifdef __linux__
/**
 * @brief Calls the real accept4(2) with reentrancy guard set (Linux only).
 */
static int chaos_net_call_real_accept4(
    int sockfd, struct sockaddr *address, socklen_t *address_length, int flags
)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept4(sockfd, address, address_length, flags);
    chaos_net_leave_internal(previous);
    return result;
}
#endif

/**
 * @brief Calls the real send(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_send(int sockfd, const void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_send(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendto(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    const struct sockaddr *address,
    socklen_t address_length
)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendto(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendmsg(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recv(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_recv(int sockfd, void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recv(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvfrom(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    struct sockaddr *address,
    socklen_t *address_length
)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvfrom(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvmsg(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/*---------------------------------------------------------------------------
 * Pre-call effect dispatcher
 *---------------------------------------------------------------------------*/

/**
 * @brief Applies pre-call effects (latency or errno injection) for connection-lifecycle
 *        and send operations.
 *
 * @details Returns -1 if the call should be intercepted and the real syscall skipped
 * (errno injection fired). Returns 0 if the real syscall should proceed (either a
 * latency was applied and we continue, or the errno injection did not fire).
 *
 * This dispatcher is used by bind, listen, connect, accept, accept4, send, sendto,
 * sendmsg. It does NOT handle CORRUPT (post-call only) or TIMEOUT (poll-family only).
 *
 * @param rule  Matched rule; may be NULL (returns 0 immediately).
 * @return 0 to proceed with the real call; -1 to return immediately (errno set).
 */
static int chaos_net_apply_pre_call_rule(const chaos_net_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(rule);
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(rule))
    {
        return -1;
    }
    return 0;
}

/*---------------------------------------------------------------------------
 * Interposed symbols
 *---------------------------------------------------------------------------*/

/**
 * @brief Interposed bind(2).
 *
 * @details Endpoint is derived from the caller-provided sockaddr + socket type.
 * If the endpoint cannot be resolved (e.g., unsupported address family) or no
 * rule matches, the call is forwarded to the real bind without modification.
 * The CHAOS_NET_CONST_SOCKADDR_PARAM / CHAOS_NET_CONST_SOCKADDR_VALUE macros
 * handle the glibc sockaddr union ABI on the parameter.
 */
CHAOS_NET_EXPORT int
bind(int sockfd, CHAOS_NET_CONST_SOCKADDR_PARAM address, socklen_t address_length)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_BIND, &endpoint, &rule))
    {
        return chaos_net_call_real_bind(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_bind(sockfd, address_ptr, address_length);
}

/**
 * @brief Interposed listen(2).
 *
 * @details Endpoint is derived from the local address of the listening socket
 * (getsockname). The sockaddr is an input parameter to listen() only implicitly:
 * it was set by a prior bind(). Using getsockname here is consistent with how
 * users write config rules: "listen on port 8080" refers to the bound address.
 */
CHAOS_NET_EXPORT int listen(int sockfd, int backlog)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_LISTEN, &endpoint, &rule))
    {
        return chaos_net_call_real_listen(sockfd, backlog);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_listen(sockfd, backlog);
}

/**
 * @brief Interposed connect(2).
 *
 * @details Endpoint is derived from the caller-provided destination address and
 * the socket's type (SO_TYPE). This allows rules to target connects to a specific
 * remote endpoint: `tcp4://10.0.0.1:6379 : connect : ECONNREFUSED : 1.0`.
 */
CHAOS_NET_EXPORT int
connect(int sockfd, CHAOS_NET_CONST_SOCKADDR_PARAM address, socklen_t address_length)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, &endpoint, &rule))
    {
        return chaos_net_call_real_connect(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_connect(sockfd, address_ptr, address_length);
}

/**
 * @brief Interposed accept(2).
 *
 * @details The sockaddr output parameter is an OUTPUT filled by the kernel post-call;
 * it is uninitialised at entry. Endpoint is therefore derived from the listening
 * socket's local address (getsockname on sockfd), not from the sockaddr argument.
 * See the file-level comment for the full rationale.
 */
CHAOS_NET_EXPORT int accept(int sockfd, CHAOS_NET_SOCKADDR_PARAM address, socklen_t *address_length)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_ACCEPT, &endpoint, &rule))
    {
        return chaos_net_call_real_accept(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_accept(sockfd, address_ptr, address_length);
}

#ifdef __linux__
/**
 * @brief Interposed accept4(2) (Linux only).
 *
 * @details Same endpoint-direction rationale as accept(): the sockaddr is an output
 * parameter. The endpoint is resolved from getsockname on the listening socket.
 * The flags parameter (SOCK_CLOEXEC, SOCK_NONBLOCK) is forwarded to the real call
 * unchanged; fault injection does not affect the semantics of the returned fd.
 */
CHAOS_NET_EXPORT int
accept4(int sockfd, CHAOS_NET_SOCKADDR_PARAM address, socklen_t *address_length, int flags)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_ACCEPT, &endpoint, &rule))
    {
        return chaos_net_call_real_accept4(sockfd, address_ptr, address_length, flags);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_accept4(sockfd, address_ptr, address_length, flags);
}
#endif

/**
 * @brief Interposed send(2).
 *
 * @details send() is a connected-mode operation; there is no explicit destination
 * address. The endpoint is resolved via getpeername on the socket. If the socket is
 * not connected (getpeername fails), the call is passed through without injection.
 */
CHAOS_NET_EXPORT ssize_t send(int sockfd, const void *buffer, size_t size, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_peer_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule))
    {
        return chaos_net_call_real_send(sockfd, buffer, size, flags);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_send(sockfd, buffer, size, flags);
}

/**
 * @brief Interposed sendto(2).
 *
 * @details sendto() may be called in two modes:
 *   - With an explicit destination (address_ptr != NULL): typical for UDP datagrams.
 *     The destination sockaddr is used for endpoint resolution.
 *   - Without a destination (address_ptr == NULL): connected-mode send on a socket
 *     for which sendto is used as an alias for send(). The peer address from
 *     getpeername is used.
 */
CHAOS_NET_EXPORT ssize_t sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    CHAOS_NET_CONST_SOCKADDR_PARAM address,
    socklen_t address_length
)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int matched;

    /* Use the explicit destination if provided; fall back to getpeername for connected mode. */
    matched =
        address_ptr != NULL
            ? chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint)
            : chaos_net_endpoint_from_peer_fd(sockfd, &endpoint);
    if (chaos_net_in_internal() || !matched ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule))
    {
        return chaos_net_call_real_sendto(sockfd, buffer, size, flags, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_sendto(sockfd, buffer, size, flags, address_ptr, address_length);
}

/**
 * @brief Interposed sendmsg(2).
 *
 * @details sendmsg() may carry an explicit destination address in msg_name (non-NULL
 * for datagram sends) or may rely on the socket being connected (msg_name == NULL).
 * Endpoint resolution mirrors sendto(): use msg_name if present, otherwise getpeername.
 */
CHAOS_NET_EXPORT ssize_t sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int matched;

    matched = message != NULL && message->msg_name != NULL
                  ? chaos_net_endpoint_from_sockaddr_fd(
                        sockfd,
                        (const struct sockaddr *)message->msg_name,
                        (socklen_t)message->msg_namelen,
                        &endpoint
                    )
                  : chaos_net_endpoint_from_peer_fd(sockfd, &endpoint);
    if (chaos_net_in_internal() || !matched ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule))
    {
        return chaos_net_call_real_sendmsg(sockfd, message, flags);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_sendmsg(sockfd, message, flags);
}

/**
 * @brief Interposed recv(2).
 *
 * @details The endpoint is derived from the local address (getsockname) because:
 *   - For connected TCP sockets, the local port identifies the service.
 *   - For UDP sockets, the local port identifies the listening endpoint.
 *   Using the peer address would require the socket to be connected, which excludes
 *   UDP servers calling recvfrom without a prior connect.
 *
 * CORRUPT is applied post-call only on rc > 0. If rc == 0 (EOF) or rc < 0 (error),
 * there is no receive buffer content to corrupt and the buffer may be uninitialised.
 */
CHAOS_NET_EXPORT ssize_t recv(int sockfd, void *buffer, size_t size, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    ssize_t rc;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_RECV, &endpoint, &rule))
    {
        return chaos_net_call_real_recv(sockfd, buffer, size, flags);
    }

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_net_call_real_recv(sockfd, buffer, size, flags);
    /* Apply corruption only to successfully received data. */
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/**
 * @brief Interposed recvfrom(2).
 *
 * @details Same endpoint resolution and CORRUPT application logic as recv(). The
 * caller-supplied address parameter (output) is forwarded to the real call unchanged;
 * libchaos-net does not modify the sender address.
 */
CHAOS_NET_EXPORT ssize_t recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    CHAOS_NET_SOCKADDR_PARAM address,
    socklen_t *address_length
)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    ssize_t rc;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_RECV, &endpoint, &rule))
    {
        return chaos_net_call_real_recvfrom(
            sockfd, buffer, size, flags, address_ptr, address_length
        );
    }

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_net_call_real_recvfrom(sockfd, buffer, size, flags, address_ptr, address_length);
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/**
 * @brief Interposed recvmsg(2).
 *
 * @details Same endpoint and pre-call logic as recv(). Post-call CORRUPT uses
 * chaos_net_corrupt_iovecs() because the receive buffer is described by the iovec
 * array in message->msg_iov, not a single flat buffer. The total received byte
 * count (rc) bounds the corruption to the actually-written portion of the scatter.
 */
CHAOS_NET_EXPORT ssize_t recvmsg(int sockfd, struct msghdr *message, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    ssize_t rc;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_RECV, &endpoint, &rule))
    {
        return chaos_net_call_real_recvmsg(sockfd, message, flags);
    }

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_net_call_real_recvmsg(sockfd, message, flags);
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_iovecs(
            message != NULL ? message->msg_iov : NULL,
            message != NULL ? (int)message->msg_iovlen : 0,
            (size_t)rc
        );
    }
    return rc;
}
