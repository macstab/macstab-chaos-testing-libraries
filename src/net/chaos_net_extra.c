/**
 * @file chaos_net_extra.c
 * @brief LD_PRELOAD interposition wrappers for socket creation, shutdown, and batch I/O.
 *
 * @details
 * This file provides the exported interposition symbols for:
 *   - socket(2), socketpair(2): socket creation.
 *   - shutdown(2): socket teardown.
 *   - sendmmsg(2), recvmmsg(2): batch message I/O (Linux only).
 *
 * @par socket() and socketpair() endpoint construction:
 * At socket-creation time there is no address available. The endpoint is constructed
 * from the (domain, type) arguments alone via chaos_net_endpoint_from_socket_spec(),
 * which produces a wildcard-host endpoint with port 0. Config selectors for socket
 * rules must therefore use wildcard forms:
 *   - `tcp4://\*:0 : socket : EMFILE : 0.1`   — match any TCP4 socket creation.
 *   - `"*" : socket : ENFILE : 0.05`          — match any socket creation at all.
 * Selectors with specific host addresses or non-zero ports are rejected at parse time
 * by chaos_net_selector_allowed() in chaos_net_config.c.
 *
 * @par shutdown() endpoint resolution:
 * shutdown() can be called on a socket that may be bound, connected, or both.
 * chaos_net_endpoint_from_activity_fd() is used, which tries getsockname first
 * and falls back to getpeername. This provides the most informative address
 * available without requiring the socket to be in a specific state.
 *
 * @par sendmmsg() multi-message endpoint resolution:
 * sendmmsg() takes an array of mmsghdr structs, each of which may have its own
 * destination address (msg_name) or rely on the socket's connected peer. The
 * wrapper scans the array sequentially and stops at the first message whose
 * endpoint resolves and matches a rule. When a match is found, the pre-call
 * effect is applied and the real sendmmsg is called (or -1 returned on errno
 * injection). The remaining messages in the array are not individually inspected;
 * the first matching message drives the decision.
 *
 * @par recvmmsg() CORRUPT application:
 * recvmmsg() receives multiple messages. If a CORRUPT rule fires post-call,
 * chaos_net_corrupt_mmsghdrs() selects one message from the returned batch at
 * random (via PRNG) and flips one bit in that message's iovec. Only one message
 * is corrupted per call to keep the corruption minimal and targeted.
 *
 * @par chaos_net_apply_simple_pre_call_rule vs chaos_net_apply_pre_call_rule:
 * chaos_net_apply_simple_pre_call_rule() is identical in logic to
 * chaos_net_apply_pre_call_rule() from chaos_net_socket.c. It is duplicated here
 * rather than placed in a shared file to keep each .c file independently compilable
 * without introducing a new translation unit boundary that would require an
 * additional header. Both functions handle exactly LATENCY and ERRNO effects.
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
 * @brief Applies pre-call effects (LATENCY or ERRNO) for socket/shutdown/sendmmsg operations.
 *
 * @details Functionally equivalent to chaos_net_apply_pre_call_rule() in
 * chaos_net_socket.c. Duplicated here to keep this translation unit self-contained
 * and avoid a dependency on chaos_net_socket.c's static symbols.
 *
 * @param rule  Matched rule; may be NULL (returns 0 immediately).
 * @return 0 to proceed with the real call; -1 to return immediately (errno set).
 */
static int chaos_net_apply_simple_pre_call_rule(const chaos_net_rule_t *rule)
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
 * Real-symbol call wrappers (reentrancy-guard wrappers)
 *---------------------------------------------------------------------------*/

/** @brief Calls the real socket(2) with reentrancy guard set. */
static int chaos_net_call_real_socket(int domain, int type, int protocol)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socket(domain, type, protocol);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real socketpair(2) with reentrancy guard set. */
static int chaos_net_call_real_socketpair(int domain, int type, int protocol, int sv[2])
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socketpair(domain, type, protocol, sv);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real shutdown(2) with reentrancy guard set. */
static int chaos_net_call_real_shutdown(int sockfd, int how)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_shutdown(sockfd, how);
    chaos_net_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/** @brief Calls the real sendmmsg(2) with reentrancy guard set (Linux only). */
static int chaos_net_call_real_sendmmsg(
    int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags
)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_sendmmsg(sockfd, msgvec, vlen, flags);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real recvmmsg(2) with reentrancy guard set (Linux only). */
static int chaos_net_call_real_recvmmsg(
    int sockfd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/**
 * @brief Corrupts one message in a recvmmsg result batch.
 *
 * @details Selects one message from @p msgvec[0..count-1] using the PRNG. If the
 * selected message has msg_len > 0 and a non-NULL iovec, walks the iovec to find
 * a non-empty segment and calls chaos_net_corrupt_buffer_sample() on it.
 *
 * The multi-segment walk mirrors chaos_net_corrupt_iovecs() in chaos_net_socket.c
 * but operates on the mmsghdr::msg_len field (the actual bytes received for this
 * message) rather than a caller-provided size, ensuring corruption does not
 * overrun the receive buffer.
 *
 * Selecting exactly one message per call is intentional: flipping bits in multiple
 * messages simultaneously would be indistinguishable from hardware-level corruption
 * and harder for applications to handle. The per-call probability is already applied
 * by the caller via chaos_net_rule_should_trigger().
 *
 * @param msgvec  Array of received messages. Must not be NULL.
 * @param count   Number of messages returned by recvmmsg (> 0).
 */
static void chaos_net_corrupt_mmsghdrs(struct mmsghdr *msgvec, unsigned int count)
{
    unsigned int selected;

    if (msgvec == NULL || count == 0U)
    {
        return;
    }

    /* Select a random message from the returned batch. */
    selected = chaos_net_prng_next_u32() % count;
    if (msgvec[selected].msg_len > 0U && msgvec[selected].msg_hdr.msg_iov != NULL &&
        msgvec[selected].msg_hdr.msg_iovlen > 0)
    {
        size_t remaining = (size_t)msgvec[selected].msg_len;
        struct iovec *iov = msgvec[selected].msg_hdr.msg_iov;
        size_t iov_index = 0U;

        while (iov_index < (size_t)msgvec[selected].msg_hdr.msg_iovlen && remaining > 0U)
        {
            size_t segment_len = iov[iov_index].iov_len;

            if (segment_len > remaining)
            {
                segment_len = remaining;
            }
            if (segment_len > 0U)
            {
                uint32_t index_sample = chaos_net_prng_next_u32();
                uint32_t bit_sample = chaos_net_prng_next_u32();

                chaos_net_corrupt_buffer_sample(
                    iov[iov_index].iov_base, segment_len, index_sample, bit_sample
                );
                return;
            }

            remaining -= segment_len;
            ++iov_index;
        }
    }
}
#endif

/*---------------------------------------------------------------------------
 * Interposed symbols
 *---------------------------------------------------------------------------*/

/**
 * @brief Interposed socket(2).
 *
 * @details Endpoint is constructed from (domain, type) via
 * chaos_net_endpoint_from_socket_spec(). If the domain or type is unsupported
 * (e.g., AF_PACKET, SOCK_RAW), the function returns 0 and the real socket() is
 * called without injection.
 */
CHAOS_NET_EXPORT int socket(int domain, int type, int protocol)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_socket_spec(domain, type, protocol, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SOCKET, &endpoint, &rule))
    {
        return chaos_net_call_real_socket(domain, type, protocol);
    }
    if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_socket(domain, type, protocol);
}

/**
 * @brief Interposed socketpair(2).
 *
 * @details Same endpoint construction as socket(). socketpair() is mapped to
 * CHAOS_NET_OP_SOCKET because it creates sockets and has the same pre-address
 * constraint: no specific endpoint is available at creation time. Rules that match
 * socket() will also match socketpair() for the same domain/type combination.
 */
CHAOS_NET_EXPORT int socketpair(int domain, int type, int protocol, int sv[2])
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_socket_spec(domain, type, protocol, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SOCKET, &endpoint, &rule))
    {
        return chaos_net_call_real_socketpair(domain, type, protocol, sv);
    }
    if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_socketpair(domain, type, protocol, sv);
}

/**
 * @brief Interposed shutdown(2).
 *
 * @details Endpoint is resolved via chaos_net_endpoint_from_activity_fd() (getsockname
 * then getpeername). The @p how argument (SHUT_RD, SHUT_WR, SHUT_RDWR) is not
 * considered for rule matching; all shutdown directions are matched by the same rule.
 */
CHAOS_NET_EXPORT int shutdown(int sockfd, int how)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_activity_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_SHUTDOWN, &endpoint, &rule))
    {
        return chaos_net_call_real_shutdown(sockfd, how);
    }
    if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_shutdown(sockfd, how);
}

#ifdef __linux__
/**
 * @brief Interposed sendmmsg(2) (Linux only).
 *
 * @details Scans the message array for the first message whose endpoint resolves
 * and matches a SEND rule. This is a "first-match-wins" strategy: if any message
 * targets a matched endpoint, the pre-call effect is applied and the entire batch
 * is affected (either all messages are sent or, on errno injection, none are).
 *
 * The reentrancy guard is checked once at entry rather than per-message to keep
 * the inner loop minimal. The guard is not needed for endpoint resolution inside
 * the loop because chaos_net_endpoint_from_sockaddr_fd / chaos_net_endpoint_from_peer_fd
 * each set the guard internally around their getsockopt/getpeername calls.
 */
CHAOS_NET_EXPORT int
sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    unsigned int index;
    int matched = 0;

    if (chaos_net_in_internal())
    {
        return chaos_net_call_real_sendmmsg(sockfd, msgvec, vlen, flags);
    }

    for (index = 0U; index < vlen; ++index)
    {
        struct msghdr *message = &msgvec[index].msg_hdr;

        /* Use msg_name if present (datagram send); otherwise use getpeername. */
        matched = message->msg_name != NULL ? chaos_net_endpoint_from_sockaddr_fd(
                                                  sockfd,
                                                  (const struct sockaddr *)message->msg_name,
                                                  message->msg_namelen,
                                                  &endpoint
                                              )
                                            : chaos_net_endpoint_from_peer_fd(sockfd, &endpoint);
        if (matched && chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule))
        {
            if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
            {
                return -1;
            }
            return chaos_net_call_real_sendmmsg(sockfd, msgvec, vlen, flags);
        }
    }

    return chaos_net_call_real_sendmmsg(sockfd, msgvec, vlen, flags);
}

/**
 * @brief Interposed recvmmsg(2) (Linux only).
 *
 * @details Endpoint is resolved from the local address (getsockname) consistent
 * with recv()/recvfrom()/recvmsg(). On CORRUPT rule firing post-call, exactly one
 * randomly selected message in the returned batch has one bit flipped via
 * chaos_net_corrupt_mmsghdrs(). Pre-call LATENCY and ERRNO effects work identically
 * to the single-message recv variants.
 *
 * The @p timeout parameter (recvmmsg-specific, a receive timeout rather than a
 * wait multiplexing timeout) is forwarded to the real call unchanged; it is not
 * related to CHAOS_NET_EFFECT_TIMEOUT (which is for poll-family operations).
 */
CHAOS_NET_EXPORT int recvmmsg(
    int sockfd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int rc;

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_RECV, &endpoint, &rule))
    {
        return chaos_net_call_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    }

    if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
    {
        return -1;
    }

    rc = chaos_net_call_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    /* Apply corruption to one randomly selected message from the received batch. */
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_mmsghdrs(msgvec, (unsigned int)rc);
    }
    return rc;
}
#endif
