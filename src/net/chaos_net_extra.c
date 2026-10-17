/**
 * @file chaos_net_extra.c
 * @brief Wrappers for socket creation, shutdown and batched message I/O.
 *
 * @details
 * Exported wrappers: socket, socketpair, shutdown; sendmmsg and recvmmsg (Linux).
 *
 * @par socket() and socketpair():
 *   No address exists at creation, so the endpoint comes from (domain, type) alone
 *   (chaos_net_endpoint_from_socket_spec()): wildcard host and port 0 for IP, path `*`
 *   for UNIX. SOCKET rules therefore accept only kind-describing selectors, enforced at
 *   parse time by chaos_net_selector_allowed():
 *   - `tcp4://\*:0 : socket : EMFILE : 0.1` -- any TCP/IPv4 socket.
 *   - `* : socket : ENFILE : 0.05`          -- any supported socket.
 *   socketpair() is matched as SOCKET for its (domain, type).
 *
 * @par shutdown():
 *   chaos_net_endpoint_from_activity_fd(): the local address, else the peer. @p how is
 *   not part of the match.
 *
 * @par sendmmsg():
 *   Scans the messages the kernel would send (at most 1024) and stops at the first
 *   whose destination matches a SEND rule; messages without msg_name stand for the
 *   connection, which is matched once (chaos_net_match_connected()). The effect then
 *   applies to the whole batch: on an ERRNO firing nothing is sent.
 *
 * @par recvmmsg():
 *   Matched like recv(). LATENCY and ERRNO apply before the call; a firing CORRUPT flips
 *   one bit in one randomly chosen message of the returned batch. TRICKLE and DUP rules
 *   match but have no effect here.
 *
 * chaos_net_apply_simple_pre_call_rule() duplicates chaos_net_apply_pre_call_rule() of
 * chaos_net_socket.c, which is static there; seven lines do not justify a shared header.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <string.h>
#include <sys/syscall.h>

/**
 * @brief Applies the pre-call effects LATENCY and ERRNO; any other effect is ignored.
 *
 * @details Same logic as chaos_net_apply_pre_call_rule() in chaos_net_socket.c.
 *
 * @param rule  Matched rule copy; NULL yields 0.
 * @return 0 to make the real call (after any delay); -1 to return -1 at once, errno set.
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
 * Calls to the real functions: guard set; raw system call before resolution
 *---------------------------------------------------------------------------*/

/** @brief Calls the real socket(2) with the guard set; SYS_socket before resolution. */
static int chaos_net_call_real_socket(int domain, int type, int protocol)
{
    int previous;
    int rc;

    if (g_chaos_net_real_socket == NULL)
    {
        /* Not resolved yet: a call from inside the symbol lookup. The system call does
         * what libc would. */
        return (int)syscall(SYS_socket, domain, type, protocol);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socket(domain, type, protocol);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real socketpair(2) with the guard set. */
static int chaos_net_call_real_socketpair(int domain, int type, int protocol, int sv[2])
{
    int previous;
    int rc;

    if (g_chaos_net_real_socketpair == NULL)
    {
        return (int)syscall(SYS_socketpair, domain, type, protocol, sv);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socketpair(domain, type, protocol, sv);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real shutdown(2) with the guard set. */
static int chaos_net_call_real_shutdown(int sockfd, int how)
{
    int previous;
    int rc;

    if (g_chaos_net_real_shutdown == NULL)
    {
        return (int)syscall(SYS_shutdown, sockfd, how);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_shutdown(sockfd, how);
    chaos_net_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/** @brief Calls the real sendmmsg(2) with the guard set (Linux). */
static int chaos_net_call_real_sendmmsg(
    int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags
)
{
    int previous;
    int rc;

    if (g_chaos_net_real_sendmmsg == NULL)
    {
        return (int)syscall(SYS_sendmmsg, sockfd, msgvec, vlen, flags);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_sendmmsg(sockfd, msgvec, vlen, flags);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real recvmmsg(2) with the guard set (Linux). */
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

    if (g_chaos_net_real_recvmmsg == NULL)
    {
        return (int)syscall(SYS_recvmmsg, sockfd, msgvec, vlen, flags, timeout);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/**
 * @brief Flips one bit in one message of a recvmmsg batch.
 *
 * @details Picks one of the @p count returned messages with the PRNG, then flips one bit
 * of the first non-empty segment of its scatter list, within the msg_len bytes received
 * for it (chaos_net_corrupt_buffer_sample()). Messages with msg_len 0 or no vector are
 * left alone, so a firing can flip nothing. One message per firing keeps the fault
 * attributable: the application sees exactly one damaged message per hit.
 *
 * @param msgvec  Returned batch; NULL is a no-op.
 * @param count   Messages recvmmsg returned; 0 is a no-op.
 * @par Thread-safety: advances the calling thread's PRNG by up to three steps.
 */
static void chaos_net_corrupt_mmsghdrs(struct mmsghdr *msgvec, unsigned int count)
{
    unsigned int selected;

    if (msgvec == NULL || count == 0U)
    {
        return;
    }

    /* One message of the batch, uniformly (up to modulo bias). */
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
 * Wrappers
 *---------------------------------------------------------------------------*/

/**
 * @brief socket(2) wrapper: SOCKET rules on (domain, type).
 *
 * @details A domain or type that does not map (AF_PACKET, AF_NETLINK, SOCK_RAW for IP,
 * ...) is forwarded without matching. An ERRNO firing creates no descriptor.
 */
CHAOS_NET_EXPORT int socket(int domain, int type, int protocol)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

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
 * @brief socketpair(2) wrapper: SOCKET rules on (domain, type), as socket().
 *
 * @details Rules that match socket() for a (domain, type) also match socketpair() for
 * it. An ERRNO firing creates neither descriptor and leaves @p sv untouched.
 */
CHAOS_NET_EXPORT int socketpair(int domain, int type, int protocol, int sv[2])
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

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
 * @brief shutdown(2) wrapper: SHUTDOWN rules on the local address, else the peer.
 *
 * @details @p how (SHUT_RD, SHUT_WR, SHUT_RDWR) is not part of the match.
 */
CHAOS_NET_EXPORT int shutdown(int sockfd, int how)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

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
/** @brief Most messages the kernel moves in one sendmmsg/recvmmsg call (UIO_MAXIOV). */
#define CHAOS_NET_MMSG_MAX 1024U

/**
 * @brief Bytes the first @p count messages describe, for `@size` gates;
 *        CHAOS_POLICY_NO_SIZE when one is invalid or the sum would exceed 2^63.
 */
static uint64_t chaos_net_mmsg_size(const struct mmsghdr *msgvec, unsigned int count)
{
    uint64_t total = 0U;
    unsigned int index;

    if (msgvec == NULL)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    for (index = 0U; index < count; ++index)
    {
        const uint64_t part = chaos_net_message_size(&msgvec[index].msg_hdr);

        if (part == CHAOS_POLICY_NO_SIZE || part > UINT64_MAX / 2U - total)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        total += part;
    }
    return total;
}

/**
 * @brief sendmmsg(2) wrapper (Linux): first matching message decides for the batch.
 *
 * @details Scans at most CHAOS_NET_MMSG_MAX messages for the first whose msg_name
 * matches a SEND rule; a message without msg_name stands for the connection, matched
 * once with chaos_net_match_connected(). The effect applies to the whole batch: on an
 * ERRNO firing nothing is sent. `@size` compares the bytes of the scanned messages.
 *
 * The guard is checked once at entry. Endpoint resolution inside the loop sets it
 * itself around each getsockopt/getsockname/getpeername.
 */
CHAOS_NET_EXPORT int
sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags)
{
    const unsigned int count = vlen < CHAOS_NET_MMSG_MAX ? vlen : CHAOS_NET_MMSG_MAX;
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    unsigned int index;
    int connected_checked = 0;
    int matched = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || msgvec == NULL || !chaos_net_config_prepare())
    {
        return chaos_net_call_real_sendmmsg(sockfd, msgvec, vlen, flags);
    }

    /* The kernel sends at most CHAOS_NET_MMSG_MAX messages of a batch. A message without
     * a destination goes to the connection, which is matched once. */
    for (index = 0U; index < count && !matched; ++index)
    {
        struct msghdr *message = &msgvec[index].msg_hdr;

        if (message->msg_name != NULL)
        {
            matched = chaos_net_endpoint_from_sockaddr_fd(
                          sockfd,
                          (const struct sockaddr *)message->msg_name,
                          message->msg_namelen,
                          &endpoint
                      ) &&
                      chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_SEND, &endpoint, &rule);
        }
        else if (!connected_checked)
        {
            connected_checked = 1;
            matched = chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule);
        }
    }
    if (matched)
    {
        rule.call_size = chaos_net_mmsg_size(msgvec, count);
        if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
        {
            return -1;
        }
    }
    return chaos_net_call_real_sendmmsg(sockfd, msgvec, vlen, flags);
}

/**
 * @brief recvmmsg(2) wrapper (Linux): RECV rules on either end of the connection.
 *
 * @details chaos_net_match_connected() as recv(), the local end winning ties. LATENCY and
 * ERRNO apply before the call; a firing CORRUPT flips one bit in one randomly selected
 * message of the returned batch (chaos_net_corrupt_mmsghdrs()). TRICKLE and DUP are not
 * applied to batches. @p timeout is recvmmsg's own and unrelated to the TIMEOUT effect.
 */
CHAOS_NET_EXPORT int recvmmsg(
    int sockfd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    chaos_net_rule_t rule;
    int rc;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_match_connected(sockfd, CHAOS_NET_OP_RECV, 0, &rule))
    {
        return chaos_net_call_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    }

    rule.call_size =
        chaos_net_mmsg_size(msgvec, vlen < CHAOS_NET_MMSG_MAX ? vlen : CHAOS_NET_MMSG_MAX);
    if (chaos_net_apply_simple_pre_call_rule(&rule) != 0)
    {
        return -1;
    }

    rc = chaos_net_call_real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    /* One bit in one randomly selected message of the batch. */
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_mmsghdrs(msgvec, (unsigned int)rc);
    }
    return rc;
}
#endif
