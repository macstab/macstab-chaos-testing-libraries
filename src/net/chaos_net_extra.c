#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <string.h>

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

static int chaos_net_call_real_socket(int domain, int type, int protocol)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socket(domain, type, protocol);
    chaos_net_leave_internal(previous);
    return rc;
}

static int chaos_net_call_real_socketpair(int domain, int type, int protocol, int sv[2])
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_socketpair(domain, type, protocol, sv);
    chaos_net_leave_internal(previous);
    return rc;
}

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

static void chaos_net_corrupt_mmsghdrs(struct mmsghdr *msgvec, unsigned int count)
{
    unsigned int selected;

    if (msgvec == NULL || count == 0U)
    {
        return;
    }

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
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_mmsghdrs(msgvec, (unsigned int)rc);
    }
    return rc;
}
#endif
