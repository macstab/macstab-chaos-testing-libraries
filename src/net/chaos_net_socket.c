#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <string.h>

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
            chaos_net_corrupt_buffer_sample(
                iov[entry].iov_base, segment_len, (uint32_t)index, bit_sample
            );
            return;
        }

        if (segment_len > 0U)
        {
            index -= segment_len;
            remaining -= segment_len;
        }
    }
}

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

static int chaos_net_call_real_listen(int sockfd, int backlog)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_listen(sockfd, backlog);
    chaos_net_leave_internal(previous);
    return result;
}

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

static ssize_t chaos_net_call_real_send(int sockfd, const void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_send(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

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

static ssize_t chaos_net_call_real_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

static ssize_t chaos_net_call_real_recv(int sockfd, void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recv(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

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

static ssize_t chaos_net_call_real_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

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
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

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
