#include "../support/test_net_support.h"

#include <fcntl.h>
#include <stdarg.h>
#include "../../src/net/chaos_net_config.h"
#include "../../src/net/chaos_net_actions.h"
#include "../../src/net/chaos_net_endpoint.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

static chaos_net_rule_t g_stub_rule;
static chaos_net_endpoint_t g_stub_endpoint;
static int g_stub_prepare = 0;
static int g_stub_match_endpoint = 0;
static int g_stub_endpoint_from_sockaddr = 0;
static int g_stub_endpoint_from_socket_spec = 0;
static int g_stub_endpoint_from_activity = 0;
static int g_stub_endpoint_from_local = 0;
static int g_stub_endpoint_from_peer = 0;
static int g_latency_calls = 0;
static int g_errno_trigger = 0;
static int g_should_trigger = 0;
static int g_corrupt_calls = 0;
static int g_wait_fail_snprintf = 0;
static int g_wait_fake_open = 0;
static int g_wait_force_open_fail = 0;
static int g_wait_force_read_fail = 0;
static int g_wait_fill_buffer = 0;
static const char *g_wait_read_text = NULL;
static size_t g_wait_read_offset = 0U;
#ifdef __linux__
static const int g_wait_fake_fd = 7331;
#endif

static int g_bind_calls = 0;
static int g_listen_calls = 0;
static int g_connect_calls = 0;
static int g_accept_calls = 0;
static int g_socket_calls = 0;
static int g_socketpair_calls = 0;
static int g_shutdown_calls = 0;
static int g_send_calls = 0;
static int g_sendto_calls = 0;
static int g_sendmsg_calls = 0;
static int g_recv_calls = 0;
static int g_recvfrom_calls = 0;
static int g_recvmsg_calls = 0;
static int g_poll_calls = 0;
static int g_ppoll_calls = 0;
static int g_select_calls = 0;
static int g_pselect_calls = 0;
#ifdef __linux__
static int g_sendmmsg_calls = 0;
static int g_recvmmsg_calls = 0;
static int g_epoll_wait_calls = 0;
static int g_epoll_pwait_calls = 0;
#endif

static int g_bind_result = 0;
static int g_listen_result = 0;
static int g_connect_result = 0;
static int g_accept_result = 10;
static int g_socket_result = 8;
static int g_socketpair_result = 0;
static int g_shutdown_result = 0;
static ssize_t g_send_result = 4;
static ssize_t g_sendto_result = 4;
static ssize_t g_sendmsg_result = 4;
static ssize_t g_recv_result = 4;
static ssize_t g_recvfrom_result = 4;
static ssize_t g_recvmsg_result = 4;
static int g_poll_result = 0;
static int g_ppoll_result = 0;
static int g_select_result = 0;
static int g_pselect_result = 0;
#ifdef __linux__
static int g_sendmmsg_result = 1;
static int g_recvmmsg_result = 1;
static int g_epoll_wait_result = 1;
static int g_epoll_pwait_result = 1;
#endif

int chaos_net_config_prepare(void)
{
    return g_stub_prepare;
}

int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    (void)operation;
    (void)endpoint;
    if (g_stub_match_endpoint == 0 || rule == NULL)
    {
        return 0;
    }
    *rule = g_stub_rule;
    return 1;
}

int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    return chaos_net_config_match_endpoint(operation, endpoint, rule);
}

int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    (void)fd;
    (void)address;
    (void)address_length;
    if (g_stub_endpoint_from_sockaddr == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
)
{
    (void)domain;
    (void)type;
    (void)protocol;
    if (g_stub_endpoint_from_socket_spec == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_activity == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_local == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_peer == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}

int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;

    ++g_corrupt_calls;
    if (buffer != NULL && size > 0U)
    {
        bytes[index_sample % size] ^= (unsigned char)(1U << (bit_sample & 7U));
    }
}

void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    chaos_net_corrupt_buffer_sample(buffer, size, 0U, 0U);
}

static int chaos_net_test_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_bind_calls;
    return g_bind_result;
}

static int chaos_net_test_listen(int sockfd, int backlog)
{
    (void)sockfd;
    (void)backlog;
    ++g_listen_calls;
    return g_listen_result;
}

static int
chaos_net_test_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_connect_calls;
    return g_connect_result;
}

static int chaos_net_test_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_accept_calls;
    return g_accept_result;
}

static int chaos_net_test_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    ++g_socket_calls;
    return g_socket_result;
}

static int chaos_net_test_socketpair(int domain, int type, int protocol, int sv[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    ++g_socketpair_calls;
    if (sv != NULL)
    {
        sv[0] = 11;
        sv[1] = 12;
    }
    return g_socketpair_result;
}

static int chaos_net_test_shutdown(int sockfd, int how)
{
    (void)sockfd;
    (void)how;
    ++g_shutdown_calls;
    return g_shutdown_result;
}

#ifdef __linux__
static int
chaos_net_test_accept4(int sockfd, struct sockaddr *address, socklen_t *address_length, int flags)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    (void)flags;
    ++g_accept_calls;
    return g_accept_result;
}
#endif

static ssize_t chaos_net_test_send(int sockfd, const void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)buffer;
    (void)size;
    (void)flags;
    ++g_send_calls;
    return g_send_result;
}

static ssize_t chaos_net_test_sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    const struct sockaddr *address,
    socklen_t address_length
)
{
    (void)sockfd;
    (void)buffer;
    (void)size;
    (void)flags;
    (void)address;
    (void)address_length;
    ++g_sendto_calls;
    return g_sendto_result;
}

static ssize_t chaos_net_test_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)message;
    (void)flags;
    ++g_sendmsg_calls;
    return g_sendmsg_result;
}

static ssize_t chaos_net_test_recv(int sockfd, void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recv_calls;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recv_result;
}

static ssize_t chaos_net_test_recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    struct sockaddr *address,
    socklen_t *address_length
)
{
    (void)sockfd;
    (void)flags;
    (void)address;
    (void)address_length;
    ++g_recvfrom_calls;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recvfrom_result;
}

static ssize_t chaos_net_test_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recvmsg_calls;
    if (message != NULL && message->msg_iovlen > 0 && message->msg_iov[0].iov_len >= 4U)
    {
        (void)memcpy(message->msg_iov[0].iov_base, "data", 4U);
    }
    return g_recvmsg_result;
}

static int chaos_net_test_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    ++g_poll_calls;
    return g_poll_result;
}

static int chaos_net_test_ppoll(
    struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask
)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    (void)sigmask;
    ++g_ppoll_calls;
    return g_ppoll_result;
}

static int chaos_net_test_select(
    int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    ++g_select_calls;
    return g_select_result;
}

static int chaos_net_test_pselect(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timespec *timeout,
    const sigset_t *sigmask
)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    (void)sigmask;
    ++g_pselect_calls;
    return g_pselect_result;
}

#ifdef __linux__
static int chaos_net_test_wait_snprintf(char *buffer, size_t size, const char *format, ...)
{
    int rc;
    va_list args;

    if (g_wait_fail_snprintf != 0)
    {
        return -1;
    }

    va_start(args, format);
    rc = vsnprintf(buffer, size, format, args);
    va_end(args);
    return rc;
}

static int chaos_net_test_wait_open(const char *path, int flags, ...)
{
    if (g_wait_force_open_fail != 0)
    {
        (void)path;
        (void)flags;
        errno = ENOENT;
        return -1;
    }
    if (g_wait_fake_open != 0)
    {
        (void)path;
        (void)flags;
        return g_wait_fake_fd;
    }
    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        mode_t mode;

        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        return open(path, flags, mode);
    }
    return open(path, flags);
}

static ssize_t chaos_net_test_wait_read(int fd, void *buffer, size_t count)
{
    if (fd == g_wait_fake_fd && g_wait_fake_open != 0)
    {
        if (g_wait_force_read_fail != 0)
        {
            errno = EIO;
            return -1;
        }
        if (g_wait_fill_buffer != 0)
        {
            (void)memset(buffer, 'x', count);
            return (ssize_t)count;
        }
        if (g_wait_read_text != NULL)
        {
            size_t remaining = strlen(g_wait_read_text) - g_wait_read_offset;
            size_t chunk = remaining < count ? remaining : count;

            if (chunk == 0U)
            {
                return 0;
            }
            (void)memcpy(buffer, g_wait_read_text + g_wait_read_offset, chunk);
            g_wait_read_offset += chunk;
            return (ssize_t)chunk;
        }
        return 0;
    }
    return read(fd, buffer, count);
}

static int chaos_net_test_wait_close(int fd)
{
    if (fd == g_wait_fake_fd && g_wait_fake_open != 0)
    {
        return 0;
    }
    return close(fd);
}
#endif

#ifdef __linux__
static int chaos_net_test_sendmmsg(
    int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags
)
{
    (void)sockfd;
    (void)msgvec;
    (void)vlen;
    (void)flags;
    ++g_sendmmsg_calls;
    return g_sendmmsg_result;
}

static int chaos_net_test_recvmmsg(
    int sockfd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    (void)sockfd;
    (void)vlen;
    (void)flags;
    (void)timeout;
    ++g_recvmmsg_calls;
    if (msgvec != NULL && vlen > 0U && msgvec[0].msg_hdr.msg_iov != NULL &&
        msgvec[0].msg_hdr.msg_iovlen > 0)
    {
        struct iovec *iov = msgvec[0].msg_hdr.msg_iov;

        if (iov[0].iov_base != NULL && iov[0].iov_len >= 4U)
        {
            (void)memcpy(iov[0].iov_base, "data", 4U);
            msgvec[0].msg_len = 4U;
        }
    }
    return g_recvmmsg_result;
}

static int
chaos_net_test_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    ++g_epoll_wait_calls;
    return g_epoll_wait_result;
}

static int chaos_net_test_epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    (void)sigmask;
    ++g_epoll_pwait_calls;
    return g_epoll_pwait_result;
}
#endif

#include "../../src/net/chaos_net_socket.c"
#include "../../src/net/chaos_net_extra.c"
#ifdef __linux__
#define open chaos_net_test_wait_open
#define read chaos_net_test_wait_read
#define close chaos_net_test_wait_close
#undef snprintf
#define snprintf chaos_net_test_wait_snprintf
#endif
#include "../../src/net/chaos_net_wait.c"
#ifdef __linux__
#undef snprintf
#undef close
#undef read
#undef open
#endif

static void reset_wrapper_stubs(void)
{
    chaos_net_test_reset_runtime();
    g_chaos_net_real_bind = chaos_net_test_bind;
    g_chaos_net_real_listen = chaos_net_test_listen;
    g_chaos_net_real_connect = chaos_net_test_connect;
    g_chaos_net_real_accept = chaos_net_test_accept;
    g_chaos_net_real_socket = chaos_net_test_socket;
    g_chaos_net_real_socketpair = chaos_net_test_socketpair;
    g_chaos_net_real_shutdown = chaos_net_test_shutdown;
    g_chaos_net_real_send = chaos_net_test_send;
    g_chaos_net_real_sendto = chaos_net_test_sendto;
    g_chaos_net_real_sendmsg = chaos_net_test_sendmsg;
    g_chaos_net_real_recv = chaos_net_test_recv;
    g_chaos_net_real_recvfrom = chaos_net_test_recvfrom;
    g_chaos_net_real_recvmsg = chaos_net_test_recvmsg;
    g_chaos_net_real_poll = chaos_net_test_poll;
    g_chaos_net_real_ppoll = chaos_net_test_ppoll;
    g_chaos_net_real_select = chaos_net_test_select;
    g_chaos_net_real_pselect = chaos_net_test_pselect;
#ifdef __linux__
    g_chaos_net_real_accept4 = chaos_net_test_accept4;
    g_chaos_net_real_sendmmsg = chaos_net_test_sendmmsg;
    g_chaos_net_real_recvmmsg = chaos_net_test_recvmmsg;
    g_chaos_net_real_epoll_wait = chaos_net_test_epoll_wait;
    g_chaos_net_real_epoll_pwait = chaos_net_test_epoll_pwait;
#endif
    (void)memset(&g_stub_rule, 0, sizeof(g_stub_rule));
    (void)memset(&g_stub_endpoint, 0, sizeof(g_stub_endpoint));
    g_stub_prepare = 0;
    g_stub_match_endpoint = 0;
    g_stub_endpoint_from_sockaddr = 0;
    g_stub_endpoint_from_socket_spec = 0;
    g_stub_endpoint_from_activity = 0;
    g_stub_endpoint_from_local = 0;
    g_stub_endpoint_from_peer = 0;
    g_latency_calls = 0;
    g_errno_trigger = 0;
    g_should_trigger = 0;
    g_corrupt_calls = 0;
    g_wait_fail_snprintf = 0;
    g_wait_fake_open = 0;
    g_wait_force_open_fail = 0;
    g_wait_force_read_fail = 0;
    g_wait_fill_buffer = 0;
    g_wait_read_text = NULL;
    g_wait_read_offset = 0U;
    g_bind_calls = 0;
    g_listen_calls = 0;
    g_connect_calls = 0;
    g_accept_calls = 0;
    g_socket_calls = 0;
    g_socketpair_calls = 0;
    g_shutdown_calls = 0;
    g_send_calls = 0;
    g_sendto_calls = 0;
    g_sendmsg_calls = 0;
    g_recv_calls = 0;
    g_recvfrom_calls = 0;
    g_recvmsg_calls = 0;
    g_poll_calls = 0;
    g_ppoll_calls = 0;
    g_select_calls = 0;
    g_pselect_calls = 0;
#ifdef __linux__
    g_sendmmsg_calls = 0;
    g_recvmmsg_calls = 0;
    g_epoll_wait_calls = 0;
    g_epoll_pwait_calls = 0;
#endif
    g_bind_result = 0;
    g_listen_result = 0;
    g_connect_result = 0;
    g_accept_result = 10;
    g_socket_result = 8;
    g_socketpair_result = 0;
    g_shutdown_result = 0;
    g_send_result = 4;
    g_sendto_result = 4;
    g_sendmsg_result = 4;
    g_recv_result = 4;
    g_recvfrom_result = 4;
    g_recvmsg_result = 4;
    g_poll_result = 0;
    g_ppoll_result = 0;
    g_select_result = 0;
    g_pselect_result = 0;
#ifdef __linux__
    g_sendmmsg_result = 1;
    g_recvmmsg_result = 1;
    g_epoll_wait_result = 1;
    g_epoll_pwait_result = 1;
#endif
}

static void test_bind_and_connect_paths(void)
{
    struct sockaddr_in address;

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9000U);
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EADDRINUSE;
    g_errno_trigger = 1;
    errno = 0;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == -1);
    assert(errno == EADDRINUSE);
    assert(g_bind_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_latency_calls == 1);
    assert(g_connect_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_connect_calls == 1);
}

static void test_accept_and_send_paths(void)
{
    struct sockaddr_in address;
    struct msghdr message;

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9100U);
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(listen(3, 16) == 0);
    assert(g_listen_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(listen(3, 16) == 0);
    assert(g_listen_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EADDRINUSE;
    g_errno_trigger = 1;
    errno = 0;
    assert(listen(3, 16) == -1);
    assert(errno == EADDRINUSE);
    assert(g_listen_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(accept(3, NULL, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_accept_calls == 0);

    reset_wrapper_stubs();
    assert(accept(3, NULL, NULL) == 10);
    assert(g_accept_calls == 1);

#ifdef __linux__
    reset_wrapper_stubs();
    assert(accept4(3, NULL, NULL, 0) == 10);
    assert(g_accept_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(accept4(3, NULL, NULL, 0) == -1);
    assert(errno == EINTR);
    assert(g_accept_calls == 0);
#endif

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(send(4, "data", 4U, 0) == 4);
    assert(g_send_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(send(4, "data", 4U, 0) == 4);
    assert(g_send_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(
        sendto(4, "data", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) ==
        -1
    );
    assert(errno == EHOSTUNREACH);
    assert(g_sendto_calls == 0);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    assert(sendmsg(4, &message, 0) == 4);
    assert(g_sendmsg_calls == 1);

    reset_wrapper_stubs();
    assert(
        sendto(4, "data", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 4
    );
    assert(g_sendto_calls == 1);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendmsg(4, &message, 0) == 4);
    assert(g_sendmsg_calls == 1);
    assert(g_latency_calls == 1);
}

static void test_recv_paths(void)
{
    char buffer[8] = "xxxxxxx";
    char msg_buffer[8] = "xxxxxxx";
    struct iovec iov;
    struct msghdr message;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(buffer[0] != 'd');

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recv(5, buffer, sizeof(buffer), 0) == -1);
    assert(errno == EAGAIN);
    assert(g_recv_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_recvfrom_calls == 0);

    reset_wrapper_stubs();
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);
    assert(g_corrupt_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = msg_buffer;
    iov.iov_len = sizeof(msg_buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(memcmp(msg_buffer, "data", 4U) != 0);

    reset_wrapper_stubs();
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = msg_buffer;
    iov.iov_len = sizeof(msg_buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);
    assert(g_latency_calls == 1);
}

static void test_socket_and_shutdown_paths(void)
{
    int sv[2];

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAFNOSUPPORT;
    g_errno_trigger = 1;
    errno = 0;
    assert(socket(AF_INET, SOCK_STREAM, 0) == -1);
    assert(errno == EAFNOSUPPORT);
    assert(g_socket_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EMFILE;
    g_errno_trigger = 1;
    errno = 0;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1);
    assert(errno == EMFILE);
    assert(g_socketpair_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(g_socketpair_calls == 1);
    assert(g_latency_calls == 1);
    assert(sv[0] == 11);
    assert(sv[1] == 12);

    reset_wrapper_stubs();
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ENOTCONN;
    g_errno_trigger = 1;
    errno = 0;
    assert(shutdown(7, SHUT_RDWR) == -1);
    assert(errno == ENOTCONN);
    assert(g_shutdown_calls == 0);

    reset_wrapper_stubs();
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);

    reset_wrapper_stubs();
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(g_socketpair_calls == 1);

    reset_wrapper_stubs();
    assert(shutdown(7, SHUT_RDWR) == 0);
    assert(g_shutdown_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(shutdown(7, SHUT_RDWR) == 0);
    assert(g_shutdown_calls == 1);
    assert(g_latency_calls == 1);
}

static void test_wait_paths(void)
{
    struct pollfd fds[1];
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timespec ts;
    struct timeval tv;

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 0);
    assert(fds[0].revents == 0);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(select(10, &readfds, NULL, NULL, NULL) == 0);
    assert(g_select_calls == 0);
    assert(!FD_ISSET(9, &readfds));

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(poll(fds, 1U, 100) == -1);
    assert(errno == EINTR);
    assert(g_poll_calls == 0);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 0);
    assert(fds[0].revents == 0);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(ppoll(fds, 1U, &ts, NULL) == -1);
    assert(errno == EINTR);
    assert(g_ppoll_calls == 0);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(9, &readfds);
    FD_SET(8, &writefds);
    FD_SET(7, &exceptfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    tv.tv_sec = 0;
    tv.tv_usec = 1;
    errno = 0;
    assert(select(10, &readfds, &writefds, &exceptfds, &tv) == -1);
    assert(errno == EAGAIN);
    assert(g_select_calls == 0);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(select(10, &readfds, NULL, NULL, &tv) == 0);
    assert(g_select_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 0);
    assert(!FD_ISSET(9, &readfds));

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == -1);
    assert(errno == EINTR);
    assert(g_pselect_calls == 0);

    reset_wrapper_stubs();
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 1);

    reset_wrapper_stubs();
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(select(10, &readfds, NULL, NULL, &tv) == 0);
    assert(g_select_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 1);
}

#ifdef __linux__
static void test_batch_paths(void)
{
    struct sockaddr_in address;
    char buffer[8] = "xxxxxxx";
    struct iovec iov;
    struct mmsghdr messages[1];

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9200U);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_name = &address;
    messages[0].msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(sendmmsg(4, messages, 1U, 0) == -1);
    assert(errno == EHOSTUNREACH);
    assert(g_sendmmsg_calls == 0);

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9200U);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_name = &address;
    messages[0].msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_iov = &iov;
    messages[0].msg_hdr.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == 1);
    assert(g_recvmmsg_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(memcmp(buffer, "data", 4U) != 0);

    reset_wrapper_stubs();
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);

    reset_wrapper_stubs();
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == 1);
    assert(g_recvmmsg_calls == 1);

    reset_wrapper_stubs();
    g_chaos_net_tls_guard = 1;
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);
    g_chaos_net_tls_guard = 0;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_recvmmsg_calls == 0);
}
#endif

static void test_direct_helper_paths(void)
{
    char second[4] = {'a', 'b', 'c', 'd'};
    struct iovec recv_iov[2];
    char first[1] = {0};
    struct pollfd fds[2];
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timespec ts;
    struct timeval tv;
    chaos_net_rule_t rule;
    int synthetic_timeout = -1;
    int pipefd[2];

    reset_wrapper_stubs();
    assert(chaos_net_apply_pre_call_rule(NULL) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(NULL) == 0);
    assert(chaos_net_wait_pre_call(NULL, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
    assert(g_latency_calls == 3);

    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_net_apply_pre_call_rule(&rule) == -1);
    assert(errno == EAGAIN);
    errno = 0;
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == -1);
    assert(errno == EAGAIN);
    errno = 0;
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == -1);
    assert(errno == EAGAIN);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    synthetic_timeout = 0;
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 1);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    synthetic_timeout = -1;
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

    chaos_net_wait_clear_pollfds(NULL, 0U);
    fds[0].revents = POLLIN;
    fds[1].revents = POLLOUT;
    chaos_net_wait_clear_pollfds(fds, 2U);
    assert(fds[0].revents == 0);
    assert(fds[1].revents == 0);

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(3, &readfds);
    FD_SET(4, &writefds);
    FD_SET(5, &exceptfds);
    chaos_net_wait_clear_fdsets(&readfds, &writefds, &exceptfds);
    assert(!FD_ISSET(3, &readfds));
    assert(!FD_ISSET(4, &writefds));
    assert(!FD_ISSET(5, &exceptfds));

    assert(chaos_net_call_real_bind(1, NULL, 0) == 0);
    assert(chaos_net_call_real_listen(1, 1) == 0);
    assert(chaos_net_call_real_connect(1, NULL, 0) == 0);
    assert(chaos_net_call_real_accept(1, NULL, NULL) == 10);
#ifdef __linux__
    assert(chaos_net_call_real_accept4(1, NULL, NULL, 0) == 10);
#endif
    assert(chaos_net_call_real_send(1, "x", 1U, 0) == 4);
    assert(chaos_net_call_real_sendto(1, "x", 1U, 0, NULL, 0) == 4);
    assert(chaos_net_call_real_sendmsg(1, NULL, 0) == 4);
    assert(chaos_net_call_real_recv(1, second, sizeof(second), 0) == 4);
    assert(chaos_net_call_real_recvfrom(1, second, sizeof(second), 0, NULL, NULL) == 4);
    assert(chaos_net_call_real_recvmsg(1, NULL, 0) == 4);
    assert(chaos_net_call_real_socket(1, 2, 3) == 8);
    assert(chaos_net_call_real_socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) == 0);
    assert(chaos_net_call_real_shutdown(1, SHUT_RDWR) == 0);
    assert(chaos_net_call_real_poll(fds, 2U, 0) == 0);
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(chaos_net_call_real_ppoll(fds, 2U, &ts, NULL) == 0);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    assert(chaos_net_call_real_select(0, NULL, NULL, NULL, &tv) == 0);
    assert(chaos_net_call_real_pselect(0, NULL, NULL, NULL, &ts, NULL) == 0);

    second[0] = 'a';
    second[1] = 'b';
    second[2] = 'c';
    second[3] = 'd';
    chaos_net_corrupt_iovecs(NULL, 0, 0U);
    recv_iov[0].iov_base = first;
    recv_iov[0].iov_len = 1U;
    recv_iov[1].iov_base = second;
    recv_iov[1].iov_len = sizeof(second);
    for (g_chaos_net_tls_prng_state = 1U; chaos_net_prng_next_u32() % 3U == 0U;
         ++g_chaos_net_tls_prng_state)
    {
    }
    chaos_net_corrupt_iovecs(recv_iov, 2, 3U);
    assert(g_corrupt_calls >= 1);

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_pollfds(NULL, 1U, &rule));
    g_stub_prepare = 1;
    fds[0].fd = -1;
    assert(!chaos_net_wait_match_pollfds(fds, 1U, &rule));
    fds[0].fd = 9;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_pollfds(fds, 1U, &rule));

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_fdsets(0, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    assert(!chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(!chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
}

#ifdef __linux__
static void test_direct_linux_helper_paths(void)
{
    struct iovec recv_iov[2];
    char first[1] = {0};
    char second[4] = {'a', 'b', 'c', 'd'};
    struct mmsghdr recv_messages[1];
    struct epoll_event events[1];
    struct epoll_event event;
    chaos_net_rule_t rule;
    int pipefd[2];
    int epfd;

    reset_wrapper_stubs();
    assert(chaos_net_call_real_sendmmsg(1, NULL, 0U, 0U) == 1);
    assert(chaos_net_call_real_recvmmsg(1, recv_messages, 0U, 0U, NULL) == 1);
    assert(chaos_net_call_real_epoll_wait(-1, events, 1, 0) == 1);
    assert(chaos_net_call_real_epoll_pwait(-1, events, 1, 0, NULL) == 1);

    recv_iov[0].iov_base = first;
    recv_iov[0].iov_len = 0U;
    recv_iov[1].iov_base = second;
    recv_iov[1].iov_len = sizeof(second);
    (void)memset(recv_messages, 0, sizeof(recv_messages));
    recv_messages[0].msg_hdr.msg_iov = recv_iov;
    recv_messages[0].msg_hdr.msg_iovlen = 2;
    recv_messages[0].msg_len = 4U;
    chaos_net_corrupt_mmsghdrs(NULL, 0U);
    chaos_net_corrupt_mmsghdrs(recv_messages, 1U);
    assert(g_corrupt_calls == 1);

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_epoll(-1, NULL));
    g_wait_fail_snprintf = 1;
    g_stub_prepare = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    assert(!chaos_net_wait_match_epoll(-1, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_wait_fake_open = 1;
    g_wait_force_read_fail = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_wait_fake_open = 1;
    g_wait_fill_buffer = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    assert(pipe(pipefd) == 0);
    epfd = epoll_create1(0);
    assert(epfd >= 0);
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];
    assert(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &event) == 0);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_epoll(epfd, &rule));
    assert(close(pipefd[0]) == 0);
    assert(close(pipefd[1]) == 0);
    assert(close(epfd) == 0);
}
#endif

static void test_wrapper_passthrough_and_additional_branches(void)
{
    struct sockaddr_in address;
    struct msghdr message;
    struct iovec iov;
    char buffer[8] = "xxxxxxx";

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9001U);
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNREFUSED;
    g_errno_trigger = 1;
    errno = 0;
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == -1);
    assert(errno == ECONNREFUSED);
    assert(g_connect_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(accept(3, NULL, NULL) == 10);
    assert(g_accept_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
#ifdef __linux__
    assert(accept4(3, NULL, NULL, 0) == 10);
    assert(g_accept_calls == 1);
    assert(g_latency_calls == 1);
#endif

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EPIPE;
    g_errno_trigger = 1;
    errno = 0;
    assert(send(4, "data", 4U, 0) == -1);
    assert(errno == EPIPE);
    assert(g_send_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendto(4, "data", 4U, 0, NULL, 0) == 4);
    assert(g_sendto_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(sendmsg(4, &message, 0) == -1);
    assert(errno == EHOSTUNREACH);
    assert(g_sendmsg_calls == 0);

    reset_wrapper_stubs();
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvmsg(5, &message, 0) == -1);
    assert(errno == EAGAIN);
    assert(g_recvmsg_calls == 0);

    reset_wrapper_stubs();
    g_chaos_net_tls_guard = 1;
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);
    g_chaos_net_tls_guard = 0;
}

#ifdef __linux__
static void test_epoll_wrapper_paths(void)
{
    int pipefd[2];
    int epfd;
    struct epoll_event event;
    struct epoll_event events[1];

    assert(pipe(pipefd) == 0);
    epfd = epoll_create1(0);
    assert(epfd >= 0);
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];
    assert(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &event) == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(epoll_wait(epfd, events, 1, 0) == 0);
    assert(g_epoll_wait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ETIMEDOUT;
    g_errno_trigger = 1;
    errno = 0;
    assert(epoll_wait(epfd, events, 1, 0) == -1);
    assert(errno == ETIMEDOUT);
    assert(g_epoll_wait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(epoll_wait(epfd, events, 1, 0) == 1);
    assert(g_epoll_wait_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ETIMEDOUT;
    g_errno_trigger = 1;
    errno = 0;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == -1);
    assert(errno == ETIMEDOUT);
    assert(g_epoll_pwait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 0);
    assert(g_epoll_pwait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 1);
    assert(g_epoll_pwait_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(epoll_wait(epfd, events, 1, 0) == 1);
    assert(g_epoll_wait_calls == 1);

    reset_wrapper_stubs();
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 1);
    assert(g_epoll_pwait_calls == 1);

    assert(close(pipefd[0]) == 0);
    assert(close(pipefd[1]) == 0);
    assert(close(epfd) == 0);
}
#endif

int main(void)
{
    test_bind_and_connect_paths();
    test_accept_and_send_paths();
    test_recv_paths();
    test_socket_and_shutdown_paths();
    test_wait_paths();
    test_direct_helper_paths();
    test_wrapper_passthrough_and_additional_branches();
#ifdef __linux__
    test_batch_paths();
    test_direct_linux_helper_paths();
    test_epoll_wrapper_paths();
#endif
    return 0;
}
