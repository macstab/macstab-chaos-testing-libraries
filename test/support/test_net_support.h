#ifndef CHAOS_NET_TEST_SUPPORT_H
#define CHAOS_NET_TEST_SUPPORT_H

#include "../../src/net/chaos_net_internal.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __linux__
#define CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()                                                     \
    chaos_net_accept4_fn g_chaos_net_real_accept4 = NULL;                                          \
    chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg = NULL;                                        \
    chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg = NULL;                                        \
    chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait = NULL;                                    \
    chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait = NULL;
#define CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL()                                                      \
    g_chaos_net_real_accept4 = NULL;                                                               \
    g_chaos_net_real_sendmmsg = NULL;                                                              \
    g_chaos_net_real_recvmmsg = NULL;                                                              \
    g_chaos_net_real_epoll_wait = NULL;                                                            \
    g_chaos_net_real_epoll_pwait = NULL;
#else
#define CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()
#define CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL()
#endif

#define CHAOS_NET_DEFINE_TEST_GLOBALS()                                                            \
    chaos_net_bind_fn g_chaos_net_real_bind = NULL;                                                \
    chaos_net_listen_fn g_chaos_net_real_listen = NULL;                                            \
    chaos_net_connect_fn g_chaos_net_real_connect = NULL;                                          \
    chaos_net_accept_fn g_chaos_net_real_accept = NULL;                                            \
    chaos_net_socket_fn g_chaos_net_real_socket = NULL;                                            \
    chaos_net_socketpair_fn g_chaos_net_real_socketpair = NULL;                                    \
    chaos_net_shutdown_fn g_chaos_net_real_shutdown = NULL;                                        \
    chaos_net_send_fn g_chaos_net_real_send = NULL;                                                \
    chaos_net_sendto_fn g_chaos_net_real_sendto = NULL;                                            \
    chaos_net_sendmsg_fn g_chaos_net_real_sendmsg = NULL;                                          \
    chaos_net_recv_fn g_chaos_net_real_recv = NULL;                                                \
    chaos_net_recvfrom_fn g_chaos_net_real_recvfrom = NULL;                                        \
    chaos_net_recvmsg_fn g_chaos_net_real_recvmsg = NULL;                                          \
    chaos_net_poll_fn g_chaos_net_real_poll = NULL;                                                \
    chaos_net_ppoll_fn g_chaos_net_real_ppoll = NULL;                                              \
    chaos_net_select_fn g_chaos_net_real_select = NULL;                                            \
    chaos_net_pselect_fn g_chaos_net_real_pselect = NULL;                                          \
    chaos_net_getsockname_fn g_chaos_net_real_getsockname = NULL;                                  \
    chaos_net_getpeername_fn g_chaos_net_real_getpeername = NULL;                                  \
    chaos_net_getsockopt_fn g_chaos_net_real_getsockopt = NULL;                                    \
    CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()                                                         \
    __thread int g_chaos_net_tls_guard = 0;                                                        \
    __thread uint64_t g_chaos_net_tls_prng_state = 0U;                                             \
    uint64_t g_chaos_net_process_seed = 1U

static inline void chaos_net_test_reset_runtime(void)
{
    g_chaos_net_real_bind = NULL;
    g_chaos_net_real_listen = NULL;
    g_chaos_net_real_connect = NULL;
    g_chaos_net_real_accept = NULL;
    g_chaos_net_real_socket = NULL;
    g_chaos_net_real_socketpair = NULL;
    g_chaos_net_real_shutdown = NULL;
    g_chaos_net_real_send = NULL;
    g_chaos_net_real_sendto = NULL;
    g_chaos_net_real_sendmsg = NULL;
    g_chaos_net_real_recv = NULL;
    g_chaos_net_real_recvfrom = NULL;
    g_chaos_net_real_recvmsg = NULL;
    g_chaos_net_real_poll = NULL;
    g_chaos_net_real_ppoll = NULL;
    g_chaos_net_real_select = NULL;
    g_chaos_net_real_pselect = NULL;
    g_chaos_net_real_getsockname = NULL;
    g_chaos_net_real_getpeername = NULL;
    g_chaos_net_real_getsockopt = NULL;
    CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL()
    g_chaos_net_tls_guard = 0;
    g_chaos_net_tls_prng_state = 0U;
    g_chaos_net_process_seed = 1U;
}

static inline void
chaos_net_test_set_ipv4(struct sockaddr_in *address, const char *ip, unsigned short port)
{
    assert(address != NULL);
    (void)memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    assert(inet_pton(AF_INET, ip, &address->sin_addr) == 1);
}

static inline void
chaos_net_test_set_ipv6(struct sockaddr_in6 *address, const char *ip, unsigned short port)
{
    assert(address != NULL);
    (void)memset(address, 0, sizeof(*address));
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    assert(inet_pton(AF_INET6, ip, &address->sin6_addr) == 1);
}

static inline void *chaos_net_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_NET_TEST_DLSYM_RESULT(type, function)                                                \
    chaos_net_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
