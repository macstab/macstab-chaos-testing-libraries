/**
 * @file test_net_support.h
 * @brief NET-domain test globals, reset helper, sockaddr builders, and dlsym cast utility.
 *
 * Subsystem under test: chaos-net (LD_PRELOAD network fault injection via
 *   bind / connect / listen / accept / send / recv / poll / select / etc.).
 *
 * This header is included by every unit test that exercises the NET domain.
 * It provides:
 *
 *   1. `CHAOS_NET_DEFINE_TEST_GLOBALS()` -- instantiates all real-function-pointer
 *      globals and PRNG/TLS globals. Platform-conditional on Linux:
 *      `CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()` additionally instantiates the
 *      Linux-only globals for accept4, sendmmsg, recvmmsg, epoll_wait, and
 *      epoll_pwait.
 *
 *   2. `chaos_net_test_reset_runtime()` -- resets all NET runtime globals to
 *      their initial (NULL/zero) state.
 *
 *   3. `chaos_net_test_set_ipv4()` and `chaos_net_test_set_ipv6()` -- helpers
 *      that build a `sockaddr_in` / `sockaddr_in6` from a text IP and port. Used
 *      by endpoint-resolution tests that need real sockaddr values.
 *
 *   4. `CHAOS_NET_TEST_DLSYM_RESULT(type, function)` -- type-safe function
 *      pointer to `void *` conversion for use in dlsym stubs.
 *
 * Coverage approach:
 * - Tests directly `#include` production `.c` files after `#define`-overriding
 *   `dlsym`, `dlerror`, `abort`, and (on Linux) `syscall`.
 * - The LD_PRELOAD interposition path is NOT tested here.
 *
 * What is NOT tested via this header:
 * - Actual socket connection/data transfer semantics.
 * - Thread-safety of the TLS guard under concurrent socket calls.
 * - OS-specific epoll/kqueue behaviour.
 */

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

/**
 * @defgroup chaos_net_test_linux_globals Linux-only NET test globals
 * @{
 *
 * Conditional macros for the five Linux-only socket operations.
 * On non-Linux platforms these expand to nothing.
 *
 * `CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()` -- declares the globals (used once
 *   at file scope inside `CHAOS_NET_DEFINE_TEST_GLOBALS()`).
 * `CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL()` -- sets all five globals to NULL
 *   (used inside `chaos_net_test_reset_runtime()`).
 */
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
/** @} */

/**
 * @brief Instantiate all NET-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope. Defines all 20 portable
 * real-function-pointer globals (bind through getsockopt) plus the Linux-only
 * five, plus the TLS guard, TLS PRNG state, and process seed.
 */
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

/**
 * @brief Reset all NET-domain runtime globals to their initial state.
 *
 * Sets all real-function-pointer globals to NULL, zeroes the TLS guard, TLS
 * PRNG state, and resets the process seed to 1. Call at the start of each test
 * function that modifies NET runtime state.
 */
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

/**
 * @brief Fill a `sockaddr_in` with the given IPv4 address and port.
 *
 * Used by endpoint tests that need a valid `struct sockaddr_in` to pass to
 * `chaos_net_endpoint_from_sockaddr()` or similar helpers.
 *
 * @param address  Output sockaddr_in; memory is zeroed before population.
 * @param ip       Dotted-decimal IPv4 address string (e.g. "127.0.0.1").
 * @param port     Port number in host byte order.
 */
static inline void
chaos_net_test_set_ipv4(struct sockaddr_in *address, const char *ip, unsigned short port)
{
    assert(address != NULL);
    (void)memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    assert(inet_pton(AF_INET, ip, &address->sin_addr) == 1);
}

/**
 * @brief Fill a `sockaddr_in6` with the given IPv6 address and port.
 *
 * Used by endpoint tests that need a valid `struct sockaddr_in6`.
 *
 * @param address  Output sockaddr_in6; memory is zeroed before population.
 * @param ip       IPv6 address string (e.g. "::1").
 * @param port     Port number in host byte order.
 */
static inline void
chaos_net_test_set_ipv6(struct sockaddr_in6 *address, const char *ip, unsigned short port)
{
    assert(address != NULL);
    (void)memset(address, 0, sizeof(*address));
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(port);
    assert(inet_pton(AF_INET6, ip, &address->sin6_addr) == 1);
}

/**
 * @brief Convert a typed function pointer to `void *` using `memcpy`.
 *
 * @param function_bytes  Address of a function-pointer-typed value.
 * @param function_size   `sizeof` the function pointer type; must be <= sizeof(void *).
 * @return `void *` carrying the same bit pattern as the function pointer.
 */
static inline void *chaos_net_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

/**
 * @brief Produce the `void *` return value for a NET `dlsym` stub entry.
 *
 * @param type      Function pointer typedef (e.g. `chaos_net_bind_fn`).
 * @param function  Stub function to associate with this symbol name.
 */
#define CHAOS_NET_TEST_DLSYM_RESULT(type, function)                                                \
    chaos_net_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
