/**
 * @file test_net_support.h
 * @brief Unit-test scaffolding for libchaos-net: runtime globals, reset helper, kernel-direct
 *        descriptor calls, sockaddr builders and dlsym cast.
 *
 * @details Unit tests compile the libchaos-net sources directly into the test binary instead
 * of loading the shared object, so the globals libchaos-net defines in its own translation
 * units must be supplied by the test. This header provides:
 *
 *   1. CHAOS_NET_DEFINE_TEST_GLOBALS(): defines the 26 portable real-function pointers, the
 *      5 Linux-only ones (accept4, sendmmsg, recvmmsg, epoll_wait, epoll_pwait, through
 *      CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()), the reentrancy guard, the PRNG state and
 *      seed, and an empty chaos_net_ensure_symbols(). Expand exactly once per test binary.
 *   2. chaos_net_test_reset_runtime(): returns those globals to their initial state.
 *   3. chaos_net_test_kernel_*(): read/write/readv/writev/close/setsockopt as raw system
 *      calls, which the reset installs as the real functions for those six operations.
 *   4. chaos_net_test_set_ipv4() / chaos_net_test_set_ipv6(): build a sockaddr_in /
 *      sockaddr_in6 from text, for endpoint tests such as test_net_endpoint.c.
 *   5. CHAOS_NET_TEST_DLSYM_RESULT(type, function): converts a typed function pointer to the
 *      `void *` a stub dlsym() returns, via memcpy (ISO C forbids the direct cast).
 *
 * Runtime tests (test_net_runtime.c) additionally `#define` dlsym, dlerror, abort and, on
 * Linux, syscall before including the production sources, so the constructor and config path
 * run without LD_PRELOAD.
 *
 * Not covered by tests built on this header: LD_PRELOAD interposition (the runtime suites
 * cover it), real connection and data-transfer semantics, epoll behaviour, and the
 * reentrancy guard under concurrent socket calls.
 */

#ifndef CHAOS_NET_TEST_SUPPORT_H
#define CHAOS_NET_TEST_SUPPORT_H

#include "../../src/net/chaos_net_internal.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>

/**
 * @defgroup chaos_net_test_linux_globals Linux-only libchaos-net test globals
 * @{
 *
 * The real functions for accept4, sendmmsg, recvmmsg, epoll_wait and epoll_pwait exist only
 * on Linux, where libchaos-net declares them; elsewhere both macros expand to nothing.
 *
 * - CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL() defines the five pointers as NULL; expanded inside
 *   CHAOS_NET_DEFINE_TEST_GLOBALS().
 * - CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL() sets them back to NULL; expanded inside
 *   chaos_net_test_reset_runtime().
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
 * @brief Defines the libchaos-net runtime globals for one test binary.
 *
 * Expand exactly once at file scope (a second expansion is a duplicate definition). Defines:
 * - The 26 portable `g_chaos_net_real_*` real-function pointers (bind through close), NULL.
 *   `g_chaos_net_real_writev` is declared with chaos_net_readv_fn, as in production.
 * - chaos_net_ensure_symbols() as a no-op, so real functions stay what the test assigns.
 * - The five Linux-only pointers via CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL().
 * - `__thread int g_chaos_net_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_net_tls_prng_state` = 0, which makes the per-thread PRNG seed
 *   itself on first use.
 * - `uint64_t g_chaos_net_process_seed` = 1, a fixed process seed.
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
    chaos_net_setsockopt_fn g_chaos_net_real_setsockopt = NULL;                                    \
    chaos_net_read_fn g_chaos_net_real_read = NULL;                                                \
    chaos_net_write_fn g_chaos_net_real_write = NULL;                                              \
    chaos_net_readv_fn g_chaos_net_real_readv = NULL;                                              \
    chaos_net_readv_fn g_chaos_net_real_writev = NULL;                                             \
    chaos_net_close_fn g_chaos_net_real_close = NULL;                                              \
    void chaos_net_ensure_symbols(void) {}                                                         \
    CHAOS_NET_DEFINE_TEST_ACCEPT4_GLOBAL()                                                         \
    __thread int g_chaos_net_tls_guard = 0;                                                        \
    __thread uint64_t g_chaos_net_tls_prng_state = 0U;                                             \
    uint64_t g_chaos_net_process_seed = 1U

/**
 * @name Kernel-direct descriptor calls for tests
 *
 * libchaos-net wraps read/write/readv/writev/close (and setsockopt) for sockets, so a test
 * binary that compiles the wrappers in routes its own descriptor I/O through them. These
 * helpers issue the system call directly. That lets the reset install working real functions
 * without dlsym() (which runtime tests stub) and without a real-function pointer that names
 * the wrapper itself, which would recurse. Return values and errno are the kernel's.
 * @{
 */
static ssize_t chaos_net_test_kernel_read(int fd, void *buffer, size_t size)
{
    return (ssize_t)syscall(SYS_read, fd, buffer, size);
}

static ssize_t chaos_net_test_kernel_write(int fd, const void *buffer, size_t size)
{
    return (ssize_t)syscall(SYS_write, fd, buffer, size);
}

static ssize_t chaos_net_test_kernel_readv(int fd, const struct iovec *iov, int iovcnt)
{
    return (ssize_t)syscall(SYS_readv, fd, iov, iovcnt);
}

static ssize_t chaos_net_test_kernel_writev(int fd, const struct iovec *iov, int iovcnt)
{
    return (ssize_t)syscall(SYS_writev, fd, iov, iovcnt);
}

static int chaos_net_test_kernel_close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

static int
chaos_net_test_kernel_setsockopt(int fd, int level, int name, const void *value, socklen_t length)
{
    return (int)syscall(SYS_setsockopt, fd, level, name, value, length);
}
/** @} */

/**
 * @brief Restores every global defined by CHAOS_NET_DEFINE_TEST_GLOBALS() to its initial value.
 *
 * Sets the real functions to NULL, except setsockopt, read, write, readv, writev and close,
 * which point at the chaos_net_test_kernel_*() helpers so the test's own descriptor I/O keeps
 * working. Zeroes the calling thread's reentrancy guard and PRNG state and resets the process
 * seed to 1. Call at the start of each test that touches libchaos-net runtime state.
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
    g_chaos_net_real_setsockopt = chaos_net_test_kernel_setsockopt;
    g_chaos_net_real_read = chaos_net_test_kernel_read;
    g_chaos_net_real_write = chaos_net_test_kernel_write;
    g_chaos_net_real_readv = chaos_net_test_kernel_readv;
    g_chaos_net_real_writev = chaos_net_test_kernel_writev;
    g_chaos_net_real_close = chaos_net_test_kernel_close;
    CHAOS_NET_RESET_TEST_ACCEPT4_GLOBAL()
    g_chaos_net_tls_guard = 0;
    g_chaos_net_tls_prng_state = 0U;
    g_chaos_net_process_seed = 1U;
}

/**
 * @brief Fills a `sockaddr_in` with an IPv4 address and port.
 *
 * Feeds endpoint tests that pass real socket addresses to
 * chaos_net_endpoint_from_sockaddr_fd().
 *
 * @param address  Output; zeroed first, must not be NULL (asserted).
 * @param ip       Dotted-decimal IPv4 text, e.g. "127.0.0.1"; inet_pton() must accept it
 *                 (asserted).
 * @param port     Port in host byte order; stored in network byte order.
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
 * @brief Fills a `sockaddr_in6` with an IPv6 address and port.
 *
 * @param address  Output; zeroed first (flow info and scope id stay 0), must not be NULL
 *                 (asserted).
 * @param ip       IPv6 text, e.g. "::1"; inet_pton() must accept it (asserted).
 * @param port     Port in host byte order; stored in network byte order.
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
 * @brief Copies a function pointer's bytes into a `void *`.
 *
 * ISO C leaves function-pointer to object-pointer casts undefined; POSIX guarantees the
 * representations match, so a byte copy is the portable way to build a dlsym() result.
 *
 * @param function_bytes  Address of a function-pointer object; must not be NULL (asserted).
 * @param function_size   Size of that object; must be <= sizeof(void *) (asserted).
 * @return A `void *` with the same bit pattern as the function pointer.
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
 * @brief Yields the `void *` a stub dlsym() returns for @p function.
 *
 * @param type      Function-pointer typedef, e.g. `chaos_net_bind_fn`; a mismatch
 *                  with @p function draws a compiler diagnostic via the compound literal.
 * @param function  Stub to hand back for the requested symbol name.
 */
#define CHAOS_NET_TEST_DLSYM_RESULT(type, function)                                                \
    chaos_net_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
