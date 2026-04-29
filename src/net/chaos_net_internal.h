#ifndef CHAOS_NET_INTERNAL_H
#define CHAOS_NET_INTERNAL_H

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CHAOS_NET_CONFIG_PATH "/tmp/.chaos-net.conf"
#define CHAOS_NET_MAX_RULES 256U
#define CHAOS_NET_MAX_LINE_LENGTH 1024U
#define CHAOS_NET_MAX_CONFIG_BYTES (CHAOS_NET_MAX_RULES * CHAOS_NET_MAX_LINE_LENGTH)
#define CHAOS_NET_MAX_TEXT 256U

#define CHAOS_NET_EXPORT __attribute__((visibility("default")))

#define CHAOS_NET_MTIME_MISSING UINT64_C(0)
#define CHAOS_NET_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_NET_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

#if defined(__GLIBC__)
#define CHAOS_NET_CONST_SOCKADDR_PARAM __CONST_SOCKADDR_ARG
#define CHAOS_NET_CONST_SOCKADDR_VALUE(arg) ((arg).__sockaddr__)
#define CHAOS_NET_SOCKADDR_PARAM __SOCKADDR_ARG
#define CHAOS_NET_SOCKADDR_VALUE(arg) ((arg).__sockaddr__)
#define CHAOS_NET_MMSG_FLAGS_TYPE int
#else
#define CHAOS_NET_CONST_SOCKADDR_PARAM const struct sockaddr *
#define CHAOS_NET_CONST_SOCKADDR_VALUE(arg) (arg)
#define CHAOS_NET_SOCKADDR_PARAM struct sockaddr *
#define CHAOS_NET_SOCKADDR_VALUE(arg) (arg)
#define CHAOS_NET_MMSG_FLAGS_TYPE unsigned int
#endif

typedef int (*chaos_net_bind_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*chaos_net_listen_fn)(int, int);
typedef int (*chaos_net_connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*chaos_net_accept_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*chaos_net_socket_fn)(int, int, int);
typedef int (*chaos_net_socketpair_fn)(int, int, int, int[2]);
typedef int (*chaos_net_shutdown_fn)(int, int);
typedef ssize_t (*chaos_net_send_fn)(int, const void *, size_t, int);
typedef ssize_t (*chaos_net_sendto_fn)(
    int, const void *, size_t, int, const struct sockaddr *, socklen_t
);
typedef ssize_t (*chaos_net_sendmsg_fn)(int, const struct msghdr *, int);
typedef ssize_t (*chaos_net_recv_fn)(int, void *, size_t, int);
typedef ssize_t (*chaos_net_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*chaos_net_recvmsg_fn)(int, struct msghdr *, int);
typedef int (*chaos_net_poll_fn)(struct pollfd *, nfds_t, int);
typedef int (*chaos_net_ppoll_fn)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);
typedef int (*chaos_net_select_fn)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
typedef int (*chaos_net_pselect_fn)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);
typedef int (*chaos_net_getsockname_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*chaos_net_getpeername_fn)(int, struct sockaddr *, socklen_t *);
typedef int (*chaos_net_getsockopt_fn)(int, int, int, void *, socklen_t *);
#ifdef __linux__
typedef int (*chaos_net_accept4_fn)(int, struct sockaddr *, socklen_t *, int);
typedef int (*chaos_net_sendmmsg_fn)(
    int, struct mmsghdr *, unsigned int, CHAOS_NET_MMSG_FLAGS_TYPE
);
typedef int (*chaos_net_recvmmsg_fn)(int, struct mmsghdr *, unsigned int, CHAOS_NET_MMSG_FLAGS_TYPE, struct timespec *);
typedef int (*chaos_net_epoll_wait_fn)(int, struct epoll_event *, int, int);
typedef int (*chaos_net_epoll_pwait_fn)(int, struct epoll_event *, int, int, const sigset_t *);
#endif

extern chaos_net_bind_fn g_chaos_net_real_bind;
extern chaos_net_listen_fn g_chaos_net_real_listen;
extern chaos_net_connect_fn g_chaos_net_real_connect;
extern chaos_net_accept_fn g_chaos_net_real_accept;
extern chaos_net_socket_fn g_chaos_net_real_socket;
extern chaos_net_socketpair_fn g_chaos_net_real_socketpair;
extern chaos_net_shutdown_fn g_chaos_net_real_shutdown;
extern chaos_net_send_fn g_chaos_net_real_send;
extern chaos_net_sendto_fn g_chaos_net_real_sendto;
extern chaos_net_sendmsg_fn g_chaos_net_real_sendmsg;
extern chaos_net_recv_fn g_chaos_net_real_recv;
extern chaos_net_recvfrom_fn g_chaos_net_real_recvfrom;
extern chaos_net_recvmsg_fn g_chaos_net_real_recvmsg;
extern chaos_net_poll_fn g_chaos_net_real_poll;
extern chaos_net_ppoll_fn g_chaos_net_real_ppoll;
extern chaos_net_select_fn g_chaos_net_real_select;
extern chaos_net_pselect_fn g_chaos_net_real_pselect;
extern chaos_net_getsockname_fn g_chaos_net_real_getsockname;
extern chaos_net_getpeername_fn g_chaos_net_real_getpeername;
extern chaos_net_getsockopt_fn g_chaos_net_real_getsockopt;
#ifdef __linux__
extern chaos_net_accept4_fn g_chaos_net_real_accept4;
extern chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg;
extern chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg;
extern chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait;
extern chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait;
#endif

extern __thread int g_chaos_net_tls_guard;
extern __thread uint64_t g_chaos_net_tls_prng_state;
extern uint64_t g_chaos_net_process_seed;

static inline int chaos_net_in_internal(void)
{
    return g_chaos_net_tls_guard != 0;
}

static inline int chaos_net_enter_internal(void)
{
    int previous = g_chaos_net_tls_guard;
    g_chaos_net_tls_guard = 1;
    return previous;
}

static inline void chaos_net_leave_internal(int previous)
{
    g_chaos_net_tls_guard = previous;
}

static inline uint64_t chaos_net_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

static inline int
chaos_net_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

static inline uint64_t chaos_net_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static inline uint64_t chaos_net_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static inline void chaos_net_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_net_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_net_process_seed;
    seed ^= chaos_net_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_net_tls_prng_state = chaos_net_prng_mix(seed);
    if (g_chaos_net_tls_prng_state == 0U)
    {
        g_chaos_net_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

static inline void chaos_net_prng_seed_thread(uint64_t seed)
{
    g_chaos_net_tls_prng_state = chaos_net_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

static inline uint32_t chaos_net_prng_next_u32(void)
{
    uint64_t state;

    chaos_net_prng_ensure_seeded();
    state = g_chaos_net_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_net_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
