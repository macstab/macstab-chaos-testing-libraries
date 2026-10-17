/**
 * @file bench_net.c
 * @brief Per-call overhead of the libchaos-net wrappers for socket I/O and lifecycle calls.
 *
 * @details
 * All kernels use AF_UNIX sockets, so no IP stack, routing or NIC is involved and the
 * kernel cost is a buffer copy between two sockets in one process. Every scenario uses
 * the selector `unix://\*`, which matches any AF_UNIX socket.
 *
 * Each hooked call has `_passthrough`, `_match_no_fire` and `_errno` variants with one
 * shared iteration body; `run-bench.sh` runs each without LD_PRELOAD (baseline) and with
 * LD_PRELOAD=libchaos-net.so plus `benchmark/scenarios/net-<fn>-*.conf` copied to the
 * rule file `/tmp/.chaos-net.conf` (treatment).
 *
 * The data-path kernels pair the hooked call with its counterpart (send with recv,
 * recvfrom with send, and so on) inside one timed iteration, so the socket buffer never
 * fills and the timed cost covers both calls. Only the hooked call has a rule, so the
 * baseline/treatment delta is still one wrapper, plus the empty-rule pass through the
 * counterpart's wrapper. Sockets are non-blocking, so a drained buffer returns EAGAIN
 * instead of hanging the run (for example in the `_errno` arm, where nothing was sent).
 *
 * Scenario status at this revision (checked against src/net/chaos_net_config.c):
 * send, recv, socket_close and shutdown are effective; sendto, recvfrom, sendmsg and
 * recvmsg use operation tokens libchaos-net does not accept, so their `_match_no_fire`
 * and `_errno` arms measure the passthrough path.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define BENCH_NET_PAYLOAD_BYTES 64

typedef struct bench_net_state
{
    int     sv[2];
    char    payload[BENCH_NET_PAYLOAD_BYTES];
    char    drain[BENCH_NET_PAYLOAD_BYTES];
    ssize_t rc_send;
    ssize_t rc_recv;
} bench_net_state_t;

static void bench_net_setup(void *user_state)
{
    bench_net_state_t *s = (bench_net_state_t *)user_state;
    int flags;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s->sv) != 0)
    {
        perror("bench_net: socketpair");
        abort();
    }
    /* Non-blocking on both ends: when a send is suppressed (`_errno` arm) the paired
     * recv must return EAGAIN instead of blocking the single-threaded run forever. */
    for (int i = 0; i < 2; ++i)
    {
        flags = fcntl(s->sv[i], F_GETFL, 0);
        if (flags < 0 || fcntl(s->sv[i], F_SETFL, flags | O_NONBLOCK) < 0)
        {
            perror("bench_net: fcntl");
            abort();
        }
    }
    memset(s->payload, 0xC3, sizeof(s->payload));
}

static void bench_net_iter_send(void *user_state)
{
    bench_net_state_t *s = (bench_net_state_t *)user_state;
    s->rc_send = send(s->sv[0], s->payload, sizeof(s->payload), 0);
    s->rc_recv = recv(s->sv[1], s->drain, sizeof(s->drain), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_send);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_recv);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->drain);
}

static void bench_net_teardown(void *user_state)
{
    bench_net_state_t *s = (bench_net_state_t *)user_state;
    if (s->sv[0] >= 0) (void)close(s->sv[0]);
    if (s->sv[1] >= 0) (void)close(s->sv[1]);
}

CHAOS_BENCH("net", send_passthrough,   bench_net_state_t,
            bench_net_setup, bench_net_iter_send, bench_net_teardown)
CHAOS_BENCH("net", send_match_no_fire, bench_net_state_t,
            bench_net_setup, bench_net_iter_send, bench_net_teardown)
CHAOS_BENCH("net", send_errno,         bench_net_state_t,
            bench_net_setup, bench_net_iter_send, bench_net_teardown)

/* ------------------------------------------------------------------ recv ---
 * `recv` on an empty non-blocking AF_UNIX datagram socket: every baseline call returns
 * -1/EAGAIN at once, so the iteration measures the wrapper and the syscall entry
 * without data movement. The `_errno` scenario injects the same EAGAIN.
 */
typedef struct bench_net_drain_state
{
    int     sv[2];
    char    drain[BENCH_NET_PAYLOAD_BYTES];
    ssize_t rc;
} bench_net_drain_state_t;

static void bench_net_drain_setup(void *user_state)
{
    bench_net_drain_state_t *s = (bench_net_drain_state_t *)user_state;
    int flags;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, s->sv) != 0) {
        perror("bench_net: socketpair drain"); abort();
    }
    for (int i = 0; i < 2; ++i) {
        flags = fcntl(s->sv[i], F_GETFL, 0);
        (void)fcntl(s->sv[i], F_SETFL, flags | O_NONBLOCK);
    }
}

static void bench_net_drain_teardown(void *user_state)
{
    bench_net_drain_state_t *s = (bench_net_drain_state_t *)user_state;
    if (s->sv[0] >= 0) (void)close(s->sv[0]);
    if (s->sv[1] >= 0) (void)close(s->sv[1]);
}

static void bench_net_iter_recv(void *user_state)
{
    bench_net_drain_state_t *s = (bench_net_drain_state_t *)user_state;
    s->rc = recv(s->sv[0], s->drain, sizeof(s->drain), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->drain);
}

CHAOS_BENCH("net", recv_passthrough,    bench_net_drain_state_t,
            bench_net_drain_setup, bench_net_iter_recv, bench_net_drain_teardown)
CHAOS_BENCH("net", recv_match_no_fire,  bench_net_drain_state_t,
            bench_net_drain_setup, bench_net_iter_recv, bench_net_drain_teardown)
CHAOS_BENCH("net", recv_errno,          bench_net_drain_state_t,
            bench_net_drain_setup, bench_net_iter_recv, bench_net_drain_teardown)

/* --------------------------------------------------- sendto / recvfrom ---
 * Same connected AF_UNIX stream socketpair as the send kernel. sendto passes a NULL
 * address (valid on a connected socket) and recvfrom a NULL address buffer, so only
 * the entry point differs from send/recv.
 */
static void bench_net_iter_sendto(void *user_state)
{
    bench_net_state_t *s = (bench_net_state_t *)user_state;
    s->rc_send = sendto(s->sv[0], s->payload, sizeof(s->payload), 0, NULL, 0);
    s->rc_recv = recv(s->sv[1], s->drain, sizeof(s->drain), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_send);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_recv);
}

static void bench_net_iter_recvfrom(void *user_state)
{
    bench_net_state_t *s = (bench_net_state_t *)user_state;
    s->rc_send = send(s->sv[0], s->payload, sizeof(s->payload), 0);
    s->rc_recv = recvfrom(s->sv[1], s->drain, sizeof(s->drain), 0, NULL, NULL);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_send);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_recv);
}

CHAOS_BENCH("net", sendto_passthrough,   bench_net_state_t,
            bench_net_setup, bench_net_iter_sendto, bench_net_teardown)
CHAOS_BENCH("net", sendto_match_no_fire, bench_net_state_t,
            bench_net_setup, bench_net_iter_sendto, bench_net_teardown)
CHAOS_BENCH("net", sendto_errno,         bench_net_state_t,
            bench_net_setup, bench_net_iter_sendto, bench_net_teardown)

CHAOS_BENCH("net", recvfrom_passthrough,   bench_net_state_t,
            bench_net_setup, bench_net_iter_recvfrom, bench_net_teardown)
CHAOS_BENCH("net", recvfrom_match_no_fire, bench_net_state_t,
            bench_net_setup, bench_net_iter_recvfrom, bench_net_teardown)
CHAOS_BENCH("net", recvfrom_errno,         bench_net_state_t,
            bench_net_setup, bench_net_iter_recvfrom, bench_net_teardown)

/* --------------------------------------------------- sendmsg / recvmsg ---
 * One-iovec msghdr over an AF_UNIX stream socketpair, prepared once in setup so the
 * iteration does not rebuild it. No control messages.
 */
typedef struct bench_net_msg_state
{
    int           sv[2];
    char          payload[BENCH_NET_PAYLOAD_BYTES];
    char          drain[BENCH_NET_PAYLOAD_BYTES];
    struct iovec  iov_send;
    struct iovec  iov_recv;
    struct msghdr msg_send;
    struct msghdr msg_recv;
    ssize_t       rc_send;
    ssize_t       rc_recv;
} bench_net_msg_state_t;

static void bench_net_msg_setup(void *user_state)
{
    bench_net_msg_state_t *s = (bench_net_msg_state_t *)user_state;
    int flags;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s->sv) != 0) {
        perror("bench_net: msg socketpair"); abort();
    }
    for (int i = 0; i < 2; ++i) {
        flags = fcntl(s->sv[i], F_GETFL, 0);
        (void)fcntl(s->sv[i], F_SETFL, flags | O_NONBLOCK);
    }
    memset(s->payload, 0xC3, sizeof(s->payload));
    s->iov_send.iov_base = s->payload; s->iov_send.iov_len = sizeof(s->payload);
    s->iov_recv.iov_base = s->drain;   s->iov_recv.iov_len = sizeof(s->drain);
    memset(&s->msg_send, 0, sizeof(s->msg_send));
    memset(&s->msg_recv, 0, sizeof(s->msg_recv));
    s->msg_send.msg_iov = &s->iov_send; s->msg_send.msg_iovlen = 1;
    s->msg_recv.msg_iov = &s->iov_recv; s->msg_recv.msg_iovlen = 1;
}

static void bench_net_msg_teardown(void *user_state)
{
    bench_net_msg_state_t *s = (bench_net_msg_state_t *)user_state;
    if (s->sv[0] >= 0) (void)close(s->sv[0]);
    if (s->sv[1] >= 0) (void)close(s->sv[1]);
}

static void bench_net_iter_sendmsg(void *user_state)
{
    bench_net_msg_state_t *s = (bench_net_msg_state_t *)user_state;
    s->rc_send = sendmsg(s->sv[0], &s->msg_send, 0);
    s->rc_recv = recv(s->sv[1], s->drain, sizeof(s->drain), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_send);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_recv);
}

static void bench_net_iter_recvmsg(void *user_state)
{
    bench_net_msg_state_t *s = (bench_net_msg_state_t *)user_state;
    s->rc_send = send(s->sv[0], s->payload, sizeof(s->payload), 0);
    s->rc_recv = recvmsg(s->sv[1], &s->msg_recv, 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_send);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc_recv);
}

CHAOS_BENCH("net", sendmsg_passthrough,   bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_sendmsg, bench_net_msg_teardown)
CHAOS_BENCH("net", sendmsg_match_no_fire, bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_sendmsg, bench_net_msg_teardown)
CHAOS_BENCH("net", sendmsg_errno,         bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_sendmsg, bench_net_msg_teardown)

CHAOS_BENCH("net", recvmsg_passthrough,   bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_recvmsg, bench_net_msg_teardown)
CHAOS_BENCH("net", recvmsg_match_no_fire, bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_recvmsg, bench_net_msg_teardown)
CHAOS_BENCH("net", recvmsg_errno,         bench_net_msg_state_t,
            bench_net_msg_setup, bench_net_iter_recvmsg, bench_net_msg_teardown)

/* ------------------------------------------------------- socket / shutdown ---
 * `socket(AF_UNIX, SOCK_DGRAM)` followed by `close`; the shutdown kernel inserts
 * `shutdown(SHUT_RDWR)` on the unconnected socket between them. All three calls are
 * wrapped. Both kernels are capped at 20000 iterations. In the socket `_errno` arm
 * socket fails with EMFILE and close is skipped.
 */
typedef struct bench_net_sock_state
{
    int fd;
} bench_net_sock_state_t;

static void bench_net_iter_socket_close(void *user_state)
{
    bench_net_sock_state_t *s = (bench_net_sock_state_t *)user_state;
    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->fd);
    if (s->fd >= 0) (void)close(s->fd);
}

static void bench_net_iter_shutdown(void *user_state)
{
    bench_net_sock_state_t *s = (bench_net_sock_state_t *)user_state;
    s->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s->fd >= 0) {
        (void)shutdown(s->fd, SHUT_RDWR);
        (void)close(s->fd);
    }
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->fd);
}

CHAOS_BENCH("net", socket_close_passthrough,   bench_net_sock_state_t,
            NULL, bench_net_iter_socket_close, NULL)
CHAOS_BENCH("net", socket_close_match_no_fire, bench_net_sock_state_t,
            NULL, bench_net_iter_socket_close, NULL)
CHAOS_BENCH("net", socket_close_errno,         bench_net_sock_state_t,
            NULL, bench_net_iter_socket_close, NULL)

CHAOS_BENCH("net", shutdown_passthrough,   bench_net_sock_state_t,
            NULL, bench_net_iter_shutdown, NULL)
CHAOS_BENCH("net", shutdown_match_no_fire, bench_net_sock_state_t,
            NULL, bench_net_iter_shutdown, NULL)
CHAOS_BENCH("net", shutdown_errno,         bench_net_sock_state_t,
            NULL, bench_net_iter_shutdown, NULL)
