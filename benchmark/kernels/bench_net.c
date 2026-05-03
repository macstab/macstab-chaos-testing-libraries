/**
 * @file bench_net.c
 * @brief Stage 3 microbenchmarks for libchaos-net.
 *
 * @details
 * Three benchmarks against an `AF_UNIX` socketpair, which avoids any
 * kernel networking stack work and isolates the chaos library overhead.
 * The chaos-net library uses endpoint-based selectors (`unix://\*`,
 * `tcp4://...`) so the AF_UNIX path is the cleanest fixture for
 * measuring the per-call cost without the noise of TCP/UDP framing.
 *
 *  1. `send_passthrough` — 64-byte `send` over the socketpair, no rule.
 *  2. `send_match_no_fire` — same, probability=0 rule loaded.
 *  3. `send_errno` — same, probability=1 ERRNO rule (synthetic EHOSTUNREACH).
 *
 * Setup creates the socketpair, sets both ends non-blocking, and pre-
 * touches the receive end's buffer so subsequent receives are cheap.
 * Iter sends and immediately drains.  The drain is *outside* the
 * timed call sequence (the iter only times the send; the recv is
 * implicit in iter wraparound).  In practice we drain inside the iter
 * so the socket buffer never fills — the cost we record covers
 * `send + recv` together but the chaos rule selector targets `send`
 * only, isolating the metric we care about.
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
    /* Non-blocking on both ends so a stuck recv never deadlocks the
     * benchmark (e.g. if a chaos LATENCY rule causes a stall). */
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
 * `recv` on a non-blocking AF_UNIX socket with no pending data: returns
 * -1/EAGAIN immediately.  Times the chaos hook + libc + kernel fast-path,
 * without depending on data movement.
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
 * `sendto` to a self-bound UDP loopback socket; `recvfrom` reads back.
 * Pair of non-blocking socketpair-style setups, but using SOCK_DGRAM so
 * sendto/recvfrom are the natural API.
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
 * Per-iter `socket(AF_UNIX)` + `close`.  Pairs the cheapest socket-creation
 * call with close.  `shutdown` adds a single extra hooked syscall per iter.
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
