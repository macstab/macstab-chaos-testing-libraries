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
