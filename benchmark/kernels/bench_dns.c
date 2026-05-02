/**
 * @file bench_dns.c
 * @brief Stage 3 microbenchmarks for libchaos-dns.
 *
 * @details
 * Three benchmarks exercising `getaddrinfo("localhost", NULL, ...)`,
 * which on glibc and musl resolves entirely from `/etc/hosts` and
 * `/etc/resolv.conf` without any DNS round-trip.  This isolates the
 * chaos-dns library's interception cost from network latency.
 *
 *  1. `getaddrinfo_passthrough`   — no rule loaded.
 *  2. `getaddrinfo_match_no_fire` — probability=0 rule on `dns://\*`.
 *  3. `getaddrinfo_errno`         — probability=1 EAI_AGAIN injection.
 *
 * Iter unconditionally calls `freeaddrinfo` after each `getaddrinfo`
 * (when the call succeeded), keeping the addrinfo allocator state
 * stable across iterations.  Failure modes (the ERRNO benchmark)
 * naturally have no list to free.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct bench_dns_state
{
    int rc;
} bench_dns_state_t;

static void bench_dns_iter_getaddrinfo(void *user_state)
{
    bench_dns_state_t *s = (bench_dns_state_t *)user_state;
    struct addrinfo   *result = NULL;
    struct addrinfo    hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    s->rc = getaddrinfo("localhost", NULL, &hints, &result);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(result);
    if (result != NULL)
    {
        freeaddrinfo(result);
    }
}

CHAOS_BENCH("dns", getaddrinfo_passthrough,   bench_dns_state_t,
            NULL, bench_dns_iter_getaddrinfo, NULL)
CHAOS_BENCH("dns", getaddrinfo_match_no_fire, bench_dns_state_t,
            NULL, bench_dns_iter_getaddrinfo, NULL)
CHAOS_BENCH("dns", getaddrinfo_errno,         bench_dns_state_t,
            NULL, bench_dns_iter_getaddrinfo, NULL)
