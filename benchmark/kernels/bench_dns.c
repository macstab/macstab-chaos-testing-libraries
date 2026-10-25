/**
 * @file bench_dns.c
 * @brief Per-call overhead of the libchaos-dns wrappers for getaddrinfo and getnameinfo.
 *
 * @details
 * Both lookups target the loopback host, so in the benchmark images they are answered
 * from `/etc/hosts` and send no DNS packet. That removes network latency from both
 * arms; what remains is resolver CPU cost plus, under LD_PRELOAD, the wrapper.
 *
 * | Benchmark suffix | Scenario (`dns-<fn>-*.conf`)                  | Path measured          |
 * |------------------|-----------------------------------------------|------------------------|
 * | `_passthrough`   | `dns-empty.conf` (no rules)                   | wrapper, empty rules   |
 * | `_match_no_fire` | EAI_AGAIN, probability 0.0                    | rule match + draw      |
 * | `_errno`         | EAI_AGAIN, probability 1.0                    | effect dispatch only   |
 *
 * getaddrinfo rules use the selector `dns://localhost`. The `_errno` arm returns
 * EAI_AGAIN without calling the real resolver, so its delta is wrapper cost minus the
 * skipped resolver work; in the 1.0.1 matrix it is negative on every variant.
 * `run-bench.sh` caps both lookups at 20000 iterations.
 *
 * Every scenario loads, and every errno scenario fires on each measured call:
 * `run-bench.sh --check-scenarios` proves it, and CI runs that check.
 *
 * The getaddrinfo kernel frees every result list it receives, so allocator state does
 * not grow across iterations; a failed lookup returns no list.
 */

#include "chaos_bench.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
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

/* ------------------------------------------------------------ getnameinfo ---
 * Reverse lookup of 127.0.0.1, port 0. NI_NUMERICSERV formats the port as "0" and
 * skips the services database; the host part is still a real reverse lookup, answered
 * by the 127.0.0.1 entry in `/etc/hosts`. Without that entry glibc moves on to the next
 * nsswitch source (normally a DNS PTR query) and the baseline measures the network.
 */
typedef struct bench_dns_gni_state
{
    struct sockaddr_in addr;
    char               host[NI_MAXHOST];
    char               serv[NI_MAXSERV];
    int                rc;
} bench_dns_gni_state_t;

static void bench_dns_gni_setup(void *user_state)
{
    bench_dns_gni_state_t *s = (bench_dns_gni_state_t *)user_state;
    memset(&s->addr, 0, sizeof(s->addr));
    s->addr.sin_family = AF_INET;
    s->addr.sin_port   = 0;
    s->addr.sin_addr.s_addr = htonl(0x7F000001); /* 127.0.0.1 */
}

static void bench_dns_iter_getnameinfo(void *user_state)
{
    bench_dns_gni_state_t *s = (bench_dns_gni_state_t *)user_state;
    s->rc = getnameinfo((const struct sockaddr *)&s->addr, sizeof(s->addr),
                        s->host, sizeof(s->host),
                        s->serv, sizeof(s->serv),
                        NI_NUMERICSERV);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->host);
}

CHAOS_BENCH("dns", getnameinfo_passthrough,   bench_dns_gni_state_t,
            bench_dns_gni_setup, bench_dns_iter_getnameinfo, NULL)
CHAOS_BENCH("dns", getnameinfo_match_no_fire, bench_dns_gni_state_t,
            bench_dns_gni_setup, bench_dns_iter_getnameinfo, NULL)
CHAOS_BENCH("dns", getnameinfo_errno,         bench_dns_gni_state_t,
            bench_dns_gni_setup, bench_dns_iter_getnameinfo, NULL)
