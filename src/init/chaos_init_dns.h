/**
 * @file chaos_init_dns.h
 * @brief `chaos-init`: libchaos-dns rules applied to a tracee's outgoing queries.
 *
 * @details `getaddrinfo()` is a library function, so SECCOMP mode cannot intercept the
 * lookup itself. What it can see is the query the resolver sends, and that carries the
 * name: a send whose payload is a DNS question is matched by the name in it, so
 * `dns://api.example.com:LATENCY:500` delays the resolution of that one name in a static
 * binary -- which is what LD_PRELOAD cannot reach at all.
 *
 * Only `LATENCY` survives the trip. Everything else the library offers changes the
 * *answer* (`GAI`, `REWRITE`, `OVERRIDE`, `SERVICE`, `FILTER_FAMILY`, `SHUFFLE`, `LIMIT`),
 * and the answer is assembled inside the resolver: failing the send would produce some
 * resolution error, not the one the rule names, which is worse than applying nothing.
 * Those rules are rejected with `reason=unsupported in seccomp mode`, as are `rdns://`
 * selectors -- a PTR query carries `in-addr.arpa` labels, not the address the rule names.
 *
 * See chaos_init_dns.c for how a query is recognised.
 */

#ifndef CHAOS_INIT_DNS_H
#define CHAOS_INIT_DNS_H

#include "chaos_init_call.h"

#include <stddef.h>

/**
 * @brief Initialises the dns rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG from getrandom() and registers its per-process slots.
 *        Call once, before the first decision.
 */
void chaos_init_dns_start(void);

/**
 * @brief Decides @p call by the dns rules (`/tmp/.chaos-dns.conf`).
 *
 * @return 1 when the call carries a DNS question a rule matched (and @p verdict is set),
 *         else 0 -- which leaves the call to the other deciders, because the same `sendto`
 *         is net's as well.
 */
int chaos_init_dns_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

/**
 * @brief The system calls the filter has to notify for the loaded rules.
 *
 * @details The sends a resolver uses: `sendto` (glibc and musl over UDP), `sendmmsg`
 * (glibc when it asks for A and AAAA at once), `sendmsg`, and `write` for a query over
 * TCP. Empty while no rule can act on any of them, so a rule file of answer-changing
 * rules costs nothing -- it is rejected anyway.
 *
 * @param out       Receives the system call numbers.
 * @param capacity  Entries @p out holds; a longer set is truncated.
 * @return How many were written.
 */
size_t chaos_init_dns_calls(long *out, size_t capacity);

#endif
