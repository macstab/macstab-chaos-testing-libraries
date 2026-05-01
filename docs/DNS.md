<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# libchaos-dns Technical Reference

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

`libchaos-dns` is the dedicated resolver-chaos preload library in this
repository. Repository-wide ownership rules live in
[`docs/SYSTEM.md`](SYSTEM.md).

Current implementation status:

- shipped and tested on glibc/musl and amd64/arm64
- exact interposed symbols today: `getaddrinfo()` and `getnameinfo()`
- config path: `/tmp/.chaos-dns.conf`
- enforced source-line coverage gate enabled for shipped `src/dns/*.c`
  with `100.00%` on `chaos_dns_actions.c` and `chaos_dns.c`, and a minimum
  `85.00%` floor on `chaos_dns_config.c` and `chaos_dns_lookup.c`

Current rule grammar:

```text
<selector>:<effect>:<value>
```

Supported selectors:

- forward lookup:
  `*`, `dns://*`, `dns://<name>`, `dns://*.<suffix>`
- reverse lookup:
  `rdns://<ipv4>`, `rdns://[<ipv6>]`, `rdns://*`

Implemented effects:

- forward `getaddrinfo()` effects:
  `EAI_AGAIN`, `EAI_FAIL`, `EAI_NONAME`, `EAI_MEMORY`, `EAI_SYSTEM`,
  `LATENCY`, `REWRITE`, `SERVICE`, `OVERRIDE`, `FILTER_FAMILY`, `LIMIT`,
  `SHUFFLE`
- reverse `getnameinfo()` effects:
  `EAI_AGAIN`, `EAI_FAIL`, `EAI_NONAME`, `EAI_MEMORY`, `EAI_SYSTEM`,
  `LATENCY`, `REWRITE`, `SERVICE`

Important current boundaries:

- `libchaos-dns` owns resolver interposition; `libchaos-net` no longer owns
  `getaddrinfo()`
- reverse lookup is implemented through `getnameinfo()` and uses `rdns://...`
  selectors keyed by numeric address text
- reverse lookup does not support `OVERRIDE`, `FILTER_FAMILY`, `LIMIT`, or
  `SHUFFLE`
- legacy resolver entry points such as `gethostbyname*()`, `gethostbyaddr*()`,
  and `res_*()` are not interposed yet
- multiple different effect kinds can compose on the same query
- post-resolution transforms for `getaddrinfo()` run in this order:
  `FILTER_FAMILY`, `SHUFFLE`, then `LIMIT`
- post-success output rewrites for `getnameinfo()` apply `REWRITE` to the host
  buffer and `SERVICE` to the service buffer

---

## Table of Contents

1. [Execution Boundary](#execution-boundary)
2. [What The Wrapper Actually Reads](#what-the-wrapper-actually-reads)
3. [What Libc Still Owns](#what-libc-still-owns)
4. [Forward Lookup Semantics](#forward-lookup-semantics)
5. [Reverse Lookup Semantics](#reverse-lookup-semantics)
6. [Why Reverse Lookup Does Not Support Certain Effects](#why-reverse-lookup-does-not-support-certain-effects)
7. [What This Library Can Do Today](#what-this-library-can-do-today)
8. [What This Library Deliberately Does Not Do](#what-this-library-deliberately-does-not-do)
9. [Data Model](#data-model)
10. [Post-Resolution Transform Pipeline](#post-resolution-transform-pipeline)
11. [Per-Hook Call Flows](#per-hook-call-flows)
12. [Reentrancy Guard and TLS State](#reentrancy-guard-and-tls-state)
13. [PRNG Model](#prng-model)
14. [Config Reload Protocol — Two-Snapshot CAS](#config-reload-protocol--two-snapshot-cas)
15. [glibc vs musl Divergence](#glibc-vs-musl-divergence)
16. [NSS Plumbing and the nsswitch.conf Stack](#nss-plumbing-and-the-nsswitchconf-stack)
17. [Legacy Resolver API Non-Coverage — res_*(), gethostbyname](#legacy-resolver-api-non-coverage----res_-gethostbyname)
18. [Execution Boundary Summary](#execution-boundary-summary)

---

## Execution Boundary

`libchaos-dns` is a libc-boundary interposer, not a DNS packet engine.

That means:

- it sees the process call `getaddrinfo()` and `getnameinfo()`
- it can read and rewrite the arguments passed to those calls
- it can decide to fail, delay, pass through, or post-process results
- it does not parse or emit raw DNS packets
- it does not see DNS transaction IDs, flags, TTLs, RRsets, nameserver retry
  logic, or packet ordering

The practical consequence is important:

- forward chaos is defined in terms of the `getaddrinfo()` contract:
  query name in, `struct addrinfo` list out
- reverse chaos is defined in terms of the `getnameinfo()` contract:
  one `sockaddr` in, host/service text out

Anything below that boundary still belongs to libc, NSS, and the operating
system resolver stack.

## What The Wrapper Actually Reads

### Forward lookup

On `getaddrinfo(node, service, hints, result)` the wrapper reasons about:

- the query name string
- the service string
- the hints passed by the caller
- the returned `struct addrinfo` linked list

The wrapper can therefore:

- fail or delay before real resolution
- rewrite the name or service before real resolution
- synthesize a replacement `addrinfo` list
- mutate the returned list after real resolution

### Reverse lookup

On `getnameinfo(address, address_len, host, host_len, service, service_len,
flags)` the wrapper reasons about:

- the raw `sockaddr`
- the address family
- the host output buffer
- the service output buffer

For reverse rule selection, the wrapper does not build an `in-addr.arpa` or
`ip6.arpa` query itself. Instead, it extracts the numeric address bytes from
the caller's `sockaddr` and canonicalizes them with `inet_ntop()`.

Current reverse selector derivation:

- `AF_INET`
  Read `sin_addr` from `struct sockaddr_in` and turn the 4-byte IPv4 address
  into text such as `127.0.0.1`
- `AF_INET6`
  Read `sin6_addr` from `struct sockaddr_in6` and turn the 16-byte IPv6
  address into text such as `::1`

If the input is not a valid IPv4/IPv6 `sockaddr`, the wrapper fails open and
passes directly to the real libc `getnameinfo()`.

## What Libc Still Owns

When the wrapper passes through, libc and the resolver stack still decide:

- whether a reverse lookup consults `/etc/hosts`, DNS, mDNS, or another NSS
  source
- whether a PTR query is actually sent
- how the PTR owner name is constructed
- which nameserver is queried
- how retries, timeouts, and failover behave
- how multiple PTR answers are collapsed into the final host string
- how service names are mapped from ports and flags

So the wrapper is intentionally process-contract-focused rather than
protocol-engine-focused.

## Forward Lookup Semantics

The forward path is the richer one because `getaddrinfo()` exposes a result
list to the caller.

Forward path capabilities:

1. Match rules against the query name using `*`, `dns://<name>`, or
   `dns://*.<suffix>`
2. Inject `LATENCY`
3. Inject `EAI_*`
4. Rewrite the hostname with `REWRITE`
5. Rewrite the service string with `SERVICE`
6. Replace real resolution entirely with `OVERRIDE`
7. Post-process the resulting `struct addrinfo` list with:
   `FILTER_FAMILY`, `SHUFFLE`, `LIMIT`

The post-processing step exists because the forward output is a linked list of
address candidates. That gives the library a concrete thing to transform after
resolution.

## Reverse Lookup Semantics

The reverse path is narrower because `getnameinfo()` does not return an address
list. It returns only:

- one host text result
- one service text result

Reverse path capabilities:

1. Match rules against the numeric address using `rdns://<ipv4>`,
   `rdns://[<ipv6>]`, or `rdns://*`
2. Inject `LATENCY`
3. Inject `EAI_*`
4. Call the real libc `getnameinfo()`
5. If libc succeeds, overwrite the returned host text with `REWRITE`
6. If libc succeeds, overwrite the returned service text with `SERVICE`

This is why the reverse path supports exactly:

- `EAI_*`
- `LATENCY`
- `REWRITE`
- `SERVICE`

That restriction is deliberate and enforced during config parsing.

## Why Reverse Lookup Does Not Support Certain Effects

### `OVERRIDE`

`OVERRIDE` means "fabricate a synthetic answer set instead of using the real
resolver."

That makes sense for `getaddrinfo()` because the forward API returns addresses.
The wrapper can build a synthetic `struct addrinfo` list and hand it to the
caller.

It does not add meaningful value for `getnameinfo()` because reverse lookup at
this boundary already returns only text:

- host text
- service text

If the goal is to replace the returned host or service, reverse lookup already
has precise primitives for that:

- `REWRITE` for host text
- `SERVICE` for service text

So reverse `OVERRIDE` would either:

- duplicate existing behavior under a confusing second name, or
- require invented semantics that do not match the actual `getnameinfo()`
  contract

### `FILTER_FAMILY`

`FILTER_FAMILY` only makes sense when there are multiple result entries tagged
with different families such as `AF_INET` and `AF_INET6`.

That is true for `getaddrinfo()`, because its result is a linked list of
`struct addrinfo` nodes and each node carries an `ai_family`.

That is not true for `getnameinfo()`:

- the caller already supplies exactly one concrete `sockaddr`
- that input already has one fixed family
- the output is only text, not a family-tagged answer list

There is nothing to filter after the reverse lookup returns. The input family
is already fixed before the call.

### `LIMIT`

`LIMIT` only makes sense when there is a visible result collection that can be
truncated.

That exists on `getaddrinfo()` because the caller receives a linked list of
addresses.

It does not exist on `getnameinfo()` because the caller receives only one
host/service pair. Even if the lower resolver considered multiple PTR records,
that multiplicity is already hidden inside libc by the time the wrapper gets
the final result.

So reverse `LIMIT` would collapse into one of two bad meanings:

- `LIMIT 1`
  A no-op, because one result pair already comes back
- `LIMIT 0`
  An indirect way to force failure, which is already handled more clearly by
  `EAI_*`

### `SHUFFLE`

`SHUFFLE` only makes sense when the caller can observe the order of multiple
results.

That is true for `getaddrinfo()`, where callers often iterate the returned
address list in order.

It is not true for `getnameinfo()`:

- the wrapper never receives an ordered list of reverse answers
- the wrapper receives only the final host string and service string

Any lower-level ordering among PTR records is hidden behind libc/NSS. At this
boundary there is nothing left to shuffle.

## What This Library Can Do Today

Forward lookup through `getaddrinfo()`:

- return synthetic `EAI_*` failures
- add latency before resolution
- rewrite the queried hostname
- rewrite the queried service string
- synthesize numeric address answers
- filter returned answers to IPv4 or IPv6
- shuffle returned answer order
- limit returned answer count

Reverse lookup through `getnameinfo()`:

- return synthetic `EAI_*` failures
- add latency before reverse resolution
- rewrite the returned host text
- rewrite the returned service text

## What This Library Deliberately Does Not Do

This library does not currently:

- own legacy resolver APIs such as `gethostbyname*()`, `gethostbyaddr*()`, or
  `res_*()`
- parse DNS headers or packet payloads
- rewrite TTLs, RCODEs, or RRsets on the wire
- control nameserver retry order or transport fallback
- expose packet-level PTR-answer ordering to the caller

If that lower-layer behavior is needed, it belongs below this libc boundary:

- a real DNS proxy
- a resolver implementation
- NSS/backend ownership
- or lower-level resolver interposition

---

## Data Model

### struct addrinfo field layout

`getaddrinfo(3)` returns a singly-linked list of `struct addrinfo` nodes
defined in `<netdb.h>`. The library reads and manipulates specific fields from
each node.

```c
struct addrinfo {
    int              ai_flags;      /* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST, … */
    int              ai_family;     /* AF_INET, AF_INET6, AF_UNSPEC                */
    int              ai_socktype;   /* SOCK_STREAM, SOCK_DGRAM, …                  */
    int              ai_protocol;   /* IPPROTO_TCP, IPPROTO_UDP, …                 */
    socklen_t        ai_addrlen;    /* byte length of ai_addr                      */
    struct sockaddr *ai_addr;       /* the resolved socket address                 */
    char            *ai_canonname; /* canonical name of the host (if requested)   */
    struct addrinfo *ai_next;       /* next node in the list, or NULL              */
};
```

Fields and their role in library result processing:

- `ai_family` — the only field the library uses to decide which nodes to retain
  during FILTER_FAMILY. Values are `AF_INET` (2) and `AF_INET6` (10) on Linux.
- `ai_next` — the pointer the library rewires during SHUFFLE (Fisher-Yates
  relinking) and NULLs during FILTER_FAMILY node isolation and LIMIT tail
  detachment.
- `ai_flags`, `ai_socktype`, `ai_protocol`, `ai_addrlen`, `ai_addr`,
  `ai_canonname` — not modified by any transform. Their values are preserved
  verbatim through the entire pipeline.

### addrinfo list ownership model

After a successful `getaddrinfo()` call returns, all nodes in the linked list
are allocated by the real libc allocator. The application owns the list and
must free it with `freeaddrinfo()`. The library does not allocate new `addrinfo`
nodes itself in any ordinary path.

One exception applies to the OVERRIDE path, covered in the next section.

The transform functions FILTER_FAMILY and LIMIT free nodes by calling
`g_chaos_dns_real_freeaddrinfo` — the cached pointer to the real libc
`freeaddrinfo`, resolved at constructor time via `dlsym(RTLD_NEXT,
"freeaddrinfo")`. Using the real symbol rather than the interposed entry point
avoids re-entering the library's own reentrancy guard path during node
disposal.

SHUFFLE rewires `ai_next` pointers only. It does not allocate or free any
`addrinfo` node. The only allocation SHUFFLE makes is a temporary
`struct addrinfo *[]` pointer array on the heap (via `calloc`), which is freed
before the function returns. If that allocation fails, SHUFFLE returns
without modifying the list: the caller still has a valid list in its original
OS-determined order.

After all transforms complete, the surviving nodes in `*result` were allocated
by the real `getaddrinfo` and can be freed normally by the application's
`freeaddrinfo()` call. The library does not need to interpose `freeaddrinfo`
to handle the surviving list correctly. The interposed `freeaddrinfo` entry
point, if present, simply passes through to the real implementation because
the reentrancy guard is not set from application code.

### OVERRIDE address encoding

When a rule specifies `OVERRIDE:1.2.3.4` (or a comma-delimited list such as
`OVERRIDE:1.2.3.4,[::1]`), the library does not construct an `addrinfo` node
by hand. Instead, for each IP literal in the list it calls:

```c
hints_copy.ai_flags |= AI_NUMERICHOST;
rc = chaos_dns_call_real_getaddrinfo(host_literal, service, &hints_copy, &partial);
```

`AI_NUMERICHOST` instructs the resolver to treat the first argument as a
numeric IP address string and perform no DNS lookup. The real `getaddrinfo`
allocates the returned nodes using its own allocator, exactly as it would for a
normal resolution. The library concatenates the per-literal result lists into a
single combined list.

Because every node in the combined list was allocated by the real `getaddrinfo`,
post-resolution transforms (FILTER_FAMILY, LIMIT) can call
`g_chaos_dns_real_freeaddrinfo` on them safely. The application's eventual
`freeaddrinfo` call works correctly without any special casing: the node
allocator and the deallocator are matched.

IPv6 literals in OVERRIDE rule text use square-bracket notation
(`[::1]`, `[2001:db8::1]`) to make the comma-delimited token boundary
unambiguous. The library strips the brackets before passing the address to
`getaddrinfo`. IPv4 addresses and unbracketed bare IPv6 addresses are passed
verbatim.

### FILTER_FAMILY node isolation pattern

When FILTER_FAMILY removes a node from the linked list, the node must be freed
without causing `freeaddrinfo` to walk the rest of the surviving list. The
isolation pattern is:

```c
/* Detach the node from the chain before freeing it. */
current->ai_next = NULL;
g_chaos_dns_real_freeaddrinfo(current);
```

Setting `ai_next = NULL` before calling `freeaddrinfo` is essential.
`freeaddrinfo` is documented to free all nodes reachable via `ai_next`. If the
`ai_next` pointer still pointed at the next surviving node, freeing the rejected
node would also free every subsequent node — a double-free or use-after-free for
all surviving nodes that followed. The isolation pattern transfers ownership of
exactly one node to `freeaddrinfo` and preserves the rest of the chain.

The head pointer `*result` is updated to skip over rejected nodes, and the
`ai_next` of the preceding surviving node is rewired to skip over the gap.

### Why freeaddrinfo interception is not required

Three properties together make `freeaddrinfo` interception unnecessary:

1. Every node the application receives in `*result` was allocated by the real
   `getaddrinfo` (either via a genuine resolution call or via the OVERRIDE path
   which also calls the real `getaddrinfo` with `AI_NUMERICHOST`). The
   application's eventual `freeaddrinfo` call uses the same allocator that
   created the nodes.

2. FILTER_FAMILY and LIMIT remove nodes from the list before the application
   ever sees them. The application's `freeaddrinfo` only frees the surviving
   nodes, which it received directly.

3. SHUFFLE only rewires `ai_next` pointers. The set of nodes is unchanged; only
   their traversal order changes. `freeaddrinfo` on the shuffled list walks all
   nodes in their new order and frees them, which is equivalent to freeing them
   in their original order.

There is therefore no scenario where the application's `freeaddrinfo` call would
need to know that the library was involved.

---

## Post-Resolution Transform Pipeline

After `getaddrinfo()` returns a result list (either from real resolution or from
the OVERRIDE path), three optional transforms are applied in a fixed sequence.
Each transform operates on the list produced by the previous step. All three
use `g_chaos_dns_real_freeaddrinfo` for node disposal so that freed nodes are
returned to the allocator that created them.

### FILTER_FAMILY

FILTER_FAMILY removes all `addrinfo` nodes whose `ai_family` does not match the
configured target family. The target is one of:

- `CHAOS_DNS_FAMILY_INET4` — retain `AF_INET` nodes, free all `AF_INET6` nodes
- `CHAOS_DNS_FAMILY_INET6` — retain `AF_INET6` nodes, free all `AF_INET` nodes
- `CHAOS_DNS_FAMILY_ANY` — retain all nodes (no-op; function returns immediately)

The traversal maintains three state pointers: the current node being examined,
the previous surviving node (whose `ai_next` must be updated when a node is
rejected), and the updated head pointer. For each rejected node:

1. The previous surviving node's `ai_next` is set to `current->ai_next` (skip
   over the rejected node).
2. `current->ai_next` is set to `NULL` (isolation, as described in the data
   model section).
3. `g_chaos_dns_real_freeaddrinfo(current)` is called.

The function returns non-zero if at least one node survives. If all nodes are
filtered out, the return is zero. The `getaddrinfo` interposer checks this
return value and returns `EAI_NONAME` to the application if the list becomes
empty — the same error code a real resolver would return for a genuinely empty
result.

### SHUFFLE

SHUFFLE implements an in-place Fisher-Yates (Knuth) shuffle on the linked list.
The algorithm requires random-access indexing, which a singly-linked list does
not natively support. The implementation uses a two-phase approach:

Phase 1 — collect:

```c
struct addrinfo **nodes = calloc(n, sizeof(struct addrinfo *));
/* fill nodes[0..n-1] with pointers to each node in order */
```

Phase 2 — shuffle and relink:

```c
for (size_t i = n - 1; i >= 1; i--) {
    size_t j = chaos_dns_prng_next_u32() % (i + 1);
    /* swap nodes[i] and nodes[j] */
}
/* relink: nodes[0]->ai_next = nodes[1]; nodes[1]->ai_next = nodes[2]; … */
nodes[n-1]->ai_next = NULL;
*result = nodes[0];
free(nodes);
```

Each swap step draws one 32-bit value from the per-thread PRNG. The modulo is
taken over `(i + 1)` which is at most the list length. The maximum supported
list length for shuffle purposes is bounded by `CHAOS_DNS_MAX_RULES` (256); in
practice resolver results rarely exceed a handful of nodes.

If the `calloc` for the pointer array fails, the function returns without
modifying the list. The application still receives a valid list in its original
OS-determined order. This is the fail-open policy: an allocation failure inside
the library never causes the application to lose a valid resolver result.

SHUFFLE does not free or allocate any `addrinfo` nodes. The only memory
managed is the temporary pointer array.

### LIMIT

LIMIT truncates the list to at most N surviving nodes. The implementation
traverses the list counting nodes. When the count reaches N, the remainder
starting from `current->ai_next` is detached:

```c
struct addrinfo *tail = current->ai_next;
current->ai_next = NULL;     /* terminate the surviving prefix */
if (tail != NULL) {
    g_chaos_dns_real_freeaddrinfo(tail);  /* free the entire tail in one call */
}
```

The tail is freed in a single `freeaddrinfo` call on the tail's head node.
Because `ai_next` chains within the tail are intact, `freeaddrinfo` walks the
entire tail and frees all its nodes. There is no need to isolate individual
tail nodes: none of them appear in the surviving prefix and none will be touched
again.

If the limit is zero, the entire list is freed and `*result` is set to `NULL`.
The `getaddrinfo` interposer then returns `EAI_NONAME`.

If the list already has fewer than N nodes, the function is a no-op.

### Why FILTER → SHUFFLE → LIMIT

The order is not arbitrary. Each position has a specific rationale grounded in
correctness and semantic clarity.

**FILTER first.** FILTER removes nodes of the wrong family. If SHUFFLE ran
before FILTER, the shuffle would operate on a set that includes nodes destined
for removal. Those PRNG draws would be wasted and the effective shuffle would
cover only the post-filter subset — but drawn from a different permutation
sequence than the one the caller observes. More importantly, if LIMIT ran before
FILTER, LIMIT might truncate to N nodes of mixed family; the subsequent filter
could reduce the count below N, potentially to zero, which makes the LIMIT
semantics surprising. Filtering first ensures SHUFFLE and LIMIT always operate
on exactly the set that will be returned.

**SHUFFLE before LIMIT.** If LIMIT applied first, it would keep only the first
N entries in the OS-determined order — the ordering the resolver happened to
return. SHUFFLE before LIMIT means LIMIT selects N entries from a randomised
ordering, providing uniform coverage over the full result set across repeated
calls. This matches the fault-injection intent: exposing the application to
different address subsets on successive lookups.

### Empty-result handling

If FILTER_FAMILY removes all nodes from the list, `chaos_dns_filter_result_list`
returns zero (the list-non-empty predicate is false). The `getaddrinfo`
interposer checks this return value immediately after calling the filter and
returns `EAI_NONAME` to the application. The application never receives a
non-NULL `*result` pointing to an empty chain.

If LIMIT is configured with `limit = 0`, the entire list is freed and
`*result` is set to `NULL`. The interposer returns `EAI_NONAME` in this case
as well.

---

## Per-Hook Call Flows

### 11.1 getaddrinfo()

The numbered steps correspond directly to the implementation in
`src/dns/chaos_dns_lookup.c`.

1. Enter the interposed `getaddrinfo` wrapper. Check `chaos_dns_in_internal()`.
   If the reentrancy guard is set, or if `node` is NULL or empty, call
   `chaos_dns_call_real_getaddrinfo` and return its result directly — no chaos
   applied.

2. Look up a LATENCY rule for `node` via `chaos_dns_config_match`. If a rule
   matches and `chaos_dns_rule_should_trigger` returns non-zero, call
   `chaos_dns_rule_apply_latency`. The sleep occurs regardless of whether a
   GAI or OVERRIDE rule subsequently fires — LATENCY models network delay that
   happens before the outcome is known.

3. Look up a GAI rule for `node`. If a rule matches and
   `chaos_dns_rule_apply_gai` fires (probability check passes), restore the
   reentrancy guard and return the synthetic `EAI_*` code immediately. The real
   resolver is not called.

4. If `result == NULL`, call `chaos_dns_call_real_getaddrinfo` and return. The
   real `getaddrinfo` defines the semantics for a NULL result pointer.

5. Look up a REWRITE rule. If it fires, copy `rule.text` into a
   stack-allocated buffer and set `effective_node` to point at that buffer.
   The original `node` argument is not modified.

6. Look up a SERVICE rule. If it fires, copy `rule.text` into a
   stack-allocated buffer and set `effective_service` to point at that buffer.

7. Look up an OVERRIDE rule. If it fires, call `chaos_dns_apply_override` which
   builds a synthetic result list by calling the real `getaddrinfo` once per IP
   literal with `AI_NUMERICHOST`. If OVERRIDE does not fire, call the real
   `getaddrinfo` with `effective_node` and `effective_service`.

8. If the call from step 7 returns a non-zero error code, return that code
   immediately. No transforms are applied to a failed result.

9. Apply FILTER_FAMILY if a matching rule fires. If the filter empties the
   list, return `EAI_NONAME`.

10. Apply SHUFFLE if a matching rule fires.

11. Apply LIMIT if a matching rule fires. If the list becomes NULL (limit 0),
    return `EAI_NONAME`.

12. Return 0.

### 11.2 getnameinfo()

The numbered steps correspond directly to the implementation in
`src/dns/chaos_dns_lookup.c`.

1. Enter the interposed `getnameinfo` wrapper. Check `chaos_dns_in_internal()`.
   If the guard is set, or if `address` is NULL, call
   `chaos_dns_call_real_getnameinfo` and return directly.

2. Extract the numeric address text from the `sockaddr` using
   `chaos_dns_reverse_query_from_sockaddr`, which calls `inet_ntop()` on the
   appropriate address field (`sin_addr` for `AF_INET`, `sin6_addr` for
   `AF_INET6`). If the address family is unsupported or the sockaddr is
   undersized, call the real `getnameinfo` and return.

3. Look up a LATENCY rule for the extracted address string via
   `chaos_dns_config_match_reverse`. If a rule matches and fires, call
   `chaos_dns_rule_apply_latency`.

4. Look up a GAI rule. If it fires, return the synthetic `EAI_*` code
   immediately. The real `getnameinfo` is not called.

5. Call `chaos_dns_call_real_getnameinfo` with the original, unmodified
   arguments. If the real call returns a non-zero error, return that error.
   Output rewrites only apply after a successful real call — the library never
   overwrites a buffer that libc did not populate.

6. If `host != NULL` and `host_len > 0`, look up a REWRITE rule. If a rule
   fires, attempt to overwrite the `host` buffer using
   `chaos_dns_copy_output_text`. If the replacement text is too long for the
   buffer (length including NUL exceeds `host_len`), return `EAI_OVERFLOW` —
   matching the POSIX-specified behavior for a too-short host buffer.

7. If `service != NULL` and `service_len > 0`, look up a SERVICE rule. Same
   logic as step 6 but for the `service` buffer.

8. Return 0.

---

## Reentrancy Guard and TLS State

### Why a reentrancy guard is needed

The interposed `getaddrinfo` and `getnameinfo` entry points sit on the libc
PLT. Any code that runs inside the wrapper — including the real resolver
invocation, the config file stat, and the usleep in the LATENCY path — may
itself call `getaddrinfo`. Without a guard, these internal calls would re-enter
the wrapper and apply chaos rules to calls the library initiated, not the
application.

Two specific cases make the guard mandatory rather than advisory:

**glibc `getnameinfo` may call `getaddrinfo` internally.** On glibc for
aarch64, `getnameinfo` can call `getaddrinfo` when reconstructing the canonical
PTR record for a reverse-lookup response. If this path fires during a
`getnameinfo` chaos call, the reentrancy guard prevents re-injection of the
internal `getaddrinfo` call.

**NSS module loading.** glibc's `getaddrinfo` implementation calls `dlopen` to
load NSS backend modules (`libnss_*.so.2`) on first use. NSS module constructors
and certain module implementations may themselves call `getaddrinfo`. The guard
suppresses chaos injection for these internal calls.

### `__thread int g_chaos_dns_tls_guard`

The guard is a thread-local variable:

```c
extern __thread int g_chaos_dns_tls_guard;
```

Being per-thread, it has zero cross-thread interference. One thread holding the
guard does not suppress chaos on any other thread. The guard is not a mutex; it
serializes nothing between threads.

### Save/restore semantics

The guard uses save/restore semantics rather than increment/decrement:

```c
static inline int chaos_dns_enter_internal(void)
{
    int previous = g_chaos_dns_tls_guard;
    g_chaos_dns_tls_guard = 1;
    return previous;
}

static inline void chaos_dns_leave_internal(int previous)
{
    g_chaos_dns_tls_guard = previous;
}
```

The caller saves the guard value before entering, sets it to 1, performs
internal work, then restores the saved value rather than unconditionally
clearing to 0.

This handles the case where the guard was already set by an outer frame on the
same call stack. If the outer frame had guard = 1 and a nested call entered and
left using save/restore, the guard returns to 1 after the nested call — which
is correct, because the outer frame is still inside internal code. An
increment/decrement scheme would behave identically in this case, but
save/restore is simpler and avoids the hypothetical where a decrement
undershoot (from a bug, not expected in correct code) could leave the guard
negative.

At the top of each interposed entry point, the check is:

```c
if (chaos_dns_in_internal()) {
    return chaos_dns_call_real_getaddrinfo(node, service, hints, result);
}
```

This is a read-only test of `g_chaos_dns_tls_guard != 0`. Only after this check
passes (guard is 0, meaning the call comes from application code) does the
wrapper call `chaos_dns_enter_internal()` and proceed with rule matching.

### Constructor reentrancy: raw syscalls for /dev/urandom

The library constructor `chaos_dns_init` reads 8 bytes from `/dev/urandom` to
seed the process-wide PRNG. It does this using raw Linux syscalls rather than
libc wrappers:

```c
fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
if (fd >= 0) {
    ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
    (void)syscall(SYS_close, fd);
    /* … */
}
```

The reason is that at constructor time, the interposed entry points are already
in place (the constructor runs after the PLT is set up), but the real-symbol
pointers (`g_chaos_dns_real_getaddrinfo`, etc.) are being resolved in the same
constructor. Using `open()` or `read()` through libc at this moment could
trigger another LD_PRELOAD library's interposer, or re-enter the partially
initialized `libchaos-dns` wrapper if any other preloaded library calls
`getaddrinfo` during initialization. Raw syscalls bypass the PLT entirely and
have no dependency on the wrapper layer being fully initialized.

The reentrancy guard is also set during the seed read (`chaos_dns_enter_internal`
is called before `SYS_openat`, `chaos_dns_leave_internal` after `SYS_close`) as
an additional defensive measure, even though the guard is per-thread TLS and
the constructor runs on the main thread before any additional threads exist.

---

## PRNG Model

### Purpose

The PRNG serves two distinct roles within the library:

- **Probability-gated effects.** Rules carry an optional probability field in
  `[0.0, 1.0]`. On each call, the library draws one 32-bit sample and compares
  it against a threshold derived from the probability. This determines whether
  the rule fires on this particular call.
- **Fisher-Yates index draws.** The SHUFFLE transform uses the PRNG to select
  swap targets during the in-place shuffle of the `addrinfo` pointer array.

Neither role requires cryptographic quality. The library explicitly does not
claim cryptographic properties for this PRNG.

### Per-thread state

```c
extern __thread uint64_t g_chaos_dns_tls_prng_state;
```

The PRNG state is thread-local. Intra-thread outputs form a deterministic
sequence determined by the seed. Inter-thread states are seeded independently
(three-source seeding, described below) and advance independently — there is no
shared PRNG state and no synchronization between threads.

This means:
- Within one thread, given the same initial seed, the sequence of probability
  outcomes is reproducible. This is intentional for testing: a deterministic
  seed in a single-threaded test produces a reproducible fault injection
  sequence.
- Across threads, the sequences are not correlated. Thread A's PRNG advancing
  does not affect thread B's PRNG.

### xorshift64* state advance

The PRNG state is advanced using xorshift64 with the shift triple (12, 25, 27)
from Marsaglia's xorshift family:

```c
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
```

This is a 64-bit xorshift with full period 2^64 - 1 (all non-zero 64-bit
values). The state is never zero (the zero-state avoidance, described below,
ensures this).

### SplitMix64 output finalizer

The raw state after the xorshift advance is not returned directly. Instead, the
output is the upper 32 bits of the state multiplied by the SplitMix64 constant:

```c
return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
```

The multiplier `0x2545f4914f6cdd1d` is the SplitMix64 finalizer constant from
Sebastiano Vigna's reference implementation (OOPSLA 2014). The multiplication
mixes the bits of the state, improving the statistical distribution of the
output. The upper 32 bits of the 64-bit product have better avalanche properties
than the lower 32 bits, which is why the result is shifted right by 32 before
truncation to `uint32_t`.

Note that the constant in `chaos_dns_prng_mix` (the seed finalizer) is distinct
from this output multiplier. The mix function uses:

```c
value += UINT64_C(0x9e3779b97f4a7c15);
value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
return value ^ (value >> 31);
```

This is the full SplitMix64 hash function applied to the seed material before
it is stored as initial PRNG state.

### Three-source seeding

Each thread's PRNG state is seeded from three independent sources XORed
together:

```c
seed = g_chaos_dns_process_seed;      /* from /dev/urandom, set once at init */
seed ^= chaos_dns_current_tid();      /* kernel thread ID (gettid syscall)   */
seed ^= (uint64_t)(uintptr_t)&seed;  /* stack address of the local variable  */
g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed);
```

Why three sources rather than one:

- **Process seed alone** would give every thread in the process the same PRNG
  sequence, because the process seed is the same for all threads.
- **TID alone** is low-entropy on Linux (TIDs are small integers assigned
  sequentially). The first few threads in a process have TIDs differing by only
  a few bits, producing nearly identical PRNG states.
- **Stack address alone** is influenced by ASLR but has coarser granularity
  than TID and is not unique when the same stack address happens to be reused
  across thread lifetimes.

XORing all three before passing through `chaos_dns_prng_mix` produces a
well-distributed 64-bit seed that distinguishes threads from each other (TID
contribution), from one process invocation to the next (process seed
contribution), and from threads at the same TID across process restarts (process
seed contribution again).

### State=0 avoidance

The xorshift64 algorithm has a degenerate fixed point at state = 0: the
three-XOR advance step maps 0 to 0 (since 0 XOR anything is 0 for a bit-shift
of 0). A PRNG in state 0 would produce all-zero outputs forever.

The seeding code guards against this:

```c
g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed);
if (g_chaos_dns_tls_prng_state == 0U) {
    g_chaos_dns_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
}
```

If the mixing of the three sources happens to produce zero (astronomically
unlikely given the SplitMix64 hash, but possible in principle), the state is
replaced with a non-zero constant. The constant chosen is the SplitMix64 output
multiplier itself, which has no special significance beyond being non-zero.

The `chaos_dns_prng_seed_thread` function (used to pre-seed the main thread
from the constructor) applies the same guard:

```c
static inline void chaos_dns_prng_seed_thread(uint64_t seed)
{
    g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}
```

Here, a zero input seed is replaced with 1 before mixing, because
`chaos_dns_prng_mix(0)` is deterministic and non-zero (the mix adds
`0x9e3779b97f4a7c15` before the first multiply), but the explicit guard makes
the intent clear.

### Non-property: intra-thread outputs are not i.i.d.

Each call to `chaos_dns_prng_next_u32` advances the state deterministically.
The outputs are not independently and identically distributed: given the k-th
output, the (k+1)-th output is fully determined. The sequence is a
pseudo-random permutation of a subset of `uint32_t` values, not independent
draws.

For the probability-gating use case, this is irrelevant: the threshold
comparison `(double)sample < probability * 2^32` produces the intended firing
frequency over any long run of calls.

For the Fisher-Yates shuffle, the PRNG draws correlate within a single shuffle
(each draw depends on the previous), but the shuffle is still uniform over all
N! permutations because xorshift64* has full period and the draws are
unbiased modulo N for small N.

Inter-thread outputs are independent: thread A's draw does not affect thread
B's draw because the states are in separate TLS slots.

---

## Config Reload Protocol — Two-Snapshot CAS

### Two config slots

The library maintains two complete config snapshots in static memory:

```c
static chaos_dns_config_state_t g_chaos_dns_config_states[2];
static volatile uint64_t g_chaos_dns_active_config_index;
```

Each `chaos_dns_config_state_t` contains a rule array, a rule count, and a
parse-success flag. At any point in time, one slot is the **active** snapshot
(index indicated by `g_chaos_dns_active_config_index`) and the other is the
**inactive** snapshot available for the next reload.

Readers always work from the active snapshot and never hold a reference across
a reload. Because the two slots are independent, a reload can write the inactive
slot concurrently with reads from the active slot, with no locking.

### mtime sentinel state machine

A single `volatile uint64_t g_chaos_dns_cached_mtime` tracks the mtime of the
last loaded config file. It participates in a four-state machine:

| Value | Constant | Meaning |
|-------|----------|---------|
| `0x0000000000000000` | `CHAOS_DNS_MTIME_MISSING` | Config file did not exist on last check |
| `0xffffffffffffffff` | `CHAOS_DNS_MTIME_UNKNOWN` | Initial state; forces a check on first call |
| `0xfffffffffffffffe` | `CHAOS_DNS_MTIME_RELOADING` | A reload is in progress (CAS lock held) |
| any other value | — | Hash of the file's `st_mtim` (seconds XOR nanoseconds) |

The `UNKNOWN` initial value ensures the first call to `chaos_dns_config_prepare`
always performs a `stat(2)` and attempts to load the file, even if no config
file is present.

The `RELOADING` sentinel functions as a lock indicator. Because the two sentinel
values are at the extreme ends of the `uint64_t` range and the mtime hash
normalizes any raw hash that collides with them (by XORing with a constant),
real timestamps never equal these sentinels.

### CAS winner selection

When a thread discovers the mtime has changed, it attempts to claim the reload
by CAS-ing the cached mtime from its current value to `RELOADING`:

```c
if (chaos_dns_atomic_cas_u64(&g_chaos_dns_cached_mtime, current_mtime,
                              CHAOS_DNS_MTIME_RELOADING)) {
    /* this thread is the reload winner */
}
```

`__sync_bool_compare_and_swap` is an atomic compare-and-swap with full memory
ordering. Exactly one thread wins for any given mtime value transition. All
other threads that observe the CAS failing fall through and continue using the
currently active snapshot — they do not wait for the reload to complete.

### Reload winner sequence

The winning thread executes the following sequence:

1. Parse the config file into the **inactive** snapshot
   (`g_chaos_dns_config_states[1 - active_index]`).
2. Issue `__sync_synchronize()` (full hardware memory barrier). This ensures
   all writes to the inactive snapshot are globally visible before the index
   flip that publishes it.
3. Store the new active index: `g_chaos_dns_active_config_index = 1 -
   active_index`.
4. Issue `__sync_synchronize()` again. This ensures the index store is visible
   to all threads before the mtime sentinel is updated.
5. Store the new mtime hash into `g_chaos_dns_cached_mtime`, exiting the
   `RELOADING` state.

### Why two barriers

The first barrier (step 2) is the write-publish barrier: it guarantees that a
thread reading the new active index (after the step 3 store) is guaranteed to
see the completed parse writes in the new slot. Without this barrier, a reader
on another core could observe the new index while the new slot's rule array is
still being written.

The second barrier (step 4) is the index-publish barrier: it guarantees that a
thread reading the mtime sentinel (after step 5) is guaranteed to see the
completed index store. Without this barrier, a thread that reads the updated
mtime and decides "no reload needed" might still read the old active index,
causing it to use the stale snapshot while another thread has already switched
to the new one.

### Reader spin on RELOADING sentinel

If a thread reads `g_chaos_dns_cached_mtime` and observes `RELOADING`, it
means a reload is in progress. The reader does not attempt its own CAS (it
would fail, since the value is already `RELOADING`, not the previous mtime).
Instead, it falls through and uses the currently active snapshot — whichever
it was before the reload started — and proceeds without waiting.

This is a deliberate design choice: readers are never blocked by a reload.
At worst, they use the previous configuration for one more call. The cost of
a stale read is at most one call's worth of rules being one version behind,
which is acceptable for a fault-injection library.

### All-or-nothing parse

If `chaos_dns_config_parse_buffer` returns a parse error (any line is
malformed), the inactive snapshot is reset to an empty-but-valid state
(`parse_ok = 0`, `rule_count = 0`) before being published. The effect is that
a malformed config causes the library to operate in passthrough mode — no rules
active — rather than continuing to use the previous (potentially stale) rule
set.

This avoids the hazard of a partially-written config file (mid-write when the
mtime changes) applying only the first N lines of a new intended configuration.
The library either loads the complete new config or falls back to no-op.

---

## glibc vs musl Divergence

The following divergences are specific to the DNS resolution subsystem. For
platform-layer divergences (ELF link-map ordering, AT_SECURE, constructor
ordering), see `docs/PLATFORM.md`.

### getnameinfo internal getaddrinfo call (glibc, aarch64)

glibc's `getnameinfo` on aarch64 may call `getaddrinfo` internally when
reconstructing the canonical PTR record format for certain reverse-lookup
responses. When this happens during a `getnameinfo` chaos call:

1. The `getnameinfo` wrapper has already set the reentrancy guard
   (`g_chaos_dns_tls_guard = 1`).
2. The internal `getaddrinfo` call hits the interposed entry point.
3. `chaos_dns_in_internal()` returns non-zero (guard is set).
4. The wrapper calls the real `getaddrinfo` directly and returns — no chaos
   applied to the internal call.

This is the correct behavior. The internal `getaddrinfo` is a private
implementation detail of glibc's `getnameinfo`; injecting chaos into it would
distort the `getnameinfo` result in ways the library does not control or
account for.

musl's `getnameinfo` does not call `getaddrinfo` internally. The reentrancy
guard on the `getnameinfo` path is therefore a no-op on musl for this
particular case, but it remains correct and harmless.

### NSS module loading (glibc only)

glibc's `getaddrinfo` implementation calls `dlopen` on the first use of each
NSS backend module to load `libnss_*.so.2` shared libraries (e.g.,
`libnss_dns.so.2`, `libnss_files.so.2`). Module constructors or their
resolution functions may, in rare cases, call `getaddrinfo` themselves — for
example to resolve a configuration server address.

When such a call occurs from within glibc's NSS dispatch, the reentrancy guard
is already set (the outer `getaddrinfo` call is in progress). The interposed
wrapper detects this and passes the internal call directly to the real
`getaddrinfo`. No chaos rules are applied.

musl uses a different NSS architecture. musl resolves names through a built-in
resolver that does not use `dlopen` for modular NSS loading. There is therefore
no NSS-triggered reentrancy risk in musl.

### Config file path

The config path `/tmp/.chaos-dns.conf` is identical on glibc and musl systems.
The stat(2) and read(2) calls for config loading use the same code path on both.
There is no glibc/musl divergence in config handling.

### Selector matching and inet_ntop output format

The reverse selector key is derived by calling `inet_ntop(3)`. Both glibc and
musl implement `inet_ntop` to produce the same canonical text format for a given
address: dotted-decimal for `AF_INET`, and the RFC 5952 compressed form for
`AF_INET6`. Config files written for one libc work unchanged on the other.

### freeaddrinfo behavior on partially-chained lists

The FILTER_FAMILY node isolation pattern (`current->ai_next = NULL` before
`freeaddrinfo`) is required on both glibc and musl. Both implementations of
`freeaddrinfo` walk the `ai_next` chain and free all reachable nodes. The
isolation is a property of the `freeaddrinfo` specification, not a
glibc-specific behavior.

---

## NSS Plumbing and the nsswitch.conf Stack

`getaddrinfo(3)` is not a raw DNS client. It is a dispatcher that consults
`/etc/nsswitch.conf` to determine which Name Service Switch (NSS) databases and
backends to query, and in which order.

### nsswitch.conf Line Format

```
hosts:   files dns resolve [!UNAVAIL=return]
```

- `files` → `/etc/hosts` lookup (`nss_files` module)
- `dns` → recursive DNS query via libc resolver (`nss_dns` module); on glibc,
  this calls `res_query()` → UDP/TCP to `resolv.conf` nameservers
- `resolve` → D-Bus call to systemd-resolved (glibc `nss_resolve` module,
  shipped by systemd, not by glibc)
- `mdns4_minimal` → Avahi/mDNS for `.local` names (optional, not in glibc base)

The NSS backend modules are themselves dynamically loaded by glibc (`dlopen()`
of `libnss_*.so.2`). They are **not** libc symbols in the PLT of the target
binary; they are loaded by glibc's `getaddrinfo` implementation.

**Consequence for injection:** `libchaos-dns` intercepts `getaddrinfo()` before
glibc's NSS dispatch. A synthetic `EAI_NONAME` fires before glibc consults
any NSS module. A passthrough lets glibc proceed through the `nsswitch.conf`
stack as configured.

### nss_files — /etc/hosts

`nss_files` reads `/etc/hosts`. The file format is:
```
127.0.0.1   localhost
::1         localhost ip6-localhost
```
`/etc/hosts` entries are returned before DNS in the default `files dns` order.
If `/etc/hosts` has an A record for a name, `dns` is not consulted.

`libchaos-dns` with `OVERRIDE` or `FILTER_FAMILY` acts _after_ glibc has
already resolved the name (potentially from `/etc/hosts`). Hosts-file entries
are therefore in the returned `addrinfo` list before filters are applied.

### nss_dns — POSIX Resolver

`nss_dns` invokes glibc's built-in resolver (`libresolv`). The resolver reads
`/etc/resolv.conf` for nameserver addresses, search domains, and options. It
sends UDP (default port 53) queries with TCP fallback for responses > 512 bytes
(or when TC bit is set). DNSSEC validation is controlled by `options edns0
trust-ad` in `resolv.conf`.

This is the standard path for container DNS: the container's `/etc/resolv.conf`
points to the container network's DNS resolver (e.g., the Kubernetes cluster DNS
at `169.254.25.10` or the container gateway). `libchaos-dns` owns the process
contract before nss_dns runs.

### nss_resolve — systemd-resolved Integration

`nss_resolve` (glibc module, provided by systemd package) calls systemd-resolved
over D-Bus (`org.freedesktop.resolve1`). systemd-resolved supports:

- LLMNR (Link-Local Multicast Name Resolution, RFC 4795)
- mDNS (RFC 6762)
- DNS-over-TLS (DoT)
- DNSSEC validation
- NXDOMAIN synthesis for `.local` on multi-homed systems

On Ubuntu 18.04+ and Debian 11+ (systemd-resolved enabled by default), many
processes hit `nss_resolve` before or instead of `nss_dns`. `libchaos-dns` is
unaware of which NSS backend was used; it only sees the final `getaddrinfo()`
result.

**Non-coverage:** the library does not intercept the D-Bus calls made by
`nss_resolve` to systemd-resolved. Injecting LLMNR or DNS-over-TLS failures
requires either systemd-resolved configuration changes or a separate D-Bus
interposition layer.

Reference: `nsswitch.conf(5)`, `resolv.conf(5)`, `nss(5)`.

## Legacy Resolver API Non-Coverage — res_*(), gethostbyname

### gethostbyname / gethostbyaddr Family

`gethostbyname(3)` and `gethostbyaddr(3)` (POSIX.1-2001, marked obsolescent)
are older resolver entry points. They return `struct hostent` rather than
`struct addrinfo`. They are:

- not thread-safe (global `struct hostent` buffer in glibc, per-thread in musl)
- IPv4-only for `gethostbyname` (no AF_INET6 support in the struct)
- superseded by `getaddrinfo()` since POSIX.1-2001

Why not interposed:

1. glibc's `gethostbyname` internally calls `getaddrinfo()` on modern glibc
   (≥ 2.25). Interposing `getaddrinfo()` therefore covers `gethostbyname`
   transitively on glibc. On musl, `gethostbyname` also calls through a common
   resolver path.
2. The `struct hostent` API is too narrow (IPv4 only) to need its own injection
   surface; all meaningful scenarios are covered via `getaddrinfo()`.
3. `gethostbyname_r` (reentrant) and `gethostbyaddr_r` would need separate
   wrappers with different return semantics. The value does not justify the
   complexity.

### res_*() — Low-Level Resolver Interface

The `res_init()`, `res_query()`, `res_search()`, `res_mkquery()`, `res_send()`,
`dn_expand()` family (POSIX.1-2017 Appendix B, "Interfaces defined for XSI
implementations") is the raw DNS wire-level API. Applications using these
functions are directly constructing and sending DNS queries.

Why not interposed:

1. `res_*()` functions construct and transmit raw DNS packets. Meaningful
   injection (NXDOMAIN, SERVFAIL) would require fabricating a valid DNS response
   packet, including the RD bit, QR flag, AA flag, RCODE, and answer section.
   That is a DNS server implementation, not a preload library.
2. `res_query()` is glibc-specific (`libresolv`). musl has a different internal
   implementation. The symbol name, calling convention, and struct `__res_state`
   layout differ between glibc and musl.
3. Applications using `res_*()` directly are rare in server-side code (Sendmail,
   BIND utilities, custom DNS tools). Standard application code uses
   `getaddrinfo()`.

For wire-level DNS chaos, use a real DNS proxy (CoreDNS, dnsmasq with fault
injection) or a `tc netem` rule at the network level.

Reference: `resolver(3)`, `res_init(3)` glibc manual.

---

## Execution Boundary Summary

| Aspect | Library controls | Library does not control |
|--------|-----------------|--------------------------|
| Query name | Read as-is; optionally rewritten by REWRITE before real call | Not parsed; suffix labels not inspected beyond selector matching |
| Resolution engine | Bypassed entirely by OVERRIDE; otherwise passed through unchanged | NSS module selection, resolv.conf nameserver list, DNS transport, retries |
| Result list transforms | FILTER_FAMILY (family drop), SHUFFLE (order), LIMIT (count truncation) | Number and content of nodes before transforms; TTLs; DNSSEC status |
| Error code | Any EAI_* synthetic error injectable before real call | Errors surfaced by real libc or NSS backends on passthrough |
| Latency | Configurable pre-call sleep via LATENCY rule (millisecond granularity) | Network RTT; resolver retry backoff; kernel scheduler jitter |
| Reverse lookup text | Host and service output buffers overwritten by REWRITE and SERVICE after successful real call | PTR RRset content; `/etc/hosts` reverse entries; mDNS PTR responses |
| Thread safety | Per-thread TLS guard and PRNG state; config reload is CAS-serialized | Signal delivery; `pthread_atfork` handlers in glibc fork paths |

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
