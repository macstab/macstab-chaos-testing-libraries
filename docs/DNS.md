# libchaos-dns Technical Reference

`libchaos-dns` is the dedicated resolver-chaos preload library in this
repository. Repository-wide ownership rules live in
[`docs/SYSTEM.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/SYSTEM.md).

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
