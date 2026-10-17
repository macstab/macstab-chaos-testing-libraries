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

`libchaos-dns` is an `LD_PRELOAD` library that injects resolver faults into a
Linux process at the libc name-resolution boundary: synthetic `EAI_*` errors,
lookup delays, rewritten names and services, fabricated answers, and filtered,
reordered or truncated address lists. It acts on what `getaddrinfo()`,
`getnameinfo()` and the legacy `gethostbyname*()`/`gethostbyaddr*()` functions
take and return; it never parses or emits DNS packets. With no matching rule,
or any input it cannot interpret, it passes the call through unchanged.
Repository-wide ownership rules live in [`docs/SYSTEM.md`](SYSTEM.md).

### At a glance

| Item | Value |
|------|-------|
| Rule file | `/tmp/.chaos-dns.conf` |
| Status file | `/tmp/.chaos-dns.status` |
| Hits file | `/tmp/.chaos-dns.hits.<n>` |
| Rule grammar | `<selector>:<effect>:<value> [qualifier ...]` |
| Forward selectors | `*`, `dns://*`, `dns://<name>`, `dns://*.<suffix>` |
| Reverse selectors | `rdns://<ipv4>`, `rdns://[<ipv6>]`, `rdns://*` |
| Forward effects | GAI (`EAI_AGAIN`, `EAI_FAIL`, `EAI_NONAME`, `EAI_MEMORY`, `EAI_SYSTEM`), LATENCY, REWRITE, SERVICE, OVERRIDE, FILTER_FAMILY, SHUFFLE, LIMIT |
| Reverse effects | GAI, LATENCY, REWRITE, SERVICE |
| Transform order | FILTER_FAMILY, then SHUFFLE, then LIMIT |
| Limits | 256 rules; rule file under 256 KiB (262 144 bytes); 32 literals per OVERRIDE |
| Failure mode | fail-open |
| Coverage gate | 100.00 % line coverage on every `src/dns/*.c` file (`test/runtime/check_coverage.sh`) |

---

## Table of Contents

1. [Execution Boundary](#execution-boundary)
2. [Interposed Functions](#interposed-functions)
3. [Rule Grammar](#rule-grammar)
4. [What The Wrapper Actually Reads](#what-the-wrapper-actually-reads)
5. [What Libc Still Owns](#what-libc-still-owns)
6. [Forward Lookup Semantics](#forward-lookup-semantics)
7. [Reverse Lookup Semantics](#reverse-lookup-semantics)
8. [Why Reverse Lookup Does Not Support Certain Effects](#why-reverse-lookup-does-not-support-certain-effects)
9. [What This Library Deliberately Does Not Do](#what-this-library-deliberately-does-not-do)
10. [Data Model](#data-model)
11. [Post-Resolution Transform Pipeline](#post-resolution-transform-pipeline)
12. [Per-Hook Call Flows](#per-hook-call-flows)
13. [Reentrancy Guard and TLS State](#reentrancy-guard-and-tls-state)
14. [PRNG Model](#prng-model)
15. [Config Reload Protocol — Two-Snapshot CAS](#config-reload-protocol--two-snapshot-cas)
16. [Failure Behaviour and Observability](#failure-behaviour-and-observability)
17. [glibc vs musl Divergence](#glibc-vs-musl-divergence)
18. [NSS Plumbing and the nsswitch.conf Stack](#nss-plumbing-and-the-nsswitchconf-stack)
19. [Legacy Resolver APIs — gethostbyname coverage, res_*() non-coverage](#legacy-resolver-apis--gethostbyname-coverage-res_-non-coverage)
20. [Execution Boundary Summary](#execution-boundary-summary)

---

## Execution Boundary

`libchaos-dns` is a libc-boundary interposer, not a DNS packet engine. It sees a
process call a resolver function, can read and replace that call's inputs, can
fail, delay or pass the call through, and can post-process its result. It does
not see DNS transaction IDs, flags, TTLs, RRsets, nameserver selection, retries or
packet order.

The contracts it works against:

- forward: `getaddrinfo()`, a query name and service in, a `struct addrinfo` list
  out;
- reverse: `getnameinfo()`, one `sockaddr` in, host and service text out;
- legacy: `gethostbyname*()`/`gethostbyaddr*()`, a name or binary address in, a
  `struct hostent` out.

Everything below these calls belongs to libc, NSS and the system resolver.

## Interposed Functions

| Function | Rules | Notes |
|----------|-------|-------|
| `getaddrinfo` | `dns://` (and `*`) of the `node` argument | full forward pipeline |
| `freeaddrinfo` | none | frees lists the library built (OVERRIDE), forwards everything else |
| `getnameinfo` | `rdns://` of the address | GAI, LATENCY, REWRITE, SERVICE |
| `gethostbyname2`, `gethostbyname2_r` | `dns://` of the name | shares the `getaddrinfo` pipeline when a result-shaping rule matches |
| `gethostbyname`, `gethostbyname_r` | `dns://` of the name | the `AF_INET` forms of the above |
| `gethostbyaddr`, `gethostbyaddr_r` | `rdns://` of the address | GAI, LATENCY, REWRITE of `h_name` |

Each wrapper calls the real function (the next definition found by
`dlsym(RTLD_NEXT)`) under a thread-local reentrancy guard. The real symbols are
resolved once, by `chaos_once`, from whichever wrapper or the constructor runs
first; a failed lookup (`dlsym` NULL with a `dlerror()` message) calls
`abort()`. A call that arrives while the table is still being filled finds no
real function and fails: `getaddrinfo`/`getnameinfo` return `EAI_SYSTEM` with
`errno` `ENOSYS`, the `_r` hostent forms return `ENOSYS` with `h_errno`
`NETDB_INTERNAL`, the others return NULL with the same, and `freeaddrinfo` leaks
the list rather than guess.

Not interposed: `res_*()`, `getaddrinfo_a()`, `getipnodebyname()` and any
resolver that does not call these functions (a statically linked binary, a
runtime with its own DNS client). `libchaos-net` interposes no resolver symbol.

## Rule Grammar

```text
<selector>:<effect>:<value> [@qualifier ...]  [# comment]
```

`#` starts a comment anywhere on the line; blank lines are ignored. The selector
ends at the first `:` after `dns://` or `rdns://` (for `rdns://[…]` at the `:`
after the closing bracket), so names cannot contain `:` and a bare IPv6 address
must be bracketed. The `*` selector must be followed directly by `:`
(`*:EAI_AGAIN:0.1`, not `* : …`). Effect names are case-sensitive.

### Selectors

| Selector | Matches | Rank |
|----------|---------|------|
| `dns://api.example.com` | that name, ASCII case-insensitive | 3 |
| `dns://*.example.com` | names ending in `.example.com` (not `example.com` itself, not `fooexample.com`) | 2 |
| `dns://*`, `*` | every forward lookup | 1 |
| `rdns://192.0.2.10` | reverse lookups of that IPv4 address | 3 |
| `rdns://[2001:db8::1]` | reverse lookups of that IPv6 address | 3 |
| `rdns://*` | every reverse lookup | 1 |

- A `*` anywhere else in a name is rejected; names are at most 255 bytes.
- Names are compared as written: a trailing dot is not stripped, so
  `example.com.` and `example.com` are different queries.
- `rdns://` addresses are parsed with `inet_pton` and stored in `inet_ntop` form,
  so any spelling of an IPv6 address (`rdns://[0:0::1]`) matches its canonical
  form (`::1`). Host names are not accepted after `rdns://`.
- An IPv4-mapped IPv6 `sockaddr` (`::ffff:192.0.2.10`) is keyed as
  `::ffff:192.0.2.10`, so `rdns://192.0.2.10` does not match it;
  `rdns://[::ffff:192.0.2.10]` does.

For each effect separately, the matching rule with the highest rank wins; a tie
goes to the longer selector text, then to the rule earlier in the file. Different
effects compose: one lookup can be delayed, rewritten, filtered and shuffled by
four rules.

### Effects and values

| Effect | Value | Forward | Reverse |
|--------|-------|---------|---------|
| `EAI_AGAIN`, `EAI_FAIL`, `EAI_NONAME`, `EAI_MEMORY`, `EAI_SYSTEM` (GAI) | probability | yes | yes |
| `LATENCY` | `<ms>[@p]`, 0–4294967295 ms | yes | yes |
| `REWRITE` | `<name>[@p]` | query name | returned host name |
| `SERVICE` | `<service>[@p]` | query service | returned service name |
| `OVERRIDE` | `<ip>[,<ip>…][@p]`, IPv6 bare or bracketed | yes | rejected |
| `FILTER_FAMILY` | `inet4`/`ipv4`, `inet6`/`ipv6` or `any`, `[@p]` | yes | rejected |
| `LIMIT` | `<N>[@p]`, N ≥ 1 | yes | rejected |
| `SHUFFLE` | probability | yes | rejected |

- `@p` is an optional probability appended to the value without a blank
  (`LATENCY:250@0.5`); without it the rule fires on every matching call. A blank
  before `@` turns it into a qualifier word, which rejects the file.
- A probability is `0`, `1`, `0.` and digits, or `1.` and zeros, parsed
  independently of `LC_NUMERIC`. A rule fires when a 32-bit sample from the
  per-thread PRNG is below `p × 2^32`.
- Text values (REWRITE, SERVICE, OVERRIDE) are at most 511 bytes.
- `LIMIT:0` is rejected: a limit that discards every answer is written
  `EAI_NONAME`.
- OVERRIDE literals are validated with `inet_pton` at parse time. List at most
  32: a literal that follows 32 resolved ones fails the lookup with `EAI_FAIL`
  (the rule still parses).
- `FILTER_FAMILY:any` parses and never acts (it also counts no hit).

### Qualifiers

`@first=N`, `@from=T`, `@until=T`, `@size>N` and `@size<N` follow the rule as
separate words, as in every library of the repository (`src/common/chaos_policy.h`).
`@first` limits firings per process, `@from`/`@until` gate on the wall clock in
Unix milliseconds. Resolver calls carry no byte count, so a rule with `@size`
never fires.

### Examples

```text
dns://api.example.com:EAI_AGAIN:0.1
dns://*.internal.example:LATENCY:250@0.5
dns://legacy.example.com:REWRITE:new.example.com
dns://api.example.com:SERVICE:8443
dns://db.example.com:OVERRIDE:10.0.0.7,[2001:db8::7]
dns://db.example.com:FILTER_FAMILY:inet4
dns://cdn.example.com:SHUFFLE:1
dns://cdn.example.com:LIMIT:1
rdns://127.0.0.1:REWRITE:spoofed.example
rdns://[::1]:EAI_NONAME:1
*:EAI_AGAIN:0.01 @first=5
```

## What The Wrapper Actually Reads

### Forward lookup

`getaddrinfo(node, service, hints, result)`: the query name, the service string,
the hints, and the returned list. Every rule is matched against the original
`node`; a REWRITE does not make the rules of the new name apply. A NULL or empty
`node` (a local-host or service-only lookup) is passed through untouched.

### Reverse lookup

`getnameinfo(address, address_len, host, host_len, service, service_len, flags)`:
the `sockaddr`, its length, and the two output buffers. The rule key is the
numeric address text: `inet_ntop` of `sin_addr` for `AF_INET`, of `sin6_addr` for
`AF_INET6`. The wrapper never builds an `in-addr.arpa` or `ip6.arpa` name. Another
family, or a length shorter than `sockaddr_in`/`sockaddr_in6`, is passed through.

## What Libc Still Owns

On passthrough, and for the real call behind every non-failing rule, libc and the
resolver stack decide:

- which NSS sources answer (`/etc/hosts`, DNS, mDNS, systemd-resolved, …);
- whether and how a PTR query is sent, to which nameserver, with which retries,
  timeouts and failover;
- how several PTR answers collapse into one host string;
- how ports map to service names and how `flags` are honoured.

## Forward Lookup Semantics

Forward lookups get the full effect set because `getaddrinfo()` returns a list
the library can shape:

1. LATENCY delays the lookup.
2. GAI fails it with an `EAI_*` code.
3. REWRITE and SERVICE replace the name and service handed to the resolver.
4. OVERRIDE replaces the resolver with fixed address literals.
5. FILTER_FAMILY, SHUFFLE and LIMIT reshape the returned list, in that order.

## Reverse Lookup Semantics

`getnameinfo()` returns one host string and one service string, so the reverse
path supports exactly GAI, LATENCY, REWRITE and SERVICE; the parser rejects
OVERRIDE, FILTER_FAMILY, LIMIT and SHUFFLE on an `rdns://` selector.

1. LATENCY delays the lookup.
2. GAI fails it with an `EAI_*` code.
3. The real `getnameinfo()` runs with the original arguments.
4. If it succeeded, REWRITE overwrites `host` and SERVICE overwrites `service`.
   A replacement that does not fit the caller's buffer returns `EAI_OVERFLOW`,
   as libc does for a too-short buffer. A failed real call is returned as is: the
   library never writes a buffer libc did not fill.

## Why Reverse Lookup Does Not Support Certain Effects

- **OVERRIDE** fabricates an address list. `getnameinfo()` returns text, and the
  text is already replaceable with REWRITE (host) and SERVICE (service); a reverse
  OVERRIDE would duplicate them under a second name or need invented semantics.
- **FILTER_FAMILY** needs a list of entries of different families. The caller of
  `getnameinfo()` supplies one `sockaddr` of one fixed family, and the output is
  text.
- **LIMIT** needs a visible collection. Any multiplicity of PTR records is
  collapsed inside libc before the wrapper sees the result: `LIMIT 1` would be a
  no-op and `LIMIT 0` a roundabout `EAI_NONAME`.
- **SHUFFLE** needs an observable order. The wrapper receives only the final
  host and service strings.

## What This Library Deliberately Does Not Do

- own the raw `res_*()` API (see [Legacy Resolver APIs](#legacy-resolver-apis--gethostbyname-coverage-res_-non-coverage));
- parse DNS headers or payloads, or rewrite TTLs, RCODEs or RRsets;
- control nameserver order, transport fallback (UDP/TCP, DoT) or retries;
- expose PTR answer order.

Those belong below the libc boundary: a DNS proxy (CoreDNS, dnsmasq), a resolver
implementation, NSS backend ownership, or `tc netem` on the resolver's traffic.

---

## Data Model

### struct addrinfo fields used

`getaddrinfo(3)` returns a singly linked list of `struct addrinfo` (`<netdb.h>`):

```c
struct addrinfo {
    int              ai_flags;      /* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST, ... */
    int              ai_family;     /* AF_INET, AF_INET6                              */
    int              ai_socktype;   /* SOCK_STREAM, SOCK_DGRAM, ...                   */
    int              ai_protocol;   /* IPPROTO_TCP, IPPROTO_UDP, ...                  */
    socklen_t        ai_addrlen;    /* byte length of ai_addr                         */
    struct sockaddr *ai_addr;       /* the resolved address                           */
    char            *ai_canonname;  /* canonical name, first node only (AI_CANONNAME) */
    struct addrinfo *ai_next;       /* next node, or NULL                             */
};
```

- `ai_family` decides which nodes FILTER_FAMILY keeps.
- `ai_next` is rewired by FILTER_FAMILY, SHUFFLE and LIMIT.
- `ai_canonname` is moved so that it stays on the head: FILTER_FAMILY hands it
  from a dropped node to the next one, SHUFFLE swaps it onto the new head.
  Callers read it from the first node only.
- All other fields pass through unchanged.

### Who allocated the list

After a successful forward lookup, `*result` is one of two kinds of list:

- **A real result**: every node came from the real `getaddrinfo()`. Nodes that
  FILTER_FAMILY or LIMIT remove are released at once with the real
  `freeaddrinfo()`, under the reentrancy guard. The survivors are freed by the
  application's `freeaddrinfo()`, which the library forwards.
- **An OVERRIDE list**: one `malloc` block owned by the library, holding all
  nodes, then their addresses (one `sockaddr_storage` each), then the canonical
  name. Nodes that FILTER_FAMILY or LIMIT remove from it are only unlinked; the
  whole block is freed when the application calls `freeaddrinfo()` with any of
  its nodes (SHUFFLE may have made any node the head).

### Why OVERRIDE builds its own list

OVERRIDE resolves each literal with the real `getaddrinfo()` and
`AI_NUMERICHOST` (no DNS query; the service and the hints' socket type expand as
usual). Splicing those per-literal results into one chain would be wrong on musl:
musl allocates each result as one reference-counted block, and its
`freeaddrinfo()` charges the whole chain to the block of the chain's last node. A
spliced list leaks on every lookup and becomes a use-after-free once SHUFFLE or
LIMIT reorders or cuts it. OVERRIDE therefore copies the nodes into one block of
its own and releases the real results immediately.

The blocks alive at one time are registered in a table of 256 entries guarded by
a spin lock held only for a table scan. A lookup that would exceed 256 live
OVERRIDE lists fails with `EAI_MEMORY`; so does a failed `malloc`.

### Removing one node safely

FILTER_FAMILY isolates a node before releasing it:

```c
current->ai_next = NULL;            /* hand freeaddrinfo exactly one node */
chaos_dns_call_real_freeaddrinfo(current);
```

`freeaddrinfo()` frees every node reachable through `ai_next`. Without the
isolation, releasing a rejected node would also release every surviving node
after it. LIMIT detaches the tail (`current->ai_next = NULL` on the last kept
node) and releases the whole tail with one call, because none of it survives.
For an OVERRIDE list both steps only unlink.

### Why freeaddrinfo is interposed

For real results interposition would not be needed: the survivors are an
ordinary real list. It exists for OVERRIDE lists, which the real `freeaddrinfo()`
must never see. The wrapper looks the pointer up in the owned-block table; if it
lies inside a block, it frees the block, otherwise it forwards to the real
function.

---

## Post-Resolution Transform Pipeline

After a successful real lookup or OVERRIDE, three optional transforms run in a
fixed order, each on the output of the previous one. Each is matched and decided
separately (own rule, own probability, own qualifiers).

### FILTER_FAMILY

Keeps only `AF_INET` nodes (`inet4`/`ipv4`) or only `AF_INET6` nodes
(`inet6`/`ipv6`). One pass with `previous` and `current` pointers unlinks and
releases each rejected node as described above. If no node survives, the lookup
returns `EAI_NONAME`, the code a resolver returns for a name without addresses of
the requested family, and an OVERRIDE block is freed.

### SHUFFLE

A Fisher–Yates shuffle over a temporary `calloc`ed array of node pointers:

1. Count the nodes; fewer than two means nothing to do.
2. Fill the array in list order.
3. For `i` from `n − 1` down to 1, swap `nodes[i]` with
   `nodes[prng() % (i + 1)]`.
4. Move `ai_canonname` onto the new head, relink, terminate the last node, store
   the new head in `*result`, free the array.

One 32-bit PRNG draw per swap. The modulo bias is at most `(i + 1) / 2^32` per
draw, negligible for resolver-sized lists; there is no upper bound on the list
length. If `calloc` fails, the list is returned in its original order. No node is
allocated or freed.

### LIMIT

Keeps the first N nodes and releases the rest with one call on the detached
tail. A list of N or fewer nodes is unchanged. N is at least 1 (the parser
rejects 0), so LIMIT never empties a list from a rule file.

### Why FILTER → SHUFFLE → LIMIT

- **FILTER first.** SHUFFLE and LIMIT then work on exactly the set that will be
  returned. LIMIT before FILTER could keep N nodes of mixed families and let the
  filter reduce them below N, even to zero.
- **SHUFFLE before LIMIT.** LIMIT then picks N entries from a random order, so
  repeated lookups expose the application to different address subsets. LIMIT
  first would always keep the first N in resolver order.

The order is fixed in code and identical for `getaddrinfo()` and the
`gethostbyname*()` pipeline. See also [`docs/DSL.md`](DSL.md).

---

## Per-Hook Call Flows

### getaddrinfo()

Implemented in `src/dns/chaos_dns_lookup.c`; steps 4–10 are shared with the
`gethostbyname*()` pipeline.

1. Resolve the symbol table once. If the guard is set, or `node` is NULL or
   empty, call the real `getaddrinfo()` and return its result.
2. **LATENCY**: if a LATENCY rule for `node` fires, sleep. The sleep happens even
   if GAI or OVERRIDE follows: it models delay before the outcome is known.
3. **GAI**: if a GAI rule fires, return its `EAI_*` code without calling the
   resolver. For `EAI_SYSTEM`, which means "see `errno`", `errno` is set to
   `EIO`.
4. If `result` is NULL, call the real `getaddrinfo()` with the original
   arguments and return.
5. **REWRITE**: if a REWRITE rule fires, the resolver is asked for the rule's
   name instead of `node`.
6. **SERVICE**: if a SERVICE rule fires, the resolver is asked for the rule's
   service instead of `service`.
7. **OVERRIDE**: if an OVERRIDE rule fires, build the answer from its literals
   (using the effective service and the caller's hints; REWRITE has no effect on
   OVERRIDE). Otherwise call the real `getaddrinfo()` with the effective name and
   service.
   - `AI_NUMERICHOST` is added to a copy of the hints.
   - A literal of a family the hints exclude is skipped. If every literal is
     skipped, the lookup returns `EAI_NONAME`.
   - A literal the real `getaddrinfo()` rejects (for example `EAI_SERVICE` for
     an unknown service) fails the lookup with that error.
   - With `AI_CANONNAME`, the queried `node` becomes the canonical name.
8. A non-zero result from step 7 is returned unchanged; no transform runs on a
   failed lookup.
9. **FILTER_FAMILY** (skipped for `any`); an empty list returns `EAI_NONAME`.
10. **SHUFFLE**.
11. **LIMIT**.
12. Return 0.

### freeaddrinfo()

Frees the owned block if the pointer lies inside one (OVERRIDE), otherwise calls
the real `freeaddrinfo()` under the guard.

### getnameinfo()

1. Resolve the symbol table once. If the guard is set or `address` is NULL, call
   the real `getnameinfo()`.
2. Derive the key with `inet_ntop`; an unsupported family or a short length
   passes through.
3. **LATENCY** for the key.
4. **GAI**: return the `EAI_*` code. Unlike `getaddrinfo()`, `errno` is not set
   for `EAI_SYSTEM`.
5. Call the real `getnameinfo()` with the original arguments; return its error if
   it failed.
6. **REWRITE**, when `host != NULL` and `host_len > 0`: copy the rule's name into
   `host`, or return `EAI_OVERFLOW` if it does not fit (length plus NUL exceeds
   `host_len`).
7. **SERVICE**, the same for `service`/`service_len`.
8. Return 0.

### gethostbyname family

See [Legacy Resolver APIs](#legacy-resolver-apis--gethostbyname-coverage-res_-non-coverage).

---

## Reentrancy Guard and TLS State

### Why a guard is needed

The real resolver, an NSS module it loads, or another preload library may call a
resolver function while the wrapper is inside the real call. Without a guard such
calls would re-enter the wrapper and apply rules to lookups the application never
made, or recurse. Every real call (`getaddrinfo`, `getnameinfo`, `freeaddrinfo`,
the hostent functions) and the library's own `stat`/`open`/`read` of the rule
file run with the guard set, and every wrapper checks it first.

### `__thread int g_chaos_dns_tls_guard`

The guard is thread-local: one thread inside the library does not suppress rules
on another, and it serialises nothing. It uses save/restore rather than
increment/decrement:

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

A nested section restores 1, not 0, so only the outermost frame clears the guard.
Wrappers test it read-only (`chaos_dns_in_internal()`) and forward at once when
it is set.

### Constructor

`chaos_dns_init()` resolves the symbol table, reads 8 bytes of `/dev/urandom` with
raw `openat`/`read`/`close` system calls (no interposable libc entry point; the
guard is set around them; fallback `0x6a09e667f3bcc909 ^ getpid()`), seeds the
main thread's PRNG, initialises the config engine and loads the rule file once,
so a bad rule file is reported in the status file at start-up. `errno` is
preserved across the seed read.

---

## PRNG Model

### Purpose

The PRNG decides probabilities (one 32-bit draw per decision) and picks SHUFFLE
swap indices. It is not cryptographic and makes no such claim.

### Per-thread state

`__thread uint64_t g_chaos_dns_tls_prng_state` holds one xorshift64* state per
thread; there is no shared PRNG state and no synchronisation. A thread seeds
lazily on its first draw:

```c
seed  = g_chaos_dns_process_seed;      /* /dev/urandom, set once in the constructor */
seed ^= chaos_dns_current_tid();       /* SYS_gettid on Linux, getpid() elsewhere   */
seed ^= (uint64_t)(uintptr_t)&seed;    /* stack address: ASLR entropy               */
g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed) | 1U;
```

- The process seed alone would give every thread the same stream.
- The thread id alone is low-entropy: consecutive threads differ in a few bits.
- The SplitMix64 finaliser (`chaos_dns_prng_mix`) spreads all three inputs over
  64 bits:

  ```c
  value += UINT64_C(0x9e3779b97f4a7c15);
  value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
  return value ^ (value >> 31);
  ```

- `| 1U` makes the state odd, hence never 0, the one state xorshift cannot
  leave. The constructor seeds the main thread with `chaos_dns_prng_mix(seed)`,
  mapping a zero seed to 1 first.
- A `fork()` child clears the forking thread's state in its atfork handler and
  reseeds from its own thread id on the next draw, so pre-fork workers do not
  make identical decisions.

### Advance and output

```c
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
```

Marsaglia's xorshift64 triple (12, 25, 27), full period 2^64 − 1 over non-zero
states, with the xorshift64* multiplier; the upper 32 bits of the product are
returned because they mix better than the lower ones.

### Properties

- Within one thread the sequence is deterministic given the seed; successive
  outputs are not independent draws.
- Across threads the streams are unrelated.
- For probability decisions the long-run firing frequency matches `p`; for
  SHUFFLE the residual modulo bias is bounded as stated above.

---

## Config Reload Protocol — Two-Snapshot CAS

### Two snapshots

```c
static chaos_dns_config_state_t g_chaos_dns_config_states[2];
static volatile unsigned int g_chaos_dns_active_config_index;
```

Each snapshot holds a sequence counter, up to 256 rules, the rule count, a
`parse_ok` flag, a hit-counter pointer per rule and each rule's text as written
(for the hits file). One snapshot is active; the reload writes the other.

### Change detection

A wrapper looks at the rule file at most once every 1 ms per process
(`CHAOS_CHECK_INTERVAL_NS`), with `stat()` under the guard. The look computes a
change stamp: an FNV-1a style hash over mtime seconds, mtime nanoseconds, size,
inode and device. The mtime alone misses two writes within one coarse file-system
tick; the size catches an append, the inode a rewrite through a temporary file and
`rename()` (`sed -i`).

`g_chaos_dns_cached_mtime` holds the stamp of the loaded file or a sentinel:

| Value | Constant | Meaning |
|-------|----------|---------|
| `0x0000000000000000` | `CHAOS_DNS_MTIME_MISSING` | no rule file at the last look |
| `0xffffffffffffffff` | `CHAOS_DNS_MTIME_UNKNOWN` | initial state; the first look always loads |
| `0xfffffffffffffffe` | `CHAOS_DNS_MTIME_RELOADING` | a reload is in progress |
| any other | — | stamp of the loaded file |

A stamp that collides with a sentinel is XORed with `0x9e3779b97f4a7c15`.

### Claim, load, publish

1. A thread whose stamp differs from the cached one CAS-es the cached value to
   `RELOADING` (`__sync_bool_compare_and_swap`, full barrier). Exactly one thread
   wins. A thread that loses, or that already sees `RELOADING`, uses the active
   snapshot and does not wait.
2. The winner reads the file into a static 256 KiB buffer with raw system calls.
   The buffer is not `__thread`: a TLS object that large is static TLS, which
   glibc reserves in every thread, and runtimes with small explicit thread stacks
   (the Erlang VM) then fail `pthread_create()` with `EINVAL`.
3. It `fstat`s the open file. If the stamp changed during the read (a concurrent
   writer), the copy is discarded and the claim is released with the old stamp,
   so the next look retries.
4. A file whose mtime is within 20 ms of now is loaded provisionally and read
   again on the next look, because a same-size rewrite within one tick leaves the
   stamp unchanged. If the content hash is unchanged on that read, the active
   snapshot stays as it is, with its hit counts and `@first` claims.
5. It parses into the inactive snapshot, attaches hit counters (a rule whose text
   is unchanged keeps its counter), and writes the status file.
6. It publishes: full barrier, store the new active index, full barrier, store
   the new stamp, which releases the claim.

### Readers

A reader fences, loads the active index and reads that snapshot. Each snapshot's
sequence counter is odd while it is being rewritten; a match that overlaps a
rewrite of the snapshot it read reports no match instead of a rule from a
half-written array. Readers never block: at worst one call uses the previous rule
set. A rule copy handed to a wrapper carries its hit slot and the slot's
generation; if the rule left the file in a later reload, the copy neither fires
nor counts.

### All-or-nothing

Parsing stops at the first invalid line. The new snapshot is then published empty
with `parse_ok = 0`, so a malformed file means no rules at all rather than the
previous rules or the first N lines of a file caught mid-write. The status file
names the rejected line.

---

## Failure Behaviour and Observability

### Failure behaviour

| Situation | Behaviour |
|-----------|-----------|
| No rule file | no rules; status file removed |
| Invalid line, unknown qualifier, more than 256 rules | whole file rejected; no rules; `state=error` naming the first bad line |
| File of 262 144 bytes or more, unreadable (`EACCES`, `EPERM`, `EISDIR`), contains a NUL byte | no rules, `state=error`; not re-read until the file changes |
| Transient read failure, concurrent writer | active snapshot kept; retried on the next look |
| Unsupported `sockaddr` family or short length (`getnameinfo`) | passthrough |
| NULL or empty `node` (`getaddrinfo`), NULL `result` | passthrough after LATENCY/GAI (`result`) or immediately (`node`) |
| SHUFFLE allocation failure | list returned unshuffled |
| OVERRIDE allocation failure or 256 live OVERRIDE lists | `EAI_MEMORY` |
| Real symbol missing at start-up | `abort()` |

The library's own system calls never leak into the caller's `errno`. Only an
injected `EAI_SYSTEM` (`EIO`), an `ERANGE`/`ENOSYS` failure described above, or
the real resolver set it.

### Status and hits files

After every load the library replaces `/tmp/.chaos-dns.status` (`state=ok|error`,
`rules=`, and on error `line=`, `reason=`, `text=`; then `pid=`); see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md#status-file). Each process writes
`/tmp/.chaos-dns.hits.<n>` with one `count<TAB>rule` line per rule: on each of
its first 64 hits, then at most every 100 ms, and at normal exit; see
[`docs/ARCHITECTURE.md`](ARCHITECTURE.md#hit-counters). A rule with count 0
parses but never matched a lookup the program made: check the exact name
(trailing dot, search-domain expansion happens below the wrapper) and whether the
program resolves through these functions at all.

---

## glibc vs musl Divergence

Platform-level divergences (link-map order, `AT_SECURE`, constructor order) are in
[`docs/PLATFORM.md`](PLATFORM.md). Resolver-specific ones:

- **`freeaddrinfo` allocation model.** musl allocates a `getaddrinfo()` result
  as one reference-counted block and frees by the block of the chain's last node;
  glibc allocates per node. This is why OVERRIDE copies its answer into a block of
  its own (see [Data Model](#data-model)). Releasing one isolated real node, as
  FILTER_FAMILY does, is correct on both: both walk `ai_next` from the node they
  are given.
- **NSS.** glibc's `getaddrinfo()` loads NSS backends (`libnss_*.so.2`) with
  `dlopen` on first use, and those backends run inside the real call, under the
  guard: any resolver call they make reaches the real function without rules.
  musl has a built-in resolver (hosts file and DNS) and no NSS module loading.
- **Internal resolver calls.** Any resolver function the C library calls
  internally while serving a wrapped call (for example from `getnameinfo()`) runs
  under the guard and is passed through unchanged, on either libc.
- **Reverse keys.** Both libcs format addresses with `inet_ntop` in the same
  canonical form (dotted decimal; RFC 5952 compressed IPv6), so a rule file works
  unchanged on both.
- **Rule file handling.** Identical: same path, same raw system calls, same
  parser.

---

## NSS Plumbing and the nsswitch.conf Stack

On glibc, `getaddrinfo(3)` is a dispatcher, not a DNS client: it consults
`/etc/nsswitch.conf` for the sources of the `hosts` database and their order.

```
hosts:   files dns
```

- `files`: `/etc/hosts` (`libnss_files`).
- `dns`: the libc stub resolver (`libnss_dns`), configured by `/etc/resolv.conf`
  (nameservers, search domains, options), UDP with TCP fallback for truncated
  responses.
- `resolve`: systemd-resolved over D-Bus (`libnss_resolve`, shipped by systemd),
  which adds LLMNR, mDNS, DNS-over-TLS and DNSSEC validation.
- `mdns4_minimal`: Avahi for `.local` names (not part of glibc).

Consequences:

- `libchaos-dns` acts before NSS dispatch. An injected `EAI_*` code means no NSS
  module is consulted; a passthrough proceeds through the configured sources.
- FILTER_FAMILY, SHUFFLE and LIMIT see whatever the sources returned, including
  `/etc/hosts` entries; the library cannot tell which source answered.
- Search-domain expansion happens inside the stub resolver: a rule for
  `dns://db` matches the application's query `db`, not the expanded
  `db.svc.cluster.local` sent on the wire.
- The D-Bus traffic of `nss_resolve` and the packets of `nss_dns` are below the
  wrapper. Failing LLMNR or DNS-over-TLS needs resolver configuration or a
  separate layer.

Reference: `nsswitch.conf(5)`, `resolv.conf(5)`, `nss(5)`.

## Legacy Resolver APIs — gethostbyname coverage, res_*() non-coverage

### gethostbyname / gethostbyaddr family

`gethostbyname(3)`, `gethostbyname2(3)`, their `_r` forms, `gethostbyaddr(3)` and
`gethostbyaddr_r(3)` return a `struct hostent`. glibc and musl serve them through
internal lookup code, never through `getaddrinfo()` or `getnameinfo()`, so the
library wraps them separately. `gethostbyname` and `gethostbyname_r` are the
`AF_INET` forms of `gethostbyname2`/`gethostbyname2_r`.

**Forward (`gethostbyname2`, `gethostbyname2_r`).** Rules are the `dns://` rules
of the name.

1. If the guard is set, the name is NULL or empty, or (for `_r`) `result` or
   `h_errnop` is NULL, call the real function.
2. LATENCY, then GAI. A GAI code is reported as `h_errno`: `EAI_NONAME` →
   `HOST_NOT_FOUND`, `EAI_AGAIN` → `TRY_AGAIN`, `EAI_NODATA`/`EAI_ADDRFAMILY`
   (where defined) → `NO_DATA`, anything else → `NO_RECOVERY`. The `_r` form
   returns 0 with `*result == NULL`, as libc does for a failed lookup; the other
   returns NULL.
3. If no REWRITE, OVERRIDE, FILTER_FAMILY, SHUFFLE or LIMIT rule matches the name,
   the real function answers unchanged (aliases included).
4. If one matches (whether or not it then fires), the answer comes from the
   `getaddrinfo()` pipeline (steps 4–11 above) with hints
   `{ai_family = family, ai_socktype = SOCK_STREAM, ai_flags = AI_CANONNAME}`,
   so both APIs see the same addresses. It is laid out as a `hostent`: no aliases,
   the addresses of the requested family, `h_name` the canonical name of the
   first node (else the queried name). A pipeline error maps to `h_errno` as in
   step 2; a list without an address of the family gives `NO_DATA`.
5. A buffer too small for the layout fails with `ERANGE` (the `_r` return value
   and `errno`), `h_errno` `NETDB_INTERNAL`, as libc does. The non-reentrant form
   lays out into a static 2048-byte buffer.

A SERVICE rule alone does not route a hostent lookup through the pipeline. Inside
the pipeline it only changes the port, which a `hostent` does not carry; a
service the resolver rejects fails the lookup (`NO_RECOVERY`).

**Reverse (`gethostbyaddr`, `gethostbyaddr_r`).** Rules are the `rdns://` rules of
the address, keyed with `inet_ntop` for `AF_INET` (length ≥ 4) and `AF_INET6`
(length ≥ 16); anything else is passed through.

1. LATENCY, then GAI, reported as above.
2. A REWRITE that fires replaces `h_name` of a successful real answer. The `_r`
   form reserves `strlen(name) + 1` bytes at the end of the caller's buffer,
   hands the real function the rest, and fails with `ERANGE`/`NETDB_INTERNAL`
   when the name alone exceeds the buffer. The non-reentrant form stores the name
   in a static 512-byte buffer and leaves `h_name` unchanged if it does not fit.

### res_*() — low-level resolver interface

`res_init()`, `res_query()`, `res_search()`, `res_mkquery()`, `res_send()` and
`dn_expand()` build and send DNS messages directly. They are not interposed:

1. Meaningful faults (NXDOMAIN, SERVFAIL) would require fabricating valid DNS
   response packets: header flags, RCODE, question and answer sections. That is
   a DNS server, not a preload library.
2. The symbols and `struct __res_state` differ between glibc (`libresolv`, where
   `<resolv.h>` renames the functions to `__res_*`) and musl.
3. Application code rarely calls them; mail servers, DNS utilities and custom
   tools do. Standard code uses `getaddrinfo()`.

For wire-level chaos use a DNS proxy (CoreDNS, dnsmasq) or `tc netem` on the
resolver's traffic. Reference: `resolver(3)`.

---

## Execution Boundary Summary

| Aspect | Library controls | Library does not control |
|--------|------------------|--------------------------|
| Query name | matched as written; replaced by REWRITE before the real call | search-domain expansion, label parsing |
| Resolution | replaced by OVERRIDE; otherwise passed through | NSS source order, nameservers, transport, retries |
| Result list | FILTER_FAMILY (family), SHUFFLE (order), LIMIT (count) | nodes before the transforms, TTLs, DNSSEC status |
| Errors | any of five `EAI_*` codes before the real call; `h_errno` for hostent APIs | errors of the real resolver on passthrough |
| Latency | LATENCY sleep, millisecond resolution, `clock_nanosleep` on `CLOCK_MONOTONIC` restarted on `EINTR` | network RTT, resolver backoff, scheduler jitter |
| Reverse text | `host` and `service` overwritten after a successful real call; `h_name` for `gethostbyaddr*` | PTR RRsets, `/etc/hosts` reverse entries, mDNS answers |
| Threads and processes | per-thread guard and PRNG; single-winner reload; atfork reset of claims, counts and PRNG | signal delivery, the C library's own atfork handlers |

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
