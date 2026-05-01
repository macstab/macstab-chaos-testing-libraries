<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# Engineering Notes

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

This document records repository-wide engineering rules and release discipline.
It still uses `libchaos-io` as the most detailed concrete example, but the
same expectations now apply across `libchaos-net`, `libchaos-dns`,
`libchaos-time`, `libchaos-memory`, and `libchaos-process`.
Subsystem-specific current-state details live in
[`docs/NETWORK.md`](NETWORK.md),
DNS-specific current-state details live in
[`docs/DNS.md`](DNS.md),
and time-specific current-state details live in
[`docs/TIME.md`](TIME.md),
and memory-specific current-state details live in
[`docs/MEMORY.md`](MEMORY.md),
and process-specific current-state details live in
[`docs/PROCESS.md`](PROCESS.md).

## Table of Contents

- [Scope](#scope)
- [How To Read The Code](#how-to-read-the-code)
- [File Responsibilities](#file-responsibilities)
- [Wrapper Semantics](#wrapper-semantics)
- [Config Model](#config-model)
- [Recursion And Internal Calls](#recursion-and-internal-calls)
- [Testing Philosophy](#testing-philosophy)
- [Extending The Library Safely](#extending-the-library-safely)
- [ABI Commitments](#abi-commitments)
- [Build Flag Rationale](#build-flag-rationale)
- [Maintenance Bar](#maintenance-bar)

## Scope

This repository ships deliberately small `LD_PRELOAD` libraries for Linux fault
injection. They are not general observability agents, not daemons, and not
full policy engines. Each library exists to do one job well: intercept a
narrow libc-facing surface and make it fail, slow down, or otherwise misbehave
under explicit rules.

The project is optimized for:

- small shared-library outputs
- deterministic behavior under test
- easy auditing of wrapper behavior
- explicit failure semantics

The project is not optimized for:

- feature breadth
- plugin systems
- runtime configuration APIs
- abstract framework design

Current maturity boundary:

- `libchaos-io` is at the repository's full bar: strict source-line coverage
  gate plus Docker runtime validation
- `libchaos-net` is now at the same bar: strict source-line coverage gate plus
  Docker runtime validation
- `libchaos-dns` is now inside the repository QA gate: enforced source-line
  coverage floor plus Docker runtime validation
- `libchaos-time` is now at the same bar: strict source-line coverage gate plus
  Docker runtime validation
- `libchaos-memory` is now at the same bar: strict source-line coverage gate
  plus Docker runtime validation
- `libchaos-process` is now at the same bar: strict source-line coverage gate
  plus Docker runtime validation

Repository-wide release discipline now also includes a `clang-format` check for
all shipped C sources and tests. Formatting is part of the quality gate, not a
best-effort cleanup step.

## How To Read The Code

If you are new to the repository, read each subsystem in the order listed below.
Each file is listed with a one-line description of its role.

### `libchaos-io`

1. [`src/core/chaos_io.c`](../src/core/chaos_io.c) — shared runtime core: constructor, symbol resolution, common fd-rule helper
2. [`src/core/chaos_io_wrappers.h`](../src/core/chaos_io_wrappers.h) — shared entry-point declarations
3. [`src/wrappers/chaos_io_open.c`](../src/wrappers/chaos_io_open.c) — path-first wrappers, openat resolution, fd-cache seeding
4. [`src/wrappers/chaos_io_rw.c`](../src/wrappers/chaos_io_rw.c) — read/write wrappers, iovec trimming, sendfile, copy_file_range
5. [`src/wrappers/chaos_io_fsops.c`](../src/wrappers/chaos_io_fsops.c) — ftruncate, fallocate, unlinkat, renameat; fd-cache invalidation
6. [`src/wrappers/chaos_io_sync.c`](../src/wrappers/chaos_io_sync.c) — close, fsync, fdatasync; post-success-only invalidation
7. [`src/config/chaos_io_config.c`](../src/config/chaos_io_config.c) — two-snapshot CAS reload, rule parser, operation/effect dispatch
8. [`src/effects/chaos_io_actions.c`](../src/effects/chaos_io_actions.c) — probability sampling, latency sleep, buffer corruption, torn-write sizing
9. [`src/config/chaos_io_fdcache.c`](../src/config/chaos_io_fdcache.c) — 32-slot direct-mapped fd→path cache, /proc/self/fd readlink on miss

### `libchaos-net`

1. [`src/net/chaos_net.c`](../src/net/chaos_net.c) — constructor: symbol resolution, PRNG seed, initial config load
2. [`src/net/chaos_net_config.c`](../src/net/chaos_net_config.c) — two-snapshot CAS reload, rule parser, endpoint-rank match selection
3. [`src/net/chaos_net_endpoint.c`](../src/net/chaos_net_endpoint.c) — sockaddr→endpoint translation: IPv4/IPv6 parsing, UNIX socket exclusion, accept/accept4 direction (output sockaddr, uses getsockname)
4. [`src/net/chaos_net_socket.c`](../src/net/chaos_net_socket.c) — connect/accept/send/recv wrappers
5. [`src/net/chaos_net_wait.c`](../src/net/chaos_net_wait.c) — select/poll/epoll wrappers, multi-fd scan, /proc/self/fdinfo epoll member lookup
6. [`src/net/chaos_net_actions.c`](../src/net/chaos_net_actions.c) — probability sampling, latency sleep, corruption draws, usleep chunking

### `libchaos-dns`

1. [`src/dns/chaos_dns.c`](../src/dns/chaos_dns.c) — constructor: symbol resolution, PRNG seed (raw /dev/urandom syscall), initial config load
2. [`src/dns/chaos_dns_config.c`](../src/dns/chaos_dns_config.c) — two-snapshot CAS reload, DNS rule parser, suffix-depth match selection
3. [`src/dns/chaos_dns_actions.c`](../src/dns/chaos_dns_actions.c) — getaddrinfo transform pipeline (FILTER_FAMILY → SHUFFLE → LIMIT), latency, EAI injection, REWRITE, SERVICE, OVERRIDE
4. [`src/dns/chaos_dns_lookup.c`](../src/dns/chaos_dns_lookup.c) — getaddrinfo and getnameinfo wrapper bodies

### `libchaos-time`

1. [`src/time/chaos_time.c`](../src/time/chaos_time.c) — constructor: symbol resolution, PRNG seed, initial config load
2. [`src/time/chaos_time_config.c`](../src/time/chaos_time_config.c) — two-snapshot CAS reload, time rule parser
3. [`src/time/chaos_time_actions.c`](../src/time/chaos_time_actions.c) — latency sleep chunks, OFFSET apply (signed nanosecond arithmetic, negative-clamp, CLOCK_MONOTONIC non-monotonicity), probability sampling
4. [`src/time/chaos_time_hooks.c`](../src/time/chaos_time_hooks.c) — clock_gettime, clock_getres, nanosleep, usleep wrappers

### `libchaos-memory`

1. [`src/memory/chaos_memory.c`](../src/memory/chaos_memory.c) — constructor: symbol resolution, PRNG seed, initial config load
2. [`src/memory/chaos_memory_config.c`](../src/memory/chaos_memory_config.c) — two-snapshot CAS reload, memory rule parser
3. [`src/memory/chaos_memory_actions.c`](../src/memory/chaos_memory_actions.c) — ERRNO injection, LATENCY, DELAY; why CORRUPT/OFFSET are absent from mmap
4. [`src/memory/chaos_memory_hooks.c`](../src/memory/chaos_memory_hooks.c) — mmap, mprotect, munmap, madvise wrappers; MAP_ANONYMOUS detection (flags & 0x20), glibc MMAP_THRESHOLD note

### `libchaos-process`

1. [`src/process/chaos_process.c`](../src/process/chaos_process.c) — constructor: symbol resolution, PRNG seed; `chaos_process_try_resolve_symbol` for musl's missing execveat
2. [`src/process/chaos_process_config.c`](../src/process/chaos_process_config.c) — two-snapshot CAS reload, process rule parser
3. [`src/process/chaos_process_actions.c`](../src/process/chaos_process_actions.c) — ERRNO injection, LATENCY (with vfork POSIX async-signal-safe hazard note), FAIL_AFTER counter logic (pre-increment, shared across threads, reset on reload)
4. [`src/process/chaos_process_hooks.c`](../src/process/chaos_process_hooks.c) — pthread_create, fork, posix_spawn, execve, execveat, waitpid wrappers; posix_spawn glibc/musl cascade gap; exec process-image replacement (library is gone after successful exec)

## File Responsibilities

### [`src/core/chaos_io.c`](../src/core/chaos_io.c)

This file owns shared runtime state and lifecycle setup.

Use it when:

- adding or resolving a downstream libc symbol
- changing recursion-guard boundaries
- changing constructor ordering
- changing shared fd-backed rule lookup behavior
- changing startup behavior

Do not use it for:

- wrapper-specific call flow
- probability math
- fd-cache policies

The main invariant is simple: shared runtime helpers should stay small, typed,
and obviously safe under preload recursion.

### [`src/wrappers/chaos_io_open.c`](../src/wrappers/chaos_io_open.c)

This file owns path-first wrappers and open-path resolution.

Use it when:

- adding or changing `open()` behavior
- adding or changing `openat()` behavior
- changing varargs forwarding for open-style calls
- changing pre-open path resolution and fd-cache seeding

Keep the `open()` and `openat()` wrappers together. They share ABI handling,
rule matching, and post-open cache population.

### [`src/wrappers/chaos_io_rw.c`](../src/wrappers/chaos_io_rw.c)

This file owns read- and write-side wrappers.

Use it when:

- adding a new fd-backed data-path wrapper
- changing when read corruption is applied
- changing when torn writes are applied
- changing Linux `sendfile()` or `copy_file_range()` behavior

The invariant here is operational symmetry: read-style wrappers should stay
read-like, write-style wrappers should stay write-like, and Linux
`sendfile()` plus `copy_file_range()` must remain explicitly destination-side.

### [`src/wrappers/chaos_io_fsops.c`](../src/wrappers/chaos_io_fsops.c)

This file owns size-change and path-identity wrappers.

Use it when:

- adding or changing `ftruncate()` behavior
- adding or changing Linux `fallocate()` behavior
- adding or changing `unlinkat()` behavior
- adding or changing `renameat()` behavior
- changing how successful path-identity changes invalidate the fd cache

Keep the policy narrow here. These wrappers support only errno injection and
latency. If they start growing torn-write or corruption semantics, the config
model is drifting.

### [`src/wrappers/chaos_io_sync.c`](../src/wrappers/chaos_io_sync.c)

This file owns close and persistence-boundary wrappers.

Use it when:

- changing `close()` semantics
- changing sync-wrapper behavior
- changing how fd-cache invalidation relates to successful close

Keep these wrappers boring. If they grow effect-specific policy beyond latency
and errno injection, the design is probably drifting.

### [`src/config/chaos_io_config.c`](../src/config/chaos_io_config.c)

This file owns config ingestion and rule selection.

Use it when:

- extending the config grammar
- adding a new operation or effect
- changing reload behavior
- changing prefix-matching semantics

The critical invariants are:

- invalid config means passthrough, not partial activation
- longest prefix wins
- prefix matching is path-boundary aware
- one thread may reload, many threads may read

### [`src/effects/chaos_io_actions.c`](../src/effects/chaos_io_actions.c)

This file owns effect mechanics, not rule lookup.

Use it when:

- changing probability behavior
- changing how torn writes are sized
- changing corruption behavior
- changing latency application

The wrappers should not reimplement effect logic. If the same branching starts
appearing in multiple wrappers, it belongs here instead.

### [`src/config/chaos_io_fdcache.c`](../src/config/chaos_io_fdcache.c)

This file translates descriptor-based calls back into paths.

Use it when:

- changing cache size or policy
- changing how `/proc/self/fd/<fd>` results are filtered
- changing when cache entries are stored or invalidated

The cache is intentionally small and direct-mapped. That is a deliberate trade:
the library prefers simple predictable code and a tiny footprint over perfect
hit ratios.

### [`src/net/chaos_net.c`](../src/net/chaos_net.c)

This file owns the network subsystem's runtime state and constructor.

Use it when:

- adding or resolving a downstream network libc symbol
- changing the PRNG seed path
- changing constructor ordering or startup behavior
- changing reentrancy-guard boundaries shared across network wrappers

Do not use it for:

- wrapper-specific call flow
- endpoint translation logic
- config parse rules

### [`src/net/chaos_net_config.c`](../src/net/chaos_net_config.c)

This file owns network config ingestion and endpoint-rank match selection.

Use it when:

- extending the network config grammar
- adding a new network operation or effect
- changing reload behavior
- changing how endpoint rank comparisons are ordered

The critical invariants mirror the IO config model: invalid config means
passthrough, the two-snapshot CAS must remain all-or-nothing, and one thread
may reload while many threads read.

### [`src/net/chaos_net_endpoint.c`](../src/net/chaos_net_endpoint.c)

This file owns sockaddr-to-endpoint translation.

Use it when:

- adding support for a new address family
- changing how IPv4-mapped IPv6 addresses are normalized
- changing UNIX socket exclusion policy
- changing how the accept/accept4 direction is determined via getsockname

Do not use it for wrapper flow, probability math, or config parsing. Its
single job is translating a raw sockaddr into a matchable endpoint
representation.

### [`src/net/chaos_net_socket.c`](../src/net/chaos_net_socket.c)

This file owns the connect, accept, send, and recv wrapper bodies.

Use it when:

- adding or changing connect behavior
- adding or changing accept or accept4 behavior
- adding or changing send, sendto, recv, or recvfrom behavior
- changing how endpoint resolution feeds into rule matching for each call

Keep this file's scope limited to the four logical operation families. If a new
network call does not naturally belong with connect, accept, send, or recv, it
may warrant its own translation unit.

### [`src/net/chaos_net_wait.c`](../src/net/chaos_net_wait.c)

This file owns the multiplexed-wait wrappers.

Use it when:

- adding or changing select behavior
- adding or changing poll behavior
- adding or changing epoll_wait behavior
- changing how epoll member fd sets are discovered via /proc/self/fdinfo
- changing multi-fd scan logic

The critical invariant here is that multi-fd scans must not allocate heap
memory. All fd enumeration must remain on-stack or use fixed-size arrays.

### [`src/net/chaos_net_actions.c`](../src/net/chaos_net_actions.c)

This file owns network effect mechanics.

Use it when:

- changing probability behavior for network operations
- changing latency application or usleep chunking
- changing corruption draw logic
- adding a new network effect

Network wrappers must not reimplement effect logic. If the same branching starts
appearing in multiple network wrappers, it belongs here.

### [`src/dns/chaos_dns.c`](../src/dns/chaos_dns.c)

This file owns the DNS subsystem's runtime state and constructor.

Use it when:

- adding or resolving a downstream resolver libc symbol
- changing the PRNG seed path (note: uses a raw /dev/urandom syscall, not the
  shared libc read path, to avoid preload recursion at constructor time)
- changing constructor ordering or startup behavior

Do not use it for wrapper bodies, transform pipeline logic, or config parsing.

### [`src/dns/chaos_dns_config.c`](../src/dns/chaos_dns_config.c)

This file owns DNS config ingestion and suffix-depth match selection.

Use it when:

- extending the DNS config grammar
- adding a new DNS operation or effect
- changing reload behavior
- changing how suffix-depth match ranking is computed

The invariants are the same as all other subsystem config files: invalid config
means passthrough, the two-snapshot CAS must remain all-or-nothing.

### [`src/dns/chaos_dns_actions.c`](../src/dns/chaos_dns_actions.c)

This file owns the getaddrinfo transform pipeline and DNS effect mechanics.

Use it when:

- changing FILTER_FAMILY, SHUFFLE, or LIMIT pipeline stage ordering
- changing EAI error injection
- adding a new DNS transform effect (REWRITE, SERVICE, OVERRIDE, etc.)
- changing latency application

The pipeline ordering (FILTER_FAMILY → SHUFFLE → LIMIT) is intentional. Do not
reorder stages without understanding how each stage feeds the next. The pipeline
must remain side-effect-free with respect to the caller's original addrinfo
list until all transforms are complete.

### [`src/dns/chaos_dns_lookup.c`](../src/dns/chaos_dns_lookup.c)

This file owns the getaddrinfo and getnameinfo wrapper bodies.

Use it when:

- changing how getaddrinfo results are handed off to the transform pipeline
- changing getnameinfo fault injection behavior
- adding a new resolver symbol wrapper

Keep this file's scope limited to wrapper entry, rule lookup, and pipeline
dispatch. Effect logic belongs in `chaos_dns_actions.c`.

### [`src/time/chaos_time.c`](../src/time/chaos_time.c)

This file owns the time subsystem's runtime state and constructor.

Use it when:

- adding or resolving a downstream time libc symbol
- changing the PRNG seed path
- changing constructor ordering or startup behavior
- changing reentrancy-guard boundaries

Do not use it for wrapper bodies, offset arithmetic, or config parsing.

### [`src/time/chaos_time_config.c`](../src/time/chaos_time_config.c)

This file owns time config ingestion and rule selection.

Use it when:

- extending the time config grammar
- adding a new time operation or effect
- changing reload behavior
- changing how clock-id matching is performed

The invariants are the same as all other subsystem config files.

### [`src/time/chaos_time_actions.c`](../src/time/chaos_time_actions.c)

This file owns time effect mechanics including OFFSET arithmetic.

Use it when:

- changing latency sleep chunking behavior
- changing the OFFSET effect (signed nanosecond arithmetic, negative-clamp to
  zero, CLOCK_MONOTONIC non-monotonicity handling)
- changing probability sampling
- adding a new time effect

The OFFSET logic must preserve the constraint that CLOCK_MONOTONIC results
never go backward: clamping to the previous value is correct; returning a
value less than the last observed value is not.

### [`src/time/chaos_time_hooks.c`](../src/time/chaos_time_hooks.c)

This file owns the clock_gettime, clock_getres, nanosleep, and usleep wrapper
bodies.

Use it when:

- changing how clock_gettime results are post-processed by the actions layer
- changing nanosleep or usleep interception behavior
- adding a new time-related symbol wrapper

Keep wrapper entry, reentrancy guard, and action dispatch together per symbol.
Do not inline effect logic here; it belongs in `chaos_time_actions.c`.

### [`src/memory/chaos_memory.c`](../src/memory/chaos_memory.c)

This file owns the memory subsystem's runtime state and constructor.

Use it when:

- adding or resolving a downstream memory libc symbol
- changing the PRNG seed path
- changing constructor ordering or startup behavior
- changing reentrancy-guard boundaries

Do not use it for wrapper bodies, MAP_ANONYMOUS detection, or config parsing.

### [`src/memory/chaos_memory_config.c`](../src/memory/chaos_memory_config.c)

This file owns memory config ingestion and rule selection.

Use it when:

- extending the memory config grammar
- adding a new memory operation or effect
- changing reload behavior
- changing how mmap operation-class matching is performed

The invariants are the same as all other subsystem config files.

### [`src/memory/chaos_memory_actions.c`](../src/memory/chaos_memory_actions.c)

This file owns memory effect mechanics.

Use it when:

- changing ERRNO injection behavior
- changing LATENCY or DELAY effect logic
- adding a new memory effect

CORRUPT and OFFSET are deliberately absent from mmap effects. mmap returns a
virtual address range, not a value buffer; corrupting the mapping contents
after return would affect live process memory in an uncontrolled way. If a
future design needs that, it requires a separate, explicitly scoped mechanism
and must not be added here without that design.

### [`src/memory/chaos_memory_hooks.c`](../src/memory/chaos_memory_hooks.c)

This file owns the mmap, mprotect, munmap, and madvise wrapper bodies.

Use it when:

- changing MAP_ANONYMOUS detection logic (flags & 0x20)
- changing how the glibc MMAP_THRESHOLD interacts with mmap interception
- adding a new memory-related symbol wrapper
- changing how mprotect or madvise faults are injected

Keep the MAP_ANONYMOUS flag check and the MMAP_THRESHOLD note as comments in
the code. These are non-obvious platform behaviors that future readers must not
accidentally remove.

### [`src/process/chaos_process.c`](../src/process/chaos_process.c)

This file owns the process subsystem's runtime state and constructor.

Use it when:

- adding or resolving a downstream process libc symbol
- changing the PRNG seed path
- changing constructor ordering or startup behavior
- changing the `chaos_process_try_resolve_symbol` path for optional symbols
  (execveat is absent from musl; the try-resolve path must remain to handle
  that gracefully)

Do not use it for wrapper bodies, FAIL_AFTER counter logic, or config parsing.

### [`src/process/chaos_process_config.c`](../src/process/chaos_process_config.c)

This file owns process config ingestion and rule selection.

Use it when:

- extending the process config grammar
- adding a new process operation or effect
- changing reload behavior
- changing how process-name or operation-class matching is performed

The invariants are the same as all other subsystem config files. Note that
FAIL_AFTER counters are reset on every config reload; this is intentional and
must remain true after any config change.

### [`src/process/chaos_process_actions.c`](../src/process/chaos_process_actions.c)

This file owns process effect mechanics including FAIL_AFTER counter logic.

Use it when:

- changing ERRNO injection behavior
- changing LATENCY effect logic (note: vfork is async-signal-safe constrained;
  usleep inside a vfork child is a POSIX hazard and must not be added)
- changing the FAIL_AFTER counter (pre-increment, shared across threads, reset
  on reload)
- adding a new process effect

The FAIL_AFTER counter is deliberately not per-thread. A per-thread counter
would allow thread N to always succeed if thread M already consumed the limit.
If you change this, document the semantic change explicitly.

### [`src/process/chaos_process_hooks.c`](../src/process/chaos_process_hooks.c)

This file owns the pthread_create, fork, posix_spawn, execve, execveat, and
waitpid wrapper bodies.

Use it when:

- adding or changing pthread_create injection behavior
- adding or changing fork injection behavior
- changing posix_spawn behavior (note: glibc and musl differ in how they
  implement posix_spawn internally; the cascade gap between glibc's internal
  clone and musl's exec-based posix_spawn must be documented in comments)
- changing execve or execveat behavior (note: exec replaces the process image;
  the chaos library is gone after a successful exec, so post-exec state
  invalidation is not possible and must not be attempted)
- adding or changing waitpid injection behavior

The exec process-image replacement constraint is fundamental. Any wrapper that
injects into exec-family calls must complete all fault decisions before the
real exec call. There is no wrapper return path after a successful exec.

## Wrapper Semantics

### `open()` and `openat()`

`open()` and `openat()` are the wrappers that naturally start from a path. That
makes them special in two ways:

- it performs direct path-based matching without going through fd resolution
- it seeds the fd cache for later descriptor-based calls

`openat()` adds one extra rule: when the pathname is relative, the wrapper tries
to resolve a match path from `AT_FDCWD` or from the supplied directory fd before
rule selection. If that pre-open resolution fails, the wrapper must bypass
pre-call injection and rely on post-open fd resolution only.

If you extend open-path behavior, keep those responsibilities together.

### `read()`, `readv()`, `pread()`, and `preadv()`

Read-style wrappers may:

- delay before the real call
- fail before the real call
- corrupt the returned buffer after a successful real call

They do not truncate the requested byte count before delegation. Any corruption
happens after libc has already returned data.

`readv()` and `preadv()` must preserve that contract across the logical
concatenation of the returned iovec buffers. Corruption sampling therefore
happens across the total byte stream, not independently per segment.

### `write()`, `writev()`, `pwrite()`, `pwritev()`, and Linux `sendfile()` / `copy_file_range()`

Write-style wrappers may:

- delay before the real call
- fail before the real call
- shorten the outgoing byte count before delegation for torn-write behavior

They do not modify the caller buffer. Torn writes are modeled as partial writes,
not buffer corruption.

`writev()` and `pwritev()` must apply torn-write sizing across the logical
total byte span and then translate that shortened byte budget back into a valid
truncated iovec array for the real libc call.

Linux `sendfile()` and `copy_file_range()` now reuse the same logical `write`
rule class, but they match on the destination fd only. There is no read-side
corruption path for either call because there is no caller-visible read buffer
to mutate.

The remaining gap is other alternate copy paths. Tools that move data through
`splice()`, `mmap()`, or similar non-`write()`, non-`writev()`,
non-`sendfile()`, and non-`copy_file_range()` paths are still outside the
current fault surface.

### `ftruncate()`, Linux `fallocate()`, `unlinkat()`, and `renameat()`

These wrappers model filesystem lifecycle and capacity edges without changing
the basic rule engine:

- `ftruncate()` matches the logical `truncate` rule class on the target fd path
- Linux `fallocate()` matches the logical `allocate` rule class on the target
  fd path
- `unlinkat()` matches the logical `unlink` rule class on the resolved target
  path
- `renameat()` matches `rename_from` and `rename_to` on the resolved source and
  destination paths

`renameat()` keeps source and destination separate on purpose. Atomic replace
patterns often care more about the destination pathname than about the original
temporary source. Successful `unlinkat()` and `renameat()` reset the current
thread fd cache because already-cached `/proc/self/fd` resolutions may no
longer describe the same pathname.

### `close()`

`close()` has one subtle requirement that is easy to regress: cache invalidation
must only happen after a successful real close. Invalidating earlier would make
the cache lie if the close fails.

### `fsync()` and `fdatasync()`

These wrappers are intentionally boring. They exist because persistence
boundaries are often where higher-level systems surface failures. Keep them
boring. If they start carrying wrapper-specific policy, that policy probably
belongs elsewhere.

## Config Model

Each rule is parsed once into a fixed-size in-memory representation. Reload
works by writing the next rule set into the inactive snapshot and then flipping
the active index. Readers never mutate the active snapshot in place.

That design gives this project three useful properties:

- readers stay cheap
- invalid config can be rejected cleanly
- reload never requires allocating a dynamic rule graph

Path matching is prefix-based, but not naive string-prefix matching. `/data`
must match `/data/file` and must not match `/database`. If you change path
semantics, preserve that boundary behavior unless you are intentionally changing
the config contract.

## Recursion And Internal Calls

The recursion guard is not optional defensive coding. It is the mechanism that
keeps the preload library from trapping itself.

Any code path that touches:

- real libc symbols
- `stat()`
- `/proc/self/fd`
- `/dev/urandom`
- config-file reads

must be deliberate about entering and leaving internal mode. If you add a new
helper that performs I/O and it is reachable from a wrapper, assume it needs a
guard boundary unless you can prove otherwise.

## Testing Philosophy

The tests are intentionally close to the implementation.

- parser tests include config internals directly so malformed input and reload
  edges can be tested precisely
- wrapper tests include the wrapper implementation files directly through
  [`test/support/test_chaos_io_harness.h`](../test/support/test_chaos_io_harness.h)
  so every branch can be forced without needing a real preload environment
- integration tests still exist to validate the real shared library on Linux

This is a low-level systems library. Direct source inclusion in tests is a
feature here, not a smell.

To verify the complete test suite passes from a clean state:

```sh verified
make unit
```

To verify all six native shared libraries build successfully (Linux only):

```sh verified
[ "$(uname -s)" != "Linux" ] && exit 0; make native
```

## Extending The Library Safely

### Adding a new interposed symbol to an existing subsystem

1. Add the enum value in `src/<subsystem>/chaos_<subsystem>_config.h`.
2. Add parser dispatch in `src/<subsystem>/chaos_<subsystem>_config.c`.
3. Add the real libc symbol pointer in `src/<subsystem>/chaos_<subsystem>_internal.h`
   (typedef + extern).
4. Resolve the symbol in the constructor. Use `chaos_<subsystem>_resolve_symbol`
   for symbols that are guaranteed present, or `chaos_<subsystem>_try_resolve_symbol`
   for optional symbols (such as execveat on musl, which may be absent).
5. Add the wrapper in `src/<subsystem>/chaos_<subsystem>_hooks.c`.
6. Ensure the TLS reentrancy guard is saved, set, and restored in the correct
   order at wrapper entry. The guard must be raised before any call to real libc
   and must be restored on every exit path, including error returns.
7. Add direct unit coverage for every new branch; keep `make coverage` at 100%.

### Adding a new effect to an existing subsystem

1. Add the enum value in the subsystem config header.
2. Define which operations are allowed to use it (validation in the config
   parser).
3. Add parser support.
4. Add effect logic in `chaos_<subsystem>_actions.c` (or a new helper if the
   logic cannot live there cleanly).
5. Wire wrapper branches in `chaos_<subsystem>_hooks.c`.
6. Add deterministic tests first, then integration coverage where it matters.

### Cross-subsystem invariants for any extension

- Never allocate heap memory on the hot path inside a wrapper.
- Any code path that calls real libc must raise the reentrancy guard before
  the call.
- Config reload must remain all-or-nothing: partially-parsed config must never
  activate. The two-snapshot CAS flip happens only after a fully validated
  parse.
- `CHAOS_<SUBSYSTEM>_EXPORT` is applied only to the wrapper symbols that
  replace libc symbols — never to internal helpers.

## ABI Commitments

### Shared Object ABI Surface

The exported symbol surface of each chaos library is intentionally minimal.
`__attribute__((visibility("default")))` (the `CHAOS_*_EXPORT` macro defined in
each library's `_internal.h`) is applied only to the interposed libc symbols.
Everything else uses the default `-fvisibility=hidden` compilation unit default.

This means:

- Only the symbols that need to be found by the dynamic linker (the interposed
  function names) are in the `.dynsym` table.
- Internal helpers (`chaos_*_check_config`, `chaos_*_enter_internal`, etc.) are
  not exported. They cannot conflict with symbols in the target application.
- The `.gnu.hash` and `.gnu.version` tables are smaller; dynamic linker symbol
  lookup is faster.

### ELF `SONAME`

Each `.so` is built with `-Wl,-soname,libchaos-<lib>-<libc>-<arch>.so`. The
SONAME is embedded in the ELF `DT_SONAME` entry. The target process's
`LD_PRELOAD` string must match the filename (not the SONAME, in LD_PRELOAD
context — but the SONAME is used if the library is listed in `DT_NEEDED`).

### No Public C API

There is no header file that callers should include. The libraries have no
`libchaos-*.h` installation target. The ABI contract is:

1. Load via `LD_PRELOAD`.
2. Write a config file at the documented path.
3. The interposed symbols are active; no function calls needed.

This is a deliberate design: a public C API would create versioning
obligations, calling-convention commitments, and a compatibility surface that
would constrain refactoring. None of those apply to a preload-only library.

## Build Flag Rationale

Each chaos library is built with the following flags (in addition to standard
`-std=c99 -Wall -Wextra -Werror`). The rationale for each is documented here.

### `-fvisibility=hidden`

All symbols default to hidden (not in `.dynsym`). Only symbols marked with
`__attribute__((visibility("default")))` are exported. Purpose:

- Prevents symbol collision with target application symbols of the same name.
- Prevents the dynamic linker from using the library's internal symbols when
  resolving other libraries' references.
- Reduces `.dynsym` and `.gnu.hash` table sizes.

Without this flag, internal helpers like `chaos_io_check_config` would be in
`.dynsym` and could shadow identically-named symbols in the target application
or other preloaded libraries.

### `-ffunction-sections` and `-fdata-sections`

Places each function and data object in its own ELF section
(`.text.<function_name>`, `.data.<variable_name>` etc.). Purpose:

- Enables the linker to dead-strip unused functions and data with `--gc-sections`.
- Without this flag, the linker operates at translation-unit granularity; any
  reference to any symbol in a `.o` forces the entire `.o` into the output.

Effect in practice: for a chaos library that includes the full config parser
but is loaded in a context where only passthrough is used, dead-stripping
removes the unreachable parse branches from the `.so`.

### `-Wl,--gc-sections`

The linker dead-strips sections not reachable from the entry point. Combined
with `-ffunction-sections`, this removes:

- Unreachable config parser branches (e.g., effects defined for future use)
- Cold-path error-handling functions not reachable from normal execution
- Unused wrapper families if any were accidentally left in

In practice for a heavily tested codebase with 100% coverage, `--gc-sections`
should remove very little, but it is a correctness check: if something is
being stripped that should not be, it reveals a dead-code issue.

### `-Wl,--strip-all`

Strips all symbol table entries and relocation sections from the final `.so`
that are not required for dynamic linking. Keeps:

- `.dynsym` (exported symbols: the interposed libc wrappers)
- `.gnu.hash` / `.hash` (used by the dynamic linker for symbol lookup)
- `.rela.dyn` / `.rela.plt` (runtime relocations)
- `.eh_frame` (if not stripped by `-fno-asynchronous-unwind-tables`)

Strips:
- `.symtab` (static symbol table, used by debuggers and `nm`)
- `.strtab` (string table for `.symtab`)
- `.debug_*` (DWARF debug info, if present)

Purpose: reduces `.so` size; removes information that could help an attacker
understand internal structure. For release builds. Debug builds omit this flag.

### `-fno-asynchronous-unwind-tables`

Suppresses the generation of `.eh_frame` (exception handling frame) and
`.ARM.exidx` tables. These tables support:

- C++ exception unwinding (not needed: library is C99, no exceptions)
- `libunwind` / `backtrace()` call-stack unwinding through the chaos library
- GCC/Clang frame-pointer-free stack unwinding (`-fomit-frame-pointer`)

Purpose: removes ~2-5 KB of `.eh_frame` data from the `.so`. Unwinding through
the chaos library is not needed for correct operation. If you need stack traces
that include chaos library frames for debugging, remove this flag in the debug
build variant.

**Trade-off:** `perf record` and similar profiling tools can still profile the
chaos library by frame pointer if `-fno-omit-frame-pointer` is set (the default
for most debug builds). `--strip-all` does not affect profiling because the
profiler reads the vDSO and kernel symbol tables separately.

### `-fno-stack-protector`

Disables the GCC/Clang stack smashing protection (`-fstack-protector-strong`
inserts a canary value between the return address and local variables). Purpose
of disabling:

1. Stack canary checking calls `__stack_chk_fail()` on failure. This function
   calls `write()` to `stderr`. `write()` is interposed by `libchaos-io`. A
   stack canary failure inside `libchaos-io` would re-enter the IO wrapper,
   triggering the reentrancy guard and calling the real `write()` — but the
   reentrancy guard's TLS access itself calls the library's constructor path,
   which is partially active. This creates an undefined-behaviour chain.
2. The chaos libraries have no user-controlled input buffers that could overflow.
   Config parsing uses bounded fixed-size buffers with explicit length checks.
   The stack-protector canary adds overhead without a corresponding threat
   surface.
3. If the linked glibc/musl has stack protection enabled (which it does), and
   the chaos library code is inlined into a glibc function by LTO (which doesn't
   happen with preload), the canary would still fire from glibc's own protection.
   The two mechanisms are independent.

**Note for hardening auditors:** the absence of `-fstack-protector` is deliberate
and is compensated by: strict bounded buffer usage, no `gets()`/`scanf()`, 100%
source coverage gate (ensuring all buffer-access branches are tested), and
`-Wall -Wextra -Werror` catching off-by-one warnings at compile time.

### Summary Table

| Flag                              | Effect                                      | Why                                       |
|-----------------------------------|---------------------------------------------|-------------------------------------------|
| `-fvisibility=hidden`             | All symbols hidden by default               | No symbol collision; minimal .dynsym      |
| `-ffunction-sections`             | One section per function                    | Enables --gc-sections dead-strip          |
| `-fdata-sections`                 | One section per data object                 | Enables --gc-sections dead-strip          |
| `-Wl,--gc-sections`               | Dead-strip unreachable sections             | Smaller .so; dead-code check              |
| `-Wl,--strip-all`                 | Remove non-dynamic symbol tables            | Smaller .so; less info leakage            |
| `-fno-asynchronous-unwind-tables` | No .eh_frame                                | Removes ~2-5 KB; no C++ unwinding needed  |
| `-fno-stack-protector`            | No stack canary                             | Avoids write() re-entrancy in canary path |

## Maintenance Bar

Good changes in this repository usually have these properties:

- they make the wrapper flow easier to audit, not harder
- they do not add dynamic allocation to hot paths
- they do not weaken passthrough behavior on invalid config
- they preserve or improve test determinism
- they do not inflate the shared object for cosmetic abstraction

If a change fights those constraints, it needs a stronger argument than "it is
more generic."

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
