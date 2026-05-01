<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# Architecture

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

This document describes the repository-wide preload architecture and uses
`libchaos-io` as the reference implementation for the common execution model.
The repository also ships implemented `libchaos-net`, `libchaos-dns`,
`libchaos-time`, `libchaos-memory`, and `libchaos-process` libraries.
Each of those libraries has its own current-state technical reference:

- `libchaos-net` in
[`docs/NETWORK.md`](NETWORK.md)
- `libchaos-dns` in
[`docs/DNS.md`](DNS.md),
- `libchaos-time` in
[`docs/TIME.md`](TIME.md),
- `libchaos-memory` in
[`docs/MEMORY.md`](MEMORY.md),
- `libchaos-process` in
[`docs/PROCESS.md`](PROCESS.md).

## Table of Contents

- [Purpose](#purpose)
- [Execution Model](#execution-model)
- [Config Reloading](#config-reloading)
- [FD Path Resolution](#fd-path-resolution)
- [Fault Effects](#fault-effects)
- [Testing Strategy](#testing-strategy)
- [Platform Internals and Symbol Resolution](#platform-internals-and-symbol-resolution)
- [Formal Symbol-Ownership Theorem](#formal-symbol-ownership-theorem)
- [Maintenance Rules](#maintenance-rules)

## Purpose

Repository-wide, these libraries exist to inject controlled Linux libc-boundary
failures through small `LD_PRELOAD` shared objects. The sections below describe
that shared architecture through the `libchaos-io` implementation, because it
is still the clearest example of the common preload model.

The code stays intentionally narrow:

- no public SDK
- no config daemon
- no background thread
- no allocator-heavy data structures

## Execution Model

### Library initialization

[`src/core/chaos_io.c`](../src/core/chaos_io.c)

- Resolves the real libc symbols with `dlsym(RTLD_NEXT, ...)`.
- Seeds process entropy from `/dev/urandom`, with a deterministic fallback when that read fails.
- Seeds the current thread PRNG.
- Resets config and fd-cache state.
- Shares common fd-rule matching used by the wrapper translation units.

### Request flow

For each intercepted operation:

1. If the thread is already inside library internals, call straight through.
2. Ignore excluded paths and excluded fds.
3. Refresh config if the config mtime changed.
4. Match the path and operation against the active rules.
5. Apply latency, errno injection, torn writes, or read corruption.
6. Call the real libc symbol.
7. Update the fd cache when needed.

Wrapper families are split by responsibility:

- [`src/wrappers/chaos_io_fsops.c`](../src/wrappers/chaos_io_fsops.c)
  owns `ftruncate()`, Linux `fallocate()`, `unlinkat()`, and `renameat()`.
- [`src/wrappers/chaos_io_open.c`](../src/wrappers/chaos_io_open.c)
  owns `open()` and `openat()`.
- [`src/wrappers/chaos_io_rw.c`](../src/wrappers/chaos_io_rw.c)
  owns `read()`, `readv()`, `write()`, `writev()`, `pread()`, `preadv()`,
  `pwrite()`, `pwritev()`, and Linux `sendfile()` plus `copy_file_range()`.
- [`src/wrappers/chaos_io_sync.c`](../src/wrappers/chaos_io_sync.c)
  owns `close()`, `fsync()`, and `fdatasync()`.

Diagram — full dispatcher call flow ([source](diagrams/dispatch.puml)):

```plantuml
@startuml dispatch
title Full Dispatcher Flow — Interposed Symbol with Matched Rule

skinparam sequenceMessageAlign center
skinparam shadowing false
skinparam roundCorner 4
skinparam sequence {
  ArrowColor                 #2C3E50
  LifeLineBorderColor        #2C3E50
  LifeLineBackgroundColor    #ECF0F1
  ParticipantBorderColor     #2C3E50
  ParticipantBackgroundColor #FFFFFF
  ParticipantFontStyle       bold
  GroupBackgroundColor       #FDFEFE
  GroupBorderColor           #95A5A6
}
hide footbox

participant "Application"    as App
participant "Wrapper"        as Wrap
participant "TLS Guard"      as Guard
participant "Config Engine"  as Config
participant "Selector\nResolver" as Sel
participant "Effect Engine"  as FX
participant "Real Symbol\n(libc)"  as Real

App -> Wrap : symbol(args…)

Wrap -> Guard : enter_internal()
note right of Guard
  __thread int guard;
  previous = guard;
  guard = 1;
  if previous != 0: bypass all injection
end note

alt Guard was already set (reentrancy)
  Wrap -> Real : direct call, no injection
  Real --> Wrap : result
  Wrap -> Guard : leave_internal(previous)
  Wrap --> App : result
else Guard was clear (normal path)

  Wrap -> Config : check_config()
  note right of Config
    stat(config_path)
    if mtime changed:
      CAS(mtime, old, RELOADING)
      reload + parse
      CAS(mtime, RELOADING, new)
  end note
  Config --> Wrap : active_snapshot

  Wrap -> Sel : resolve_selector(args…)
  note right of Sel
    IO: fd → /proc/self/fd path
    NET: sockaddr → endpoint string
    TIME: clockid → clock name
    MEM: MAP_ANONYMOUS bit
    PROC: symbol name
  end note
  Sel --> Wrap : selector_string

  Wrap -> Config : select_rule(op, selector)
  Config --> Wrap : matched_rule (or null)

  alt No rule matched
    Wrap -> Real : real_symbol(args…)
    Real --> Wrap : result
    Wrap -> Guard : leave_internal(previous)
    Wrap --> App : result
  else Rule matched
    Wrap -> FX : apply_latency(rule)
    note right of FX
      if rule.effect == LATENCY:
        real_nanosleep(ms → ns)
      (reentrancy guard already set;
       nanosleep bypasses own wrapper)
    end note

    Wrap -> FX : apply_pre_errno(rule)
    note right of FX
      if rule.effect == ERRNO and
         PRNG()/UINT32_MAX ≤ probability:
        errno = rule.errnum; return fail
    end note

    alt ERRNO triggered
      FX --> Wrap : inject failure
      Wrap -> Guard : leave_internal(previous)
      Wrap --> App : -1 or error code, errno set
    else No pre-call failure
      Wrap -> Real : real_symbol(args…)
      Real --> Wrap : result

      alt Post-call mutation (OFFSET / CORRUPT)
        Wrap -> FX : apply_post_mutation(rule, result)
        note right of FX
          OFFSET: ts += offset_ms
          CORRUPT: flip one bit in read buffer
        end note
        FX --> Wrap : mutated result
      end

      Wrap -> Guard : leave_internal(previous)
      Wrap --> App : result (possibly mutated)
    end
  end
end

@enduml
```

## Config Reloading

[`src/config/chaos_io_config.c`](../src/config/chaos_io_config.c)

- The config cache uses two snapshots.
- Reload writes into the inactive snapshot, then atomically flips the active index.
- Missing config means empty passthrough state.
- Invalid config means empty passthrough state.
- Matching uses longest-prefix wins with path-boundary checks.

That boundary rule is important:

- `/data` matches `/data/file`
- `/data` does not match `/database`

Diagram — two-snapshot CAS config reload ([source](diagrams/config_reload.puml)):

```plantuml
@startuml config_reload
title Two-Snapshot CAS Config Reload — Winner and Loser Threads

skinparam sequenceMessageAlign center
skinparam shadowing false
skinparam roundCorner 4
skinparam sequence {
  ArrowColor                 #2C3E50
  LifeLineBorderColor        #2C3E50
  LifeLineBackgroundColor    #ECF0F1
  ParticipantBorderColor     #2C3E50
  ParticipantBackgroundColor #FFFFFF
  ParticipantFontStyle       bold
  GroupBackgroundColor       #FDFEFE
  GroupBorderColor           #95A5A6
}
hide footbox

participant "Thread A\n(reload winner)" as A
participant "mtime_slot\n(volatile uint64)" as Slot
participant "Config Store\n(two snapshots)" as Store
participant "Thread B\n(concurrent caller)" as B

note over Slot
  State encoding:
  MISSING    = 0x0000…0000  (file absent)
  UNKNOWN    = 0xffff…ffff  (initial sentinel)
  RELOADING  = 0xffff…fffe  (reload in progress)
  <timestamp>               (loaded + cached)
end note

== Thread A: Reload Trigger ==

A -> Slot : __sync_synchronize(); load(mtime_slot)
Slot --> A : old_mtime (e.g., UNKNOWN or stale timestamp)
A -> A : stat(config_path) → new_mtime
note right of A
  If new_mtime == old_mtime: done, no reload needed.
end note

A -> Slot : CAS(old_mtime, MTIME_RELOADING)
note right of Slot
  __sync_bool_compare_and_swap(
    &mtime_slot, old_mtime, MTIME_RELOADING)
  Returns true for exactly one winner thread.
end note

== Concurrent Thread B encounters MTIME_RELOADING ==

B -> Slot : load(mtime_slot) → MTIME_RELOADING
note right of B
  Spin: keep re-loading mtime_slot until
  it is no longer MTIME_RELOADING.
  (Reload window is < 15 µs for typical configs.)
end note

loop while mtime_slot == MTIME_RELOADING
  B -> Slot : load(mtime_slot)
  Slot --> B : MTIME_RELOADING
end

Slot --> B : new_mtime (reload complete)
B -> Store : read active_snapshot_index
Store --> B : active_snapshot

== Thread A: Winner completes reload ==

A -> Store : open+read config_path into INACTIVE snapshot
A -> Store : parse rules into inactive snapshot buffer
A -> Store : __sync_synchronize() (write barrier)
A -> Store : swap active_snapshot_index
A -> Store : __sync_synchronize() (read barrier for others)
A -> Slot : CAS(MTIME_RELOADING, new_mtime)
note right of Slot
  Releases the reload lock. Spinning threads unblock.
end note

@enduml
```

## FD Path Resolution

[`src/config/chaos_io_fdcache.c`](../src/config/chaos_io_fdcache.c)

- `read`, `readv`, `write`, `writev`, `fsync`, `fdatasync`, `pread`, `preadv`, `pwrite`, `pwritev`, `ftruncate`, and Linux `fallocate` operate on fds, not paths.
- The library resolves each fd through `/proc/self/fd/<fd>`.
- Resolved paths are cached in thread-local direct-mapped slots.
- Successful `close` invalidates the cache entry.
- Successful `unlinkat` and `renameat` reset the current thread cache because
  previously resolved path identities may now be stale.

Diagram — thread-local FD cache lookup and invalidation ([source](diagrams/fdcache.puml)):

```plantuml
@startuml fdcache
title libchaos-io Thread-Local FD Cache — Lookup and Invalidation

skinparam sequenceMessageAlign center
skinparam shadowing false
skinparam roundCorner 4
skinparam sequence {
  ArrowColor                 #2C3E50
  LifeLineBorderColor        #2C3E50
  LifeLineBackgroundColor    #ECF0F1
  ParticipantBorderColor     #2C3E50
  ParticipantBackgroundColor #FFFFFF
  ParticipantFontStyle       bold
  GroupBackgroundColor       #FDFEFE
  GroupBorderColor           #95A5A6
}
hide footbox

participant "Wrapper\n(read/write/fsync/…)" as Wrap
participant "FD Cache\n(TLS, direct-mapped)" as Cache
participant "/proc/self/fd\n<fd>" as Proc
participant "Config Engine" as Config
participant "Real libc" as Real

== Normal read/write call ==

Wrap -> Cache : lookup(fd)
note right of Cache
  slot = fd % CACHE_SLOTS
  if cache[slot].fd == fd:
    return cache[slot].path  (hit)
  else:
    return NULL              (miss)
end note

alt Cache hit
  Cache --> Wrap : cached_path
else Cache miss
  Cache --> Wrap : NULL
  Wrap -> Proc : readlink("/proc/self/fd/<fd>", buf)
  note right of Proc
    Returns canonical path or socket pseudo-path.
    Filtered: /proc, /sys, /dev, config path,
    fd 0/1/2 are excluded from injection.
  end note
  Proc --> Wrap : path_string
  Wrap -> Cache : store(fd, path_string)
end

Wrap -> Config : select_rule(op, path_string)
Config --> Wrap : rule or null
Wrap -> Real : real_symbol(fd, …)
Real --> Wrap : result

== open() seeds the cache ==

note over Wrap, Cache
  open(path, flags) / openat(dirfd, path, flags):
    resolve match_path (pre-open)
    call real_open()
    if succeeded: store(returned_fd, match_path)
end note

== close() invalidates ==

note over Wrap, Cache
  close(fd):
    call real_close(fd)
    if succeeded: cache[fd % SLOTS].fd = -1  (invalidate)
    ONLY invalidate after successful close.
    A failed close leaves the cache entry intact
    because the fd is still valid.
end note

== renameat() / unlinkat() reset ==

note over Wrap, Cache
  renameat() / unlinkat() success:
    memset(cache, 0, sizeof(cache))  (full reset)
    Reason: previously resolved /proc/self/fd paths
    may now point to different inodes or be stale.
end note

note across
  Thread-local scope: only the calling thread's cache
  is affected by close/rename/unlink.
  Cross-thread stale path hazard: Thread A closes fd 7;
  Thread B still has fd 7 cached with old path.
  If kernel reuses fd 7 for a new file, Thread B
  may match wrong rules until its slot is evicted.
end note

@enduml
```

## Fault Effects

[`src/effects/chaos_io_actions.c`](../src/effects/chaos_io_actions.c)

- `ERRNO`: fail before calling libc.
- `LATENCY`: sleep before calling libc.
- `TORN`: reduce the write length to a positive partial write.
- `CORRUPT`: call libc, then flip one bit in the returned buffer.

## Testing Strategy

### Unit tests

The unit tests include the implementation files directly where it improves reach:

- static helpers are exercised directly
- wrapper branches are tested without needing a real preload environment
- the production library remains unchanged apart from small testability hooks

That is why coverage can stay strict without adding exported test-only symbols.

### Coverage gate

[`test/runtime/check_coverage.sh`](../test/runtime/check_coverage.sh)

- Builds an instrumented tree in `build-coverage/`
- Runs all unit binaries
- Verifies `100.00%` line coverage for the shipped `libchaos-io`,
  `libchaos-net`, `libchaos-time`, `libchaos-memory`, and
  `libchaos-process` sources
- Verifies an enforced source-line coverage floor for the shipped
  `libchaos-dns` sources

### Style gate

[`test/runtime/check_format.sh`](../test/runtime/check_format.sh)

- Resolves `clang-format` from `PATH`, `CLANG_FORMAT`, or `xcrun`
- Checks or rewrites all shipped C sources and tests against the repository
  `.clang-format`

### Integration checks

[`test/runtime/test_integration.sh`](../test/runtime/test_integration.sh)

- Linux-only
- Builds the real shared object
- Verifies passthrough, injected errno failure, measured latency, and
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` runtime interposition on Linux hosts

[`test/runtime/test_glibc.sh`](../test/runtime/test_glibc.sh)

- Verifies the glibc Debian Docker build and runtime path, including direct
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` probes
- Accepts `linux/amd64` or `linux/arm64` as an optional explicit Docker target

[`test/runtime/test_alpine.sh`](../test/runtime/test_alpine.sh)

- Verifies the musl Alpine Docker build and runtime path, including direct
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` probes
- Accepts `linux/amd64` or `linux/arm64` as an optional explicit Docker target

[`test/runtime/test_net_glibc.sh`](../test/runtime/test_net_glibc.sh)
and [`test/runtime/test_net_alpine.sh`](../test/runtime/test_net_alpine.sh)

- Build and run the real `libchaos-net` shared object under glibc and musl
- Exercise `socket`, `bind`, `listen`, `connect`, `accept`, `shutdown`,
  `send`, `recv`, and readiness waits with endpoint-based rules
- Accept `linux/amd64` or `linux/arm64` as explicit Docker targets

[`test/runtime/test_dns_glibc.sh`](../test/runtime/test_dns_glibc.sh)
and [`test/runtime/test_dns_alpine.sh`](../test/runtime/test_dns_alpine.sh)

- Build and run the real `libchaos-dns` shared object under glibc and musl
- Exercise `getaddrinfo` failure injection, rewrite, service rewrite, latency,
  and synthetic answer manipulation
- Accept `linux/amd64` or `linux/arm64` as explicit Docker targets

[`test/runtime/test_time_glibc.sh`](../test/runtime/test_time_glibc.sh),
[`test/runtime/test_time_alpine.sh`](../test/runtime/test_time_alpine.sh),
[`test/runtime/test_memory_glibc.sh`](../test/runtime/test_memory_glibc.sh),
[`test/runtime/test_memory_alpine.sh`](../test/runtime/test_memory_alpine.sh),
[`test/runtime/test_process_glibc.sh`](../test/runtime/test_process_glibc.sh),
and [`test/runtime/test_process_alpine.sh`](../test/runtime/test_process_alpine.sh)

- Build and run the real `libchaos-time`, `libchaos-memory`, and
  `libchaos-process` shared objects under glibc and musl
- Exercise their dedicated runtime probes on both supported architectures
- Accept `linux/amd64` or `linux/arm64` as explicit Docker targets

## Platform Internals and Symbol Resolution

The detailed mechanics of ELF link-map ordering, PLT/GOT lazy binding, vDSO
dispatch, `AT_SECURE` stripping, `STT_GNU_IFUNC` resolver phases, and the
glibc/musl divergence matrix are documented in [`docs/PLATFORM.md`](PLATFORM.md).

Key facts that affect every wrapper in this repository:

**Link-map order and RTLD_NEXT:** `dlsym(RTLD_NEXT, name)` walks the link-map
starting from the DSO _after_ the caller. LD_PRELOAD libraries appear before
`DT_NEEDED` entries in the link-map. Therefore `RTLD_NEXT` from any chaos library
always reaches glibc/musl, regardless of LD_PRELOAD load order — provided no two
chaos libraries own the same symbol (the `one symbol, one owner` rule).

**PLT hot path cost:** After the first call (cold resolver dance), the GOT slot
for an interposed symbol points directly to the chaos library wrapper. The hot
path overhead is one indirect branch into the wrapper. See `docs/diagrams/linkmap.puml`.

**IFUNC and dlsym:** glibc uses `STT_GNU_IFUNC` (indirect function resolver) for
`clock_gettime`, `memcpy`, `strlen`, and similar. The IFUNC resolver fires at
`dl_open` time and resolves the function pointer to an architecture-optimal
implementation. `dlsym(RTLD_NEXT, "clock_gettime")` returns the post-IFUNC
resolved address, which is the vDSO-backed or syscall implementation. This is
correct. The chaos wrapper caches this resolved pointer.

## Formal Symbol-Ownership Theorem

This theorem is the mathematical basis for the architecture. See §17 of
[`docs/SYSTEM.md`](SYSTEM.md) for the complete proof. Short form:

> The interposition is correct if and only if every symbol is owned by at most
> one chaos library. If two libraries export the same symbol, RTLD_NEXT from the
> losing library resolves to the winning library's wrapper, not to glibc, causing
> double injection and preload-order-dependent behaviour.

The theorem's contrapositive is a direct rationale for the domain split:
`libchaos-net` must not own `read()` or `write()` because they are owned by
`libchaos-io`, and double ownership would make behaviour depend on LD_PRELOAD
order.

## Maintenance Rules

If you extend this library, keep these bars in place:

- preserve the no-public-API model
- preserve small output size
- keep new logic in C99
- extend unit coverage to 100% for any changed source file
- prefer boring, explicit code over generic abstractions

For the file-by-file maintenance map and wrapper-specific guidance, see
[`docs/ENGINEERING.md`](ENGINEERING.md).

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
