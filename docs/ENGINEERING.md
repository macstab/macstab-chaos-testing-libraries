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

This document holds the repository-wide engineering rules: how the code is
organised, which invariants every change must keep, how it is tested and
built, and why. `libchaos-io` is the most detailed example; the same rules
apply to every library. The system-level contract is in
[SYSTEM.md](SYSTEM.md); per-library behaviour is in [IO.md](IO.md),
[NETWORK.md](NETWORK.md), [DNS.md](DNS.md), [TIME.md](TIME.md),
[MEMORY.md](MEMORY.md) and [PROCESS.md](PROCESS.md); SECCOMP mode in
[SECCOMP.md](SECCOMP.md).

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
- [Verified Doc Examples](#verified-doc-examples)
- [Maintenance Bar](#maintenance-bar)

## Scope

Each library intercepts one narrow libc surface and makes it fail, stall or
misbehave under explicit rules. None is an observability agent, a daemon or a
policy engine.

Optimised for: small objects (`-Os`, stripped), deterministic behaviour under
test, wrappers that can be audited line by line, explicit failure semantics.

Not optimised for: feature breadth, plugin systems, runtime configuration
APIs, abstraction for its own sake.

Quality bar, identical for all six libraries and `chaos-init`
(`.github/workflows/ci.yml`, `matrix.yml`, `release.yml`):

- 100.00 % line coverage per source file (`test/runtime/check_coverage.sh`;
  `src/init/chaos_init.c`, the supervisor's `main` loop, is exercised by the
  runtime suites `test_init.sh` and `test_seccomp.sh` instead)
- unit tests under ASan and UBSan; the clang static analyzer
- `clang-format` conformance of `src/` and `test/` (`make fmt-check`)
- runtime suites on glibc and musl, amd64 and arm64, each on a runner of its
  own architecture
- glibc symbol versions no newer than `GLIBC_2.17`
  (`test/runtime/check_glibc_baseline.sh`, run on the release `dist/` objects)

## How To Read The Code

Read each library in the order below. Every library has the same four layers:
start-up and real functions, rule file and snapshots, effects, wrappers.
Shared mechanisms live in header-only `src/common/` (see
[SYSTEM.md §6](SYSTEM.md#shared-internal-scaffold)).

### `libchaos-io`

1. [`src/core/chaos_io.c`](../src/core/chaos_io.c) — constructor, lazy real-function table (`chaos_io_ensure_symbols`), seed, the shared fd-rule lookup
2. [`src/core/chaos_io_internal.h`](../src/core/chaos_io_internal.h) — limits, real-function types, recursion guard, PRNG
3. [`src/core/chaos_io_wrappers.h`](../src/core/chaos_io_wrappers.h) — helpers shared across wrapper units
4. [`src/wrappers/chaos_io_open.c`](../src/wrappers/chaos_io_open.c) — `open`/`openat` families, `at`-path resolution, fd-cache seeding
5. [`src/wrappers/chaos_io_rw.c`](../src/wrappers/chaos_io_rw.c) — `read`/`write` families, vectored I/O, `sendfile`, `copy_file_range`
6. [`src/wrappers/chaos_io_fsops.c`](../src/wrappers/chaos_io_fsops.c) — truncate, allocate, unlink, rename families
7. [`src/wrappers/chaos_io_sync.c`](../src/wrappers/chaos_io_sync.c) — `close`, `dup2`/`dup3`, `close_range`, `closefrom`, `fsync`, `fdatasync`
8. [`src/wrappers/chaos_io_stdio.c`](../src/wrappers/chaos_io_stdio.c) — stdio streams
9. [`src/config/chaos_io_config.c`](../src/config/chaos_io_config.c) — reload, parser, longest-prefix selection
10. [`src/effects/chaos_io_actions.c`](../src/effects/chaos_io_actions.c) — probability, latency, corruption, torn-write sizing
11. [`src/config/chaos_io_fdcache.c`](../src/config/chaos_io_fdcache.c) — process-wide 32-slot fd→path cache

### `libchaos-net`

1. [`src/net/chaos_net.c`](../src/net/chaos_net.c) — constructor, real functions, seed
2. [`src/net/chaos_net_config.c`](../src/net/chaos_net_config.c) — reload, parser, endpoint-rank selection
3. [`src/net/chaos_net_endpoint.c`](../src/net/chaos_net_endpoint.c) — selector parsing; endpoints from `sockaddr`, `getsockname`/`getpeername`, `SO_TYPE`
4. [`src/net/chaos_net_socket.c`](../src/net/chaos_net_socket.c) — `connect`, `accept`, `send*`/`recv*`, and `read`/`write`/`readv`/`writev`/`close` on sockets; `TRICKLE`, `DUP`, `RESET`
5. [`src/net/chaos_net_extra.c`](../src/net/chaos_net_extra.c) — `socket`, `socketpair`, `shutdown`, `sendmmsg`, `recvmmsg`
6. [`src/net/chaos_net_wait.c`](../src/net/chaos_net_wait.c) — `poll`, `ppoll`, `select`, `pselect`, `epoll_wait`, `epoll_pwait`; epoll membership from `/proc/self/fdinfo`
7. [`src/net/chaos_net_actions.c`](../src/net/chaos_net_actions.c) — probability, latency, corruption

### `libchaos-dns`

1. [`src/dns/chaos_dns.c`](../src/dns/chaos_dns.c) — constructor, real functions, seed
2. [`src/dns/chaos_dns_config.c`](../src/dns/chaos_dns_config.c) — reload, parser, exact/suffix/any ranking
3. [`src/dns/chaos_dns_lookup.c`](../src/dns/chaos_dns_lookup.c) — `getaddrinfo`, `getnameinfo`, `gethostby*` wrappers
4. [`src/dns/chaos_dns_actions.c`](../src/dns/chaos_dns_actions.c) — latency, `EAI_*`, rewrites, `FILTER_FAMILY` → `SHUFFLE` → `LIMIT`
5. [`src/dns/chaos_dns_owned.c`](../src/dns/chaos_dns_owned.c) — `OVERRIDE` result lists and their release through `freeaddrinfo`

### `libchaos-time`

1. [`src/time/chaos_time.c`](../src/time/chaos_time.c) — constructor, real functions, seed, first load
2. [`src/time/chaos_time_config.c`](../src/time/chaos_time_config.c) — reload, parser, clock selectors
3. [`src/time/chaos_time_actions.c`](../src/time/chaos_time_actions.c) — probability, latency, `OFFSET` arithmetic (clamped at `{0, 0}`), `REGRESS` state
4. [`src/time/chaos_time_hooks.c`](../src/time/chaos_time_hooks.c) — `clock_gettime`, `gettimeofday`, `time`, `timespec_get`, `nanosleep`, `clock_nanosleep`, `sleep`, `usleep`

### `libchaos-memory`

1. [`src/memory/chaos_memory.c`](../src/memory/chaos_memory.c) — constructor, real functions, seed
2. [`src/memory/chaos_memory_config.c`](../src/memory/chaos_memory_config.c) — reload, parser, `mmap/anon` and `mmap/file` selectors
3. [`src/memory/chaos_memory_actions.c`](../src/memory/chaos_memory_actions.c) — `ERRNO` and `LATENCY`
4. [`src/memory/chaos_memory_hooks.c`](../src/memory/chaos_memory_hooks.c) — `mmap`/`mmap64`, `mprotect`, `madvise`/`posix_madvise`, `munmap`

### `libchaos-process`

1. [`src/process/chaos_process.c`](../src/process/chaos_process.c) — constructor, real functions (`chaos_process_try_resolve_symbol` for symbols a libc may lack), seed, `FAIL_AFTER` counters
2. [`src/process/chaos_process_config.c`](../src/process/chaos_process_config.c) — reload, parser; resets `FAIL_AFTER` counters when the rules change
3. [`src/process/chaos_process_actions.c`](../src/process/chaos_process_actions.c) — probability, latency, `FAIL_AFTER`
4. [`src/process/chaos_process_hooks.c`](../src/process/chaos_process_hooks.c) — `pthread_create`, `fork`, `posix_spawn*`, `system`, `popen`, the `exec*` family, the `wait*` family

### `chaos-init`

1. [`src/init/chaos_init.c`](../src/init/chaos_init.c) — PID 1: fork, filter handover, status, notification loop, signal forwarding, reaping
2. [`src/init/chaos_init_core.c`](../src/init/chaos_init_core.c) — argument parsing, BPF filter, kernel-version checks, exit codes (no system calls)
3. [`src/init/chaos_init_delay.c`](../src/init/chaos_init_delay.c) — queue of calls held back by `LATENCY`
4. [`src/init/chaos_init_proc.c`](../src/init/chaos_init_proc.c) — reading a tracee's memory, descriptors and identity
5. [`src/init/chaos_init_tracee.c`](../src/init/chaos_init_tracee.c) — per-tracee hits, `@first` claims, windows
6. `src/init/chaos_init_{io,net,memory,process}.c` — each library's rules applied to notified system calls

## File Responsibilities

### [`src/core/chaos_io.c`](../src/core/chaos_io.c)

Owns process-global state and start-up.

Change it to: add or resolve a real function; change constructor order;
change the recursion-guard boundary; change the shared fd-rule lookup
(`chaos_io_match_fd_rule`: refresh → resolve fd → select).

Do not put wrapper flow, probability math or fd-cache policy here.

Invariants:

- Every wrapper calls `chaos_io_ensure_symbols()` before touching a real
  function pointer. The constructor may run after another library's
  constructor has already called a wrapper.
- A mandatory symbol that cannot be resolved aborts; an optional one
  (`close_range`, `closefrom`, `renameat2`, `__vfprintf_chk`, `__fread_chk`,
  `__fgets_chk`) stays NULL and its wrapper reports `ENOSYS`.
- Descriptors 0–2 are never matched.

### [`src/wrappers/chaos_io_open.c`](../src/wrappers/chaos_io_open.c)

Owns the path-first wrappers. `open` and `openat` (and their `64`, `__*_2`
and `creat` variants) share varargs handling, path resolution and fd-cache
seeding; keep them together.

`mode_t` is read from the varargs as `int` (default promotion) only when
`O_CREAT` or `O_TMPFILE` is set, and passed as a third argument only then.

### [`src/wrappers/chaos_io_rw.c`](../src/wrappers/chaos_io_rw.c)

Owns read- and write-class wrappers.

Invariant: read-class wrappers may delay, fail, or corrupt returned bytes;
write-class wrappers may delay, fail, or shorten the request. `sendfile` and
`copy_file_range` are write-class on the destination descriptor only, with no
`CORRUPT` (the data never enters user space). The caller's iovec array is read
only after a rule matched, never past `IOV_MAX` entries, and through a checked
copy (`process_vm_readv` on the own process), so an invalid array still fails
in the kernel with `EINVAL` or `EFAULT` instead of crashing the wrapper.

### [`src/wrappers/chaos_io_fsops.c`](../src/wrappers/chaos_io_fsops.c)

Owns size-change and path-identity wrappers: `ftruncate`, `truncate`,
`fallocate`, `posix_fallocate`, `unlinkat`, `unlink`, `rmdir`, `remove`,
`renameat`, `renameat2`, `rename`. Only `ERRNO` and `LATENCY` apply. A
successful unlink or rename resets the whole fd cache: a rename changes what
previously resolved paths mean, and selective invalidation would require
knowing every path resolved under the old name.

### [`src/wrappers/chaos_io_sync.c`](../src/wrappers/chaos_io_sync.c)

Owns `close`, `fsync`, `fdatasync` and the descriptor-recycling calls
(`dup2`, `dup3`, `close_range`, `closefrom`, `closedir`, `pclose`). `fsync`
and `fdatasync` take `ERRNO` and `LATENCY` only. Keep these wrappers free of
effect-specific policy.

### [`src/wrappers/chaos_io_stdio.c`](../src/wrappers/chaos_io_stdio.c)

Owns stdio. glibc and musl read and write a `FILE` with internal system calls,
never through `read`/`write`, so stdio needs its own wrappers to be faulted at
all. Read class: `fread`, `fgets`, `fgetc`, `getc`, `getline`, `getdelim`,
`__getdelim`, `__fread_chk`, `__fgets_chk`. Write class: `fwrite`, `fputs`,
`fputc`, `putc`, `fprintf`, `vfprintf`, `fflush`, `__fprintf_chk`,
`__vfprintf_chk`. `ERRNO` returns the stdio error value (0 items, NULL, EOF,
negative count), sets errno and raises the stream's error indicator (bit
`0x20` of the first word of `FILE` on glibc and musl, set under the stream
lock). `TORN` does not apply: a short `fwrite` signals an error in stdio, not
partial success. Not wrapped: `scanf` family, `*_unlocked`, and
`printf`/`puts`/`putchar`/`getchar`, which only use descriptors 0–2.

### [`src/config/chaos_io_config.c`](../src/config/chaos_io_config.c)

Owns rule-file ingestion and rule selection. Invariants:

- a rejected file means no rules, never a partial rule set
- the longest matching prefix wins; prefixes match at path boundaries
  (`/data` covers `/data/file`, not `/database`)
- `*` covers absolute paths except `/memfd:`; pipes, sockets and anonymous
  inodes only match a rule that names them
- one thread reloads, any number read

### [`src/effects/chaos_io_actions.c`](../src/effects/chaos_io_actions.c)

Owns effect mechanics, not lookup. If the same effect branching appears in
two wrappers, it belongs here.

### [`src/config/chaos_io_fdcache.c`](../src/config/chaos_io_fdcache.c)

Translates descriptors back into paths. 32 direct-mapped slots indexed by
`fd % 32`, one table per process, mapped with a raw `mmap` on the first store.

- Each slot has a seqlock (odd while written) and a generation bumped by every
  invalidation; a lookup that raced with `close` cannot store the stale path.
- Excluded paths (the rule file, `/proc`, `/sys`, `/dev`) are never stored or returned.
- If the table cannot be mapped, every lookup reads `/proc/self/fd`.

It used to be thread-local. That cost every thread `32 × PATH_MAX` bytes of
static TLS from its first instruction (the static-TLS budget that crashed the
Erlang VM under `libchaos-net`) and left other threads' entries stale after a
`close`, so a recycled descriptor number could match the old path.

### [`src/net/chaos_net.c`](../src/net/chaos_net.c)

Owns net start-up: real functions, seed, constructor order. Not for wrapper
flow, endpoint translation or parsing.

### [`src/net/chaos_net_config.c`](../src/net/chaos_net_config.c)

Owns net rule-file ingestion and endpoint-rank selection: a more specific
endpoint beats a wildcard; equal ranks go to the longer selector text. Same
reload invariants as io.

### [`src/net/chaos_net_endpoint.c`](../src/net/chaos_net_endpoint.c)

Translates a `sockaddr` (or a descriptor's local/peer address) into a
matchable endpoint. Kind comes from `(sa_family, SO_TYPE)` with
`SOCK_CLOEXEC`/`SOCK_NONBLOCK` masked off. Change it to add an address
family or change IPv4-mapped IPv6 normalisation. A descriptor that is not a
socket yields `ENOTSOCK`, which is how the shared wrappers leave files to io.

### [`src/net/chaos_net_socket.c`](../src/net/chaos_net_socket.c)

Owns `connect`, `accept`/`accept4`, `send`/`sendto`/`sendmsg`,
`recv`/`recvfrom`/`recvmsg`, the fortified receive variants, and the generic
`read`/`readv` (counted as `recv`), `write`/`writev` (counted as `send`) and
`close` on sockets. Every call it does not decide goes to `RTLD_NEXT`, never
to libc directly. Receive reshaping lives here: `TRICKLE` only on stream
sockets (shortening a datagram receive truncates the datagram), and only for
iovec arrays of at most 64 entries; `DUP` skips peeks, `MSG_TRUNC`,
out-of-band and error-queue reads, `MSG_WAITALL` and empty buffers.

### [`src/net/chaos_net_extra.c`](../src/net/chaos_net_extra.c)

Owns `socket`, `socketpair`, `shutdown`, `sendmmsg`, `recvmmsg`. `socket`
selectors can use only kind and wildcards: there is no address yet.

### [`src/net/chaos_net_wait.c`](../src/net/chaos_net_wait.c)

Owns readiness waits. Multi-descriptor scans do not allocate. Epoll
membership is read from `/proc/self/fdinfo/<epfd>` in 512-byte chunks, at most
256 KiB per wait; when it cannot be read the wait passes through.

### [`src/net/chaos_net_actions.c`](../src/net/chaos_net_actions.c)

Owns net effect mechanics: probability, latency, corruption bounded to the
bytes the kernel actually wrote.

### [`src/dns/chaos_dns.c`](../src/dns/chaos_dns.c)

Owns dns start-up. The seed is read from `/dev/urandom` with raw
`openat`/`read`/`close` system calls, like every library's: the libc path
would pass through `libchaos-io`'s wrappers.

### [`src/dns/chaos_dns_config.c`](../src/dns/chaos_dns_config.c)

Owns dns rule-file ingestion and selection: exact (rank 3) > suffix (2) >
any (1), ties to the longer text. Suffix selectors apply to forward lookups
only.

### [`src/dns/chaos_dns_actions.c`](../src/dns/chaos_dns_actions.c)

Owns pre-call effects and the result transforms. The stage order
`FILTER_FAMILY` → `SHUFFLE` → `LIMIT` is part of the contract: `LIMIT=1`
after `SHUFFLE` yields a random single answer, and filtering first ensures
`LIMIT` counts only surviving families. Nodes a transform removes are freed
through the real `freeaddrinfo`. `SHUFFLE` allocates its pointer array with
`calloc`; on allocation failure the list is left unchanged.

### [`src/dns/chaos_dns_lookup.c`](../src/dns/chaos_dns_lookup.c)

Owns wrapper entry, rule lookup and dispatch for `getaddrinfo`,
`getnameinfo` and the `gethostby*` family. Effect logic belongs in
`chaos_dns_actions.c`.

### [`src/time/chaos_time.c`](../src/time/chaos_time.c)

Owns time start-up. Its own sleeps and clock reads never use the interposed
symbols (see [Recursion And Internal Calls](#recursion-and-internal-calls)).

### [`src/time/chaos_time_config.c`](../src/time/chaos_time_config.c)

Owns time rule-file ingestion: selectors `*` (rank 1), operation (rank 2),
`clock_gettime/<clock>` (rank 3). `OFFSET` is valid only on `clock_gettime`
selectors; `REGRESS` only on `clock_gettime/<clock>` with a positive offset.

### [`src/time/chaos_time_actions.c`](../src/time/chaos_time_actions.c)

Owns `OFFSET` arithmetic on `int64_t` intermediates (no signed overflow),
normalising `tv_nsec` into `[0, 999 999 999]` and clamping a negative result
to `{0, 0}`. Neither `OFFSET` nor `REGRESS` keeps `CLOCK_MONOTONIC`
monotonic; that is their purpose.

### [`src/time/chaos_time_hooks.c`](../src/time/chaos_time_hooks.c)

Owns the eight time wrappers. Order per wrapper: guard → `LATENCY` →
`ERRNO` → real call → `OFFSET`/`REGRESS` (clock reads only, on success).
`gettimeofday`, `time` and `timespec_get` use the `clock_gettime/realtime`
rules; `clock_nanosleep` and `sleep` use the `nanosleep` rules.

### [`src/memory/chaos_memory.c`](../src/memory/chaos_memory.c)

Owns memory start-up. `chaos_once` returns 0 instead of deadlocking when
`dlsym` allocates and a preloaded allocator calls `mmap` back into this
library during resolution; that `mmap` passes through.

### [`src/memory/chaos_memory_config.c`](../src/memory/chaos_memory_config.c)

Owns memory rule-file ingestion; selectors `*`, operation, `mmap/anon`,
`mmap/file`.

### [`src/memory/chaos_memory_actions.c`](../src/memory/chaos_memory_actions.c)

Owns the two memory effects, `ERRNO` and `LATENCY`. There is deliberately no
`CORRUPT` or `OFFSET`: a mapping is live process memory, not a result buffer,
and corrupting it after return would fault the process in places no test can
attribute. Such a feature needs its own explicitly scoped design.

### [`src/memory/chaos_memory_hooks.c`](../src/memory/chaos_memory_hooks.c)

Owns `mmap` (`mmap64` is an alias on 64-bit glibc; current musl exports no
`mmap64`), `mprotect`, `madvise`, `posix_madvise`, `munmap`. `mmap/anon` vs
`mmap/file` is decided by `flags & MAP_ANONYMOUS`. `posix_madvise` follows
the `madvise` rules and returns the error number instead of setting errno,
as POSIX specifies.

### [`src/process/chaos_process.c`](../src/process/chaos_process.c)

Owns process start-up. `execveat`, `execvpe` and `fexecve` are resolved with
`chaos_process_try_resolve_symbol` (absent from some libcs);
`pthread_create` is resolved on first use because before glibc 2.34 it lives
in libpthread, which may be loaded after the constructor ran.

### [`src/process/chaos_process_config.c`](../src/process/chaos_process_config.c)

Owns process rule-file ingestion; selectors `*` or an operation name. Resets
every `FAIL_AFTER` counter when a reload changes the rule file. A provisional
re-read that finds identical content keeps the counters.

### [`src/process/chaos_process_actions.c`](../src/process/chaos_process_actions.c)

Owns `ERRNO`, `LATENCY` and `FAIL_AFTER`. A `FAIL_AFTER` rule (`ERRNO,N`)
atomically increments one counter per operation (`__sync_fetch_and_add`) and
fails when the value before the increment is ≥ N: the first N calls succeed.
The counter is process-wide by design: per-thread counters would let a fresh
thread succeed after another thread exhausted the budget. Document any change
to that semantic.

### [`src/process/chaos_process_hooks.c`](../src/process/chaos_process_hooks.c)

Owns the process wrappers. Order per wrapper: guard → `LATENCY` → `ERRNO` →
`FAIL_AFTER` → real call.

- `posix_spawn`/`posix_spawnp` are decided at their own boundary; neither
  glibc nor musl calls the exported `fork`, so `fork` rules never reach them.
  `system` and `popen` follow the `posix_spawn` rules.
- Every exec-family decision completes before the real call. A successful
  exec does not return; library state and destructors are gone.
- A `fork` arriving while the real `fork` is still unresolved (a call from
  inside symbol resolution) fails with `ENOSYS` rather than issuing a bare
  `clone`, which would skip libc's atfork handlers.
- `vfork` is not interposed. A future wrapper must not sleep in the child,
  which runs on the parent's stack until it execs or exits.

## Wrapper Semantics

### `open()` and `openat()`

These start from a path:

1. Resolve the path to an absolute string (`chaos_io_resolve_at_path`):
   relative paths against the current directory or the `dirfd`. Failure is
   not fatal.
2. Match `open` rules on the resolved path; apply `LATENCY`, then `ERRNO`
   (no real call).
3. Call the real function.
4. On success, seed the fd cache so later descriptor calls need no
   `/proc/self/fd` lookup.

If step 1 fails, pre-call injection is skipped and only the post-open cache
seeding applies.

### `read()`, `readv()`, `pread()`, and `preadv()`

May delay before, fail before (no real call), or corrupt after a successful
real call. They never shorten the request. Corruption applies only when
`rc > 0` and only within the returned bytes; for `readv`/`preadv` the target
byte is chosen across the concatenation of the returned segments. A torn read
is not offered: the caller cannot tell it from a genuine short read.

### `write()`, `writev()`, `pwrite()`, `pwritev()`, and Linux `sendfile()` / `copy_file_range()`

May delay before, fail before, or shorten the request (`TORN`). The caller's
buffer is never modified. For `writev`/`pwritev` the torn byte budget is
mapped back into a truncated copy of the iovec array (vectors longer than
`CHAOS_IO_TORN_MAX_IOV` are not torn). `sendfile` and `copy_file_range` match
on the destination descriptor and support `ERRNO`, `LATENCY`, `TORN`.

Data moved through `splice`, `mmap` or other paths outside the wrapped set is
not faulted.

### `ftruncate()`, Linux `fallocate()`, `unlinkat()`, and `renameat()`

| Call | Operation | Matched on |
| --- | --- | --- |
| `ftruncate`, `truncate` | `truncate` | descriptor path / path |
| `fallocate`, `posix_fallocate` | `allocate` | descriptor path |
| `unlinkat`, `unlink`, `rmdir`, `remove` | `unlink` | resolved target path |
| `renameat`, `renameat2`, `rename` | `rename_from`, `rename_to` | resolved source, destination |

A rename evaluates both sides, takes the longer-prefix match, and breaks ties
towards the destination: atomic-replace patterns (write a temporary file,
rename it over the final name) care about the final name. A successful
unlink or rename resets the fd cache.

### `close()`

Linux releases the descriptor even when `close` reports an error (`EIO` on
NFS write-back, `EINTR`), and correct programs never retry it. The wrapper
keeps that contract: it applies `LATENCY` before, always calls the real
`close`, invalidates the fd-cache slot whatever the result (the number may be
reused by the next `open`), and reports an injected `ERRNO` after the
descriptor is gone. A synthetic error that left the descriptor open would
leak it in exactly the programs that handle `close` correctly.

### `fsync()` and `fdatasync()`

Persistence boundaries, where higher layers surface storage failures.
`ERRNO` and `LATENCY` only; no cache change.

## Config Model

Each rule is parsed once into a fixed-size struct. A reload parses into the
inactive snapshot and publishes it by flipping the active index after a full
barrier; readers never see a snapshot being written (seqlock), and never
mutate one.

Properties this buys:

- the match path is a linear scan of at most 256 fixed-size rules, no
  allocation
- a rejected file is rejected whole; the previous snapshot stays intact until
  the replacement is complete
- reload never allocates

The rule file is read with raw `openat`/`read` system calls into a static
262,145-byte buffer: through libc, `libchaos-io` would see one library reading
its rules and an io rule could fail that read. See
[SYSTEM.md §8](SYSTEM.md#8-concurrency-and-threading-model) for the reload
protocol, the 1 ms throttle and the 20 ms racy-stamp window.

## Recursion And Internal Calls

The recursion guard is what keeps a library from intercepting itself. Every
call a library makes to a real function on its own behalf runs between
`chaos_<lib>_enter_internal()` and `chaos_<lib>_leave_internal(previous)`;
wrappers entered in internal mode pass straight through. The guard is a
per-thread `int`, saved and restored (not just cleared), so nested internal
sections compose.

Work that must not even reach another chaos library uses no interposable
symbol at all:

| Work | Mechanism | Why |
| --- | --- | --- |
| rule-file read | raw `openat`/`read`/`close` | io rules must not fail another library's rule load |
| status and hits files | raw `openat`/`write`/`renameat`/`linkat` | io rules must not fail the report |
| `LATENCY` sleep | raw `clock_nanosleep(CLOCK_MONOTONIC)` | time rules must not shorten (`EINTR`) or lengthen another library's delay |
| throttle, hits, `@from`/`@until` clock | vDSO via `AT_SYSINFO_EHDR`, else raw `clock_gettime` | time rules must not change rule timing |
| seed | raw `openat`/`read` of `/dev/urandom` | runs before the real-function table may exist |
| fd cache, `DUP` table | raw `mmap` | memory rules must not fail the library's own memory |

Every path that may change errno on behalf of the library (rule-file `stat`,
reads, socket lookups, status writes) restores it; `test_errno_glibc.sh`
checks that an idle library never leaks errno into a successful call. A new
helper reachable from a wrapper that performs I/O needs the guard, or a raw
system call, unless you can prove otherwise.

## Testing Philosophy

The tests sit close to the implementation:

- Parser and reload tests include the config sources directly, so malformed
  input, size limits, NUL bytes, racy stamps and reload races are exercised
  precisely.
- Wrapper tests include the wrapper sources through
  [`test/support/test_chaos_io_harness.h`](../test/support/test_chaos_io_harness.h)
  (and the `test_<lib>_support.h` headers), which replace every dependency
  with recording stubs, so every branch can be forced without a real preload.
- Test seams are compile-time macros (`CHAOS_SLEEP_SYSCALL`,
  `CHAOS_STATUS_OPEN`, `CHAOS_CONFIG_FILE_OPEN`, `CHAOS_CLOCK_RAW_GETTIME`,
  `CHAOS_NET_SOCKET_TYPE`, ...) or replaceable function pointers; production
  builds compile the raw system calls.
- `test/unit/test_config_proptest.c` runs property tests over the parser;
  `test/fuzz/` holds libFuzzer targets for every rule parser (`make fuzz`).
- `test/runtime/` loads the real shared objects in glibc and Alpine
  containers: per-library behaviour, errno hygiene, alternate entry points
  (`open64`, `__read_chk`, ...), io/net sharing in both orders, cross-library
  isolation, fork, reload, status and hits files, stdio, SECCOMP mode.

Direct source inclusion is deliberate for a low-level library: it is the
cheapest way to reach every branch.

To run the unit suite from a clean state:

```sh verified
make unit
```

To build all six shared libraries (Linux only):

```sh verified
[ "$(uname -s)" != "Linux" ] && exit 0; make native
```

## Extending The Library Safely

### Adding a new interposed symbol to an existing subsystem

1. If it introduces a new operation, add the enum value in the library's
   config header and the parser dispatch in its config source.
2. Add the real-function typedef and pointer in the library's internal header.
3. Resolve it in `chaos_<lib>_resolve_all_symbols()`: mandatory symbols abort
   when missing; a symbol a supported libc may lack must be optional and its
   wrapper must report `ENOSYS` when it is NULL.
4. Add the wrapper with `CHAOS_<LIB>_EXPORT`. It calls
   `chaos_<lib>_ensure_symbols()` first, passes through in internal mode, and
   calls the real function between `enter_internal` and `leave_internal` on
   every path.
5. If the symbol is a generic descriptor call, decide only on your own
   descriptor kind and forward everything else to `RTLD_NEXT`.
6. Cover every new branch with unit tests (`make coverage` stays at 100.00 %)
   and add a runtime probe for glibc and musl.

### Adding a new effect to an existing subsystem

1. Add the enum value in the config header.
2. Define the operations it is valid for; reject every other combination in
   the parser (the whole file is rejected).
3. Add the effect mechanics to `chaos_<lib>_actions.c`.
4. Wire the wrapper branches.
5. Write deterministic unit tests first, then runtime coverage, and, when
   SECCOMP mode cannot apply it, reject it in `chaos-init` with reason
   `unsupported in seccomp mode`.

### Cross-subsystem invariants for any extension

- No allocation on the match path. The exceptions are `libchaos-dns` result
  transforms, which operate on `getaddrinfo` results that are heap objects
  anyway.
- Every real call made on the library's behalf runs in internal mode.
- Reload stays all-or-nothing: the index flips only after a complete,
  validated parse.
- `CHAOS_<LIB>_EXPORT` marks only the wrappers that replace libc symbols.
- errno is unchanged on every path that does not inject.

## ABI Commitments

### Shared Object ABI Surface

Every object is compiled with `-fvisibility=hidden`; only functions marked
`CHAOS_<LIB>_EXPORT` (`__attribute__((visibility("default")))`, defined in
each library's internal header) enter `.dynsym`. The exported set is the
wrapper list in [SYSTEM.md §1](SYSTEM.md#global-invariant).

Consequences:

- internal helpers cannot interpose on, or be interposed by, symbols of the
  target or of other preloaded objects
- `.dynsym`, `.dynstr` and `.gnu.hash` stay small, so symbol lookup in the
  object is cheap

### ELF `SONAME`

The objects carry no `DT_SONAME`: the link line passes no `-soname`. Nothing
links against them, and `LD_PRELOAD` loads by path or file name, so a soname
would only add a dynamic entry.

### No Public C API

There is no header to include and no install target. The contract is:

1. load via `LD_PRELOAD` (or run under `chaos-init`)
2. write the rule file at its documented path
3. read the status and hits files

A C API would create versioning, calling-convention and compatibility
obligations that constrain refactoring and buy nothing for a preload-only
library.

## Build Flag Rationale

Every shared object is built with the base flags
`-std=c99 -Wall -Wextra -Werror -pedantic -Os`, linked with `-ldl`
(`dlsym` lives in libdl before glibc 2.34), plus the flags below
(`SHARED_CFLAGS`, `SHARED_LDFLAGS` in the `Makefile`). Unit tests use only the
base flags; sanitizer and coverage builds override `CFLAGS`.

### `-fvisibility=hidden`

Only symbols marked for export enter `.dynsym`. Without it, a helper such as
`chaos_io_config_prepare` would be exported and could shadow, or be shadowed
by, a same-named symbol in the target or another preloaded object.

### `-ffunction-sections` and `-fdata-sections`

One ELF section per function and per data object, so `--gc-sections` can drop
unreferenced code and data individually instead of per translation unit.

### `-Wl,--gc-sections`

Drops every section unreachable from the exported symbols and constructors.
With 100 % line coverage little is dead; the flag mostly removes unused
`static inline` copies from `src/common/` and unreferenced data.

### `-Wl,--strip-all`

Removes `.symtab`, `.strtab` and debug sections; `.dynsym`, `.dynstr`, the
hash tables and the dynamic relocations stay, because the loader needs them.
There is no separate debug variant of the shared objects; to debug, build with
your own `CFLAGS`/`LDFLAGS` overrides.

### `-fno-unwind-tables`, `-fno-asynchronous-unwind-tables`, `-fomit-frame-pointer`, `-fno-ident`

No `.eh_frame` and no `.comment` payload, and no frame-pointer register
reserved. The library is C99 and throws nothing. Trade-off: debuggers,
`backtrace()` and frame-pointer profilers cannot unwind through a chaos
frame; `perf` attributes samples to the object but cannot walk past it.

### `-fno-stack-protector`

No canary checks, therefore no import of `__stack_chk_fail`: one fewer libc
dependency and symbol version, and smaller code. The compensating controls are
bounded fixed-size buffers with explicit length checks, no `gets`/`scanf`,
100 % line coverage, ASan and UBSan unit runs, libFuzzer targets for every
parser, and `-Wall -Wextra -Werror`.

### `-Wl,--build-id=none`

No build-id note; release objects are identified by version and file name.

### `-Wl,-z,max-page-size=4096` and `-Wl,-z,common-page-size=4096`

4 KiB segment alignment instead of the 64 KiB aarch64 default, which pads the
file. Consequence: the segments assume 4 KiB pages. On arm64 kernels
configured with 16 KiB or 64 KiB pages the loader cannot map these objects.

### Summary Table

| Flag | Effect | Why |
| --- | --- | --- |
| `-Os` | optimise for size | the object is mapped into every target process |
| `-fvisibility=hidden` | only exported wrappers in `.dynsym` | no symbol collision; small dynamic table |
| `-ffunction-sections`, `-fdata-sections` | one section per function / object | enables `--gc-sections` |
| `-Wl,--gc-sections` | drop unreachable sections | smaller object |
| `-Wl,--strip-all` | drop non-dynamic symbols and debug info | smaller object |
| `-fno-unwind-tables`, `-fno-asynchronous-unwind-tables` | no `.eh_frame` | smaller; no unwinding through chaos frames |
| `-fomit-frame-pointer`, `-fno-ident` | no frame pointer, no `.comment` | smaller, one more register |
| `-fno-stack-protector` | no canary | no `__stack_chk_fail` import |
| `-Wl,--build-id=none` | no build-id note | smaller |
| `-Wl,-z,max-page-size=4096`, `common-page-size=4096` | 4 KiB alignment | smaller arm64 objects; requires 4 KiB pages |
| `-ldl` | link libdl | `dlsym` before glibc 2.34 |

## Verified Doc Examples

A command in a document that no longer works is worse than none. Fenced shell
blocks in `docs/` whose info string is `sh verified`, `bash verified` or
`shell verified` are extracted and run by `make verify-docs`
(`scripts/run_verified_examples.sh`), the last step of the `unit` job in
`ci.yml`. Untagged blocks are never run.

### Safety model

Each block is written to a temporary script and run with:

- `set -euo pipefail`; the first failing command fails the block
- a 30-second limit (`timeout`, or `gtimeout` on macOS; without either, no limit)
- the working directory set to the repository root, and `REPO_ROOT` exported

There is no sandbox: the block runs in the checkout. Tag only commands that
are safe in a fresh checkout. Guard platform-specific commands, as the
`make native` example in [Testing Philosophy](#testing-philosophy) does with
`[ "$(uname -s)" != "Linux" ] && exit 0`.

The scan covers `docs/*.md` and one level of subdirectories
(`docs/development/*.md`). The opening fence must start in column 0; an
indented fence, such as the illustration below, is not executed:

    ```sh verified
    make unit
    ```

### Running locally

```sh
make verify-docs
```

### Adding a new verified block

1. Write the command.
2. Change the info string from `sh` to `sh verified`.
3. Run `make verify-docs`.
4. Commit.

There is no registry or manifest.

### What to tag

Tag: `make unit`, `make fmt-check`, `make coverage`; `make native` behind a
Linux guard; commands from quick-start sections that finish within 30 s.

Do not tag: placeholder paths (`/path/to/libchaos-io.so`), commands that need
root, a running process or a specific environment, and long-running commands
(fuzzing, image pulls).

## Maintenance Bar

A good change in this repository:

- makes wrapper flow easier to audit
- adds no allocation to the match path
- keeps a rejected rule file a no-rules state, never a partial one
- keeps tests deterministic
- does not grow the object for cosmetic abstraction
- keeps every decision inside one library's domain

A change that fights these constraints needs a stronger argument than
"it is more generic".

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
