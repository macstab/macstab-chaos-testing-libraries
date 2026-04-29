# Roadmap

This repository currently ships implemented `libchaos-io`, `libchaos-net`,
`libchaos-dns`, `libchaos-time`, `libchaos-process`, and `libchaos-memory`
libraries.

The roadmap below answers two separate questions:

1. What should be added to `libchaos-io` itself?
2. What chaos surfaces matter, but should live in separate libraries so this
   repository does not lose its small, auditable shape?

## Constraints

Every planned change in this repository must preserve these constraints:

- Linux `LD_PRELOAD` library model
- C99 implementation
- very small source footprint and shared-object size
- no public SDK
- explicit control flow over generic abstractions
- full unit coverage for changed source files
- runtime verification on glibc and musl
- supported build outputs for:
  - glibc amd64
  - glibc arm64
  - musl amd64
  - musl arm64

## Cross-Target Completion Gate

Every roadmap step below is incomplete until all of the following are true:

- the code builds for glibc amd64
- the code builds for glibc arm64
- the code builds for musl amd64
- the code builds for musl arm64
- runtime behavior is verified on glibc and musl
- runtime behavior is verified on amd64 and arm64 through CI or equivalent
  runner coverage

Local development is not enough to close a step when it only proves the host
architecture. The musl/glibc amd64/arm64 matrix must be treated as a release
gate, not as a follow-up task.

## Historical Failure Pattern

The local git history shows why this gate exists:

- commit `99de3e4` on April 5, 2026 introduced the initial implementation
- commit `0819122` on April 6, 2026 added Alpine musl runtime verification later
- no `src/` implementation files changed between those two commits

That means "builds here" and "passes host-local tests" were previously allowed
to stand in for "implementation is valid everywhere". This repository must not
repeat that mistake.

For every step below:

- do not treat host-only verification as implementation validity
- do not treat build-only verification as runtime validity
- do not split implementation and cross-target proof into separate "later"
  cleanup work
- do not mark a wrapper complete until its behavior is proven on the required
  libc and architecture matrix

## Current Status

Implemented in `libchaos-io`:

- `open`
- `openat`
- `close`
- `read`
- `readv`
- `write`
- `writev`
- Linux `sendfile`
- Linux `copy_file_range`
- `pread`
- `preadv`
- `pwrite`
- `pwritev`
- `fsync`
- `fdatasync`

Current effects:

- `ERRNO`
- `LATENCY`
- `TORN` for write-style calls
- `CORRUPT` for read-style calls

Known gap:

- `cp` and similar tools may still move data with `splice()`, which bypasses
  the current write hooks.

Local verification snapshot for the current implementation:

- passed: Linux amd64 Docker unit run
- passed: Linux arm64 Docker unit run
- passed: Linux amd64 Docker coverage run
- passed: Linux arm64 Docker coverage run
- passed: glibc amd64 Docker runtime
- passed: glibc arm64 Docker runtime
- passed: musl amd64 Docker runtime
- passed: musl arm64 Docker runtime
- passed: Linux amd64 Docker integration run for `openat`, `readv`, `writev`,
  `preadv`, `pwritev`, `sendfile`, and `copy_file_range`

This means the implementation is materially ahead of the roadmap, but the
current `openat`, vectored I/O, `sendfile`, and `copy_file_range` work is
locally proven across the required libc and architecture matrix.

Implemented in `libchaos-net`:

- `socket`
  - backed by `socket()` and `socketpair()`
- `bind`
- `listen`
- `connect`
- `accept`
  - backed by `accept()` and Linux `accept4()`
- `shutdown`
  - backed by `shutdown()`
- `poll`
  - backed by `poll()`, `ppoll()`, `select()`, `pselect()`, and Linux
    `epoll_wait()` plus `epoll_pwait()`
- `send`
  - backed by `send()`, `sendto()`, `sendmsg()`, and Linux `sendmmsg()`
- `recv`
  - backed by `recv()`, `recvfrom()`, `recvmsg()`, and Linux `recvmmsg()`
- `dns`
  - backed by `getaddrinfo()`

Current `libchaos-net` effects:

- `ERRNO`
- `LATENCY`
- `CORRUPT` for receive-side buffers
- `TIMEOUT` for readiness waits
- `GAI` for `getaddrinfo()`

Current `libchaos-net` verification snapshot:

- passed: Linux amd64 Docker unit run
- passed: Linux arm64 Docker unit run
- passed: Linux amd64 Docker coverage run
- passed: Linux arm64 Docker coverage run
- passed: glibc amd64 Docker runtime
- passed: glibc arm64 Docker runtime
- passed: musl amd64 Docker runtime
- passed: musl arm64 Docker runtime

Current `libchaos-net` gaps:

- `libchaos-net` deliberately does not own `read()`, `write()`, or `close()`
  so it can compose with `libchaos-io`
- Linux `epoll_*` matching is intentionally best-effort and derived from
  `/proc/self/fdinfo/<epfd>` instead of an owned membership cache

Implemented in `libchaos-process`:

- `pthread_create`
- `fork`
- `posix_spawn`
- `posix_spawnp`
- `execve`
- `execveat`
- `waitpid`

Current `libchaos-process` effects:

- `ERRNO`
- `LATENCY`
- `FAIL_AFTER`

Current `libchaos-process` verification snapshot:

- passed: `make unit`
- passed: `make coverage`
- passed: glibc amd64 Docker runtime
- passed: glibc arm64 Docker runtime
- passed: musl amd64 Docker runtime
- passed: musl arm64 Docker runtime

Current `libchaos-process` gaps:

- selectors are symbol-only today
- `waitid()`, `kill()`, `pthread_kill()`, `clone*()`, and `vfork()` remain
  future work
- `execveat()` depends on the current libc exporting that symbol; some musl
  environments do not

## Phase 1: Close The Biggest Real-World Gaps

These items deliver the best coverage gain without changing the current config
model or inflating the library too much.

- [x] Add `openat`
  - Existing `open` rule semantics are reused.
  - Absolute paths, `AT_FDCWD`, and directory-fd relative paths are supported.
  - Successful calls seed the fd cache with the resolved path.
- [x] Add Linux `sendfile`
  - Treated as a destination-side `write` operation.
  - Supports `ERRNO`, `LATENCY`, and `TORN`.
- [x] Add a glibc Docker runtime test matching the Alpine musl test
  - The dedicated glibc runtime script exists and is part of the repo.
- [x] Extend unit tests for every new wrapper branch and failure path
  - `openat`, Linux `sendfile`, and the `TORN` contract regression are covered.
- [x] Document the exact matching semantics for `openat` and Linux `sendfile`
  - `README`, architecture notes, and engineering notes are updated.

Phase 1 release-gate closure is still separate and remains open:

- [x] Close the cross-target gate for `openat`
  - Reuse existing `open` rule semantics.
  - Support absolute paths, `AT_FDCWD`, and directory-fd relative paths.
  - Cache the resolved path for the returned fd after success.
  - Complete glibc/musl amd64/arm64 runtime proof now passes locally.
  - Cross-target completion gate applies.
- [x] Close the cross-target gate for Linux `sendfile`
  - Treat it as a destination-side `write` operation.
  - Support `ERRNO`, `LATENCY`, and `TORN`.
  - Complete glibc/musl amd64/arm64 runtime proof now passes locally.
  - Cross-target completion gate applies.
- [x] Close the cross-target gate for the glibc Docker runtime test.
  - A matching glibc runtime test is already landed.
  - Local amd64 and arm64 runtime proof now pass.
  - Cross-target completion gate applies.
- [x] Close the cross-target gate for unit coverage of the Phase 1 wrappers.
  - Unit branches for `openat`, Linux `sendfile`, and the `TORN` fix are
    already landed.
  - Linux amd64 and arm64 unit plus coverage execution in Docker pass.
  - Cross-target completion gate applies.
- [x] Close the cross-target gate for Phase 1 documentation.
  - `README`, architecture notes, and engineering notes already describe
    `openat` and Linux `sendfile` semantics.
  - Cross-target completion gate applies.

## Phase 2: Finish Modern File Copy And Buffered I/O Coverage

These additions keep the same logical fault model while covering more real
applications.

- [x] Add `copy_file_range`
  - Treat it as a destination-side `write` operation.
  - Support `ERRNO`, `LATENCY`, and `TORN`.
  - Local glibc/musl amd64/arm64 runtime proof now passes.
  - Cross-target completion gate applies.
- [x] Extend native Linux integration tests for `copy_file_range`
  - Linux amd64 Docker integration proof passes locally.
  - Cross-target completion gate applies.
- [x] Extend Docker runtime tests for `copy_file_range` on both libc families
  - glibc and musl amd64/arm64 runtime proof now passes locally.
  - Cross-target completion gate applies.
- [x] Extend native Linux integration tests for vectored I/O
  - Linux amd64 Docker integration proof for `readv`, `writev`, `preadv`, and
    `pwritev` now passes locally.
  - Cross-target completion gate applies.
- [x] Extend Docker runtime tests for vectored I/O on both libc families
  - glibc and musl amd64/arm64 runtime proof for `readv`, `writev`, `preadv`,
    and `pwritev` now passes locally.
  - Cross-target completion gate applies.
- [x] Add `readv`
  - Reuses `read` semantics across the concatenated iovec byte stream.
  - Local glibc/musl amd64/arm64 runtime proof now passes.
  - Cross-target completion gate applies.
- [x] Add `writev`
  - Reuses `write` semantics across the concatenated iovec byte stream.
  - Local glibc/musl amd64/arm64 runtime proof now passes.
  - Cross-target completion gate applies.
- [x] Add `preadv`
  - Reuses `pread` semantics across the concatenated iovec byte stream.
  - Local glibc/musl amd64/arm64 runtime proof now passes.
  - Cross-target completion gate applies.
- [x] Add `pwritev`
  - Reuses `pwrite` semantics across the concatenated iovec byte stream.
  - Local glibc/musl amd64/arm64 runtime proof now passes.
  - Cross-target completion gate applies.

## Phase 3: File Lifecycle And Capacity Operations

These operations are valuable, but they likely require expanding the config
surface with new logical operations rather than silently reusing unrelated ones.

- [x] Define the config contract for these operations before implementation.
  - Added logical operations: `truncate`, `allocate`, `unlink`,
    `rename_from`, and `rename_to`.
  - Only `ERRNO` and `LATENCY` apply in this phase.
  - Cross-target completion gate passed locally in Docker across glibc/musl and
    amd64/arm64.
- [x] Add `ftruncate`
  - Implemented with logical `truncate` matching on the target fd path.
  - Cross-target completion gate passed locally in Docker across glibc/musl and
    amd64/arm64.
- [x] Add `fallocate`
  - Implemented as a Linux-only wrapper with logical `allocate` matching on the
    target fd path.
  - Cross-target completion gate passed locally in Docker across glibc/musl and
    amd64/arm64.
- [x] Add `renameat`
  - Implemented with explicit `rename_from` and `rename_to` matching and
    successful-cache reset behavior.
  - Cross-target completion gate passed locally in Docker across glibc/musl and
    amd64/arm64.
- [x] Add `unlinkat`
  - Implemented with logical `unlink` matching and successful-cache reset
    behavior.
  - Cross-target completion gate passed locally in Docker across glibc/musl and
    amd64/arm64.
- [x] Add unit and runtime tests for each new operation/effect combination.
  - Docker proof now passes for unit amd64/arm64, coverage amd64/arm64, glibc
    runtime amd64/arm64, musl runtime amd64/arm64, and Linux amd64 integration.
  - Cross-target completion gate applies.

Notes:

- `ftruncate` and `fallocate` are useful for realistic storage and capacity
  failures.

## libchaos-net Phase 1: Endpoint-Based Network Surface

- [x] Add a dedicated `/tmp/.chaos-net.conf` grammar with endpoint selectors.
  - Implemented selectors: `*`, `tcp4`, `tcp6`, `udp4`, `udp6`, `unix`, and
    `dns`.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add endpoint-based matching instead of fd-number matching.
  - Matching now uses peer, local, or DNS identities depending on the logical
    operation.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add the first socket wrapper set.
  - Implemented operations: `bind`, `listen`, `connect`, `accept`,
    `send`, `recv`, and `dns`.
  - `accept` is backed by `accept()` and Linux `accept4()`.
  - `send` is backed by `send()`, `sendto()`, and `sendmsg()`.
  - `recv` is backed by `recv()`, `recvfrom()`, and `recvmsg()`.
  - `dns` is backed by `getaddrinfo()`.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add the first network effect set.
  - Implemented effects: `ERRNO`, `LATENCY`, `CORRUPT`, and `GAI`.
  - `CORRUPT` is receive-only.
  - `GAI` is DNS-only.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add the remaining planned network wrapper surface.
  - Implemented operations now also include `socket`, `shutdown`, and `poll`.
  - `socket` is backed by `socket()` and `socketpair()`.
  - `poll` is backed by `poll()`, `ppoll()`, `select()`, `pselect()`, and
    Linux `epoll_wait()` plus `epoll_pwait()`.
  - `send` now also covers Linux `sendmmsg()`.
  - `recv` now also covers Linux `recvmmsg()`.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add the remaining planned network effect set.
  - Implemented effect: `TIMEOUT` for readiness waits.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Add Docker runtime probes for `libchaos-net`.
  - Dedicated glibc and Alpine runtime scripts now exist.
  - Cross-target runtime gate passed locally on glibc/musl and amd64/arm64.
- [x] Promote changed `libchaos-net` sources into the strict `100.00%` source
  coverage gate.
  - `check_coverage.sh` now asserts `src/net/*.c` at `100.00%` line coverage.
  - Linux amd64 and arm64 Docker coverage runs pass.
- `renameat` and `unlinkat` matter for atomic replace patterns, compaction, WAL
  rotation, and cleanup behavior.

## Phase 4: Mapped File I/O

This is high value for databases, but it is not a small extension of the
current wrapper model.

- [ ] Design mapped-I/O semantics before implementation.
  - Cross-target completion gate applies.
- [ ] Evaluate `mmap`
  - Cross-target completion gate applies.
- [ ] Evaluate `msync`
  - Cross-target completion gate applies.
- [ ] Decide how mapped writes should relate to `TORN`, `ERRNO`, and durability
  failures.
  - Cross-target completion gate applies.

Notes:

- SQLite and LMDB style workloads make this valuable.
- The failure model is different enough that this phase should not be mixed into
  earlier wrapper work.

## Deferred Inside `libchaos-io`

These are useful but not in the first execution path.

- [ ] Evaluate `openat2`
  - Cross-target completion gate applies.
- [ ] Evaluate `statfs`
  - Cross-target completion gate applies.

Notes:

- `openat2` is Linux-specific and ABI-sensitive; it should come only after
  `openat` is solid.
- `statfs` can fake visible disk pressure, but it does not replace real write or
  sync failures.

## Not Planned For `libchaos-io`

The following areas are worth pursuing, but they should not be added to
`libchaos-io` itself. Folding them into this library would increase code size,
semantic complexity, and cross-libc risk too much.

### Network Chaos

Candidate future library: `libchaos-net`

- `connect`
- `accept`
- `send`
- `recv`
- `sendmsg`
- `recvmsg`
- `getaddrinfo`
- `poll`
- `epoll_wait`
YOU 
### Time Chaos

Current shipped library: `libchaos-time`

- `clock_gettime`
- `nanosleep`
- `usleep`

Candidate future time hooks:

- `clock_nanosleep`
- `gettimeofday`

### Memory Chaos

Current shipped library: `libchaos-memory`

- `mmap`
- `munmap`
- `madvise`
- `mprotect`

Candidate future memory hooks:

- `mmap64`
- `mremap`
- `brk`
- `sbrk`

### Process Chaos

Candidate future library: `libchaos-proc`

- `fork`
- `clone`

## CI And Verification Roadmap

- [ ] Keep unit tests as the primary branch-complete correctness gate.
  - Cross-target completion gate applies.
- [ ] Keep native Linux integration tests for end-to-end local verification.
  - Cross-target completion gate applies.
- [ ] Keep musl Docker runtime verification.
  - Cross-target completion gate applies.
- [ ] Close the cross-target gate for glibc Docker runtime verification.
  - The runtime test exists and passes on arm64 locally.
  - The remaining local gap is amd64 runtime proof on a Docker host with enough
    free space.
  - Cross-target completion gate applies.
- [ ] Run runtime tests on both amd64 and arm64 CI runners.
  - Cross-target completion gate applies.
- [ ] Report artifact sizes for every dist build.
  - Cross-target completion gate applies.
- [ ] Add a size budget only after the current artifact sizes are stable.
  - Cross-target completion gate applies.

## Execution Order

Recommended implementation order:

1. `openat` with the cross-target completion gate enforced
2. `sendfile` with the cross-target completion gate enforced
3. glibc Docker runtime test with the cross-target completion gate enforced
4. `copy_file_range` with the cross-target completion gate enforced
5. `readv` / `writev` / `preadv` / `pwritev` with the cross-target completion gate enforced
6. file lifecycle and capacity operations with the cross-target completion gate enforced
7. mapped file I/O design with the cross-target completion gate enforced
8. separate sibling libraries for network, time, memory, and process chaos, each with their own cross-target completion gate
