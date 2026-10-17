<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# Roadmap

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

The repository ships six libraries (`libchaos-io`, `libchaos-net`,
`libchaos-dns`, `libchaos-time`, `libchaos-memory`, `libchaos-process`) and
the SECCOMP-mode supervisor `chaos-init`. This roadmap records what was
planned, what is implemented (checked against `src/`), and what remains.

It answers two questions:

1. What belongs in `libchaos-io` itself?
2. Which chaos surfaces belong in separate libraries, so that no library
   loses its small, auditable shape?

Status markers: `[x]` implemented and verified in `src/`; `[ ]` open.

## Constraints

Every change must keep:

- the Linux `LD_PRELOAD` model (and, for SECCOMP mode, a static `chaos-init`)
- C99, `-Wall -Wextra -Werror -pedantic`
- a small source footprint and object size (`-Os`, stripped)
- no public SDK or C API
- explicit control flow over generic abstraction
- 100.00 % line coverage per source file
- runtime verification on glibc and musl, amd64 and arm64, for the release
  tuples glibc-amd64, glibc-arm64, musl-amd64, musl-arm64

## Cross-Target Completion Gate

A step is complete only when:

- it builds for all four tuples
- its runtime behaviour is verified on glibc and musl
- its runtime behaviour is verified on amd64 and arm64

Since `matrix.yml`, CI enforces this on every branch push: each tuple is
built and runtime-tested on a runner of its own architecture
(`ubuntu-24.04`, `ubuntu-24.04-arm`). Host-local success never closes a step.

## Historical Failure Pattern

In the pre-publication history (not an ancestor of the current branch), root
commit `99de3e4` (2026-04-05) contained the first `libchaos-io`
implementation, and commit `0819122` (2026-04-06) added Alpine musl runtime
verification. No `src/` file changed between them (`git diff --stat 99de3e4
0819122 -- src` is empty): musl correctness had been assumed, not shown.

Rules derived from it:

- host-only verification is not implementation validity
- build-only verification is not runtime validity
- implementation and cross-target proof land together, not as later cleanup
- a wrapper is complete only when proven on the full libc and architecture matrix

## Current Status

### `libchaos-io`

Implemented wrappers: `open`, `open64`, `openat`, `openat64`, `__open_2`,
`__open64_2`, `__openat_2`, `__openat64_2`, `creat`, `creat64`, `read`,
`readv`, `__read_chk`, `write`, `writev`, `pread`, `pread64`, `__pread_chk`,
`__pread64_chk`, `preadv`, `preadv64`, `pwrite`, `pwrite64`, `pwritev`,
`pwritev64`, `sendfile`, `sendfile64`, `copy_file_range`, `fsync`,
`fdatasync`, `ftruncate`, `ftruncate64`, `truncate`, `truncate64`,
`fallocate`, `fallocate64`, `posix_fallocate`, `posix_fallocate64`,
`unlink`, `unlinkat`, `rmdir`, `remove`, `rename`, `renameat`, `renameat2`,
`close`, `close_range`, `closefrom`, `closedir`, `pclose`, `dup2`, `dup3`,
and stdio (`fopen`, `fopen64`, `freopen`, `freopen64`, `fclose`, `fread`,
`fwrite`, `fgets`, `fputs`, `fgetc`, `getc`, `fputc`, `putc`, `getline`,
`getdelim`, `__getdelim`, `fprintf`, `vfprintf`, `fflush`, `__fread_chk`,
`__fgets_chk`, `__fprintf_chk`, `__vfprintf_chk`).

Effects: `ERRNO`, `LATENCY`, `TORN` (write class), `CORRUPT` (read class).

Known gaps:

- data moved by `splice`, or through `mmap`ed pages, bypasses the write
  wrappers (`cp` variants may use `splice`)
- `scanf` family and `*_unlocked` stdio are not wrapped

### `libchaos-net`

Implemented operations and the symbols behind them:

| Operation | Symbols |
| --- | --- |
| `socket` | `socket`, `socketpair` |
| `bind` | `bind` |
| `listen` | `listen` |
| `connect` | `connect` |
| `accept` | `accept`, `accept4` |
| `shutdown` | `shutdown` |
| `poll` | `poll`, `__poll_chk`, `ppoll`, `__ppoll_chk`, `select`, `pselect`, `epoll_wait`, `epoll_pwait` |
| `send` | `send`, `sendto`, `sendmsg`, `sendmmsg`, and `write`/`writev` on sockets |
| `recv` | `recv`, `__recv_chk`, `recvfrom`, `__recvfrom_chk`, `recvmsg`, `recvmmsg`, and `read`/`readv`/`__read_chk` on sockets |
| `close` | `close` on sockets |

Effects: `ERRNO`, `LATENCY`, `CORRUPT` (recv), `TIMEOUT` (poll), `RESET`
(close), `TRICKLE` (recv on stream sockets), `DUP` (recv).

Known gaps:

- epoll matching reads `/proc/self/fdinfo/<epfd>` per wait (at most
  256 KiB); when unreadable the wait passes through
- DNS moved to `libchaos-dns`; `libchaos-net` has no `dns` operation and no
  `GAI` effect

### `libchaos-dns`

Implemented: `getaddrinfo`, `freeaddrinfo`, `getnameinfo`, `gethostbyname`,
`gethostbyname_r`, `gethostbyname2`, `gethostbyname2_r`, `gethostbyaddr`,
`gethostbyaddr_r`. Effects: `GAI`, `LATENCY`, `REWRITE`, `SERVICE`,
`OVERRIDE`, `FILTER_FAMILY`, `SHUFFLE`, `LIMIT`.

### `libchaos-time`

Implemented: `clock_gettime`, `gettimeofday`, `time`, `timespec_get`,
`nanosleep`, `clock_nanosleep`, `sleep`, `usleep`. Effects: `ERRNO`,
`LATENCY`, `OFFSET`, `REGRESS`.

### `libchaos-memory`

Implemented: `mmap`, `mmap64`, `munmap`, `mprotect`, `madvise`,
`posix_madvise`. Effects: `ERRNO`, `LATENCY`.

### `libchaos-process`

Implemented: `pthread_create`, `fork`, `posix_spawn`, `posix_spawnp`,
`system`, `popen`, `execve`, `execveat`, `execv`, `execvp`, `execvpe`,
`execl`, `execle`, `execlp`, `fexecve`, `waitpid`, `wait`, `wait3`, `wait4`,
`waitid`. Effects: `ERRNO`, `LATENCY`, `FAIL_AFTER`.

Known gaps:

- selectors are `*` or an operation name; there is no selector by program
  path, argument or pid
- `kill`, `pthread_kill`, `clone*` and `vfork` are not interposed
- `execveat`, `execvpe` and `fexecve` work only where the libc exports them;
  otherwise the wrapper reports `ENOSYS`

### Implemented beyond the original plan

- [x] rule qualifiers `@first`, `@from`, `@until`, `@size` in every library
- [x] status file `/tmp/.chaos-<lib>.status` after every load
- [x] per-process hits files `/tmp/.chaos-<lib>.hits.<n>`
- [x] glibc alternate entry points (`*64`, `__*_chk`), runtime-tested by `test_variants_glibc.sh`
- [x] io/net sharing of `read`/`write`/`readv`/`writev`/`close` by descriptor kind, runtime-tested by `test_sharing_glibc.sh`
- [x] SECCOMP mode: `chaos-init` applies io, net, memory and process rules to static and Go binaries (see [SECCOMP.md](../SECCOMP.md))
- [x] rule-file check throttled to once per millisecond (vDSO clock)

## Phase 1: Close The Biggest Real-World Gaps

Coverage gains without changing the config model.

- [x] Add `openat`
  - Reuses `open` rule semantics.
  - Absolute paths, `AT_FDCWD` and directory-fd-relative paths are resolved before matching.
  - A successful call seeds the fd cache with the resolved path.
- [x] Add Linux `sendfile`
  - Destination-side `write`; `ERRNO`, `LATENCY`, `TORN`.
- [x] Add a glibc Docker runtime test matching the Alpine musl test
  - `test/runtime/test_glibc.sh`.
- [x] Unit tests for every new wrapper branch and failure path
  - `openat`, `sendfile` and the `TORN` contract regression are covered.
- [x] Document the matching semantics for `openat` and `sendfile`

Cross-target gate for Phase 1:

- [x] `openat` on glibc/musl, amd64/arm64
- [x] `sendfile` on glibc/musl, amd64/arm64
- [x] glibc runtime test on amd64 and arm64
- [x] unit and coverage runs for the Phase 1 wrappers
- [x] Phase 1 documentation

## Phase 2: Finish Modern File Copy And Buffered I/O Coverage

Same fault model, more real applications.

- [x] Add `copy_file_range`
  - Destination-side `write`; `ERRNO`, `LATENCY`, `TORN`.
- [x] Native Linux integration tests for `copy_file_range`
- [x] Docker runtime tests for `copy_file_range` on both libc families
- [x] Native Linux integration tests for vectored I/O
- [x] Docker runtime tests for vectored I/O on both libc families
- [x] Add `readv` — `read` semantics over the concatenated iovec byte stream
- [x] Add `writev` — `write` semantics over the concatenated iovec byte stream
- [x] Add `preadv` — `pread` semantics over the concatenated iovec byte stream
- [x] Add `pwritev` — `pwrite` semantics over the concatenated iovec byte stream
- [x] Buffered I/O: stdio read and write wrappers (`fread`, `fwrite`, `fgets`,
  `fprintf`, ...), with `ERRNO` raising the stream's error indicator

## Phase 3: File Lifecycle And Capacity Operations

New logical operations rather than reuse of unrelated ones.

- [x] Define the config contract
  - Operations `truncate`, `allocate`, `unlink`, `rename_from`, `rename_to`;
    only `ERRNO` and `LATENCY` apply.
- [x] Add `ftruncate` (and `truncate`) — `truncate` on the target path
- [x] Add `fallocate` (and `posix_fallocate`) — `allocate` on the target path
- [x] Add `renameat` (and `rename`, `renameat2`) — `rename_from`/`rename_to`;
  a successful rename resets the fd cache
- [x] Add `unlinkat` (and `unlink`, `rmdir`, `remove`) — `unlink`; a
  successful unlink resets the fd cache
- [x] Unit and runtime tests for every operation/effect combination

`ftruncate` and `fallocate` model storage and capacity failures; `renameat`
and `unlinkat` model atomic replace, compaction, WAL rotation and cleanup.

## libchaos-net Phase 1: Endpoint-Based Network Surface

- [x] Dedicated `/tmp/.chaos-net.conf` grammar with endpoint selectors
  - Selectors: `*`, `tcp4`, `tcp6`, `udp4`, `udp6`, `unix`. (The original
    `dns` selector moved to `libchaos-dns`.)
- [x] Endpoint-based matching instead of descriptor-number matching
  - Peer or local identity depending on the operation.
- [x] First socket wrapper set
  - `bind`, `listen`, `connect`, `accept` (`accept`, `accept4`), `send`
    (`send`, `sendto`, `sendmsg`), `recv` (`recv`, `recvfrom`, `recvmsg`).
  - The original `dns` operation (`getaddrinfo`) moved to `libchaos-dns`.
- [x] First network effect set
  - `ERRNO`, `LATENCY`, `CORRUPT` (recv only). The original `GAI` effect moved
    to `libchaos-dns`.
- [x] Remaining planned wrapper surface
  - `socket` (`socket`, `socketpair`), `shutdown`, `poll` (`poll`, `ppoll`,
    `select`, `pselect`, `epoll_wait`, `epoll_pwait`); `sendmmsg`, `recvmmsg`.
- [x] Remaining planned effect set: `TIMEOUT` for readiness waits
- [x] Docker runtime probes for `libchaos-net` on glibc and Alpine
- [x] `src/net/*.c` inside the 100.00 % per-file coverage gate
- [x] Generic descriptor calls on sockets: `read`/`readv` as `recv`,
  `write`/`writev` as `send`, `close` as `close`, shared with `libchaos-io`
  by descriptor kind (supersedes the earlier "net does not own read/write/close")
- [x] Receive and teardown effects: `RESET`, `TRICKLE`, `DUP`

## Phase 4: Mapped File I/O

High value for databases (SQLite, LMDB), but not a small extension of the
wrapper model.

- [ ] Design mapped-I/O semantics before implementation.
- [x] Evaluate `mmap`
  - The mapping boundary is covered by `libchaos-memory`: `mmap/file` and
    `mmap/anon` selectors with `ERRNO` and `LATENCY`. Faults on the data of
    mapped pages remain undesigned.
- [ ] Evaluate `msync`
- [ ] Decide how mapped writes relate to `TORN`, `ERRNO` and durability failures.

The failure model differs enough that this phase stays separate from the
earlier wrapper work. Cross-target completion gate applies.

## Deferred Inside `libchaos-io`

- [ ] Evaluate `openat2` — Linux-specific and ABI-sensitive (`struct open_how`);
  after `openat` is settled.
- [ ] Evaluate `statfs` — can fake visible disk pressure, but does not replace
  real write or sync failures.

Cross-target completion gate applies.

## Not Planned For `libchaos-io`

These surfaces belong in separate libraries; folding them into `libchaos-io`
would grow size, semantic complexity and cross-libc risk.

### Network Chaos

Shipped as `libchaos-net` (sockets) and `libchaos-dns` (resolver):

- [x] `connect`
- [x] `accept`
- [x] `send`
- [x] `recv`
- [x] `sendmsg`
- [x] `recvmsg`
- [x] `getaddrinfo` (in `libchaos-dns`)
- [x] `poll`
- [x] `epoll_wait`

### Time Chaos

Shipped as `libchaos-time`:

- [x] `clock_gettime`
- [x] `nanosleep`
- [x] `usleep`
- [x] `clock_nanosleep` (under the `nanosleep` rules)
- [x] `gettimeofday` (under the `clock_gettime/realtime` rules)

### Memory Chaos

Shipped as `libchaos-memory`:

- [x] `mmap`
- [x] `munmap`
- [x] `madvise`
- [x] `mprotect`
- [x] `mmap64` (alias on 64-bit glibc)
- [ ] `mremap`
- [ ] `brk`
- [ ] `sbrk`

### Process Chaos

Shipped as `libchaos-process` (planned under the name `libchaos-proc`):

- [x] `fork`
- [ ] `clone`
- [ ] `vfork` (a wrapper must not sleep in the child, which shares the parent's stack)
- [ ] `kill`, `pthread_kill`

## CI And Verification Roadmap

- [x] Unit tests as the primary branch-complete correctness gate
  (`make unit`, `make coverage` at 100.00 % per file; ASan and UBSan runs)
- [x] Native Linux integration tests (`ci.yml`, every glibc runtime suite)
- [x] musl Docker runtime verification (`matrix.yml`, Alpine suites)
- [x] glibc Docker runtime verification on amd64 and arm64 (`matrix.yml`)
- [x] Runtime tests on both amd64 and arm64 CI runners
- [x] glibc symbol-version floor (`check_glibc_baseline.sh`, `GLIBC_2.17`, release gate)
- [x] Report artifact sizes for every dist build (`ls -lah` of every
  `dist/libchaos-*.so` in `matrix.yml`; job log only)
- [ ] Add a size budget once artifact sizes are stable

## Execution Order

1. [x] `openat`
2. [x] `sendfile`
3. [x] glibc Docker runtime test
4. [x] `copy_file_range`
5. [x] `readv` / `writev` / `preadv` / `pwritev`
6. [x] file lifecycle and capacity operations
7. [ ] mapped file I/O design
8. [x] sibling libraries for network, DNS, time, memory and process chaos

Each step carries its own cross-target completion gate.

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
