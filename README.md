<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

<div align="center">

# macstab-chaos-testing-libraries

**Pure C99 `LD_PRELOAD` chaos engineering for any Linux process. Kernel-real syscall faults — language-agnostic, zero runtime dependencies beyond libc and libdl, 100% line-coverage gated.**

[![ci](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/ci.yml/badge.svg)](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/ci.yml)
[![matrix](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/matrix.yml/badge.svg)](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/matrix.yml)
[![CodeQL](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/codeql.yml/badge.svg)](https://github.com/macstab/macstab-chaos-testing-libraries/actions/workflows/codeql.yml)
[![C99](https://img.shields.io/badge/C-C99-00599C.svg)](https://en.wikipedia.org/wiki/C99)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Linux](https://img.shields.io/badge/Linux-LD__PRELOAD-FCC624.svg)](https://man7.org/linux/man-pages/man8/ld.so.8.html)
[![libc: glibc + musl](https://img.shields.io/badge/libc-glibc%20%2B%20musl-lightgrey.svg)](https://musl.libc.org/)
[![arch: amd64 + arm64](https://img.shields.io/badge/arch-amd64%20%2B%20arm64-blue.svg)](https://en.wikipedia.org/wiki/AArch64)
[![coverage: 100% on shipped sources](https://img.shields.io/badge/coverage-100%25%20shipped%20sources-brightgreen.svg)](#coverage-gate)

*Designed and engineered by* **[Christian Schnapka](https://macstab.com)** —
Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

</div>

---

## Overview

Six Linux fault-injection libraries make real libc calls fail, stall or return
altered results, driven by a plain-text rule file that can be rewritten while the
target runs:

| Library | Domain | Rule file |
|---|---|---|
| `libchaos-io` | file I/O, including buffered stdio | `/tmp/.chaos-io.conf` |
| `libchaos-net` | sockets, multiplexed waits | `/tmp/.chaos-net.conf` |
| `libchaos-dns` | `getaddrinfo`, `getnameinfo`, `gethostby*` | `/tmp/.chaos-dns.conf` |
| `libchaos-time` | clocks and sleeps | `/tmp/.chaos-time.conf` |
| `libchaos-memory` | `mmap`, `munmap`, `mprotect`, `madvise` | `/tmp/.chaos-memory.conf` |
| `libchaos-process` | threads, `fork`, spawn, exec, wait | `/tmp/.chaos-process.conf` |

Two injection modes apply the same rule files:

- **LD_PRELOAD mode.** Each library is a shared object whose exported wrappers
  shadow the libc symbols. A wrapper matches the call against the rules, applies the
  effect, and forwards to the real function (the next definition, resolved with
  `dlsym(RTLD_NEXT)`). Works for any dynamically linked program, in any language.
- **SECCOMP mode.** `chaos-init`, a static supervisor run as the container's PID 1,
  installs a seccomp user-notification filter on its child (the tracee) and decides
  every notified system call with the libraries' own rule cores. Works for statically
  linked programs (Go with `CGO_ENABLED=0`, `FROM scratch` images) that `LD_PRELOAD`
  cannot reach. It applies io, net, memory and process rules; see
  [SECCOMP Mode (chaos-init)](#seccomp-mode-chaos-init).

There is no public C API. A library's whole interface is its interposed symbols,
its rule file, its status file (`/tmp/.chaos-<lib>.status`) and its hits files
(`/tmp/.chaos-<lib>.hits.<n>`).

## Part of a Three-Layer Chaos Engineering Stack

`chaos-testing-libraries` is the **`LD_PRELOAD` libc layer** of a vertically-integrated chaos engineering toolkit. This repo is self-contained — everything in this README works standalone — but it composes with two sibling layers when broader coverage is needed.

| Layer                              | Repo                                                                                                    | What it covers                                                                                                                                                                                                                |
|------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`LD_PRELOAD` libc** (this repo)  | [`macstab/macstab-chaos-testing-libraries`](https://github.com/macstab/macstab-chaos-testing-libraries) | Pure C99 `LD_PRELOAD` shared objects: file I/O (latency / `errno` / torn / corrupt), network, DNS, clock, process, memory, plus the `chaos-init` seccomp supervisor for static binaries. **glibc + musl × amd64 + arm64**, 100 % line coverage on shipped sources, Docker runtime validation as a quality gate. Language-agnostic — works for any process inside any container. |
| **JVM bytecode**                   | [`macstab/macstab-chaos-jvm-agent`](https://github.com/macstab/macstab-chaos-jvm-agent)                 | 62 JDK call sites instrumented in-process. Spring Boot 3/4 + Micronaut + Quarkus integration. JUnit 5 `@ChaosTest`. Selector × effect × policy DSL. Live config reload.                                                       |
| **Container orchestration**        | [`macstab/chaos-testing`](https://github.com/macstab/chaos-testing)                                     | Annotation-driven chaos on top of Testcontainers. CPU throttling, memory pressure, disk I/O, network partitions, DNS failures, pre-built Redis Sentinel + replication-lag scenarios, Toxiproxy adapter, Redis-aware fault injection.                                                                              |

**Start here** when failure injection must cross language boundaries, or when the
fault has to be kernel-real: time skew, slow disks and DNS slowdowns that an
in-process agent cannot produce. Example: `clock_gettime` is served by the vDSO,
which the JVM does not route through any interceptable Java call site; the libc
layer wraps it.

**Compose layers** for distributed-system coverage:
- Add the JVM agent for selector × effect × policy chaos *inside* JVM call sites — DNS, JDBC, NIO, virtual threads, monitors, GC.
- Add the orchestration layer to wire chaos to Testcontainers-managed Redis, Postgres, Kafka — including pre-built scenarios like *replication lag during pod drainage*.

All three layers share one model: **selector × effect × policy** (mapping in
[`docs/DSL.md`](docs/DSL.md)). There is no cross-layer coupling; each layer is
adopted, versioned and released independently.

## Design Constraints

| Constraint | How it is held |
|---|---|
| Pure C99, no C++ runtime | `-std=c99 -pedantic -Wall -Wextra -Werror` on every library, `chaos-init` and unit-test build |
| No runtime dependency beyond libc and `libdl` | `-ldl` is the only link library; status and hits files are written with raw system calls |
| glibc and musl, amd64 and arm64 | Docker runtime probes on all four cells (`make test-matrix`); release `.so` files reference no glibc symbol version above `GLIBC_2.17` (`test/runtime/check_glibc_baseline.sh`) |
| Fail-open | A missing, unreadable or invalid rule file means no rules: every call passes through unchanged |
| Small, boring artifacts | Hidden visibility, section GC, stripped, no unwind tables ([Minimal Artifact Strategy](#minimal-artifact-strategy)) |
| Quality gate in-repo | `make check` = `fmt-check` + 100 % line coverage of every shipped source + runtime probes ([Build And Test](#build-and-test)) |

## Table of Contents
<!-- TOC -->
* [macstab-chaos-testing-libraries](#macstab-chaos-testing-libraries)
  * [Overview](#overview)
  * [Part of a Three-Layer Chaos Engineering Stack](#part-of-a-three-layer-chaos-engineering-stack)
  * [Design Constraints](#design-constraints)
  * [Table of Contents](#table-of-contents)
  * [Quick Start](#quick-start)
  * [Rule Files](#rule-files)
  * [Rule Qualifiers](#rule-qualifiers)
  * [Status and Hits Files](#status-and-hits-files)
  * [libchaos-io Config Format](#libchaos-io-config-format)
    * [Operations](#operations)
    * [Effects](#effects)
    * [Supported Errnos](#supported-errnos)
    * [Matching Rules](#matching-rules)
  * [libchaos-net](#libchaos-net)
  * [libchaos-dns](#libchaos-dns)
  * [libchaos-time](#libchaos-time)
  * [libchaos-memory](#libchaos-memory)
  * [libchaos-process](#libchaos-process)
  * [Runtime Behavior](#runtime-behavior)
  * [SECCOMP Mode (chaos-init)](#seccomp-mode-chaos-init)
  * [Limits](#limits)
  * [Repository Layout](#repository-layout)
  * [Build And Test](#build-and-test)
    * [Fast local loop](#fast-local-loop)
    * [Coverage gate](#coverage-gate)
    * [C style gate](#c-style-gate)
    * [Docker runtime probes](#docker-runtime-probes)
    * [Full local quality gate](#full-local-quality-gate)
    * [Full Docker matrix gate](#full-docker-matrix-gate)
    * [Build targets](#build-targets)
  * [Minimal Artifact Strategy](#minimal-artifact-strategy)
  * [More Detail](#more-detail)
  * [License](#license)
  * [About the Engineer](#about-the-engineer)
    * [Timeline](#timeline)
    * [Specific evidence in this project](#specific-evidence-in-this-project)
    * [Available for Principal+ engineering engagements](#available-for-principal-engineering-engagements)
<!-- TOC -->

## Quick Start

LD_PRELOAD mode, on a Linux host (`make native` refuses other hosts):

```sh
make native                                    # build/libchaos-{io,net,dns,time,process,memory}.so
mkdir -p /tmp/demo && echo hello > /tmp/demo/f
printf '/tmp/demo:read:EIO:1.0\n' > /tmp/.chaos-io.conf
LD_PRELOAD=$PWD/build/libchaos-io.so cat /tmp/demo/f   # cat: /tmp/demo/f: Input/output error
cat /tmp/.chaos-io.status                      # state=ok, rules=1, pid=<pid of that cat>
cat /tmp/.chaos-io.hits.*                      # 1<TAB>/tmp/demo:read:EIO:1.0
rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.hits.*
```

- Several libraries load together:
  `LD_PRELOAD="$PWD/build/libchaos-io.so $PWD/build/libchaos-net.so"`.
  They share no state, and `libchaos-io`/`libchaos-net` split `read`, `write`,
  `readv`, `writev` and `close` by descriptor type (files vs sockets) in either order.
- The library constructor loads the rule file, so rules written before the program
  starts apply from its first call. A rewrite while it runs takes effect within about
  1 ms ([Runtime Behavior](#runtime-behavior)).
- Rule files are trusted input: any user who can write `/tmp` can create them
  ([`docs/SAFETY.md` §9](docs/SAFETY.md#9-config-file-security)).

SECCOMP mode, for a statically linked program:

```sh
make native-init                               # build/chaos-init, linked -static
printf '/data:write:EIO:1.0\n' > /tmp/.chaos-io.conf
build/chaos-init --libs io -- /usr/local/bin/my-static-app
cat /tmp/.chaos-init.status                    # state=active | state=unsupported + reason=
```

In a container, `chaos-init` is the entrypoint:
`ENTRYPOINT ["/chaos-init", "--libs", "io,net", "--", "/app"]`.

The [`demo/`](demo/README.md) directory has 15 runnable `docker compose` profiles,
one per fault.

## Rule Files

Every library reads `/tmp/.chaos-<lib>.conf`, one rule per line. The path is fixed at
compile time.

- A rule is `selector`, optional `operation`, `effect`, `value`, separated by `:`. The
  exact field layout differs per library and is given in each library's section.
- `#` starts a comment; by convention the comment names the rule's owner
  (`… # payments-team`). Blank lines are skipped.
- **Probability** is written `0`, `1`, `0.` followed by digits, or `1.` followed by
  zeros: `[0.0, 1.0]`, parsed without `strtod`, so the application's `LC_NUMERIC`
  cannot change it. `nan`, `inf`, exponents and hex are rejected.
- **Latency** is a decimal count of milliseconds, at most 4 294 967 295.
- **Specificity**: when several rules match one call, the most specific selector wins
  (exact over prefix/suffix over wildcard; for io, the longest path prefix). io and
  net apply one rule per call. dns, time, memory and process match each effect kind
  separately, so a `LATENCY` rule and an `ERRNO` rule compose on the same call
  (`LATENCY` first).
- **All or nothing.** One invalid line rejects the whole file and leaves the library
  with no rules. The status file names the line.
- **Limits.** At most 256 rules and 1024 bytes per line. A file of 256 KiB
  (256 × 1024 bytes) or more is rejected as `file too large`; a file holding a NUL byte
  is rejected too.

## Rule Qualifiers

Every library accepts the same qualifiers (`src/common/chaos_policy.h`), written as
separate whitespace-delimited words after the rule and before any `#` comment:

| Qualifier | Meaning |
|---|---|
| `@first=N` | Fire at most N times per process (N ≥ 1), then go inert. |
| `@from=T` | Active once the wall clock reaches T (Unix milliseconds). |
| `@until=T` | Active while the wall clock is before T; the window is `[from, until)`. `@until` ≤ `@from` rejects the line. |
| `@size>N`, `@size<N` | Only calls that move more / fewer than N bytes. A call without a byte count never matches a size-gated rule (list in [`docs/DSL.md` §7.1](docs/DSL.md#71-todays-surface)). |

```text
tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 @first=3 # net
/data:write:EIO:1.0 @from=1760000000000 @until=1760000005000 # disk
tcp4://127.0.0.1:9092:send:LATENCY:200 @size>65536
```

- Windows are absolute so that every process in a container agrees on them. The time
  is read from the vDSO, so a `libchaos-time` `OFFSET` rule never moves another rule's
  window.
- A rule fires only when its probability gate, window, size gate and `@first` budget
  all pass. Only a firing counts as a hit.
- `@first` budgets are per process, survive a reload that keeps the rule's text, and
  start from zero in a forked child.
- An unknown or malformed qualifier, or qualifiers on a line without a rule, rejects
  the file. Numbers have at most 18 digits.

## Status and Hits Files

A rule file that does not parse and a rule that parses but never matches both look
like "no fault". Two files per library make each case visible; their full contract is
in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#status-file).

**Status file** `/tmp/.chaos-<lib>.status`, rewritten after every load:

```text
state=error
rules=0
line=3
reason=invalid rule
text=bogus-rule # typo
pid=4711
```

- `state=ok` with `rules=<n>` on success. On rejection: the 1-based `line`, the
  `reason` (`invalid rule`, `too many rules`, `file too large`, `file unreadable`,
  `file contains a NUL byte`, or in SECCOMP mode `unsupported in seccomp mode`) and the
  line as written (`text`, at most 200 bytes). File-level reasons report `line=0`.
- `pid` is the process that loaded the file. Every process with the library writes the
  same report; check that `pid` is the program you started.
- Without a rule file the status file is removed.

**Hits files** `/tmp/.chaos-<lib>.hits.<n>`, one per process, one line per rule:

```text
3	tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 # net
0	tcp4://127.0.0.1:6379:recv:LATENCY:200 # redis
```

- `<n>` is the pid. A program started by `execve` keeps the pid, so its file is
  `<pid>` followed by nine digits of its load time; the replaced image's file stays.
- Written on each of a process's first 64 hits, then at most every 100 ms on a hit,
  and at normal exit. A hit that is not due makes no system call.
- A forked child starts from zero; a `vfork` child counts into its parent's slots.
- Files of finished processes stay: sum every `.hits.<digits>` file for totals and
  remove them between test runs.
- Both files are written via a staging file and `rename`, with raw system calls, so an
  io rule cannot fail or delay a report, and `errno` is preserved. They are created
  with mode 0666 so that a process that dropped root can still update them.

## libchaos-io Config Format

Rule file `/tmp/.chaos-io.conf`. Each rule is exactly four fields:

```text
<path-prefix>:<operation>:<effect>:<value>
```

```text
/data:write:EIO:0.3
/data/wal.log:fsync:EIO:0.1
/data:write:LATENCY:200
/data:write:TORN:0.1
/data:read:CORRUPT:0.5
*:open:EMFILE:0.05
```

### Operations

| Operation | Calls |
|---|---|
| `read` | `read`, `readv`, `__read_chk`; stdio `fread`, `fgets`, `fgetc`, `getc`, `getline`, `getdelim`, `__getdelim`, `__fread_chk`, `__fgets_chk` |
| `write` | `write`, `writev`; Linux `sendfile` and `copy_file_range` (matched on the destination); stdio `fwrite`, `fputs`, `fputc`, `putc`, `fprintf`, `vfprintf`, `fflush`, `__fprintf_chk`, `__vfprintf_chk` |
| `open` | `open`, `openat`, `creat`, `fopen`, `freopen`, `__open_2`, `__openat_2` |
| `close` | `close` |
| `fsync` | `fsync` |
| `fdatasync` | `fdatasync` |
| `pread` | `pread`, `preadv`, `__pread_chk` |
| `pwrite` | `pwrite`, `pwritev` |
| `truncate` | `truncate`, `ftruncate` |
| `allocate` | Linux `fallocate`, `posix_fallocate` |
| `unlink` | `unlink`, `unlinkat`, `rmdir`, `remove` |
| `rename_from` | `rename`, `renameat`, `renameat2`, matched on the source path |
| `rename_to` | `rename`, `renameat`, `renameat2`, matched on the destination path |

On 64-bit glibc the large-file names (`open64`, `openat64`, `creat64`, `pread64`,
`pwrite64`, `preadv64`, `pwritev64`, `truncate64`, `ftruncate64`, `fallocate64`,
`posix_fallocate64`, `sendfile64`, `fopen64`, `freopen64`, `__open64_2`,
`__openat64_2`, `__pread64_chk`) are aliases of the same wrappers. The JDK, Redis,
nginx and MySQL bind to the `64` names and `_FORTIFY_SOURCE` builds to the `_chk`/`_2`
names, so each is interposed.

### Effects

| Effect field | `value` | Valid for | Behaviour |
|---|---|---|---|
| an errno name (`ERRNO`) | probability | every operation | Returns the call's failure value with `errno` set, without calling the real function. On `close` the real close runs first and the error is reported after it. Stdio calls fail as stdio does (0 items, `NULL`, `EOF`, -1) and raise the stream's error indicator, so `ferror()` is true. |
| `LATENCY` | milliseconds | every operation | Sleeps before the real call. Always fires: io `LATENCY` takes no probability. |
| `TORN` | probability | `write`, `pwrite` (not stdio) | Calls the real function with a shortened count: a short write, the rest of the buffer never written. |
| `CORRUPT` | probability | `read`, `pread`, stdio reads | Calls the real function, then flips a bit in the bytes it returned. |

### Supported Errnos

`EIO`, `ENOSPC`, `EDQUOT`, `EROFS`, `EACCES`, `EMFILE`, `ENFILE`, `ENOENT`.

### Matching Rules

- The longest matching path prefix wins; on equal length the earlier line wins.
- Matching is path-boundary aware: `/data` matches `/data` and `/data/file`, not
  `/database`.
- Paths are resolved before matching. Relative paths are joined to the working
  directory or the `*at` directory descriptor, then normalised lexically (`//`, `.`,
  `..`). Descriptor-based calls use the kernel's name from `/proc/self/fd/<fd>`.
  A rule prefix that contains a symbolic link also matches its resolved form
  (`/lib` matches `/usr/lib` where `/lib` links there).
- `*` matches regular paths only. Pipes, sockets, anonymous inodes and memfds
  (`pipe:[N]`, `socket:[N]`, `anon_inode:[…]`, `/memfd:…`) are left to rules that
  name them, so a `*` `TORN` rule cannot break an eventfd or a socket protocol.
- Never faulted: descriptors 0–2, every libchaos control file (`/tmp/.chaos-*`), and
  anything under `/proc`, `/sys` or `/dev`.

## libchaos-net

Rule file `/tmp/.chaos-net.conf`. Each rule is exactly four fields:

```text
<endpoint-selector>:<operation>:<effect>:<value>
```

```text
tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0
tcp4://*:8080:listen:LATENCY:250
udp4://127.0.0.1:5353:send:EHOSTUNREACH:0.2
tcp4://127.0.0.1:9000:recv:CORRUPT:0.1
tcp4://127.0.0.1:6379:recv:TRICKLE:1
tcp4://127.0.0.1:9092:recv:DUP:0.05
tcp4://*:5432:close:RESET:1.0
*:connect:ETIMEDOUT:0.05
```

**Endpoint selectors.** `*`; `tcp4://<ipv4>:<port>`, `tcp4://*:<port>`;
`tcp6://[<ipv6>]:<port>`, `tcp6://*:<port>`; the same for `udp4`/`udp6`;
`unix://<path>`, `unix://*`, and `unix://@name` for abstract sockets. The port is a
decimal number 0–65535; there is no port wildcard. Rank, lowest to highest: `*`, a
wildcard host or `unix://*`, an exact address and port, an exact UNIX path. The
family must match: `tcp4` never matches a `tcp6` or UDP socket.

**Operations and the address they match.**

| Operation | Calls | Matched address |
|---|---|---|
| `socket` | `socket`, `socketpair` | family and type only: `*`, `<family>://*:0` or `unix://*` |
| `bind` | `bind` | the address being bound |
| `listen` | `listen` | the socket's local address |
| `connect` | `connect` | the destination |
| `accept` | `accept`, Linux `accept4` | the listening socket's local address |
| `shutdown` | `shutdown` | local address, else the peer |
| `send` | `send`, `sendto`, `sendmsg`, Linux `sendmmsg`; `write`, `writev` on sockets | an explicit destination, else both ends (peer tried first) |
| `recv` | `recv`, `recvfrom`, `recvmsg`, Linux `recvmmsg`, glibc `__recv_chk`, `__recvfrom_chk`; `read`, `readv`, `__read_chk` on sockets | both ends (local tried first) |
| `poll` | `poll`, `ppoll`, `select`, `pselect`, `__poll_chk`, `__ppoll_chk`, Linux `epoll_wait`, `epoll_pwait` | any watched descriptor's endpoint |
| `close` | `close` on sockets | local address, else the peer |

On a connected socket, `send` and `recv` rules match either end in one search, so a
client rule naming the server's port and a server rule naming its own port both
match, and a wildcard for one end never shadows a more specific rule for the other.
`epoll_*` membership is read from `/proc/self/fdinfo/<epfd>`; if that read fails the
call passes through.

**Effects.**

| Effect field | `value` | Valid for | Behaviour |
|---|---|---|---|
| an errno name (`ERRNO`) | probability | every operation | Fails the call with that `errno` before the real call. On `close` the socket is closed first and the error reported after. |
| `LATENCY` | milliseconds | every operation | Sleeps before the real call; always fires. |
| `TIMEOUT` | probability | `poll` | Skips the real wait and waits out the call's own timeout as if nothing became ready (a signal ends it with `EINTR`, as it would end the real wait; `ppoll`, `pselect` and `epoll_pwait` wait under their signal mask), then returns 0 with `revents` / descriptor sets cleared; `select` leaves its timeout at 0. A wait without a timeout (-1 or `NULL`) is never timed out. |
| `CORRUPT` | probability | `recv` | Flips one bit within the bytes the real receive wrote. |
| `TRICKLE` | bytes per call (≥ 1) | `recv` | Every receive on a stream socket returns at most that many bytes; data stays complete and in order. Not applied to datagram sockets, `MSG_WAITALL` receives, requests no larger than the chunk, or `recvmsg`/`readv` with more than 64 iovecs. No probability. |
| `DUP` | probability | `recv` | Delivers the socket's previous payload again (with its sender address for datagrams) instead of new data: at-least-once delivery. Payloads are kept per socket up to 4 KiB (longer ones replay truncated) for 64 sockets at once. Skipped for `MSG_PEEK`, `MSG_TRUNC`, `MSG_OOB`, `MSG_WAITALL` and empty buffers. |
| `RESET` | probability | `close` | Sets `SO_LINGER` to 0 before the close, so the peer receives an RST (`ECONNRESET`) instead of a FIN, as after a crashed process or a load balancer drop. |

**Errnos.** `ECONNREFUSED`, `ETIMEDOUT`, `ECONNRESET`, `EHOSTUNREACH`, `ENETUNREACH`,
`EADDRINUSE`, `EADDRNOTAVAIL`, `EAFNOSUPPORT`, `EPROTONOSUPPORT`, `EPIPE`, `ENOTCONN`,
`EOPNOTSUPP`, `EINVAL`, `EINTR`, `ENOMEM`, `ENOBUFS`, `EMFILE`, `ENFILE`, `EAGAIN`.

**Boundaries.**

- `read`, `write`, `readv`, `writev` and `close` are shared with `libchaos-io`: net
  decides for sockets, io for files, each forwards the rest down the chain, so the two
  compose in either `LD_PRELOAD` order (`test/runtime/test_sharing_glibc.sh` checks
  every order). `libchaos-io`'s `*` rule never matches a socket.
- A socket whose endpoint cannot be resolved (unsupported family, unconnected for a
  peer lookup) passes through.
- Not covered: io_uring; corrupting or withholding descriptors received through
  `SCM_RIGHTS` (effects act on the payload only;
  [`docs/NETWORK.md` §16a](docs/NETWORK.md#16a-scm_rights-and-fd-passing--non-coverage)).

## libchaos-dns

Rule file `/tmp/.chaos-dns.conf`. Each rule is three fields:

```text
<selector>:<effect>:<value>
```

```text
dns://api.example.com:EAI_AGAIN:0.5
dns://*.example.internal:LATENCY:150@0.2
dns://payments.example.com:REWRITE:payments-canary.internal
dns://db.example.com:SERVICE:15432
dns://auth.example.com:OVERRIDE:127.0.0.1,[::1]
dns://api.example.com:FILTER_FAMILY:inet6@1.0
dns://api.example.com:LIMIT:1
*:SHUFFLE:0.3
rdns://127.0.0.1:REWRITE:localhost.test
rdns://[::1]:SERVICE:https
```

**Selectors.** Forward lookups: `*` (same as `dns://*`), `dns://<name>`,
`dns://*.<suffix>`. Reverse lookups: `rdns://<ipv4>`, `rdns://[<ipv6>]`, `rdns://*`.
An exact name beats a suffix, a suffix beats `*`.

**Interposed calls.** `getaddrinfo` and the legacy `gethostbyname`,
`gethostbyname2`, `gethostbyname_r`, `gethostbyname2_r` use the `dns://` rules, so a
rule shapes a name's answer identically whichever API resolves it. `getnameinfo`,
`gethostbyaddr` and `gethostbyaddr_r` use the `rdns://` rules. `freeaddrinfo` is
interposed to release the lists `OVERRIDE` builds. The `res_*` resolver API is not
interposed.

**Effects.**

| Effect | `value` | Forward | Reverse | Behaviour |
|---|---|---|---|---|
| `EAI_AGAIN`, `EAI_FAIL`, `EAI_NONAME`, `EAI_MEMORY`, `EAI_SYSTEM` | probability | yes | yes | Returns that error without calling the resolver (`gethostby*`: the matching `h_errno`). |
| `LATENCY` | `ms[@p]` | yes | yes | Sleeps before the lookup. |
| `REWRITE` | `name[@p]` | yes | yes | Forward: resolves the given name instead. Reverse: returns the given host name. |
| `SERVICE` | `service[@p]` | yes | yes | Forward: replaces the service/port argument. Reverse: returns the given service name. |
| `OVERRIDE` | `ip[,ip…][@p]` | yes | no | Answers with up to 32 IP literals (`[…]` for IPv6) without asking the resolver. |
| `FILTER_FAMILY` | `inet4`/`ipv4`, `inet6`/`ipv6`, `any` `[@p]` | yes | no | Drops results of the other family; an empty result returns `EAI_NONAME`. |
| `SHUFFLE` | probability | yes | no | Randomises result order. |
| `LIMIT` | `n[@p]` | yes | no | Keeps at most n results. |

A forward lookup runs `LATENCY`, then `EAI_*`, then `REWRITE` and `SERVICE`, then
`OVERRIDE` or the real resolver, then `FILTER_FAMILY` → `SHUFFLE` → `LIMIT` in that
fixed order. Each effect kind is matched separately, so different kinds compose on
one query.

## libchaos-time

Rule file `/tmp/.chaos-time.conf`. Each rule is three fields, the probability
optional:

```text
<selector>:<effect>:<value>[@probability]
```

```text
*:ERRNO:EINVAL@0.05
clock_gettime:ERRNO:EFAULT@0.01
clock_gettime/monotonic:OFFSET:500
clock_gettime/monotonic:REGRESS:5000
nanosleep:LATENCY:200
usleep:ERRNO:EINTR@0.1
```

**Selectors.** `*`, `clock_gettime`, `clock_gettime/<clock>`, `nanosleep`, `usleep`.
`<clock>` is `realtime`, `monotonic`, `monotonic_raw`, `realtime_coarse`,
`monotonic_coarse`, `boottime`, `tai`, `process_cputime_id`, `thread_cputime_id`, or a
decimal clock id.

**Interposed calls.**

| Calls | Rules |
|---|---|
| `clock_gettime` | `clock_gettime[/<clock>]` |
| `gettimeofday`, `time`, `timespec_get` | `clock_gettime/realtime` (they read the realtime clock from the vDSO without calling `clock_gettime`, so without this one process would see two wall clocks) |
| `nanosleep`, `clock_nanosleep`, `sleep` | `nanosleep` |
| `usleep` | `usleep` |

**Effects.**

| Effect | `value` | Valid for | Behaviour |
|---|---|---|---|
| `ERRNO` | `EINVAL`, `EFAULT`, `EINTR`, `EPERM`, `ENOSYS`, `EAGAIN` | every selector | Fails before the real call. An injected `EINTR` copies the request into `remaining` (relative sleeps only). `clock_nanosleep` returns the error number; `sleep` returns the whole request unslept. |
| `LATENCY` | milliseconds | every selector | Sleeps before the real call. |
| `OFFSET` | signed milliseconds, ±100 years | `clock_gettime[/<clock>]` | Adds the offset to every returned time the probability gate lets through. |
| `REGRESS` | positive milliseconds, ≤ 100 years | `clock_gettime/<clock>` only | Steps that clock back once: the first read under the rule is real, the next read where the gate fires is that much earlier, and every read after stays shifted, so the clock keeps advancing from the earlier time. `clock_gettime/monotonic:REGRESS:5000` is `CLOCK_MONOTONIC` going back 5 s, as after a VM migration. A clock is required because the jump state is per rule. |

- `REGRESS` state is per process and survives a reload that keeps the rule's text; a
  forked child starts its own.
- A `clock_nanosleep` with `TIMER_ABSTIME` computed from a shifted clock is translated
  back to the real clock (deterministic `OFFSET` at probability 1 and `REGRESS`), so
  a shifted clock neither stalls nor shortens absolute sleeps.
- Not interposed: `alarm`, `setitimer`, timer and `timerfd` APIs, futex timeouts.

## libchaos-memory

Rule file `/tmp/.chaos-memory.conf`. Each rule is three fields, the probability
optional:

```text
<selector>:<effect>:<value>[@probability]
```

```text
*:ERRNO:ENOMEM@0.05
mmap/anon:ERRNO:ENOMEM
mmap:LATENCY:150
munmap:ERRNO:EINVAL
mprotect:ERRNO:EACCES
madvise:LATENCY:100
```

| Selector | Calls |
|---|---|
| `mmap` | `mmap`, and `mmap64` on 64-bit glibc |
| `mmap/anon`, `mmap/file` | the same, split by `MAP_ANONYMOUS` |
| `munmap` | `munmap` |
| `mprotect` | `mprotect` |
| `madvise` | `madvise`, `posix_madvise` (which returns the error number) |
| `*` | all of the above |

| Effect | `value` | Behaviour |
|---|---|---|
| `ERRNO` | `ENOMEM`, `EINVAL`, `EACCES`, `EPERM`, `EBADF`, `ENODEV`, `EAGAIN`, `EFAULT`, `ENOSYS`, `ENFILE`, `EMFILE` | Fails before the real call (`mmap` returns `MAP_FAILED`). |
| `LATENCY` | milliseconds | Sleeps before the real call. |

- `munmap`, `mprotect` and `madvise` match by symbol only; the library keeps no
  region provenance. An injected `munmap` failure leaves the mapping in place.
- Which `malloc` calls reach `mmap` depends on the allocator: glibc maps requests at
  or above `M_MMAP_THRESHOLD` (128 KiB initially, raised dynamically up to 32 MiB on
  64-bit), musl maps new memory for every size class. An allocation served from memory
  the allocator already holds cannot fail ([`docs/MEMORY.md`](docs/MEMORY.md)).
- Not interposed: `mremap`, `mlock*`, `brk`, `sbrk`.

## libchaos-process

Rule file `/tmp/.chaos-process.conf`. Each rule is three fields, the probability
optional:

```text
<selector>:<effect>:<value>[@probability]
```

```text
*:LATENCY:25@0.01
pthread_create:ERRNO:EAGAIN
pthread_create:FAIL_AFTER:EAGAIN,128
fork:ERRNO:EAGAIN
posix_spawnp:LATENCY:150
execve:ERRNO:EACCES
waitpid:ERRNO:EINTR@0.1
```

| Selector | Calls | Failure reported as |
|---|---|---|
| `pthread_create` | `pthread_create` | error number returned, `errno` untouched |
| `fork` | `fork` | -1, `errno` |
| `posix_spawn` | `posix_spawn`, `system`, `popen` | `posix_spawn`: error number returned; `system`: -1, `errno`; `popen`: `NULL`, `errno` |
| `posix_spawnp` | `posix_spawnp` | error number returned |
| `execve` | `execve`, `execv`, `execvp`, `execvpe`, `execl`, `execlp`, `execle` | -1, `errno` |
| `execveat` | `execveat`, `fexecve` | -1, `errno` |
| `waitpid` | `waitpid`, `wait`, `wait3`, `wait4`, `waitid` | -1, `errno` |
| `*` | all of the above | |

| Effect | `value` | Behaviour |
|---|---|---|
| `ERRNO` | `EAGAIN`, `ENOMEM`, `EACCES`, `ENOENT`, `EINTR`, `ECHILD`, `EPERM`, `ESRCH`, `EBUSY`, `EINVAL`, `ENOSYS`, `EMFILE`, `ENFILE`, `E2BIG` | Fails before the real call. |
| `LATENCY` | milliseconds | Sleeps before the real call. |
| `FAIL_AFTER` | `<errno>,<count>` | Lets the first `count` matching calls of that operation through, then fails later ones (where the probability gate fires). |

- `FAIL_AFTER` counts every call of the operation that a `FAIL_AFTER` rule matches,
  per operation, not per rule. The counters restart at 0 when a changed rule file is
  loaded and in a forked child.
- `fork` rules do not cover `posix_spawn`: glibc spawns with `clone(CLONE_VFORK)`.
  Write `posix_spawn` rules for spawn paths.
- Not interposed: `vfork`, `clone*`, `kill`, `pthread_kill`. `execveat` and `fexecve`
  are interposed where the C library exports them.

## Runtime Behavior

- **Reload.** Once rules are loaded, each library `stat()`s its rule file at most
  every 1 ms, timed with the vDSO clock (not the interposed `clock_gettime`); without
  a vDSO clock it checks on every call. A change is detected by mtime, size, inode and
  device, so an append or a `rename`-based rewrite within one mtime tick is still
  seen. Tests that write rules and call at once must wait at least 2 ms.
- **Lock-free reads.** Each library keeps two rule snapshots. One thread wins the
  reload by compare-and-swap, fills the inactive snapshot and flips the active index;
  readers never block. A snapshot carries a sequence number (seqlock), so a reader
  that copied a rule from a snapshot rewritten meanwhile discards the copy and passes
  the call through.
- **Reentrancy.** Every wrapper checks a thread-local guard and forwards directly to
  the real function when the library itself is inside libc.
- **Randomness.** One PRNG per thread, seeded lazily; a forked child reseeds, so
  pre-fork workers do not draw the same sequence.
- **close().** Linux releases the descriptor even when `close` reports an error, and
  correct programs never retry it. io and net therefore always run the real close and
  report an injected error after it.
- **fd-to-path cache (io).** One process-wide 32-slot table, mapped lazily with a raw
  `mmap` system call, guarded per slot by a seqlock and a generation counter. `close`,
  `dup2`, `dup3`, `close_range`, `closefrom`, `fclose`, `closedir` and `pclose`
  invalidate the descriptors they release; a successful `unlinkat` or `renameat`
  clears the table. A miss reads `/proc/self/fd/<fd>`.
- **errno.** An idle wrapper leaves `errno` as it found it
  (`test/runtime/test_errno_glibc.sh`).
- **fork and exec.** Hit counts and `@first` budgets start from zero in a forked
  child. A program started by `execve` loads the libraries anew.
- **Not reached by `LD_PRELOAD`.** Statically linked programs; set-user-ID and
  file-capability programs (the loader ignores `LD_PRELOAD` under `AT_SECURE`); system
  calls the C library makes internally without its exported symbol (glibc's
  `posix_spawn` clones directly, never calling `fork`); I/O through io_uring, `splice`
  or a file `mmap`. Details: [`docs/PLATFORM.md`](docs/PLATFORM.md),
  [`docs/SAFETY.md`](docs/SAFETY.md).

## SECCOMP Mode (chaos-init)

`chaos-init` applies the same rule files to processes `LD_PRELOAD` cannot reach,
through the kernel's seccomp user notification. Full reference:
[`docs/SECCOMP.md`](docs/SECCOMP.md).

```sh
chaos-init --libs io,net,memory,process -- /usr/local/bin/nats-server -js
```

- It forks the tracee, which sets `no_new_privs`, installs the filter, hands the
  listener back and executes the command. The supervisor answers each notified call:
  fail it, delay it (`LATENCY`, from a timer queue), return without running it (poll
  `TIMEOUT`), or let it run. It forwards termination and user signals, reaps orphans
  and exits with the application's exit code (128 + signal if killed). Its own exit
  codes: 2 usage error, 125 setup failure, 126 command not executable, 127 command not
  found.
- `src/init/chaos_init_<lib>.c` turns a system call into what the library's wrapper
  would pass to the rule core; parsing, reload, matching, qualifiers and the status and
  hits files are the libraries' own source files.
- `/tmp/.chaos-init.status` reports `state=active` with `libs=` and `pid=` (and
  `mptcp=off` when chaos-init disabled Go's Multipath TCP), or `state=unsupported` with
  a `reason=`. The application starts in both cases; unsupported means no chaos.

| Library | Applied in SECCOMP mode |
|---|---|
| io | errno and `LATENCY` on every operation (`close`: `LATENCY` only) |
| net | errno and `LATENCY` on every operation (`close`: `LATENCY` only); `TIMEOUT` on `poll` |
| memory | `ERRNO`, `LATENCY` |
| process | `ERRNO`, `LATENCY`, `FAIL_AFTER`; `clone` is classified as `pthread_create` (`CLONE_THREAD`), `posix_spawn` (`CLONE_VFORK`) or `fork` |
| dns, time | nothing: name resolution is a library function, clocks are read from the vDSO |

- Rules seccomp cannot carry out reject their whole file with
  `reason=unsupported in seccomp mode`: io `TORN`/`CORRUPT`, net
  `CORRUPT`/`TRICKLE`/`DUP`/`RESET`, errno on `close`, and any `posix_spawnp` rule.
- Per-process state follows the libraries (hits, `@first`, a new count after
  `execve`), with one difference: a forked child continues its parent's `FAIL_AFTER`
  counts, where the library's atfork handler resets them to 0.
- Every system call of the process counts, including the dynamic loader's `open` and
  `mmap` and the allocator's mappings. Narrow paths, `@size`, `@first` or `@from`
  keep a rule to the calls meant.
- Requires kernel 5.5 or newer, x86_64 or aarch64 (native, not emulated), and no
  privilege beyond Docker's default seccomp profile. One notified call costs about
  2.5 µs instead of 0.2 µs (Docker Desktop, kernel 6.10); only the requested
  libraries' system calls are notified.

## Limits

| Limit | Value |
|---|---|
| Rules per file | 256 |
| Bytes per rule line | 1024 |
| Rule file size | < 256 KiB |
| Rule text reported in status and hits files, and used to keep a rule's counts across reloads | first 200 bytes |
| `LATENCY` | 0 – 4 294 967 295 ms |
| `OFFSET`, `REGRESS` | ±3 155 760 000 000 ms (100 years) |
| `OVERRIDE` literals per rule | 32 |
| `DUP` payload kept per socket / sockets tracked | 4096 bytes / 64 |
| `TRICKLE` iovec entries reshaped | 64 |
| io fd-to-path cache | 32 slots |
| Qualifier numbers | 18 digits |
| `chaos-init` processes with counts / delayed calls / descriptors scanned per poll | 128 / 1024 / 1024 |

## Repository Layout

```text
src/
  common/      shared headers: qualifiers (chaos_policy.h), status file (chaos_status.h),
               hits files and seqlock (chaos_hits.h), vDSO clock (chaos_clock.h), sleep
  core/        libchaos-io runtime state, symbol resolution, path filters
  config/      libchaos-io rule parser and reload; fd-to-path cache
  effects/     libchaos-io effect decisions (ERRNO, LATENCY, TORN, CORRUPT)
  wrappers/    libchaos-io wrappers: open, read/write, fs operations, sync/close, stdio
  net/         libchaos-net: rules, endpoints, socket and wait wrappers
  dns/         libchaos-dns: rules, lookups, result transforms, owned address lists
  time/        libchaos-time: rules, actions, hooks
  memory/      libchaos-memory: rules, actions, hooks
  process/     libchaos-process: rules, actions, hooks
  init/        chaos-init: supervisor loop, filter and status (core), per-library
               call mapping (chaos_init_<lib>.c), tracee state, /proc and memory
               reads, LATENCY timer queue
test/
  unit/        one assert-based binary per module; sources are #included directly
  support/     per-library test globals and stubs
  runtime/     Docker and host probes (*_probe.c, test_*.sh), coverage and format gates
  fuzz/        libFuzzer harnesses for the six rule parsers (make fuzz)
benchmark/     harness, kernels, scenarios, driver (benchmark/README.md)
demo/          15 docker compose fault profiles (demo/README.md)
docker/        build and CI images
docs/          subsystem references; diagrams/ holds the PlantUML sources
scripts/       run_verified_examples.sh (make verify-docs)
Makefile
```

Planned work and scope boundaries: [`docs/development/ROADMAP.md`](docs/development/ROADMAP.md).

## Build And Test

### Fast local loop

```sh
make unit
```

Builds and runs every unit binary in `test/unit/`: parsers and reload, effect
decisions, fd cache, every wrapper of all six libraries, the property-based parser
test (`test_config_proptest`), and every `chaos-init` module. Unit tests `#include`
the library sources instead of loading the shared objects. The `chaos-init` tests need
Linux headers; on macOS run `make ci-local-unit`, which uses the Linux CI image.

### Coverage gate

```sh
make coverage
```

Builds an instrumented `make unit` in `build-coverage/` and fails unless every
shipped source reaches `100.00%` line coverage
(`test/runtime/check_coverage.sh`):

- every `.c` of `libchaos-io` (`src/core`, `src/config`, `src/effects`,
  `src/wrappers`), `libchaos-net`, `libchaos-dns`, `libchaos-time`,
  `libchaos-memory` and `libchaos-process`;
- every `src/init/` module except the process glue in `chaos_init.c`;
- the shared headers (`src/common/*.h` and each library's `*_internal.h`), counted as
  the union over all test binaries that include them.

### C style gate

```sh
make fmt-check
```

Runs `clang-format` (repository `.clang-format`, 100 columns) in check mode over
every `.c` and `.h` under `src/` and `test/`. `make fmt` rewrites them.

### Docker runtime probes

Each script builds the libraries in Docker, runs a probe under `LD_PRELOAD` (or
`chaos-init`), and skips when Docker is unavailable. Per-library scripts take an
optional platform (`linux/amd64`, `linux/arm64`; default: the host).

| Script | Proves |
|---|---|
| `test_glibc.sh`, `test_alpine.sh` | libchaos-io effects on glibc / musl |
| `test_net_{glibc,alpine}.sh` | libchaos-net |
| `test_dns_{glibc,alpine}.sh` | libchaos-dns |
| `test_time_{glibc,alpine}.sh` | libchaos-time |
| `test_memory_{glibc,alpine}.sh` | libchaos-memory |
| `test_process_{glibc,alpine}.sh` | libchaos-process |
| `test_integration.sh` | libchaos-io natively on a Linux host, no Docker |
| `test_errno_glibc.sh` | an idle library leaves `errno` alone |
| `test_variants_glibc.sh` | glibc's `64`, `_chk` and `_2` entry points are faulted like the base calls |
| `test_sharing_glibc.sh` | io and net share `read`/`write`/`close` in every `LD_PRELOAD` order |
| `test_isolation_glibc.sh` | no library's rules change another library's effects |
| `test_baseline_glibc.sh` | the release build loads into ordinary programs on glibc 2.31 |
| `test_path_forms.sh` | unlink, rmdir, rename, truncate and creat are faulted |
| `test_stdio.sh` | buffered stdio reads and writes are faulted; `ferror()` is set |
| `test_status.sh`, `test_hits.sh` | status and hits files of every library |
| `test_reload.sh` | `@first` holds while the rule file is reloaded under load |
| `test_fork.sh` | per-process state across `vfork`, `fork` and `posix_spawn` |
| `test_init.sh`, `test_seccomp.sh`, `test_mptcp.sh` | `chaos-init` process model; SECCOMP-mode effects on static C and Go programs; MPTCP socket lookups |

### Full local quality gate

```sh
make check
```

Runs `make fmt-check`, `make coverage`, then `make test`. `make test` runs `make
unit`, builds the libraries on Linux, and runs every script of the table above for
the host architecture. CI (`.github/workflows/ci.yml`) adds `make verify-docs`,
ASan and UBSan unit runs, and `scan-build`; `make ci-local` runs the same gates in a
Linux container.

### Full Docker matrix gate

```sh
make test-matrix
```

Runs the twelve per-library glibc and musl scripts on `linux/amd64` and then on
`linux/arm64`. One cell by hand:

```sh
sh test/runtime/test_net_alpine.sh linux/arm64
```

### Build targets

| Target | Output |
|---|---|
| `make native` | `build/libchaos-<lib>.so` for all six libraries (Linux only) |
| `make native-<lib>` | one library, `<lib>` ∈ `io net dns time process memory` |
| `make native-init` | `build/chaos-init`, statically linked |
| `make cross-<libc>-<arch>` | `dist/libchaos-<lib>-<libc>-<arch>.so` for all six, `<libc>` ∈ `glibc musl`, `<arch>` ∈ `amd64 arm64` (needs the cross compilers named in the Makefile) |
| `make cross-<libc>-<arch>-<lib>` | one library, e.g. `make cross-musl-arm64-memory` |
| `make cross-init-<arch>` | `dist/chaos-init-<arch>`; run inside an image of that architecture (`docker/Dockerfile.build`, `MAKE_TARGET=cross-init-<arch>`), because the filter's system call numbers come from that architecture's headers |
| `make docker-build-all` | all 24 `.so` files into `dist/` via Docker Buildx (glibc on `gcc:10`, musl on `alpine:3.20`) |
| `make fuzz` | libFuzzer harnesses in `build-fuzz/` (clang) |
| `make clean` | removes `build/`, `build-coverage/`, `dist/` |

One `chaos-init` binary per architecture serves glibc, musl and libc-less images.

## Minimal Artifact Strategy

The shared objects carry only the wrappers and their rule engine:

| Flag | Effect |
|---|---|
| `-Os` | size-optimised code |
| `-fvisibility=hidden` | only the interposed symbols are exported |
| `-ffunction-sections -fdata-sections` + `-Wl,--gc-sections` | unreferenced functions and data are dropped |
| `-fno-unwind-tables -fno-asynchronous-unwind-tables` | no `.eh_frame` |
| `-fomit-frame-pointer`, `-fno-ident` | no frame-pointer setup, no compiler ident string |
| `-fno-stack-protector` | no canary: `__stack_chk_fail` would write to stderr through the interposed `write` ([`docs/ENGINEERING.md`](docs/ENGINEERING.md)) |
| `-Wl,--strip-all`, `-Wl,--build-id=none` | no symbol table beyond the dynamic one, no build-id note |
| `-Wl,-z,max-page-size=4096 -Wl,-z,common-page-size=4096` | 4 KiB segment alignment; the aarch64 GNU ld default of 64 KiB pads every segment |

No C++ runtime, no allocator in the hot path, `-ldl` as the only link library.

## More Detail

| Document | Content |
|---|---|
| [`docs/DSL.md`](docs/DSL.md) | Rule grammar (ABNF), qualifiers, specificity order, cross-layer mapping |
| [`docs/PLATFORM.md`](docs/PLATFORM.md) | ELF link map, PLT/GOT, `RTLD_NEXT`, IFUNC, symbol versioning, vDSO, `AT_SECURE`, static binaries |
| [`docs/SYSTEM.md`](docs/SYSTEM.md) | Loader/libc/kernel interaction, one-symbol-one-owner invariant, composition |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component map, call flow, reload protocol, status and hits files, fd cache |
| [`docs/SECCOMP.md`](docs/SECCOMP.md) | SECCOMP mode: model, call mapping, rejected rules, requirements |
| [`docs/IO.md`](docs/IO.md) | libchaos-io internals: fd cache, `/proc/self/fd`, symbol versioning, non-covered paths |
| [`docs/NETWORK.md`](docs/NETWORK.md) | libchaos-net internals: endpoint normalisation, `SCM_RIGHTS`, TCP Fast Open, io_uring |
| [`docs/DNS.md`](docs/DNS.md) | libchaos-dns internals: NSS plumbing, `getaddrinfo` flow, result transforms |
| [`docs/TIME.md`](docs/TIME.md) | libchaos-time internals: clock taxonomy, vDSO per architecture, `OFFSET` semantics |
| [`docs/MEMORY.md`](docs/MEMORY.md) | libchaos-memory internals: ptmalloc2/mallocng divergence, `MAP_ANONYMOUS` dispatch |
| [`docs/PROCESS.md`](docs/PROCESS.md) | libchaos-process internals: clone flags, NPTL, spawn cascade, exec family |
| [`docs/ENGINEERING.md`](docs/ENGINEERING.md) | Build flag rationale, ABI commitments, CI gates |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Measurement methodology, per-library overhead, comparisons |
| [`docs/SAFETY.md`](docs/SAFETY.md) | `AT_SECURE`, container capabilities, seccomp, fail-open, rule-file security, sanitisers |
| [`docs/diagrams/`](docs/diagrams/) | 8 PlantUML diagrams |
| [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) | Contribution workflow; vulnerability reporting |

Code-level intent lives in the file headers and the internal headers under [`src/`](src).

---

## License

Apache License 2.0 — see [LICENSE](LICENSE). Use it in production, ship it in your products, fork it, build a business around it. The only thing you cannot do is claim you wrote it.

---

## About the Engineer

This three-repo stack — [`macstab-chaos-jvm-agent`](https://github.com/macstab/macstab-chaos-jvm-agent), [`chaos-testing`](https://github.com/macstab/chaos-testing), `macstab-chaos-testing-libraries` — is the work of one engineer: **Christian Schnapka**, Hamburg, Germany.

### Timeline

| Year                     | What I was shipping                                                                                                                                                                                                        |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1984** *(age 10)*      | 6502 assembler on the Commodore 64                                                                                                                                                                                         |
| **1987** *(age 14)*      | Motorola 68000 (M68k) assembler / C on the Commodore Amiga                                                                                                                                                                 |
| **1989** *(from age 15)* | International demoscene — active in **Razor 1911**, **Sanity**, **Anthrox**, **Incal**; multiple demo-competition wins with my groups                                                                                      |
| **1990**                 | x86 assembler + C / C++ on PC. Part-time at German game studios (**Software 2000**, **Rainbow Arts**) and short stints at studios in Birmingham, UK — shipping on cartridges and floppies, where there was no patch button |
| **1996**                 | Transitioned to business / enterprise software engineering — the arc that runs to today                                                                                                                                    |
| **1996**                 | Java — since 1.0, 30 years and counting                                                                                                                                                                                    |
| **2002**                 | Python — 24 years and counting                                                                                                                                                                                             |
| **2008**                 | LXC (Linux Containers) — early adopter, production use through to the Docker era and beyond                                                                                                                                |
| **2013**                 | Docker — since first release; production use across enterprise stacks                                                                                                                                                      |
| **~2014**                | Kubernetes                                                                                                                                                                                                                 |
| **~2015**                | Go — distributed-system internals, network programming                                                                                                                                                                     |
| **2018**                 | Kotlin — JVM ecosystem coverage alongside Java; coroutines, multiplatform, server-side                                                                                                                                     |

**Diplom Informatiker** — German pre-Bologna 5-year computer-science degree, equivalent to a master's. 42 years of programming, 36 years of professional systems work, 30 years of enterprise software, 24 of Python, 10 of Go, 7 of Kotlin.

The depth shown in this project — `LD_PRELOAD` symbol interposition that composes cleanly with `dlsym(RTLD_NEXT, ...)`, lock-free config reload via two-snapshot pointer swap, a process-wide fd-path cache that respects `unlinkat()`/`renameat()` invalidation, endpoint-aware wait-path matching derived from `/proc/self/fdinfo/<epfd>`, hand-tuned `.so` outputs with hidden visibility and section-level dead-code elimination, and a 100 % source-line coverage gate enforced across glibc + musl × amd64 + arm64 — comes from a path that started with peeking C64 memory at 10, ran through the demoscene where every cycle counted on the wire, through game studios that shipped on cartridges with no recall option, and then 30 years of production enterprise software. Most engineers enter at the framework layer and look down. **This stack reads from below.** Principal-engineer titles are job descriptions; assembler at 10, the demoscene at 15, and shipping for game studios at 16 — that is a starting line.

### Specific evidence in this project

Concrete artifacts a reviewer can read:

- **Six libraries shipped** — `libchaos-io`, `libchaos-net`, `libchaos-dns`, `libchaos-time`, `libchaos-process`, `libchaos-memory` — each with its own selector grammar, config file, and runtime contract; no shared mutable state across libraries
- **A second injection mode** — `chaos-init` applies the same rule files to statically linked programs through seccomp user notification, compiling the libraries' own rule cores
- **Cross-libc and cross-arch validation** — `glibc + musl × amd64 + arm64`, every release walked through Docker runtime probes on all four matrix cells
- **Strict 100 % source-line coverage** on every shipped source of all six libraries and of `chaos-init`'s modules
- **Honest documentation** of what *cannot* work and why — every library section names the symbols and edge cases it does not cover, not papered over
- **Composable by design** — `libchaos-net` and `libchaos-io` share `read()`, `write()` and `close()` by descriptor type and compose in either `LD_PRELOAD` order; DNS interception was extracted out of `libchaos-net` into its own library
- **Apache 2.0 throughout** — usable in production, in commercial products, no lock-in

### Available for Principal+ engineering engagements

Limited capacity. Typically:

- **Fractional / interim Principal Engineer** — architecture, mentoring, hardest-problem ownership
- **Reliability engineering** — chaos-engineering / SRE-tooling enablement, post-incident systemic fixes, "we keep getting paged for X" investigations
- **Systems-level work** — C / C++ / assembler-adjacent investigations, native libraries, Linux internals, `LD_PRELOAD` and `ptrace` instrumentation
- **JVM performance** — agents, GC tuning, instrumentation, deep profiling

If your team is fighting production issues that "more tests" hasn't fixed:

- **[macstab.com](https://macstab.com)** — engagement enquiries
- **info@macstab.com** — direct contact
- **[GitHub @macstab](https://github.com/macstab)** — more open-source work

A small number of engagements per year. The work is deep — production systems with receipts in `git log`, not slide decks.

---

<div align="center">

**[Christian Schnapka](https://macstab.com)**
Principal+ Engineer
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
