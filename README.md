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

**Pure C99 `LD_PRELOAD` chaos engineering for any Linux process. Kernel-real syscall faults — language-agnostic, library-thin, 100% line-coverage gated.**

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

<div align="center">

### Part of the Macstab Chaos Engineering Stack

| [**JVM bytecode**](https://github.com/macstab/macstab-chaos-jvm-agent) | [**Container orchestration**](https://github.com/macstab/chaos-testing) |        **`LD_PRELOAD` libc** *(this repo)*        |
|:----------------------------------------------------------------------:|:-----------------------------------------------------------------------:|:-------------------------------------------------:|
|                  In-process chaos for JVM applications                 |          Annotation-driven Testcontainers chaos for any service         | Pure C99 syscall-level chaos for any Linux container |
|          62 JDK call sites · Spring 3/4 · Micronaut · Quarkus          |        Network · disk · DNS · CPU · memory · pre-built scenarios        |    glibc + musl × amd64 + arm64 · 100 % line coverage   |

**One mental model — three layers.** Same selector × effect × policy DSL spans the JVM, the container, and the libc layer. Each layer ships and runs independently; combine them when you need full distributed-system chaos coverage.

</div>

---

## chaos-testing-libraries

`chaos-testing-libraries` is a small collection of Linux `LD_PRELOAD`
fault-injection libraries. Today, `libchaos-io`, `libchaos-net`,
`libchaos-dns`, `libchaos-time`, `libchaos-process`, and `libchaos-memory` are
implemented.

There is intentionally no public C API header. Each library surface is its
interposed libc symbols plus its config file. Today, `libchaos-io`,
`libchaos-net`, `libchaos-dns`, `libchaos-time`, `libchaos-process`, and
`libchaos-memory` all interpose real libc symbols.

## Part of a Three-Layer Chaos Engineering Stack

`chaos-testing-libraries` is the **`LD_PRELOAD` libc layer** of a vertically-integrated chaos engineering toolkit. This repo is self-contained — everything in this README works standalone — but it composes with two sibling layers when broader coverage is needed.

| Layer                              | Repo                                                                                                    | What it covers                                                                                                                                                                                                                |
|------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`LD_PRELOAD` libc** (this repo)  | [`macstab/macstab-chaos-testing-libraries`](https://github.com/macstab/macstab-chaos-testing-libraries) | Pure C99 `LD_PRELOAD` shared objects: file I/O (latency / `errno` / torn / corrupt), network, DNS, clock, process, memory. **glibc + musl × amd64 + arm64**, 100 % line coverage on shipped sources, Docker runtime validation as a quality gate. Language-agnostic — works for any process inside any container. |
| **JVM bytecode**                   | [`macstab/macstab-chaos-jvm-agent`](https://github.com/macstab/macstab-chaos-jvm-agent)                 | 62 JDK call sites instrumented in-process. Spring Boot 3/4 + Micronaut + Quarkus integration. JUnit 5 `@ChaosTest`. Selector × effect × policy DSL. Live config reload.                                                       |
| **Container orchestration**        | [`macstab/chaos-testing`](https://github.com/macstab/chaos-testing)                                     | Annotation-driven chaos on top of Testcontainers. CPU throttling, memory pressure, disk I/O, network partitions, DNS failures, pre-built Redis Sentinel + replication-lag scenarios, Toxiproxy adapter, Redis-aware fault injection.                                                                              |

**Start here** if you need failure injection that crosses language boundaries — or if you need *kernel-real* time skew, slow disks, and DNS slowdowns that no in-process agent can fake (e.g. `clock_gettime` is a syscall the JVM cannot intrinsically intercept; the LD_PRELOAD lib can).

**Compose layers** for full distributed-system coverage:
- Add the JVM agent for selector × effect × policy chaos *inside* JVM call sites — DNS, JDBC, NIO, virtual threads, monitors, GC.
- Add the orchestration layer to wire chaos directly to Testcontainers-managed Redis, Postgres, Kafka — including pre-built scenarios like *replication lag during pod drainage*.

Three repos, one mental model: **the same selector × effect × policy DSL spans the libc layer, the JVM layer, and the orchestration layer.** No cross-layer coupling — each layer is independently adoptable, independently versioned, independently released.

## Design Constraints

- Pure C99.
- Very small shared objects.
- No runtime dependency beyond libc and `libdl`.
- Works with glibc and musl builds.
- Safe fallback behavior: invalid, unreadable, or missing config means full passthrough.
- Quality gate is enforced in-repo:
  - `fmt-check`: `clang-format` style check across all shipped `src/**/*.c`,
    `src/**/*.h`, `test/**/*.c`, and `test/**/*.h`
  - `libchaos-io`: unit tests plus 100% source line coverage for its shipped
    `src/*.c`, plus Docker runtime validation
  - `libchaos-net`: unit tests plus 100% source line coverage for its shipped
    `src/net/*.c`, plus Docker runtime validation across glibc and musl on
    amd64 and arm64
  - `libchaos-dns`: unit tests plus an enforced source-line coverage floor for
    its shipped `src/dns/*.c`, plus Docker runtime validation across glibc and
    musl on amd64 and arm64
  - `libchaos-time`: unit tests plus 100% source line coverage for its shipped
    `src/time/*.c`, plus Docker runtime validation across glibc and musl on
    amd64 and arm64
  - `libchaos-memory`: unit tests plus 100% source line coverage for its
    shipped `src/memory/*.c`, plus Docker runtime validation across glibc and
    musl on amd64 and arm64
  - `libchaos-process`: unit tests plus 100% source line coverage for its
    shipped `src/process/*.c`, plus Docker runtime validation across glibc and
    musl on amd64 and arm64

## Documentation Standard

The repository documentation is expected to be an authoritative engineering
reference, not a feature sketch.

Each subsystem document should:

- describe current implemented behavior first
- label future work explicitly
- state ownership boundaries and non-goals directly
- state failure and passthrough behavior directly
- state cross-target constraints when libc, loader, distro, or architecture
  materially affect correctness
- state the validation bar used to call work complete

[`docs/SYSTEM.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/SYSTEM.md)
is the repository-level reference for cross-library composition, symbol
ownership, and the Linux loader/libc/kernel stack model.

## Repository Layout

```text
ROADMAP.md
src/
  common/
    chaos_domain_stub.c
    chaos_domain_stub.h
  core/
    chaos_io.c
    chaos_io_internal.h
    chaos_io_wrappers.h
  config/
    chaos_io_config.c
    chaos_io_config.h
    chaos_io_fdcache.c
    chaos_io_fdcache.h
  effects/
    chaos_io_actions.c
    chaos_io_actions.h
  dns/
    chaos_dns.c
    chaos_dns_actions.c
    chaos_dns_actions.h
    chaos_dns_config.c
    chaos_dns_config.h
    chaos_dns_internal.h
    chaos_dns_lookup.c
  memory/
    chaos_memory.c
  net/
    chaos_net.c
    chaos_net_actions.c
    chaos_net_config.c
    chaos_net_endpoint.c
    chaos_net_extra.c
    chaos_net_internal.h
    chaos_net_socket.c
    chaos_net_wait.c
  process/
    chaos_process.c
    chaos_process_actions.c
    chaos_process_actions.h
    chaos_process_config.c
    chaos_process_config.h
    chaos_process_hooks.c
    chaos_process_internal.h
  time/
    chaos_time.c
  wrappers/
    chaos_io_fsops.c
    chaos_io_open.c
    chaos_io_rw.c
    chaos_io_sync.c
test/
  runtime/
    dns_probe.c
    check_coverage.sh
    test_alpine.sh
    test_dns_alpine.sh
    test_dns_glibc.sh
    test_glibc.sh
    test_integration.sh
    test_net_alpine.sh
    test_net_glibc.sh
  support/
    test_dns_support.h
    test_net_support.h
    test_chaos_io_harness.h
    test_support.h
  unit/
    test_actions.c
    test_chaos_dns.c
    test_chaos_io.c
    test_config_parse.c
    test_dns_actions.c
    test_dns_config.c
    test_dns_runtime.c
    test_fdcache.c
    test_chaos_net.c
    test_net_actions.c
    test_net_config.c
    test_net_endpoint.c
    test_net_runtime.c
docker/
  Dockerfile.build
docs/
  ARCHITECTURE.md
  BENCHMARKS.md
  DNS.md
  DSL.md
  ENGINEERING.md
  IO.md
  MEMORY.md
  NETWORK.md
  PLATFORM.md
  PROCESS.md
  SAFETY.md
  SYSTEM.md
  TIME.md
  diagrams/
    atsecure.puml
    composition.puml
    config_reload.puml
    dispatch.puml
    dsl_pipeline.puml
    fdcache.puml
    linkmap.puml
    vdso.puml
Makefile
```

Planned extension work and scope boundaries live in
[`ROADMAP.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/ROADMAP.md).

Deep subsystem references:

- [`docs/DSL.md`](docs/DSL.md)
  Cross-layer selector × effect × policy grammar (ABNF); identity proof across all six libraries;
  specificity ordering; (S × E × P) algebra; full effect taxonomy A–E
- [`docs/PLATFORM.md`](docs/PLATFORM.md)
  ELF gABI §5.2 link-map mechanics, PLT/GOT lazy binding, RTLD_NEXT chain, STT_GNU_IFUNC
  resolver phase, GNU symbol versioning, AT_SECURE auxv, static-binary immunity
- [`docs/SYSTEM.md`](docs/SYSTEM.md)
  Global system manual: symbol ownership theorem, loader/libc/kernel interaction,
  cross-library composition, formal one-symbol-one-owner invariant
- [`docs/IO.md`](docs/IO.md)
  `libchaos-io`: FD cache design, /proc/self/fd resolution, pread GNU symbol versioning,
  splice/tee non-coverage, O_DIRECT alignment hazard
- [`docs/NETWORK.md`](docs/NETWORK.md)
  `libchaos-net`: endpoint selector normalisation, SCM_RIGHTS non-coverage,
  TCP Fast Open, io_uring non-coverage
- [`docs/DNS.md`](docs/DNS.md)
  `libchaos-dns`: NSS plumbing (nsswitch.conf, nss_files/nss_dns/nss_resolve),
  getaddrinfo call flow, FILTER_FAMILY/SHUFFLE/LIMIT post-call mutations
- [`docs/TIME.md`](docs/TIME.md)
  `libchaos-time`: full clock taxonomy (9 POSIX + Linux extensions), vDSO offload table
  per-arch (x86_64/aarch64/riscv64/…), OFFSET monotonicity semantics
- [`docs/MEMORY.md`](docs/MEMORY.md)
  `libchaos-memory`: virtual-memory taxonomy, ptmalloc2/mallocng divergence, MAP_ANONYMOUS
  dispatch, MADVISE hint catalogue, mremap/mlock non-coverage
- [`docs/PROCESS.md`](docs/PROCESS.md)
  `libchaos-process`: clone(2) flag taxonomy, NPTL pthread_create internals,
  posix_spawn glibc/musl cascade gap, FAIL_AFTER atomic counter, exec family matrix
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
  Component map, dispatch pipeline, FD cache, config reload, formal symbol-ownership theorem
- [`docs/ENGINEERING.md`](docs/ENGINEERING.md)
  Build flag rationale (`-fvisibility=hidden`, `-fno-stack-protector`, `--gc-sections`, …),
  ABI commitments, CI gates
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)
  rdtsc/CNTPCT_EL0 measurement methodology, per-library hot-path overhead tables,
  cold-path reload cost, libfaketime/toxiproxy comparison
- [`docs/SAFETY.md`](docs/SAFETY.md)
  AT_SECURE kernel mechanics, container capability model, seccomp syscall table,
  fail-open guarantee, sanitiser interactions, config file security
- [`docs/diagrams/`](docs/diagrams/)
  PlantUML: `linkmap.puml`, `vdso.puml`, `dispatch.puml`, `fdcache.puml`,
  `config_reload.puml`, `composition.puml`, `atsecure.puml`, `dsl_pipeline.puml`

## Libraries

- `libchaos-io`
  Fully implemented file-I/O fault injection library.
- `libchaos-net`
  Implemented endpoint-based network chaos library.
- `libchaos-dns`
  Implemented resolver-focused chaos and answer-manipulation library.
- `libchaos-time`
  Implemented clock/sleep chaos library.
- `libchaos-memory`
  Implemented memory-mapping chaos library.
- `libchaos-process`
  Implemented process-lifecycle chaos library.

The remainder of this README documents the current `libchaos-time`,
`libchaos-memory`, `libchaos-process`, and `libchaos-dns` contracts directly.
`libchaos-io` and `libchaos-net` retain their subsystem references.

## libchaos-time

Config path:

```text
/tmp/.chaos-time.conf
```

Each non-empty rule line is:

```text
<selector>:<effect>:<value>
```

Examples:

```text
*:ERRNO:EINVAL@0.05
clock_gettime:ERRNO:EFAULT@0.01
clock_gettime/monotonic:OFFSET:500
nanosleep:LATENCY:200
usleep:ERRNO:EINTR@0.1
```

Exact interposed symbols today:

- `clock_gettime()`
- `nanosleep()`
- `usleep()`

Supported selectors:

- `*`
- `clock_gettime`
- `clock_gettime/<clock-name-or-id>`
- `nanosleep`
- `usleep`

Implemented effects:

- `ERRNO`
  Synthetic pre-call failure with optional `@probability`
- `LATENCY`
  Added pre-call milliseconds with optional `@probability`
- `OFFSET`
  Signed milliseconds added to `clock_gettime()` results, with optional
  `@probability`

Important current boundary:

- `OFFSET` is supported for `clock_gettime()` only
- sleep wrappers support `ERRNO` and `LATENCY`, not returned-time mutation
- injected `ERRNO:EINTR` on `nanosleep()` copies the requested interval into
  `remaining` because the failure is injected before the real sleep runs
- this library does not currently interpose `clock_nanosleep()`,
  `gettimeofday()`, `sleep()`, `alarm()`, `setitimer()`, timerfd APIs, or
  futex timeout paths

## libchaos-memory

Config path:

```text
/tmp/.chaos-memory.conf
```

Each non-empty rule line is:

```text
<selector>:<effect>:<value>
```

Examples:

```text
*:ERRNO:ENOMEM@0.05
mmap/anon:ERRNO:ENOMEM
mmap:LATENCY:150
munmap:ERRNO:EINVAL
mprotect:ERRNO:EACCES
madvise:LATENCY:100
```

Exact interposed symbols today:

- `mmap()`
- `munmap()`
- `mprotect()`
- `madvise()`

Supported selectors:

- `*`
- `mmap`
- `mmap/anon`
- `mmap/file`
- `munmap`
- `mprotect`
- `madvise`

Implemented effects:

- `ERRNO`
  Synthetic pre-call failure with optional `@probability`
- `LATENCY`
  Added pre-call milliseconds with optional `@probability`

Important current boundary:

- `mmap()` is the only hook with selector-specific matching by call shape, via
  `mmap/anon` and `mmap/file`
- `munmap()`, `mprotect()`, and `madvise()` are matched by symbol only; the
  library does not keep region provenance metadata
- latency is injected before the real call; there is no post-call mutation of
  protection, advice, or returned mappings
- synthetic `munmap()` failure intentionally leaves the mapping alive until
  the process retries successfully or exits
- this library does not currently interpose `mmap64()`, `mremap()`, `mlock*()`,
  `brk()`, or `sbrk()`

## libchaos-process

Config path:

```text
/tmp/.chaos-process.conf
```

Each non-empty rule line is:

```text
<selector>:<effect>:<value>
```

Examples:

```text
*:LATENCY:25@0.01
pthread_create:ERRNO:EAGAIN
pthread_create:FAIL_AFTER:EAGAIN,128
fork:ERRNO:EAGAIN
posix_spawnp:LATENCY:150
execve:ERRNO:EACCES
waitpid:ERRNO:EINTR@0.1
```

Exact interposed symbols today:

- `pthread_create()`
- `fork()`
- `posix_spawn()`
- `posix_spawnp()`
- `execve()`
- `execveat()`
- `waitpid()`

Supported selectors:

- `*`
- `pthread_create`
- `fork`
- `posix_spawn`
- `posix_spawnp`
- `execve`
- `execveat`
- `waitpid`

Implemented effects:

- `ERRNO`
  Synthetic pre-call failure with optional `@probability`
- `LATENCY`
  Added pre-call milliseconds with optional `@probability`
- `FAIL_AFTER`
  Allow the first `N` calls for that operation, then fail later calls with the
  configured error, with optional `@probability`

Important current boundary:

- selectors are symbol-only today
- `FAIL_AFTER` counters are per operation and reset on config reload
- `pthread_create()` and `posix_spawn*()` return the configured error number
  directly on synthetic failure; they do not set `errno`
- `fork()`, `execve()`, `execveat()`, and `waitpid()` return `-1` and set
  `errno` on synthetic failure
- `execveat()` is interposed when the target libc exports that symbol; some
  musl environments do not expose it as a public libc symbol
- this library does not currently interpose `waitid()`, `kill()`,
  `pthread_kill()`, `clone*()`, or `vfork()`

## libchaos-dns

Config path:

```text
/tmp/.chaos-dns.conf
```

Each non-empty rule line is:

```text
<selector>:<effect>:<value>
```

Examples:

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

Exact interposed symbols today:

- `getaddrinfo()`
- `getnameinfo()`

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

Important current boundary:

- `libchaos-dns` currently owns `getaddrinfo()` and `getnameinfo()`
- reverse rules are address-based and use `rdns://...` selectors
- reverse lookup currently supports `EAI_*`, `LATENCY`, `REWRITE`, and
  `SERVICE` only
- legacy resolver APIs such as `gethostbyname*()`, `gethostbyaddr*()`, and
  `res_*()` remain future work
- rule matching is selector-specific and effect-specific; different effect
  kinds can compose on the same query
- post-resolution transforms for `getaddrinfo()` currently run in this order:
  `FILTER_FAMILY`, `SHUFFLE`, then `LIMIT`

## libchaos-net

Config path:

```text
/tmp/.chaos-net.conf
```

Each non-empty rule line is:

```text
<endpoint-selector>:<operation>:<effect>:<value>
```

Examples:

```text
tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0
tcp4://*:8080:listen:LATENCY:250
udp4://127.0.0.1:5353:send:EHOSTUNREACH:0.2
tcp4://127.0.0.1:9000:recv:CORRUPT:0.1
*:connect:ETIMEDOUT:0.05
```

Implemented logical operations:

- `socket`
  Applies to `socket()` and `socketpair()`
- `bind`
- `listen`
- `connect`
- `accept`
  Applies to `accept()` and Linux `accept4()`
- `shutdown`
  Applies to `shutdown()`
- `poll`
  Applies to `poll()`, `ppoll()`, `select()`, `pselect()`, and Linux
  `epoll_wait()` plus `epoll_pwait()`
- `send`
  Applies to `send()`, `sendto()`, `sendmsg()`, and Linux `sendmmsg()`
- `recv`
  Applies to `recv()`, `recvfrom()`, `recvmsg()`, and Linux `recvmmsg()`

Exact interposed symbols today:

- `socket()`, `socketpair()`, `bind()`, `listen()`, `connect()`, `accept()`,
  Linux `accept4()`, `shutdown()`
- `send()`, `sendto()`, `sendmsg()`, Linux `sendmmsg()`
- `recv()`, `recvfrom()`, `recvmsg()`, Linux `recvmmsg()`
- `poll()`, `ppoll()`, `select()`, `pselect()`, Linux `epoll_wait()`, Linux
  `epoll_pwait()`

Implemented effects:

- `ERRNO`
  Probability from `0.0` to `1.0`
- `LATENCY`
  Milliseconds
- `CORRUPT`
  Probability from `0.0` to `1.0`; valid only for `recv`
- `TIMEOUT`
  Probability from `0.0` to `1.0`; valid only for `poll`

Supported endpoint selectors:

- `*`
- `tcp4://<ipv4-or-*>:<port>`
- `tcp6://[<ipv6>]:<port>`
- `tcp6://*:<port>`
- `udp4://<ipv4-or-*>:<port>`
- `udp6://[<ipv6>]:<port>`
- `udp6://*:<port>`
- `unix://<path>`

Important current boundary:

- `libchaos-net` deliberately does not own `read()`, `write()`, or `close()`
  so it composes cleanly with `libchaos-io`
- `libchaos-net` no longer owns DNS lookup interception; that surface now lives
  in `libchaos-dns`
- wait-path matching is endpoint-aware and best-effort; Linux `epoll_*`
  matching is derived from `/proc/self/fdinfo/<epfd>` rather than a persistent
  membership cache
- runtime behavior is Docker-validated across glibc/musl and amd64/arm64
- the strict 100% source coverage gate now asserts `libchaos-io`,
  `libchaos-net`, `libchaos-time`, `libchaos-memory`, and
  `libchaos-process`

## Config Format

Each non-empty rule line is:

```text
<path-prefix>:<operation>:<errno|action>:<value>
```

Examples:

```text
/data:write:EIO:0.3
/data/wal.log:fsync:EIO:0.1
/data:write:LATENCY:200
/data:write:TORN:0.1
/data:read:CORRUPT:0.5
*:open:EMFILE:0.05
```

### Operations

- `read`
  Applies to `read()` and `readv()`.
- `write`
  Applies to `write()`, `writev()`, Linux `sendfile()`, and Linux
  `copy_file_range()` destination paths.
- `open`
  Applies to both `open()` and `openat()`.
- `close`
- `fsync`
- `fdatasync`
- `pread`
  Applies to `pread()` and `preadv()`.
- `pwrite`
  Applies to `pwrite()` and `pwritev()`.
- `truncate`
  Applies to `ftruncate()`.
- `allocate`
  Applies to Linux `fallocate()`.
- `unlink`
  Applies to `unlinkat()`.
- `rename_from`
  Applies to `renameat()` source paths.
- `rename_to`
  Applies to `renameat()` destination paths.

### Effects

- `ERRNO`
  `value` is a probability from `0.0` to `1.0`.
- `LATENCY`
  `value` is milliseconds.
- `TORN`
  `value` is a probability from `0.0` to `1.0`.
  Valid only for `write` and `pwrite`.
- `CORRUPT`
  `value` is a probability from `0.0` to `1.0`.
  Valid only for `read` and `pread`.

### Supported Errnos

- `EIO`
- `ENOSPC`
- `EDQUOT`
- `EROFS`
- `EACCES`
- `EMFILE`
- `ENFILE`
- `ENOENT`

### Matching Rules

- Longest prefix wins.
- `*` is the lowest-priority wildcard.
- Prefix matching is path-boundary aware.
  `/data` matches `/data` and `/data/file`.
  `/data` does not match `/database`.
- Invalid lines invalidate the full config load and force passthrough.

## Runtime Behavior

- The intercepted libc entry points are `read`, `readv`, `write`, `writev`, `open`, `openat`, `close`, `fsync`, `fdatasync`, `pread`, `preadv`, `pwrite`, `pwritev`, `ftruncate`, `unlinkat`, `renameat`, and Linux `sendfile`, `copy_file_range`, plus `fallocate`.
- The config file is checked with `stat()` on each intercepted call.
- Reload is lock-free for readers and swaps between two config snapshots.
- FD-backed operations resolve paths through `/proc/self/fd/<fd>` and cache them in thread-local storage.
- The library uses a thread-local recursion guard.
- The library seeds a thread-local PRNG once per thread.
- `readv(2)` and `preadv(2)` reuse the logical `read` and `pread` rule classes across the concatenated iovec byte stream.
- `writev(2)` and `pwritev(2)` reuse the logical `write` and `pwrite` rule classes across the concatenated iovec byte stream.
- Linux `sendfile(2)` and `copy_file_range(2)` use the logical `write` rule class and match on the destination fd path.
- `ftruncate(2)` and Linux `fallocate(2)` use the logical `truncate` and `allocate` rule classes on the target fd path.
- `unlinkat(2)` matches the logical `unlink` rule class on the resolved target path.
- `renameat(2)` matches the logical `rename_from` and `rename_to` rule classes against the resolved source and destination paths.
- Successful `unlinkat(2)` and `renameat(2)` calls reset the current thread fd cache because cached path identities may now be stale.
- Programs that copy data with `splice(2)`, `mmap(2)`, or other non-`write(2)`/`writev(2)`/`sendfile(2)`/`copy_file_range(2)` paths bypass `write` and `pwrite` rules.
- Injection is never applied to:
  `stdin`, `stdout`, `stderr`, `/tmp/.chaos-io.conf`, `/proc`, `/sys`, or `/dev`.

## Build And Test

### Fast local loop

```sh
make unit
```

Runs all unit binaries:

- config parsing and reload logic
- effect helpers
- fd cache logic
- full wrapper behavior across `src/core/chaos_io.c`,
  `src/wrappers/chaos_io_fsops.c`,
  `src/wrappers/chaos_io_open.c`, `src/wrappers/chaos_io_rw.c`, and
  `src/wrappers/chaos_io_sync.c`

### Coverage gate

```sh
make coverage
```

This compiles an instrumented build and enforces `100.00%` line coverage for
the shipped `libchaos-io`, `libchaos-net`, `libchaos-time`,
`libchaos-memory`, and `libchaos-process` sources:

- `src/core/chaos_io.c`
- `src/wrappers/chaos_io_fsops.c`
- `src/wrappers/chaos_io_open.c`
- `src/wrappers/chaos_io_rw.c`
- `src/wrappers/chaos_io_sync.c`
- `src/effects/chaos_io_actions.c`
- `src/config/chaos_io_config.c`
- `src/config/chaos_io_fdcache.c`
- `src/net/chaos_net_actions.c`
- `src/net/chaos_net_config.c`
- `src/net/chaos_net_endpoint.c`
- `src/net/chaos_net_extra.c`
- `src/net/chaos_net_socket.c`
- `src/net/chaos_net_wait.c`
- `src/net/chaos_net.c`
- `src/time/chaos_time_actions.c`
- `src/time/chaos_time_config.c`
- `src/time/chaos_time.c`
- `src/time/chaos_time_hooks.c`
- `src/memory/chaos_memory_actions.c`
- `src/memory/chaos_memory_config.c`
- `src/memory/chaos_memory.c`
- `src/memory/chaos_memory_hooks.c`
- `src/process/chaos_process_actions.c`
- `src/process/chaos_process_config.c`
- `src/process/chaos_process.c`
- `src/process/chaos_process_hooks.c`

DNS is also part of the repository coverage gate:

- `src/dns/chaos_dns_actions.c`: `100.00%`
- `src/dns/chaos_dns.c`: `100.00%`
- `src/dns/chaos_dns_config.c`: minimum `85.00%`
- `src/dns/chaos_dns_lookup.c`: minimum `85.00%`

That split is intentional: DNS now participates in the enforced coverage gate,
but only IO, NET, TIME, MEMORY, and PROCESS are held at strict `100.00%`
line coverage today.

### C style gate

```sh
make fmt-check
```

This runs `clang-format` in check mode across all shipped C sources and tests.
Use `make fmt` to rewrite the tree to the repository style.

### Docker runtime probes

`libchaos-io` runtime proof:

- `sh test/runtime/test_glibc.sh linux/amd64`
- `sh test/runtime/test_glibc.sh linux/arm64`
- `sh test/runtime/test_alpine.sh linux/amd64`
- `sh test/runtime/test_alpine.sh linux/arm64`

`libchaos-net` runtime proof:

- `sh test/runtime/test_net_glibc.sh linux/amd64`
- `sh test/runtime/test_net_glibc.sh linux/arm64`
- `sh test/runtime/test_net_alpine.sh linux/amd64`
- `sh test/runtime/test_net_alpine.sh linux/arm64`

`libchaos-dns` runtime proof:

- `sh test/runtime/test_dns_glibc.sh linux/amd64`
- `sh test/runtime/test_dns_glibc.sh linux/arm64`
- `sh test/runtime/test_dns_alpine.sh linux/amd64`
- `sh test/runtime/test_dns_alpine.sh linux/arm64`

`libchaos-time` runtime proof:

- `sh test/runtime/test_time_glibc.sh linux/amd64`
- `sh test/runtime/test_time_glibc.sh linux/arm64`
- `sh test/runtime/test_time_alpine.sh linux/amd64`
- `sh test/runtime/test_time_alpine.sh linux/arm64`

`libchaos-memory` runtime proof:

- `sh test/runtime/test_memory_glibc.sh linux/amd64`
- `sh test/runtime/test_memory_glibc.sh linux/arm64`
- `sh test/runtime/test_memory_alpine.sh linux/amd64`
- `sh test/runtime/test_memory_alpine.sh linux/arm64`

`libchaos-process` runtime proof:

- `sh test/runtime/test_process_glibc.sh linux/amd64`
- `sh test/runtime/test_process_glibc.sh linux/arm64`
- `sh test/runtime/test_process_alpine.sh linux/amd64`
- `sh test/runtime/test_process_alpine.sh linux/arm64`

### Full local quality gate

```sh
make check
```

This runs:

1. `make fmt-check`
2. `make coverage`
3. `make test`

`make test` runs the host-architecture runtime probes for IO, NET, DNS, TIME,
MEMORY, and PROCESS. On non-Linux hosts, the Linux-only integration test is
skipped. The Docker probes are skipped when Docker is unavailable.

### Full Docker matrix gate

```sh
make test-matrix
```

This runs the glibc and musl Docker probes for IO, NET, DNS, TIME, MEMORY, and
PROCESS on both `linux/amd64` and `linux/arm64`.

The Docker runtime scripts accept an optional explicit platform argument:

```sh
sh test/runtime/test_glibc.sh linux/amd64
sh test/runtime/test_glibc.sh linux/arm64
sh test/runtime/test_alpine.sh linux/amd64
sh test/runtime/test_alpine.sh linux/arm64
```

When no platform is given, each script falls back to the host architecture.

The Docker runtime probes explicitly validate `openat()`, `readv()`, `writev()`,
`preadv()`, `pwritev()`, `ftruncate()`, Linux `fallocate()`, `unlinkat()`,
`renameat()`, Linux `sendfile()`, Linux `copy_file_range()`, and `fsync()`
under `LD_PRELOAD`.

### Build targets

Native Linux builds for all current libraries:

```sh
make native
```

Per-library native convenience targets:

```sh
make native-io
make native-net
make native-dns
make native-time
make native-process
make native-memory
```

Cross-build outputs for all libraries in a libc/arch tuple:

```sh
make cross-glibc-amd64
make cross-glibc-arm64
make cross-musl-amd64
make cross-musl-arm64
```

Per-library cross-build targets follow the same pattern:

```sh
make cross-glibc-amd64-net
make cross-glibc-arm64-time
make cross-musl-amd64-process
make cross-musl-arm64-memory
```

All four distro/arch binaries via Docker Buildx:

```sh
make docker-build-all
```

Expected output names:

- `dist/libchaos-<library>-glibc-amd64.so`
- `dist/libchaos-<library>-glibc-arm64.so`
- `dist/libchaos-<library>-musl-amd64.so`
- `dist/libchaos-<library>-musl-arm64.so`

Where `<library>` is one of:

- `io`
- `net`
- `dns`
- `time`
- `process`
- `memory`

## Minimal Artifact Strategy

The shared-library build is intentionally aggressive about size:

- hidden visibility by default
- section-level dead-code elimination
- stripped outputs
- no unwind tables
- no async unwind tables
- no stack protector
- no extra runtime or ABI baggage from C++

The goal is simple: keep the `.so` small, predictable, and boring.

## More Detail

| Document | Content |
|---|---|
| [`docs/DSL.md`](docs/DSL.md) | Grammar, specificity ordering, identity proof |
| [`docs/PLATFORM.md`](docs/PLATFORM.md) | ELF, PLT/GOT, RTLD_NEXT, vDSO, AT_SECURE |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component map, call flow, formal theorems |
| [`docs/ENGINEERING.md`](docs/ENGINEERING.md) | Build flags, ABI, CI, no-C++ rationale |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Overhead model, rdtsc methodology, comparisons |
| [`docs/SAFETY.md`](docs/SAFETY.md) | AT_SECURE, seccomp, fail-open, sanitisers |
| [`docs/SYSTEM.md`](docs/SYSTEM.md) | Global system manual, symbol ownership |
| [`docs/IO.md`](docs/IO.md) | libchaos-io internals |
| [`docs/NETWORK.md`](docs/NETWORK.md) | libchaos-net internals |
| [`docs/DNS.md`](docs/DNS.md) | libchaos-dns internals |
| [`docs/TIME.md`](docs/TIME.md) | libchaos-time internals |
| [`docs/MEMORY.md`](docs/MEMORY.md) | libchaos-memory internals |
| [`docs/PROCESS.md`](docs/PROCESS.md) | libchaos-process internals |
| [`docs/diagrams/`](docs/diagrams/) | 8 PlantUML architecture diagrams |

Code-level intent lives in the internal headers under [`src/`](src).

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

The depth shown in this project — `LD_PRELOAD` symbol interposition that composes cleanly with `dlsym(RTLD_NEXT, ...)`, lock-free config reload via two-snapshot pointer swap, thread-local fd-path caching that respects `unlinkat()`/`renameat()` invalidation, endpoint-aware wait-path matching derived from `/proc/self/fdinfo/<epfd>`, hand-tuned `.so` outputs with hidden visibility and section-level dead-code elimination, and a 100 % source-line coverage gate enforced across glibc + musl × amd64 + arm64 — comes from a path that started with peeking C64 memory at 10, ran through the demoscene where every cycle counted on the wire, through game studios that shipped on cartridges with no recall option, and then 30 years of production enterprise software. Most engineers enter at the framework layer and look down. **This stack reads from below.** Principal-engineer titles are job descriptions; assembler at 10, the demoscene at 15, and shipping for game studios at 16 — that is a starting line.

### Specific evidence in this project

Concrete artifacts a reviewer can read:

- **Six libraries shipped** — `libchaos-io`, `libchaos-net`, `libchaos-dns`, `libchaos-time`, `libchaos-process`, `libchaos-memory` — each with its own selector grammar, config file, and runtime contract; no shared mutable state across libraries
- **Cross-libc and cross-arch validation** — `glibc + musl × amd64 + arm64`, every release walked through Docker runtime probes on all four matrix cells
- **Strict 100 % source-line coverage** on shipped sources for IO, NET, TIME, MEMORY, and PROCESS; DNS at an enforced floor with the strict gate scoped intentionally
- **Honest documentation** of what *cannot* work and why — every library has an explicit "Important current boundary" section calling out the symbols and edge cases left as future work, not papered over
- **Composable by design** — `libchaos-net` deliberately does not own `read()`, `write()`, or `close()` so it composes cleanly with `libchaos-io`; DNS interception was extracted out of `libchaos-net` into its own library for the same reason
- **Apache 2.0 throughout** — usable in production, in commercial products, no lock-in

### Available for senior engineering engagements

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
