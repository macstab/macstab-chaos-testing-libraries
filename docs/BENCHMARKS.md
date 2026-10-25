<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# Performance and Overhead Reference

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

This document states what an intercepted call costs, how that cost is
measured, and how far each number can be trusted. It is written for
operators deciding whether to preload a library into a given workload and for
maintainers checking a change for regressions.

Two kinds of numbers appear here, and they must not be confused:

- **Measured**: medians from the benchmark harness (`benchmark/`), published
  per release as `<version>-benchmarks.md` in the repository root. All
  published data is Tier 1 `ADVISORY` (GitHub-hosted runners, §13.1).
- **Model**: analytic estimates of the per-call cost components. They were
  written before the measurements existed and before the rule-file check was
  throttled; each model table is labelled, and §2 states how the current code
  differs.

> **Provenance warning.** The published 1.0.0 and 1.0.1 matrices were
> measured on code that `stat()`ed the rule file on every intercepted call.
> Commit `9e630e2` (2026-10-15, "look at the rule file at most every
> millisecond") replaced that with a vDSO-clock throttle. Until a sweep of the
> current code is published, the measured passthrough costs below overstate
> the current hot path, and the model tables describe the old one.

---

## Table of Contents

1. [Measurement Methodology — rdtscp and CNTVCT_EL0](#1-measurement-methodology--rdtscp-and-cntvct_el0)
2. [Overhead Model — Zero Rule, One Rule, N Rules](#2-overhead-model--zero-rule-one-rule-n-rules)
3. [Cold Path Characterisation](#3-cold-path-characterisation)
4. [Memory Overhead](#4-memory-overhead)
5. [libchaos-io Hot Path Profile](#5-libchaos-io-hot-path-profile)
6. [libchaos-net Hot Path Profile](#6-libchaos-net-hot-path-profile)
7. [libchaos-dns Hot Path Profile](#7-libchaos-dns-hot-path-profile)
8. [libchaos-time Hot Path Profile](#8-libchaos-time-hot-path-profile)
9. [libchaos-memory Hot Path Profile](#9-libchaos-memory-hot-path-profile)
10. [libchaos-process Hot Path Profile](#10-libchaos-process-hot-path-profile)
11. [Comparison Baselines — libfaketime and Toxiproxy](#11-comparison-baselines--libfaketime-and-toxiproxy)
12. [Statistical Notes](#12-statistical-notes)
13. [Reproducible Benchmark Harness — `benchmark/`](#13-reproducible-benchmark-harness--benchmark)

---

## 1. Measurement Methodology — rdtscp and CNTVCT_EL0

A wrapper costs tens of nanoseconds to a few microseconds, so the timer must
resolve well below that and must not itself be interposed. `clock_gettime`
through libc has ~25-50 ns overhead on glibc (vDSO path) and is the very
symbol `libchaos-time` wraps; timing the interposer with an interposed clock
is circular. The harness therefore reads the CPU's counter directly
(`benchmark/harness/chaos_bench_timer.c`).

### 1.1 x86_64: RDTSCP

The harness uses `rdtscp` followed by `lfence`, selected only when the CPU
reports both `constant_tsc` and `nonstop_tsc` (otherwise the TSC rate follows
P-state or stops in deep C-states):

```c
static inline uint64_t chaos_bench_rdtscp(void)
{
    uint32_t aux;
    uint64_t tsc = __rdtscp(&aux);
    __asm__ volatile("lfence" ::: "memory");
    return tsc;
}
```

`rdtscp` waits for all earlier instructions to complete before reading the
counter; the trailing `lfence` stops later instructions from starting before
the read. The `"memory"` clobber stops the compiler from moving loads and
stores across it. This is the idiom of Intel's "How to Benchmark Code
Execution Times on Intel IA-32 and IA-64 Instruction Set Architectures"
(2010). The classic `cpuid; rdtsc` … `rdtscp; cpuid` pair is equivalent in
ordering but adds a `cpuid` (a VM exit under most hypervisors) to every read.

### 1.2 aarch64: CNTVCT_EL0

The harness reads the virtual counter between two instruction barriers:

```c
static inline uint64_t chaos_bench_cntvct(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\t"
                     "mrs %0, cntvct_el0\n\t"
                     "isb"
                     : "=r"(v) :: "memory");
    return v;
}
```

`isb` drains the pipeline so the `mrs` cannot be reordered with surrounding
work. `CNTVCT_EL0` is the physical count minus the hypervisor offset
(`CNTVOFF_EL2`); `CNTPCT_EL0` has no offset but is commonly trapped or
inaccessible to EL0 in guests. A benchmark only ever subtracts two reads, so
the constant offset cancels and the virtual counter is the portable choice.
The generic timer runs at a fixed frequency (`CNTFRQ_EL0`), typically 24 MHz
(Raspberry Pi 4, Cortex-A53/A72), 100 MHz (Ampere Altra), or 1 GHz
(Apple M1 virtual). At 24 MHz one tick is ~41.7 ns, so single-call samples on
such hosts are quantised; compare medians, not individual samples.

### 1.3 Calibration and fallback

The counter rate is not the core clock. At start-up the harness measures it
against `CLOCK_MONOTONIC_RAW` over a 100 ms window (counter read first, then
wall clock, on both ends, so jitter is bounded by one wall-clock read), then
repeats the calibration over 10 ms and **aborts** if the two rates differ by
more than 1 %: a non-invariant TSC, P-state interference or hypervisor steal
would otherwise produce plausible but wrong numbers. Converting:

```c
double ns_per_tick = 1e9 / calibrated_hz;
double ns = (double)(t_after - t_before) * ns_per_tick;
```

The per-read overhead (back-to-back reads, a median of nine sampled pairs
out of 1000) is recorded as `timer.overhead_ns` in every envelope; it is not
subtracted from the samples. Without an invariant counter the harness falls
back to `clock_gettime(CLOCK_MONOTONIC_RAW)` (~5–25 ns per read), which makes
results below ~50 ns per operation unreliable.

Caveat: calibration calls `clock_gettime` through libc. In a run with
`libchaos-time` preloaded, that call passes through the time wrapper
(passthrough, no rule for `CLOCK_MONOTONIC_RAW`), so calibration itself is not
affected by rules, but it does run interposed.

### 1.4 Benchmark Protocol

As implemented by `benchmark/run-bench.sh` and the runner:

1. One process per benchmark and arm (fresh ASLR layout, branch predictors,
   TLB, and a library loaded from scratch).
2. Warm-up: `BENCH_WARMUP` iterations (default 10 000; the release workflow
   uses 5000), so lazy PLT binding, symbol resolution, the first rule-file
   load and page faults happen before measurement.
3. Measurement: `BENCH_ITERS` iterations (default 200 000; release 100 000;
   heavy calls capped per `run_trio`: 20 000 for `open`/`openat`, `fsync`,
   `fdatasync`, `fallocate`, `socket`, `shutdown`, `getaddrinfo`,
   `getnameinfo`, `pthread_create`; 5000 for `fork`; 1000 for `execve`).
   One timer pair per iteration (or per `--batch=N` iterations).
4. Statistics over all samples, no trimming: min, max, mean, two-pass
   standard deviation, and R-7 percentiles p50/p90/p99/p99.9/p99.99.
5. Arms: baseline (no `LD_PRELOAD`), passthrough (preloaded, rule file with
   only comments), match-no-fire (one matching rule at probability 0),
   errno (one matching rule at probability 1).
6. Repetition: `--runs=N` (5 in CI); the driver compares the per-run medians.

CPU pinning, governor and IRQ affinity are the host's responsibility; inside
Docker the sweep is restricted to CPUs 0 and 1 (`--cpuset-cpus="0,1"`), not
pinned to one core.

---

## 2. Overhead Model — Zero Rule, One Rule, N Rules

### 2.0 Current hot path

Since `9e630e2` an intercepted call looks at its rule file at most once per
millisecond per library (`CHAOS_CHECK_INTERVAL_NS`), timed with the vDSO
`CLOCK_MONOTONIC` read directly (no PLT, no system call, not interposable):

```
wrapper entry
  ├─ chaos_once acquire load     symbols resolved?
  ├─ TLS guard check
  ├─ vDSO clock read             throttle: < 1 ms since the last look?
  │    └─ yes: use the active snapshot, no system call
  │    └─ no:  stat(rule file); reload if the change stamp moved
  ├─ no active rules             return: real call, no selector derived
  ├─ derive selector             path / endpoint / name (only with rules)
  ├─ linear rule scan            ≤ 256 rules
  ├─ qualifier + probability     PRNG step; wall clock only for @from/@until
  ├─ effect                      hit count; hits file at most every 100 ms
  └─ real call
```

The `stat()` that dominated the model below is now amortised to at most one
per millisecond per library, whether or not the rule file exists. On
architectures without a vDSO clock symbol known to `src/common/chaos_clock.h`
(anything but amd64 and arm64) the throttle is disabled and the model below
still applies.

### 2.1 Zero Rules (Empty Config / No Config File) — pre-throttle model

> Model (estimate) of the code before `9e630e2`: one `stat()` per call.

```
wrapper entry
  ├─ TLS guard check           ~2-3 cycles (TLS access)
  ├─ stat(config_path)         dominant cost: ~200-500 ns (filesystem metadata)
  ├─ config mtime unchanged    branch taken: immediate return
  ├─ real symbol call          (the library call itself)
  └─ TLS guard restore         ~1-2 cycles
```

The dominant overhead was `stat(config_path)`, one `SYS_statx` or `SYS_stat`
system call per interposed call:

| Platform           | stat() cost (cached inode) | stat() cost (cold inode) |
|--------------------|---------------------------|--------------------------|
| NVMe SSD + tmpfs   | 150-300 ns                | 300-600 ns               |
| ext4 (tmpfs inode) | 100-200 ns                | 200-400 ns               |

The model assumed `/tmp` on tmpfs and a page-cache-hot inode, giving
**150-300 ns per interposed call** in the passthrough case. Caveat: `/tmp` is
tmpfs only where the distribution or container runtime mounts it so; Docker
images usually keep `/tmp` on the overlay root file system. The cost was
non-negligible for high-frequency calls such as `clock_gettime`.

### 2.2 One Rule (Config Present, Single Rule) — pre-throttle model

> Model (estimate).

```
wrapper entry
  ├─ TLS guard check           ~2-3 cycles
  ├─ stat(config_path)         ~150-300 ns (mtime check)
  ├─ config mtime unchanged    skip reload
  ├─ resolve selector          ~10-30 cycles (path lookup / endpoint parse)
  ├─ linear rule scan (N=1)    ~5-15 cycles
  ├─ probability check         ~5-10 cycles (PRNG + compare)
  ├─ effect dispatch           ~5-30 cycles (no-op or set errno)
  ├─ real symbol call
  └─ TLS guard restore
```

Total added overhead over passthrough: ~25-100 ns for rule evaluation
(excluding `stat()`). With `stat()`: **175-400 ns per call**.

The selector line is optimistic for io and net: a fd-cache miss costs a
`readlink("/proc/self/fd/<fd>")` (a system call), and an endpoint costs
`getsockname`/`getpeername` plus `getsockopt(SO_TYPE)` (two or three system
calls).

### 2.3 N Rules (Config Present, N Rules) — model

Rule scanning is O(N) and linear; `CHAOS_<LIB>_MAX_RULES` is 256 in every library.

| N rules | Rule scan overhead (estimated) |
|---------|-------------------------------|
| 1       | ~15 cycles (~5 ns at 3 GHz)   |
| 16      | ~60-120 cycles (~20-40 ns)    |
| 64      | ~200-400 cycles (~65-130 ns)  |
| 256     | ~800-1200 cycles (~260-400 ns)|

At 256 rules the scan (~400 ns) was comparable to the old per-call `stat()`.
With the throttle the scan becomes the largest software cost of a rule-heavy
configuration; for typical files (< 16 rules) it is negligible. The scan also
copies the selected rule out of the snapshot under a seqlock (§3.1), and
io/net rules are large (an io rule carries a 1024-byte prefix), so N also
determines how much memory one call touches.

---

## 3. Cold Path Characterisation

### 3.1 CAS Winner: Config Reload

A reload runs when a look finds a new change stamp (hash of mtime, size,
inode, device), and again on the next look while the file's mtime is within
20 ms of now (racy-stamp window; a re-read with an identical content hash
keeps the snapshot). The thread that wins the CAS of the cached stamp to
`RELOADING` reads the file with raw system calls, parses it into the inactive
snapshot, assigns hit slots, writes the status file (staging file + rename)
and publishes. Model cost:

```
stat(config)          ~300 ns
open(config)          ~500 ns
read(config, 256KB)   ~2-10 µs (depends on file size; 256KB max)
parse N rules         ~1-5 µs (for N ≤ 256 rules)
CAS publish           ~5-10 cycles
total                 ~5-15 µs
```

The model omits the status-file write (open, write, close, rename: four more
system calls, tens of µs on overlay file systems).

Threads that lose the CAS, or arrive while the stamp is `RELOADING`, do not
spin or wait: they use the currently active snapshot and proceed. A reload
therefore adds latency only to the thread performing it.

### 3.2 dlsym Cold Path (First Call)

`dlsym(RTLD_NEXT, name)` runs once per symbol per process, in the constructor
or on the first wrapper call that precedes it, never per call. Model:

- `_dl_lookup_symbol_x()` in ld.so: ~1-5 µs for a single symbol.
- 7-10 symbols per library × ~5 µs = ~35-50 µs total at startup.

The symbol counts are now higher: `libchaos-io` resolves 45 symbols,
`libchaos-net` 31, `libchaos-process` 13, `libchaos-time` 8, `libchaos-dns` 7,
`libchaos-memory` 5. At the model's ~1-5 µs each, `libchaos-io` start-up
resolution is ~45–225 µs. The constructor additionally reads 8 bytes of
`/dev/urandom` and loads the rule file once.

---

## 4. Memory Overhead

Fixed memory per library. The sizes below are derived from the source
constants; they are virtual (`.bss`) sizes. Resident memory is lower: pages
are committed only when touched (the read buffer up to the file size, the
snapshots up to the rule count).

| Component | Size | Notes |
| --- | --- | --- |
| Two rule snapshots (io) | 2 × 256 × `sizeof(chaos_io_rule_t)` | rule ≥ 1056 bytes (1024-byte prefix plus fields) → ≥ 528 KiB |
| Two rule snapshots (others) | 2 × 256 × rule struct | net rules embed a 256-byte selector text (UNIX path); time, memory, process rules are small |
| Rule-file read buffer | 262,145 bytes | every library |
| Rule texts | 256 × 201 = 51,456 bytes | every library |
| Hits write buffer | 256 × 222 + 1 = 56,833 bytes | every library |
| Hit-slot pool | 512 slots × ~48 bytes ≈ 24 KiB | every library |
| Resolved symbol pointers | 5–45 × 8 bytes | see §3.2 |
| Process seed | 8 bytes | |
| Per-thread TLS | 12 bytes (guard + PRNG) plus 4 bytes per translation unit (`chaos_once`) | |
| fd cache (io only) | 32 × (`PATH_MAX` + 12) ≈ 128 KiB | **process-wide**, mapped on first store |
| `DUP` table (net only) | 64 × ~4.2 KiB ≈ 267 KiB | mapped on first use by a `DUP` rule |

Previous estimate, kept for reference and now stale:

| Component                     | Size (approx.)                                           |
|-------------------------------|----------------------------------------------------------|
| Two config snapshots (IO)     | 2 × 256 rules × `sizeof(chaos_io_rule_t)` ≈ 512 KiB      |
| Two config snapshots (others) | 2 × 256 rules × rule_struct ≈ 32–256 KiB (path fields vary) |
| Resolved symbol ptrs          | 7–12 symbols × 8 bytes ≈ 64–96 bytes                    |
| Process seed (`uint64_t`)     | 8 bytes                                                  |
| Per-thread TLS guard          | 4 bytes                                                  |
| Per-thread PRNG state         | 8 bytes                                                  |
| Per-thread FD cache (IO only) | `CHAOS_IO_FD_CACHE_SLOTS` (32) × `PATH_MAX` (4096) = 128 KiB |

That estimate put each library at approximately **128–640 KiB** of fixed
process memory and all six at approximately **2.5–4 MiB**. Two corrections:
the fd cache is no longer per thread (it is one 128 KiB table per process,
so thread count no longer scales it; per-thread static TLS of 128 KiB crashed
the Erlang VM), and the estimate omitted the 256 KiB read buffer and the
status/hits buffers every library carries. Virtual size per library is
therefore ~0.4–1 MiB, resident size usually far less.

The previous estimate of `.so` sizes, stripped: 30-80 KiB per library
(depending on symbol count), mapped read-only and shared by every process
that loads the same file. Measure the current artifacts with `ls -l dist/`
(`matrix.yml` lists them in each job log).

---

## 5. libchaos-io Hot Path Profile

> Model (estimate), pre-throttle.

| Call                     | Passthrough overhead (no rules) | With rules (N=1) |
|--------------------------|--------------------------------|------------------|
| `write(fd, buf, N)`      | 150-300 ns (stat only)         | +50-100 ns       |
| `read(fd, buf, N)`       | 150-300 ns                     | +50-100 ns       |
| `fsync(fd)`              | 150-300 ns                     | +50-100 ns       |
| `open(path, O_RDONLY)`   | 150-300 ns + path resolution   | +50-100 ns       |
| `openat(dirfd, path, ...)` | 200-400 ns (proc readlink)   | +50-100 ns       |

`openat()` with a non-`AT_FDCWD` directory descriptor resolves the directory
through the fd cache or `readlink("/proc/self/fd/N")`, another ~200-300 ns
beyond `stat()` on a miss. Path resolution happens only when io rules are
active.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, median of 5 runs, pre-throttle):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `write_passthrough` | 610.9 ns | 3,575.0 ns | +2,964 ns |
| `read_passthrough` | 640.9 ns | 3,745.3 ns | +3,104 ns |
| `pread_passthrough` | 1,081.5 ns | 4,275.9 ns | +3,194 ns |
| `pread_errno` | 1,071.5 ns | 3,004.2 ns | +1,933 ns |
| `fsync_passthrough` | 891.3 ns | 3,925.5 ns | +3,034 ns |
| `open_close_passthrough` | 3,955.6 ns | 7,260.2 ns | +3,305 ns |
| `open_close_errno` | 3,955.6 ns | 11,275.8 ns | +7,320 ns |

`pread_errno` is cheaper than `pread_passthrough` because the injected
failure skips the real `pread`.

---

## 6. libchaos-net Hot Path Profile

> Model (estimate), pre-throttle.

| Call                   | Passthrough overhead | With rules (N=1)  |
|------------------------|---------------------|-------------------|
| `connect(fd, addr, n)` | 150-300 ns           | +50-200 ns        |
| `send(fd, buf, n, 0)`  | 150-300 ns           | +50-200 ns        |
| `recv(fd, buf, n, 0)`  | 150-300 ns           | +50-200 ns        |
| `accept(fd, addr, n)`  | 150-300 ns           | +50-100 ns        |
| `poll(fds, n, timeout)`| 150-300 ns + endpoint derivation | +50-200 ns |

With `poll` rules active, `poll()`/`select()` derive an endpoint per watched
descriptor, so the cost grows with the set size (n > 64 makes it dominant);
`epoll_wait()` reads `/proc/self/fdinfo/<epfd>` (512-byte chunks, at most
256 KiB): add ~500 ns-5 µs per scan. Without net rules none of this runs.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, pre-throttle; send and recv
over an `AF_UNIX` socketpair):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `send_passthrough` | 2,373.3 ns | 4,566.4 ns | +2,193 ns |
| `recv_passthrough` | 811.1 ns | 1,722.4 ns | +911 ns |
| `socket_close_passthrough` | 5,157.3 ns | 8,652.2 ns | +3,495 ns |
| `shutdown_passthrough` | 6,098.6 ns | 11,356.0 ns | +5,257 ns |

The `send_*` kernel times a `send` plus a draining `recv`, and
`socket_close_*` a `socket` plus a `close`: two wrappers per iteration.

---

## 7. libchaos-dns Hot Path Profile

> Model (estimate), pre-throttle.

`libchaos-dns` wraps `getaddrinfo()`, `getnameinfo()` and the `gethostby*`
family. Real resolution reads `/etc/hosts` and `/etc/nsswitch.conf` and may
send UDP/TCP queries, so the wrapper is small relative to the call.

| Call                         | Passthrough overhead (no rules) | With rules (N=1) |
|------------------------------|--------------------------------|------------------|
| `getaddrinfo(host, ...)`     | 150-300 ns (stat only)         | +50-200 ns       |
| `getnameinfo(addr, ...)`     | 150-300 ns + inet_ntop         | +50-200 ns       |

`getnameinfo()` formats the numeric address with `inet_ntop()` (the reverse
selector key) on every call, before the rule check, even with no rules.
Cost: ~10-30 cycles (~5-10 ns at 3 GHz).

Post-resolution transforms (`FILTER_FAMILY` → `SHUFFLE` → `LIMIT`) cost in
proportion to the result list. For a typical result of 2-4 entries:

| Transform      | Cost (N=4 entries)   | Notes                                      |
|----------------|---------------------|--------------------------------------------|
| FILTER_FAMILY  | ~10-30 cycles        | One pass; `freeaddrinfo` per removed node   |
| SHUFFLE        | ~20-50 cycles        | Fisher–Yates over a `calloc`'d pointer array; list unchanged if allocation fails; no size cap |
| LIMIT          | ~5-10 cycles         | List truncation + `freeaddrinfo` on tail    |

Each removed node goes through the real `freeaddrinfo`, which frees through
the allocator: ~50-200 ns per freed node (allocator dependent). For results
of ≤ 8 nodes this stays sub-microsecond. Against the real `getaddrinfo()`
itself (typically 0.1–100 ms with network RTT; tens of µs from `/etc/hosts`),
the wrapper is below the noise floor.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, pre-throttle; `localhost`):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `getaddrinfo_passthrough` | 25,245.6 ns | 49,149.0 ns | +23,903 ns |
| `getaddrinfo_errno` | 25,145.4 ns | 5,958.4 ns | −19,187 ns |
| `getnameinfo_passthrough` | 6,088.6 ns | 18,345.8 ns | +12,257 ns |

The measured passthrough delta (~24 µs) is far above the model. It was
measured before the throttle and includes everything the resolver does
differently under the preload (the wrapper's own `stat()`, and every file the
resolver opens passing through no other chaos library here); it has not been
decomposed. `getaddrinfo_errno` is faster than native because the injected
`EAI_AGAIN` skips resolution.

---

## 8. libchaos-time Hot Path Profile

> Model (estimate), pre-throttle.

`clock_gettime(CLOCK_MONOTONIC)` through the glibc vDSO costs ~5-10 ns
uninstrumented (the harness's `clock_gettime_*` native column shows 60.1 ns
on the glibc-amd64 runner, which includes the timer pair).

| Config state               | Total clock_gettime cost |
|----------------------------|--------------------------|
| No preload                 | ~5-10 ns (vDSO)          |
| Preload, no config file    | ~160-310 ns (+stat)      |
| Preload, passthrough rule  | ~210-360 ns              |
| Preload, OFFSET rule       | ~215-370 ns (+offset add)|

Before the throttle, the per-call `stat()` made the preloaded call 20-60×
the uninstrumented cost in the model. With the throttle, a call that finds
no due look adds one vDSO clock read (the library's own throttle clock) plus
the guard and branch overhead to the real vDSO read, and one call per
millisecond pays the `stat()`.

The earlier mitigation advice ("remove the config file; absence is cached for
one call cycle") no longer applies: a missing rule file is throttled exactly
like a present one. Do not preload `libchaos-time` into a workload whose hot
path is clock reads unless clock faults are the point of the test.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, pre-throttle):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `clock_gettime_baseline` (passthrough arm) | 60.1 ns | 8,660.2 ns | +8,600 ns |
| `nanosleep_zero_passthrough` | 62,147.5 ns | 68,423.6 ns | +6,276 ns |

These measured hooked costs exceed the model by more than an order of
magnitude. The cause is not established by the published data; reproduce on
the current code before drawing conclusions. The `match_no_fire` and `errno`
time arms measured the same path as passthrough (§12.4).

---

## 9. libchaos-memory Hot Path Profile

> Model (estimate), pre-throttle.

| Call              | Passthrough overhead | With rules (N=1) |
|-------------------|---------------------|------------------|
| `mmap(...)` large | 150-300 ns           | +50-100 ns       |
| `munmap(...)`     | 150-300 ns           | +50-100 ns       |
| `mprotect(...)`   | 150-300 ns           | +50-100 ns       |
| `madvise(...)`    | 150-300 ns           | +50-100 ns       |

`mmap()` itself costs ~1-10 µs (VMA allocation, page-table work, and TLB
shootdowns on `munmap`/`mprotect` in multi-threaded processes), so a
150-300 ns wrapper is small against it.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, pre-throttle):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `madvise_passthrough` | 2,914.1 ns | 9,293.1 ns | +6,379 ns |
| `mprotect_passthrough` (two calls) | 8,892.5 ns | 21,690.4 ns | +12,798 ns |
| `munmap_passthrough` (`mmap` + `munmap`) | 5,487.7 ns | 17,945.2 ns | +12,458 ns |

---

## 10. libchaos-process Hot Path Profile

> Model (estimate), pre-throttle.

| Call                    | Passthrough overhead | Notes                         |
|-------------------------|---------------------|-------------------------------|
| `pthread_create(...)`   | 150-300 ns           | Negligible; create is ~30 µs  |
| `fork()`                | 150-300 ns           | Negligible; fork is ~50-200 µs|
| `posix_spawn(...)`      | 150-300 ns           | Negligible                     |
| `execve(...)`           | 150-300 ns           | Negligible; exec is ~1-5 ms   |
| `waitpid(...)`          | 150-300 ns           | Negligible; wait blocks        |

In the model the wrapper is 0.1-1% of a process lifecycle call.

Measured (1.0.1, glibc-amd64, Tier 1 `ADVISORY`, pre-throttle):

| Benchmark | Native | Hooked | Δ |
| --- | ---: | ---: | ---: |
| `pthread_create_passthrough` (create + join) | 49,379.4 ns | 63,439.2 ns | +14,060 ns (+28.5%) |
| `fork_wait_passthrough` | 112,098.0 ns | 153,325.4 ns | +41,227 ns (+36.8%) |
| `execve_short_passthrough` | 566,942.7 ns | 600,307.8 ns | +33,365 ns (+5.9%) |
| `waitpid_nohang_passthrough` | 650.9 ns | 9,403.2 ns | +8,752 ns |

The measured relative cost is 6–37 %, not 0.1–1 %: a forked child or new
thread under the preload runs the libraries' atfork handlers and touches
library state for the first time, which the model does not include. Treat
the model row as a lower bound.

---

## 11. Comparison Baselines — libfaketime and Toxiproxy

The third-party columns below are as previously documented and have not been
re-verified against current libfaketime and Toxiproxy releases; check them
against upstream documentation before relying on them.

### 11.1 libfaketime

`libfaketime` (https://github.com/wolfcw/libfaketime) is an `LD_PRELOAD`
library that intercepts time calls (`clock_gettime`, `gettimeofday`, ...) and
returns shifted or scaled timestamps.

| Aspect               | libfaketime                          | libchaos-time                       |
|----------------------|--------------------------------------|-------------------------------------|
| Mechanism            | LD_PRELOAD                           | LD_PRELOAD                          |
| stat() on hot path   | Yes (FAKETIME_NO_CACHE=1 mode)        | At most once per ms per process (vDSO-timed throttle); previously every call |
| vDSO bypass          | Uses `FAKETIME_DONT_RESET_SYSCALL`   | Does not bypass vDSO (wraps glibc)  |
| Go runtime coverage  | Optional fork with vsyscall patching | Not in LD_PRELOAD mode              |
| Clocks covered       | REALTIME, MONOTONIC, gettimeofday    | All clockids via clock_gettime; `gettimeofday`, `time`, `timespec_get` via the realtime rules |
| ERRNO injection      | No                                   | Yes                                 |
| LATENCY injection    | No                                   | Yes (sleeps too: `nanosleep`, `clock_nanosleep`, `sleep`, `usleep`) |
| One-time step back   | —                                    | `REGRESS`                           |
| Config syntax        | `FAKETIME=+2h`                       | `clock_gettime/realtime:OFFSET:7200000` |

The previous comparison put both at ~150-300 ns per call in the no-injection
passthrough case, on the assumption that both `stat()` per call. That
assumption no longer holds for `libchaos-time`.

### 11.2 Toxiproxy

Toxiproxy (https://github.com/Shopify/toxiproxy) is an out-of-process TCP
proxy that injects latency, bandwidth limits and connection faults.

| Aspect               | Toxiproxy                            | libchaos-net                         |
|----------------------|--------------------------------------|--------------------------------------|
| Mechanism            | Out-of-process TCP proxy             | LD_PRELOAD libc wrapper (SECCOMP mode via `chaos-init` for static/Go) |
| Requires kernel net  | Yes (network namespaces or iptables) | No                                   |
| Overhead (latency)   | ~50-200 µs (extra TCP hop + RTT)     | ~150-300 ns modelled (stat only); +0.9 to +5.3 µs measured per benchmark iteration of one to three wrapped calls (Tier 1, pre-throttle) |
| Overhead (connect)   | Full TCP three-way handshake overhead| One pre-call delay + real connect    |
| Requires root/cap    | NET_ADMIN for some topologies        | No                                   |
| Language coverage    | Any TCP/UDP traffic, incl. Go        | Dynamically linked libc callers; any process under `chaos-init` |
| Endpoint targeting   | By proxy port                        | By endpoint selector                 |
| CORRUPT effect       | Yes (chaos proxy plugin)             | Yes (single bit flip in received bytes) |
| Short / duplicated reads | slicer toxic (short writes)      | `TRICKLE`, `DUP`                     |
| Abortive close       | reset_peer toxic                     | `RESET`                              |
| Config format        | JSON API / CLI                       | Text file                            |

Choose Toxiproxy when the fault must sit on the wire (any client, any
language, no process cooperation). Choose `libchaos-net` when no daemon or
topology change is acceptable and per-process, per-endpoint targeting
matters; its per-call cost is microseconds against Toxiproxy's extra network
hop.

---

## 12. Statistical Notes

### 12.1 Variance Sources

1. **Scheduler preemption**: removed by `taskset -c N` + `SCHED_FIFO` on an
   isolated core; inside Docker the sweep only gets `--cpuset-cpus="0,1"`.
2. **TLB shootdowns**: reduced by disabling transparent hugepages during runs
   (the envelope records `thp_enabled`).
3. **C-states**: limited by `/sys/devices/system/cpu/cpu*/power/pm_qos_resume_latency_us` = 0.
4. **Rule-file `stat()` cache warmth**: the inode is normally cached; with the
   throttle only one call per millisecond pays it, which appears as a sparse
   upper tail rather than a shift of the median.
5. **Branch predictor warm-up**: the guard and no-rules branches are
   predictable after a few iterations; warm-up absorbs this.
6. **Counter resolution**: on 24 MHz generic timers one tick is ~41.7 ns, so
   sub-100 ns samples are quantised; use `--batch=N`.

### 12.2 Representative Percentiles — model

A well-calibrated passthrough measurement of the pre-throttle code was
expected to show:

- p50: ~180 ns (stat + guard + symbol call overhead)
- p95: ~350 ns (occasional TLB miss or page fault in tmpfs metadata)
- p99: ~1 µs (rare OS preemption)
- p99.9: ~10-50 µs (scheduler jitter, not preload-related)

The harness reports p50/p90/p99/p99.9/p99.99 per envelope (not p95). The
published matrices show medians only; check `stats` in the envelopes for
tails.

### 12.3 Benchmark vs Production

Microbenchmarks isolate the wrapper on a cheap kernel path (`/dev/zero`,
`AF_UNIX`, one cached page). In production:

- the wrapper cost is amortised against real I/O (disk: µs–ms; network: ms)
- `clock_gettime` is the exception: it is fast (5-10 ns) and frequent, so any
  wrapper cost is a large relative overhead
- Δ % is a ratio, `wrapper_cost / native_cost`: the same few µs is
  +10 000 % on a vDSO read and single-digit % on `pthread_create`

### 12.4 Scenario validity

The `_match_no_fire` and `_errno` arms exercise the rule path only if their scenario loads
and matches the benchmark's calls. `run-bench.sh --check-scenarios` proves it for every
benchmark of `benchmark/suite.tsv`, on glibc and musl, and CI (`ci.yml`, `bench.yml`,
`release.yml`) runs it before any sweep:

- the errno scenario loads (`state=ok`, at least one rule) and fires on every one of 64
  measured calls, and the run still completes and writes its envelope;
- the match-no-fire scenario is the errno scenario with probability 0 and loads;
- the passthrough scenario loads with 0 rules.

**Matrices up to and including 2.0.0 predate this check** and are partly invalid: the time,
memory and process scenarios used `ERRNO:<name>,<p>` (the grammar is `@<p>`) and were
rejected; io `readv`, `writev`, `openat_close`, `ftruncate`, `fallocate`, `sendfile` and net
`sendto`, `recvfrom`, `sendmsg`, `recvmsg` used operation names the parsers do not accept;
io `read`, `write`, `readv`, `writev`, `open_close`, `openat_close` targeted `/dev/zero` and
`/dev/null`, which libchaos-io excludes, and `pread`, `fsync`, `fdatasync` used selectors
that never matched (io prefixes match at path-component boundaries); dns `getnameinfo` used a
`dns://` rule where reverse lookups consult `rdns://`. In those matrices the affected
`_match_no_fire` and `_errno` cells measure passthrough or a non-matching rule. Net
`send`, `recv` and `shutdown` were not effective either: their `unix://*` rules target the
benchmark's socketpair, and before 2.0.0 libchaos-net could not resolve unnamed UNIX
sockets (and `send` looked at the peer only), so those arms measured the no-match path. Only
net `socket_close` (its rule matches the `socket()` arguments) and dns `getaddrinfo` were
effective.

The corrected benchmarks carry kernel revision 2 (`krev`, the six io kernels moved from
`/dev` to temp files) or scenario revision 2 (`srev`) in `benchmark/suite.tsv`. The
release-over-release gate compares a benchmark only between releases with the same
revision, so these are re-baselined once instead of reported as regressions.

### 12.5 Significance testing and the number of runs

Release sweeps (`release.yml`, `bench.yml`) use `--runs=10`; this section explains why five
were not enough. The driver tests per-run medians, so with `--runs=5` each arm contributes
five values. With n₁ = n₂ = 5 the Mann-Whitney normal approximation reaches
|z| = 12.5 / √(275/12) ≈ 2.61 at most (complete separation), i.e. p ≈ 0.009.
The p < 0.01 criterion is therefore met only when every treatment median
exceeds every baseline median, and r = z/√10 ≈ 0.83 follows automatically.
The bootstrap CI over five medians takes few distinct values. At five runs the
flag means "consistently slower in every run", not a calibrated significance level. With
ten runs per side the smallest reachable p is about 1.8 × 10⁻⁴, so a real slowdown clears
p < 0.01 with margin, and n₁ + n₂ = 20 is where the normal approximation becomes
reasonable. The release gate additionally requires the median slowdown to exceed 25 ns
(`--vs-prev-min-ns`), so scheduler and VM jitter on nanosecond-scale benchmarks cannot fail
a release on percentages alone.

---

## 13. Reproducible Benchmark Harness — `benchmark/`

The harness is a self-contained C benchmark suite in the style of JMH:
defences against dead-code elimination, a calibrated serialising timer,
percentile statistics, optional hardware counters, and an explicit
`OFFICIAL`/`ADVISORY` tag in every result. Operator instructions:
`benchmark/README.md`.

### 13.1 Two-tier model

| Tier | Where it runs | Use | Variance budget |
|---|---|---|---|
| **Tier 1** | Docker on any developer machine or CI runner | dev-loop change detection, PR CI, release matrices | 1–25% |
| **Tier 2** | bare-metal Linux with `isolcpus=N nohz_full=N rcu_nocbs=N`, `governor=performance`, IRQs steered off the bench cores | release-grade headline numbers | <1% |

The runner tags each envelope `OFFICIAL` only when every checked
precondition holds, otherwise `ADVISORY` with one warning per failed check
(`benchmark/harness/chaos_bench_isolation.c`):

| Check | Pass condition |
| --- | --- |
| `governor` | cpu0 governor is `performance` |
| `isolcpus` | `/sys/devices/system/cpu/isolated` non-empty |
| `container` | `/.dockerenv` absent |
| `smt` | cpu0 has no SMT sibling |
| `constant_tsc`, `nonstop_tsc` | CPU flags present (x86 only) |

`nohz_full`, `rcu_nocbs` and IRQ affinity are not checked. Every container
run is `ADVISORY` by construction.

No Tier 2 data has been published. The 1.0.0 and 1.0.1 matrices come from
the release workflow's sweep on GitHub-hosted runners (`ubuntu-24.04` and
`ubuntu-24.04-arm`, glibc and musl, 5 runs, 5000 warm-up and 100 000
measured iterations; releases after 2.0.0 use 10 runs) and are Tier 1 `ADVISORY`. They are
suitable for "did this regress relative to the previous release on the same runner
class?", not as absolute costs.

### 13.2 What the harness measures

Per hooked call, three benchmarks sharing one iteration body:

| Benchmark | Rule file | What it isolates |
|---|---|---|
| `<symbol>_passthrough`   | comments only | guard + throttle + early return + real call |
| `<symbol>_match_no_fire` | one matching rule, probability 0.0 | + selector derivation + rule scan + probability draw |
| `<symbol>_errno`         | one matching rule, probability 1.0 | + effect dispatch; the real call is skipped |

Each runs once without `LD_PRELOAD` (baseline) and once with it (treatment);
`run-bench.sh` tags the envelope file name with the arm. The scenario is
copied to `/tmp/.chaos-<lib>.conf` with an mtime 60 s in the future before the
first iteration and removed afterwards. The A/B driver
(`benchmark/driver/chaos_bench_driver.py`) computes:

- median delta and percentage delta (treatment − baseline) over per-run medians
- Mann-Whitney U (two-sided, normal approximation, tie-averaged ranks)
- effect size r = z / √N
- bootstrap 95 % CI (2 000 resamples, fixed seed 0) on the median delta
- regression flag only when *p < 0.01* **and** *|r| > 0.5* **and** *Δ > 3 %*;
  fewer than 3 runs per arm skips the test

Native-vs-preload comparisons flag every hooked call by design (the wrapper
always costs something); the release workflow accepts that exit code. The
gate that matters is release-over-release: `--vs-prev <dir>` compares this
release's treatment medians with the previous release's, with a 15 %
threshold (`--vs-prev-pct`).

### 13.3 Hardware counters

With `perf_event_open(2)` available (`CAP_PERFMON`, or
`kernel.perf_event_paranoid ≤ 2`; `run-bench.sh` adds `--cap-add=SYS_ADMIN`
and `--security-opt seccomp=unconfined`, and CI sets the sysctl to 1), the
harness counts `cycles`, `instructions`, `branches`, `branch_misses`,
`cache_references`, `cache_misses`, `dtlb_load_misses`, `context_switches`,
`cpu_migrations`, `page_faults` over the measurement loop (opened after
warm-up). Without permission the envelope's `pmu` section says
`available: false` with the reason; missing data is never silent. On shared
VMs hardware counters are often virtualised away; expect `available: false`
or zeros on hosted runners.

### 13.4 Schema versioning

Envelopes carry `schema_version` (currently 1). The driver refuses to compare
across versions; a bump is a breaking change. Annotated schema:
`benchmark/README.md`; canonical writer: `benchmark/harness/chaos_bench_json.c`.

### 13.5 What the harness does NOT do

Delegated to the wrapper layer or the host:

- **CPU pinning**: `taskset` on Tier 2; `--cpuset-cpus` on Tier 1.
- **Governor, SMT, IRQ affinity**: host-only, configured when provisioning Tier 2.
- **`LD_PRELOAD`**: set per run by `run-bench.sh`.
- **Page-cache state**: not normalised. Kernels pick targets that stay cached
  (`/dev/zero`, `/dev/null`, one 4 KiB page); for cold-cache studies add
  `posix_fadvise(POSIX_FADV_DONTNEED)` to the benchmark setup.
- **Outlier trimming**: none; statistics are over all samples.

The harness checks the isolation preconditions and downgrades to `ADVISORY`;
it does not enforce them.

### 13.6 Coverage matrix

Benchmarks registered in `benchmark/kernels/` and run by
`run-bench.sh --full` (each with `_passthrough`, `_match_no_fire`, `_errno`,
except `clock_gettime`, whose passthrough arm is named
`clock_gettime_baseline`):

| Subsystem | Benchmarks |
|---|---|
| `libchaos-time`    | `clock_gettime`, `nanosleep_zero`, `usleep_zero` |
| `libchaos-io`      | `pread`, `read`, `write`, `readv`, `writev`, `open_close`, `openat_close`, `fsync`, `fdatasync`, `ftruncate`, `fallocate`, `sendfile` |
| `libchaos-net`     | `send`, `recv`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `socket_close`, `shutdown` (all `AF_UNIX`) |
| `libchaos-dns`     | `getaddrinfo` (`localhost`), `getnameinfo` |
| `libchaos-memory`  | `madvise`, `mprotect`, `munmap` |
| `libchaos-process` | `pthread_create`, `waitpid_nohang`, `fork_wait`, `execve_short` |
| harness self-test  | `nop_loop_1k`, `clock_overhead` (`bench_meta`, not part of the sweep) |

`--smoke` runs only `clock_gettime_baseline` (baseline and passthrough).
See §12.4 for which arms currently exercise the rule path.

Not benchmarked: data-reshaping effects (`TORN`, `CORRUPT`, `TRICKLE`,
`DUP`), `LATENCY` (its cost is the configured delay), stdio wrappers, readiness
waits, the cold paths of §3, and multi-threaded reload contention.

Planned (Stage 4): a multi-thread reload-contention benchmark (a different
shape from per-call benchmarks; with non-waiting CAS losers it measures the
reloading thread's latency and readers' seqlock retries per thread count),
an `mmap` allocation-size sweep, `fork()`/`posix_spawn()` `SINGLE_SHOT`
benchmarks, and sample-time CDF output.

### 13.7 Known harness caveats

- The `bench.yml` hyperfine cross-check looks for
  `benchmark/reports/<sha>/clock_gettime_baseline.json`, but `run-bench.sh`
  writes `<name>.<arm>.<run>.json`; the check therefore always takes its
  "harness JSON not found" branch and only reports the hyperfine estimate.
- `run-bench.sh --full` on a developer laptop produces Tier 1 numbers:
  comparable only with runs on the same machine.

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
