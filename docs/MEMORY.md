<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# libchaos-memory Technical Reference

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

`libchaos-memory` is the dedicated memory-mapping preload library in this
repository. Repository-wide ownership and composition rules live in
[`docs/SYSTEM.md`](SYSTEM.md). Platform-layer internals (ELF link-map ordering,
PLT/GOT cold/hot paths, vDSO, AT_SECURE) are in [`docs/PLATFORM.md`](PLATFORM.md).

Current implementation status:

- exact interposed symbols today: `mmap()`, `munmap()`, `mprotect()`, `madvise()`
- config path: `/tmp/.chaos-memory.conf`
- unit-tested; strict `100.00%` line coverage gate on `src/memory/*.c`
- runtime probe implemented for glibc/musl and amd64/arm64 validation

---

## Table of Contents

1. [Virtual-Memory Taxonomy](#1-virtual-memory-taxonomy)
2. [Allocator Linkage — ptmalloc2 and mallocng](#2-allocator-linkage--ptmalloc2-and-mallocng)
3. [DSL Grammar and Rule Semantics](#3-dsl-grammar-and-rule-semantics)
4. [Per-Hook Call Flows](#4-per-hook-call-flows)
5. [mmap/anon vs mmap/file Dispatch](#5-mmapanon-vs-mmapfile-dispatch)
6. [Non-Coverage: brk/sbrk](#6-non-coverage-brksbrk)
7. [Non-Coverage: mremap](#7-non-coverage-mremap)
8. [Non-Coverage: mlock and mlock2](#8-non-coverage-mlock-and-mlock2)
9. [madvise Hint Catalogue and Injection Surface](#9-madvise-hint-catalogue-and-injection-surface)
10. [NUMA, mbind, and move_pages — Out of Scope](#10-numa-mbind-and-move_pages--out-of-scope)
11. [MAP_HUGETLB and Transparent Hugepages](#11-map_hugetlb-and-transparent-hugepages)
12. [KASLR Interaction](#12-kaslr-interaction)
13. [PT_GNU_STACK and the Executable-Stack Guard](#13-pt_gnu_stack-and-the-executable-stack-guard)
14. [Reentrancy Guard and TLS State](#14-reentrancy-guard-and-tls-state)
15. [PRNG Model](#15-prng-model)
16. [Config Reload Protocol — Two-Snapshot CAS](#16-config-reload-protocol--two-snapshot-cas)
17. [glibc vs musl Divergence](#17-glibc-vs-musl-divergence)
18. [Execution Boundary Summary](#18-execution-boundary-summary)

---

## 1. Virtual-Memory Taxonomy

Linux user-space memory is divided into four archetypal VMA classes. Understanding
which ones this library can and cannot reach is prerequisite to reasoning about
injection scope.

### 1.1 Anonymous Private (`MAP_PRIVATE | MAP_ANONYMOUS`)

Backed by zero pages from the kernel's page allocator (ZONE_NORMAL / ZONE_HIGHMEM
depending on arch and size). Pages are demand-paged from the zero-page until first
write, at which point CoW (copy-on-write) creates a private physical page. The
allocators (`malloc`, operator `new`) use anonymous VMAs for large allocations
(glibc: `>= MMAP_THRESHOLD`, default 128 KB; mallocng: arena threshold per
`malloc_options.h`).

Selector `mmap/anon` fires for any call where `flags & MAP_ANONYMOUS` is non-zero.
`MAP_ANONYMOUS | MAP_PRIVATE` is the dominant class. `MAP_ANONYMOUS | MAP_SHARED`
(SysV IPC emulation) also matches.

### 1.2 File-Backed Private (`MAP_PRIVATE`, fd ≥ 0)

Used by the dynamic linker to map ELF segments (text, rodata, data+bss CoW),
by `dlopen()` for shared libraries, and by application code for memory-mapped I/O.
Writeable pages get CoW copies on first write; the underlying file is never
modified. Selector `mmap/file` fires.

Because the dynamic linker calls `mmap()` during `dl_open` before `dlsym`
returns control to `__libc_start_main`, injection here can make library loading
fail — which is a valid test (ENOMEM from a plugin loader) but requires care with
probability guards.

### 1.3 File-Backed Shared (`MAP_SHARED`, fd ≥ 0)

Direct page-cache sharing; writes are visible to other processes mapping the same
file and propagate to the backing file on writeback. Used for IPC via `mmap()` of
a shared file, for `shm_open`/`posix_shm`, and for POSIX shared memory objects.
Selector `mmap/file` fires.

### 1.4 Anonymous Shared (`MAP_SHARED | MAP_ANONYMOUS`)

Zero-initialised pages shared between parent and children after `fork()`. Pages
live in tmpfs internally (Linux ≥ 2.4). Selector `mmap/anon` fires because the
`MAP_ANONYMOUS` bit is set regardless of the sharing flag.

### 1.5 Guard Pages and Special VMAs

`PROT_NONE` guard pages are typically created by `mmap(NULL, size, PROT_NONE,
MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`. They match `mmap/anon`. Thread stack guards,
`pthread_create`-internal guard pages, and `valgrind`/`asan` shadow maps all
arrive through the same `mmap()` call path. Injecting `ENOMEM` with a non-zero
probability here will trigger thread-creation failures — a valid chaos scenario,
but the correct configuration should use the `mmap/anon` selector with a small
probability guard (e.g., `mmap/anon:ERRNO:ENOMEM@0.001`) rather than a hard
100% rate.

---

## 2. Allocator Linkage — ptmalloc2 and mallocng

### 2.1 glibc ptmalloc2

ptmalloc2 (Wolfram Gloger's malloc, derived from Doug Lea's dlmalloc, standard in
glibc since 2.3) manages a main arena and per-thread arenas. Small allocations
(below `MMAP_THRESHOLD`, default 128 KiB) are served from arena bins using the
`brk()`/`sbrk()` heap segment. Allocations at or above the threshold use
`mmap(MAP_PRIVATE|MAP_ANONYMOUS)` directly and are freed with `munmap()`.

Consequence for injection:

- `malloc(N)` for N ≥ 128 KiB → `mmap/anon:ERRNO:ENOMEM` can make it fail
- `malloc(N)` for N < 128 KiB → served from the arena, **not through `mmap()`**;
  `mmap/anon:ERRNO:ENOMEM` does NOT affect it
- `free()` of a large allocation → `munmap()`; `munmap:ERRNO:EINVAL` can leave
  the mapping alive (intentional semantics, see §4.3)

The threshold is tunable via `mallopt(M_MMAP_THRESHOLD, ...)` or
`MALLOC_MMAP_THRESHOLD_` environment variable. At runtime the threshold adapts
upward dynamically (up to `DEFAULT_MMAP_MAX = 65536` mmaps) unless disabled by
`mallopt(M_TRIM_THRESHOLD, -1)`.

Reference: glibc `malloc/malloc.c`, symbols `__libc_malloc`, `_int_malloc`,
`sysmalloc`; POSIX.1-2017 §11.2 (no dynamic threshold is standardised).

### 2.2 musl mallocng

musl's `mallocng` (introduced in musl 1.2.x, replacing the previous "old malloc")
does not use `brk()` at all. All arenas are `mmap(MAP_PRIVATE|MAP_ANONYMOUS)`.
Meta-data pages (group headers, `struct meta_area`) are allocated by an internal
`alloc_meta()` path that also uses anonymous `mmap()`.

Consequence: on musl, even small allocations eventually require `mmap()`. The
selector `mmap/anon` has broader coverage against mallocng than against ptmalloc2.

Reference: musl `src/malloc/mallocng/malloc.c`, `alloc_meta()`, `nontrivial_free()`.

### 2.3 Why brk/sbrk Is Not Interposed

`brk(2)` and `sbrk(3)` are the historical heap-extension primitives. glibc's
ptmalloc2 calls `__sbrk()` internally to extend the main arena's heap region.
However:

1. `brk()` is a raw syscall on Linux (NR 12 on x86_64, NR 214 on aarch64); glibc's
   `sbrk()` wrapper calls it directly via `__brk()` which uses the `brk` syscall
   number. LD_PRELOAD interposition of a libc symbol `brk` or `sbrk` would work
   only if the allocator called it through the public libc symbol table — which
   glibc's own malloc does not (it calls `__brk` directly, bypassing the PLT).
2. musl mallocng does not use `brk()` at all; the hook would be dead on musl.
3. The behaviour of breaking the main arena heap in a controlled way is extremely
   difficult to make idempotent; a failed `brk()` corrupts the arena's bookkeeping
   in ways that are not recoverable without forking the allocator.

For heap exhaustion scenarios, the correct injection point is `mmap/anon:ERRNO:ENOMEM`
for large allocations (ptmalloc2 mmap path) and for all allocations on musl.

---

## 3. DSL Grammar and Rule Semantics

### 3.1 Full ABNF (RFC 5234)

```abnf
rule-line   = selector ":" effect ":" value [ "@" probability ] CRLF / LF
selector    = "*"
            / "mmap"
            / "mmap/anon"
            / "mmap/file"
            / "munmap"
            / "mprotect"
            / "madvise"
effect      = "ERRNO" / "LATENCY"
value       = errno-name / latency-ms
errno-name  = 1*ALPHA *( ALPHA / DIGIT / "_" )
latency-ms  = 1*DIGIT
probability = "0." 1*DIGIT / "1.0" / "1"
```

`*` is the wildcard selector matching any interposed call regardless of symbol
name. More specific selectors (`mmap/anon`, `mmap/file`) take precedence; see
§3.2 for rule ordering.

### 3.2 Rule Precedence and First-Match Semantics

The config engine scans rules top-to-bottom. For a given call:

1. The most specific matching selector wins per effect type.
2. If two rules with the same effect and equal specificity exist, the one appearing
   first in the file is applied.
3. A single call evaluates `LATENCY` first (pre-call delay), then `ERRNO`
   (pre-call failure gate). The real call fires only if `ERRNO` did not trigger.
4. `mmap/anon` and `mmap/file` are more specific than `mmap`, which is more
   specific than `*`. Within the specificity tier, first-match wins.

### 3.3 Effect Semantics per Symbol

| Symbol     | LATENCY | ERRNO | Notes                                      |
|------------|---------|-------|--------------------------------------------|
| `mmap`     | yes     | yes   | LATENCY fires before the real call         |
| `mmap/anon`| yes     | yes   | Sub-selector of mmap; MAP_ANONYMOUS test   |
| `mmap/file`| yes     | yes   | Sub-selector of mmap; !MAP_ANONYMOUS test  |
| `munmap`   | yes     | yes   | Synthetic failure leaves mapping alive     |
| `mprotect` | yes     | yes   | No post-call mutation path                 |
| `madvise`  | yes     | yes   | No hint-rewrite path                       |

### 3.4 Valid `errno` Values per Call

These are the values the POSIX.1-2017 and Linux man-pages document as meaningful;
the library does not validate the configured value against this list but callers
should use documented errors to avoid surprising application behaviour.

`mmap()`: `EACCES`, `EAGAIN`, `EBADF`, `EINVAL`, `ENFILE`, `ENODEV`, `ENOMEM`,
`EOVERFLOW`, `EPERM` (Linux 4.9+, MAP_FIXED_NOREPLACE seal), `ETXTBSY`.

`munmap()`: `EINVAL`.

`mprotect()`: `EACCES`, `EINVAL`, `ENOMEM`.

`madvise()`: `EACCES`, `EAGAIN`, `EBADF`, `EINVAL`, `EIO`, `ENOMEM`, `EPERM`.

---

## 4. Per-Hook Call Flows

### 4.1 `mmap()` Call Flow

```
wrapper entry
  ├─ chaos_memory_enter_internal()  → TLS guard: re-entrancy check
  │    (guard non-zero → bypass all injection, call real mmap, return)
  ├─ chaos_memory_check_config()    → stat(config_path), CAS-based reload if mtime changed
  ├─ LATENCY rule match
  │    if matched → nanosleep(ms * 1e6 ns) via real_nanosleep
  ├─ ERRNO rule match
  │    if matched and PRNG()/UINT32_MAX ≤ probability → errno=value, return MAP_FAILED
  ├─ mmap_is_anonymous(flags) → set sub-selector for /anon or /file
  ├─ real_mmap(addr, length, prot, flags, fd, offset)
  └─ chaos_memory_leave_internal()
```

The reentrancy guard prevents the LATENCY nanosleep from recursing back through
the memory wrapper (because `nanosleep` is in `libchaos-memory`'s own hook table).
See §14 for the full TLS guard mechanics.

### 4.2 `mprotect()` Call Flow

```
wrapper entry
  ├─ chaos_memory_enter_internal()
  ├─ chaos_memory_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match
  │    if fired → errno=value, return -1
  ├─ real_mprotect(addr, len, prot)
  └─ chaos_memory_leave_internal()
```

No post-call mutation. The library does not rewrite `prot` values before or after
the real call. Rewriting protection flags non-atomically would create TOCTOU
windows unrelated to the failure mode being tested.

### 4.3 `munmap()` Call Flow

```
wrapper entry
  ├─ chaos_memory_enter_internal()
  ├─ chaos_memory_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match
  │    if fired → errno=EINVAL (or configured), return -1
  │    mapping remains alive in process address space
  ├─ real_munmap(addr, len)
  └─ chaos_memory_leave_internal()
```

The synthetic `munmap()` failure is semantically correct: when `munmap(2)` returns
`EINVAL` from the kernel the mapping stays; this library's synthetic failure
models exactly that observable. The library does not track that the mapping has
been "leaked" — it is the caller's responsibility to retry or fail-fast, which is
the behaviour the test is probing for.

### 4.4 `madvise()` Call Flow

```
wrapper entry
  ├─ chaos_memory_enter_internal()
  ├─ chaos_memory_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match
  │    if fired → errno=value, return -1
  ├─ real_madvise(addr, len, advice)
  └─ chaos_memory_leave_internal()
```

`madvise()` is advisory by POSIX.1-2017 definition. A kernel is permitted to
ignore any advice; `EINVAL` is the canonical error for bad advice values. The
library does not mutate the `advice` argument.

---

## 5. mmap/anon vs mmap/file Dispatch

The split is derived from the `flags` argument of the incoming `mmap()` call:

```c
static inline int chaos_memory_mmap_is_anonymous(int flags)
{
    return (flags & MAP_ANONYMOUS) != 0;
}
```

This single bit test is the sole dispatch criterion. The library does not inspect:
- the `fd` argument (which may be -1 or a valid fd even for `MAP_ANONYMOUS`)
- the `offset` argument
- the VMA type (private vs shared within each class)

On Linux, `MAP_ANONYMOUS` (0x20 on x86_64/aarch64) and its historical alias
`MAP_ANON` (defined identically on platforms that use the alias) are normalised
at the top of `chaos_memory_internal.h`:

```c
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
```

This ensures portability across BSDs and older POSIX platforms. The library is
not expected to run on those platforms, but the guard eliminates a compile-time
portability trap.

---

## 6. Non-Coverage: brk/sbrk

Covered in detail in §2.3. Short form: `brk()` bypasses the PLT in glibc's own
malloc; musl does not call it at all; interposing it is not idempotent. Out of
scope by design.

---

## 7. Non-Coverage: mremap

`mremap(2)` (Linux-specific, not in POSIX.1-2017) extends or shrinks an existing
VMA or moves it to a new address. glibc does not use it internally for normal
allocation, but some allocators (jemalloc, mimalloc) do use it as an efficient
realloc path (`MREMAP_MAYMOVE`).

Why not interposed:

1. `mremap()` is Linux-only (`_GNU_SOURCE` required); shipping a hook for a
   non-portable symbol adds platform gating that is not yet worth the complexity.
2. The primary failure scenarios (ENOMEM, EFAULT) are already reachable via
   `mmap/anon:ERRNO:ENOMEM` for the allocator's initial allocation, which is
   usually more useful for resilience testing.
3. `mremap(MREMAP_FIXED)` semantics overlap with `munmap+mmap`, making a synthetic
   failure of `mremap` alone ambiguous without tracking source VMA.

Candidate for future expansion. Reference: `mremap(2)` Linux man-pages, jemalloc
`src/pages.c` `pages_huge_aligned()`, mimalloc `src/segment.c` `_mi_segment_map_aligned()`.

---

## 8. Non-Coverage: mlock and mlock2

`mlock(2)`, `mlock2(2)` (Linux 4.4+), and `munlock(2)` pin pages into RAM,
preventing reclaim. Used by: HSMs, memory-safe key storage, real-time audio
daemons (JACK, PulseAudio), latency-critical network paths.

Why not interposed:

1. The primary chaos target for memory residency is the allocator path, not the
   lock/unlock protocol.
2. `mlock()` failure (`EAGAIN`, `ENOMEM`, `EPERM` when `RLIMIT_MEMLOCK` is
   exhausted) is already reachable in integration tests by reducing
   `RLIMIT_MEMLOCK` to 0 via `ulimit -l 0` before test execution — without
   requiring a preload hook.
3. `mlock2(MLOCK_ONFAULT)` semantics interact with page-fault handling in ways
   that are genuinely kernel-internal and not observable at the libc wrapper level.

`mlockall(MCL_FUTURE)` is the extreme variant; this is also not interposed for
the same reasons. Reference: `mlock(2)`, `mlock2(2)` Linux man-pages.

---

## 9. madvise Hint Catalogue and Injection Surface

`madvise(2)` carries a rich set of advice values. The library does not restrict
which `advice` value the real call receives, but understanding the catalogue
clarifies what a synthetic `madvise` failure means for the target application.

### 9.1 Advisory Hints (POSIX.1-2017 and Linux Extensions)

| Advice constant         | Source      | Semantics                                               |
|-------------------------|-------------|---------------------------------------------------------|
| `MADV_NORMAL`           | POSIX       | No special treatment, reset any prior advice            |
| `MADV_SEQUENTIAL`       | POSIX       | Prefetch forward; kernel read-ahead aggressively        |
| `MADV_RANDOM`           | POSIX       | Disable read-ahead; random access expected              |
| `MADV_WILLNEED`         | POSIX       | Prefetch the range now; `read-ahead` into page cache    |
| `MADV_DONTNEED`         | POSIX       | Kernel may reclaim pages; accesses re-fault from zero   |
| `MADV_FREE`             | Linux 4.5   | Pages may be reclaimed, but remain if not under pressure|
| `MADV_HUGEPAGE`         | Linux 2.6.38| Promote range to THPs if `CONFIG_TRANSPARENT_HUGEPAGE` |
| `MADV_NOHUGEPAGE`       | Linux 2.6.38| Inhibit THP promotion for the range                    |
| `MADV_DONTFORK`         | Linux 2.6.16| Range not copied on `fork()`, child gets zero pages    |
| `MADV_DOFORK`           | Linux 2.6.16| Undo `MADV_DONTFORK`                                    |
| `MADV_DONTDUMP`         | Linux 3.4   | Exclude range from core dumps                           |
| `MADV_DODUMP`           | Linux 3.4   | Undo `MADV_DONTDUMP`                                    |
| `MADV_MERGEABLE`        | Linux 2.6.32| KSM candidate (Kernel Samepage Merging)                 |
| `MADV_UNMERGEABLE`      | Linux 2.6.32| Undo KSM eligibility                                    |
| `MADV_HWPOISON`         | Linux 2.6.32| Simulate hardware memory error on the range (CAP_SYS_ADMIN required) |
| `MADV_SOFT_OFFLINE`     | Linux 2.6.33| Offline page without data loss (CAP_SYS_ADMIN required) |
| `MADV_REMOVE`           | Linux 2.6.16| Release range from shared file mapping (hole punch)     |
| `MADV_COLD`             | Linux 5.4   | Deactivate pages; reclaim under pressure before others  |
| `MADV_PAGEOUT`          | Linux 5.4   | Reclaim pages immediately; useful for cold-tier flushing|
| `MADV_POPULATE_READ`    | Linux 5.14  | Eagerly populate (read) range                           |
| `MADV_POPULATE_WRITE`   | Linux 5.14  | Eagerly populate (write) range                          |

### 9.2 Injection Surface

The library's `madvise:ERRNO:EINVAL` or `madvise:ERRNO:ENOMEM` injects a
pre-call failure. The application sees the failure but the kernel does not see the
advice. Useful for:

- testing that applications handle `MADV_WILLNEED` failure gracefully (prefetch
  degrades to demand-paging, not a crash)
- testing that `MADV_FREE` / `MADV_DONTNEED` failure at `free()` time does not
  corrupt the allocator
- testing that `MADV_DONTDUMP` failure does not expose secrets in core dumps
  (the injection simulates the syscall not running, so secrets remain dumpable)

### 9.3 What madvise Injection Cannot Reach

The library cannot inject a partial-range error (`ENOMEM` for part of the range
only), cannot simulate `MADV_HWPOISON` machine-check events, and cannot
synthesise the delayed reclaim of `MADV_FREE`-marked pages under memory pressure.

---

## 10. NUMA, mbind, and move_pages — Out of Scope

`mbind(2)`, `set_mempolicy(2)`, `get_mempolicy(2)`, and `move_pages(2)` operate
on NUMA memory policies. They are not interposed.

Rationale:

1. NUMA policy failures (`EINVAL`, `EPERM`, `EIO` from `move_pages`) are
   typically infrastructure failures (misconfigured NUMA topology, missing
   `CAP_SYS_NICE`), not application code-path failures worth testing via preload.
2. NUMA-aware testing requires a multi-NUMA-node machine; single-node VMs
   (CI standard) return `ENOTSUP` from `mbind()` unconditionally — the real error
   surface is already available without injection.
3. `mbind()` and `set_mempolicy()` affect the NUMA policy on already-mapped VMAs;
   their failure modes do not propagate backward to the `mmap()` that created
   the VMA. They are orthogonal to the allocation-failure scenarios this library
   targets.

---

## 11. MAP_HUGETLB and Transparent Hugepages

### 11.1 Explicit Hugepages (MAP_HUGETLB)

`MAP_HUGETLB` (Linux 2.6.32) requests pages from the HugeTLB pool. Sizes are
specified with `MAP_HUGE_2MB` or `MAP_HUGE_1GB` shift flags (Linux 3.8). The pool
must be pre-allocated (`/proc/sys/vm/nr_hugepages`).

`mmap/anon:ERRNO:ENOMEM` covers MAP_HUGETLB allocations because they set
`MAP_ANONYMOUS | MAP_HUGETLB`. No special selector is needed.

### 11.2 Transparent Hugepages (THP)

THP promotion is controlled by `madvise(MADV_HUGEPAGE)` per-range and by the
system-wide `/sys/kernel/mm/transparent_hugepage/enabled` policy. The library
can inject `madvise:ERRNO:EINVAL` to simulate the promotion hint being rejected
(useful for testing that THP-optimised code handles MADV fallback without data
corruption). The actual promotion decision, demotion, and compaction are
kernel-internal and beyond the preload boundary.

---

## 12. KASLR Interaction

Kernel Address Space Layout Randomisation (KASLR, CONFIG_RANDOMIZE_BASE) shifts
the kernel's own virtual address layout. It does not affect user-space mmap
placement directly. What does affect user-space mapping addresses is ASLR
(`/proc/sys/kernel/randomize_va_space`, `mmap_min_addr`).

This library does not interact with KASLR. It notes KASLR only because the
mechanism is sometimes confused with user-space ASLR in system docs.

ASLR context: when the library injects a synthetic `mmap` failure, the kernel
never runs the mmap path, so no ASLR slot is consumed. If the test relies on
a deterministic address layout (e.g., `MAP_FIXED_NOREPLACE`), failures and
retries will not desynchronise the slot allocator.

---

## 13. PT_GNU_STACK and the Executable-Stack Guard

`PT_GNU_STACK` is a load-segment type in ELF PHDR that signals the desired
stack permission to the kernel's `load_elf_binary()`. If absent or set
`PF_X`, the loader maps the initial thread stack as `PROT_READ|PROT_WRITE|PROT_EXEC`.
If set `PF_R|PF_W` (non-executable), the stack mapping is `PROT_READ|PROT_WRITE`.

This is relevant here because:

1. `libchaos-memory.so` itself is built with `-z noexecstack` (standard hardening
   flag); its `PT_GNU_STACK` segment has `PF_R|PF_W`. That does not override the
   target executable's own `PT_GNU_STACK` setting.
2. If the target executable lacks `PT_GNU_STACK`, `load_elf_binary()` falls back
   to `READ_IMPLIES_EXEC` personality, which makes all mappings implicitly
   executable. In that scenario `mprotect(PROT_READ|PROT_WRITE)` effectively
   leaves the executable bit set because the personality flag overrides the
   protection. Injecting `mprotect:ERRNO:EACCES` in that environment will appear
   to have the correct observable (the application gets `EACCES`), but the
   background permission state is anomalous.
3. Build check: `readelf -l <target> | grep GNU_STACK` should show
   `RW` (non-executable). `libchaos-memory.so` does not enforce or check this on
   the target; it is a pre-deployment hygiene concern.

---

## 14. Reentrancy Guard and TLS State

### 14.1 The Problem

`libchaos-memory` interposes `mmap`, `munmap`, `mprotect`, and `madvise`. The
LATENCY path calls `nanosleep()` (via the cached `real_nanosleep` pointer), not
the interposed `nanosleep` in `libchaos-time`. But the config reload path calls
`open()`, `read()`, `fstat()` — all potentially interposed by `libchaos-io`. More
subtly, the reentrancy guard itself uses TLS (`__thread`), and TLS access on some
implementations calls `mmap` internally during thread-local storage setup.

### 14.2 Implementation

The guard is a `__thread int g_chaos_memory_tls_guard` per-thread flag:

```c
static inline int chaos_memory_enter_internal(void)
{
    int previous = g_chaos_memory_tls_guard;
    g_chaos_memory_tls_guard = 1;
    return previous;
}

static inline void chaos_memory_leave_internal(int previous)
{
    g_chaos_memory_tls_guard = previous;
}
```

Every interposed function calls `chaos_memory_enter_internal()` at entry and
`chaos_memory_leave_internal(previous)` at exit, including all early-exit paths.
If the guard is already set on entry, the wrapper skips all injection logic and
calls the real function immediately.

The guard restores `previous` rather than unconditionally writing 0, which means
nesting depth is tracked correctly: if `mmap` (wrapper) calls something that also
triggers the `mmap` wrapper (e.g., during TLS initialisation), the inner call
exits the guard at the same depth it found, not below it.

### 14.3 TLS Initialisation Race

On glibc, `__thread` variables that are not in the executable's TLS block may
require a call to `__tls_get_addr()` on first access per thread. For the initial
thread and for threads created before the library is loaded (rare in LD_PRELOAD
context), TLS is already set up. For threads created after preload, the first
access to `g_chaos_memory_tls_guard` triggers `__tls_get_addr()` in glibc (or
`__tls_get_addr` in musl), which does not call `mmap()` because the TLS segment
was already mapped when the DSO was loaded. This is safe.

On musl, `__tls_get_addr` is also safe in this respect; the dynamic TLS is
allocated via `__mmap` (musl's internal mmap alias, `SYS_mmap` syscall directly),
which bypasses the interposed `mmap` symbol.

---

## 15. PRNG Model

Probability-gated rules (`@probability`) use a per-thread xorshift64* PRNG
seeded from three independent sources:

```c
seed = g_chaos_memory_process_seed;   // set once at library load from /dev/urandom or time(NULL)
seed ^= chaos_memory_current_tid();   // SYS_gettid on Linux, getpid() on others
seed ^= (uint64_t)(uintptr_t)&seed;  // stack address (ASLR contribution)
g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed);
```

The mix function is Murmur3 finaliser / SplitMix64 round:

```c
static inline uint64_t chaos_memory_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value  = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value  = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return   value ^ (value >> 31);
}
```

Constants are from SplitMix64 (Steele & Vigna, "Fast Splittable Pseudorandom
Number Generators", OOPSLA 2014). The mixing property ensures that linearly
correlated seeds (e.g., TIDs differing by 1) produce uncorrelated states.

The per-step update is xorshift64 (Marsaglia 2003):

```c
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
```

The output multiplicative finaliser (`0x2545f4914f6cdd1d` is a GoldenRatio-based
multiplier) improves the lower-bit quality of the raw xorshift output. Period is
2^64 − 1 per thread; zero-state is avoided by the post-init check.

---

## 16. Config Reload Protocol — Two-Snapshot CAS

The config is reloaded on-demand, without a background thread, and without locks.
The protocol is a two-snapshot compare-and-swap on the file's mtime encoded as a
`uint64_t`.

### 16.1 State Machine

```
MTIME_MISSING  (0x0000...0000) — config file absent; use empty ruleset
MTIME_UNKNOWN  (0xffff...ffff) — initial sentinel; force first stat()
MTIME_RELOADING(0xffff...fffe) — reload CAS winner is active
<timestamp>                    — loaded and cached
```

### 16.2 Protocol Steps

1. `atomic_load(mtime_slot)` — read current state with `__sync_synchronize()`.
2. If current == `MTIME_RELOADING`, spin (another thread is loading); this
   is the only busy-wait point. In practice, config files are small (< 256 KB)
   and the parse is O(N lines) with N ≤ 256, so the spin is very short.
3. `stat(config_path, &st)` — get the file's mtime.
4. If mtime unchanged: done.
5. CAS(`mtime_slot`, old_value, `MTIME_RELOADING`):
   - Success → this thread is the reload winner; read+parse+swap.
   - Failure → another thread won; continue with existing config.
6. Read config, parse rules, build new `chaos_memory_config_t` snapshot.
7. Atomic store new snapshot pointer (two-pointer swap: the old pointer is
   overwritten; there is no epoch-based reclaim because the config is read
   only under the guard context and writes are infrequent).
8. CAS(`mtime_slot`, `MTIME_RELOADING`, new_mtime) — release the reload lock.

This is an RCU-flavored design without a formal RCU read-side critical section
or grace-period mechanism. It is safe because:
- Readers hold the TLS guard while accessing the config, preventing reentrancy
  during the check-and-call sequence.
- The config pointer swap is sequentially consistent (both sides issue
  `__sync_synchronize()` full barriers).
- The old config allocation is not freed (it leaks one struct per reload cycle).
  This is intentional and acceptable for a test-infrastructure library where config
  reloads are rare and process lifetime is bounded.

Reference: Paul McKenney, "Is Parallel Programming Hard?" §9 (RCU mechanics);
GCC `__sync_*` builtins documentation.

---

## 17. glibc vs musl Divergence

| Aspect                    | glibc (ptmalloc2)                          | musl (mallocng)                            |
|---------------------------|--------------------------------------------|--------------------------------------------|
| Small alloc path          | brk/sbrk arena (below MMAP_THRESHOLD)     | mmap/anon (all allocations via alloc_meta) |
| mmap threshold            | Adaptive; default 128 KiB; max 65536 mmaps| No threshold; always mmap                  |
| mmap/anon coverage        | Large allocs only                          | All allocs                                 |
| mremap usage              | Never in normal malloc                     | Never in mallocng                           |
| brk() usage               | Yes (via __brk syscall direct)             | No                                          |
| MAP_ANONYMOUS alias       | MAP_ANONYMOUS (0x20 on x86_64)             | Same                                        |
| execveat in libc          | Yes, glibc 2.34+ (syscall wrapper)         | Not always exported as public symbol        |
| madvise(MADV_FREE)        | glibc 2.30+ uses MADV_FREE in free()       | musl does not use MADV_FREE (MADV_DONTNEED) |
| mprotect on stack guard   | Called by pthread_create via libpthread    | Called by musl thread creation              |

**Key difference for injection:** On musl, `mmap/anon:ERRNO:ENOMEM` with even a
moderate probability will cause `malloc()` for any allocation size to fail, because
mallocng's meta-area allocation path calls `mmap()` for all size classes. On glibc,
the same rule only affects allocations ≥ 128 KiB (or whatever the current
`MMAP_THRESHOLD` is). Calibrate your probabilities accordingly.

---

## 18. Execution Boundary Summary

`libchaos-memory` operates at the libc contract boundary. It can reach any call
to `mmap()`, `munmap()`, `mprotect()`, or `madvise()` that travels through the
PLT of the target binary.

It does not reach:

- `brk()` / `sbrk()` heap operations inside glibc's ptmalloc2
- `mremap()` (not interposed)
- `mlock()` / `mlock2()` (not interposed)
- anonymous mmap calls made by the kernel itself (page fault handlers, stack
  growth)
- mmap calls issued via raw syscall number (`syscall(SYS_mmap, ...)`) — bypass
  surface identical to other preload libraries; see `docs/PLATFORM.md` §5
- mmap calls inside statically linked binaries

The library is process-local. Unrelated processes are not affected. Kernel VM
subsystem policy (page reclaim, compaction, OOM killer) is not affected.

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
