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

`libchaos-memory` fails or delays memory-mapping calls of a dynamically linked
process: an ERRNO rule makes `mmap` return `MAP_FAILED` (or `munmap`, `mprotect`,
`madvise` return `-1`) with the configured errno, without the real call; a LATENCY
rule delays the call. Rules live in `/tmp/.chaos-memory.conf`. This document
describes the implementation in `src/memory/`; repository-wide composition rules are
in [SYSTEM.md](SYSTEM.md), loader and symbol-resolution internals in
[PLATFORM.md](PLATFORM.md).

| | |
|---|---|
| Interposed | `mmap`, `munmap`, `mprotect`, `madvise`, `posix_madvise` (uses the `madvise` rules, returns the error number), and on 64-bit glibc `mmap64` (alias of the `mmap` wrapper; the JVM, Redis, nginx and MySQL bind to it) |
| Rule file | `/tmp/.chaos-memory.conf` |
| Status file | `/tmp/.chaos-memory.status` |
| Hits file | `/tmp/.chaos-memory.hits.<n>` |
| Effects | ERRNO, LATENCY (both with a probability) |
| Test gates | 100.00 % line coverage on `chaos_memory.c`, `chaos_memory_config.c`, `chaos_memory_actions.c`, `chaos_memory_hooks.c`; runtime probes on glibc and musl, amd64 and arm64 |

**Reach in LD_PRELOAD mode.** The wrappers see calls made through the exported
symbols. The C library's own mappings do not go through them: glibc and musl
`malloc`, thread-stack allocation in `pthread_create` and the dynamic loader call
C-library-internal entry points that bind inside libc or `ld.so`. A memory rule
therefore reaches mappings made by the application and by libraries that call the
exported `mmap` (the JVM's heap reservation, jemalloc and other allocators linked
into the program), not `malloc()` of the C library. SECCOMP mode (`chaos-init`)
filters the system calls themselves and sees every mapping, the loader's and
`malloc`'s included ([SECCOMP.md §5](SECCOMP.md#5-how-calls-map-to-the-libraries-operations)).

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

The `mmap` selectors classify a call by one bit of its `flags` argument:
`mmap/anon` when `MAP_ANONYMOUS` is set, `mmap/file` otherwise (§5). The table maps
the four classic mapping classes onto that split.

| Class | flags | Selector | Typical callers that reach the wrapper |
|---|---|---|---|
| Anonymous private | `MAP_PRIVATE \| MAP_ANONYMOUS` | `mmap/anon` | Runtime heaps (JVM heap and code cache reservation), allocators outside libc, guard regions (`PROT_NONE`) |
| Anonymous shared | `MAP_SHARED \| MAP_ANONYMOUS` | `mmap/anon` | Memory shared with children after `fork()` |
| File-backed private | `MAP_PRIVATE`, a file descriptor | `mmap/file` | Programs mapping files read-only or copy-on-write |
| File-backed shared | `MAP_SHARED`, a file descriptor | `mmap/file` | Memory-mapped files, POSIX shared memory (`shm_open` + `mmap`), device mappings |

The sharing flag and the descriptor are not inspected: `MAP_ANONYMOUS` alone
decides.

Mappings the wrapper does not see in LD_PRELOAD mode: ELF segments mapped by the
dynamic loader at start-up and on `dlopen()`, glibc and musl `malloc` (§2), thread
stacks and guard pages created by `pthread_create`, stack growth and other
kernel-internal mappings. Under SECCOMP mode the loader's and `malloc`'s mappings are
ordinary `mmap` system calls: an `mmap/file:ERRNO:ENOMEM` rule there stops a dynamic
program from loading (exit 127); narrow it with `@size`, `@first` or `@from`.

---

## 2. Allocator Linkage — ptmalloc2 and mallocng

### 2.1 glibc ptmalloc2

ptmalloc2 serves requests below `M_MMAP_THRESHOLD` (128 KiB by default, adjusted
dynamically by glibc unless set with `mallopt` or `MALLOC_MMAP_THRESHOLD_`) from
arenas grown with `brk`/`sbrk` (main arena) or arena mappings (other threads), and
requests at or above it with a dedicated anonymous mapping released by `munmap`.

All of these calls go through glibc's internal `__mmap`/`__munmap`/`__madvise`
aliases, which are bound inside libc and never through the exported symbols. In
LD_PRELOAD mode `mmap/anon:ERRNO:ENOMEM` therefore does **not** make `malloc()` fail,
for any size. To fail large glibc allocations, use SECCOMP mode, where the same rule
with `@size>131071` hits the dedicated mappings above the default threshold.

### 2.2 musl mallocng

musl's mallocng (musl 1.2.1 and later) maps its groups with its internal `__mmap`
and grows its metadata area with the `brk` system call, both invisible to the
exported symbols. As with glibc, memory rules in LD_PRELOAD mode do not reach musl's
`malloc()`; SECCOMP mode does, and since mallocng maps memory for small size classes
as well, an unrestricted `mmap/anon:ERRNO:ENOMEM` under SECCOMP mode fails a musl
program almost immediately. Use a low probability or `@size`.

### 2.3 Allocators that do reach the wrapper

An allocator linked into the program (jemalloc, tcmalloc, mimalloc) or a runtime
managing its own heap (the JVM) calls the exported `mmap`/`munmap`/`madvise`, so the
wrappers see those calls. This also happens during symbol resolution:
`dlsym` → `calloc` → jemalloc → `mmap` → libchaos-memory, which is why the wrapper
falls back to a raw system call while its own symbols are unresolved (§14).

### 2.4 Why brk/sbrk Is Not Interposed

- The C libraries' allocators never call the exported `brk`/`sbrk`: glibc uses its
  internal `__brk`/`__sbrk`, musl issues the system call directly. An interposed
  `brk` would see almost nothing.
- Failing a heap extension behind an allocator's back is not a clean fault: the
  allocator handles `brk` failure by falling back to `mmap`, so the observable effect
  is a different mapping pattern, not an allocation failure.

For heap exhaustion scenarios, use `mmap/anon` rules on the allocators that call the
exported `mmap` (§2.3), or SECCOMP mode for the C library's `malloc`.

---

## 3. DSL Grammar and Rule Semantics

### 3.1 Full ABNF (RFC 5234)

```abnf
line        = [ rule *( 1*WSP qualifier ) ] *WSP [ comment ] LF
rule        = *WSP selector *WSP ":" *WSP effect *WSP ":" *WSP value
selector    = "*" / "mmap" / "mmap/anon" / "mmap/file"
            / "munmap" / "mprotect" / "madvise"
effect      = "ERRNO" / "LATENCY"
value       = payload [ "@" probability ]     ; split at the last "@"; no blanks around "@"
payload     = errno-value / latency-ms        ; at most 255 bytes
errno-value = "ENOMEM" / "EINVAL" / "EACCES" / "EPERM" / "EBADF" / "ENODEV"
            / "EAGAIN" / "EFAULT" / "ENOSYS" / "ENFILE" / "EMFILE"
            / 1*DIGIT                          ; decimal, 1 .. 2147483647
latency-ms  = 1*DIGIT                          ; decimal, 0 .. 4294967295
probability = ( "0" [ "." 1*DIGIT ] ) / ( "1" [ "." 1*"0" ] )
qualifier   = "@first=" 1*18DIGIT / "@from=" 1*18DIGIT / "@until=" 1*18DIGIT
            / "@size>" 1*18DIGIT / "@size<" 1*18DIGIT
                                               ; @first > 0; @until > @from when both set
comment     = "#" *( VCHAR / WSP )
```

- The selector ends at the first `:`, the effect at the second; everything after it
  is the value.
- A blank before `@` turns the probability into a word starting with `@`, which is
  parsed as a qualifier and rejects the line: write `ENOMEM@0.05`, not
  `ENOMEM @0.05`.
- The probability is parsed without `strtod`, independent of `LC_NUMERIC`.
- Omitted probability: 1.0. Probability 0 parses and never fires.
- Limits: 256 rules (`CHAOS_MEMORY_MAX_RULES`), a file smaller than 262 144 bytes, no
  NUL byte. Any violation rejects the whole file (§16).

Examples:

```text
mmap/anon:ERRNO:ENOMEM@0.05          # 5 % of anonymous mappings fail
mmap/file:LATENCY:20                 # 20 ms on every file mapping
mprotect:ERRNO:EPERM                 # every mprotect fails
*:LATENCY:5@0.1                      # 10 % of all calls take 5 ms longer
mmap/anon:ERRNO:ENOMEM @size>1048575 # only mappings of 1 MiB and more
madvise:ERRNO:5                      # EIO by number (not in the name list)
```

### 3.2 Rule Precedence

For every call the wrapper selects **one LATENCY rule and one ERRNO rule
independently**:

1. Only rules of that effect whose selector matches the call are candidates.
2. Highest rank wins: `mmap/anon` and `mmap/file` (3) > `mmap`, `munmap`,
   `mprotect`, `madvise` (2) > `*` (1).
3. Equal rank: the longer selector text wins; equal text: the first rule in the file.
4. LATENCY is applied first, then ERRNO. Both can fire on the same call: the call
   is delayed and then fails.

Each selected rule fires when its `@from`/`@until` window is open, its `@size` gate
passes (the byte count is the `length` argument of all five functions), its
probability draw succeeds and its `@first` budget is not used up. A rule that fires
records a hit.

### 3.3 Effect Semantics per Symbol

| Selector | Calls | LATENCY | ERRNO result |
|---|---|---|---|
| `mmap` | `mmap`, `mmap64` | before the call | `MAP_FAILED`, `errno` set, nothing mapped |
| `mmap/anon` | `mmap` with `MAP_ANONYMOUS` | before the call | as `mmap` |
| `mmap/file` | `mmap` without `MAP_ANONYMOUS` | before the call | as `mmap` |
| `munmap` | `munmap` | before the call | `-1`, `errno` set; the mapping stays (§4.3) |
| `mprotect` | `mprotect` | before the call | `-1`, `errno` set; protection unchanged |
| `madvise` | `madvise` | before the call | `-1`, `errno` set; advice not given |
| `madvise` | `posix_madvise` | before the call | the error number returned, `errno` unchanged |
| `*` | all of the above | | |

No effect mutates arguments or results. A corrupted `mmap` result would be either an
address with no mapping (SIGSEGV on first access, not an error path) or a write into
live memory (undefined behaviour), so CORRUPT and OFFSET do not exist here.

### 3.4 Valid `errno` Values per Call

The parser accepts the 11 names in §3.1 and any positive decimal number; it does not
check whether the value is one the function can return. Use the values the Linux
man pages document, so the application's error handling is the one that runs in
production:

| Call | Documented errors | Not in the name list (write as number; Linux asm-generic numbering on amd64 and arm64) |
|---|---|---|
| `mmap` | `EACCES`, `EAGAIN`, `EBADF`, `EEXIST` (`MAP_FIXED_NOREPLACE`), `EINVAL`, `ENFILE`, `ENODEV`, `ENOMEM`, `EOVERFLOW`, `EPERM`, `ETXTBSY` | `EEXIST` 17, `EOVERFLOW` 75, `ETXTBSY` 26 |
| `munmap` | `EINVAL` | — |
| `mprotect` | `EACCES`, `EINVAL`, `ENOMEM` | — |
| `madvise` | `EACCES`, `EAGAIN`, `EBADF`, `EINVAL`, `EIO`, `ENOMEM`, `EPERM` | `EIO` 5 |

---

## 4. Per-Hook Call Flows

All five wrappers share one shape (`src/memory/chaos_memory_hooks.c`):

```text
wrapper entry
  ├─ chaos_memory_ensure_symbols()          resolve real functions once (chaos_once)
  ├─ guard set?  → real call, return        (the library's own work, §14)
  ├─ LATENCY: chaos_memory_config_match()   refresh snapshot (≤ 1 stat per ms), select
  │    rule found → apply_latency()         window, @size, probability, @first, then
  │                                         chaos_sleep_ms(): raw clock_nanosleep
  ├─ ERRNO: chaos_memory_config_match()
  │    rule found and fires → errno = errnum, return error value (no real call)
  └─ real call under the guard; while the real pointer is still NULL: raw syscall
```

The real call runs with the guard set, so any interposed call it makes internally
passes through untouched. While symbol resolution is still running on this thread
(re-entry from `dlsym`'s allocator, §2.3) the real pointer is NULL and the wrapper
issues `SYS_mmap`, `SYS_munmap`, `SYS_mprotect` or `SYS_madvise` directly.

### 4.1 `mmap()`

The `flags` word is passed to both matches, so `mmap/anon` and `mmap/file` are
decided per call (§5). ERRNO returns `MAP_FAILED` before any kernel work: no address
range is reserved.

### 4.2 `mprotect()`

The library never rewrites `prot`. Changing protection non-atomically would add a
window unrelated to the fault being tested.

### 4.3 `munmap()`

A synthetic failure returns `-1` and leaves the mapping in place, which is exactly
what the caller observes when the kernel rejects `munmap` (`EINVAL`). The library
does not track the leaked range; whether the application retries, aborts or leaks is
what the test observes.

### 4.4 `madvise()` and `posix_madvise()`

`madvise` is advisory: the kernel may ignore advice, and the library never changes
`advice`. `posix_madvise` matches the `madvise` rules (glibc and musl implement it
with the `madvise` system call, never through `madvise()`), returns an injected
error as its result and leaves `errno` unchanged. While its real pointer is NULL it
issues the system call itself and returns 0 for `POSIX_MADV_DONTNEED` without a call:
that value equals `MADV_DONTNEED`, which would discard pages, while POSIX only asks
for advice; glibc and musl ignore it the same way.

---

## 5. mmap/anon vs mmap/file Dispatch

The split is one bit test on the `flags` argument:

```c
static inline int chaos_memory_mmap_is_anonymous(int flags)
{
    return (flags & MAP_ANONYMOUS) != 0;
}
```

The library does not inspect:

- `fd` (callers pass `-1` with `MAP_ANONYMOUS`, but Linux ignores it either way);
- `offset`;
- private vs shared.

`MAP_ANONYMOUS` is `0x20` on amd64 and arm64. Platforms that spell it `MAP_ANON` are
normalised at the top of `chaos_memory_internal.h`:

```c
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
```

The library targets Linux; the shim only keeps the header compiling elsewhere.

---

## 6. Non-Coverage: brk/sbrk

Not interposed. The C libraries' allocators never call the exported symbols, and a
failed heap extension makes allocators fall back to `mmap` rather than fail (§2.4).

---

## 7. Non-Coverage: mremap

`mremap(2)` (Linux only) grows, shrinks or moves an existing mapping. It is not
interposed:

- A synthetic `mremap` failure is ambiguous with `MREMAP_MAYMOVE`/`MREMAP_FIXED`:
  whether the caller expects the old range to survive depends on flags the library
  would have to model.
- The scenario it serves, a mapping that cannot grow, is reachable by failing the
  `mmap` that would replace it.

Candidate for a future wrapper. Reference: `mremap(2)`.

---

## 8. Non-Coverage: mlock and mlock2

`mlock(2)`, `mlock2(2)` (Linux 4.4), `munlock(2)` and `mlockall(2)` are not
interposed. Their failure modes (`EAGAIN`, `ENOMEM`, `EPERM` once `RLIMIT_MEMLOCK` is
exhausted) are reproducible without a preload by lowering the limit (`ulimit -l 0`)
before the test.

---

## 9. madvise Hint Catalogue and Injection Surface

### 9.1 Advice values

The library passes `advice` through unchanged. The catalogue clarifies what a
synthetic failure means to the caller.

| Advice | Since | Semantics |
|---|---|---|
| `MADV_NORMAL`, `MADV_SEQUENTIAL`, `MADV_RANDOM`, `MADV_WILLNEED` | — (POSIX equivalents `POSIX_MADV_*`) | Read-ahead hints and prefetch |
| `MADV_DONTNEED` | — | Drop the pages now; private anonymous memory refaults zero-filled. `POSIX_MADV_DONTNEED` has the same number but is pure advice and ignored by glibc and musl |
| `MADV_REMOVE` | 2.6.16 | Free the range and its backing store (hole punch) |
| `MADV_DONTFORK`, `MADV_DOFORK` | 2.6.16 | Exclude from / include in a `fork()` child |
| `MADV_MERGEABLE`, `MADV_UNMERGEABLE` | 2.6.32 | Kernel samepage merging candidates |
| `MADV_HWPOISON` | 2.6.32 | Poison the pages as on a hardware error (`CAP_SYS_ADMIN`) |
| `MADV_SOFT_OFFLINE` | 2.6.33 | Migrate and offline the pages (`CAP_SYS_ADMIN`) |
| `MADV_HUGEPAGE`, `MADV_NOHUGEPAGE` | 2.6.38 | Allow / forbid transparent huge pages |
| `MADV_DONTDUMP`, `MADV_DODUMP` | 3.4 | Exclude from / include in core dumps |
| `MADV_FREE` | 4.5 | Pages may be reclaimed lazily under pressure |
| `MADV_COLD`, `MADV_PAGEOUT` | 5.4 | Deactivate / reclaim now |
| `MADV_POPULATE_READ`, `MADV_POPULATE_WRITE` | 5.14 | Prefault the range |

### 9.2 Injection surface

`madvise:ERRNO:EINVAL` (or `ENOMEM`, `EAGAIN`, ...) fails the call before the kernel
sees the advice. Useful for:

- prefetch hints (`MADV_WILLNEED`, `MADV_POPULATE_*`) whose failure must degrade to
  demand paging, not to an error;
- `MADV_DONTDUMP` failures in code that protects secrets (the advice was not applied,
  so the range stays in core dumps);
- `MADV_HUGEPAGE` refusals in code tuned for transparent huge pages;
- an application's or allocator's own `MADV_DONTNEED`/`MADV_FREE` calls on release
  (glibc's and musl's `free()` advise through internal calls the wrapper does not
  see, §2).

### 9.3 What madvise injection cannot reach

No partial-range failure (the whole call fails), no machine-check event for
`MADV_HWPOISON`, no simulation of delayed reclaim of `MADV_FREE` pages.

---

## 10. NUMA, mbind, and move_pages — Out of Scope

`mbind(2)`, `set_mempolicy(2)`, `get_mempolicy(2)` and `move_pages(2)` are not
interposed. Their failures (`EINVAL`, `EPERM` without `CAP_SYS_NICE`, `EIO` from
`move_pages`) describe NUMA topology and privileges rather than application error
paths, and a policy change on an existing mapping does not feed back into the `mmap`
that created it.

---

## 11. MAP_HUGETLB and Transparent Hugepages

### 11.1 Explicit huge pages (MAP_HUGETLB)

`MAP_HUGETLB` (Linux 2.6.32) takes pages from the preallocated HugeTLB pool
(`/proc/sys/vm/nr_hugepages`); `MAP_HUGE_2MB`/`MAP_HUGE_1GB` (Linux 3.8) select the
size. An anonymous huge-page mapping sets `MAP_ANONYMOUS | MAP_HUGETLB` and matches
`mmap/anon`; a mapping of a file on hugetlbfs matches `mmap/file`. No separate
selector exists; `@size` separates large requests.

### 11.2 Transparent huge pages

THP use is steered per range with `madvise(MADV_HUGEPAGE)` and system-wide by
`/sys/kernel/mm/transparent_hugepage/enabled`. `madvise:ERRNO:EINVAL` simulates a
rejected hint. Promotion, demotion and compaction are kernel-internal and beyond the
preload boundary.

---

## 12. KASLR Interaction

KASLR (`CONFIG_RANDOMIZE_BASE`) randomises the kernel's own layout and has no effect
on user mappings. User-space placement is governed by ASLR
(`/proc/sys/kernel/randomize_va_space`) and `vm.mmap_min_addr`. A synthetic `mmap`
failure never reaches the kernel, so no address range is consumed and a retry sees
the same address space as the failed call would have.

---

## 13. PT_GNU_STACK and the Executable-Stack Guard

`PT_GNU_STACK` in an executable's program headers tells the kernel whether the
initial stack must be executable. The library neither inspects nor changes it, and
the `mprotect` wrapper never alters `prot`. Where the kernel adds `PROT_EXEC` on its
own (the `READ_IMPLIES_EXEC` personality of binaries without `PT_GNU_STACK`), an
injected `mprotect` error is still exactly the configured errno; only the protection
the real call would have produced differs. Check a target with
`readelf -lW <binary> | grep GNU_STACK`.

---

## 14. Reentrancy Guard and TLS State

This section describes the mechanism every `libchaos-<lib>` library uses; only the
names differ.

### 14.1 The problem

The library's own work calls functions that are interposed, by this library or by
others preloaded with it: `stat()`, `open()` and `read()` of the rule file (all
interposed by libchaos-io), the real `mmap` (which another preloaded library may
wrap again), and symbol resolution (`dlsym` may allocate, and an allocator may call
`mmap`). Without a guard those calls would be faulted or would recurse.

### 14.2 Implementation

```c
extern __thread int g_chaos_memory_tls_guard;

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

- Every wrapper tests the guard after `chaos_memory_ensure_symbols()`; when set it
  forwards to the real function with no rule lookup.
- The guard is set around each real call (the `chaos_memory_call_real_*`
  trampolines), around `stat()` of the rule file, around its `open`/`read`/`fstat`
  loop, and around the raw seed read in the constructor.
- Save and restore, not increment and clear: a nested section restores the state it
  found, so leaving an inner section never clears an outer one.
- The LATENCY sleep is a raw `clock_nanosleep` system call
  (`src/common/chaos_sleep.h`) and needs no guard: no interposed symbol is entered,
  and libchaos-time cannot shorten or lengthen the delay.

### 14.3 TLS placement

The library is loaded at process start by `LD_PRELOAD`, so its TLS is part of the
static TLS block the C library allocates with every thread; reading or writing the
guard never maps memory. TLS is deliberately tiny (the guard, an `int`, and the PRNG state, a
`uint64_t`): static TLS is reserved in every thread and counts against its minimum stack
size, and large objects there made runtimes with small explicit thread stacks (the
Erlang VM) fail `pthread_create` with `EINVAL`. The 256 KiB rule-file buffer is
therefore a process-wide static, used only by the thread that owns a reload.

### 14.4 Symbol resolution re-entry

`chaos_memory_ensure_symbols()` runs `chaos_memory_resolve_all_symbols()` once
through `chaos_once()` (release/acquire, no libpthread dependency). A call that
re-enters on the resolving thread (`dlsym` → allocator → `mmap`) returns from
`chaos_once()` at once instead of deadlocking; the real pointer is still NULL and the
trampoline issues the raw system call. A missing symbol (`dlsym` NULL with `dlerror()`
set) calls `abort()`.

---

## 15. PRNG Model

Shared by all libraries. Each thread owns an xorshift64* generator; probability
draws need no synchronisation and threads never share a sequence.

**Process seed.** The constructor reads 8 bytes from `/dev/urandom` with raw
`SYS_openat`/`SYS_read`/`SYS_close` (no interposed call during construction),
`errno` preserved. Fallback when that fails: `0x6a09e667f3bcc909 ^ getpid()`. The
main thread is seeded directly from the process seed.

**Lazy per-thread seed** on a thread's first draw:

```c
seed  = g_chaos_memory_process_seed;
seed ^= chaos_memory_current_tid();      /* SYS_gettid on Linux */
seed ^= (uint64_t)(uintptr_t)&seed;      /* stack address */
g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed) | 1U;  /* never 0 */
```

`chaos_memory_prng_mix()` is the SplitMix64 finaliser (Steele, Lea, Flood, OOPSLA
2014): consecutive thread ids yield uncorrelated states. Forcing the low bit keeps
the state out of 0, the one state xorshift cannot leave.

**Step and output:**

```c
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
```

xorshift64 (Marsaglia, 2003) with the multiplicative output scrambler of xorshift64*
(Vigna, 2016); period 2^64 − 1. Every probability check consumes one draw and fires
when `sample < p × 2^32`; `p <= 0` never fires, `p >= 1` always fires.

**fork.** The atfork child handler zeroes the forking thread's state, so the child
reseeds from its own thread id on its next draw; pre-fork workers would otherwise
make identical decisions.

---

## 16. Config Reload Protocol — Two-Snapshot CAS

Shared by all libraries (libchaos-io adds link re-resolution, see
[IO.md §4](IO.md#4-end-to-end-behavior)). No thread, no lock, no allocation.

### 16.1 State

- Two statically allocated snapshots of 256 rules each, with the rule texts and hit
  slot pointers; an active index (0 or 1).
- A cached change stamp that doubles as the reload lock:

```text
MTIME_MISSING   (0x0000000000000000)  no rule file: no rules
MTIME_UNKNOWN   (0xffffffffffffffff)  initial: the first look always loads
MTIME_RELOADING (0xfffffffffffffffe)  a thread owns the reload
<stamp>                               FNV-1a over mtime s, mtime ns, size, inode, device
```

A real stamp equal to `UNKNOWN` or `RELOADING` is decremented by one.

### 16.2 Protocol

1. **Throttle.** Once rules are loaded, the file is looked at no more than every
   1 ms (`CHAOS_CHECK_INTERVAL_NS`, vDSO `CLOCK_MONOTONIC`). The first load, and
   every call while no rules are loaded, always looks. Without a vDSO clock every
   call looks.
2. `stat()` the file (guard set) and compute the stamp. Mtime alone misses two writes
   within one filesystem clock tick; size catches an append, inode a rename-over
   (`sed -i`).
3. Stamp unchanged and the last load not provisional: use the active snapshot.
4. Cached stamp is `RELOADING`: another thread is loading; use the active snapshot.
   Nobody waits or spins.
5. CAS cached stamp → `RELOADING`. Losers use the active snapshot.
6. The winner rewrites the inactive snapshot (its sequence counter is odd meanwhile),
   reads the file into the process-wide buffer, verifies with `fstat()` that the file
   still has the stamp that triggered the load (a writer that changed it mid-read
   makes the copy unusable: the claim is released with the previous stamp and the
   next look retries), parses, attaches hit slots (a rule whose text is unchanged
   keeps its slot, so its count and `@first` claims survive the reload), and writes
   the status file.
7. Publish: sequence even, full barrier, active index, full barrier, cached stamp.
8. A file whose mtime is within 20 ms of now (`CHAOS_RACY_WINDOW_MS`) is loaded
   provisionally and read again on the next look until it is older, because a
   same-size rewrite within one tick leaves every stat field unchanged. A re-read
   with identical content keeps the snapshot and its counters.

**Readers** copy the selected rule out of the active snapshot and check its sequence
before and after (a seqlock). Two reloads later the same snapshot is rewritten; a
reader preempted in the middle of its copy sees the sequence change and discards the
copy (the call passes through) instead of using half of one rule and half of
another. Nothing is ever freed, so there is nothing to reclaim.

All atomics are GCC `__sync_*` builtins with full barriers.

### 16.3 Failure behaviour

| Condition | Result | Status file |
|---|---|---|
| No rule file | no rules | removed |
| Invalid line, malformed qualifier, qualifier without a rule | no rules (previous rules dropped) | `state=error`, `reason=invalid rule`, `line`, `text` |
| More than 256 rules | no rules | `reason=too many rules` |
| 262 144 bytes or more | no rules | `reason=file too large`, `line=0` |
| `open` fails with `EACCES`/`EPERM`, `read` with `EISDIR` | no rules until the file changes | `reason=file unreadable`, `line=0` |
| NUL byte | no rules | `reason=file contains a NUL byte` |
| Other read error, file changed mid-read | active snapshot kept, retried | unchanged |

The constructor loads the file immediately, so a bad file is reported at start-up.
Every refresh saves and restores `errno`.

### 16.4 fork and vfork

The `pthread_atfork` child handler releases a reload claim held by a parent thread
that does not exist in the child, clears the hits writer state, resets hit counts and
`@first` claims, and gives the child its own hits file. `vfork` children and
`posix_spawn` run no handler: they share the parent's memory, see its claim as busy
and never write a hits file.

Reference: GCC `__sync` builtins documentation; Linux `Documentation/RCU/whatisRCU.rst`
for the publish-then-switch pattern.

---

## 17. glibc vs musl Divergence

| Aspect | glibc | musl |
|---|---|---|
| `mmap64` | separate exported symbol on 64-bit; wrapped as an alias | does not exist |
| `malloc` mappings | internal `__mmap`/`__munmap`/`__madvise`: not seen in LD_PRELOAD mode | internal `__mmap` and the `brk` system call: not seen in LD_PRELOAD mode |
| Small allocations | `brk` heap below `M_MMAP_THRESHOLD` (128 KiB default) | mallocng groups, mapped for small size classes too |
| `posix_madvise` | implemented with the `madvise` system call; `POSIX_MADV_DONTNEED` ignored | same |
| `MAP_ANONYMOUS` | `0x20` | `0x20` |

Consequence for SECCOMP mode, where `malloc`'s mappings are visible: an
`mmap/anon:ERRNO:ENOMEM` rule fails musl programs on small allocations too, glibc
programs mainly on allocations at or above the threshold. Calibrate
probability and `@size` per libc.

---

## 18. Execution Boundary Summary

`libchaos-memory` operates at the exported-symbol boundary of the C library. It
reaches every call to `mmap`, `mmap64` (glibc), `munmap`, `mprotect`, `madvise` and
`posix_madvise` that binds to the exported symbol.

It does not reach, in LD_PRELOAD mode:

- the C library's own mappings: `malloc`/`free`, thread stacks, the dynamic loader;
- `brk`/`sbrk`, `mremap`, `mlock*`, NUMA policy calls (not interposed);
- raw `syscall(SYS_mmap, ...)`, statically linked binaries, kernel-internal mappings
  (page faults, stack growth).

SECCOMP mode (`chaos-init`) applies the same rule file to the `mmap`, `munmap`,
`mprotect` and `madvise` system calls of every process it supervises, with ERRNO and
LATENCY on every selector, and therefore reaches the loader and `malloc` as well
([SECCOMP.md](SECCOMP.md)).

The library is process-local: other processes and kernel memory policy (reclaim,
compaction, the OOM killer) are unaffected.

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
