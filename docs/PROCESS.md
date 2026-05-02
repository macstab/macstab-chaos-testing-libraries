<!--
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Engineered by  Christian Schnapka
                 Embedded Principal+ Engineer
                 Macstab GmbH · Hamburg, Germany
                 https://macstab.com
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
-->

# libchaos-process Technical Reference

> *Engineered by* **[Christian Schnapka](https://macstab.com)** — Embedded Principal+ Engineer · [Macstab GmbH](https://macstab.com) · Hamburg, Germany

---

`libchaos-process` is the dedicated process-lifecycle preload library in this
repository. Repository-wide ownership and composition rules live in
[`docs/SYSTEM.md`](SYSTEM.md). Platform-layer internals (ELF link-map ordering,
PLT/GOT cold/hot paths, AT_SECURE, glibc/musl matrix) are in
[`docs/PLATFORM.md`](PLATFORM.md).

Current implementation status:

- interposed symbols: `pthread_create()`, `fork()`, `posix_spawn()`,
  `posix_spawnp()`, `execve()`, `execveat()`, `waitpid()`
- config path: `/tmp/.chaos-process.conf`
- unit-tested; strict `100.00%` line coverage gate on `src/process/*.c`
- runtime probe implemented for glibc/musl and amd64/arm64 validation

---

## Table of Contents

1. [clone(2) Flag Taxonomy](#1-clone2-flag-taxonomy)
2. [pthread_create Internal Flow](#2-pthread_create-internal-flow)
3. [fork() Mechanics and CoW Semantics](#3-fork-mechanics-and-cow-semantics)
4. [posix_spawn: glibc vs musl Divergence](#4-posix_spawn-glibc-vs-musl-divergence)
5. [vfork Hazards and Non-Coverage](#5-vfork-hazards-and-non-coverage)
6. [execve, execveat, and the exec Family Matrix](#6-execve-execveat-and-the-exec-family-matrix)
7. [waitpid, waitid, and the wait Family Gap](#7-waitpid-waitid-and-the-wait-family-gap)
8. [EINTR Contract per POSIX.1-2017 §2.4.3](#8-eintr-contract-per-posix1-2017-243)
9. [FAIL_AFTER Semantics and Counter Implementation](#9-fail_after-semantics-and-counter-implementation)
10. [DSL Grammar and Rule Semantics](#10-dsl-grammar-and-rule-semantics)
11. [Per-Hook Call Flows](#11-per-hook-call-flows)
12. [Reentrancy Guard and TLS State](#12-reentrancy-guard-and-tls-state)
13. [PRNG Model](#13-prng-model)
14. [Config Reload Protocol](#14-config-reload-protocol)
15. [Non-Coverage: clone/clone3, vfork, kill, pthread_kill, waitid](#15-non-coverage-cloneclone3-vfork-kill-pthread_kill-waitid)
16. [glibc vs musl Divergence per Symbol](#16-glibc-vs-musl-divergence-per-symbol)
17. [Execution Boundary Summary](#17-execution-boundary-summary)

---

## 1. clone(2) Flag Taxonomy

`clone(2)` is the Linux primitive underlying all process and thread creation.
`fork()`, `pthread_create()`, `posix_spawn()`, and `vfork()` are all libc wrappers
that call `clone()` (or `clone3()`, Linux 5.3+) with specific flag combinations.
Understanding these flags is prerequisite to understanding what each wrapper
interposition intercepts and what it does not.

### 1.1 Key clone Flags

| Flag                  | Hex       | Meaning                                                                   |
|-----------------------|-----------|---------------------------------------------------------------------------|
| `CLONE_VM`            | 0x00000100| Share virtual memory (thread semantics)                                    |
| `CLONE_FS`            | 0x00000200| Share filesystem state (cwd, umask, root)                                  |
| `CLONE_FILES`         | 0x00000400| Share file descriptor table                                                |
| `CLONE_SIGHAND`       | 0x00000800| Share signal handlers                                                      |
| `CLONE_PIDFD`         | 0x00001000| Return pidfd instead of pid (Linux 5.2)                                    |
| `CLONE_PTRACE`        | 0x00002000| Attach ptrace to child                                                     |
| `CLONE_VFORK`         | 0x00004000| Parent blocked until child calls exec/exit (vfork semantics)               |
| `CLONE_PARENT`        | 0x00008000| New task is a sibling not a child                                          |
| `CLONE_THREAD`        | 0x00010000| Thread in same thread group (NPTL)                                         |
| `CLONE_NEWNS`         | 0x00020000| New mount namespace                                                        |
| `CLONE_SYSVSEM`       | 0x00040000| Share SysV semaphore undo values                                           |
| `CLONE_SETTLS`        | 0x00080000| Set TLS segment (arg5 is `struct user_desc` on x86 or tls_ptr on others)  |
| `CLONE_PARENT_SETTID` | 0x00100000| Store child TID in parent's memory before wakeup                          |
| `CLONE_CHILD_CLEARTID`| 0x00200000| Zero child TID on exit; wake futex (NPTL thread join)                     |
| `CLONE_CHILD_SETTID`  | 0x01000000| Store child TID in child's own memory                                     |
| `CLONE_NEWCGROUP`     | 0x02000000| New cgroup namespace (Linux 4.6)                                          |
| `CLONE_NEWUTS`        | 0x04000000| New UTS (hostname/domainname) namespace                                    |
| `CLONE_NEWIPC`        | 0x08000000| New IPC namespace                                                          |
| `CLONE_NEWUSER`       | 0x10000000| New user namespace                                                         |
| `CLONE_NEWPID`        | 0x20000000| New PID namespace                                                          |
| `CLONE_NEWNET`        | 0x40000000| New network namespace                                                      |
| `CLONE_IO`            | 0x80000000| Share I/O context                                                          |

### 1.2 Flag Combinations by API

| API              | Effective clone flags (dominant path)                                         |
|------------------|-------------------------------------------------------------------------------|
| `fork()`         | `SIGCHLD` only (copy everything, POSIX process semantics)                    |
| `vfork()`        | `CLONE_VFORK \| CLONE_VM \| SIGCHLD`                                          |
| `pthread_create` | `CLONE_VM \| CLONE_FS \| CLONE_FILES \| CLONE_SIGHAND \| CLONE_THREAD \| CLONE_SYSVSEM \| CLONE_SETTLS \| CLONE_PARENT_SETTID \| CLONE_CHILD_CLEARTID \| CLONE_DETACHED \| SIGCHLD` (glibc NPTL) |
| `posix_spawn`    | glibc: `CLONE_VFORK \| CLONE_VM \| SIGCHLD` then `execve`. musl: `fork()`+`execve`. |

Note that `clone3()` (Linux 5.3+) consolidates these via a `struct clone_args`
struct rather than a flags word, adding `exit_signal`, `stack_size`, and pidfd
semantics. glibc 2.35+ uses `clone3` for `pthread_create` when the kernel
supports it. The observable libc-symbol interface (`pthread_create`) is identical
regardless.

Reference: `clone(2)` Linux man-pages; NPTL source glibc `nptl/pthread_create.c`;
Ulrich Drepper, "The Native POSIX Thread Library for Linux" (2003).

---

## 2. pthread_create Internal Flow

glibc NPTL's `pthread_create()` (glibc source: `nptl/pthread_create.c`):

```
pthread_create(thread, attr, start_routine, arg)
  ├─ __pthread_create_2_1()              (versioned symbol @@GLIBC_2.1)
  ├─ allocate_stack()                    allocates thread stack + guard via mmap
  │    ├─ mmap(NULL, stacksize, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
  │    └─ mprotect(guard_page, PROT_NONE)  installs stack guard
  ├─ _dl_allocate_tls()                  allocates TLS for new thread
  ├─ clone(clone_flags, stack_top, ...)  creates the kernel task
  │    clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
  │                  CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
  │                  CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD
  ├─ (child) thread_start()
  │    └─ start_routine(arg)
  └─ return 0 on success, error number on failure
```

**Injection point:** `libchaos-process` intercepts `pthread_create()` at the
PLT entry. The wrapper fires before `allocate_stack()` runs. A synthetic failure
at this point prevents the `mmap()` for the stack from being called, so there is
no stack-allocation-then-abandon scenario.

**Return convention:** On failure, `pthread_create()` returns the positive error
number directly. It does not set `errno`. Callers that check `errno` instead of
the return value are buggy under POSIX.1-2017 §2.9.1. The library matches this
convention: synthetic failure returns the configured error number, not -1.

**Cascade observation:** Because `pthread_create` internally calls `mmap` (for the
stack), if `libchaos-memory` is also loaded and `mmap/anon:ERRNO:ENOMEM` fires
during `allocate_stack()`, the failure will surface as `ENOMEM` from the real
`pthread_create()` — not from the `libchaos-process` wrapper. Both injection
points are valid but produce failures at different depths.

---

## 3. fork() Mechanics and CoW Semantics

`fork(2)` creates an exact copy of the calling process. The Linux kernel
implementation (`kernel/fork.c`, `copy_process()`) performs:

1. Allocates new `task_struct`.
2. Copies (CoW) all VMAs via `copy_mm()` → `dup_mm()` → `copy_page_range()`.
   Each writable VMA becomes CoW on both parent and child; actual page copies
   are deferred to first write (demand paging).
3. Copies file descriptor table via `copy_files()`.
4. Copies signal handlers via `copy_sighand()`.
5. Sets child's PID, PPID, PGID.
6. Returns child PID to parent, 0 to child.

**glibc implementation:** glibc wraps `clone(SIGCHLD, ...)` and then calls
`_dl_fork_*` callbacks and the `pthread_atfork` handlers in the correct order
(prefork handlers in reverse registration order, postfork-parent and
postfork-child in forward order).

**NPTL fork-safety:** glibc 2.3+ acquires a set of internal locks before calling
clone (malloc lock, IO lock, resolver lock) to ensure the child inherits a
consistent allocator state. These locks are released in the `_dl_fork_*` path.
A synthetic fork failure (`fork:ERRNO:EAGAIN`) fired before the real `clone()`
call means those locks are never acquired or released in the abnormal path — which
is the intended observable (the application's fork-failure path is exercised).

**Injection point:** `libchaos-process` wraps `fork()`. The wrapper fires before
any glibc-internal lock acquisition. Synthetic failure returns -1 + `errno`.

---

## 4. posix_spawn: glibc vs musl Divergence

`posix_spawn(3)` (POSIX.1-2001) spawns a new process from a file path with
optional file-action and attribute configuration.

### 4.1 glibc Implementation

glibc 2.24+ implements `posix_spawn` as:

```
posix_spawn(pid, path, file_actions, attrp, argv, envp)
  ├─ clone(CLONE_VM | CLONE_VFORK | SIGCHLD, ...)   // vfork semantics
  ├─ (child) apply file_actions                      // dup2, close, open
  ├─ (child) apply attrp                             // sched, sigmask, pgroup
  ├─ (child) execve(path, argv, envp)
  └─ (parent) unblocked when child execs or exits
```

The `CLONE_VFORK | CLONE_VM` combination means the parent's address space is
shared (not copied) and the parent is blocked. The child must not use the parent's
heap before `execve` — only async-signal-safe functions (POSIX.1-2017 §2.4.3
Table 2-2) are allowed in the interstitial window. glibc uses only direct
syscalls in this window.

Reference: glibc `sysdeps/unix/sysv/linux/spawni.c`, `__spawnix()`.

### 4.2 musl Implementation

musl implements `posix_spawn` via a straightforward `fork()` + `execve()` path
(musl `src/process/posix_spawn.c`, `__posix_spawnx()`). No `CLONE_VFORK` is
used. The child uses an `execfd` from `open()` to avoid path re-lookup.

Consequence for injection:

- **glibc:** Injecting `posix_spawn:ERRNO:ENOENT` fails at the wrapper entry
  (before clone). The vfork window never opens.
- **musl:** Same; the wrapper entry is before `fork()`. The real `fork()` is never
  called.
- **Cascade:** If `libchaos-process` is loaded without injecting `posix_spawn`
  but `fork:ERRNO:EAGAIN` is active, the glibc path (using `clone` directly, not
  `fork()`) is **not** affected because glibc's `posix_spawn` does not call the
  libc `fork()` symbol — it calls `clone()` directly. musl's path **is** affected
  because it calls `fork()`.

This is a material semantic difference between glibc and musl for multi-rule
configs. The DSL does not currently model this cross-symbol cascade. Document your
target libc when using simultaneous `fork` + `posix_spawn` rules.

### 4.3 posix_spawnp

`posix_spawnp` differs only in path-search semantics (searches `PATH`, analogous
to `execvp`). The glibc and musl implementation paths are identical to
`posix_spawn` except the path-resolution step. The library wraps both symbols
independently; rules for `posix_spawn` do not match `posix_spawnp` calls and
vice versa.

---

## 5. vfork Hazards and Non-Coverage

`vfork(2)` is a POSIX-deprecated mechanism (withdrawn in POSIX.1-2008, restored
informatively in POSIX.1-2018 as "an obsolescent feature"). It uses `CLONE_VFORK |
CLONE_VM`: the parent is suspended and shares the child's address space until the
child calls `execve()` or `_exit()`.

**Why not interposed:**

1. The window between `vfork()` return in the child and `execve()`/`_exit()` is
   subject to async-signal-safe requirements. Installing a LATENCY hook (which
   calls `nanosleep()`) in that window violates the safety contract.
2. Any heap access in the child before `exec` corrupts the parent's heap because
   the address space is shared (no CoW). The wrapper itself would allocate on
   the heap (config check, rule match) and corrupt the parent.
3. Modern code should use `posix_spawn` (which is properly interposed here) or
   `clone(CLONE_VFORK|CLONE_VM)` directly. `vfork()` is a historical artefact.

If you need to test the `posix_spawn` vfork-clone path on glibc, use the
`posix_spawn` selector. The wrapper fires before the clone, not inside the
vfork window.

---

## 6. execve, execveat, and the exec Family Matrix

### 6.1 exec Family

POSIX.1-2017 specifies a family of `exec*` functions; all are libc wrappers that
eventually call `execve(2)` or `execveat(2)`:

| Symbol          | Path search | argv/envp   | Libc wrapper → syscall      |
|-----------------|-------------|-------------|-----------------------------|
| `execl`         | No          | varargs     | → `execve`                  |
| `execv`         | No          | `char*[]`   | → `execve`                  |
| `execle`        | No          | varargs+env | → `execve`                  |
| `execve`        | No          | `char*[]`+env| syscall directly            |
| `execlp`        | PATH        | varargs     | → `execvp` → `execve`       |
| `execvp`        | PATH        | `char*[]`   | → `execve`                  |
| `execvpe`       | PATH        | `char*[]`+env| GNU extension → `execvp`   |
| `fexecve`       | fd          | `char*[]`+env| → `execveat` (Linux 3.19+) |
| `execveat`      | dirfd+path  | `char*[]`+env| syscall (Linux 3.19+)      |

`libchaos-process` intercepts `execve` and `execveat` at the PLT. The other
variants (`execl`, `execlp`, `execvp`, `fexecve`) all call through `execve` or
`execveat` via the PLT, so they are covered transitively.

### 6.2 execveat Portability

`execveat(2)` (Linux 3.19+, glibc 2.34+ wrapper) allows executing relative to
a directory fd. It is not in POSIX.1-2017. Musl does not always export it as a
named public libc symbol (musl versions before the explicit wrapper integration);
in those cases the library falls back to `ENOSYS` if the wrapper is somehow
called:

```c
// From chaos_process_hooks.c:
if (g_chaos_process_real_execveat == NULL) {
    errno = ENOSYS;
    return -1;
}
```

In practice, code that needs `execveat` and is running on a musl environment that
doesn't export it will fail to link or will call the syscall directly — bypassing
the interposition surface. The guard avoids a NULL dereference.

### 6.3 exec After Synthetic Failure

`execve()` and `execveat()` replace the calling process image on success. A
synthetic failure (`execve:ERRNO:EACCES`) returns -1 to the caller without
calling the real `execve()`. The process image is therefore not replaced. This
models the scenario "exec was denied by the kernel" — the correct chaos for
testing privilege-checking or sandbox-escape resistance logic.

The library does not fabricate a successful image replacement. There is no
"fake exec succeeded but we're still running the old image" semantics — that would
require a ptrace-level intercept.

---

## 7. waitpid, waitid, and the wait Family Gap

### 7.1 The wait Family

| Symbol    | POSIX       | Returns          | Status info                  | idtype_t support   |
|-----------|-------------|------------------|------------------------------|--------------------|
| `wait`    | POSIX       | pid_t            | `int *status`                | only children      |
| `waitpid` | POSIX       | pid_t            | `int *status` + options      | specific pid/group |
| `waitid`  | POSIX.1-2001| 0                | `siginfo_t *infop` (richer)  | P_PID/P_PGID/P_ALL |
| `wait3`   | BSD         | pid_t            | `int *status` + rusage       | only children      |
| `wait4`   | BSD/Linux   | pid_t            | `int *status` + pid + rusage | specific pid       |

`libchaos-process` intercepts `waitpid()` only. `wait()`, `waitid()`, `wait3()`,
`wait4()` are not currently interposed.

### 7.2 waitid Gap

`waitid(2)` (POSIX.1-2001, Linux 2.6.9) provides richer status via `siginfo_t`:
`si_code` (CLD_EXITED / CLD_KILLED / CLD_DUMPED / CLD_STOPPED / CLD_TRAPPED /
CLD_CONTINUED), `si_status` (exit code or signal number), `si_pid`, `si_uid`,
`si_utime`, `si_stime`. It also supports `WNOWAIT` (peek without consuming the
state) and `P_PIDFD` (Linux 5.4+, wait by pidfd).

Applications using `waitid` in preference to `waitpid` (more portable status
detail, `P_PIDFD` support) are not covered by the current interposition surface.
This is a known gap; see §15.

### 7.3 EINTR on waitpid

`waitpid` with `options = 0` blocks until a child changes state. A signal
delivered during the wait causes the kernel to return `EINTR`. POSIX.1-2017
§2.4.3 mandates that SA_RESTART-flagged signals cause automatic restart unless
the signal disposition specifies `SA_INTERRUPT`. See §8 for the full EINTR contract.

`waitpid:ERRNO:EINTR` injects this observable: the call returns -1 with
`errno = EINTR` without actually waiting for a child. The process still has
children that it must eventually wait for; failing to wait after an injected EINTR
will eventually cause zombie accumulation. Test code must either retry or use
`WNOHANG`.

---

## 8. EINTR Contract per POSIX.1-2017 §2.4.3

POSIX.1-2017 §2.4.3 "Signal Actions" specifies the interaction between signals
and blocking functions. This is the most commonly misunderstood aspect of EINTR
injection.

### 8.1 The Restartable / Non-Restartable Split

A blocking syscall interrupted by a signal may:

1. Return `EINTR` — the function was interrupted and the application must retry.
2. Be automatically restarted by the kernel if `SA_RESTART` was set when the
   signal handler was installed (Linux: `sigaction(2)` with `SA_RESTART`).

Not all syscalls are restartable. POSIX.1-2017 Table 2-6 lists which are.
Relevant to this library:

| Function      | SA_RESTART effect  | Notes                                              |
|---------------|--------------------|----------------------------------------------------|
| `waitpid`     | Restarted          | Unless `WNOHANG` is set                            |
| `nanosleep`   | NOT restarted      | Always returns EINTR; remaining time in *rem       |
| `fork`        | Not applicable     | Does not block                                     |
| `pthread_create` | Not applicable  | Does not block in the library sense                |

### 8.2 Consequence for Injection

When the library injects `EINTR` on `waitpid`, it bypasses the kernel's
`SA_RESTART` logic — there is no real signal, so SA_RESTART never fires. The
application sees `EINTR` unconditionally regardless of its signal disposition.
This is the correct chaos: it tests the application's EINTR-handling code path,
which is exercised only when `SA_RESTART` is not set or when the signal is
non-restartable.

When injecting `waitpid:ERRNO:EINTR@0.1`, 10% of waitpid calls will return `EINTR`
even if the application installed all handlers with `SA_RESTART`. This reveals
code that relies on SA_RESTART to silently swallow EINTR without any
application-level retry loop — a latent bug that becomes visible only on certain
signal-delivery races in production.

### 8.3 nanosleep EINTR Handling

From the POSIX.1-2017 §2.4.3 contract and the `nanosleep(2)` man-page:

> If `nanosleep()` is interrupted by a signal, it shall return a value of -1 and
> set errno to EINTR. The `*rem` argument shall be updated to contain the amount
> of time remaining.

The library models "interrupted before any sleep elapsed":

```c
if (remaining != NULL) {
    *remaining = *requested;   // full requested interval returned as remaining
}
errno = EINTR;
return -1;
```

This is the correct conservative model for injection before the real call runs.
The application's retry loop should re-issue `nanosleep(remaining, &remaining)`,
which is standard POSIX idiom.

---

## 9. FAIL_AFTER Semantics and Counter Implementation

`FAIL_AFTER:EAGAIN,N` allows the first `N` calls to succeed, then fails subsequent
calls with the configured error. This models resource exhaustion: a thread pool
accepts new threads up to its limit, then returns `EAGAIN`.

### 9.1 Counter Storage

Counters are per-operation, stored in a shared array indexed by operation enum:

```c
extern volatile uint64_t g_chaos_process_fail_after_counters[];
```

Each element is incremented with `__sync_fetch_and_add()` (full barrier, atomic
increment, returns old value):

```c
static inline uint64_t chaos_process_atomic_fetch_add_u64(volatile uint64_t *value,
                                                           uint64_t delta)
{
    return (uint64_t)__sync_fetch_and_add(value, delta);
}
```

### 9.2 Semantics

Given rule `pthread_create:FAIL_AFTER:EAGAIN,128`:

1. Counter starts at 0.
2. Each `pthread_create` call increments the counter (post-increment: old value
   is compared against the threshold).
3. While `old_value < 128`: call succeeds (counter was below threshold before
   this call).
4. At `old_value == 128` and beyond: call fails with `EAGAIN`.

The counter is per-operation (all `pthread_create` calls share one counter),
not per-thread. Multiple threads calling `pthread_create` concurrently increment
the same counter atomically; the N-th global call (not the N-th call on any
particular thread) triggers failure.

### 9.3 Counter Reset on Config Reload

Counters reset to zero when the config is reloaded. This means:
- Writing a new config file with a changed rule resets the budget.
- Writing the same config file with a modified mtime also resets the budget.
- If you want a "single-shot" exhaustion test, write the config, run the test
  until the N-th call fails, then remove the config to restore normal operation.

### 9.4 Interaction with ERRNO and LATENCY

Rule ordering within an operation:

1. LATENCY fires first (unconditional pre-call delay, if rule matches).
2. ERRNO fires second (probabilistic pre-call failure).
3. FAIL_AFTER fires third (counter-gated failure).
4. If none fired: real call executes.

A call matching both `ERRNO@0.5` and `FAIL_AFTER,128` can fail either way; the
probability-weighted ERRNO check runs before the counter check. This is a fine
point: in a high-concurrency scenario, the counter may advance past the threshold
for some threads before the ERRNO probability fires for others — the interleaving
is deterministic per call but non-deterministic in the concurrency order.

---

## 10. DSL Grammar and Rule Semantics

### 10.1 Full ABNF (RFC 5234)

```abnf
rule-line       = selector ":" effect ":" value [ "@" probability ] CRLF / LF
selector        = "*"
                / "pthread_create"
                / "fork"
                / "posix_spawn"
                / "posix_spawnp"
                / "execve"
                / "execveat"
                / "waitpid"
effect          = "ERRNO" / "LATENCY" / "FAIL_AFTER"
value           = errno-pair / latency-ms
errno-pair      = errno-name [ "," count ]   ; count used only for FAIL_AFTER
errno-name      = 1*ALPHA *( ALPHA / DIGIT / "_" )
latency-ms      = 1*DIGIT
count           = 1*DIGIT
probability     = "0." 1*DIGIT / "1.0" / "1"
```

`FAIL_AFTER` value format: `ERRNO_NAME,N` where N is the number of successful
calls before failure begins. Example: `pthread_create:FAIL_AFTER:EAGAIN,128`.

### 10.2 Valid errno Values per Symbol

`pthread_create()`: `EAGAIN` (resource limit, OS thread limit), `EINVAL`
(invalid attr), `EPERM` (no CAP_SYS_ADMIN for realtime scheduling attr).

`fork()`: `EAGAIN` (resource limit: max PID, RLIMIT_NPROC exceeded), `ENOMEM`
(kernel allocation failure).

`posix_spawn()` / `posix_spawnp()`: `EINVAL` (bad attrp), `ENOENT` (path not
found), `ENOMEM`, `EAGAIN` — any `execve` error can surface via spawn.

`execve()` / `execveat()`: `EACCES` (permission, `noexec` mount), `ENOENT`,
`ENOEXEC` (bad ELF/magic), `ENOMEM`, `E2BIG` (argv+envp too large), `ETXTBSY`
(binary open for write), `ELOOP` (symlink loop in interpreter), `EPERM`
(`no_new_privs` + setuid binary, Linux 3.5+).

`waitpid()`: `ECHILD` (no children or not waitable), `EINTR` (signal while
waiting), `EINVAL` (bad options).

---

## 11. Per-Hook Call Flows

### 11.1 pthread_create()

```
wrapper entry
  ├─ chaos_process_enter_internal()     TLS guard check
  ├─ chaos_process_check_config()       mtime-CAS reload
  ├─ LATENCY rule match
  ├─ ERRNO rule match                   returns error number directly (not -1)
  ├─ FAIL_AFTER rule match              returns error number directly (not -1)
  ├─ real_pthread_create(thread, attr, fn, arg)
  └─ chaos_process_leave_internal()
```

### 11.2 fork()

```
wrapper entry
  ├─ chaos_process_enter_internal()
  ├─ chaos_process_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match                   returns -1, errno set
  ├─ FAIL_AFTER rule match              returns -1, errno set
  ├─ real_fork()
  └─ chaos_process_leave_internal()
```

### 11.3 posix_spawn() / posix_spawnp()

Same flow as pthread_create. Returns error number directly (not -1) per POSIX.

### 11.4 execve()

```
wrapper entry
  ├─ chaos_process_enter_internal()
  ├─ chaos_process_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match                   returns -1, errno set
  ├─ FAIL_AFTER rule match              returns -1, errno set
  ├─ real_execve(path, argv, envp)      does not return on success
  └─ chaos_process_leave_internal()     only reached on real execve failure
```

### 11.5 execveat()

Same flow as execve. Includes NULL-guard on real_execveat pointer.

### 11.6 waitpid()

```
wrapper entry
  ├─ chaos_process_enter_internal()
  ├─ chaos_process_check_config()
  ├─ LATENCY rule match
  ├─ ERRNO rule match                   returns -1, errno set
  ├─ FAIL_AFTER rule match              returns -1, errno set
  ├─ real_waitpid(pid, status, options)
  └─ chaos_process_leave_internal()
```

---

## 12. Reentrancy Guard and TLS State

Identical architecture to `libchaos-memory`; see `docs/MEMORY.md` §14 for
the full analysis. The process library uses:

```c
extern __thread int g_chaos_process_tls_guard;
extern __thread uint64_t g_chaos_process_tls_prng_state;
```

The LATENCY path calls `real_nanosleep` (a cached pointer to the real `nanosleep`,
not the interposed symbol). Config reload calls `open`/`read`/`stat` — if
`libchaos-io` is simultaneously loaded, the TLS guard from that library fires
instead; the process library's guard does not prevent `libchaos-io` reentrancy.
The guard is per-library, not cross-library. Libraries do not share guard state.

---

## 13. PRNG Model

The xorshift64* PRNG is identical to the one in `libchaos-memory` and
`libchaos-time`. See `docs/MEMORY.md` §15 for the full analysis (SplitMix64
constants, per-thread seeding, GoldenRatio finaliser). The `chaos_process_prng_mix`
and `chaos_process_prng_next_u32` functions are structurally identical across all
three libraries — same constants, same shift schedule, same zero-state guard.

---

## 14. Config Reload Protocol

Identical two-snapshot CAS design. See `docs/MEMORY.md` §16 for the full protocol.
The `g_chaos_process_*` state machine uses `CHAOS_PROCESS_MTIME_MISSING`,
`CHAOS_PROCESS_MTIME_RELOADING`, and `CHAOS_PROCESS_MTIME_UNKNOWN` sentinels with
the same values (`0x0`, `0xfffffffffffffffe`, `0xffffffffffffffff`).

---

## 15. Non-Coverage: clone/clone3, vfork, kill, pthread_kill, waitid

| Symbol        | Rationale for non-coverage                                                |
|---------------|---------------------------------------------------------------------------|
| `clone(2)`    | Not a public POSIX/glibc symbol; typically `SYS_clone` directly or via `__clone` internal. Adding it requires arch-specific calling convention handling (different register/stack layouts per arch for the new stack). |
| `clone3(2)`   | Linux 5.3+; syscall-only, not a libc symbol. `struct clone_args` ABI is also evolving. |
| `vfork(2)`    | See §5. Safety contract violations in the injection window.               |
| `kill(2)`     | Signal semantics orthogonal to the process-creation/destruction focus. Signal injection requires a different abstraction (signal interposition via `sigaction`/`raise` wrappers) with entirely different effect taxonomy. |
| `pthread_kill`| Same rationale as `kill`. Signal delivery to threads is a signal-domain problem. |
| `waitid(2)`   | Gap acknowledged. `waitid` offers `siginfo_t` status and `P_PIDFD` that `waitpid` cannot express. Candidate for next process-surface expansion. |
| `wait(2)`     | Wrapper around `waitpid(-1, status, 0)` in glibc; covered transitively when `waitpid` is the implementation. But the libc symbol `wait` itself is not interposed. |
| `wait3/wait4` | BSD-heritage symbols; `wait4` calls `waitpid` internally on Linux. Not interposed directly. |

---

## 16. glibc vs musl Divergence per Symbol

| Symbol             | glibc                                      | musl                                          |
|--------------------|--------------------------------------------|-----------------------------------------------|
| `pthread_create`   | NPTL, uses `clone` with CLONE_THREAD flags | musl thread model, uses `clone` directly       |
| `fork`             | `__libc_fork`, calls `clone(SIGCHLD,...)`  | `__fork`, calls `clone(SIGCHLD,...)`           |
| `posix_spawn`      | vfork+exec via `__spawnix` (CLONE_VFORK)  | fork+exec via `__posix_spawnx`                |
| `execveat`         | glibc 2.34+ exposes wrapper               | Not always exported as public symbol in older musl |
| `waitpid`          | Calls `wait4(-,-,-,NULL)` syscall          | Direct `SYS_wait4` call                       |
| `pthread_create` errno | Returns positive int (not -1)         | Same (POSIX requirement)                      |
| `FAIL_AFTER` counter  | Per-operation, shared across threads    | Same (atomic, architecture-independent)       |

**posix_spawn cascade gap** (glibc vs musl):

On glibc, `posix_spawn` uses `clone(CLONE_VFORK|CLONE_VM)` and does not call
the libc `fork()` symbol. A rule `fork:ERRNO:EAGAIN` does not fire when
`posix_spawn` is called on glibc.

On musl, `posix_spawn` calls `fork()`. The rule `fork:ERRNO:EAGAIN` fires for
musl's `posix_spawn` path.

This cross-symbol cascade is not modelled in the DSL selector grammar. Configure
`posix_spawn:ERRNO:EAGAIN` explicitly when targeting musl, rather than relying
on a `fork` rule to cover it.

---

## 17. Execution Boundary Summary

`libchaos-process` operates at the libc process/thread contract boundary.

Covered by interposition:

- `pthread_create()` → thread resource exhaustion, thread-pool saturation testing
- `fork()` → process table exhaustion, fork-bomb prevention testing
- `posix_spawn()` / `posix_spawnp()` → subprocess spawn failure, PATH resolution
  failure
- `execve()` / `execveat()` → privilege denial, noexec-mount simulation
- `waitpid()` → zombie accumulation testing, EINTR-handling robustness

Not covered:

- Raw `clone()` / `clone3()` syscalls (bypasses PLT)
- `vfork()` (safety contract violation in injection window)
- `kill()`, `pthread_kill()`, `tgkill()` (signal domain, orthogonal)
- `waitid()` (not yet interposed)
- Statically linked binaries (no PLT)
- Go/Rust/Zig runtimes that use `SYS_clone`/`SYS_clone3` directly

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
