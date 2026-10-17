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

`libchaos-process` is the LD_PRELOAD library that fails and delays thread creation,
process creation, program execution and child reaping in a dynamically linked process.
It decides before the real call: an injected failure never creates a thread or process,
never replaces the image, never reaps a child. Repository-wide ownership and composition
rules are in [`docs/SYSTEM.md`](SYSTEM.md); loader-level internals (link map, PLT/GOT,
`AT_SECURE`, glibc/musl matrix) are in [`docs/PLATFORM.md`](PLATFORM.md).

| | |
|---|---|
| Wrappers with a selector | `pthread_create()`, `fork()`, `posix_spawn()`, `posix_spawnp()`, `execve()`, `execveat()` (Linux), `waitpid()` |
| Wrappers under another call's rules | `wait()`, `wait3()`, `wait4()`, `waitid()` (waitpid); `execv()`, `execvp()`, `execvpe()`, `execl()`, `execle()`, `execlp()` (execve); `fexecve()` (execveat, Linux); `system()`, `popen()` (posix_spawn) |
| Effects | ERRNO, LATENCY, FAIL_AFTER |
| Qualifiers | `@first`, `@from`, `@until`, `@size` (accepted; `@size` never matches, §10.4) |
| Rule file | `/tmp/.chaos-process.conf` |
| Status file | `/tmp/.chaos-process.status` |
| Hits file | `/tmp/.chaos-process.hits.<n>` |
| Verification | unit tests with a 100.00 % line-coverage gate on `src/process/*.c`; runtime suites `test/runtime/test_process_glibc.sh` and `test_process_alpine.sh` (glibc and musl, amd64 and arm64) |

SECCOMP mode (`chaos-init`) applies the same rules at the system-call layer, with
differences listed in [SECCOMP.md §5](SECCOMP.md#5-how-calls-map-to-the-libraries-operations).

---

## Table of Contents

1. [clone(2) Flag Taxonomy](#1-clone2-flag-taxonomy)
2. [pthread_create Internal Flow](#2-pthread_create-internal-flow)
3. [fork() Mechanics and CoW Semantics](#3-fork-mechanics-and-cow-semantics)
4. [posix_spawn: glibc and musl](#4-posix_spawn-glibc-and-musl)
5. [vfork Hazards and Non-Coverage](#5-vfork-hazards-and-non-coverage)
6. [execve, execveat, and the exec Family Matrix](#6-execve-execveat-and-the-exec-family-matrix)
7. [waitpid, waitid, and the wait Family](#7-waitpid-waitid-and-the-wait-family)
8. [EINTR Contract](#8-eintr-contract)
9. [FAIL_AFTER Semantics and Counter Implementation](#9-fail_after-semantics-and-counter-implementation)
10. [DSL Grammar and Rule Semantics](#10-dsl-grammar-and-rule-semantics)
11. [Per-Hook Call Flows](#11-per-hook-call-flows)
12. [Reentrancy Guard and TLS State](#12-reentrancy-guard-and-tls-state)
13. [PRNG Model](#13-prng-model)
14. [Config Reload Protocol](#14-config-reload-protocol)
15. [Non-Coverage: clone/clone3, vfork, kill, pthread_kill](#15-non-coverage-cloneclone3-vfork-kill-pthread_kill)
16. [glibc vs musl Divergence per Symbol](#16-glibc-vs-musl-divergence-per-symbol)
17. [Execution Boundary Summary and Limits](#17-execution-boundary-summary-and-limits)

---

## 1. clone(2) Flag Taxonomy

Every thread and process on Linux is created by `clone(2)` or `clone3(2)`; the flags
decide what the new task shares. The library intercepts the libc functions above
`clone`, never `clone` itself (§15). The flags matter here for two reasons: they explain
why one libc function cannot be faulted through another, and SECCOMP mode classifies
`clone` calls by them.

### 1.1 Key clone Flags

| Flag                   | Value        | Meaning                                                                 |
|------------------------|--------------|-------------------------------------------------------------------------|
| `CLONE_VM`             | `0x00000100` | Share the address space                                                 |
| `CLONE_FS`             | `0x00000200` | Share cwd, root, umask                                                  |
| `CLONE_FILES`          | `0x00000400` | Share the descriptor table                                              |
| `CLONE_SIGHAND`        | `0x00000800` | Share signal handlers                                                   |
| `CLONE_PIDFD`          | `0x00001000` | Also return a pidfd (Linux 5.2)                                         |
| `CLONE_VFORK`          | `0x00004000` | Suspend the parent until the child execs or exits                       |
| `CLONE_THREAD`         | `0x00010000` | Same thread group (a thread, not a process)                             |
| `CLONE_SYSVSEM`        | `0x00040000` | Share System V semaphore undo lists                                     |
| `CLONE_SETTLS`         | `0x00080000` | Set the thread pointer                                                  |
| `CLONE_PARENT_SETTID`  | `0x00100000` | Store the child TID in the parent                                       |
| `CLONE_CHILD_CLEARTID` | `0x00200000` | Clear the child TID and wake its futex on exit (thread join)            |
| `CLONE_CHILD_SETTID`   | `0x01000000` | Store the child TID in the child                                        |
| `CLONE_NEW*`           | various      | New namespaces (mount, cgroup, UTS, IPC, user, PID, network)            |

### 1.2 Flag Combinations by API

| API              | clone flags (glibc and musl)                                                            | SECCOMP mode classifies as |
|------------------|-----------------------------------------------------------------------------------------|----------------------------|
| `pthread_create` | `CLONE_VM \| CLONE_FS \| CLONE_FILES \| CLONE_SIGHAND \| CLONE_THREAD \| CLONE_SYSVSEM \| CLONE_SETTLS \| CLONE_PARENT_SETTID \| CLONE_CHILD_CLEARTID`, no exit signal | pthread_create |
| `fork`           | glibc: `CLONE_CHILD_SETTID \| CLONE_CHILD_CLEARTID \| SIGCHLD`; musl: `SYS_fork` where it exists, else `SIGCHLD` | fork |
| `vfork`          | `CLONE_VM \| CLONE_VFORK \| SIGCHLD` (or `SYS_vfork`)                                   | posix_spawn                |
| `posix_spawn`    | `CLONE_VM \| CLONE_VFORK \| SIGCHLD`, then `execve` in the child                         | posix_spawn                |

`clone3()` passes the flags in `struct clone_args`; libc may use it when the kernel
supports it. The libc function the program calls, and therefore the wrapper, is the same
either way.

Reference: `clone(2)`; glibc `nptl/pthread_create.c`, `sysdeps/unix/sysv/linux/spawni.c`;
musl `src/thread/pthread_create.c`, `src/process/posix_spawn.c`.

---

## 2. pthread_create Internal Flow

```
pthread_create(thread, attr, start, arg)          ← wrapper decides here
  ├─ allocate the stack (mmap + guard page) and TLS
  ├─ clone(CLONE_VM | CLONE_THREAD | ..., stack)
  ├─ (child) start(arg)
  └─ return 0, or a positive error number
```

- **Injection point.** The wrapper decides before the real `pthread_create` runs: an
  injected failure allocates no stack and creates no task.
- **Return convention.** `pthread_create()` returns the error number and does not set
  `errno`. The wrapper does the same: an injected failure returns the configured value
  and leaves `errno` untouched. Callers that test `errno` instead of the return value are
  wrong under POSIX and are exposed by this rule.
- **No cascade through libchaos-memory.** libc allocates the stack with its internal
  `mmap`, which never reaches an exported symbol, so `libchaos-memory`'s `mmap` rules do
  not fail thread creation under LD_PRELOAD. In SECCOMP mode they do: there the stack
  `mmap` is a system call like any other.
- **libpthread before glibc 2.34.** `pthread_create` lives in libpthread there. The
  symbol is resolved on demand, without aborting, so programs that never load libpthread
  start normally; a program that `dlopen()`s it later is served then. If it still does
  not resolve, the wrapper returns `EAGAIN`: a thread needs libc's own setup, and there is
  no system call to fall back to.

Useful errors: `EAGAIN` (thread or process limit, `RLIMIT_NPROC`,
`kernel.threads-max`), `ENOMEM`, `EINVAL`, `EPERM` (scheduling attributes).

---

## 3. fork() Mechanics and CoW Semantics

`fork()` duplicates the calling process. The kernel (`kernel/fork.c`, `copy_process()`)
copies the task, marks writable private mappings copy-on-write, duplicates the
descriptor table and signal dispositions, and returns the child PID to the parent and 0
to the child. libc runs `pthread_atfork` prepare handlers before the system call and the
parent/child handlers after it.

- **Injection point.** LATENCY, ERRNO and FAIL_AFTER are evaluated in the parent before
  the real `fork()`. An injected failure returns -1 with `errno` set: no system call, no
  atfork handler, no child.
- **The child.** The child of a real fork starts with the library state the parent had,
  then the library's atfork child handler gives it its own: FAIL_AFTER counters, hit
  counts and `@first` claims start at 0, the PRNG reseeds from the child's TID, and the
  child writes its own hits file (§14).
- **Not resolved yet.** A `fork()` that arrives while the real pointer is still NULL (a
  call from inside symbol resolution) fails with `ENOSYS`: a bare `clone` would skip
  libc's atfork handlers and caches.

Useful errors: `EAGAIN` (`RLIMIT_NPROC`, `pid_max`, cgroup `pids.max`), `ENOMEM`.

---

## 4. posix_spawn: glibc and musl

`posix_spawn(3)` creates a child, applies file actions and attributes, and executes a
program, in one call.

### 4.1 Implementation

Both glibc (`__spawnix`) and musl (`__posix_spawnx`) create the child with
`clone(CLONE_VM | CLONE_VFORK | SIGCHLD)`: the child runs on its own stack in the
parent's address space while the parent is suspended, applies the file actions with
direct system calls, and calls `execve`. The parent resumes when the child execs or
exits, and reports an exec failure as the return value.

### 4.2 Consequences for Rules

- **Injection point.** The wrapper decides before the real `posix_spawn`; the vfork
  window never opens. An injected failure is returned as the error number, `errno`
  untouched, as `posix_spawn()` specifies.
- **A `fork` rule never fails `posix_spawn()`.** Neither libc calls `fork()`; the clone
  happens inside libc. Write `posix_spawn` rules for spawn paths.
- **An `execve` rule never fails the exec inside `posix_spawn()`** under LD_PRELOAD: the
  child calls libc's internal `execve`. In SECCOMP mode it does, because the child's
  `execve` is a system call ([SECCOMP.md §5](SECCOMP.md#5-how-calls-map-to-the-libraries-operations)).
- **`system()` and `popen()`** run their shell through libc's internal posix_spawn
  (glibc 2.29+, musl), so they follow the `posix_spawn` rules (§6.1).
- When the real `posix_spawn`/`posix_spawnp` did not resolve, the wrapper returns
  `ENOSYS` (there is no single system call to fall back to).

### 4.3 posix_spawnp

`posix_spawnp()` differs only in the `PATH` search. It has its own selector and its own
FAIL_AFTER counter: `posix_spawn` rules do not match `posix_spawnp` calls and vice versa.

Useful errors: `ENOENT`, `EACCES`, `ENOEXEC`, `ENOMEM`, `EAGAIN`, `E2BIG`.

---

## 5. vfork Hazards and Non-Coverage

`vfork()` suspends the parent and lets the child run in the parent's address space until
it calls `execve()` or `_exit()`. POSIX.1-2008 removed it.

`vfork()` is not wrapped:

1. Between `vfork()` returning in the child and `execve()`/`_exit()`, the child may only
   call async-signal-safe functions and must not return from the calling frame. The
   rule lookup (`stat()`, a reload into static buffers) and the hit report do not belong
   in that window.
2. A wrapper frame that returned in the child would corrupt the parent's stack, which the
   child shares.
3. `posix_spawn()` provides the vfork-style spawn; it is wrapped and decided before its
   clone.

The library tolerates vfork children it did not create: they share the parent's memory,
run no atfork handler, see a reload claimed by the parent as busy, and never write a hits
file (the hits writer checks `getpid()`).

---

## 6. execve, execveat, and the exec Family Matrix

### 6.1 exec Family

| Function   | Search        | Arguments      | Wrapper behaviour                                                         | Rules of   |
|------------|---------------|----------------|---------------------------------------------------------------------------|------------|
| `execve`   | no            | array + env    | rules, then real `execve`                                                 | `execve`   |
| `execv`    | no            | array          | `execve(path, argv, environ)`                                             | `execve`   |
| `execle`   | no            | varargs + env  | arguments collected into a stack array, then `execve()`                   | `execve`   |
| `execl`    | no            | varargs        | arguments collected, then `execv()`                                       | `execve`   |
| `execvpe`  | `PATH`        | array + env    | `execve` rules, then real `execvpe` (libc's own search)                   | `execve`   |
| `execvp`   | `PATH`        | array          | `execvpe(file, argv, environ)`                                            | `execve`   |
| `execlp`   | `PATH`        | varargs        | arguments collected, then `execvp()`                                      | `execve`   |
| `execveat` | dirfd + path  | array + env    | rules, then real `execveat` (Linux only)                                  | `execveat` |
| `fexecve`  | descriptor    | array + env    | `execveat` rules (Linux only), then real `fexecve`                        | `execveat` |
| `system`   | shell         | command        | `system(NULL)` forwarded; else `posix_spawn` rules, then real `system`    | `posix_spawn` |
| `popen`    | shell         | command, mode  | `posix_spawn` rules, then real `popen`                                    | `posix_spawn` |

- glibc and musl implement every variant on their internal `execve`/`execveat` and
  `posix_spawn`, which never reach the exported symbols; each variant therefore has its
  own wrapper.
- Each call is decided **once**: the forwarding wrappers call this library's own exported
  `execve`/`execv`/`execvpe`, and the real functions run with the guard raised.
- All members of a row group share the operation's FAIL_AFTER counter: an `execvp()`
  advances the `execve` counter.
- Failure report: -1 with `errno` (`system()`), NULL with `errno` (`popen()`).
- `execvpe`, `fexecve`, `system` and `popen` that did not resolve fail with `ENOSYS`.

### 6.2 execveat Portability

`execveat(2)` (Linux 3.19) executes relative to a directory descriptor; glibc exports a
wrapper from 2.34, musl does not consistently export one. The wrapper is exported on
Linux in either case. The real symbol is looked up without aborting; when it is absent,
the call-through issues `syscall(SYS_execveat, …)` directly (`ENOSYS` only where the
headers lack `SYS_execveat`).

### 6.3 exec After an Injected Failure

An injected failure returns -1 with `errno` set; the real `execve` is never called and the
process keeps its image, with the library loaded. This models an exec the kernel refused
(`EACCES` on a `noexec` mount, `ENOENT`, `ETXTBSY`, `E2BIG`). The library cannot fake a
successful exec.

A LATENCY before a successful exec delays the new program's start by that much, visible
to a parent that measures it. On success the kernel discards the image: no destructor
runs, so hits not yet written are lost unless the eager phase (first 64 hits) or the
100 ms interval wrote them (§14). The new program loads the library again only if its
environment still carries `LD_PRELOAD`; its hits file does not overwrite the replaced
image's (§14).

Useful errors: `EACCES`, `ENOENT`, `ENOEXEC`, `ENOMEM`, `E2BIG`, `ETXTBSY`, `ELOOP`,
`EPERM` (`no_new_privs` with a set-user-ID file).

---

## 7. waitpid, waitid, and the wait Family

### 7.1 The wait Family

| Function  | Wrapper behaviour                                                | Status output             |
|-----------|------------------------------------------------------------------|---------------------------|
| `waitpid` | rules, then real `waitpid`                                       | `int *status`             |
| `wait`    | `waitpid(-1, status, 0)`                                         | `int *status`             |
| `wait4`   | rules, then real `wait4` (`rusage` still filled)                 | `int *status`, `rusage`   |
| `wait3`   | `wait4(-1, status, options, rusage)`                             | `int *status`, `rusage`   |
| `waitid`  | rules, then real `waitid` (`siginfo_t` still filled)             | `siginfo_t *`             |

glibc and musl implement each with its own system call (`wait4` or `waitid`), not through
`waitpid()`, so each has a wrapper. There is no separate selector: all five follow the
`waitpid` rules and share its FAIL_AFTER counter. An injected failure returns -1 with
`errno` set and reaps nothing. While a real pointer is unresolved, the wrappers issue
`SYS_wait4` or `SYS_waitid` (with a NULL `rusage`) directly.

### 7.2 waitid

`waitid(2)` reports through `siginfo_t` (`si_code`: `CLD_EXITED`, `CLD_KILLED`,
`CLD_DUMPED`, `CLD_STOPPED`, `CLD_TRAPPED`, `CLD_CONTINUED`), supports `WNOWAIT` and, from
Linux 5.4, `P_PIDFD`. It is covered by the `waitpid` rules (§7.1).

### 7.3 EINTR and LATENCY on waitpid

`waitpid:ERRNO:EINTR` returns -1 with `EINTR` without waiting. The child is still there;
a caller that does not retry leaves a zombie. `waitpid:ERRNO:ECHILD` exercises "no such
child" handling.

LATENCY is added before the real wait, which may block on its own: the caller observes
the delay plus the wait. A caller polling with `WNOHANG` against a deadline can expire
during the injected delay before the real call looks at an already exited child.

---

## 8. EINTR Contract

A blocking call interrupted by a signal handler either returns `EINTR` or is restarted
by the kernel, depending on the call and on `SA_RESTART` (`signal(7)`, "Interruption of
system calls and library functions by signal handlers").

### 8.1 The Restartable / Non-Restartable Split

| Call             | With `SA_RESTART`         | Without                    | Notes                                         |
|------------------|---------------------------|----------------------------|-----------------------------------------------|
| `wait`, `waitpid`, `wait3`, `wait4`, `waitid` | restarted | `EINTR`          | `WNOHANG` never blocks                        |
| `nanosleep`, `clock_nanosleep` | never restarted | `EINTR`                  | unslept time in `*rem`                        |
| `fork`, `pthread_create`, `posix_spawn`, `execve` | — | —                    | do not block on signals                       |

### 8.2 Consequence for Injection

An injected `EINTR` bypasses the kernel's restart logic: there is no signal, so
`SA_RESTART` never applies, and the caller sees `EINTR` whatever its signal dispositions.
`waitpid:ERRNO:EINTR@0.1` makes 10 % of wait calls return `EINTR` even in a program whose
handlers all use `SA_RESTART`, which exposes code that relies on restart instead of a
retry loop. That code fails in production when a handler without `SA_RESTART` is
installed later, for example by a library.

### 8.3 nanosleep EINTR

`libchaos-time` models an interrupted `nanosleep` as interrupted before any time elapsed:
the full request is written to `*rem`
([TIME.md §6.2](TIME.md#62-injected-eintr)).

---

## 9. FAIL_AFTER Semantics and Counter Implementation

`FAIL_AFTER:<errno>,N` lets the first `N` calls of the operation pass, then fails the
following ones with `<errno>`. It models exhaustion: a pool that creates threads up to a
limit, then gets `EAGAIN`.

### 9.1 Counter Storage

One counter per operation, process-wide, in the library's data segment:

```c
extern volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT];
```

Indices: 0 `pthread_create`, 1 `fork`, 2 `posix_spawn`, 3 `posix_spawnp`, 4 `execve`,
5 `execveat`, 6 `waitpid`. Each evaluation is one `__sync_fetch_and_add(…, 1)` (full
barrier), and the value **before** the increment is compared.

### 9.2 Semantics

Given `pthread_create:FAIL_AFTER:EAGAIN,128`:

1. The counter starts at 0.
2. A call that reaches the FAIL_AFTER step increments it.
3. Pre-increment value `< 128`: the call passes (calls 1 to 128).
4. Pre-increment value `≥ 128`: the call fails with `EAGAIN` (call 129 onwards), subject
   to the gates below.

Precise rules:

- **What advances the counter.** Only a call for which a FAIL_AFTER rule matches the
  operation and no ERRNO rule fired first. With `N = 0` the first such call fails.
- **One counter per operation, not per rule.** A `*:FAIL_AFTER:EAGAIN,3` rule gives each
  operation its own 3 passing calls. The derived wrappers share the counter of the
  operation whose rules they follow (§6.1, §7.1).
- **Gates after the threshold, in order:** probability, then `@from`/`@until`, then
  `@first`. The counter advances on every evaluated call, also when a gate then says no:
  outside a time window the budget is still being used up. With probability `p` below 1,
  calls past the threshold fail with probability `p`. `@first=K` caps the injected
  failures at `K` per process.
- **Concurrency.** Threads share the counter; the `N+1`-th call overall fails, not the
  `N+1`-th call of any thread.
- **Overflow.** Not guarded; 2^64 calls are out of reach.
- **Hit.** Each injected failure counts one hit.

### 9.3 Counter Reset

The counters are reset to 0:

- on every reload that publishes a new snapshot: a change of the rule file's content,
  mtime, size or inode (a `touch` is enough), its removal, or a rejected file;
- not by a provisional re-read that finds the same content (§14);
- in the child of a `fork()` (atfork child handler): FAIL_AFTER counts per process, like
  `@first`;
- implicitly after a successful `execve`: the new image loads the library afresh.

For a single-shot exhaustion test, write the rule file, run until the `N+1`-th call
fails, then remove the file. SECCOMP mode inherits the parent's counts into a forked
child instead of resetting them ([SECCOMP.md §1](SECCOMP.md#1-model)).

### 9.4 Interaction with ERRNO and LATENCY

Per call, in this order:

1. LATENCY: if a LATENCY rule fires, sleep (§11).
2. ERRNO: if an ERRNO rule fires, fail; FAIL_AFTER is not evaluated and its counter does
   not advance.
3. FAIL_AFTER: increment, compare, gate; fail if all pass.
4. Otherwise the real call.

A call can be delayed and then failed. It is never failed twice.

---

## 10. DSL Grammar and Rule Semantics

### 10.1 Grammar (RFC 5234 ABNF)

```abnf
line          = [ rule *( 1*WSP qualifier ) ] [ comment ] LF
rule          = selector *WSP ":" *WSP effect *WSP ":" *WSP value
selector      = "*" / "pthread_create" / "fork" / "posix_spawn" / "posix_spawnp"
              / "execve" / "execveat" / "waitpid"
effect        = "ERRNO" / "LATENCY" / "FAIL_AFTER"
value         = payload [ "@" probability ]        ; no blank before "@"
payload       = errno                              ; ERRNO
              / latency-ms                         ; LATENCY
              / errno *WSP "," *WSP count          ; FAIL_AFTER
errno         = "EAGAIN" / "ENOMEM" / "EACCES" / "ENOENT" / "EINTR" / "ECHILD"
              / "EPERM" / "ESRCH" / "EBUSY" / "EINVAL" / "ENOSYS" / "EMFILE"
              / "ENFILE" / "E2BIG"
              / 1*DIGIT                            ; 1 .. 2147483647
latency-ms    = 1*DIGIT                            ; 0 .. 4294967295
count         = 1*DIGIT                            ; 0 .. 18446744073709551615
probability   = "0" / "1" / "0." 1*DIGIT / "1." 1*"0"
qualifier     = "@first=" 1*18DIGIT                ; > 0
              / "@from=" 1*18DIGIT / "@until=" 1*18DIGIT   ; Unix ms, until > from
              / "@size>" 1*18DIGIT / "@size<" 1*18DIGIT
comment       = "#" *( %x01-09 / %x0B-FF )
```

- Selectors, effect names and errno names are case-sensitive; blanks around fields are
  trimmed; everything from the first `#` is a comment.
- The probability is attached with `@` and no blank: `fork:ERRNO:EAGAIN@0.1`,
  `pthread_create:FAIL_AFTER:EAGAIN,128@0.5`. As a separate word it is parsed as a
  qualifier, is unknown, and rejects the rule file.
- A FAIL_AFTER count must start with a digit: `-1` is rejected rather than read as
  2^64−1 by `strtoull`. Out-of-range counts are rejected.
- The probability parser is locale-independent; a missing probability means 1.
- A line with qualifiers but no rule rejects the rule file.

### 10.2 Precedence

For each effect one rule is selected: an operation selector (rank 2) beats `*` (rank 1);
equal rank, the longer selector text wins; still equal, the first rule in the file wins.
LATENCY, ERRNO and FAIL_AFTER are selected independently.

### 10.3 Useful errno Values per Operation

| Operation        | errno                                                                       |
|------------------|-----------------------------------------------------------------------------|
| `pthread_create` | `EAGAIN`, `ENOMEM`, `EINVAL`, `EPERM`                                       |
| `fork`           | `EAGAIN`, `ENOMEM`, `ENOSYS`                                                |
| `posix_spawn(p)` | `ENOENT`, `EACCES`, `ENOEXEC`, `ENOMEM`, `EAGAIN`, `E2BIG`, `EINVAL`        |
| `execve(at)`     | `EACCES`, `ENOENT`, `ENOEXEC`, `ENOMEM`, `E2BIG`, `ETXTBSY`, `ELOOP`, `EPERM` |
| `waitpid`        | `ECHILD`, `EINTR`, `EINVAL`                                                 |

The library does not check that an errno is plausible for the call.

### 10.4 Qualifiers

`@first`, `@from`, `@until` and `@size` behave as in every library (`chaos_policy.h`).
Process calls carry no byte count, so **a rule with `@size` parses but never fires**.

### 10.5 Failure Behaviour of the Rule File

Parsing is all-or-nothing and fails open: one invalid line, more than 256 rules, a file of
262144 bytes or more, an unreadable file (`EACCES`, `EPERM`, a directory) or a NUL byte
leaves the library with no rules and writes `state=error` with `line=`, `reason=` and
`text=` to the status file. A transient read error, or a file changed while it was read,
keeps the previous snapshot and retries on the next look. Without a rule file the status
file is removed.

---

## 11. Per-Hook Call Flows

Every wrapper first calls `chaos_process_ensure_symbols()` (§12). "Bypass" forwards to
the real function with the guard raised. Each rule lookup may reload the rule file (§14).
LATENCY sleeps with `chaos_sleep_ms()`: a raw `clock_nanosleep(CLOCK_MONOTONIC)` system
call, restarted on `EINTR` with the remaining time, `errno` preserved. It passes through
no interposed symbol, so neither `libchaos-time` nor a time rule can shorten or lengthen
it, and it is not a cancellation point.

### 11.1 pthread_create()

```
wrapper entry
  ├─ guard set                   → bypass
  ├─ LATENCY rule                → sleep
  ├─ ERRNO rule                  → return the error number (errno untouched)
  ├─ FAIL_AFTER rule             → return the error number (errno untouched)
  └─ real pthread_create(thread, attr, start, arg)
```

### 11.2 fork()

```
wrapper entry
  ├─ guard set                   → bypass
  ├─ LATENCY rule                → sleep
  ├─ ERRNO rule                  → errno = value, return -1
  ├─ FAIL_AFTER rule             → errno = value, return -1
  └─ real fork()                 (atfork handlers run; the child resets its state, §3)
```

### 11.3 posix_spawn() / posix_spawnp()

Same flow as `pthread_create`, each with its own operation: an injected failure is
returned as the error number, `errno` untouched.

### 11.4 execve() / execveat()

```
wrapper entry
  ├─ guard set                   → bypass
  ├─ LATENCY rule                → sleep
  ├─ ERRNO rule                  → errno = value, return -1
  ├─ FAIL_AFTER rule             → errno = value, return -1
  └─ real execve(path, argv, envp)    does not return on success
```

`execveat()` is the same with its own operation; an unresolved real `execveat` becomes a
direct `SYS_execveat` (§6.2).

### 11.5 waitpid() and the wait Family

```
wrapper entry
  ├─ guard set                   → bypass
  ├─ waitpid rules: LATENCY → sleep; ERRNO or FAIL_AFTER → errno = value, return -1
  └─ real waitpid / wait4 / waitid
```

`wait()` and `wait3()` call the `waitpid()` and `wait4()` wrappers (§7.1).

---

## 12. Reentrancy Guard and TLS State

Same design as `libchaos-memory` ([MEMORY.md §14](MEMORY.md#14-reentrancy-guard-and-tls-state)):

```c
extern __thread int g_chaos_process_tls_guard;          /* non-zero: inside the library */
extern __thread uint64_t g_chaos_process_tls_prng_state; /* 0: not seeded yet */
```

- Every real call runs between `chaos_process_enter_internal()` and
  `chaos_process_leave_internal(previous)`; leave restores the saved value, so nested
  sections never clear the outer guard early. A wrapper entered with the guard set
  forwards without consulting rules.
- The guard is per library and does not suppress other libraries. Rule files, status
  files and hits files are read and written with raw system calls (`chaos_status.h`), so
  `libchaos-io` rules never apply to this library's own file access.
- Symbols are resolved once with `chaos_once()` (not `pthread_once()`, which lives in
  libpthread before glibc 2.34), from the constructor or the first wrapper call,
  whichever comes first. A lookup `dlerror()` reports as failed calls `abort()`, except
  for `pthread_create`, `execveat`, `execvpe` and `fexecve`, which may be absent and are
  looked up without aborting. Fallbacks for a NULL pointer: §2 (`EAGAIN`), §3 (`ENOSYS`),
  §4.2 (`ENOSYS`), §6 (`SYS_execve`, `SYS_execveat`, `ENOSYS`), §7.1 (`SYS_wait4`,
  `SYS_waitid`).

---

## 13. PRNG Model

xorshift64* per thread, identical across the libraries
([MEMORY.md §15](MEMORY.md#15-prng-model)): process seed from 8 bytes of `/dev/urandom`
read with raw system calls in the constructor (fallback `0x6a09e667f3bcc909 ^ getpid()`);
thread seed `SplitMix64(process seed ^ gettid() ^ &local) | 1`; step
`>>12, <<25, >>27`, output the upper 32 bits of `x * 0x2545f4914f6cdd1d`; fire when
`sample < p * 2^32`. The atfork child handler zeroes the forking thread's state so
pre-fork workers do not decide alike.

---

## 14. Config Reload Protocol

Same two-snapshot design as the other libraries
([MEMORY.md §16](MEMORY.md#16-config-reload-protocol--two-snapshot-cas)), with
`CHAOS_PROCESS_MTIME_MISSING` (`0x0`), `CHAOS_PROCESS_MTIME_RELOADING`
(`0xfffffffffffffffe`) and `CHAOS_PROCESS_MTIME_UNKNOWN` (`0xffffffffffffffff`).

- The rule file is looked at no more than once per 1 ms per process, timed with the vDSO
  `CLOCK_MONOTONIC` (every lookup where there is no vDSO clock). The constructor loads it
  once, so a bad file is reported at start-up.
- The change stamp hashes mtime (s, ns), size, inode and device; a file stamped within
  20 ms of now is re-read on the next look and kept, counters included, if its content is
  unchanged.
- One thread reloads (CAS of the stamp to `RELOADING`); others keep the active snapshot.
  Publishing resets the FAIL_AFTER counters (§9.3), then flips the index and stores the
  stamp behind full barriers. Rules with unchanged text keep their hit slot and `@first`
  claims.
- Readers copy a rule under the snapshot's sequence counter and discard a torn copy.
- A reload leaves the caller's `errno` untouched.
- In a forked child the atfork handler releases an inherited `RELOADING` claim, resets
  FAIL_AFTER counters, hit counts and `@first` claims, reseeds the PRNG and picks the
  child's own hits file.

**Hits file** `/tmp/.chaos-process.hits.<n>`: one `count<TAB>rule text` line per rule;
`<n>` is the pid, or `pid × 10^9 + salt` when a file of that pid exists (for example the
one of the image an `execve` replaced). Written on each of the first 64 hits, then at most
every 100 ms, on the next rule-file look after that interval, and at normal exit (not
after a successful `execve`).

---

## 15. Non-Coverage: clone/clone3, vfork, kill, pthread_kill

| Function       | Why not wrapped                                                                                       |
|----------------|-------------------------------------------------------------------------------------------------------|
| `clone(2)`     | The libc wrapper's child runs a function on a caller-supplied stack, with arch-specific register and stack conventions; libc's own users call it internally, so a wrapper would see only direct callers. SECCOMP mode sees every `clone`. |
| `clone3(2)`    | No libc wrapper in glibc or musl for applications; system call only.                                  |
| `vfork(2)`     | §5.                                                                                                   |
| `kill(2)`, `tgkill(2)`, `pthread_kill(3)` | Signal delivery, not lifecycle; would need a separate effect model.                         |

---

## 16. glibc vs musl Divergence per Symbol

| Symbol             | glibc                                                       | musl                                         |
|--------------------|-------------------------------------------------------------|----------------------------------------------|
| `pthread_create`   | in libc from 2.34, libpthread before (resolved on demand, §2) | in libc                                    |
| `fork`             | `clone(CLONE_CHILD_SETTID \| CLONE_CHILD_CLEARTID \| SIGCHLD)` | `SYS_fork`, or `clone(SIGCHLD)` where no fork syscall exists |
| `posix_spawn(p)`   | `__spawnix`: `clone(CLONE_VM \| CLONE_VFORK)`               | `__posix_spawnx`: `clone(CLONE_VM \| CLONE_VFORK)` |
| `system`, `popen`  | internal posix_spawn (2.29+)                                | internal posix_spawn                         |
| `execveat`         | exported from 2.34                                          | not consistently exported; wrapper falls back to `SYS_execveat` |
| `waitpid`          | `wait4` system call                                         | `wait4` system call                          |

Neither libc routes `posix_spawn()`, `system()` or `popen()` through the exported
`fork()`, and neither routes the exec family through the exported `execve()`; the
wrappers exist because of that, and the behaviour is the same on both.

---

## 17. Execution Boundary Summary and Limits

`libchaos-process` operates at the libc process and thread boundary of one process.

Covered:

- `pthread_create()`: thread exhaustion, pool saturation
- `fork()`: process-table exhaustion
- `posix_spawn()`, `posix_spawnp()`, `system()`, `popen()`: spawn failure
- `execve()`, `execveat()`, the exec family: exec denied (`noexec`, permissions, missing file)
- `waitpid()` and the wait family: `EINTR` and `ECHILD` handling, zombie accumulation

Not covered:

- raw `clone()`/`clone3()` system calls and runtimes that issue them (Go, Rust without
  libc, Zig); SECCOMP mode covers those
- `vfork()` (§5)
- `kill()`, `tgkill()`, `pthread_kill()`
- libc-internal process creation (the clone inside `posix_spawn`, threads libc creates)
- statically linked binaries (SECCOMP mode covers them)

Limits:

| Limit                          | Value                                  |
|--------------------------------|----------------------------------------|
| Rules per file                 | 256                                    |
| Rule file size                 | < 262144 bytes (256 KiB)               |
| Rule text in status/hits files | 200 bytes                              |
| LATENCY                        | 0 .. 4294967295 ms                     |
| FAIL_AFTER count               | 0 .. 2^64−1                            |
| Rule-file look interval        | ≥ 1 ms per process                     |

---

<div align="center">

*Architecture, implementation, and documentation crafted with Love and Passion by*

**[Christian Schnapka](https://macstab.com)**  
Embedded Principal+ Engineer  
[Macstab GmbH](https://macstab.com) · Hamburg, Germany

*Building systems that operate correctly at the edges — including the ones you deliberately break.*

</div>
