# Data effects and clock effects in SECCOMP mode — design

Status: design, validated by experiment where marked. Implements §7 of the 2.1.0 plan
(L18 data effects and RESET, L20 clock effects, L21 matching after a user switch).

This document exists because §7 was the one part of the release that could not be built
from the plan as written: two of its questions had no answer in it, and one of its answers
was more complicated than the kernel requires. Each section states what was measured, on
what, and what remains open.

---

## 1. Why ptrace at all

A `SECCOMP_RET_USER_NOTIF` reply can do three things: let the call run unchanged, fail it
with an errno, or return a value without running it. The supervisor can also read and
write the tracee's **memory** while a call is parked — it already does, for net `TIMEOUT`,
through `process_vm_readv`/`process_vm_writev` (`chaos_init_proc.c`).

What it cannot do is reach the tracee's **registers**. That is the whole gap:

| Effect | What it needs | USER_NOTIF |
|---|---|---|
| `TORN`, `TRICKLE` | shorten the length argument before the kernel reads it | register write — no |
| `CORRUPT` | flip a bit after the call filled the buffer | a second stop after the call — no |
| `DUP` | replay the previous payload on the next receive | a second stop, plus memory — partly |
| `RESET` | run `setsockopt(SO_LINGER)` *before* the notified `close` | a reply runs the notified call or none — no |
| time `OFFSET`/`REGRESS`/`FREEZE` | change a value the kernel never returns (vDSO) | not a system call at all — no |

`SECCOMP_RET_TRACE` plus `PTRACE_O_TRACESECCOMP` gives a stop at syscall entry with full
register access, and `PTRACE_SYSCALL` gives the matching stop at exit. That is what the
first four need. The clock effects need neither: they need the vDSO patched (§4).

---

## 2. Tracer identity — measured, no split needed

**The question.** `chaos_init_proc.h` records that chaos-init as PID 1 is an ancestor of
every process "but its background copy is not". ptrace stops are reported to the tracer
and only the tracer may `waitpid`. Must the process running the USER_NOTIF loop be a
different one from the tracer?

**The answer: no.** The parent that runs the `poll()` loop is the natural tracer:

- `PTRACE_TRACEME` is called by the child on itself, before it installs the filter and
  before `exec`. It needs no capability — unlike `pidfd_getfd`, which is what
  [SECCOMP.md](../SECCOMP.md) used to give as the reason RESET was impossible.
- That makes the **fork parent** the tracer, and the fork parent is the process that owns
  the listener and runs the loop.
- ptrace stops reach it as `SIGCHLD`, which the loop already multiplexes through its
  signalfd, and it already calls `waitpid` there.

**Measured.** A spike installed one filter answering `sched_yield` with
`SECCOMP_RET_TRACE | 0x1234` and `sync` with `SECCOMP_RET_USER_NOTIF`, handed the listener
to its parent over a socketpair, and made both calls. The parent received the ptrace
seccomp-stop (event `PTRACE_EVENT_SECCOMP`, `PTRACE_GETEVENTMSG` = `0x1234`) **and** the
notification for the same child, answered both, and the child exited 0. Linux 6.x, arm64,
Docker.

### 2.1 The one hard constraint, found by deadlocking on it

The first run of that spike hung. The filter notified `getpid`, and glibc's `raise()` calls
`getpid` internally: the child blocked in the notification while the parent blocked in
`waitpid`. Neither was wrong on its own.

**Rule:** the serve loop must never block on one of its two channels while the other has
work. The existing `poll()` over {signalfd, timerfd, listener} satisfies this by
construction — a blocking `waitpid` in the loop would not. Any change to the loop has to
keep that property, and a blocking `SECCOMP_IOCTL_NOTIF_RECV` is only safe because `poll()`
reported the listener readable first.

The related constraint is the one chaos-init already lives with: a syscall the supervisor's
own handover needs must not be notified. That is why exactly one `sendmsg` flag combination
is exempt (SECCOMP.md §3.1).

### 2.2 What stays out of reach

A process the background copy adopts (chaos-init not PID 1, §7 of SECCOMP.md) is not its
child, so `PTRACE_TRACEME` never made it a tracer of it. ptrace-based effects therefore
apply only where chaos-init is PID 1, which is the documented normal case. Rules of the
notification path keep working there; the traced effects report `unsupported` instead.

---

## 3. Scratch memory in the tracee — the plan's `mmap` injection is not needed

**The plan's design.** Inject an `mmap` into the tracee, because `process_vm_writev` can
write but not allocate.

**Simpler, and enough for both users of it:**

- **`RESET`** needs a `struct linger` (8 bytes) at an address the tracee can pass to
  `setsockopt`. At a syscall-entry stop the tracee's stack below the stack pointer is
  dead space: write the 8 bytes there, point the injected call at them, restore the
  original bytes afterwards. One `process_vm_readv` to save, two writes.
- **The clock state** (§4) has to be readable by code running *in* the tracee, with no
  syscall. It goes into the vDSO page itself, which is already mapped, already readable,
  and private — see §4.2.

Neither needs a new mapping, so §7.1 of the plan disappears as a work item. What remains
is the save/restore discipline, which belongs to the RESET injection and is tested with it.

---

## 4. Clock effects (L20) — vDSO patching

### 4.1 Measured on arm64

Dumped from a running process (`getauxval(AT_SYSINFO_EHDR)`), Linux 6.x, arm64:

| Symbol | Offset | Size |
|---|---|---|
| `__kernel_clock_gettime` | `0x2c0` | 660 bytes |
| `__kernel_gettimeofday` | `0x558` | 428 bytes |
| `__kernel_clock_getres` | `0x708` | 108 bytes |
| `__kernel_rt_sigreturn` | `0x7a0` | 8 bytes |

Loaded span 2312 bytes of a 4096-byte page: **1784 bytes of the mapped page are past
everything the vDSO loads.**

Two facts follow. First, a stub plus its state fits inside the function it replaces, with
room to spare. Second, **arm64 has no `__kernel_time`**: `time()` is not a vDSO symbol
there, so the plan's "scope: CLOCK_REALTIME/_COARSE, gettimeofday, time" is one symbol
smaller than it says on that architecture. amd64 exports `__vdso_time` and has to be
measured in CI — under QEMU the vDSO is not the host's, so this machine cannot answer it.

### 4.2 Consequence for the design

The patcher reads the symbol's size out of the tracee's own vDSO and patches only when
`size >= stub + state`. Anything else reports `unsupported` with the reason rather than
writing a stub that overruns the next function. The state lives at the tail of the same
symbol, so the stub reaches it with a fixed relative offset and the supervisor finds it
again through the same symbol lookup.

Writing through `/proc/<pid>/mem` with `FOLL_FORCE` triggers copy-on-write on the private
vDSO mapping, so the patch is process-local. That property is what makes this safe in a
shared container and belongs in SECCOMP.md once built.

---

## 5. Open — to be measured in CI, not here

1. **amd64 vDSO symbol sizes**, including `__vdso_time`. This host cannot answer it.
2. **Notification round-trip and ptrace-stop cost.** Docker Desktop runs a Linux VM, so
   absolute numbers here are not a budget. The shape to measure in CI: one notified call,
   one traced call (two stops), and `TRICKLE:1` on a busy reader, which is the case the
   plan names as critical.
3. **Which syscalls get `SECCOMP_RET_TRACE`.** A filter is fixed when it is installed, and
   the child installs it before the parent has read any rule file. Tracing the whole io/net
   syscall set would put two stops on every read and write for users who load no data
   effect at all. The intended answer is to let the parent read the rule files first and
   hand the needed set to the child over the socketpair it already has, so a run without
   data effects keeps today's cost exactly. This is the next decision to settle, and it is
   the one that decides whether §7 is cheap or expensive in practice.
