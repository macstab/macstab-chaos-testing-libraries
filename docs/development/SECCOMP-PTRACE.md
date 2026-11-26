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

### 4.2 What was built instead: no stub at all

A stub would have meant hand-written machine code per architecture, a state page, and a
copy of the kernel's timekeeping arithmetic -- for a property nobody asked for (cheap
reads) at the price of the one thing this release is about (reads that are *seen*).

The cheaper way in is the **lookup**. The C library and the Go runtime find the vDSO's
functions by name at startup and keep the address; every one of them carries a fallback to
the system call for the case where the symbol is not there (glibc's `INLINE_VSYSCALL`,
musl's `__vdsosym`, Go's `vdsoClockgettimeSym`). So the supervisor renames the time
symbols in the tracee's copy of the mapping, at the `execve` stop, before the new image
has run one instruction. From then on the clock is read through the kernel, where the
filter and the deciders already work -- and the effects are the deciders', not a stub's.

Measured on arm64, with the renaming done at the exec stop of a child:

| Program | Clock reads seen by the filter |
|---|---|
| glibc, three `clock_gettime(CLOCK_REALTIME)` | 3 |
| musl, the same | 3 |
| static Go (CGO_ENABLED=0), one `time.Now()` pair | 12 |

Before the renaming: **zero** for all three. The Go figure is the whole runtime's reads,
not only the program's, which is why the filter tests the clock argument and notifies only
the clocks a rule names -- `time.Now()` takes its monotonic reading from the same call,
and a wall-clock rule leaves that clock to the kernel.

What this costs: one notification per read of a named clock, and a plain system call
instead of a vDSO call for every other read of that image. What it saves: no machine code,
no state page, no architecture-specific arithmetic -- and `usleep` is the only time rule
SECCOMP mode has to reject.

Writing through `/proc/<pid>/mem` with `FOLL_FORCE` triggers copy-on-write on the private
vDSO mapping, so the change is process-local: no other process in the container, and no
other container, sees it. An image that cannot be written (not dumpable, or it changed
user before its exec) keeps its vDSO; that is reported as `vdso=failed` in the status file,
because a time rule that looks applied and does nothing is the failure this release is
about.

---

## 5. Open — to be measured in CI, not here

1. **amd64 vDSO symbol names.** The renaming list covers both spellings
   (`__kernel_*` and `__vdso_*`) plus the unversioned aliases and `__vdso_time`, which
   arm64 does not export. That the amd64 list is complete has to be seen in CI: a symbol
   left behind means clock reads that stay invisible, which the `vdso=failed` flag does
   *not* catch (nothing failed; the lookup simply succeeded).
2. **Notification round-trip and ptrace-stop cost.** Docker Desktop runs a Linux VM, so
   absolute numbers here are not a budget. The shape to measure in CI: one notified call,
   one traced call (two stops), and `TRICKLE:1` on a busy reader, which is the case the
   plan names as critical.
3. **amd64 register map.** The entry stop was proven on arm64 (`NT_PRSTATUS`,
   `struct user_pt_regs`, args in `regs[0..5]`, number in `regs[8]`). x86_64 needs
   `user_regs_struct`, args in `rdi, rsi, rdx, r10, r8, r9` and the number in `orig_rax`,
   and the rule that the number may not be changed to another call through `orig_rax` at a
   `RET_TRACE` stop. Same shape, different table; measured in CI.

---

## 6. Which syscalls get `SECCOMP_RET_TRACE` — decided

### 6.1 The constraint that settles it

Filters stack, and the kernel takes the highest-precedence action of all of them:
`KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW`
([kernel documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)).

**`USER_NOTIF` outranks `TRACE`.** Two consequences, and they decide the design:

1. A syscall that any filter notifies can never be traced. Installing a second filter later
   to "add tracing" to an already notified call does nothing.
2. Every notified syscall must therefore be assigned to exactly one of the two paths when
   the filter is installed — and the filter is installed by the child, before it execs.

### 6.2 The options, measured against that

| | Cost per intercepted call | Verdict |
|---|---|---|
| **A. Trace set from the loaded rules** | today's cost when no data effect is loaded; two stops only on syscalls that have one | **chosen** |
| B. Trace the whole `--libs` set | two stops on every read and write, for everyone | rejected |
| C. Rewrite syscall sites in the tracee (zpoline class) | ~200–500 ns | rejected for 2.1.0 |
| D. Notification only, no ptrace | cannot do it at all | not an option |

Published figures for the orders of magnitude: a user-space monitor reached through ptrace
or seccomp user notification costs **2658–12019 ns per call**, while mechanisms that stay
in the process (`LD_PRELOAD`, binary rewriting) or in the kernel cost **198–487 ns**
([lazypoline, 2024](https://gulmezmerve.github.io/files/2024-lazypoline.pdf)). So option B
is a factor of 10 to 60 on every read of every process in the container, which no chaos
test is worth. Option C is the fast one, but
[zpoline](https://www.usenix.org/system/files/atc23-yasukata.pdf) is x86-64 only — it needs
address 0 mapped and rewrites the two-byte `syscall` instruction — and the arm64 equivalent
is [a 2024 paper](https://arxiv.org/pdf/2412.05784), not something a C99 library with no
dependencies ships on four tuples. It is also the mechanism `LD_PRELOAD` mode already
covers; chaos-init exists for the static and Go cases, where the per-call cost is paid only
by calls a rule actually names.

### 6.3 What option A means concretely

- The **parent** reads the rule files before the go signal — it already reads them, just
  later — works out which operations carry a traced effect, and hands that syscall set to
  the child over the socketpair that already carries the listener.
- The child builds one filter: `TRACE` for those numbers, `USER_NOTIF` for the rest of its
  `--libs` set, `ALLOW` for everything else.
- For a syscall on the trace path, **every** effect runs from the ptrace stop, including
  `ERRNO` and `LATENCY`: the precedence rule leaves no way to split them. Failing a call
  from the entry stop is setting the return register and skipping the call; delaying it is
  the existing delay queue, with the continue issued when due, because the loop must not
  block (§2.1).
- A run that loads no traced effect installs exactly the filter it installs today and
  behaves identically. That is the property worth having.

### 6.4 The limitation this buys, stated plainly

A filter cannot be changed after it is installed. A rule file that **gains** its first data
effect for an operation while the container runs cannot start tracing that operation: the
rule loads, and it is reported `unsupported in seccomp mode` until the container restarts.
Reload keeps working for everything else, including adding more rules of an effect already
on the trace path.

This is seccomp's design, not a shortcut. The alternative is option B's cost for every user
on every call, which is worse, and tracing a set that a later rule file might need is
guesswork that costs the same.
