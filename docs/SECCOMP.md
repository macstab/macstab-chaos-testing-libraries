# SECCOMP mode: chaos-init

LD_PRELOAD cannot reach statically linked programs: Go built with `CGO_ENABLED=0` and
`FROM scratch` C programs never run a dynamic loader
([PLATFORM.md §7](PLATFORM.md#7-statically-linked-binaries)). `chaos-init` applies the
same rule files to them from outside the process: it runs the application under a
seccomp filter whose matching system calls are reported to it (seccomp user
notification, Linux 5.5+) and answers each one by the libraries' rules.

It is a second injection mode, not a replacement. Dynamically linked programs keep
LD_PRELOAD, which reaches more effects (data-changing effects, ERRNO on close, dns,
time) and decides inside the process, without a round trip to a supervisor per call
(§7, Cost).

| | |
|---|---|
| Binary | `chaos-init`, static, one per architecture (x86_64, aarch64); serves glibc, musl and libc-less images |
| Command line | `chaos-init --libs <io,net,dns,time,memory,process> -- <command> [args...]` |
| Libraries applied | io, net, dns (`LATENCY` only), time, memory, process |
| Effects applied | ERRNO, LATENCY; net TIMEOUT; process FAIL_AFTER |
| Mode status file | `/tmp/.chaos-init.status` |
| Rule, status and hits files | those of the libraries: `/tmp/.chaos-<lib>.conf`, `.status`, `.hits.<n>` |
| Sources | `src/init/`; rule cores compiled in from `src/<lib>/` and `src/common/` |

---

## 1. Model

```text
container PID 1: chaos-init --libs io,net -- <entrypoint> [args...]
  │
  ├─ fork ─► child: probe install, no_new_privs, seccomp filter with a notification
  │                 listener, hands the listener back over a socketpair, waits for
  │                 SIGUSR1 ("go"), execs the entrypoint
  │
  └─ supervisor: writes /tmp/.chaos-init.status, sends "go", then answers every
       notified system call
       ├─ decides it with the libraries' own rule cores (parsing, reload,
       │  matching, qualifiers, status and hits files: the same source files)
       ├─ fails it (errno), delays it (LATENCY, in a timer queue), returns a
       │  value without running it (poll TIMEOUT), or lets it run
       ├─ forwards termination and user signals, reaps orphans
       └─ exits with the application's exit code (128 + signal if killed);
          when it is not PID 1, a background copy goes on answering the
          processes the application left behind until the last of them ends
```

- **One core, two front ends.** `chaos-init` compiles each library's rule core
  (`chaos_<lib>_config.c`, `chaos_<lib>_actions.c`, the shared `src/common` headers)
  unchanged, as the unit tests do. `src/init/chaos_init_<lib>.c` only turns a notified
  system call into what the library's wrapper would pass to the core. The rule
  grammar, precedence, probability, qualifiers, all-or-nothing parsing, reload and
  status files are therefore identical in both modes.
- **Only the requested libraries' system calls** are passed to the supervisor; every
  other call is allowed by the filter in the kernel and costs nothing extra.
- **Per process, as with the libraries.** A supervised process is identified by its
  tgid, its start time (`/proc/<pid>/stat` field 22) and its image (fields 26 and 28,
  start of code and stack, which change with every `execve`). Per process and library,
  chaos-init keeps one hit slot per rule: `@first` claims and hit counts are per
  process, follow rule texts across reloads, and each process writes its own
  `/tmp/.chaos-<lib>.hits.<n>`. A program an `execve` starts is a new process, as under
  LD_PRELOAD: its counts start over, and its hits go to a file of its own beside the
  replaced image's.
- **FAIL_AFTER** counts per operation and process, from 0 again after a reload. A
  forked child starts with the counts its parent had at that fork (the first new
  process whose parent made the fork takes them over). **This differs from LD_PRELOAD**,
  where the library's atfork handler resets the child's counters to 0
  ([PROCESS.md §9.3](PROCESS.md#93-counter-reset)).

### 1.1 Start-up Sequence

1. Parse `--libs` (comma-separated, from `io`, `net`, `dns`, `time`, `memory`,
   `process`); anything else prints the usage and exits 2.
2. `prctl(PR_SET_CHILD_SUBREAPER)`, so orphans are reaped even when chaos-init is not
   PID 1. Block SIGCHLD and the forwarded signals before forking, so none is lost while
   the child starts.
3. Resolve the command like `execvp()` would (default `PATH`
   `/usr/local/bin:/usr/bin:/bin`), once, in the supervisor: the child then runs a single
   `execve` of the right file instead of one per `PATH` entry, and only the
   application's first `execve` is exempt from the process rules (§5).
4. With `net`: probe whether the kernel offers MPTCP (§3.2).
5. Fork. The **child**:
   - builds the filter (§1.4) and rejects kernels before 5.5 (`uname` release);
   - asks `SECCOMP_GET_ACTION_AVAIL` for `SECCOMP_RET_USER_NOTIF`;
   - tries `no_new_privs` + install in a throw-away grandchild first. `no_new_privs`
     cannot be undone, so it is set in the child only once the install is known to work;
     an application started without chaos also runs without `no_new_privs`;
   - sets `no_new_privs` and installs the filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER |
     SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, retrying without the second flag on
     `EINVAL` (kernels before 5.19);
   - sends `{error}` and, on success, the listener (`SCM_RIGHTS`) over the socketpair;
   - waits for SIGUSR1 with `sigwait()`, restores the original signal mask, adds
     `multipathtcp=0` to `GODEBUG` if §3.2 asks for it, and `execv()`s the command. A
     file the kernel will not execute (`ENOEXEC`) is run as `/bin/sh <path> args...`, as
     `execvp()` does.
6. The **supervisor** receives the listener, checks that the kernel's notification
   structures fit its 512-byte buffers (`SECCOMP_GET_NOTIF_SIZES`), starts the requested
   rule cores, writes `/tmp/.chaos-init.status` (creating `/tmp` with mode 01777 if the
   image has none), and only then sends SIGUSR1: whoever sees the application running
   reads this run's status.
7. Main loop: `poll()` on a signalfd, a `CLOCK_MONOTONIC` timerfd and the listener.

### 1.2 Answering a Notification

```text
SECCOMP_IOCTL_NOTIF_RECV                (EINTR / ENOENT: nothing to answer)
  ├─ a parked call restarted by the kernel (before 5.19)? → keep its due time and verdict
  ├─ decide: net → io → memory → process (first library that claims the call)
  ├─ verdict ≠ run: SECCOMP_IOCTL_NOTIF_ID_VALID
  │     ENOENT → the thread is gone (its pid may be reused); drop
  │     any other error (5.5–5.8 know the request under an older number) → answer anyway
  ├─ TIMEOUT: write "nothing ready" into the caller's buffers
  ├─ DELAY: park until now + delay + 1 ms (queue full: no delay, rest of the verdict now)
  └─ SECCOMP_IOCTL_NOTIF_SEND: error = -errno | val = value | FLAG_CONTINUE
```

- The supervisor is single-threaded. A delayed call is parked in a queue of 1024 entries
  (`chaos_init_delay.c`) and answered from the timer, so other threads of the
  application are not delayed with it. Whole-millisecond clock reads round down; the
  extra 1 ms keeps a delay from ending short.
- The validity check closes the window between reading the thread's memory and acting
  on it. A reply goes by notification id and never reaches another thread, so answering
  despite an inconclusive check is safe, while leaving a call unanswered would block
  the thread for good.
- `FAIL` replies make the system call return `-1` with the errno without running it.
  `CONTINUE` lets the kernel run the original call; it is not a sandbox and gives no
  protection against argument changes after the decision (seccomp's documented
  `CONTINUE` caveat), which a fault injector does not need.

### 1.3 Signals, Reaping, Exit

- Forwarded to the application: SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
  SIGWINCH, SIGALRM, SIGPIPE. SIGCHLD reaps every exited process (`waitpid(-1, WNOHANG)`).
- When the application exits, all pending hits files are written. They are the libraries'
  own files, header lines and all: every library's hits file names the reload generation
  its counts belong to, and net adds its RESET suppressions, whichever mode produced them
  -- a reader correlates a count with a rule file version without knowing how the rules
  were applied. As PID 1, or when no
  listener exists, chaos-init exits with the application's code (`128 + signal` when it
  was killed). Otherwise it returns that code at once and a forked background copy, with
  stdio on `/dev/null`, keeps answering until the kernel reports that no process uses
  the filter any more (`POLLHUP` on the listener, Linux 5.8+).
- chaos-init's own exit codes: 2 usage, 125 set-up failure (socketpair, fork, handover,
  notification sizes, signalfd/timerfd), 126 command not executable, 127 command not
  found.

### 1.4 The Filter

`chaos_init_build_filter()` emits classic BPF, at most 128 instructions:

```text
load arch
  arch ≠ AUDIT_ARCH_X86_64 / AUDIT_ARCH_AARCH64     → ALLOW   (other ABIs pass, §7)
load nr
  [x86_64] nr ≥ 0x40000000 (x32 ABI)                → ALLOW
  [net]    nr == sendmsg:
              args[0] == handover fd && args[2] == MSG_NOSIGNAL|MSG_CMSG_CLOEXEC → ALLOW
              else                                   → USER_NOTIF
  nr ∈ { system calls of the requested libraries }  → USER_NOTIF
  else                                               → ALLOW
```

- **Handover.** The filter is active before the child sends the listener, and `sendmsg`
  is a net call. The one `sendmsg` on the child's end of the socketpair with exactly
  `MSG_NOSIGNAL | MSG_CMSG_CLOEXEC` passes (a flag combination no program uses;
  `MSG_CMSG_CLOEXEC` only means something to `recvmsg`). The descriptor is opened with
  `SOCK_CLOEXEC` and gone after `execve`. If the handover cannot be sent, the child exits
  (125) rather than run under a filter nobody answers. Taking the listener out of the
  child instead would mean `pidfd_getfd()`, which does need `CAP_SYS_PTRACE` over the
  target -- unlike `PTRACE_TRACEME`, which a tracee calls on itself and which needs no
  capability. The distinction matters because the effects §4 rejects are not blocked by
  privilege.
- Argument comparisons read the low 32 bits at the argument's offset; the build refuses
  big-endian targets.

System calls passed to the supervisor (those marked † exist on x86_64 only):

| Library | System calls |
|---------|--------------|
| io      | `openat`, `openat2`, `open`†, `creat`†, `read`, `readv`, `write`, `writev`, `pread64`, `preadv`, `preadv2`, `pwrite64`, `pwritev`, `pwritev2`, `sendfile`, `copy_file_range`, `ftruncate`, `truncate`, `fallocate`, `unlinkat`, `unlink`†, `rmdir`†, `renameat2`, `renameat`†, `rename`†, `close`, `fsync`, `fdatasync` |
| net     | `socket`, `socketpair`, `bind`, `listen`, `connect`, `accept4`, `accept`†, `shutdown`, `sendto`, `sendmsg`, `sendmmsg`, `recvfrom`, `recvmsg`, `recvmmsg`, `read`, `readv`, `write`, `writev`, `close`, `ppoll`, `poll`†, `pselect6`, `select`†, `epoll_pwait`, `epoll_wait`†, `epoll_pwait2` |
| memory  | `mmap`, `munmap`, `mprotect`, `madvise` |
| process | `clone`, `clone3`, `fork`†, `vfork`†, `execve`, `execveat`, `wait4`, `waitid` |

---

## 2. Usage

```sh
chaos-init --libs io,net,memory,process -- /usr/local/bin/nats-server -js
```

- Rules are written to `/tmp/.chaos-<lib>.conf` exactly as for the libraries and are
  reloaded the same way. The supervisor reads them itself; it is under no filter.
- A replaced rule file is read **when it is replaced**, not only when the next intercepted
  call arrives: the supervisor watches `/tmp` (inotify) for a rule file being renamed into
  place, written or removed, and reads it then. That matters for what the read writes --
  the library's status file -- because a test that puts rules in place and waits to see
  them accepted would otherwise wait for a call it has not made yet. Under `LD_PRELOAD`
  the constructor does the same at process start. The watch is on the directory because
  the file arrives by rename (`mv -f`), which a watch on the file itself never sees; a
  watch that cannot be created costs nothing, since the next intercepted call still reads
  the file. Two limits are unchanged by it: a rule file is stat'ed at most once per
  millisecond, so two changes inside one millisecond are read as one, and the **filter
  cannot be changed** after it is installed (§3.3).
- `/tmp/.chaos-init.status` reports whether the mode is active:

  ```text
  state=active
  libs=io,net
  pid=1
  mptcp=off          (only when §3.2 applies)
  vdso=failed        (only when an image kept its vDSO, §3.4)
  unreadable=yes     (only when a process could not be read, §7)
  ```

  The last two are written **after** the application started, the moment they happen: each
  says that rules of one kind cannot reach one process, which is the one thing this mode
  must not be quiet about.

  or

  ```text
  state=unsupported
  reason=<one of the reasons below>
  libs=io,net
  pid=1
  ```

  | `reason=`                                                        | Cause                                    |
  |------------------------------------------------------------------|------------------------------------------|
  | `kernel older than 5.5`                                          | `uname` release below 5.5                |
  | `seccomp user notification not available (emulated architecture?)` | `EINVAL`                              |
  | `seccomp not available in this kernel`                           | `ENOSYS`                                 |
  | `seccomp refused by the container's security settings`           | `EACCES` / `EPERM`                       |
  | `seccomp could not be installed`                                 | any other error (`EBUSY`: another listener) |

  With `state=unsupported` the application still starts, without chaos and without
  `no_new_privs`.
- The libraries' status files report each rule file as usual (written by the
  supervisor, so `pid=` is chaos-init's). A rule this mode cannot apply rejects its file
  there with `reason=unsupported in seccomp mode` (§4).

Builds: `make cross-init-amd64` / `make cross-init-arm64` (static, inside an image of
that architecture: `docker/Dockerfile.build` with `MAKE_TARGET=cross-init-<arch>`),
output `dist/chaos-init-<arch>`; or `make native-init`, output `build/chaos-init`.

---

## 3. What it applies

| Library | Applied | Matched on |
|---|---|---|
| io | ERRNO, LATENCY on open, read, write, pread, pwrite, close (LATENCY only), fsync, fdatasync, truncate, allocate, unlink, rename; DROP on pwrite; TORN and THROTTLE on write and pwrite, CORRUPT on read and pread and DROP on write and writev, through a ptrace stop (§3.3) | the path: absolute, or joined lexically to `/proc/<pid>/cwd` or to the directory descriptor's path; descriptors through `/proc/<pid>/fd`. As in the library, descriptors 0–2, paths under `/proc`, `/sys`, `/dev` and the `/tmp/.chaos-*` control files are never faulted |
| net | ERRNO, LATENCY on socket, bind, listen, connect, accept, shutdown, send, recv, close (LATENCY only), poll; TIMEOUT on the poll family; REDIRECT on connect, whose address the supervisor writes into the tracee before letting the call run; DROP on a datagram send (not `sendmmsg`); THROTTLE on a send, TRICKLE on a stream receive, CORRUPT and DUP on a receive, RESET on close, through a ptrace stop (§3.3) | the endpoint: sockaddr arguments from memory, a socket's own address and peer from `/proc/<pid>/net/*` or sock_diag (§3.2), its type from its `system.sockprotoname` attribute |
| memory | ERRNO, LATENCY on mmap (anon/file), munmap, mprotect, madvise | the arguments: operation, `mmap` flags, length for `@size` |
| process | ERRNO, LATENCY, FAIL_AFTER on pthread_create, fork, posix_spawn, execve, execveat, waitpid | the system call and clone's flags (§5) |
| time | ERRNO, LATENCY on a clock read and on nanosleep; OFFSET, REGRESS, FREEZE on a clock read, which the supervisor answers with a value of its own (§3.4) | the operation and, for a clock read, the clock in `args[0]`; a `usleep` rule is rejected, because libc sleeps through nanosleep |
| dns | LATENCY on a forward selector (§3.5) | the name in the query the resolver sends; the answer-changing effects and `rdns://` selectors are rejected |

Probability and all qualifiers apply (`@first`, `@from`, `@until`, `@size`). When a
LATENCY and an ERRNO rule both fire for one call, the call is delayed, then failed.

### 3.1 Details per Library

- **io.** `sendfile` and `copy_file_range` are writes to their output descriptor;
  `creat` is an open; `rmdir` is an unlink; renames are decided like `renameat()` in the
  library: the destination's rule when both sides match and its prefix is at least as
  long. `@size` uses the byte count argument, or the sum of an iovec array of at most
  1024 entries (larger or unreadable: no size, so `@size` rules do not match).
- **net.** `read`, `readv`, `write`, `writev` and `close` are net's on a socket
  (`/proc/<pid>/fd/<n>` links to `socket:[…]`) and io's on anything else. Endpoints are
  looked up only for operations a loaded rule is for: rules on connect alone leave recv
  and poll at the base cost. `send*` use the destination named in the call, else either
  end of the connection; a `sendmmsg` batch is matched on its first message whose
  destination or connection matches (at most 1024 messages). The wait calls scan their
  descriptors as the library does: the pollfd array and fd_sets from memory, an epoll
  instance's descriptors from `/proc/<pid>/fdinfo/<epfd>`, up to 1024 per call.
- **net TIMEOUT.** As in the library, the wait's own timeout is waited out (rounded up
  to whole milliseconds), then it returns 0: `revents` of the pollfd array and the
  fd_sets are cleared, `select()`'s timeout is set to 0; epoll writes no events. A
  timeout of 0 returns at once. A wait without a timeout, or with one the kernel would
  refuse, is left alone.
- **memory.** `mmap/anon` versus `mmap/file` is decided by `MAP_ANONYMOUS` in the flags
  argument.

### 3.2 Multipath TCP

Go listens with Multipath TCP by default from 1.24 where the kernel offers it. MPTCP
sockets appear in no `/proc/<pid>/net` table, so chaos-init asks sock_diag for them, as
`ss` does: an `inet_diag_req_v2` dump with the protocol in an `INET_DIAG_REQ_PROTOCOL`
attribute (the protocol number 262 does not fit the request's own byte; Linux 5.10+).
The answer describes the supervisor's network namespace, which is the container's.

sock_diag lists MPTCP sockets by their MPTCP token. A connection that an MPTCP listener
accepts from a plain TCP client falls back to TCP and has no token, yet stays an MPTCP
socket (`system.sockprotoname` "MPTCP"): it is in no sock_diag MPTCP dump and in no
`/proc/net` table, so its endpoints cannot be resolved, even where `mptcp_diag` exists.
Every plain TCP client of a Go 1.24+ server (a JVM test, `redis-cli`, a health check)
creates such a connection.

At start-up, with `net` requested, chaos-init therefore checks only whether the kernel
offers MPTCP (an `IPPROTO_MPTCP` socket can be created):

- No MPTCP: Go uses plain TCP by itself; nothing to do.
- MPTCP available: the application's `GODEBUG` gets `multipathtcp=0` appended, so Go uses
  plain TCP and net rules match, and the status file says `mptcp=off`. A `multipathtcp=`
  setting of the user's own (first, or after a comma) is kept unchanged; the status still
  reports `mptcp=off`.

MPTCP sockets a program opens explicitly (not Go's default) are still looked up through
sock_diag where `mptcp_diag` exists; their fallback connections stay unresolvable.

---

### 3.3 Effects that need the registers, not a reply

A notification reply can fail a call, delay it or return a value. It cannot reach the
tracee's registers, and `TORN` lives exactly there: it shortens the byte count *before*
the kernel reads it, as `TRICKLE` and `THROTTLE` do. Such a call is answered by the
filter with `SECCOMP_RET_TRACE` instead, which stops the thread with its registers
readable and writable.

- The set of traced calls comes from the **rule file**, read by the child before it
  installs the filter. `read` is shared between io and net, so a net `TRICKLE` rule puts
  every read on the trace path, file reads included: a filter has one action per system
  call number. Correct either way -- the same deciders run -- but the cost spreads.
  The alternative, leaving `read` notified, would make `TRICKLE` silently miss every
  program that receives with `read()`. A run whose rules need no register gets byte for byte the filter
  this supervisor always built, so it costs exactly what it used to.
- An effect on what a call *returned* -- `CORRUPT` flips a bit of the bytes a read or a
  receive delivered, `DUP` keeps them for the next receive -- cannot be decided when the
  call has not run. Such a thread is continued into its syscall-exit stop and decided again
  there, with the result known. The call is carried from the first stop to the second in a
  table of at most 256 threads, because the return value overwrites the first argument
  register on aarch64: the descriptor is gone by the second stop, while the buffer and the
  count are still there. More threads inside such a call at once than the table holds means
  the call runs without the effect. `CORRUPT` draws at the second stop, so a read or
  receive that delivered nothing counts no hit, exactly as in the library.
- `DUP` uses both stops for one effect. At the entry stop it asks whether a payload is
  kept for the socket: if none is, the receive runs and the exit stop keeps what it
  delivered, with no draw -- keeping is not a hit. If one is, the rule is drawn there and a
  hit returns it from the reply, without the call running; the draw that does not fire lets
  the receive run and replace the payload. Each payload replays once. The payloads live in
  the supervisor, 16 sockets' worth of at most 4 KiB, keyed by socket inode and evicted
  oldest first -- which is also the one place this mode differs from the library, where the
  table belongs to the address space rather than to the socket (NETWORK.md).
- An effect that needs a **second system call** to keep the descriptor consistent runs
  that call in the tracee itself: at the stop, the number and the arguments are replaced by
  the ones the supervisor wants, the thread is continued with `PTRACE_SYSCALL`, and at the
  exit stop the tracee is told the value the original call would have reported rather than
  what the substituted one returned. `write:DROP` is that case -- a dropped write has to
  move the file offset on by the count it claims -- and the substituted `lseek` is not
  filtered again, because seccomp ran before the stop. The promised value is kept per
  thread, in a table of the same size as the parking one; no room for it means the call
  runs unchanged.
- `close:RESET` needs its second call to run **before** the original one rather than in
  its place: `SO_LINGER` has to be on the socket that the close then aborts. The
  `setsockopt` is substituted the same way, its `struct linger` written into the tracee's
  stack scratch -- 256 bytes below the stack pointer, clear of the x86-64 red zone and
  of anything the stopped thread keeps. At the exit stop the original call is put back:
  its number and arguments are restored and the program counter steps back onto the
  system call instruction, so the thread issues the close again. That second issue is
  filtered again, and a per-thread mark lets it through rather than deciding it twice.
  Everything the second stop needs is reserved before the substitution, so a table too
  full leaves the call alone instead of losing it.
- `THROTTLE` shortens the count like `TORN`, to what its token bucket allows, and needs
  one thing more than a register: somewhere to wait when the bucket is empty. The call is
  put in the delay queue of the supervisor, and the answer that delay turns into is a
  shortened call rather than a whole one -- the bytes the wait bought. They are charged to
  the bucket when the call is parked, not when it is let go, so two threads waiting on one
  descriptor are told to wait one after the other and the rate comes out the same as the
  rate the library enforces. The thread stays stopped meanwhile, so the other threads of
  the process keep being served, which is the one way this mode is better than sleeping
  inside the call. A non-blocking descriptor is told `EAGAIN` instead, as in the library;
  whether it is non-blocking is read from `/proc/<pid>/fdinfo/<fd>`, and a descriptor
  whose flags cannot be read counts as blocking.
- The ownership check `close:RESET` needs (`NETWORK.md` §RESET) reads the tracee's
  descriptor table rather than the supervisor's: the socket inode comes from the
  `/proc/<pid>/fd` link, and the table searched first is the thread's group leader's,
  because `/proc` lists no threads. A suppressed RESET is counted and published in the
  header lines of that library's hits file, which chaos-init writes as the library does.
- A call cannot be both notified and traced: across stacked seccomp filters `USER_NOTIF`
  outranks `TRACE`. A traced number therefore carries **all** of its effects through the
  stop -- an `ERRNO` rule on a traced call is injected by setting its return register, a
  `LATENCY` rule by leaving the thread stopped until its delay is up.
- `PTRACE_TRACEME` is called by the child on itself, so **no capability and no container
  change are needed**. The tracer is the same process that owns the listener and runs the
  serve loop.
- The filter survives `fork` and `exec`, and a `RET_TRACE` with no tracer fails the call
  with `ENOSYS`. Descendants are therefore attached as they appear
  (`PTRACE_O_TRACEFORK`, `TRACEVFORK`, `TRACECLONE`), which is what keeps a forked child
  of the application working.
- **A filter cannot be changed after it is installed.** A rule file that gains its first
  such effect for an operation while the container runs cannot start tracing it: the rule
  loads and does not fire until the container restarts. Everything else still reloads.
- While the application is traced, `strace` and debuggers cannot attach to it: a process
  has one tracer.

The design, the measurements behind it and the rejected alternatives are in
[docs/development/SECCOMP-PTRACE.md](development/SECCOMP-PTRACE.md).

### 3.4 Clock reads, which do not arrive by themselves

`clock_gettime`, `gettimeofday` and `time` are served from the **vDSO**, a page the kernel
maps into every process. The C library and the Go runtime look the symbols up there at
startup and call them directly: no system call, nothing for a filter to see. That is why
time rules applied nothing in this mode at all.

The way in is the lookup, not the code. At every `execve` -- a stop of its own
(`PTRACE_O_TRACEEXEC`), before the new image has run one instruction -- the supervisor
renames the vDSO's time symbols in that process's copy of the mapping. A lookup by name
then finds nothing, and glibc, musl and Go each fall back to the system call they carry
for that case. The write goes through `/proc/<pid>/mem`, which writes a read-only mapping
where `process_vm_writev` refuses, and because the mapping is private the page is copied
for that process alone: no other process, and no other container, is affected.

- **The read does not run.** A clock read a value-changing rule matches is answered by the
  supervisor: it reads the same clock, applies the effect and writes the value into the
  caller's buffer, then answers 0. The clock is read at the moment the answer goes out, so
  a read held back by LATENCY reports the time after its delay, as the library's does.
- **Only the clocks a rule names are notified.** `clock_gettime` carries the clock in its
  first argument, so the filter tests it: a rule on the wall clock leaves a monotonic read
  to the kernel. A rule that names no clock (`*` or `clock_gettime`) notifies every one.
  `gettimeofday` and `time` read the wall clock and nothing else, so a rule on another
  clock leaves them out of the filter too.
- **The cost is a notification per read of an affected clock**, instead of a vDSO call.
  Every other clock read of that process costs a system call rather than a vDSO call,
  because the fallback is permanent for the image. Measurements:
  [docs/development/SECCOMP-PTRACE.md](development/SECCOMP-PTRACE.md).
- **An image that cannot be written keeps its vDSO**, which is the one case where a time
  rule would look applied and do nothing: a process that is not dumpable, or that changed
  user before its `exec`. The status file then says `vdso=failed`, written again after the
  application started.
- **A `fork` child inherits the renamed mapping**; a child that execs gets a fresh vDSO
  and a stop of its own.
- `usleep` rules are rejected (§4): libc sleeps through `nanosleep`, so the supervisor
  cannot tell the two entry points apart and such a rule could never fire.

### 3.5 DNS queries, matched by the name in them

`getaddrinfo()` is a library function, so the lookup itself cannot be intercepted here.
What can be seen is the **query the resolver sends**, and that carries the name: a send
whose payload is a DNS question is matched by the name in it, which is what makes
`dns://api.example.com:LATENCY:500` work in a static binary -- the case LD_PRELOAD cannot
reach at all.

- **A query is recognised by its shape, not by a port.** The payload is parsed as a DNS
  message: one question, the answer bit clear, the opcode QUERY, and a `QNAME` of
  length-prefixed labels ending inside the payload. A query over TCP carries its length in
  front, which is skipped when it matches the rest. A port test would be weaker -- it needs
  the socket's peer, misses a resolver on another port, and still has to parse the name.
- The sends looked at are `sendto` (glibc and musl over UDP), `sendmmsg` (glibc asking for
  A and AAAA at once; the first message of the batch), `sendmsg` and `write` (a query over
  TCP). They are notified only while a `LATENCY` rule is loaded.
- **`LATENCY` is the only effect that survives.** The query is held, so the resolver sees a
  slow name server, which is what the rule says. Everything else libchaos-dns offers
  changes the *answer* (`GAI`, `REWRITE`, `OVERRIDE`, `SERVICE`, `FILTER_FAMILY`,
  `SHUFFLE`, `LIMIT`), and the answer is assembled inside the resolver: failing the send
  would produce whatever resolution error that resolver makes of it, not the `EAI_*` the
  rule names. Those rules are rejected (§4), as are `rdns://` selectors -- a PTR query
  carries `in-addr.arpa` labels, and the rule names an address.
- The same send is net's call as well. dns decides first, because the name is the narrower
  match; a send that is not a query falls through to net untouched.

---

## 4. Rejected rules

A rule the parser accepts but seccomp cannot carry out rejects its whole file, like an
invalid line, with its line number and `reason=unsupported in seccomp mode`. No rule of
that file applies. The rows that end in "counting no hit" are the exception: the rule
loads, and only the call forms named there are left alone -- the operation is the same for
`read` and `readv`, so the parser cannot tell them apart.

| Rule | Why not |
|---|---|
| io FREE, FULL | They rewrite the structure the kernel returned, which neither a notification reply nor a register reaches. |
| io TORN or THROTTLE on a vectored write, net TRICKLE or THROTTLE on `recvmsg`, `sendmsg` or a batch | The byte count of `writev`, `pwritev`, `sendmsg`, `recvmsg` and the batches is in memory, not in a register, so one argument cannot shorten it. The call runs whole and counts no hit, as in the library. |
| io CORRUPT on a vectored read, net CORRUPT or DUP on `recvmsg` or a batch | The bytes `readv` and `recvmsg` delivered are spread over segments, and finding the one that holds byte N, or filling them from a kept payload, would mean walking the iovec in the tracee. Left alone, counting no hit. |
| io and net ERRNO on close | The libraries close, then report the error, as Linux does for a failing close. A notified call either runs or fails, not both. |
| process `posix_spawnp` selector | The `PATH` search is in the C library; the system calls are those of posix_spawn, whose rules apply to it, so the rule could never fire. A `*` rule is accepted. |
| time `usleep` selector | libc serves `usleep` through `nanosleep`, so the filter cannot tell which entry point the program used: a `nanosleep` rule covers both and a `usleep` rule could never fire. |
| dns GAI, REWRITE, OVERRIDE, SERVICE, FILTER_FAMILY, SHUFFLE, LIMIT, and every `rdns://` selector | They change the answer, which the resolver assembles from what comes back: a reply to the query's send cannot produce the `EAI_*` or the address list a rule names, only some resolution error. A reverse selector cannot even be matched -- a PTR query carries `in-addr.arpa` labels (§3.5). |

The check is a build hook in the parsers (`CHAOS_IO_RULE_SUPPORTED`,
`CHAOS_NET_RULE_SUPPORTED`, `CHAOS_DNS_RULE_SUPPORTED`, `CHAOS_TIME_RULE_SUPPORTED`,
`CHAOS_PROCESS_RULE_SUPPORTED`; `1` in the libraries), so the
status file reports the rejection together with the load, never a passing `state=ok`
first.

---

## 5. How calls map to the libraries' operations

- `read`, `write`, `readv`, `writev` and `close` are net's on a socket and io's on
  anything else.
- `clone` with `CLONE_THREAD` is pthread_create. With `CLONE_VFORK` (glibc's and musl's
  posix_spawn, Go's os/exec) it is posix_spawn. Otherwise it is fork. `clone3` is
  classified by the flags at the start of its `struct clone_args`, read from the
  caller's memory (unreadable: fork). The `fork` system call is fork, `vfork` is
  posix_spawn. posix_spawnp cannot be told from posix_spawn: the path search is in the
  C library, so posix_spawn rules apply to it, and a posix_spawnp rule rejects its file
  (§4). `system()` and `popen()` are posix_spawn, as in the library.
- `wait4` and `waitid` are waitpid.
- The first `execve` of the application, the one that starts it, is never faulted. With
  LD_PRELOAD the library is not loaded at that point either. The exemption holds while
  the process still runs chaos-init's image, so a failed start and the `/bin/sh` retry
  for a script without `#!` are exempt too; the first `execve` from the application's
  own image is not. chaos-init looks a command without a `/` up on `PATH` itself, so the
  start is a single `execve` of the right file, not one per `PATH` entry tried.
- **Every call of the process counts, not only the program's own.** The libraries see
  the calls the program makes through their functions; chaos-init sees system calls,
  whoever makes them. The dynamic loader opening and mapping shared libraries, malloc
  and pthread_create mapping memory, and the `execve` inside `posix_spawn()` (or Go's
  os/exec) are calls like any other here. A dynamic program under
  `mmap/file:ERRNO:ENOMEM` or `/lib:open:EIO` fails to load (exit 127, "error while
  loading shared libraries"); an execve rule also fails the programs posix_spawn starts;
  a fork rule never fails `posix_spawn()` (its clone carries `CLONE_VFORK`). Narrow
  paths, `@size`, `@first` or `@from` keep a rule to the calls meant.
- `pthread_create` failures surface as the error the C library reports for a failed
  `clone`, normally the injected errno returned by `pthread_create()`.
- **Each process draws its own samples.** A rule's sample depends on the process it is
  evaluated in, because the supervisor gives every process it decides for a lineage of its
  own -- taken from the order the processes appeared in, which is the only ordering it can
  see. Without it the backends of a pre-forking server, each evaluating a rule for the
  first time, would all draw the same sample and `close:RESET:0.5` would reset every
  connection or none. The first process, the application itself, keeps lineage 0, so a
  single-process run decides exactly as it does under `LD_PRELOAD`; descendants decide
  differently between the modes, because the library mixes a child's ordinal among its
  siblings and the supervisor cannot see the fork topology. Both are reproducible under
  `CHAOS_SEED` ([`docs/DSL.md` §6.4](DSL.md#64-reproducible-faults-chaos_seed)).
- **net REDIRECT overwrites the caller's sockaddr**, where the library passes a copy and
  leaves it alone: the kernel reads that argument from the tracee's memory, and only a
  register could point it elsewhere. A program that keeps the sockaddr and dials it again
  reaches the target a second time, with no rule firing and no hit counted. Every runtime
  builds the address per connect, so this is a difference to know rather than one to
  work around (NETWORK.md, REDIRECT).

---

## 6. Not possible

- **dns, beyond `LATENCY`.** The query is reachable (§3.5) and so is the name in it, but
  the answer is the resolver's: no reply to a send produces a chosen `EAI_*` code or a
  chosen address list. Those rules are rejected rather than approximated.

---

## 7. Requirements and limits

| | |
|---|---|
| Kernel | 5.5 or newer (user notification with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Older: `state=unsupported`. 5.8+ for the end of a background copy (§1.3), 5.10+ for MPTCP lookups (§3.2), 5.19+ for killable waits (Signals). |
| Privileges | None beyond Docker's default profile: installing a filter under `no_new_privs` needs no capability. The child sets `no_new_privs`, so set-user-ID programs it starts do not gain privileges. It does so only once the filter is known to install (tried first in a process that ends at once): an application started in `state=unsupported` because the kernel, the profile or another supervisor's listener refuses it runs without `no_new_privs`. |
| Architecture | x86_64 and aarch64. Under emulation (amd64 on an arm64 host) seccomp user notification is unavailable: `state=unsupported`. Other ABIs (i386 `int 0x80`, x32) pass unfiltered. |
| Reading the process | Paths, addresses, iovec sizes and `clone3` flags are read from the process's memory (`process_vm_readv`; TIMEOUT writes with `process_vm_writev`), descriptors, sockets and identities through `/proc/<pid>`. This needs ptrace read access: a process of the same user that chaos-init started (Yama lets an ancestor read it even with `kernel.yama.ptrace_scope=1`; `2` or more forbids it). **A process that changes user** (a database server dropping privileges) becomes non-dumpable, and the kernel then refuses every look into it -- `process_vm_readv` with EPERM, the tracer's own ptrace reads with EIO (`ptrace_access_vm()` checks the dumpable flag even for the tracer), the `/proc/<pid>` links with EACCES. Since every io selector names a path and every net selector an endpoint, **io and net rules stop matching that process entirely**; memory, process and time rules match on arguments alone and keep working. The supervisor writes `unreadable=yes` into its status file the first time this happens, rather than leaving a rule looking applied. The cure is one line of container configuration: **`--cap-add SYS_PTRACE`**, with which the kernel allows the reads and path and endpoint rules match again. |
| Leftover processes | When chaos-init is not PID 1 (a shell or another init started it), processes the application left behind keep the filter. A background copy answers them until the last one ends, which the kernel reports from 5.8; on 5.5 to 5.7 that copy stays, idle, until the container stops. That copy is not their ancestor: where Yama lets only ancestors read a process's memory (`ptrace_scope=1`, the default on Ubuntu hosts), their path and endpoint rules do not match, as for a process that changed user (above). As PID 1, chaos-init is the ancestor of every process and this does not arise. |
| Signals | A call held back by LATENCY or TIMEOUT waits out its delay when signals arrive (Go signals its threads constantly); unlike under LD_PRELOAD, a TIMEOUT's wait does not end with `EINTR`. From 5.19 (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`) the waiting call cannot be interrupted except by a fatal signal, and handlers of signals that arrive meanwhile run after the delay. Before 5.19 the kernel restarts an interrupted call as a new notification; chaos-init recognises it (same thread, system call and arguments as a parked call), keeps the original due time and verdict, and does not count it again. |
| `posix_fallocate` | The wrappers interpose the library function itself, so an `allocate` rule always reaches it. Here only the system calls it makes are visible: glibc issues `fallocate(2)` (verified on glibc 2.36, overlayfs), which an `allocate` rule matches. Should the file system refuse `fallocate`, glibc emulates the call by writing instead; those writes are what the filter then sees, so `write` rules match and `allocate` rules do not. musl makes the system call and returns its error, with no emulation. |
| UNIX sockets | The peer of a UNIX socket is not in `/proc`. Rules on a UNIX socket's peer (send on a connected client) do not match. |
| Calls the filter does not see | io_uring, where the container's profile allows it (recent Docker default profiles do not), submits I/O without the system calls the filter knows, so its reads, writes and opens are never faulted. On x86_64, 32-bit calls (`int 0x80`, i386 programs) and x32 calls pass unfiltered. |
| Asynchronous submission | `io_submit(2)` (libaio) and `io_uring_enter(2)` hand the kernel a batch of operations in one call, so a rule on them acts on the **submission**, not on the reads and writes inside it: `ERRNO` fails the whole batch, and "every tenth read" cannot be expressed. Neither is in the filter, and neither is interposed under `LD_PRELOAD` -- `io_submit` lives in libaio rather than libc, and io_uring makes no per-operation call at all. A test that needs per-operation faults has to use an engine that issues one system call per operation (`libaio` off, `io_uring` off), which both PostgreSQL and MySQL can be told to do. |
| An application's own listener | A process can hold one seccomp notification listener per filter chain. An application that installs its own filter with a listener (a sandbox, a container runtime inside the container) gets `EBUSY` under chaos-init. |
| Cost | One notified call takes about 2.5 µs instead of 0.2 µs (Docker Desktop, kernel 6.10). Only the requested libraries' system calls pay it. Matching a socket's endpoint reads `/proc/<pid>/net/*` once per socket, and a wait call does it for each of its descriptors (up to 1024): net does so only for operations a loaded rule is for, so rules on connect alone leave recv and epoll at the base cost. One supervisor thread serialises all decisions. |
| Capacity | 128 processes with counts at once (when full, the state of an ended process is written and dropped first, then that of the one unused longest), 1024 delayed calls (beyond that a call runs without its delay), 1024 descriptors scanned per wait call, 1024 iovec entries and 1024 `sendmmsg` messages measured for `@size`, 128 filter instructions. |

---

## 8. Tests

- `make unit` and the coverage gate (100.00 % lines) cover every `src/init/` module
  except the process glue in `chaos_init.c`. Most tests run against the test process
  itself: its memory, its sockets, its `/proc` entries.
- `test/runtime/test_init.sh`: process model, signals, exit codes, reaping, a file limit
  of 256, an unsupported kernel and a failed handover (test builds), a profile that
  refuses seccomp (no filter, no `no_new_privs`).
- `test/runtime/test_seccomp.sh`: a static C program and a `CGO_ENABLED=0` Go program
  get EIO, latency, refused connections, failed mmap, fork and os/exec from the rule
  files, `@first` per process across fork and execve, a rejected TORN rule, and a
  dynamic loader faulted like the program, on glibc and musl, under Docker's default
  profile.
- `test/runtime/test_mptcp.sh`: chaos-init's sock_diag lookups against the kernel's own
  answers for MPTCP sockets, fallback connections excepted, and that chaos-init turns MPTCP
  off for Go (host; skipped without MPTCP).
