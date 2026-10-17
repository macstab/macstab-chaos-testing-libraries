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
| Libraries applied | io, net, memory, process (dns and time are accepted and apply nothing, §6) |
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
4. With `net`: probe whether MPTCP sockets can be resolved (§3.2).
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
- When the application exits, all pending hits files are written. As PID 1, or when no
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
  (125) rather than run under a filter nobody answers. Taking the listener from the
  child instead (`pidfd_getfd()`) would need `CAP_SYS_PTRACE`.
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
- `/tmp/.chaos-init.status` reports whether the mode is active:

  ```text
  state=active
  libs=io,net
  pid=1
  mptcp=off          (only when §3.2 applies)
  ```

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
| io | ERRNO, LATENCY on open, read, write, pread, pwrite, close (LATENCY only), fsync, fdatasync, truncate, allocate, unlink, rename | the path: absolute, or joined lexically to `/proc/<pid>/cwd` or to the directory descriptor's path; descriptors through `/proc/<pid>/fd`. As in the library, descriptors 0–2, paths under `/proc`, `/sys`, `/dev` and the `/tmp/.chaos-*` control files are never faulted |
| net | ERRNO, LATENCY on socket, bind, listen, connect, accept, shutdown, send, recv, close (LATENCY only), poll; TIMEOUT on the poll family | the endpoint: sockaddr arguments from memory, a socket's own address and peer from `/proc/<pid>/net/*` or sock_diag (§3.2), its type from its `system.sockprotoname` attribute |
| memory | ERRNO, LATENCY on mmap (anon/file), munmap, mprotect, madvise | the arguments: operation, `mmap` flags, length for `@size` |
| process | ERRNO, LATENCY, FAIL_AFTER on pthread_create, fork, posix_spawn, execve, execveat, waitpid | the system call and clone's flags (§5) |
| dns, time | nothing (§6) | |

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

At start-up, with `net` requested, chaos-init opens an `IPPROTO_MPTCP` socket, binds it
to loopback, listens, and looks it up through sock_diag:

- `socket()` fails: the kernel offers no MPTCP; Go uses plain TCP; nothing to do.
- Lookup succeeds: MPTCP sockets are resolved through sock_diag.
- Lookup fails (no `mptcp_diag` module, or a kernel before 5.10): the application's
  `GODEBUG` gets `multipathtcp=0` appended, so Go uses plain TCP and net rules match,
  and the status file says `mptcp=off`. A `multipathtcp=` setting of the user's own
  (first, or after a comma) is kept unchanged; the status still reports `mptcp=off`.

---

## 4. Rejected rules

A rule the parser accepts but seccomp cannot carry out rejects its whole file, like an
invalid line, with its line number and `reason=unsupported in seccomp mode`. No rule of
that file applies.

| Rule | Why not |
|---|---|
| io TORN, CORRUPT; net CORRUPT, TRICKLE, DUP | They change data the kernel moves. Seccomp can fail, delay or skip a call, not change what it transfers. |
| net RESET | It needs the socket itself (`SO_LINGER` on the application's descriptor). Taking another process's descriptor (`pidfd_getfd`) needs `CAP_SYS_PTRACE`. |
| io and net ERRNO on close | The libraries close, then report the error, as Linux does for a failing close. A notified call either runs or fails, not both. |
| process `posix_spawnp` selector | The `PATH` search is in the C library; the system calls are those of posix_spawn, whose rules apply to it, so the rule could never fire. A `*` rule is accepted. |

The check is a build hook in the parsers (`CHAOS_IO_RULE_SUPPORTED`,
`CHAOS_NET_RULE_SUPPORTED`, `CHAOS_PROCESS_RULE_SUPPORTED`; `1` in the libraries), so the
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

---

## 6. Not possible

- **time.** Programs read clocks through the vDSO, without a system call, so seccomp
  never sees them. Sleeps (`nanosleep`, `clock_nanosleep`) would be visible, but Go
  sleeps through its own timers, and the clock-shifting effects (OFFSET, REGRESS) change
  results the kernel never returns through a notification. `--libs time` installs no
  rule for it.
- **dns.** `getaddrinfo` is a library function. A static program resolves names with
  plain UDP/TCP to port 53, which net rules can fail or delay by endpoint, but not by
  the name looked up. `--libs dns` installs no rule for it.

---

## 7. Requirements and limits

| | |
|---|---|
| Kernel | 5.5 or newer (user notification with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`). Older: `state=unsupported`. 5.8+ for the end of a background copy (§1.3), 5.10+ for MPTCP lookups (§3.2), 5.19+ for killable waits (Signals). |
| Privileges | None beyond Docker's default profile: installing a filter under `no_new_privs` needs no capability. The child sets `no_new_privs`, so set-user-ID programs it starts do not gain privileges. It does so only once the filter is known to install (tried first in a process that ends at once): an application started in `state=unsupported` because the kernel, the profile or another supervisor's listener refuses it runs without `no_new_privs`. |
| Architecture | x86_64 and aarch64. Under emulation (amd64 on an arm64 host) seccomp user notification is unavailable: `state=unsupported`. Other ABIs (i386 `int 0x80`, x32) pass unfiltered. |
| Reading the process | Paths, addresses, iovec sizes and `clone3` flags are read from the process's memory (`process_vm_readv`; TIMEOUT writes with `process_vm_writev`), descriptors, sockets and identities through `/proc/<pid>`. This needs ptrace read access: a process of the same user that chaos-init started (Yama lets an ancestor read it even with `kernel.yama.ptrace_scope=1`; `2` or more forbids it). A process that changes user (root to nobody) cannot be read: its path and endpoint rules do not match, while rules on the operation alone still do. |
| Leftover processes | When chaos-init is not PID 1 (a shell or another init started it), processes the application left behind keep the filter. A background copy answers them until the last one ends, which the kernel reports from 5.8; on 5.5 to 5.7 that copy stays, idle, until the container stops. That copy is not their ancestor: where Yama lets only ancestors read a process's memory (`ptrace_scope=1`, the default on Ubuntu hosts), their path and endpoint rules do not match, while rules on the operation alone still do. As PID 1, chaos-init is the ancestor of every process and this does not arise. |
| Signals | A call held back by LATENCY or TIMEOUT waits out its delay when signals arrive (Go signals its threads constantly); unlike under LD_PRELOAD, a TIMEOUT's wait does not end with `EINTR`. From 5.19 (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`) the waiting call cannot be interrupted except by a fatal signal, and handlers of signals that arrive meanwhile run after the delay. Before 5.19 the kernel restarts an interrupted call as a new notification; chaos-init recognises it (same thread, system call and arguments as a parked call), keeps the original due time and verdict, and does not count it again. |
| UNIX sockets | The peer of a UNIX socket is not in `/proc`. Rules on a UNIX socket's peer (send on a connected client) do not match. |
| Calls the filter does not see | io_uring, where the container's profile allows it (recent Docker default profiles do not), submits I/O without the system calls the filter knows, so its reads, writes and opens are never faulted. On x86_64, 32-bit calls (`int 0x80`, i386 programs) and x32 calls pass unfiltered. |
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
  answers for MPTCP sockets (host; skipped without MPTCP).
