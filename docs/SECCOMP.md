# SECCOMP mode: chaos-init

`LD_PRELOAD` cannot reach statically linked programs: Go with `CGO_ENABLED=0` and
`FROM scratch` C programs never load a library (see [PLATFORM.md §7](PLATFORM.md#7-statically-linked-binaries)).
`chaos-init` applies the same rule files to them from outside the process, through
the kernel's seccomp user notification.

It is a second injection mode, not a replacement. Dynamically linked programs keep
`LD_PRELOAD`, which reaches more effects at less cost.

## 1. Model

```text
container PID 1: chaos-init --libs io,net -- <entrypoint> [args...]
  │
  ├─ fork ─► child: no_new_privs, seccomp filter with a notification listener,
  │                 hands the listener back, waits for "go", execs the entrypoint
  │
  └─ supervisor: answers every notified system call
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
  (`src/<lib>/chaos_<lib>_config.c`, `_actions.c`, the shared `src/common` headers)
  as the unit tests do. `src/init/chaos_init_<lib>.c` only turns a notified system
  call into what the library's wrapper would pass to the core.
- **Per process, as with the libraries.** `@first`, hits and FAIL_AFTER are kept per
  supervised process (by pid, start time and image), counts follow rule texts
  across reloads, and every process writes its own `/tmp/.chaos-<lib>.hits.<pid>`.
  A program an execve starts is a new process, as under `LD_PRELOAD`: its counts
  start over, and its hits go to a file of its own beside the replaced image's.
- **Only the requested libraries' system calls** are passed to the supervisor; every
  other call runs untouched by the filter.

## 2. Usage

```sh
chaos-init --libs io,net,memory,process -- /usr/local/bin/nats-server -js
```

- Rules are written to `/tmp/.chaos-<lib>.conf` exactly as for the libraries.
- `/tmp/.chaos-init.status` says whether the mode is active:

  ```text
  state=active
  libs=io,net
  pid=1
  ```

  or `state=unsupported` with a `reason=`. The application then still starts,
  without chaos.
- The libraries' status files report each rule file as usual. A rule this mode
  cannot apply rejects its file there with `reason=unsupported in seccomp mode` (§4).
- `chaos-init` creates `/tmp` if the image has none.

Builds: `make cross-init-<amd64|arm64>` (static, inside an image of that
architecture: `docker/Dockerfile.build`, `MAKE_TARGET=cross-init-<arch>`), or
`make native-init`. One binary per architecture serves glibc, musl and libc-less
images.

## 3. What it applies

| Library | Applied | Matched on |
|---|---|---|
| io | ERRNO, LATENCY on open, read, write, pread, pwrite, close (LATENCY), fsync, fdatasync, truncate, allocate, unlink, rename | the path: absolute, or joined to `/proc/<pid>/cwd` or the directory fd; fds through `/proc/<pid>/fd` |
| net | ERRNO, LATENCY on socket, bind, listen, connect, accept, shutdown, send, recv, close (LATENCY), poll; TIMEOUT on the poll family (as in the library: the wait's own timeout is waited out, its revents and descriptor sets are cleared, select's timeout reads 0; a wait without a timeout is left alone) | the endpoint: sockaddr arguments from memory, a socket's own address and peer from `/proc/<pid>/net/*`, its type from its `system.sockprotoname` attribute |
| memory | ERRNO, LATENCY on mmap (anon/file), munmap, mprotect, madvise | the arguments (flags, length for `@size`) |
| process | ERRNO, LATENCY, FAIL_AFTER on pthread_create, fork, posix_spawn, execve, execveat, waitpid | the system call and clone's flags (§5) |
| dns, time | nothing (§6) | |

All qualifiers apply: `@p`, `@first`, `@from`, `@until`, `@size`.

## 4. Rejected rules

A rule the parser accepts but seccomp cannot carry out rejects its whole file, like
an invalid line, with its line number and `reason=unsupported in seccomp mode`.
No rule of that file applies.

| Rule | Why not |
|---|---|
| io TORN, CORRUPT; net CORRUPT, TRICKLE, DUP | They change data the kernel moves. Seccomp can fail or delay a call, not change what it transfers. |
| net RESET | It needs the socket itself (SO_LINGER). Taking another process's descriptor (`pidfd_getfd`) needs CAP_SYS_PTRACE. |
| io and net ERRNO on close | The libraries close, then report the error, as Linux does for a failing close. A notified call either runs or fails, not both. |
| process posix_spawnp | The path search is in the C library; the system calls are those of posix_spawn, whose rules apply to it. |

The check is a build hook in the parsers (`CHAOS_IO_RULE_SUPPORTED`,
`CHAOS_NET_RULE_SUPPORTED`, `CHAOS_PROCESS_RULE_SUPPORTED`), so the status file reports the rejection together with
the load, never a passing `state=ok` first.

## 5. How calls map to the libraries' operations

- read, write and close are net's on a socket and io's on anything else.
- clone with CLONE_THREAD is pthread_create. With CLONE_VFORK (glibc's posix_spawn,
  Go's os/exec) it is posix_spawn. Otherwise it is fork. clone3 is classified by the
  flags in its argument structure. posix_spawnp cannot be told from posix_spawn: the
  path search is in the C library, so posix_spawn rules apply to it, and a
  posix_spawnp rule rejects its file (§4). system() and popen() are posix_spawn, as
  in the library.
- wait4 and waitid are waitpid.
- The first execve of the application, the one that starts it, is never faulted. With
  `LD_PRELOAD` the library is not loaded at that point either. chaos-init looks a
  command without a '/' up on `PATH` itself, so that start is a single execve of the
  right file, not one per `PATH` entry tried.

## 6. Not possible

- **time.** Programs read clocks through the vDSO, without a system call, so seccomp
  never sees them. Sleeps (nanosleep) would be visible, but Go sleeps through its own
  timers.
- **dns.** `getaddrinfo` is a library function. A static program resolves names with
  plain UDP/TCP to port 53, which net rules can fail or delay by endpoint, but not by
  the name looked up.

## 7. Requirements and limits

| | |
|---|---|
| Kernel | 5.5 or newer (user notification with CONTINUE). Older: `state=unsupported`. |
| Privileges | None beyond Docker's default profile. The child sets no_new_privs, so set-user-ID programs it starts do not gain privileges. It does so only once seccomp has said it offers user notification: an application started in  because the kernel or the profile refuses seccomp runs without it. |
| Architecture | x86_64 and aarch64. Under emulation (amd64 on an arm64 host) seccomp is unavailable: `state=unsupported`. Other ABIs (x32) pass unfiltered. |
| Reading the process | Paths, addresses and iovec sizes are read from the process's memory (`process_vm_readv`), and fds and sockets through `/proc/<pid>`. This works for a process of the same user. A process that changes user (root to nobody) cannot be read: its path and endpoint rules do not match, while rules on the operation alone still do. |
| Leftover processes | When chaos-init is not PID 1 (a shell or another init started it), processes the application left behind keep the filter. A background copy answers them until the last one ends, which the kernel reports from 5.8; on 5.5 to 5.7 that copy stays, idle, until the container stops. |
| Signals | A call held back by LATENCY waits out its delay when signals arrive (Go signals its threads constantly). From 5.19 the waiting call cannot be interrupted except by a fatal signal; before 5.19 the kernel restarts an interrupted call as a new notification, which keeps the delay's original due time and is not counted again. Handlers of signals that arrive meanwhile run after the delay (5.19+). |
| UNIX sockets | The peer of a UNIX socket is not in `/proc`. Rules on a UNIX socket's peer (send on a connected client) do not match. |
| Cost | One notified call takes about 2.5 µs instead of 0.2 µs (Docker Desktop, kernel 6.10). Only the requested libraries' system calls pay it. |
| Capacity | 128 processes with counts at once (the state of an ended one is dropped first, then that of the one unused longest), 1024 delayed calls (beyond that a call runs without its delay), 1024 descriptors scanned per poll call. |

## 8. Tests

- `make unit` and the coverage gate (100% lines) cover every `src/init/` module except
  the process glue in `chaos_init.c`. Most of them run against the test process
  itself: its memory, its sockets, its `/proc` entries.
- `test/runtime/test_init.sh`: process model, signals, exit codes, reaping,
  unsupported kernel.
- `test/runtime/test_seccomp.sh`: a static C program and a `CGO_ENABLED=0` Go program
  get EIO, latency, refused connections, failed mmap, fork and os/exec from the rule
  files, on glibc and musl, under Docker's default profile.
