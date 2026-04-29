# libchaos-process Technical Reference

`libchaos-process` is the dedicated process-lifecycle preload library in this
repository. Repository-wide ownership and composition rules live in
[`docs/SYSTEM.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/SYSTEM.md).

Current implementation status:

- exact interposed symbols today: `pthread_create()`, `fork()`, `posix_spawn()`,
  `posix_spawnp()`, `execve()`, `execveat()`, `waitpid()`
- config path: `/tmp/.chaos-process.conf`
- unit-tested
- strict `100.00%` line coverage gate enabled for shipped `src/process/*.c`
- runtime probe implemented for glibc/musl and amd64/arm64 validation

Current rule grammar:

```text
<selector>:<effect>:<value>
```

Supported selectors:

- `*`
- `pthread_create`
- `fork`
- `posix_spawn`
- `posix_spawnp`
- `execve`
- `execveat`
- `waitpid`

Implemented effects:

- `ERRNO`
  Fail before the real call, with optional `@probability`
- `LATENCY`
  Add pre-call milliseconds, with optional `@probability`
- `FAIL_AFTER`
  Allow the first `N` calls for that operation, then fail later calls with the
  configured error, with optional `@probability`

Examples:

```text
*:LATENCY:25@0.01
pthread_create:ERRNO:EAGAIN
pthread_create:FAIL_AFTER:EAGAIN,128
fork:ERRNO:EAGAIN
posix_spawnp:LATENCY:150
execve:ERRNO:EACCES
waitpid:ERRNO:EINTR@0.1
```

Important current boundaries:

- selectors are symbol-only today; there is no path-aware or signal-aware match
  model yet
- `FAIL_AFTER` counters are per operation, not per rule instance, and reset on
  config reload
- `pthread_create()` and `posix_spawn*()` follow libc contracts and return the
  error number directly on synthetic failure; they do not set `errno`
- `fork()`, `execve()`, `execveat()`, and `waitpid()` return `-1` and set
  `errno` on synthetic failure
- `execveat()` is interposed when the target libc exports that symbol; some
  musl environments do not expose it as a public libc entry point
- the library does not currently interpose `waitid()`, `kill()`,
  `pthread_kill()`, `clone*()`, or `vfork()`

## Execution Boundary

`libchaos-process` operates at the libc process/thread contract boundary, not
at the kernel scheduler or task-table boundary.

That means:

- it sees `pthread_create()`, `fork()`, `posix_spawn*()`, `execve*()`, and
  `waitpid()` calls made by the target process
- it can delay them or fail them before the real libc call runs
- it does not invent fake child processes, fake wait statuses, or fake
  successful `exec`

The practical effect is process-local chaos:

- the target process sees modified lifecycle behavior through the symbols it
  calls
- unrelated processes do not
- code paths that never traverse these libc symbols are out of scope

## Behavior By Hook

### `pthread_create()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `pthread_create()`

Synthetic failure returns the configured error number directly.

### `fork()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `fork()`

Synthetic failure returns `-1` and sets `errno`.

### `posix_spawn()` and `posix_spawnp()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `posix_spawn*()`

Synthetic failure returns the configured error number directly.

### `execve()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `execve()`

Synthetic failure returns `-1` and sets `errno`. The library does not fake a
successful image replacement.

### `execveat()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `execveat()`

If the current libc does not expose a real `execveat()` symbol, the wrapper
falls back to `ENOSYS` if it is somehow called. In practice, code on that libc
usually cannot link or call `execveat()` directly either.

### `waitpid()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Match `FAIL_AFTER`
4. If no synthetic failure fired, call the real libc `waitpid()`

Synthetic failure returns `-1` and sets `errno`. The library does not fabricate
child exit states.

## What This Library Can Do Today

- make native thread creation fail with synthetic error numbers
- delay native thread creation
- fail thread creation only after an operation-local call budget is exhausted
- make `fork()` fail with synthetic `errno`
- delay `fork()`
- make `posix_spawn()` or `posix_spawnp()` fail with synthetic error numbers
- delay `posix_spawn()` or `posix_spawnp()`
- make `execve()` fail with synthetic `errno`
- make `execveat()` fail with synthetic `errno` when the libc exposes it
- make `waitpid()` fail with synthetic `errno`
- delay `waitpid()`

## What This Library Deliberately Does Not Do

- fake successful child creation without a real child
- fake successful `exec`
- synthesize wait statuses for children that do not exist
- track per-child metadata or per-thread lifetime state beyond `FAIL_AFTER`
  counters
- match by executable path or signal number yet
- interpose `clone()`, `clone3()`, `vfork()`, `kill()`, `pthread_kill()`, or
  `waitid()` yet

Those behaviors belong either in future process-surface expansion or at a lower
system boundary than this preload library currently owns.
