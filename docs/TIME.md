# libchaos-time Technical Reference

`libchaos-time` is the dedicated clock/sleep preload library in this
repository. Repository-wide ownership and composition rules live in
[`docs/SYSTEM.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/SYSTEM.md).

Current implementation status:

- exact interposed symbols today: `clock_gettime()`, `nanosleep()`, `usleep()`
- config path: `/tmp/.chaos-time.conf`
- unit-tested
- runtime probe implemented for glibc/musl and amd64/arm64 validation

Current rule grammar:

```text
<selector>:<effect>:<value>
```

Supported selectors:

- `*`
- `clock_gettime`
- `clock_gettime/<clock-name-or-id>`
- `nanosleep`
- `usleep`

Common `clock_gettime/<clock-name>` selectors include:

- `clock_gettime/realtime`
- `clock_gettime/monotonic`
- `clock_gettime/monotonic_raw` where supported by libc/kernel headers
- `clock_gettime/process_cputime_id` where supported
- `clock_gettime/thread_cputime_id` where supported

Implemented effects:

- `ERRNO`
  Fail before the real call, with optional `@probability`
- `LATENCY`
  Add pre-call milliseconds, with optional `@probability`
- `OFFSET`
  Add signed milliseconds to returned `clock_gettime()` timestamps, with
  optional `@probability`

Examples:

```text
*:ERRNO:EINVAL@0.01
clock_gettime:ERRNO:EFAULT@0.01
clock_gettime/monotonic:OFFSET:500
nanosleep:LATENCY:200
usleep:ERRNO:EINTR@0.1
```

Important current boundaries:

- `OFFSET` is valid only for `clock_gettime()`
- `nanosleep()` and `usleep()` support `ERRNO` and `LATENCY`, not returned-time
  mutation
- injected `ERRNO:EINTR` on `nanosleep()` copies the requested interval into
  the caller's `remaining` buffer because the failure is injected before the
  real sleep call runs
- latency is added before the real call; it does not replace the real sleep
  duration
- the library does not currently interpose `clock_nanosleep()`,
  `gettimeofday()`, `sleep()`, `alarm()`, `setitimer()`, timerfd APIs, or
  futex timeout paths

## Execution Boundary

`libchaos-time` operates at the libc contract boundary, not at the kernel timer
or scheduler boundary.

That means:

- it sees `clock_gettime()`, `nanosleep()`, and `usleep()` calls made by the
  target process
- it can delay them, fail them, or adjust returned `timespec` values where the
  API exposes one
- it does not change kernel clock sources, timer wheel behavior, or scheduler
  wakeup semantics for the whole system

The practical effect is process-local chaos:

- the target process sees modified time behavior through the symbols it calls
- unrelated processes do not
- code paths that never traverse these libc symbols are out of scope

## Behavior By Hook

### `clock_gettime()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. Call the real libc `clock_gettime()`
4. If the real call succeeds, apply `OFFSET`

This makes `clock_gettime()` the only current time hook that can return a
synthetically shifted timestamp while still preserving the underlying clock's
general shape.

### `nanosleep()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `nanosleep()`

Synthetic `EINTR` handling is intentionally simple:

- the wrapper returns `-1`
- `errno` is set to `EINTR`
- if `remaining` is non-null, the original requested interval is copied into it

That models "interrupted before the real sleep consumed the request" rather
than partial elapsed-sleep accounting.

### `usleep()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `usleep()`

`usleep()` has no returned timestamp and no `remaining` buffer, so its current
surface is intentionally narrow.

## What This Library Can Do Today

- make `clock_gettime()` fail with synthetic `errno`
- add measured delay ahead of `clock_gettime()`
- skew returned `clock_gettime()` values by signed milliseconds
- make `nanosleep()` fail with synthetic `errno`
- add measured delay ahead of `nanosleep()`
- make `usleep()` fail with synthetic `errno`
- add measured delay ahead of `usleep()`

## What This Library Deliberately Does Not Do

- freeze time globally for the process
- rescale time progression
- change kernel timer source selection
- affect `poll()`, `select()`, `epoll_*()`, DNS timeouts, or socket timeouts
  through implicit magic
- control futex timeout behavior
- hook timerfd or POSIX timer APIs yet

Those behaviors belong either in future time-surface expansion or in a lower
system boundary than this preload library currently owns.
