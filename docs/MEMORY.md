# libchaos-memory Technical Reference

`libchaos-memory` is the dedicated memory-mapping preload library in this
repository. Repository-wide ownership and composition rules live in
[`docs/SYSTEM.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/SYSTEM.md).

Current implementation status:

- exact interposed symbols today: `mmap()`, `munmap()`, `mprotect()`, `madvise()`
- config path: `/tmp/.chaos-memory.conf`
- unit-tested
- strict `100.00%` line coverage gate enabled for shipped `src/memory/*.c`
- runtime probe implemented for glibc/musl and amd64/arm64 validation

Current rule grammar:

```text
<selector>:<effect>:<value>
```

Supported selectors:

- `*`
- `mmap`
- `mmap/anon`
- `mmap/file`
- `munmap`
- `mprotect`
- `madvise`

Implemented effects:

- `ERRNO`
  Fail before the real call, with optional `@probability`
- `LATENCY`
  Add pre-call milliseconds, with optional `@probability`

Examples:

```text
*:ERRNO:ENOMEM@0.01
mmap/anon:ERRNO:ENOMEM
mmap:LATENCY:150
munmap:ERRNO:EINVAL
mprotect:ERRNO:EACCES
madvise:LATENCY:100
```

Important current boundaries:

- `mmap()` is the only hook with extra selector specificity, through
  `mmap/anon` and `mmap/file`
- `munmap()`, `mprotect()`, and `madvise()` are matched by symbol only; the
  library does not keep region provenance metadata
- latency is added before the real call; it does not replace the real kernel
  memory-management work
- synthetic `munmap()` failure intentionally leaves the mapping alive until the
  target process retries successfully or exits
- the library does not currently interpose `mmap64()`, `mremap()`, `mlock*()`,
  `brk()`, or `sbrk()`

## Execution Boundary

`libchaos-memory` operates at the libc contract boundary, not at the kernel VM
subsystem boundary.

That means:

- it sees `mmap()`, `mprotect()`, and `madvise()` calls made by the target
  process, plus `munmap()` teardown calls
- it can delay them or fail them before the real libc call runs
- it does not globally alter allocator behavior, page reclaim policy, or the
  kernel's memory-management algorithms for the whole system

The practical effect is process-local chaos:

- the target process sees modified behavior through the symbols it calls
- unrelated processes do not
- code paths that never traverse these libc symbols are out of scope

## Behavior By Hook

### `mmap()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `mmap()`

`mmap/anon` versus `mmap/file` matching is derived only from the presence or
absence of `MAP_ANONYMOUS` in the call flags. The library does not inspect the
target file path.

### `mprotect()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `mprotect()`

There is no post-call mutation path. The library either fails early or lets the
real protection change happen.

### `munmap()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `munmap()`

If synthetic failure fires, the mapping remains active in the target process.
That is intentional. This library does not free or track the mapping later.

### `madvise()`

Call flow:

1. Match `LATENCY`
2. Match `ERRNO`
3. If no synthetic failure fired, call the real libc `madvise()`

Like `mprotect()`, this is intentionally pre-call only. The library does not
rewrite advice values or remember per-region metadata.

## What This Library Can Do Today

- make anonymous `mmap()` calls fail with synthetic `errno`
- make file-backed `mmap()` calls fail with synthetic `errno`
- add measured delay ahead of `mmap()`
- make `munmap()` fail with synthetic `errno`
- add measured delay ahead of `munmap()`
- make `mprotect()` fail with synthetic `errno`
- add measured delay ahead of `mprotect()`
- make `madvise()` fail with synthetic `errno`
- add measured delay ahead of `madvise()`

## What This Library Deliberately Does Not Do

- track mapping provenance across later `mprotect()` or `madvise()` calls
- alter actual protection flags or advice values after the real call
- rewrite file-backed `mmap()` targets by path or fd
- affect allocator internals that do not traverse the interposed symbols
- control `brk()` / `sbrk()` yet
- control `mremap()`, `mlock*()`, or page-fault behavior yet

Those behaviors belong either in future memory-surface expansion or in a lower
system boundary than this preload library currently owns.
