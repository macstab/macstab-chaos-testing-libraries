# libchaos-io

`libchaos-io` is a tiny Linux `LD_PRELOAD` fault-injection library for POSIX-style file I/O. It exists to ship as an embedded test resource for `macstab-chaos-testing`, not as a general-purpose package or daemon.

There is intentionally no public C API header. The library surface is the
intercepted libc symbols plus the config file at `/tmp/.chaos-io.conf`.

## Design Constraints

- Pure C99.
- Very small shared objects.
- No runtime dependency beyond libc and `libdl`.
- Works with glibc and musl builds.
- Safe fallback behavior: invalid, unreadable, or missing config means full passthrough.
- Quality gate is enforced in-repo: unit tests plus 100% source line coverage for `src/*.c`.

## Repository Layout

```text
ROADMAP.md
src/
  core/
    chaos_io.c
    chaos_io_internal.h
    chaos_io_wrappers.h
  config/
    chaos_io_config.c
    chaos_io_config.h
    chaos_io_fdcache.c
    chaos_io_fdcache.h
  effects/
    chaos_io_actions.c
    chaos_io_actions.h
  wrappers/
    chaos_io_open.c
    chaos_io_rw.c
    chaos_io_sync.c
test/
  runtime/
    check_coverage.sh
    test_alpine.sh
    test_glibc.sh
    test_integration.sh
  support/
    test_chaos_io_harness.h
    test_support.h
  unit/
    test_actions.c
    test_chaos_io.c
    test_config_parse.c
    test_fdcache.c
docker/
  Dockerfile.build
docs/
  ARCHITECTURE.md
Makefile
```

Planned extension work and scope boundaries live in
[`ROADMAP.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/ROADMAP.md).

## Config Format

Each non-empty rule line is:

```text
<path-prefix>:<operation>:<errno|action>:<value>
```

Examples:

```text
/data:write:EIO:0.3
/data/wal.log:fsync:EIO:0.1
/data:write:LATENCY:200
/data:write:TORN:0.1
/data:read:CORRUPT:0.5
*:open:EMFILE:0.05
```

### Operations

- `read`
  Applies to `read()` and `readv()`.
- `write`
  Applies to `write()`, `writev()`, Linux `sendfile()`, and Linux
  `copy_file_range()` destination paths.
- `open`
  Applies to both `open()` and `openat()`.
- `close`
- `fsync`
- `fdatasync`
- `pread`
  Applies to `pread()` and `preadv()`.
- `pwrite`
  Applies to `pwrite()` and `pwritev()`.

### Effects

- `ERRNO`
  `value` is a probability from `0.0` to `1.0`.
- `LATENCY`
  `value` is milliseconds.
- `TORN`
  `value` is a probability from `0.0` to `1.0`.
  Valid only for `write` and `pwrite`.
- `CORRUPT`
  `value` is a probability from `0.0` to `1.0`.
  Valid only for `read` and `pread`.

### Supported Errnos

- `EIO`
- `ENOSPC`
- `EDQUOT`
- `EROFS`
- `EACCES`
- `EMFILE`
- `ENFILE`
- `ENOENT`

### Matching Rules

- Longest prefix wins.
- `*` is the lowest-priority wildcard.
- Prefix matching is path-boundary aware.
  `/data` matches `/data` and `/data/file`.
  `/data` does not match `/database`.
- Invalid lines invalidate the full config load and force passthrough.

## Runtime Behavior

- The intercepted libc entry points are `read`, `readv`, `write`, `writev`, `open`, `openat`, `close`, `fsync`, `fdatasync`, `pread`, `preadv`, `pwrite`, `pwritev`, and Linux `sendfile` plus `copy_file_range`.
- The config file is checked with `stat()` on each intercepted call.
- Reload is lock-free for readers and swaps between two config snapshots.
- FD-backed operations resolve paths through `/proc/self/fd/<fd>` and cache them in thread-local storage.
- The library uses a thread-local recursion guard.
- The library seeds a thread-local PRNG once per thread.
- `readv(2)` and `preadv(2)` reuse the logical `read` and `pread` rule classes across the concatenated iovec byte stream.
- `writev(2)` and `pwritev(2)` reuse the logical `write` and `pwrite` rule classes across the concatenated iovec byte stream.
- Linux `sendfile(2)` and `copy_file_range(2)` use the logical `write` rule class and match on the destination fd path.
- Programs that copy data with `splice(2)`, `mmap(2)`, or other non-`write(2)`/`writev(2)`/`sendfile(2)`/`copy_file_range(2)` paths bypass `write` and `pwrite` rules.
- Injection is never applied to:
  `stdin`, `stdout`, `stderr`, `/tmp/.chaos-io.conf`, `/proc`, `/sys`, or `/dev`.

## Build And Test

### Fast local loop

```sh
make unit
```

Runs all unit binaries:

- config parsing and reload logic
- effect helpers
- fd cache logic
- full wrapper behavior across `src/core/chaos_io.c`,
  `src/wrappers/chaos_io_open.c`, `src/wrappers/chaos_io_rw.c`, and
  `src/wrappers/chaos_io_sync.c`

### Coverage gate

```sh
make coverage
```

This compiles an instrumented build and enforces `100.00%` line coverage for:

- `src/core/chaos_io.c`
- `src/wrappers/chaos_io_open.c`
- `src/wrappers/chaos_io_rw.c`
- `src/wrappers/chaos_io_sync.c`
- `src/effects/chaos_io_actions.c`
- `src/config/chaos_io_config.c`
- `src/config/chaos_io_fdcache.c`

### Full local quality gate

```sh
make check
```

This runs:

1. `make coverage`
2. `make test`

On non-Linux hosts, the Linux-only integration test is skipped. The glibc and Alpine Docker tests are skipped when Docker is unavailable.

The Docker runtime scripts accept an optional explicit platform argument:

```sh
sh test/runtime/test_glibc.sh linux/amd64
sh test/runtime/test_glibc.sh linux/arm64
sh test/runtime/test_alpine.sh linux/amd64
sh test/runtime/test_alpine.sh linux/arm64
```

When no platform is given, each script falls back to the host architecture.

The Docker runtime probes explicitly validate `openat()`, `readv()`, `writev()`,
`preadv()`, `pwritev()`, Linux `sendfile()`, Linux `copy_file_range()`, and
`fsync()` under `LD_PRELOAD`.

### Build targets

Native Linux shared library:

```sh
make native
```

Cross-build outputs:

```sh
make cross-glibc-amd64
make cross-glibc-arm64
make cross-musl-amd64
make cross-musl-arm64
```

All four distro/arch binaries via Docker Buildx:

```sh
make docker-build-all
```

Expected output names:

- `dist/libchaos-io-glibc-amd64.so`
- `dist/libchaos-io-glibc-arm64.so`
- `dist/libchaos-io-musl-amd64.so`
- `dist/libchaos-io-musl-arm64.so`

## Minimal Artifact Strategy

The shared-library build is intentionally aggressive about size:

- hidden visibility by default
- section-level dead-code elimination
- stripped outputs
- no unwind tables
- no async unwind tables
- no stack protector
- no extra runtime or ABI baggage from C++

The goal is simple: keep the `.so` small, predictable, and boring.

## More Detail

- Architecture notes: [`docs/ARCHITECTURE.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/ARCHITECTURE.md)
- Engineering notes: [`docs/ENGINEERING.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/ENGINEERING.md)
- Code-level intent lives in the comments on the internal headers under [`src/`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src)
