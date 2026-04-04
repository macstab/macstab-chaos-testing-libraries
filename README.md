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
src/
  chaos_io.c
  chaos_io_actions.c
  chaos_io_actions.h
  chaos_io_config.c
  chaos_io_config.h
  chaos_io_fdcache.c
  chaos_io_fdcache.h
  chaos_io_internal.h
test/
  check_coverage.sh
  test_actions.c
  test_alpine.sh
  test_chaos_io.c
  test_config_parse.c
  test_fdcache.c
  test_integration.sh
  test_support.h
docs/
  ARCHITECTURE.md
Dockerfile.build
Makefile
```

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
- `write`
- `open`
- `close`
- `fsync`
- `fdatasync`
- `pread`
- `pwrite`

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

- The config file is checked with `stat()` on each intercepted call.
- Reload is lock-free for readers and swaps between two config snapshots.
- FD-backed operations resolve paths through `/proc/self/fd/<fd>` and cache them in thread-local storage.
- The library uses a thread-local recursion guard.
- The library seeds a thread-local PRNG once per thread.
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
- full wrapper behavior in `chaos_io.c`

### Coverage gate

```sh
make coverage
```

This compiles an instrumented build and enforces `100.00%` line coverage for:

- `src/chaos_io.c`
- `src/chaos_io_actions.c`
- `src/chaos_io_config.c`
- `src/chaos_io_fdcache.c`

### Full local quality gate

```sh
make check
```

This runs:

1. `make coverage`
2. `make test`

On non-Linux hosts, the Linux-only integration test is skipped. The Alpine Docker test is skipped when Docker is unavailable.

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
