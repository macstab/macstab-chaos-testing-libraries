# Architecture

## Purpose

`libchaos-io` exists to inject controlled filesystem failures into Linux processes by interposing a small set of libc calls with `LD_PRELOAD`.

The code stays intentionally narrow:

- no public SDK
- no config daemon
- no background thread
- no allocator-heavy data structures

## Execution Model

### Library initialization

[`src/core/chaos_io.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/core/chaos_io.c)

- Resolves the real libc symbols with `dlsym(RTLD_NEXT, ...)`.
- Seeds process entropy from `/dev/urandom`, with a deterministic fallback when that read fails.
- Seeds the current thread PRNG.
- Resets config and fd-cache state.
- Shares common fd-rule matching used by the wrapper translation units.

### Request flow

For each intercepted operation:

1. If the thread is already inside library internals, call straight through.
2. Ignore excluded paths and excluded fds.
3. Refresh config if the config mtime changed.
4. Match the path and operation against the active rules.
5. Apply latency, errno injection, torn writes, or read corruption.
6. Call the real libc symbol.
7. Update the fd cache when needed.

Wrapper families are split by responsibility:

- [`src/wrappers/chaos_io_fsops.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/wrappers/chaos_io_fsops.c)
  owns `ftruncate()`, Linux `fallocate()`, `unlinkat()`, and `renameat()`.
- [`src/wrappers/chaos_io_open.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/wrappers/chaos_io_open.c)
  owns `open()` and `openat()`.
- [`src/wrappers/chaos_io_rw.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/wrappers/chaos_io_rw.c)
  owns `read()`, `readv()`, `write()`, `writev()`, `pread()`, `preadv()`,
  `pwrite()`, `pwritev()`, and Linux `sendfile()` plus `copy_file_range()`.
- [`src/wrappers/chaos_io_sync.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/wrappers/chaos_io_sync.c)
  owns `close()`, `fsync()`, and `fdatasync()`.

## Config Reloading

[`src/config/chaos_io_config.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/config/chaos_io_config.c)

- The config cache uses two snapshots.
- Reload writes into the inactive snapshot, then atomically flips the active index.
- Missing config means empty passthrough state.
- Invalid config means empty passthrough state.
- Matching uses longest-prefix wins with path-boundary checks.

That boundary rule is important:

- `/data` matches `/data/file`
- `/data` does not match `/database`

## FD Path Resolution

[`src/config/chaos_io_fdcache.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/config/chaos_io_fdcache.c)

- `read`, `readv`, `write`, `writev`, `fsync`, `fdatasync`, `pread`, `preadv`, `pwrite`, `pwritev`, `ftruncate`, and Linux `fallocate` operate on fds, not paths.
- The library resolves each fd through `/proc/self/fd/<fd>`.
- Resolved paths are cached in thread-local direct-mapped slots.
- Successful `close` invalidates the cache entry.
- Successful `unlinkat` and `renameat` reset the current thread cache because
  previously resolved path identities may now be stale.

## Fault Effects

[`src/effects/chaos_io_actions.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/effects/chaos_io_actions.c)

- `ERRNO`: fail before calling libc.
- `LATENCY`: sleep before calling libc.
- `TORN`: reduce the write length to a positive partial write.
- `CORRUPT`: call libc, then flip one bit in the returned buffer.

## Testing Strategy

### Unit tests

The unit tests include the implementation files directly where it improves reach:

- static helpers are exercised directly
- wrapper branches are tested without needing a real preload environment
- the production library remains unchanged apart from small testability hooks

That is why coverage can stay strict without adding exported test-only symbols.

### Coverage gate

[`test/runtime/check_coverage.sh`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/runtime/check_coverage.sh)

- Builds an instrumented tree in `build-coverage/`
- Runs all unit binaries
- Verifies `100.00%` line coverage for every `src/*.c`

### Integration checks

[`test/runtime/test_integration.sh`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/runtime/test_integration.sh)

- Linux-only
- Builds the real shared object
- Verifies passthrough, injected errno failure, measured latency, and
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` runtime interposition on Linux hosts

[`test/runtime/test_glibc.sh`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/runtime/test_glibc.sh)

- Verifies the glibc Debian Docker build and runtime path, including direct
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` probes
- Accepts `linux/amd64` or `linux/arm64` as an optional explicit Docker target

[`test/runtime/test_alpine.sh`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/runtime/test_alpine.sh)

- Verifies the musl Alpine Docker build and runtime path, including direct
  `openat()`, `readv()`, `writev()`, `preadv()`, `pwritev()`, `ftruncate()`,
  Linux `fallocate()`, `unlinkat()`, `renameat()`, and Linux `sendfile()` plus
  `copy_file_range()` probes
- Accepts `linux/amd64` or `linux/arm64` as an optional explicit Docker target

## Maintenance Rules

If you extend this library, keep these bars in place:

- preserve the no-public-API model
- preserve small output size
- keep new logic in C99
- extend unit coverage to 100% for any changed source file
- prefer boring, explicit code over generic abstractions

For the file-by-file maintenance map and wrapper-specific guidance, see
[`docs/ENGINEERING.md`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/docs/ENGINEERING.md).
