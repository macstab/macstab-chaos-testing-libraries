# Engineering Notes

## Scope

`libchaos-io` is a deliberately small `LD_PRELOAD` library for filesystem fault
injection. It is not a general observability agent, not a daemon, and not a
full policy engine. The code exists to do one job well: intercept a narrow set
of POSIX-style I/O calls and make them fail, slow down, tear, or corrupt under
controlled rules.

The project is optimized for:

- small shared-library outputs
- deterministic behavior under test
- easy auditing of wrapper behavior
- explicit failure semantics

The project is not optimized for:

- feature breadth
- plugin systems
- runtime configuration APIs
- abstract framework design

## How To Read The Code

If you are new to the repository, read it in this order:

1. [`src/chaos_io.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io.c)
   This is the shared runtime core. It resolves real libc symbols, owns the
   constructor path, and centralizes the common fd-backed match path.
2. [`src/chaos_io_open.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_open.c)
   This holds the path-first wrappers and the `openat()` resolution logic.
3. [`src/chaos_io_rw.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_rw.c)
   This holds the read/write wrappers and Linux `sendfile()`.
4. [`src/chaos_io_sync.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_sync.c)
   This holds `close()`, `fsync()`, and `fdatasync()`.
5. [`src/chaos_io_config.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_config.c)
   This explains how rules get from text into an active in-memory snapshot.
6. [`src/chaos_io_actions.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_actions.c)
   This contains the actual fault-effect mechanics once a rule has matched.
7. [`src/chaos_io_fdcache.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_fdcache.c)
   This explains how fd-based calls recover the original path cheaply.
8. [`test/test_chaos_io_harness.h`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/test_chaos_io_harness.h)
   This holds the wrapper test harness and direct source inclusion boundary.
9. [`test/test_chaos_io.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/test_chaos_io.c)
   This holds the actual wrapper behavior assertions.

## File Responsibilities

### [`src/chaos_io.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io.c)

This file owns shared runtime state and lifecycle setup.

Use it when:

- adding or resolving a downstream libc symbol
- changing recursion-guard boundaries
- changing constructor ordering
- changing shared fd-backed rule lookup behavior
- changing startup behavior

Do not use it for:

- wrapper-specific call flow
- probability math
- fd-cache policies

The main invariant is simple: shared runtime helpers should stay small, typed,
and obviously safe under preload recursion.

### [`src/chaos_io_open.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_open.c)

This file owns path-first wrappers and open-path resolution.

Use it when:

- adding or changing `open()` behavior
- adding or changing `openat()` behavior
- changing varargs forwarding for open-style calls
- changing pre-open path resolution and fd-cache seeding

Keep the `open()` and `openat()` wrappers together. They share ABI handling,
rule matching, and post-open cache population.

### [`src/chaos_io_rw.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_rw.c)

This file owns read- and write-side wrappers.

Use it when:

- adding a new fd-backed data-path wrapper
- changing when read corruption is applied
- changing when torn writes are applied
- changing Linux `sendfile()` behavior

The invariant here is operational symmetry: read-style wrappers should stay
read-like, write-style wrappers should stay write-like, and Linux `sendfile()`
must remain explicitly destination-side.

### [`src/chaos_io_sync.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_sync.c)

This file owns close and persistence-boundary wrappers.

Use it when:

- changing `close()` semantics
- changing sync-wrapper behavior
- changing how fd-cache invalidation relates to successful close

Keep these wrappers boring. If they grow effect-specific policy beyond latency
and errno injection, the design is probably drifting.

### [`src/chaos_io_config.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_config.c)

This file owns config ingestion and rule selection.

Use it when:

- extending the config grammar
- adding a new operation or effect
- changing reload behavior
- changing prefix-matching semantics

The critical invariants are:

- invalid config means passthrough, not partial activation
- longest prefix wins
- prefix matching is path-boundary aware
- one thread may reload, many threads may read

### [`src/chaos_io_actions.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_actions.c)

This file owns effect mechanics, not rule lookup.

Use it when:

- changing probability behavior
- changing how torn writes are sized
- changing corruption behavior
- changing latency application

The wrappers should not reimplement effect logic. If the same branching starts
appearing in multiple wrappers, it belongs here instead.

### [`src/chaos_io_fdcache.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_fdcache.c)

This file translates descriptor-based calls back into paths.

Use it when:

- changing cache size or policy
- changing how `/proc/self/fd/<fd>` results are filtered
- changing when cache entries are stored or invalidated

The cache is intentionally small and direct-mapped. That is a deliberate trade:
the library prefers simple predictable code and a tiny footprint over perfect
hit ratios.

## Wrapper Semantics

### `open()` and `openat()`

`open()` and `openat()` are the wrappers that naturally start from a path. That
makes them special in two ways:

- it performs direct path-based matching without going through fd resolution
- it seeds the fd cache for later descriptor-based calls

`openat()` adds one extra rule: when the pathname is relative, the wrapper tries
to resolve a match path from `AT_FDCWD` or from the supplied directory fd before
rule selection. If that pre-open resolution fails, the wrapper must bypass
pre-call injection and rely on post-open fd resolution only.

If you extend open-path behavior, keep those responsibilities together.

### `read()` and `pread()`

Read-style wrappers may:

- delay before the real call
- fail before the real call
- corrupt the returned buffer after a successful real call

They do not truncate the requested byte count before delegation. Any corruption
happens after libc has already returned data.

### `write()`, `pwrite()`, and Linux `sendfile()`

Write-style wrappers may:

- delay before the real call
- fail before the real call
- shorten the outgoing byte count before delegation for torn-write behavior

They do not modify the caller buffer. Torn writes are modeled as partial writes,
not buffer corruption.

Linux `sendfile()` now reuses the same logical `write` rule class, but it
matches on the destination fd only. There is no read-side corruption path for
`sendfile()` because there is no caller-visible read buffer to mutate.

The remaining gap is other alternate copy paths. Tools that move data through
`copy_file_range()`, `splice()`, `mmap()`, or similar non-`write()` and
non-`sendfile()` paths are still outside the current fault surface.

### `close()`

`close()` has one subtle requirement that is easy to regress: cache invalidation
must only happen after a successful real close. Invalidating earlier would make
the cache lie if the close fails.

### `fsync()` and `fdatasync()`

These wrappers are intentionally boring. They exist because persistence
boundaries are often where higher-level systems surface failures. Keep them
boring. If they start carrying wrapper-specific policy, that policy probably
belongs elsewhere.

## Config Model

Each rule is parsed once into a fixed-size in-memory representation. Reload
works by writing the next rule set into the inactive snapshot and then flipping
the active index. Readers never mutate the active snapshot in place.

That design gives this project three useful properties:

- readers stay cheap
- invalid config can be rejected cleanly
- reload never requires allocating a dynamic rule graph

Path matching is prefix-based, but not naive string-prefix matching. `/data`
must match `/data/file` and must not match `/database`. If you change path
semantics, preserve that boundary behavior unless you are intentionally changing
the config contract.

## Recursion And Internal Calls

The recursion guard is not optional defensive coding. It is the mechanism that
keeps the preload library from trapping itself.

Any code path that touches:

- real libc symbols
- `stat()`
- `/proc/self/fd`
- `/dev/urandom`
- config-file reads

must be deliberate about entering and leaving internal mode. If you add a new
helper that performs I/O and it is reachable from a wrapper, assume it needs a
guard boundary unless you can prove otherwise.

## Testing Philosophy

The tests are intentionally close to the implementation.

- parser tests include config internals directly so malformed input and reload
  edges can be tested precisely
- wrapper tests include the wrapper implementation files directly through
  [`test/test_chaos_io_harness.h`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/test/test_chaos_io_harness.h)
  so every branch can be forced without needing a real preload environment
- integration tests still exist to validate the real shared library on Linux

This is a low-level systems library. Direct source inclusion in tests is a
feature here, not a smell.

## Extending The Library Safely

If you add a new interposed operation:

1. Add the enum value in [`src/chaos_io_config.h`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_config.h).
2. Extend parser support and validation in [`src/chaos_io_config.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_config.c).
3. Add the real libc symbol plumbing in [`src/chaos_io.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io.c).
4. Add the wrapper in the appropriate translation unit:
   [`src/chaos_io_open.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_open.c),
   [`src/chaos_io_rw.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_rw.c),
   or [`src/chaos_io_sync.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_sync.c).
5. Decide whether the operation is path-based or fd-based.
6. Add direct unit coverage for every new branch.
7. Keep `make coverage` at 100% for `src/*.c`.

If you add a new effect:

1. Add the enum value.
2. Define which operations are allowed to use it.
3. Add parser support.
4. Add the effect logic in [`src/chaos_io_actions.c`](/Users/nolem/dev/macstab/projects/oss/chaos-testing-libraries/src/chaos_io_actions.c) or a new helper module if it cannot live there cleanly.
5. Wire the wrapper branches in the appropriate wrapper translation unit.
6. Add deterministic tests first, then integration coverage where it matters.

## Maintenance Bar

Good changes in this repository usually have these properties:

- they make the wrapper flow easier to audit, not harder
- they do not add dynamic allocation to hot paths
- they do not weaken passthrough behavior on invalid config
- they preserve or improve test determinism
- they do not inflate the shared object for cosmetic abstraction

If a change fights those constraints, it needs a stronger argument than “it is
more generic.”
