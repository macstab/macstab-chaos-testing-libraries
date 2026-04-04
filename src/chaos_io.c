/*
 * Core interposition layer for libchaos-io.
 *
 * This file is the executable policy boundary of the library. The other modules
 * answer narrower questions:
 *
 * - `chaos_io_config.*` answers "which rule matches this operation?"
 * - `chaos_io_actions.*` answers "what does the matched rule do?"
 * - `chaos_io_fdcache.*` answers "which path does this fd currently represent?"
 *
 * This file is where those answers are assembled into process-visible behavior.
 * Every interposed function in this file defines the externally observable
 * semantics of the preload library: whether the call is delayed, failed,
 * truncated, corrupted, cached, or passed through untouched.
 *
 * The control flow is intentionally repetitive rather than abstract. At this
 * layer, repetition is cheaper than cleverness because correctness depends on a
 * reader being able to audit exact sequencing:
 *
 * 1. detect recursion or unconditional bypass
 * 2. locate a matching rule
 * 3. apply any pre-call effect
 * 4. enter passthrough mode and call the real libc symbol
 * 5. apply any post-call effect
 * 6. update local runtime state such as the fd cache
 *
 * The most important invariants in this file are:
 *
 * - every call into the real libc symbol happens under the thread-local internal
 *   recursion guard
 * - any effect that changes whether libc is called at all happens before the
 *   real call
 * - `CORRUPT` is a post-read effect and therefore only runs after a successful
 *   `read()` or `pread()`
 * - `TORN` is a write-shaping effect and therefore only changes the outgoing
 *   byte count before `write()` or `pwrite()`
 * - fd-cache invalidation is coupled to successful `close()`, not attempted
 *   `close()`
 *
 * If a future change makes any wrapper harder to explain in those terms, the
 * change is moving in the wrong direction.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

chaos_io_read_fn g_chaos_io_real_read = NULL;
chaos_io_write_fn g_chaos_io_real_write = NULL;
chaos_io_open_fn g_chaos_io_real_open = NULL;
chaos_io_close_fn g_chaos_io_real_close = NULL;
chaos_io_sync_fn g_chaos_io_real_fsync = NULL;
chaos_io_sync_fn g_chaos_io_real_fdatasync = NULL;
chaos_io_pread_fn g_chaos_io_real_pread = NULL;
chaos_io_pwrite_fn g_chaos_io_real_pwrite = NULL;

__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_IO_CONSTRUCTOR
#define CHAOS_IO_CONSTRUCTOR __attribute__((constructor))
#endif

/*
 * Resolve one downstream libc symbol and store it in typed storage.
 *
 * Parameters:
 * - `target`
 *   Address of the global function-pointer slot that should receive the result.
 *   The caller passes the address of storage such as `g_chaos_io_real_read`.
 * - `symbol`
 *   Exact symbol name expected from `RTLD_NEXT`, for example `"read"` or
 *   `"fsync"`.
 *
 * Why this helper exists:
 * - all wrappers depend on a trusted downstream symbol
 * - the failure mode must be uniform across the library
 * - the pointer conversion from `dlsym()` must be handled carefully
 *
 * System interaction:
 * - calls `dlerror()` to clear prior dynamic-loader state
 * - calls `dlsym(RTLD_NEXT, symbol)` to find the next definition after this
 *   preload object
 * - calls `abort()` if the dynamic loader reports a real lookup failure
 *
 * The `memcpy()` step is deliberate. In strict C, function-pointer and object-
 * pointer conversions are awkward. Copying the raw bytes from the `void *`
 * result into the function-pointer storage avoids depending on a compiler-
 * specific cast convention while remaining tiny and explicit.
 *
 * A lookup failure is process-fatal because there is no safe degraded mode.
 * Returning from this function with a missing downstream symbol would leave the
 * wrapper layer able to intercept calls but unable to delegate them.
 */
static void chaos_io_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL) abort();

    (void)memcpy(target, &resolved, sizeof(resolved));
}

/*
 * Obtain process-level seed material without depending on the wrapper layer.
 *
 * Parameters:
 * - none
 *
 * Returns:
 * - 64 bits of seed material for `g_chaos_io_process_seed`
 *
 * Why this helper exists:
 * - startup needs a process-unique seed before rule evaluation begins
 * - calling through `open()` or `read()` here would be wrong because those very
 *   symbols are the ones this library interposes
 *
 * System interaction:
 * - enters internal mode before touching any syscall path
 * - issues `SYS_openat` on `/dev/urandom`
 * - issues `SYS_read` to obtain exactly eight bytes
 * - issues `SYS_close` to release the descriptor
 *
 * Failure handling:
 * - if `/dev/urandom` cannot be opened, or fewer than eight bytes are read, the
 *   function falls back to a deterministic seed derived from a fixed constant and
 *   the current pid
 *
 * The fallback is not trying to be cryptographically strong. Its job is to
 * guarantee that the PRNG state is defined and non-zero even in restricted or
 * pathological environments.
 */
static uint64_t chaos_io_read_seed_material(void)
{
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_io_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0) {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_io_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed)) {
            return seed;
        }
    } else {
        chaos_io_leave_internal(previous);
    }

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/*
 * Call the real `open()` with the exact ABI shape expected by libc.
 *
 * Parameters:
 * - `path`
 *   Pathname forwarded to the downstream libc `open()`.
 * - `flags`
 *   Original open flags. These are forwarded unchanged.
 * - `has_mode`
 *   Non-zero when the wrapper decoded a trailing mode argument from the caller
 *   and therefore must pass three arguments to the real symbol.
 * - `mode`
 *   Decoded file mode. Meaningful only when `has_mode` is non-zero.
 *
 * Returns:
 * - the return value of the real libc `open()`
 *
 * Why this helper exists:
 * - `open()` is varargs and therefore awkward to delegate correctly in multiple
 *   places
 * - the recursion-guard boundary should be identical across all `open()` paths
 *
 * System interaction:
 * - does not touch config or cache state
 * - enters internal mode
 * - calls the resolved downstream libc `open()` symbol
 * - restores the prior recursion-guard state
 *
 * The subtle point here is argument promotion: by the time the caller reaches
 * this helper, any optional `mode_t` has already been decoded from varargs with
 * default integer promotion rules. This helper only decides whether the real
 * call is made with two or three arguments.
 */
static int chaos_io_call_real_open(const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    if (has_mode != 0) {
        result = g_chaos_io_real_open(path, flags, mode);
    } else {
        result = g_chaos_io_real_open(path, flags);
    }
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Match a rule for an fd-backed operation.
 *
 * Parameters:
 * - `fd`
 *   File descriptor supplied by the intercepted libc call.
 * - `operation`
 *   Logical operation being performed on that descriptor, such as
 *   `CHAOS_IO_OP_READ` or `CHAOS_IO_OP_FSYNC`.
 * - `rule`
 *   Output location for the selected rule. The caller must provide writable
 *   storage.
 *
 * Returns:
 * - non-zero when a matching rule was found
 * - zero when the operation should pass through without injection
 *
 * Why this helper exists:
 * - the config language is path-based
 * - fd-backed wrappers do not naturally have the original path
 * - the sequence "refresh config -> resolve fd -> select rule" should stay
 *   uniform across all descriptor-based wrappers
 *
 * System interaction:
 * - may trigger a config refresh, which can `stat()` and read the config file
 * - may resolve the descriptor through `/proc/self/fd/<fd>`
 * - does not itself call the real intercepted data-path symbol
 *
 * Early exits are intentional:
 * - `fd <= 2` bypasses stdio descriptors
 * - empty or invalid config means no rule
 * - unresolved or excluded paths mean no rule
 *
 * That keeps the no-rule path cheap and prevents the wrapper layer from paying
 * unnecessary work when the library is effectively in passthrough mode.
 */
static int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule)
{
    char path[CHAOS_IO_MAX_PATH];

    if (fd <= 2 || rule == NULL) {
        return 0;
    }
    if (!chaos_io_config_prepare()) {
        return 0;
    }
    if (!chaos_io_fdcache_resolve(fd, path, sizeof(path))) {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/*
 * Constructor entry point executed when the preload object is loaded.
 *
 * Parameters:
 * - none
 *
 * Why this function exists:
 * - wrappers may be reachable immediately after the loader maps the shared
 *   object, so all downstream symbol resolution and runtime initialization must
 *   complete before the first intercepted call
 *
 * Initialization order:
 * - resolve downstream libc symbols first
 * - establish process and current-thread PRNG state second
 * - reset config and fd-cache state last
 *
 * System interaction:
 * - dynamic-loader symbol lookup through `dlsym()`
 * - raw syscalls for process seed material
 *
 * The order is not cosmetic. Symbol resolution must happen before any helper
 * that might depend on real libc calls, and the runtime state must be coherent
 * before the first wrapper executes.
 */
CHAOS_IO_CONSTRUCTOR
static void chaos_io_init(void)
{
    chaos_io_resolve_symbol(&g_chaos_io_real_read, "read");
    chaos_io_resolve_symbol(&g_chaos_io_real_write, "write");
    chaos_io_resolve_symbol(&g_chaos_io_real_open, "open");
    chaos_io_resolve_symbol(&g_chaos_io_real_close, "close");
    chaos_io_resolve_symbol(&g_chaos_io_real_fsync, "fsync");
    chaos_io_resolve_symbol(&g_chaos_io_real_fdatasync, "fdatasync");
    chaos_io_resolve_symbol(&g_chaos_io_real_pread, "pread");
    chaos_io_resolve_symbol(&g_chaos_io_real_pwrite, "pwrite");

    g_chaos_io_process_seed = chaos_io_read_seed_material();
    chaos_io_prng_seed_thread(g_chaos_io_process_seed);
    chaos_io_config_init();
    chaos_io_fdcache_reset();
}

/*
 * Interposed `open(2)` entry point.
 *
 * Parameters:
 * - `path`
 *   User-supplied pathname. It is both the object of the real open operation and
 *   the key used for rule matching and later fd-cache seeding.
 * - `flags`
 *   Original open flags. These are inspected to determine whether a trailing
 *   mode argument exists and are then forwarded unchanged to libc.
 * - `...`
 *   Optional `mode_t`, present when `flags` requires it. Because varargs use
 *   default argument promotions, the wrapper decodes it as `int` and casts back
 *   to `mode_t`.
 *
 * Returns:
 * - the result of the real libc `open()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - `open()` is the only intercepted path-first operation
 * - it is the point where a successful fd/path mapping first becomes known to
 *   the library
 *
 * Execution sequence:
 * 1. decode the optional mode argument if required by `flags`
 * 2. if already in internal mode, delegate directly to libc
 * 3. reject excluded paths from injection
 * 4. match the path against the active config snapshot
 * 5. apply latency or fail early with injected errno
 * 6. call the real libc `open()`
 * 7. cache the returned fd -> path mapping when the call succeeds
 *
 * System interaction:
 * - may trigger config reload work before the real open occurs
 * - may sleep before the real open occurs
 * - may return failure without performing any kernel open at all
 * - successful calls populate thread-local cache state for later fd-based
 *   wrappers
 */
CHAOS_IO_EXPORT int open(const char *path, int flags, ...)
{
    chaos_io_rule_t rule;
    mode_t mode = 0;
    int has_mode = 0;
    int fd;

#ifdef O_TMPFILE
    has_mode = ((flags & O_CREAT) != 0) || ((flags & O_TMPFILE) == O_TMPFILE);
#else
    has_mode = ((flags & O_CREAT) != 0);
#endif

    if (has_mode != 0) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (chaos_io_in_internal()) {
        return chaos_io_call_real_open(path, flags, has_mode, mode);
    }

    if (!chaos_io_is_excluded_path(path) && chaos_io_config_match_path(CHAOS_IO_OP_OPEN, path, &rule)) {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
            chaos_io_rule_apply_latency(&rule);
        } else if (chaos_io_rule_apply_errno(&rule)) {
            return -1;
        }
    }

    fd = chaos_io_call_real_open(path, flags, has_mode, mode);
    if (fd >= 0 && !chaos_io_is_excluded_path(path)) {
        chaos_io_fdcache_store(fd, path);
    }
    return fd;
}

/*
 * Interposed `read(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor being read. The wrapper may resolve this descriptor back to a
 *   path before deciding whether to inject a fault.
 * - `buffer`
 *   Caller-owned output buffer. This buffer is passed unchanged to libc and may
 *   later be mutated in place by `CORRUPT` rules after a successful real read.
 * - `count`
 *   Maximum requested byte count forwarded to the real libc `read()`.
 *
 * Returns:
 * - the result of the real libc `read()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - read paths are where corruption semantics differ fundamentally from write
 *   semantics
 *
 * Execution sequence:
 * 1. bypass immediately if the call is already in internal mode
 * 2. resolve `fd` to a path and match a `READ` rule if possible
 * 3. apply latency or fail early with injected errno
 * 4. call the real libc `read()`
 * 5. if the call returned a positive byte count and a `CORRUPT` rule triggers,
 *    flip one bit in the caller buffer
 *
 * System interaction:
 * - may `stat()` and reread config before the read
 * - may readlink `/proc/self/fd/<fd>` before the read
 * - may sleep before the read
 * - may return failure without issuing any real read
 *
 * This wrapper never simulates torn reads. If the call succeeds, byte-count
 * semantics come from libc; only the returned bytes may be corrupted afterward.
 */
CHAOS_IO_EXPORT ssize_t read(int fd, void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_READ, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_read(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_read(fd, buffer, count);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule)) {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `write(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor being written. The wrapper may resolve it to a path for rule
 *   matching before any data is written.
 * - `buffer`
 *   Caller-owned input buffer. The wrapper never mutates this buffer.
 * - `count`
 *   Requested byte count. This may be rewritten downward for `TORN` rules before
 *   the real libc write is issued.
 *
 * Returns:
 * - the result of the real libc `write()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - write-side faults have a pre-call shaping behavior that read-side wrappers
 *   do not: torn writes change the outgoing byte count
 *
 * Execution sequence:
 * 1. bypass immediately if already in internal mode
 * 2. resolve `fd` to a path and match a `WRITE` rule if possible
 * 3. apply latency, fail early with errno, or shorten `count` for a torn write
 * 4. call the real libc `write()` with the final byte count
 *
 * System interaction:
 * - may `stat()` and reread config before the write
 * - may readlink `/proc/self/fd/<fd>` before the write
 * - may sleep before the write
 * - may fail without issuing any real write
 *
 * Torn writes are modeled as successful short writes, not as post-write
 * corruption. That distinction matters because higher-level callers often branch
 * on the returned byte count.
 */
CHAOS_IO_EXPORT ssize_t write(int fd, const void *buffer, size_t count)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_WRITE, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_write(fd, buffer, count);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    } else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule)) {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_write(fd, buffer, count);
    chaos_io_leave_internal(previous);
    return rc;
}

/*
 * Interposed `close(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor being closed. This may be resolved back to a path for rule
 *   matching before the real close occurs.
 *
 * Returns:
 * - the result of the real libc `close()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - `close()` is both an injectable syscall boundary and the point where stale
 *   fd-cache state must be retired
 *
 * Execution sequence:
 * 1. bypass immediately if already in internal mode
 * 2. resolve `fd` and match a `CLOSE` rule if possible
 * 3. apply latency or fail early with injected errno
 * 4. call the real libc `close()`
 * 5. invalidate the fd cache only if libc reports success
 *
 * System interaction:
 * - may `stat()` and reread config before the close
 * - may readlink `/proc/self/fd/<fd>` before the close
 * - may sleep before the close
 * - may fail without issuing any real close
 *
 * The post-close invalidation rule is critical. If the cache were invalidated
 * before the real close and libc then returned an error, the library would have
 * lost the path mapping for a descriptor that is still live.
 */
CHAOS_IO_EXPORT int close(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_CLOSE, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_close(fd);
        chaos_io_leave_internal(previous);
        if (rc == 0) {
            chaos_io_fdcache_invalidate(fd);
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);
    if (rc == 0) {
        chaos_io_fdcache_invalidate(fd);
    }
    return rc;
}

/*
 * Interposed `fsync(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor whose underlying file is being synchronized.
 *
 * Returns:
 * - the result of the real libc `fsync()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - persistence boundaries are often the exact fault point a storage test wants
 *   to control
 *
 * Execution sequence:
 * 1. bypass immediately if already in internal mode
 * 2. resolve `fd` and match an `FSYNC` rule if possible
 * 3. apply latency or fail early with injected errno
 * 4. call the real libc `fsync()`
 *
 * There is no post-call mutation path. Once libc has been called, the wrapper is
 * finished.
 */
CHAOS_IO_EXPORT int fsync(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FSYNC, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_fsync(fd);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fsync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

/*
 * Interposed `fdatasync(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor whose data-only durability boundary is being forced.
 *
 * Returns:
 * - the result of the real libc `fdatasync()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - many storage engines distinguish data-only durability from full metadata
 *   durability, so the fault-injection surface must preserve that distinction
 *
 * Execution sequence is intentionally the same as `fsync()`:
 * 1. bypass on internal mode
 * 2. resolve fd and match a rule
 * 3. apply latency or fail early
 * 4. delegate to libc
 */
CHAOS_IO_EXPORT int fdatasync(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FDATASYNC, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_fdatasync(fd);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fdatasync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

/*
 * Interposed `pread(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor being read.
 * - `buffer`
 *   Caller-owned output buffer. As with `read()`, it may be mutated in place
 *   after a successful real call when a `CORRUPT` rule fires.
 * - `count`
 *   Maximum requested byte count forwarded to libc.
 * - `offset`
 *   Explicit file offset supplied by the caller. The wrapper forwards it
 *   unchanged to the real libc `pread()`.
 *
 * Returns:
 * - the result of the real libc `pread()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - callers often rely on positioned I/O semantics specifically because they do
 *   not want to mutate the shared file offset; fault injection must preserve that
 *   contract
 *
 * Execution sequence matches `read()` exactly except that the supplied `offset`
 * is part of the real libc call.
 */
CHAOS_IO_EXPORT ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PREAD, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pread(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pread(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    if (rc > 0 && rule.effect == CHAOS_IO_EFFECT_CORRUPT && chaos_io_rule_should_trigger(&rule)) {
        chaos_io_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/*
 * Interposed `pwrite(2)` entry point.
 *
 * Parameters:
 * - `fd`
 *   Descriptor being written.
 * - `buffer`
 *   Caller-owned input buffer. The wrapper never mutates it.
 * - `count`
 *   Requested byte count, subject to torn-write reduction before delegation.
 * - `offset`
 *   Explicit file offset forwarded unchanged to the real libc `pwrite()`.
 *
 * Returns:
 * - the result of the real libc `pwrite()`
 * - `-1` with injected `errno` when an `ERRNO` rule fires before libc is called
 *
 * Why this wrapper exists:
 * - positioned writes need the same write-side fault semantics as `write()`
 *   while preserving caller-controlled offset semantics
 *
 * Execution sequence matches `write()` exactly except that the supplied `offset`
 * is part of the real libc call.
 */
CHAOS_IO_EXPORT ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
    chaos_io_rule_t rule;
    ssize_t rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_PWRITE, &rule)) {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    } else if (rule.effect == CHAOS_IO_EFFECT_TORN && chaos_io_rule_should_trigger(&rule)) {
        count = chaos_io_torn_count(count);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pwrite(fd, buffer, count, offset);
    chaos_io_leave_internal(previous);
    return rc;
}
