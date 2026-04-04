#ifndef CHAOS_IO_INTERNAL_H
#define CHAOS_IO_INTERNAL_H

/*
 * Shared internal runtime definitions used across the preload library.
 *
 * This header is the common contract between the wrapper layer, config loader,
 * fault helpers, and fd cache. It keeps the low-level guard, PRNG, path filter,
 * and libc symbol state in one place so the codebase behaves consistently while
 * still keeping the final shared object small.
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define CHAOS_IO_CONFIG_PATH "/tmp/.chaos-io.conf"
#define CHAOS_IO_MAX_RULES 256U
#define CHAOS_IO_MAX_PATH ((size_t)PATH_MAX)
#define CHAOS_IO_MAX_RULE_PATH 1024U
#define CHAOS_IO_MAX_LINE_LENGTH 1024U
#define CHAOS_IO_MAX_CONFIG_BYTES (CHAOS_IO_MAX_RULES * CHAOS_IO_MAX_LINE_LENGTH)
#define CHAOS_IO_FD_CACHE_SLOTS 32U

#define CHAOS_IO_EXPORT __attribute__((visibility("default")))

#define CHAOS_IO_MTIME_MISSING UINT64_C(0)
#define CHAOS_IO_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_IO_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

typedef ssize_t (*chaos_io_read_fn)(int, void *, size_t);
typedef ssize_t (*chaos_io_write_fn)(int, const void *, size_t);
typedef int (*chaos_io_open_fn)(const char *, int, ...);
typedef int (*chaos_io_close_fn)(int);
typedef int (*chaos_io_sync_fn)(int);
typedef ssize_t (*chaos_io_pread_fn)(int, void *, size_t, off_t);
typedef ssize_t (*chaos_io_pwrite_fn)(int, const void *, size_t, off_t);

extern chaos_io_read_fn g_chaos_io_real_read;
extern chaos_io_write_fn g_chaos_io_real_write;
extern chaos_io_open_fn g_chaos_io_real_open;
extern chaos_io_close_fn g_chaos_io_real_close;
extern chaos_io_sync_fn g_chaos_io_real_fsync;
extern chaos_io_sync_fn g_chaos_io_real_fdatasync;
extern chaos_io_pread_fn g_chaos_io_real_pread;
extern chaos_io_pwrite_fn g_chaos_io_real_pwrite;

extern __thread int g_chaos_io_tls_guard;
extern __thread uint64_t g_chaos_io_tls_prng_state;
extern uint64_t g_chaos_io_process_seed;

/*
 * Returns non-zero when the current thread is already inside library internals.
 *
 * Wrappers use this as the first recursion check before touching config,
 * `/proc/self/fd`, or any other code path that can reach an interposed libc
 * symbol again.
 */
static inline int chaos_io_in_internal(void)
{
    return g_chaos_io_tls_guard != 0;
}

/*
 * Marks the current thread as executing internal library code and returns the
 * previous guard state.
 *
 * Every wrapper calls this before delegating to a real libc symbol or another
 * helper that must run in passthrough mode. The saved value lets nested callers
 * restore the original state correctly on the way out.
 */
static inline int chaos_io_enter_internal(void)
{
    int previous = g_chaos_io_tls_guard;
    g_chaos_io_tls_guard = 1;
    return previous;
}

/*
 * Restores the thread-local recursion guard after an internal section ends.
 *
 * This must pair with `chaos_io_enter_internal()` on every exit path so nested
 * calls do not leave the thread stuck in permanent passthrough mode.
 */
static inline void chaos_io_leave_internal(int previous)
{
    g_chaos_io_tls_guard = previous;
}

/*
 * Reads a volatile 64-bit shared value with a full memory barrier.
 *
 * Config snapshot metadata is published lock-free, so readers use this helper
 * to observe the active snapshot and cached mtime in a consistent order.
 */
static inline uint64_t chaos_io_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/*
 * Performs a compare-and-swap on a shared 64-bit value.
 *
 * Config reload ownership is decided without locks so only one thread performs
 * disk I/O while the others continue serving calls from the current snapshot.
 */
static inline int chaos_io_atomic_cas_u64(
    volatile uint64_t *value,
    uint64_t expected,
    uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/*
 * Returns an identifier for the current execution thread.
 *
 * The PRNG uses this during lazy seeding so different threads do not inherit
 * the same fault sequence. Linux gets a true thread id; non-Linux test hosts
 * fall back to the process id.
 */
static inline uint64_t chaos_io_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/*
 * Diffuses a 64-bit seed value into a well-scrambled result.
 *
 * Raw inputs such as pid, tid, or stack addresses have obvious structure. This
 * mixing step removes that structure before the value becomes PRNG state.
 */
static inline uint64_t chaos_io_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/*
 * Lazily initializes the current thread's PRNG state.
 *
 * Threads that never hit injected rules should not pay startup cost. When a
 * random sample is first needed, the helper derives a thread-specific seed from
 * the process seed, current thread id, and a stack address, then mixes it into
 * the thread-local state.
 */
static inline void chaos_io_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_io_tls_prng_state != 0U) {
        return;
    }

    seed = g_chaos_io_process_seed;
    seed ^= chaos_io_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed);
    if (g_chaos_io_tls_prng_state == 0U) {
        g_chaos_io_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/*
 * Forces a deterministic seed into the current thread PRNG.
 *
 * Tests use this to get reproducible behavior, and startup uses it to seed the
 * first thread from process entropy. Zero is normalized so the generator never
 * starts from an invalid all-zero state.
 */
static inline void chaos_io_prng_seed_thread(uint64_t seed)
{
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/*
 * Produces the next 32-bit pseudo-random sample for the current thread.
 *
 * Fault helpers call this in hot paths, so it keeps the implementation cheap:
 * seed on first use, then advance a small xorshift-style state machine.
 */
static inline uint32_t chaos_io_prng_next_u32(void)
{
    uint64_t state;

    chaos_io_prng_ensure_seeded();
    state = g_chaos_io_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_io_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

/*
 * Returns non-zero when a path is exactly the active config file.
 *
 * The preload library must never inject faults into its own control plane, so
 * wrappers and cache code use this as an early exclusion check.
 */
static inline int chaos_io_is_config_path(const char *path)
{
    return path != NULL && strcmp(path, CHAOS_IO_CONFIG_PATH) == 0;
}

/*
 * Returns non-zero when a path lives under a reserved top-level prefix.
 *
 * The helper enforces path-boundary-aware matching so `/proc` matches
 * `/proc/self/status` but not `/process`.
 */
static inline int chaos_io_has_reserved_prefix(const char *path, const char *prefix)
{
    size_t prefix_len;

    if (path == NULL || prefix == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

/*
 * Returns whether a path is permanently excluded from injection.
 *
 * Excluded paths cover the control file and kernel-facing trees that the
 * library itself depends on. The same filter is applied before matching rules
 * and before storing fd-cache entries.
 */
static inline int chaos_io_is_excluded_path(const char *path)
{
    if (path == NULL || *path == '\0') {
        return 1;
    }
    if (chaos_io_is_config_path(path)) {
        return 1;
    }
    if (chaos_io_has_reserved_prefix(path, "/proc")
        || chaos_io_has_reserved_prefix(path, "/sys")
        || chaos_io_has_reserved_prefix(path, "/dev")) {
        return 1;
    }
    return 0;
}

#endif
