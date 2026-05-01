/**
 * @file chaos_io_internal.h
 * @brief Shared runtime definitions for the libchaos-io preload library.
 *
 * @details
 * This header is the single source of truth for every primitive that crosses
 * compilation-unit boundaries inside the preload library: capacity limits,
 * sentinel values, libc symbol types, the TLS reentrancy guard, the PRNG, and
 * the path exclusion filter.
 *
 * All wrapper translation units, the config subsystem, the fd-cache, and the
 * effect helpers include this file directly.  The implementation deliberately
 * avoids dynamic allocation anywhere in this header so that every inline
 * function is safe to call from signal handlers and constructors.
 *
 * **Module ownership:** core/
 * **Stability:** internal – not part of any public ABI
 * **Thread-safety:** all non-`static` symbols exposed here are either
 * thread-local (`__thread`) or truly read-only after `chaos_io_init()`;
 * the atomic helpers provide the necessary ordering for shared fields.
 */

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
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * @defgroup chaos_io_limits Capacity and path limits
 * @{
 */

/**
 * @brief Absolute path of the fault-injection configuration file.
 *
 * @details The library reads this file on demand when its mtime changes.
 * The path is also used as the primary exclusion key: any operation whose
 * resolved path equals this string is passed through without injection,
 * preventing the library from injecting faults into its own control plane.
 */
#define CHAOS_IO_CONFIG_PATH "/tmp/.chaos-io.conf"

/**
 * @brief Maximum number of rules that one config snapshot may hold.
 *
 * @details Bounds the two statically allocated `chaos_io_config_state_t`
 * arrays.  Increasing this value increases BSS usage by
 * `2 * CHAOS_IO_MAX_RULES * sizeof(chaos_io_rule_t)`.
 */
#define CHAOS_IO_MAX_RULES 256U

/**
 * @brief Maximum byte length of a resolved filesystem path, including NUL.
 *
 * @details Set to `PATH_MAX` so on-stack path buffers never need to be
 * larger than the kernel's own limit.
 */
#define CHAOS_IO_MAX_PATH ((size_t)PATH_MAX)

/**
 * @brief Maximum byte length of a rule path prefix stored in a parsed rule.
 *
 * @details Kept smaller than `CHAOS_IO_MAX_PATH` because rule prefixes are
 * specified by the operator and do not need to cover every possible
 * kernel-resolved path.  Paths longer than this at parse time are rejected.
 */
#define CHAOS_IO_MAX_RULE_PATH 1024U

/**
 * @brief Maximum byte length of one line in the config file.
 */
#define CHAOS_IO_MAX_LINE_LENGTH 1024U

/**
 * @brief Maximum total byte size of the config file that the library will read.
 *
 * @details The config reader rejects files that hit this boundary to prevent
 * a partial rule set from silently truncating intended configuration.
 * The value is `CHAOS_IO_MAX_RULES * CHAOS_IO_MAX_LINE_LENGTH`.
 */
#define CHAOS_IO_MAX_CONFIG_BYTES (CHAOS_IO_MAX_RULES * CHAOS_IO_MAX_LINE_LENGTH)

/**
 * @brief Number of direct-mapped slots in the per-thread fd-to-path cache.
 *
 * @details The cache is indexed by `fd % CHAOS_IO_FD_CACHE_SLOTS`, so any
 * two descriptors whose values differ by this modulus share a slot and the
 * later one evicts the earlier one.  32 slots covers the typical fd range of
 * a single-threaded I/O loop without bloating per-thread storage.
 */
#define CHAOS_IO_FD_CACHE_SLOTS 32U

/** @} */

/**
 * @defgroup chaos_io_visibility Symbol visibility
 * @{
 */

/**
 * @brief Marks a symbol as part of the public preload ABI.
 *
 * @details Applied exclusively to the interposed libc symbols (e.g. `open`,
 * `read`, `write`).  Every other symbol in the library is compiled with
 * `-fvisibility=hidden` so it is invisible to the dynamic linker and cannot
 * conflict with symbols in the target process.
 *
 * @note `-fno-stack-protector` is also required at compile time because
 * `__stack_chk_fail` calls `write`, which would recurse back into this
 * library before `g_chaos_io_real_write` is resolved.
 */
#define CHAOS_IO_EXPORT __attribute__((visibility("default")))

/** @} */

/**
 * @defgroup chaos_io_mtime Config mtime sentinel values
 * @{
 *
 * @details The library stores the mtime of the config file as a hashed
 * 64-bit value in a shared `volatile uint64_t` that doubles as a lock-free
 * CAS token.  Three special sentinel values have meaning beyond a normal
 * hash result.  `chaos_io_config_normalize_mtime_hash()` maps genuine hash
 * collisions with these sentinels to a nearby distinct value.
 */

/**
 * @brief Sentinel: config file does not exist or could not be stat'd.
 *
 * @details When the cached mtime equals this value, the active config state
 * has zero rules and all operations pass through without injection.
 */
#define CHAOS_IO_MTIME_MISSING UINT64_C(0)

/**
 * @brief Sentinel: another thread has won the CAS race and is reloading.
 *
 * @details A thread that observes this value as the cached mtime yields the
 * reload responsibility and falls back to the current active snapshot.
 * This prevents two threads from reading the config file simultaneously.
 */
#define CHAOS_IO_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Sentinel: initial state before the first stat check.
 *
 * @details Set by `chaos_io_config_init()`.  Any observed mtime differs from
 * this on the first call to `chaos_io_config_prepare()`, guaranteeing that
 * the config file is read at least once before any wrapper fires a rule.
 */
#define CHAOS_IO_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/**
 * @defgroup chaos_io_fn_types Resolved libc function pointer types
 * @{
 *
 * @details Each typedef mirrors the exact POSIX signature of the
 * corresponding libc symbol.  Using typed function pointers rather than
 * `void (*)(void)` casts lets the compiler check argument types at call
 * sites and avoids undefined behavior from incompatible pointer-to-pointer
 * conversions.  The actual pointers are populated by `dlsym(RTLD_NEXT, …)`
 * during the library constructor and must be non-NULL before any wrapper
 * reaches a `g_chaos_io_real_*` call.
 */

/** @brief Type of the real `read(2)` libc symbol. */
typedef ssize_t (*chaos_io_read_fn)(int, void *, size_t);

/** @brief Type of the real `write(2)` libc symbol. */
typedef ssize_t (*chaos_io_write_fn)(int, const void *, size_t);

/** @brief Type of the real `readv(2)` libc symbol. */
typedef ssize_t (*chaos_io_readv_fn)(int, const struct iovec *, int);

/** @brief Type of the real `writev(2)` libc symbol. */
typedef ssize_t (*chaos_io_writev_fn)(int, const struct iovec *, int);

/** @brief Type of the real `open(2)` libc symbol (varargs). */
typedef int (*chaos_io_open_fn)(const char *, int, ...);

/** @brief Type of the real `openat(2)` libc symbol (varargs). */
typedef int (*chaos_io_openat_fn)(int, const char *, int, ...);

/** @brief Type of the real `close(2)` libc symbol. */
typedef int (*chaos_io_close_fn)(int);

/**
 * @brief Type shared by the real `fsync(2)` and `fdatasync(2)` libc symbols.
 *
 * @details Both functions have the same signature `int f(int fd)` so a
 * single typedef covers both stored pointers.
 */
typedef int (*chaos_io_sync_fn)(int);

/** @brief Type of the real `pread(2)` libc symbol. */
typedef ssize_t (*chaos_io_pread_fn)(int, void *, size_t, off_t);

/** @brief Type of the real `pwrite(2)` libc symbol. */
typedef ssize_t (*chaos_io_pwrite_fn)(int, const void *, size_t, off_t);

/** @brief Type of the real `preadv(2)` libc symbol. */
typedef ssize_t (*chaos_io_preadv_fn)(int, const struct iovec *, int, off_t);

/** @brief Type of the real `pwritev(2)` libc symbol. */
typedef ssize_t (*chaos_io_pwritev_fn)(int, const struct iovec *, int, off_t);

/** @brief Type of the real `ftruncate(2)` libc symbol. */
typedef int (*chaos_io_ftruncate_fn)(int, off_t);

/** @brief Type of the real `unlinkat(2)` libc symbol. */
typedef int (*chaos_io_unlinkat_fn)(int, const char *, int);

/** @brief Type of the real `renameat(2)` libc symbol. */
typedef int (*chaos_io_renameat_fn)(int, const char *, int, const char *);

#ifdef __linux__
/** @brief Type of the real Linux `fallocate(2)` libc symbol. */
typedef int (*chaos_io_fallocate_fn)(int, int, off_t, off_t);

/** @brief Type of the real Linux `sendfile(2)` libc symbol. */
typedef ssize_t (*chaos_io_sendfile_fn)(int, int, off_t *, size_t);

/** @brief Type of the real Linux `copy_file_range(2)` libc symbol. */
typedef ssize_t (*chaos_io_copy_file_range_fn)(int, off_t *, int, off_t *, size_t, unsigned int);
#endif

/** @} */

/**
 * @defgroup chaos_io_real_symbols Resolved downstream libc symbols
 * @{
 *
 * @details These globals are populated once by `chaos_io_init()` using
 * `dlsym(RTLD_NEXT, name)` before any wrapper can reach them.  After
 * construction they are effectively read-only: no wrapper ever writes to
 * them again, so no synchronization is needed for reads.
 *
 * All pointers default to `NULL` in BSS.  Any wrapper that observes a NULL
 * pointer before calling it indicates a constructor ordering bug and will
 * segfault intentionally rather than silently misbehave.
 */

extern chaos_io_read_fn g_chaos_io_real_read;           /**< Downstream `read`. */
extern chaos_io_write_fn g_chaos_io_real_write;         /**< Downstream `write`. */
extern chaos_io_readv_fn g_chaos_io_real_readv;         /**< Downstream `readv`. */
extern chaos_io_writev_fn g_chaos_io_real_writev;       /**< Downstream `writev`. */
extern chaos_io_open_fn g_chaos_io_real_open;           /**< Downstream `open`. */
extern chaos_io_openat_fn g_chaos_io_real_openat;       /**< Downstream `openat`. */
extern chaos_io_close_fn g_chaos_io_real_close;         /**< Downstream `close`. */
extern chaos_io_sync_fn g_chaos_io_real_fsync;          /**< Downstream `fsync`. */
extern chaos_io_sync_fn g_chaos_io_real_fdatasync;      /**< Downstream `fdatasync`. */
extern chaos_io_pread_fn g_chaos_io_real_pread;         /**< Downstream `pread`. */
extern chaos_io_pwrite_fn g_chaos_io_real_pwrite;       /**< Downstream `pwrite`. */
extern chaos_io_preadv_fn g_chaos_io_real_preadv;       /**< Downstream `preadv`. */
extern chaos_io_pwritev_fn g_chaos_io_real_pwritev;     /**< Downstream `pwritev`. */
extern chaos_io_ftruncate_fn g_chaos_io_real_ftruncate; /**< Downstream `ftruncate`. */
extern chaos_io_unlinkat_fn g_chaos_io_real_unlinkat;   /**< Downstream `unlinkat`. */
extern chaos_io_renameat_fn g_chaos_io_real_renameat;   /**< Downstream `renameat`. */
#ifdef __linux__
extern chaos_io_fallocate_fn g_chaos_io_real_fallocate; /**< Downstream `fallocate` (Linux). */
extern chaos_io_sendfile_fn g_chaos_io_real_sendfile;   /**< Downstream `sendfile` (Linux). */
extern chaos_io_copy_file_range_fn
    g_chaos_io_real_copy_file_range; /**< Downstream `copy_file_range` (Linux). */
#endif

/** @} */

/**
 * @defgroup chaos_io_tls Thread-local state
 * @{
 */

/**
 * @brief Per-thread reentrancy guard.
 *
 * @details Non-zero while the current thread is executing inside library
 * internals (config reads, fd-cache lookups, path resolution via
 * `/proc/self/fd`).  Every interposed wrapper checks this as its very first
 * action and falls through to the real libc call if it is set.
 *
 * The guard is a save/restore value, not a simple increment/decrement, so
 * that a nested internal entry always restores the *caller's* guard state
 * rather than blindly clearing it.  This matters because a wrapper may call
 * an internal helper that itself calls `chaos_io_enter_internal()`.
 *
 * @note TLS variables are zero-initialized per the C standard, so the guard
 * starts as "not inside internals" on every thread without explicit setup.
 */
extern __thread int g_chaos_io_tls_guard;

/**
 * @brief Per-thread xorshift64* PRNG state.
 *
 * @details Zero is the invalid state for the xorshift family; the PRNG is
 * lazily seeded on first use by `chaos_io_prng_ensure_seeded()`.  Each
 * thread derives a distinct seed from `g_chaos_io_process_seed`, the
 * thread's kernel TID, and a stack address, ensuring that concurrent threads
 * do not share fault sequences.
 */
extern __thread uint64_t g_chaos_io_tls_prng_state;

/**
 * @brief Process-wide entropy base used to seed per-thread PRNGs.
 *
 * @details Initialized once during `chaos_io_init()` from `/dev/urandom` if
 * available, or from a PID-derived fallback constant otherwise.  This value
 * is read-only after construction; threads read it without synchronization
 * because the constructor guarantees visibility before any wrapper fires.
 */
extern uint64_t g_chaos_io_process_seed;

/** @} */

/**
 * @defgroup chaos_io_guard_inlines Reentrancy guard inline helpers
 * @{
 */

/**
 * @brief Returns non-zero when the current thread is already inside library internals.
 *
 * @details Wrappers use this as the first recursion check before touching config,
 * `/proc/self/fd`, or any other code path that can reach an interposed libc
 * symbol again.
 *
 * @return Non-zero if `g_chaos_io_tls_guard` is set; zero otherwise.
 *
 * @note Checking the guard before calling `chaos_io_enter_internal()` avoids
 * the save/restore overhead on the fast passthrough path.  Once this returns
 * non-zero, the wrapper must not touch any library state.
 */
static inline int chaos_io_in_internal(void)
{
    return g_chaos_io_tls_guard != 0;
}

/**
 * @brief Marks the current thread as executing internal library code.
 *
 * @details Every wrapper calls this before delegating to a real libc symbol or another
 * helper that must run in passthrough mode. The saved value lets nested callers
 * restore the original state correctly on the way out.
 *
 * @return The previous value of `g_chaos_io_tls_guard`.  Must be passed back
 *         to `chaos_io_leave_internal()` on every exit path, including error
 *         paths.
 *
 * @post `g_chaos_io_tls_guard == 1`.
 *
 * @note The return-and-restore pattern rather than a paired increment/decrement
 * is necessary because a single interposed call may re-enter
 * `chaos_io_enter_internal()` from nested helpers.  Restoring the previous
 * value keeps the innermost call's guard state intact when the outer level
 * exits.
 */
static inline int chaos_io_enter_internal(void)
{
    int previous = g_chaos_io_tls_guard;
    g_chaos_io_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the thread-local recursion guard after an internal section ends.
 *
 * @details This must pair with `chaos_io_enter_internal()` on every exit path so nested
 * calls do not leave the thread stuck in permanent passthrough mode.
 *
 * @param[in] previous  The value returned by the matching
 *                      `chaos_io_enter_internal()` call.
 *
 * @post `g_chaos_io_tls_guard == previous`.
 */
static inline void chaos_io_leave_internal(int previous)
{
    g_chaos_io_tls_guard = previous;
}

/** @} */

/**
 * @defgroup chaos_io_atomic Lock-free atomic helpers
 * @{
 */

/**
 * @brief Reads a volatile 64-bit shared value with a full memory barrier.
 *
 * @details Config snapshot metadata is published lock-free, so readers use this helper
 * to observe the active snapshot and cached mtime in a consistent order.
 *
 * @param[in] value  Pointer to the volatile shared variable.  Must not be NULL.
 * @return The value of `*value` observed after the barrier.
 *
 * @note The full `__sync_synchronize()` barrier before the load ensures that
 * the index read in `chaos_io_config_active_state()` and the subsequent
 * array dereference cannot be reordered ahead of a concurrent
 * `chaos_io_config_publish()` store sequence.
 */
static inline uint64_t chaos_io_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Performs a compare-and-swap on a shared 64-bit value.
 *
 * @details Config reload ownership is decided without locks so only one thread performs
 * disk I/O while the others continue serving calls from the current snapshot.
 *
 * @param[in,out] value     Pointer to the shared variable.  Must not be NULL.
 * @param[in]     expected  The value that must currently be stored.
 * @param[in]     desired   The value to write if the CAS succeeds.
 * @return Non-zero if the swap happened (i.e. `*value == expected` at the
 *         moment of the swap); zero if another thread changed `*value` first.
 *
 * @note The winning thread writes `CHAOS_IO_MTIME_RELOADING` as `desired` to
 * act as an advisory "reload in progress" token.  Threads that lose the
 * race and observe `CHAOS_IO_MTIME_RELOADING` continue serving from the
 * current active snapshot rather than spinning.
 */
static inline int
chaos_io_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/** @} */

/**
 * @defgroup chaos_io_prng PRNG helpers
 * @{
 */

/**
 * @brief Returns an identifier for the current execution thread.
 *
 * @details The PRNG uses this during lazy seeding so different threads do not inherit
 * the same fault sequence. Linux gets a true thread id; non-Linux test hosts
 * fall back to the process id.
 *
 * @return The kernel thread ID on Linux (`SYS_gettid`); `getpid()` elsewhere.
 *
 * @note `SYS_gettid` is used via `syscall()` rather than `gettid()` from
 * `<unistd.h>` because the latter was only added in glibc 2.30 and the
 * syscall form remains compatible with older toolchains.
 */
static inline uint64_t chaos_io_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/**
 * @brief Diffuses a 64-bit seed value into a well-scrambled result (SplitMix64 step).
 *
 * @details Raw inputs such as pid, tid, or stack addresses have obvious structure. This
 * mixing step removes that structure before the value becomes PRNG state.
 * The constants and shift distances are the SplitMix64 finalizer from
 * Steele et al., chosen for their avalanche properties.
 *
 * @param[in] value  Raw input to mix.
 * @return A 64-bit value with good bit diffusion from every input bit.
 */
static inline uint64_t chaos_io_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Lazily initializes the current thread's PRNG state on first use.
 *
 * @details Threads that never hit injected rules should not pay startup cost. When a
 * random sample is first needed, the helper derives a thread-specific seed from
 * the process seed, current thread id, and a stack address, then mixes it into
 * the thread-local state.
 *
 * @post `g_chaos_io_tls_prng_state != 0`.
 *
 * @note The stack address `&seed` is included in the XOR chain to
 * differentiate threads that happen to share a TID (e.g. after fork) and to
 * add an additional entropy dimension beyond the process/thread pair.
 * The fallback to `0x2545f4914f6cdd1d` guards against the astronomically
 * unlikely case where the mix produces zero, which would be a dead state for
 * xorshift.
 */
static inline void chaos_io_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_io_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_io_process_seed;
    seed ^= chaos_io_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed);
    if (g_chaos_io_tls_prng_state == 0U)
    {
        g_chaos_io_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * @brief Forces a deterministic seed into the current thread PRNG.
 *
 * @details Tests use this to get reproducible behavior, and startup uses it to seed the
 * first thread from process entropy. Zero is normalized so the generator never
 * starts from an invalid all-zero state.
 *
 * @param[in] seed  Desired seed value.  If zero, `1` is substituted before
 *                  mixing to prevent the xorshift state from becoming stuck.
 *
 * @post `g_chaos_io_tls_prng_state != 0`.
 */
static inline void chaos_io_prng_seed_thread(uint64_t seed)
{
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Produces the next 32-bit pseudo-random sample for the current thread.
 *
 * @details Fault helpers call this in hot paths, so it keeps the implementation cheap:
 * seed on first use, then advance a small xorshift-style state machine.
 * The generator is an xorshift64* variant: three shift-XOR steps advance the
 * 64-bit state, and the output is the upper 32 bits of
 * `state * 0x2545f4914f6cdd1d`, which provides significantly better
 * statistical properties than the raw state for the probability comparisons
 * made in `chaos_io_probability_hit_sample()`.
 *
 * @return A pseudo-random `uint32_t` uniformly distributed over [0, 2^32).
 *
 * @note This function is not re-entrant from a signal handler that fires
 * mid-computation; callers should not invoke it from signal contexts.
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

/** @} */

/**
 * @defgroup chaos_io_path_filter Path exclusion helpers
 * @{
 */

/**
 * @brief Returns non-zero when a path is exactly the active config file.
 *
 * @details The preload library must never inject faults into its own control plane, so
 * wrappers and cache code use this as an early exclusion check.
 *
 * @param[in] path  Null-terminated path string.  May be NULL.
 * @return Non-zero when `path` equals `CHAOS_IO_CONFIG_PATH`.
 */
static inline int chaos_io_is_config_path(const char *path)
{
    return path != NULL && strcmp(path, CHAOS_IO_CONFIG_PATH) == 0;
}

/**
 * @brief Returns non-zero when a path lives under a reserved top-level prefix.
 *
 * @details The helper enforces path-boundary-aware matching so `/proc` matches
 * `/proc/self/status` but not `/process`.  The boundary check requires that
 * the character immediately after the prefix is either NUL (exact match) or
 * `/` (subdirectory), preventing overzealous exclusions on paths that merely
 * share a common string prefix.
 *
 * @param[in] path    Null-terminated path to test.  May be NULL.
 * @param[in] prefix  Null-terminated prefix to match against.  May be NULL.
 * @return Non-zero when `path` is equal to or is a child of `prefix`.
 */
static inline int chaos_io_has_reserved_prefix(const char *path, const char *prefix)
{
    size_t prefix_len;

    if (path == NULL || prefix == NULL)
    {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0)
    {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

/**
 * @brief Returns whether a path is permanently excluded from injection.
 *
 * @details Excluded paths cover the control file and kernel-facing trees that the
 * library itself depends on. The same filter is applied before matching rules
 * and before storing fd-cache entries.
 *
 * Excluded paths:
 * - NULL or empty string (unresolvable or unknown)
 * - The config file path exactly (`/tmp/.chaos-io.conf`)
 * - Anything under `/proc`, `/sys`, or `/dev`
 *
 * The `/proc` exclusion is essential: resolving fd paths via
 * `/proc/self/fd/<n>` happens inside the internal guard but the resulting
 * resolved path must not itself be stored in the cache or matched against
 * rules.  The `/sys` and `/dev` exclusions prevent accidental injection into
 * device I/O or kernel interface files.
 *
 * @param[in] path  Null-terminated path to test.  May be NULL.
 * @return Non-zero when the path should be silently passed through.
 */
static inline int chaos_io_is_excluded_path(const char *path)
{
    if (path == NULL || *path == '\0')
    {
        return 1;
    }
    if (chaos_io_is_config_path(path))
    {
        return 1;
    }
    if (chaos_io_has_reserved_prefix(path, "/proc") || chaos_io_has_reserved_prefix(path, "/sys") ||
        chaos_io_has_reserved_prefix(path, "/dev"))
    {
        return 1;
    }
    return 0;
}

/** @} */

#endif
