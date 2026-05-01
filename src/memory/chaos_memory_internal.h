/**
 * @file chaos_memory_internal.h
 * @brief Internal shared declarations for the libchaos-memory LD_PRELOAD module.
 *
 * @details
 * This header is the spine of the memory chaos subsystem.  It is included by
 * every translation unit in the module and is **not** part of any public API.
 *
 * Responsibilities carried by this header:
 *  - Platform compatibility shims (MAP_ANONYMOUS normalisation, Linux gettid).
 *  - Compile-time constants governing config file path, rule limits, and magic
 *    sentinel values used by the two-snapshot config reload protocol.
 *  - Function-pointer typedefs and extern declarations for the real libc symbols
 *    resolved once at constructor time.
 *  - The per-thread reentrancy guard and PRNG state variables.
 *  - Inline helpers: reentrancy guard enter/leave, atomic load/CAS, PRNG, and
 *    the MAP_ANONYMOUS classifier that drives mmap/anon vs mmap/file selection.
 *
 * @par Thread safety
 * All mutable global state uses either TLS (`__thread`) or
 * `__sync_*` builtins.  The inline helpers in this header are safe to call
 * from any thread, including from within a reentrancy-guarded frame.
 *
 * @par Stability
 * Internal — subject to change without notice.  Do not include from outside the
 * memory chaos module.
 */
#ifndef CHAOS_MEMORY_INTERNAL_H
#define CHAOS_MEMORY_INTERNAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @brief Ensure MAP_ANONYMOUS is defined.
 *
 * @details
 * On Linux, MAP_ANONYMOUS == 0x20.  Some older or non-Linux BSDs expose the
 * same flag as MAP_ANON.  This shim normalises both spellings to MAP_ANONYMOUS
 * so the rest of the module can use a single constant.
 *
 * This library targets Linux exclusively; the shim exists only to prevent
 * compile-time errors on systems that still use the historical spelling.
 */
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

/**
 * @brief Absolute path to the chaos-memory configuration file.
 *
 * @details
 * The file is polled for modification-time changes on every intercepted call.
 * Writing a new config atomically (e.g., via rename(2)) is the recommended
 * way to update rules without races.  An absent file is treated as zero rules
 * (fail-open: all calls proceed normally).
 */
#define CHAOS_MEMORY_CONFIG_PATH "/tmp/.chaos-memory.conf"

/**
 * @brief Maximum number of rules that can be parsed from the config file.
 *
 * @details
 * Rules beyond this limit cause the entire config reload to be rejected.
 * The limit is sized to bound the per-thread stack-allocated parse buffer.
 */
#define CHAOS_MEMORY_MAX_RULES 256U

/**
 * @brief Maximum byte length of a single config file line, including the
 *        newline terminator.
 */
#define CHAOS_MEMORY_MAX_LINE_LENGTH 1024U

/**
 * @brief Maximum total byte size of the config file that will be read.
 *
 * @details
 * Equals CHAOS_MEMORY_MAX_RULES * CHAOS_MEMORY_MAX_LINE_LENGTH.  A config
 * file that reaches this limit (before the final newline) is rejected so that
 * a partial read cannot be mistaken for the full config.
 */
#define CHAOS_MEMORY_MAX_CONFIG_BYTES (CHAOS_MEMORY_MAX_RULES * CHAOS_MEMORY_MAX_LINE_LENGTH)

/**
 * @brief Maximum byte length of a single parsed field value (errno name,
 *        latency string, etc.) inside a rule.
 */
#define CHAOS_MEMORY_MAX_VALUE 256U

/**
 * @brief Visibility attribute applied to the exported mmap/munmap/mprotect/madvise symbols.
 *
 * @details
 * The symbols must have default ELF visibility so that the dynamic linker
 * interposes them ahead of the libc definitions when the library is preloaded.
 */
#define CHAOS_MEMORY_EXPORT __attribute__((visibility("default")))

/**
 * @brief Sentinel mtime hash: config file does not exist (stat(2) failed).
 *
 * @details
 * Stored in g_chaos_memory_cached_mtime when a previous stat showed the file
 * absent.  Value 0 is chosen because chaos_memory_config_normalize_mtime_hash()
 * guarantees that a real mtime hash never equals 0 or the other two sentinels.
 */
#define CHAOS_MEMORY_MTIME_MISSING UINT64_C(0)

/**
 * @brief Sentinel mtime hash: a config reload is in progress on another thread.
 *
 * @details
 * The two-snapshot CAS protocol sets g_chaos_memory_cached_mtime to this value
 * atomically before it writes to the inactive config slot.  Any competing thread
 * that observes this value loses the CAS race and skips the reload, falling back
 * to the currently active snapshot.
 *
 * chaos_memory_config_normalize_mtime_hash() shifts real hashes that collide
 * with this sentinel down by one so this value is never produced from real stat
 * timestamps.
 */
#define CHAOS_MEMORY_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Sentinel mtime hash: cache has not yet been populated (initial state).
 *
 * @details
 * Set at construction time before the first stat.  Forces an unconditional
 * reload on the first call to chaos_memory_config_prepare().
 *
 * chaos_memory_config_normalize_mtime_hash() shifts real hashes that collide
 * with this sentinel down by one so this value is never produced from real stat
 * timestamps.
 */
#define CHAOS_MEMORY_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/* =========================================================================
 * Function-pointer typedefs for real libc symbols
 * =========================================================================
 * These typedefs capture the exact signatures of the intercepted syscall
 * wrappers.  Storing them as function pointers rather than calling through
 * dlsym() every time avoids repeated symbol lookups in the hot path and
 * makes the call-through explicit in the code.
 */

/** @brief Signature of the real mmap(2). */
typedef void *(*chaos_memory_mmap_fn)(void *, size_t, int, int, int, off_t);

/** @brief Signature of the real munmap(2). */
typedef int (*chaos_memory_munmap_fn)(void *, size_t);

/** @brief Signature of the real mprotect(2). */
typedef int (*chaos_memory_mprotect_fn)(void *, size_t, int);

/** @brief Signature of the real madvise(2). */
typedef int (*chaos_memory_madvise_fn)(void *, size_t, int);

/**
 * @brief Signature of the real nanosleep(2).
 *
 * @details
 * Used as a fallback sleep primitive when usleep is unavailable.  The
 * implementation restarts on EINTR by passing the @c rem argument back as
 * @c req.
 */
typedef int (*chaos_memory_nanosleep_fn)(const struct timespec *, struct timespec *);

/**
 * @brief Signature of the real usleep(3).
 *
 * @details
 * Preferred sleep primitive for LATENCY injection because it accepts a
 * microsecond granularity directly.  Resolved at constructor time; if NULL
 * the implementation falls back to nanosleep.
 */
typedef int (*chaos_memory_usleep_fn)(useconds_t);

/* =========================================================================
 * Resolved real-symbol pointers
 * =========================================================================
 * Populated by chaos_memory_init() via dlsym(RTLD_NEXT, ...) before any
 * intercepted call can be made.  All are NULL until the constructor runs.
 * Access is always through the inline call-through helpers in
 * chaos_memory_hooks.c, which hold the reentrancy guard around the call.
 */

/** @brief Pointer to the real mmap(2) resolved via RTLD_NEXT. */
extern chaos_memory_mmap_fn g_chaos_memory_real_mmap;

/** @brief Pointer to the real munmap(2) resolved via RTLD_NEXT. */
extern chaos_memory_munmap_fn g_chaos_memory_real_munmap;

/** @brief Pointer to the real mprotect(2) resolved via RTLD_NEXT. */
extern chaos_memory_mprotect_fn g_chaos_memory_real_mprotect;

/** @brief Pointer to the real madvise(2) resolved via RTLD_NEXT. */
extern chaos_memory_madvise_fn g_chaos_memory_real_madvise;

/** @brief Pointer to the real nanosleep(2) resolved via RTLD_NEXT. */
extern chaos_memory_nanosleep_fn g_chaos_memory_real_nanosleep;

/** @brief Pointer to the real usleep(3) resolved via RTLD_NEXT. */
extern chaos_memory_usleep_fn g_chaos_memory_real_usleep;

/* =========================================================================
 * TLS reentrancy guard and PRNG state
 * =========================================================================
 */

/**
 * @brief Per-thread reentrancy depth flag.
 *
 * @details
 * Non-zero when the current thread is executing inside the chaos library
 * (config I/O, dlsym resolution, sleep calls, or any other internal path).
 * The intercepted symbols check this before applying any fault so that
 * recursive calls from the library's own internals bypass injection entirely.
 *
 * @par Why mmap needs this more than read/write
 * mmap is called by:
 *  1. The dynamic linker during dlopen() — resolving RTLD_NEXT itself may
 *     trigger an mmap call before the guard is set, leading to infinite
 *     recursion.
 *  2. glibc's malloc for allocations above MMAP_THRESHOLD (default 128 KiB).
 *     Any heap allocation inside the chaos path (logging, sprintf, etc.) could
 *     re-enter the mmap hook.
 *  3. TLS block expansion: the first access to a `__thread` variable by a new
 *     thread may require the OS to map a new TLS block.  Reading the guard
 *     itself could therefore trigger an mmap call, creating a bootstrapping
 *     hazard.  The guard's TLS storage is allocated at thread creation time by
 *     the initial TLS image and does not require a dynamic mmap, which is why
 *     the guard can safely be read before it is set.
 *  4. The config read path (open/read/stat via glibc wrappers may internally
 *     call mmap on some allocator code paths).
 *
 * @note TLS (`__thread`).  Zero-initialised per C thread model.  Never
 *       accessed from a different thread.
 */
extern __thread int g_chaos_memory_tls_guard;

/**
 * @brief Per-thread xorshift64* PRNG state.
 *
 * @details
 * Holds the 64-bit state word for the per-thread PRNG.  Zero is the
 * uninitialised sentinel; chaos_memory_prng_ensure_seeded() populates it on
 * first use.  The seeding path does not allocate memory (it mixes
 * g_chaos_memory_process_seed with the TID and stack address) so it is safe
 * inside the reentrancy guard.
 *
 * @note TLS (`__thread`).  Each thread gets an independent PRNG stream so
 *       probability evaluations do not require synchronisation.
 */
extern __thread uint64_t g_chaos_memory_tls_prng_state;

/**
 * @brief Process-wide seed derived from /dev/urandom at constructor time.
 *
 * @details
 * Read once in chaos_memory_init() using raw syscalls (SYS_openat + SYS_read)
 * to avoid re-entering the mmap hook via glibc's stdio path.  Every thread's
 * TLS PRNG is seeded by XOR-ing this value with the thread ID and a stack
 * address, producing independent per-thread streams that are still causally
 * linked to the process entropy pool.
 *
 * If /dev/urandom is unavailable, a deterministic fallback
 * (0x6a09e667f3bcc909 ^ getpid()) is used; fault injection remains
 * probabilistic but reproducible across runs with the same PID.
 */
extern uint64_t g_chaos_memory_process_seed;

/* =========================================================================
 * Reentrancy guard — inline helpers
 * =========================================================================
 */

/**
 * @brief Test whether the current thread is inside an internal chaos frame.
 *
 * @details
 * Returns non-zero if g_chaos_memory_tls_guard is set.  Callers that receive
 * a non-zero result must forward the call to the real symbol immediately
 * without any fault injection.
 *
 * @return Non-zero if already inside internal code, zero otherwise.
 */
static inline int chaos_memory_in_internal(void)
{
    return g_chaos_memory_tls_guard != 0;
}

/**
 * @brief Enter an internal chaos frame, acquiring the reentrancy guard.
 *
 * @details
 * Sets g_chaos_memory_tls_guard to 1 and returns the previous value so that
 * the caller can restore it with chaos_memory_leave_internal().  The
 * save/restore pattern supports nested enter/leave pairs, which occur when
 * the config read path calls open()/read() whose wrappers might themselves
 * call into this module (though those symbols are not intercepted, the
 * pattern is defensive).
 *
 * @return Previous value of g_chaos_memory_tls_guard (0 or 1).
 */
static inline int chaos_memory_enter_internal(void)
{
    int previous = g_chaos_memory_tls_guard;
    g_chaos_memory_tls_guard = 1;
    return previous;
}

/**
 * @brief Leave an internal chaos frame, restoring the reentrancy guard.
 *
 * @param previous  Value returned by the matching chaos_memory_enter_internal()
 *                  call.  Restores exactly the depth that existed before the
 *                  paired enter, supporting nested frames correctly.
 */
static inline void chaos_memory_leave_internal(int previous)
{
    g_chaos_memory_tls_guard = previous;
}

/* =========================================================================
 * Atomic helpers (GCC built-ins, C99 compatible)
 * =========================================================================
 */

/**
 * @brief Sequentially consistent load of a 64-bit value.
 *
 * @details
 * Issues a full memory barrier before the load so that the caller observes
 * the most recent store from any thread.  Used to read g_chaos_memory_cached_mtime
 * and g_chaos_memory_active_config_index without tearing.
 *
 * @param value  Pointer to the volatile uint64_t to load.
 * @return       The value after the memory barrier.
 */
static inline uint64_t chaos_memory_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Compare-and-swap on a 64-bit value (GCC __sync built-in).
 *
 * @details
 * Atomically compares *value with @p expected; if equal, stores @p desired and
 * returns 1.  Otherwise returns 0 and leaves *value unchanged.  Used to
 * implement the single-winner reload protocol: exactly one thread per mtime
 * change wins the CAS and performs the reload; all others fall back to the
 * currently active snapshot.
 *
 * @param value     Pointer to the volatile uint64_t to update.
 * @param expected  Value that must be observed for the swap to succeed.
 * @param desired   Value to write if the swap succeeds.
 * @return          1 if the swap succeeded, 0 if it did not.
 */
static inline int
chaos_memory_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/* =========================================================================
 * Thread identity
 * =========================================================================
 */

/**
 * @brief Return a per-thread numeric identifier used for PRNG seeding.
 *
 * @details
 * On Linux this is the kernel TID obtained via SYS_gettid, which is unique
 * process-wide.  On other platforms (compilation fallback only; this library
 * targets Linux) the PID is returned instead, which gives all threads the
 * same value — acceptable since the stack-address term still differentiates
 * them.
 *
 * @return A uint64_t that is unique per kernel thread on Linux.
 */
static inline uint64_t chaos_memory_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/* =========================================================================
 * PRNG — xorshift64* with splitmix64 finaliser
 * =========================================================================
 */

/**
 * @brief Apply the splitmix64 finaliser to a 64-bit value.
 *
 * @details
 * Used to mix seed material (process seed XOR tid XOR stack address) into a
 * high-quality initial PRNG state.  The three-step multiply-xorshift cascade
 * is the standard splitmix64 constants; it passes SmallCrush and PractRand
 * and has no known short cycles.
 *
 * This function does not allocate memory and does not touch any global state,
 * making it safe to call anywhere in the module including before the PRNG is
 * seeded or inside the reentrancy guard.
 *
 * @param value  Input value to mix.
 * @return       Finalised 64-bit value with good avalanche properties.
 */
static inline uint64_t chaos_memory_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Seed the per-thread PRNG if it has not been seeded yet.
 *
 * @details
 * Called lazily by chaos_memory_prng_next_u32() before producing the first
 * random value for a thread.  The seed is derived entirely from values
 * available without any I/O or heap allocation:
 *  - g_chaos_memory_process_seed  (from /dev/urandom at init, or fallback)
 *  - The kernel TID                (process-wide unique per thread)
 *  - The address of a local variable (ASLR-derived stack offset)
 *
 * The XOR combination is passed through chaos_memory_prng_mix() to break
 * linear correlations between threads that share the same process seed.
 *
 * Zero is the uninitialised sentinel for g_chaos_memory_tls_prng_state.  If
 * the mix produces zero (probability 2^-64), the state is replaced with a
 * fixed non-zero constant to keep the PRNG alive.
 *
 * @note No /dev/urandom access occurs here.  The per-thread seed is derived
 *       purely from in-process state, so this function cannot trigger a
 *       recursive mmap call through glibc's open() path.
 */
static inline void chaos_memory_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_memory_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_memory_process_seed;
    seed ^= chaos_memory_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed);
    if (g_chaos_memory_tls_prng_state == 0U)
    {
        g_chaos_memory_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * @brief Unconditionally seed the per-thread PRNG with a given value.
 *
 * @details
 * Intended for testing and for the initial seeding in chaos_memory_init()
 * where the process-seed has just been read and must be applied immediately
 * to the main thread's PRNG state.
 *
 * If @p seed is zero (invalid PRNG state sentinel), the value 1 is used
 * before mixing so the PRNG is never left in the all-zero absorbing state.
 *
 * @param seed  Raw seed value.  Zero is treated as 1 before mixing.
 */
static inline void chaos_memory_prng_seed_thread(uint64_t seed)
{
    g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Produce the next 32-bit pseudo-random value from the per-thread stream.
 *
 * @details
 * Implements xorshift64* — a three-step xorshift on the 64-bit state followed
 * by multiplication with a Weyl constant to extract the upper 32 bits.  The
 * algorithm has a period of 2^64 - 1, passes BigCrush, and requires no memory
 * allocation or synchronisation.
 *
 * chaos_memory_prng_ensure_seeded() is called first so that the PRNG is
 * transparently initialised on first use even for threads that did not call
 * chaos_memory_prng_seed_thread() explicitly.
 *
 * The returned value is uniformly distributed in [0, 2^32).  Probability
 * thresholding in chaos_memory_probability_hit_sample() compares it against a
 * scaled threshold without bias for probability values representable as
 * fractions of 2^32.
 *
 * @return 32-bit pseudo-random value.
 */
static inline uint32_t chaos_memory_prng_next_u32(void)
{
    uint64_t state;

    chaos_memory_prng_ensure_seeded();
    state = g_chaos_memory_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_memory_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

/**
 * @brief Classify an mmap flags word as anonymous or file-backed.
 *
 * @details
 * Tests whether MAP_ANONYMOUS (0x20 on Linux) is set in @p flags.
 *
 * @par Why this distinction matters for allocator pressure testing
 * glibc's malloc uses mmap(MAP_ANONYMOUS | MAP_PRIVATE) for allocations that
 * exceed MMAP_THRESHOLD (default 128 KiB, tunable via mallopt(M_MMAP_THRESHOLD,
 * ...)).  Allocations below the threshold use the brk/sbrk heap.  Injecting
 * ERRNO:ENOMEM on the `mmap/anon` selector therefore simulates allocator
 * pressure for large objects under glibc, but small allocations are unaffected
 * (they never reach the mmap hook).
 *
 * musl libc's malloc always uses mmap(MAP_ANONYMOUS | MAP_PRIVATE) for every
 * allocation — there is no brk path.  Under musl, ERRNO:ENOMEM on `mmap/anon`
 * causes malloc() to return NULL for all allocation sizes immediately, giving
 * complete allocator failure coverage with a single rule.
 *
 * @par Platform note
 * MAP_ANONYMOUS == 0x20 on all supported Linux architectures (x86, x86-64,
 * arm64, riscv64).  This library targets Linux only; MAP_ANON is normalised
 * to MAP_ANONYMOUS at the top of this header for completeness.
 *
 * @param flags  The @p flags argument passed to mmap(2).
 * @return       Non-zero if MAP_ANONYMOUS is set (anonymous mapping),
 *               zero if clear (file-backed or device mapping).
 */
static inline int chaos_memory_mmap_is_anonymous(int flags)
{
    return (flags & MAP_ANONYMOUS) != 0;
}

#endif
