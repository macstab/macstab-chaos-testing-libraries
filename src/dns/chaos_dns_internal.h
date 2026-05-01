/**
 * @file chaos_dns_internal.h
 * @brief Internal shared declarations for the libchaos-dns LD_PRELOAD library.
 *
 * @details
 * This header is included by every translation unit in the DNS chaos subsystem.
 * It collects three categories of shared state:
 *
 *   1. **Configuration constants** — compile-time upper bounds on config file
 *      size, number of rules, and field widths.
 *
 *   2. **Global state** — function pointers to the real (libc) resolver
 *      symbols resolved at construction time, the process-wide PRNG seed, and
 *      the per-thread reentrancy guard and PRNG state.
 *
 *   3. **Inline utilities** — reentrancy guard helpers, compiler-fence–based
 *      atomic primitives, platform-portable thread-ID accessor, and the full
 *      xorshift64* PRNG including lazy per-thread seeding.
 *
 * ### Visibility model
 * All symbols in this library are compiled with `-fvisibility=hidden` except
 * the interposed entry points (`getaddrinfo`, `getnameinfo`, `freeaddrinfo`)
 * which are marked @ref CHAOS_DNS_EXPORT.  This header does **not** declare
 * any exported symbols.
 *
 * ### Thread safety
 * Every function declared or defined here is either:
 *   - Pure / stateless (no writes), or
 *   - Restricted to TLS (`g_chaos_dns_tls_guard`, `g_chaos_dns_tls_prng_state`), or
 *   - Protected by the two-snapshot CAS reload protocol in chaos_dns_config.c.
 *
 * @module  libchaos-dns internals
 * @stability  Private — not part of any public API.
 */

#ifndef CHAOS_DNS_INTERNAL_H
#define CHAOS_DNS_INTERNAL_H

#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/** Filesystem path polled for the chaos rule configuration file. */
#define CHAOS_DNS_CONFIG_PATH "/tmp/.chaos-dns.conf"

/** Maximum number of rules that will be loaded from the config file. */
#define CHAOS_DNS_MAX_RULES 256U

/** Maximum byte length of a single config file line (including the newline). */
#define CHAOS_DNS_MAX_LINE_LENGTH 1024U

/**
 * @brief Maximum total config file size that will be read into the TLS buffer.
 *
 * @details Derived from CHAOS_DNS_MAX_RULES * CHAOS_DNS_MAX_LINE_LENGTH.  A
 * file larger than this causes the reload to be abandoned and the previously
 * loaded rule set to remain active (fail-open).
 */
#define CHAOS_DNS_MAX_CONFIG_BYTES (CHAOS_DNS_MAX_RULES * CHAOS_DNS_MAX_LINE_LENGTH)

/** Maximum byte length of a selector text field (hostname pattern, IP string). */
#define CHAOS_DNS_MAX_TEXT 256U

/** Maximum byte length of an effect value field (override address list, hostname, etc.). */
#define CHAOS_DNS_MAX_VALUE 512U

/**
 * @brief Mark a symbol as having default (exported) ELF visibility.
 *
 * @details Applied only to the interposed libc entry points
 * (`getaddrinfo`, `getnameinfo`, `freeaddrinfo`).  All other symbols remain
 * hidden so the dynamic linker cannot resolve them from outside the DSO.
 */
#define CHAOS_DNS_EXPORT __attribute__((visibility("default")))

/**
 * @name Config mtime sentinel values
 *
 * The cached-mtime field uses a few reserved values as state flags.  Any real
 * mtime hash must not collide with these three constants.  The normalization
 * function chaos_dns_config_normalize_mtime_hash() XORs with a constant if
 * the raw hash equals one of them.
 * @{
 */
/** mtime slot value indicating the config file did not exist on last check. */
#define CHAOS_DNS_MTIME_MISSING    UINT64_C(0)
/** mtime slot value set by the thread currently performing a reload (CAS lock). */
#define CHAOS_DNS_MTIME_RELOADING  UINT64_C(0xfffffffffffffffe)
/** mtime slot value used at process start before the first stat(2) call. */
#define CHAOS_DNS_MTIME_UNKNOWN    UINT64_C(0xffffffffffffffff)
/** @} */

/* -------------------------------------------------------------------------
 * Function-pointer typedefs for the real libc resolver symbols.
 * Resolved once by chaos_dns_init() via dlsym(RTLD_NEXT, ...).
 * ------------------------------------------------------------------------- */

/**
 * @brief Function pointer type matching the POSIX getaddrinfo(3) signature.
 * @see g_chaos_dns_real_getaddrinfo
 */
typedef int (*chaos_dns_getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

/**
 * @brief Function pointer type matching the POSIX getnameinfo(3) signature.
 * @see g_chaos_dns_real_getnameinfo
 */
typedef int (*chaos_dns_getnameinfo_fn)(
    const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int
);

/**
 * @brief Function pointer type matching the POSIX freeaddrinfo(3) signature.
 *
 * @details This pointer is used in two contexts:
 *   1. Inside the transform helpers (chaos_dns_filter_result_list,
 *      chaos_dns_limit_result_list) to free individual nodes excised from the
 *      list returned by the real getaddrinfo.
 *   2. In the interposed freeaddrinfo entry point (if present) when the caller
 *      frees a list that was synthesised entirely by the override path and
 *      therefore was also allocated via the real getaddrinfo.
 *
 * @see g_chaos_dns_real_freeaddrinfo
 */
typedef void (*chaos_dns_freeaddrinfo_fn)(struct addrinfo *);

/* -------------------------------------------------------------------------
 * Global variables — defined in chaos_dns.c, declared here for all TUs.
 * ------------------------------------------------------------------------- */

/**
 * @brief Pointer to the real libc getaddrinfo(3).
 *
 * @details Resolved by dlsym(RTLD_NEXT, "getaddrinfo") during the constructor.
 * NULL only if the constructor has not yet run or if resolution failed (the
 * latter causes abort()).  All call sites guard against the in-internal flag
 * before using this pointer, preventing recursive interposition.
 */
extern chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo;

/**
 * @brief Pointer to the real libc getnameinfo(3).
 * @see g_chaos_dns_real_getaddrinfo for lifecycle notes.
 */
extern chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo;

/**
 * @brief Pointer to the real libc freeaddrinfo(3).
 *
 * @details Used by the transform helpers to free individual addrinfo nodes
 * whose ownership has been transferred back to the library (e.g., nodes
 * dropped by FILTER_FAMILY or LIMIT).  Must not be called on nodes whose
 * ai_addr or ai_canonname was allocated separately by override logic.
 *
 * @see g_chaos_dns_real_getaddrinfo for lifecycle notes.
 */
extern chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo;

/**
 * @brief Per-thread reentrancy guard.
 *
 * @details Non-zero while the current thread is executing inside library
 * internals (symbol resolution, config file I/O, real resolver calls).
 * Prevents the interposed entry points from recursing when the real resolver
 * library itself calls getaddrinfo.
 *
 * Access pattern:
 * @code
 *   int previous = chaos_dns_enter_internal();
 *   // ... do internal work ...
 *   chaos_dns_leave_internal(previous);
 * @endcode
 * Saving and restoring `previous` rather than always clearing to 0 means
 * nested enter/leave pairs work correctly even across call stacks where the
 * outer frame already set the guard.
 */
extern __thread int g_chaos_dns_tls_guard;

/**
 * @brief Per-thread xorshift64* PRNG state.
 *
 * @details Initialised lazily by chaos_dns_prng_ensure_seeded() on first use.
 * Each thread gets a distinct seed derived from the process seed, the thread
 * ID, and the stack address of the seed-local variable to provide additional
 * entropy.  The invariant `state != 0` is maintained by substituting a
 * non-zero fallback constant if mixing produces zero.
 */
extern __thread uint64_t g_chaos_dns_tls_prng_state;

/**
 * @brief Process-wide base seed for per-thread PRNG initialisation.
 *
 * @details Set once in chaos_dns_init() from /dev/urandom (Linux) or a
 * PID-based fallback.  All threads XOR this value with their thread ID and a
 * stack address to derive their individual TLS seed, ensuring per-thread
 * independence without requiring a shared lock.
 */
extern uint64_t g_chaos_dns_process_seed;

/* -------------------------------------------------------------------------
 * Inline reentrancy guard helpers
 * ------------------------------------------------------------------------- */

/**
 * @brief Return non-zero if the current thread is already inside library internals.
 *
 * @details Tests the TLS guard without modifying it.  Used at the top of
 * every interposed entry point to short-circuit to the real implementation
 * when the call originates from within the library itself.
 *
 * @return Non-zero if re-entrant; zero if the call is from application code.
 *
 * @threadsafety  Safe — reads only TLS.
 */
static inline int chaos_dns_in_internal(void)
{
    return g_chaos_dns_tls_guard != 0;
}

/**
 * @brief Set the reentrancy guard and return the previous value.
 *
 * @details Must be paired with chaos_dns_leave_internal() using the returned
 * value.  Saving the previous state allows this to be called in nested
 * contexts without incorrectly clearing the guard on return.
 *
 * @return The value of g_chaos_dns_tls_guard before the call.
 *
 * @threadsafety  Safe — reads and writes only TLS.
 */
static inline int chaos_dns_enter_internal(void)
{
    int previous = g_chaos_dns_tls_guard;
    g_chaos_dns_tls_guard = 1;
    return previous;
}

/**
 * @brief Restore the reentrancy guard to its state before a matching enter call.
 *
 * @param previous  Value returned by the matching chaos_dns_enter_internal().
 *
 * @threadsafety  Safe — writes only TLS.
 */
static inline void chaos_dns_leave_internal(int previous)
{
    g_chaos_dns_tls_guard = previous;
}

/* -------------------------------------------------------------------------
 * Compiler-fence atomic helpers
 * -------------------------------------------------------------------------
 * These are intentionally minimal: the config reload path is the only
 * concurrent state, and it uses a single uint64_t CAS for lock-free
 * double-buffering.  Full C11 atomics are not used because the library
 * targets C99 toolchains.
 * ------------------------------------------------------------------------- */

/**
 * @brief Atomically load a 64-bit value with a full memory barrier.
 *
 * @details Issues a compiler and hardware memory fence via __sync_synchronize
 * before reading @p value.  Ensures that the index written by
 * chaos_dns_config_publish() is visible before the state array contents it
 * was protecting.
 *
 * @param value  Pointer to the volatile uint64_t to read.
 * @return  The current value of *value.
 *
 * @threadsafety  Safe — loads only; fence prevents reordering with prior stores.
 */
static inline uint64_t chaos_dns_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Compare-and-swap a 64-bit value.
 *
 * @details Wraps __sync_bool_compare_and_swap.  Used by the config reload path
 * as a single-winner election: only the thread that successfully CAS-es
 * g_chaos_dns_cached_mtime from @p expected to CHAOS_DNS_MTIME_RELOADING
 * proceeds with the reload; all other concurrent threads fall through to the
 * still-active config snapshot.
 *
 * @param value     Pointer to the volatile uint64_t target.
 * @param expected  Value the caller believes @p value holds.
 * @param desired   Value to write atomically if the CAS succeeds.
 * @return  Non-zero if the exchange was performed; zero if @p value != @p expected.
 *
 * @threadsafety  Safe — lock-free.
 */
static inline int
chaos_dns_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/* -------------------------------------------------------------------------
 * Thread-ID helper
 * ------------------------------------------------------------------------- */

/**
 * @brief Return a numeric identifier for the calling thread.
 *
 * @details On Linux, uses the gettid(2) syscall directly (avoids any libc
 * interposition that might trigger a re-entrant lookup).  On all other
 * platforms falls back to getpid(2), which gives per-process uniqueness but
 * not per-thread uniqueness; this is acceptable because the value is only
 * used as PRNG seed diversity material, not for correctness.
 *
 * @return  A uint64_t containing the thread (or process) ID.
 *
 * @threadsafety  Safe — read-only OS query, no shared state.
 */
static inline uint64_t chaos_dns_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/* -------------------------------------------------------------------------
 * xorshift64* PRNG
 * -------------------------------------------------------------------------
 * Algorithm: xorshift64 state update with a 64-bit Murmur3-style finaliser.
 * Chosen for its small state (one uint64_t per thread), simplicity, and
 * acceptable statistical quality for random-order shuffles and probability
 * threshold tests.  Cryptographic quality is not required or claimed.
 * ------------------------------------------------------------------------- */

/**
 * @brief Murmur3 / SplitMix64 bit-mixing finaliser.
 *
 * @details Applied to the raw seed material before storing it in the TLS PRNG
 * state.  Ensures that low-entropy seeds (e.g., small PIDs or TIDs) are
 * spread across the full 64-bit state space before the first xorshift step.
 * This is the SplitMix64 finaliser from Sebastiano Vigna's reference
 * implementation.
 *
 * @param value  Raw seed or intermediate value to mix.
 * @return  Finalised 64-bit value suitable for use as initial PRNG state.
 *
 * @threadsafety  Pure function — no shared state.
 */
static inline uint64_t chaos_dns_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Initialise the calling thread's PRNG state if it is zero.
 *
 * @details Called automatically by chaos_dns_prng_next_u32() so callers
 * never need to invoke it directly.  Seeds from three independent sources
 * XORed together:
 *   - @c g_chaos_dns_process_seed — randomised once per process from /dev/urandom
 *   - @c chaos_dns_current_tid()  — differentiates threads within the process
 *   - stack address of the local @c seed variable — adds ASLR-based entropy
 *
 * The combined value is passed through chaos_dns_prng_mix() to diffuse the
 * bits.  If mixing produces zero (which would make the xorshift degenerate),
 * a known non-zero constant is substituted.
 *
 * @post  g_chaos_dns_tls_prng_state != 0.
 *
 * @threadsafety  Reads g_chaos_dns_process_seed (set once, never modified
 * after init); all writes target TLS only.
 */
static inline void chaos_dns_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_dns_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_dns_process_seed;
    seed ^= chaos_dns_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed);
    if (g_chaos_dns_tls_prng_state == 0U)
    {
        g_chaos_dns_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * @brief Directly set the calling thread's PRNG state from an explicit seed.
 *
 * @details Used by the constructor (chaos_dns_init) to pre-seed the main
 * thread's PRNG from the process-wide seed so that the first call on the main
 * thread is not deferred to chaos_dns_prng_ensure_seeded().  Passing zero
 * is safe: it is normalised to 1 before mixing to avoid the zero-state trap.
 *
 * @param seed  Seed value; 0 is treated as 1.
 *
 * @post  g_chaos_dns_tls_prng_state != 0.
 *
 * @threadsafety  Writes only TLS.
 */
static inline void chaos_dns_prng_seed_thread(uint64_t seed)
{
    g_chaos_dns_tls_prng_state = chaos_dns_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Advance the per-thread PRNG and return a 32-bit pseudo-random value.
 *
 * @details The xorshift step uses the shifts (12, 25, 27) from Marsaglia's
 * xorshift family.  The output is the high 32 bits of (state *
 * 0x2545f4914f6cdd1d), which passes the Murmur3 finaliser's avalanche
 * requirement and gives a better distribution than the raw state LSBs.
 *
 * Used by:
 *   - chaos_dns_probability_hit() — compares the result against a threshold
 *     derived from rule->probability * 2^32.
 *   - chaos_dns_shuffle_result_list() — Fisher–Yates index selection.
 *
 * @return  A 32-bit pseudo-random value drawn uniformly from [0, 2^32).
 *
 * @pre   g_chaos_dns_tls_prng_state may be 0 (seeded lazily on first call).
 * @post  g_chaos_dns_tls_prng_state != 0; advances the PRNG by one step.
 *
 * @threadsafety  Reads and writes only TLS; safe to call concurrently from
 *               multiple threads without synchronisation.
 */
static inline uint32_t chaos_dns_prng_next_u32(void)
{
    uint64_t state;

    chaos_dns_prng_ensure_seeded();
    state = g_chaos_dns_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_dns_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
