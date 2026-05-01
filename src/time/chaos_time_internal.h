/**
 * @file chaos_time_internal.h
 * @brief Internal shared definitions for the libchaos-time subsystem.
 *
 * This header is the single point of truth for all definitions that must be
 * visible to every translation unit inside libchaos-time but that form no part
 * of the public ABI.  It exposes:
 *
 *  - Compile-time limits and sentinel mtime values used by the config reload
 *    protocol.
 *  - The visibility macro that marks exported interceptor symbols.
 *  - Function-pointer typedefs for the three intercepted syscall wrappers and
 *    the matching extern declarations of the global real-function pointers.
 *  - TLS variables that implement per-thread reentrancy guarding and PRNG
 *    state.
 *  - Inline helpers for the reentrancy guard, lock-free atomic primitives, and
 *    the per-thread xorshift64* PRNG seeded with SplitMix64 mixing.
 *
 * @module chaos-time
 * @stability Internal — not part of the installed public API.
 */

#ifndef CHAOS_TIME_INTERNAL_H
#define CHAOS_TIME_INTERNAL_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @defgroup chaos_time_limits Compile-time limits
 * @{
 */

/** Filesystem path of the configuration file polled for live reload. */
#define CHAOS_TIME_CONFIG_PATH "/tmp/.chaos-time.conf"

/** Maximum number of rules that may be loaded from a single config snapshot. */
#define CHAOS_TIME_MAX_RULES 256U

/** Maximum byte length of a single config line, including the NUL terminator. */
#define CHAOS_TIME_MAX_LINE_LENGTH 1024U

/**
 * Maximum total config file size accepted by the reader.
 *
 * Chosen as CHAOS_TIME_MAX_RULES * CHAOS_TIME_MAX_LINE_LENGTH so that a fully
 * populated file fits exactly within the per-thread read buffer.  Files that
 * reach this byte count without reaching EOF are rejected to avoid truncated
 * rule sets.
 */
#define CHAOS_TIME_MAX_CONFIG_BYTES (CHAOS_TIME_MAX_RULES * CHAOS_TIME_MAX_LINE_LENGTH)

/** Maximum length of a selector text field stored inside chaos_time_selector_t. */
#define CHAOS_TIME_MAX_TEXT 128U

/** Maximum length of an effect value payload, used for temporary parse buffers. */
#define CHAOS_TIME_MAX_VALUE 256U

/** @} */

/**
 * @defgroup chaos_time_visibility Symbol visibility
 * @{
 */

/**
 * Marks a symbol as having default ELF visibility.
 *
 * Applied to the three interceptor functions (clock_gettime, nanosleep,
 * usleep) so that the dynamic linker finds them before the libc originals when
 * the library is loaded via LD_PRELOAD.
 */
#define CHAOS_TIME_EXPORT __attribute__((visibility("default")))

/** @} */

/**
 * @defgroup chaos_time_mtime_sentinels Config mtime sentinel values
 *
 * The config reload protocol uses a single @c volatile @c uint64_t
 * (g_chaos_time_cached_mtime) to represent the state machine for live reload.
 * Three sentinel values are reserved; all other values represent a normalised
 * hash of the file's mtime.
 *
 * @{
 */

/**
 * The config file does not exist (stat returned ENOENT or any error).
 *
 * When the observed mtime equals this value, the next_state is zeroed and
 * published with an empty rule set (no chaos injected).
 */
#define CHAOS_TIME_MTIME_MISSING UINT64_C(0)

/**
 * A reload is in progress on another thread.
 *
 * This value is written into g_chaos_time_cached_mtime atomically via
 * compare-and-swap before the reloading thread begins reading the file.  Any
 * thread that loses the CAS race sees this value and falls back to the
 * currently active config without waiting.
 */
#define CHAOS_TIME_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * The cached mtime has never been set (initial state at library load).
 *
 * chaos_time_config_init() writes this value so that the first call to
 * chaos_time_config_prepare() on any thread will unconditionally attempt a
 * reload.
 */
#define CHAOS_TIME_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/**
 * @defgroup chaos_time_fn_ptrs Real-function pointer types and globals
 *
 * At constructor time, chaos_time_init() resolves each intercepted symbol to
 * the next definition in the dynamic linker chain (RTLD_NEXT) and stores the
 * result here.  All internal call sites that need the real behaviour use these
 * pointers directly rather than calling the symbol by name, which would
 * recurse back into the wrapper.
 *
 * @{
 */

/** Function-pointer type matching the POSIX clock_gettime(2) signature. */
typedef int (*chaos_time_clock_gettime_fn)(clockid_t, struct timespec *);

/** Function-pointer type matching the POSIX nanosleep(2) signature. */
typedef int (*chaos_time_nanosleep_fn)(const struct timespec *, struct timespec *);

/** Function-pointer type matching the POSIX usleep(3) signature. */
typedef int (*chaos_time_usleep_fn)(useconds_t);

/**
 * Resolved pointer to the real clock_gettime implementation.
 *
 * Set once during chaos_time_init() and never modified afterwards.
 * Read-only from all other translation units.
 */
extern chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime;

/**
 * Resolved pointer to the real nanosleep implementation.
 *
 * Set once during chaos_time_init() and never modified afterwards.
 * Read-only from all other translation units.
 */
extern chaos_time_nanosleep_fn g_chaos_time_real_nanosleep;

/**
 * Resolved pointer to the real usleep implementation.
 *
 * Set once during chaos_time_init() and never modified afterwards.
 * Read-only from all other translation units.
 */
extern chaos_time_usleep_fn g_chaos_time_real_usleep;

/** @} */

/**
 * @defgroup chaos_time_tls Thread-local state
 * @{
 */

/**
 * Per-thread reentrancy guard for the chaos interceptors.
 *
 * Non-zero while the current thread is executing inside the library itself
 * (e.g. during config stat/read, LATENCY sleep, or any other internal
 * operation that calls a function the library intercepts).  When a wrapper
 * entry point detects this flag it bypasses all chaos injection and calls the
 * real function directly, preventing recursive loops.
 *
 * The guard is manipulated exclusively through chaos_time_enter_internal() and
 * chaos_time_leave_internal(), which implement save/restore semantics rather
 * than simple set/clear.  See @ref chaos_time_guard for the detailed rationale.
 */
extern __thread int g_chaos_time_tls_guard;

/**
 * Per-thread PRNG state for the xorshift64* generator.
 *
 * Must never be zero; chaos_time_prng_ensure_seeded() enforces this invariant
 * by substituting a fixed non-zero constant if the mixed seed happens to
 * produce zero.  Stored per-thread so that concurrent callers produce
 * independent random streams without synchronisation.
 */
extern __thread uint64_t g_chaos_time_tls_prng_state;

/**
 * Process-wide base seed, set once from /dev/urandom during chaos_time_init().
 *
 * Each thread XORs this value with its TID and a stack-pointer contribution
 * before applying the SplitMix64 finaliser, ensuring that threads started
 * before and after library init all get distinct PRNG streams.
 */
extern uint64_t g_chaos_time_process_seed;

/** @} */

/**
 * @defgroup chaos_time_guard Reentrancy guard helpers
 *
 * The three inline functions below form the complete interface to the
 * per-thread reentrancy guard.  They are deliberately simple so that callers
 * cannot misuse them.
 *
 * ### Why save/restore rather than set-to-1 / set-to-0?
 *
 * Consider a LATENCY injection on @c nanosleep that calls
 * g_chaos_time_real_nanosleep() (via chaos_time_sleep_chunk()).  The call
 * sequence without save/restore would be:
 *
 * @code
 *   nanosleep wrapper enters       guard = 0 → set to 1
 *   LATENCY: sleep_chunk called    (guard is 1)
 *   sleep_chunk: enter_internal    guard = 1 → set to 1   (noop)
 *   real nanosleep returns
 *   sleep_chunk: leave_internal    guard set to 0          ← BUG
 *   // guard is now 0 while outer wrapper is still active
 *   outer wrapper calls real fn    guard = 0 → set to 1 again
 *   ...
 * @endcode
 *
 * With save/restore the inner leave_internal() restores the guard to the value
 * it had on entry to sleep_chunk (1), not to zero.  The outer leave_internal()
 * then restores it to 0 when the outer call truly finishes.  The same argument
 * applies to any nested internal operation (config stat, clock_gettime LATENCY
 * during a nanosleep LATENCY sleep, etc.).
 *
 * @{
 */

/**
 * Returns non-zero if the calling thread is currently inside the library.
 *
 * Entry points call this first; when it returns true they skip chaos injection
 * and forward directly to the real function.
 */
static inline int chaos_time_in_internal(void)
{
    return g_chaos_time_tls_guard != 0;
}

/**
 * Marks the calling thread as being inside the library.
 *
 * @return The previous value of the guard.  Callers must pass this to the
 *         matching chaos_time_leave_internal() call; discarding it breaks
 *         correct nesting.
 */
static inline int chaos_time_enter_internal(void)
{
    int previous = g_chaos_time_tls_guard;
    g_chaos_time_tls_guard = 1;
    return previous;
}

/**
 * Restores the guard to the value it had before the matching
 * chaos_time_enter_internal() call.
 *
 * @param previous  The value returned by the paired chaos_time_enter_internal().
 *
 * Must only be called by the same thread that called enter_internal().
 * Restores, rather than unconditionally clears, so that nested enter/leave
 * pairs work correctly.  See the module description for the detailed
 * reentrancy example.
 */
static inline void chaos_time_leave_internal(int previous)
{
    g_chaos_time_tls_guard = previous;
}

/** @} */

/**
 * @defgroup chaos_time_atomic Lock-free atomic primitives
 *
 * Thin wrappers around GCC built-in sync operations, used by the two-snapshot
 * config reload protocol.  Full memory barriers are emitted on both sides of
 * each operation.
 *
 * @{
 */

/**
 * Atomically loads a uint64_t with a full memory barrier.
 *
 * @param value  Pointer to the volatile variable to read.
 * @return       The value observed after the barrier.
 */
static inline uint64_t chaos_time_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * Atomically compares and conditionally swaps a uint64_t.
 *
 * Uses __sync_bool_compare_and_swap which issues a full memory barrier on
 * both success and failure paths.
 *
 * @param value     Pointer to the volatile variable to update.
 * @param expected  Value that must be currently stored for the swap to occur.
 * @param desired   Value to write if the swap succeeds.
 * @return          Non-zero if the swap was performed, zero otherwise.
 */
static inline int
chaos_time_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/** @} */

/**
 * @defgroup chaos_time_tid Thread identifier
 * @{
 */

/**
 * Returns a numeric identifier for the calling thread.
 *
 * On Linux, uses SYS_gettid to obtain the kernel thread ID, which is unique
 * within the process and across its lifetime.  On non-Linux platforms falls
 * back to getpid(), which identifies the process but does not distinguish
 * threads; the stack-address contribution to the PRNG seed then provides
 * most of the per-thread entropy.
 *
 * @return Numeric thread (or process) identifier cast to uint64_t.
 */
static inline uint64_t chaos_time_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/** @} */

/**
 * @defgroup chaos_time_prng Per-thread xorshift64* PRNG with SplitMix64 seeding
 *
 * The PRNG has two components:
 *
 * **Seed mixing — SplitMix64 finaliser** (Steele & Vigna, OOPSLA 2014)
 *
 * Raw seed material (process entropy XOR TID XOR stack address) is fed through
 * chaos_time_prng_mix() before being stored as PRNG state.  The function
 * implements the SplitMix64 finaliser:
 *
 *  1. Add the Weyl-sequence increment 0x9e3779b97f4a7c15 (derived from the
 *     golden ratio: floor((2^64) / phi)).
 *  2. Multiply by 0xbf58476d1ce4e5b9 after xorshift-right 30.
 *  3. Multiply by 0x94d049bb133111eb after xorshift-right 27.
 *  4. Final xorshift-right 31.
 *
 * These constants were selected by Steele & Vigna through exhaustive testing
 * for avalanche (every input bit affects every output bit) and minimal linear
 * complexity.  The result is that even seeds differing in a single bit produce
 * statistically independent PRNG streams.
 *
 * **Generator — xorshift64***
 *
 * chaos_time_prng_next_u32() advances the 64-bit state with the shift schedule
 * >>12, <<25, >>27 and then applies the output multiplier 0x2545f4914f6cdd1d
 * before returning the upper 32 bits.  The shift schedule has full period
 * 2^64 − 1 over the non-zero integers.  The output multiplier ensures that
 * low bits of the state are well distributed in the returned value.
 *
 * **Per-thread isolation**
 *
 * State is kept in TLS (g_chaos_time_tls_prng_state) so that concurrent
 * threads produce independent random streams without any synchronisation.
 * Each thread seeds independently from g_chaos_time_process_seed XOR TID XOR
 * stack address, so even threads created simultaneously get different initial
 * states.
 *
 * @{
 */

/**
 * SplitMix64 finaliser — maps an arbitrary uint64_t to a high-quality 64-bit
 * hash suitable for use as a PRNG seed.
 *
 * The constants and shift amounts are from Steele & Vigna, "Fast Splittable
 * Pseudorandom Number Generators", OOPSLA 2014.  They were chosen to maximise
 * avalanche: every bit of the input affects every bit of the output.
 *
 * @param value  Raw seed material (need not be uniformly distributed).
 * @return       Mixed seed value, never used in zero-detection — the caller is
 *               responsible for substituting a non-zero fallback if required.
 */
static inline uint64_t chaos_time_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * Lazily initialises the calling thread's PRNG state on first use.
 *
 * Combines g_chaos_time_process_seed (set from /dev/urandom at library init),
 * the kernel TID, and the address of a stack variable to produce per-thread
 * seed material.  The material is then mixed through chaos_time_prng_mix()
 * (SplitMix64 finaliser) to produce a high-quality initial state.
 *
 * If the mix result is zero (extremely unlikely but possible), the fallback
 * 0x2545f4914f6cdd1d (the xorshift64* output multiplier itself) is used,
 * ensuring the xorshift generator's invariant that state must not be zero.
 *
 * This function is idempotent: if g_chaos_time_tls_prng_state is already
 * non-zero it returns immediately.
 */
static inline void chaos_time_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_time_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_time_process_seed;
    seed ^= chaos_time_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed);
    if (g_chaos_time_tls_prng_state == 0U)
    {
        g_chaos_time_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * Explicitly seeds the calling thread's PRNG state from a caller-supplied
 * value.
 *
 * Intended for deterministic test scenarios where reproducible random streams
 * are required.  The seed is passed through chaos_time_prng_mix() before
 * storage so that low-quality seeds (e.g. small integers) still produce
 * statistically independent initial states.
 *
 * @param seed  Desired seed value.  If zero, the value 1 is substituted
 *              before mixing to prevent the xorshift generator from receiving
 *              a zero state.
 */
static inline void chaos_time_prng_seed_thread(uint64_t seed)
{
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * Advances the per-thread xorshift64* PRNG and returns the next 32-bit value.
 *
 * The generator uses the shift schedule >>12, <<25, >>27 which gives a full
 * period of 2^64 − 1 over the non-zero 64-bit integers.  The upper 32 bits of
 * (state * 0x2545f4914f6cdd1d) are returned; the multiplication scrambles the
 * low bits of the state that the shift operations leave poorly distributed.
 *
 * Calls chaos_time_prng_ensure_seeded() on first use per thread.
 *
 * @return  Pseudo-random uint32_t drawn uniformly from [0, 2^32).
 */
static inline uint32_t chaos_time_prng_next_u32(void)
{
    uint64_t state;

    chaos_time_prng_ensure_seeded();
    state = g_chaos_time_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_time_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

/** @} */

#endif
