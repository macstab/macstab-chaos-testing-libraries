/**
 * @file chaos_time_internal.h
 * @brief Definitions shared by every translation unit of libchaos-time; not part of the ABI.
 *
 * @details
 * Contents:
 *  - Paths of the rule file, status file and hits file, and the parser limits.
 *  - The change-stamp sentinels that double as the reload state machine.
 *  - Typedefs and globals for the eight real functions (clock_gettime, nanosleep, usleep,
 *    gettimeofday, time, sleep, timespec_get, clock_nanosleep), resolved through
 *    `dlsym(RTLD_NEXT)`.
 *  - The per-thread reentrancy guard, which makes every wrapper call straight through to
 *    the real function while the library itself is running.
 *  - The per-thread xorshift64* PRNG behind the probability gate: no locks, no shared
 *    cache lines, independent streams per thread and per forked child.
 *
 * Everything here is async-signal-safe: TLS reads and writes, `__sync` builtins and one
 * gettid system call. No function here sets errno.
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
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @defgroup chaos_time_limits Compile-time limits
 * @{
 */

/** Rule file; looked at no more than once per CHAOS_CHECK_INTERVAL_NS (1 ms) per process. */
#define CHAOS_TIME_CONFIG_PATH "/tmp/.chaos-time.conf"

/** Status file: outcome of the last load (see chaos_status.h). */
#define CHAOS_TIME_STATUS_PATH "/tmp/.chaos-time.status"

/** Hits file prefix; each image appends `.<n>` (see chaos_hits.h). */
#define CHAOS_TIME_HITS_PREFIX "/tmp/.chaos-time.hits"

/** Rules per snapshot; one more rejects the whole file (CHAOS_STATUS_REASON_TOO_MANY). */
#define CHAOS_TIME_MAX_RULES 256U

/** Nominal bytes per line; only used to size CHAOS_TIME_MAX_CONFIG_BYTES. */
#define CHAOS_TIME_MAX_LINE_LENGTH 1024U

/**
 * Rule-file size limit: 256 * 1024 bytes = 256 KiB.
 *
 * A file of this size or larger is rejected as a whole (CHAOS_STATUS_REASON_TOO_LARGE):
 * parsing a truncated prefix would load a rule set nobody wrote.
 */
#define CHAOS_TIME_MAX_CONFIG_BYTES (CHAOS_TIME_MAX_RULES * CHAOS_TIME_MAX_LINE_LENGTH)

/** Capacity of chaos_time_selector_t::text including the NUL; a longer clock name is invalid. */
#define CHAOS_TIME_MAX_TEXT 128U

/** Capacity of the value field (before `@probability`) including the NUL. */
#define CHAOS_TIME_MAX_VALUE 256U

/** @} */

/**
 * @defgroup chaos_time_visibility Symbol visibility
 * @{
 */

/**
 * Default ELF visibility for the eight wrappers.
 *
 * The library is built with hidden visibility; only symbols marked with this macro enter
 * the dynamic symbol table, where LD_PRELOAD places them ahead of libc's definitions.
 */
#define CHAOS_TIME_EXPORT __attribute__((visibility("default")))

/** @} */

/**
 * @defgroup chaos_time_mtime_sentinels Change-stamp sentinels
 *
 * g_chaos_time_cached_mtime is both the cached change stamp of the rule file (a hash of
 * mtime, size, inode and device) and the reload lock. The three values below are
 * reserved; chaos_time_config_normalize_mtime_hash() keeps a real stamp off the two
 * high ones. A real stamp of 0 is not remapped: such a file (probability 2^-64 per
 * stamp) is treated as missing until its stamp changes.
 *
 * @{
 */

/**
 * stat() of the rule file failed (ENOENT or any other error).
 *
 * A load that observes it publishes an empty snapshot and removes the status file.
 */
#define CHAOS_TIME_MTIME_MISSING UINT64_C(0)

/**
 * A thread of this process owns the reload.
 *
 * Installed by compare-and-swap before the file is read. Every other caller serves the
 * active snapshot without waiting. The atfork child handler turns an inherited value
 * back into UNKNOWN, since the owning thread does not exist in the child.
 */
#define CHAOS_TIME_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * No load has completed yet (set by chaos_time_config_init()).
 *
 * The next call loads the file unconditionally, bypassing the 1 ms throttle.
 */
#define CHAOS_TIME_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/**
 * @defgroup chaos_time_fn_ptrs Real-function pointer types and globals
 *
 * chaos_time_ensure_symbols() fills each pointer once with the real function
 * (`dlsym(RTLD_NEXT)`); the constructor and every wrapper call it first. Internal code
 * calls through these pointers: calling the symbol by name would re-enter the wrapper.
 *
 * A pointer stays NULL while resolution is still running (a call from inside dlsym, from
 * a preloaded allocator, or from a signal handler) or when no later object defines the
 * symbol. The call helpers in chaos_time_hooks.c then issue the system call directly.
 * Written only by the resolving thread; read without synchronisation afterwards.
 *
 * @{
 */

/** clock_gettime(2). */
typedef int (*chaos_time_clock_gettime_fn)(clockid_t, struct timespec *);

/** nanosleep(2). */
typedef int (*chaos_time_nanosleep_fn)(const struct timespec *, struct timespec *);

/** usleep(3). */
typedef int (*chaos_time_usleep_fn)(useconds_t);

/** gettimeofday(2); the zone argument is `void *` as in glibc and musl. */
typedef int (*chaos_time_gettimeofday_fn)(struct timeval *, void *);

/** time(2). */
typedef time_t (*chaos_time_time_fn)(time_t *);

/** sleep(3). */
typedef unsigned int (*chaos_time_sleep_fn)(unsigned int);

/** timespec_get(3), C11. */
typedef int (*chaos_time_timespec_get_fn)(struct timespec *, int);

/** clock_nanosleep(2); returns an error number instead of setting errno. */
typedef int (*chaos_time_clock_nanosleep_fn)(clockid_t, int, const struct timespec *, struct timespec *);

/** Real clock_gettime; NULL until resolved. */
extern chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime;

/** Real nanosleep; NULL until resolved. */
extern chaos_time_nanosleep_fn g_chaos_time_real_nanosleep;

/** Real usleep; NULL until resolved. Also used for LATENCY sleeps (chaos_time_actions.c). */
extern chaos_time_usleep_fn g_chaos_time_real_usleep;

/** Real gettimeofday; NULL until resolved. */
extern chaos_time_gettimeofday_fn g_chaos_time_real_gettimeofday;

/** Real time; NULL until resolved. */
extern chaos_time_time_fn g_chaos_time_real_time;

/** Real sleep; NULL until resolved. */
extern chaos_time_sleep_fn g_chaos_time_real_sleep;

/** Real timespec_get; NULL until resolved. */
extern chaos_time_timespec_get_fn g_chaos_time_real_timespec_get;

/** Real clock_nanosleep; NULL until resolved. */
extern chaos_time_clock_nanosleep_fn g_chaos_time_real_clock_nanosleep;

/** @} */

/**
 * @defgroup chaos_time_tls Thread-local state
 * @{
 */

/**
 * Per-thread reentrancy guard: non-zero while this thread runs library code.
 *
 * Set around the rule-file stat and read, LATENCY sleeps and every call of a real
 * function. A wrapper entered while it is set calls the real function and injects
 * nothing, so libchaos-time never faults or delays its own work and cannot recurse.
 * A signal handler that interrupts library code inherits the guard and is not faulted
 * either.
 *
 * Changed only through chaos_time_enter_internal() / chaos_time_leave_internal(), which
 * save and restore instead of set and clear (see @ref chaos_time_guard).
 */
extern __thread int g_chaos_time_tls_guard;

/**
 * Per-thread xorshift64* state; 0 means "not seeded yet".
 *
 * chaos_time_prng_ensure_seeded() replaces 0 with an odd value on the next draw. The
 * atfork child handler resets the forking thread's state to 0, so each child draws its
 * own stream instead of repeating the parent's decisions.
 */
extern __thread uint64_t g_chaos_time_tls_prng_state;

/**
 * Process-wide seed: 8 bytes of /dev/urandom read by chaos_time_init().
 *
 * Mixed with the thread id and a stack address when a thread seeds itself. Before the
 * constructor runs it holds a fixed constant, which the thread id and stack address
 * still decorrelate per thread.
 */
extern uint64_t g_chaos_time_process_seed;

/** @} */

/**
 * @defgroup chaos_time_guard Reentrancy guard helpers
 *
 * The complete interface to g_chaos_time_tls_guard.
 *
 * ### Why save/restore, not set/clear
 *
 * Guarded regions nest: the reload holds the guard around stat() and the file read, and
 * a LATENCY sleep raises it inside a region that may already hold it. With set/clear the
 * inner leave would clear the guard while the outer region is still running, and the
 * rest of that region would be faulted by the library's own rules:
 *
 * @code
 *   outer region   enter: guard 0 -> 1
 *   inner region   enter: guard 1 -> 1
 *   inner region   leave: guard -> 0      <- set/clear: outer region now unguarded
 *                  leave: guard -> 1      <- save/restore: still guarded
 *   outer region   leave: guard -> 0
 * @endcode
 *
 * Only the outermost leave returns the guard to 0.
 *
 * @{
 */

/**
 * Non-zero while the calling thread runs library code.
 *
 * Every wrapper tests this first and, when set, calls the real function unmodified.
 */
static inline int chaos_time_in_internal(void)
{
    return g_chaos_time_tls_guard != 0;
}

/**
 * Raises the calling thread's guard.
 *
 * @return The previous guard value; pass it to the matching chaos_time_leave_internal()
 *         on every exit path of the region.
 */
static inline int chaos_time_enter_internal(void)
{
    int previous = g_chaos_time_tls_guard;
    g_chaos_time_tls_guard = 1;
    return previous;
}

/**
 * Restores the guard to its value before the matching chaos_time_enter_internal().
 *
 * @param previous  Value returned by that call, on the same thread.
 */
static inline void chaos_time_leave_internal(int previous)
{
    g_chaos_time_tls_guard = previous;
}

/** @} */

/**
 * @defgroup chaos_time_atomic Lock-free atomic primitives
 *
 * `__sync` builtins for the reload protocol. `__sync`, not C11 `<stdatomic.h>`: the
 * library is C99. Both are full barriers. 64-bit loads and stores are single-copy atomic
 * on the two supported targets (amd64, arm64).
 *
 * @{
 */

/**
 * Loads @p value after a full barrier.
 *
 * @param value  Variable to read.
 * @return       The value; later loads are not reordered before it.
 */
static inline uint64_t chaos_time_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * Replaces @p expected with @p desired atomically; a full barrier either way.
 *
 * @param value     Variable to update.
 * @param expected  Value that must be stored for the swap to happen.
 * @param desired   Value to store.
 * @return          Non-zero when the swap happened.
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
 * Kernel thread id of the caller, as seed material only.
 *
 * Raw `SYS_gettid`: the gettid() wrapper exists only since glibc 2.30. Off Linux the pid
 * stands in and the stack address separates the threads.
 *
 * @return Thread id (pid off Linux).
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
 * Drives the probability gate only; not cryptographic.
 *
 * - **Seeding:** process seed XOR thread id XOR a stack address, passed through the
 *   SplitMix64 finaliser, so seeds that differ in one bit give unrelated states. Weyl
 *   increment 0x9e3779b97f4a7c15 = floor(2^64/phi).
 * - **Generator:** xorshift64*: shifts 12/25/27, period 2^64 - 1 over non-zero
 *   states, output multiplier 0x2545f4914f6cdd1d, upper 32 bits returned because the low
 *   bits of the product are the weakest.
 * - **Isolation:** state is `__thread`, so draws take no lock and touch no shared cache
 *   line; a thread seeds itself on its first draw.
 *
 * @{
 */

/**
 * SplitMix64 finaliser: a bijective 64-bit mix with full avalanche.
 *
 * @param value  Seed material of any quality.
 * @return       Mixed value; may be 0, callers that need a non-zero state ensure it.
 */
static inline uint64_t chaos_time_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * Seeds the calling thread's PRNG unless it already has a state.
 *
 * Seed material is the process seed XOR thread id XOR the address of a local, mixed with
 * chaos_time_prng_mix() and forced odd, so the state is never 0 (the one state
 * xorshift64* never leaves). Async-signal-safe; errno is not touched.
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
    /* Odd, hence never 0: the one state xorshift64* cannot leave. */
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed) | 1U;
}

/**
 * Seeds the calling thread's PRNG with mix(@p seed): the constructor seeds the main
 * thread this way, and unit tests use it for reproducible streams.
 *
 * Unlike chaos_time_prng_ensure_seeded() the result is not forced odd; a mixed value of
 * 0 is only treated as "unseeded" and replaced on the next draw.
 *
 * @param seed  Seed; 0 is replaced by 1 before mixing.
 */
static inline void chaos_time_prng_seed_thread(uint64_t seed)
{
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * Next 32-bit value of the calling thread's xorshift64* stream; seeds it on first use.
 *
 * @return Uniform value in [0, 2^32).
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

/**
 * @brief Resolves all eight real functions once, on whichever call comes first.
 *
 * @details The constructor alone is not enough: ELF initialisers run in dependency
 * order, so another object's constructor can reach a wrapper before this library's
 * constructor has run. Every wrapper calls this first. Other threads wait (spinning on
 * sched_yield()) until resolution completes; a call re-entering from the resolving
 * thread itself (dlsym -> preloaded allocator, or a signal handler) returns at once
 * and the call helpers fall back to raw system calls (see chaos_once.h). After
 * completion the cost is one acquire load.
 */
void chaos_time_ensure_symbols(void);

#endif
