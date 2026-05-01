/**
 * @file chaos_process_internal.h
 * @brief Internal ABI contracts, global state, and inline utilities for the
 *        libchaos-process LD_PRELOAD fault-injection subsystem.
 *
 * @details
 * This header is the private spine of the process chaos library.  It is
 * included by every translation unit in the subsystem and must never be
 * exposed to consumers of the library.
 *
 * ## Subsystem overview
 *
 * libchaos-process interposes the following libc/POSIX symbols at the dynamic
 * linker level via LD_PRELOAD:
 *
 *   - `pthread_create(3)` — NPTL thread creation
 *   - `fork(2)` / `vfork(2)` — process forking
 *   - `posix_spawn(3)` / `posix_spawnp(3)` — spawn-with-exec
 *   - `execve(2)` / `execveat(2)` — process image replacement
 *   - `waitpid(2)` — child process reaping
 *
 * Each wrapper may inject ERRNO failures, artificial LATENCY, or
 * FAIL_AFTER-counted failures as described by a rules file loaded at runtime.
 *
 * ## Re-entrancy guard
 *
 * Because many interposed functions are also called internally (e.g. `stat`
 * invoked during config reload calls through libc which may in turn call our
 * interposed symbols), the library maintains a per-thread TLS re-entrancy
 * guard (`g_chaos_process_tls_guard`).  Any code path that must reach real
 * libc without passing through chaos logic must bracket itself with
 * `chaos_process_enter_internal()` / `chaos_process_leave_internal()`.
 *
 * ## PRNG
 *
 * Each thread has its own xorshift64* PRNG state seeded from the process-wide
 * seed XOR-ed with the thread ID and a stack address.  This ensures
 * independent per-thread probability decisions without locks.
 *
 * ## Stability
 * Private — not part of the public API.  Definitions may change between
 * library versions without notice.
 */

#ifndef CHAOS_PROCESS_INTERNAL_H
#define CHAOS_PROCESS_INTERNAL_H

#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/** @defgroup chaos_process_constants Compile-time limits and sentinel values
 *  @{
 */

/** Filesystem path from which the live rules file is read. */
#define CHAOS_PROCESS_CONFIG_PATH "/tmp/.chaos-process.conf"

/** Maximum number of rules that can be loaded from a single config file. */
#define CHAOS_PROCESS_MAX_RULES 256U

/** Maximum byte length of a single config line (including NUL). */
#define CHAOS_PROCESS_MAX_LINE_LENGTH 1024U

/**
 * Maximum total bytes of config file that will be read in a single reload.
 * If the file is exactly this size the read is treated as a truncation error
 * and the reload fails (the previous valid config is retained).
 */
#define CHAOS_PROCESS_MAX_CONFIG_BYTES (CHAOS_PROCESS_MAX_RULES * CHAOS_PROCESS_MAX_LINE_LENGTH)

/** Maximum byte length of a single field value token within a config line. */
#define CHAOS_PROCESS_MAX_VALUE 256U

/**
 * Symbol visibility attribute applied to every interposed public symbol.
 * Required so the dynamic linker can resolve these names ahead of libc.
 */
#define CHAOS_PROCESS_EXPORT __attribute__((visibility("default")))

/**
 * Sentinel stored in `g_chaos_process_cached_mtime` when the config file
 * does not exist on disk.  A missing file means "no active rules".
 */
#define CHAOS_PROCESS_MTIME_MISSING UINT64_C(0)

/**
 * Sentinel written into `g_chaos_process_cached_mtime` during a config
 * reload to act as an optimistic lock.  A CAS from the previously observed
 * mtime to this value serialises concurrent reloaders: only the thread that
 * wins the CAS performs the actual read+parse; all others fall through to the
 * currently active config state.
 */
#define CHAOS_PROCESS_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * Initial value of `g_chaos_process_cached_mtime` set during library init.
 * Forces the first call to `chaos_process_config_prepare()` to unconditionally
 * attempt a reload regardless of whether the config file is present.
 */
#define CHAOS_PROCESS_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/** @defgroup chaos_process_fptypes Function-pointer typedefs for real symbols
 *  @{
 *
 * These typedefs describe the ABI of each intercepted symbol exactly as it
 * appears in the system libc.  The corresponding `g_chaos_process_real_*`
 * globals are populated by `dlsym(RTLD_NEXT, ...)` during library
 * constructor execution.
 */

/** Signature of the real `pthread_create(3)`. */
typedef int (*chaos_process_pthread_create_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

/** Signature of the real `fork(2)`. */
typedef pid_t (*chaos_process_fork_fn)(void);

/**
 * Signature of the real `posix_spawn(3)`.
 *
 * @note On glibc, `posix_spawn` is implemented via `__spawnix` which uses
 *       `clone(CLONE_VFORK|CLONE_VM, ...)` internally — it does NOT call the
 *       libc `fork()` symbol.  Therefore a `fork:ERRNO:EAGAIN` rule does NOT
 *       affect `posix_spawn` on glibc.  Our wrapper intercepts at the
 *       `posix_spawn` ABI boundary directly, so it fires regardless of the
 *       underlying implementation path.
 *
 *       On musl, `posix_spawn` calls `fork()` then `exec()`, so a `fork`
 *       rule WOULD additionally affect it — but our direct wrapper fires
 *       first, before the musl path reaches the (also interposed) `fork`.
 */
typedef int (*chaos_process_posix_spawn_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);

/**
 * Signature of the real `posix_spawnp(3)`.
 * Same glibc/musl divergence as `posix_spawn` applies here; see above.
 */
typedef int (*chaos_process_posix_spawnp_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);

/** Signature of the real `execve(2)`. */
typedef int (*chaos_process_execve_fn)(const char *, char *const[], char *const[]);

/**
 * Signature of the real `execveat(2)` (Linux only).
 * May be NULL on musl where `execveat` is not consistently exported as a
 * public libc symbol; callers must check for NULL before invoking.
 */
typedef int (*chaos_process_execveat_fn)(int, const char *, char *const[], char *const[], int);

/** Signature of the real `waitpid(2)`. */
typedef pid_t (*chaos_process_waitpid_fn)(pid_t, int *, int);

/** Signature of the real `nanosleep(2)`, used for latency injection. */
typedef int (*chaos_process_nanosleep_fn)(const struct timespec *, struct timespec *);

/** Signature of the real `usleep(3)`, used for latency injection. */
typedef int (*chaos_process_usleep_fn)(useconds_t);

/** @} */

/** @defgroup chaos_process_globals Global state variables
 *  @{
 *
 * All `g_chaos_process_real_*` pointers are written once during library
 * construction and are thereafter read-only.  They require no locking for
 * reads.
 */

/** Pointer to the real `pthread_create` resolved via RTLD_NEXT. */
extern chaos_process_pthread_create_fn g_chaos_process_real_pthread_create;

/** Pointer to the real `fork` resolved via RTLD_NEXT. */
extern chaos_process_fork_fn g_chaos_process_real_fork;

/** Pointer to the real `posix_spawn` resolved via RTLD_NEXT. */
extern chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn;

/** Pointer to the real `posix_spawnp` resolved via RTLD_NEXT. */
extern chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp;

/** Pointer to the real `execve` resolved via RTLD_NEXT. */
extern chaos_process_execve_fn g_chaos_process_real_execve;

/**
 * Pointer to the real `execveat` resolved via RTLD_NEXT, or NULL if the
 * symbol is not available (e.g. musl without a public `execveat` export).
 * Linux-only; guarded by `#ifdef __linux__` at all call sites.
 */
extern chaos_process_execveat_fn g_chaos_process_real_execveat;

/** Pointer to the real `waitpid` resolved via RTLD_NEXT. */
extern chaos_process_waitpid_fn g_chaos_process_real_waitpid;

/** Pointer to the real `nanosleep` resolved via RTLD_NEXT. */
extern chaos_process_nanosleep_fn g_chaos_process_real_nanosleep;

/** Pointer to the real `usleep` resolved via RTLD_NEXT. */
extern chaos_process_usleep_fn g_chaos_process_real_usleep;

/**
 * Per-thread re-entrancy guard.
 *
 * Non-zero while the current thread is executing inside library-internal code
 * (config I/O, sleep primitives, symbol resolution).  The wrappers check this
 * before applying chaos logic; if set they call straight through to the real
 * function.  This prevents infinite recursion when, for example, the config
 * reload calls `stat()` and our `fork` wrapper is somehow reached via a
 * signal handler or atfork handler during that call.
 *
 * The guard is a counter (not a boolean) so that nested calls to
 * `chaos_process_enter_internal()` restore the correct previous depth.
 */
extern __thread int g_chaos_process_tls_guard;

/**
 * Per-thread xorshift64* PRNG state.
 *
 * Initialised lazily on first use by `chaos_process_prng_ensure_seeded()`.
 * A value of 0 means "not yet seeded".  The seeding mixes the process-wide
 * seed with the kernel thread ID (Linux) or PID (other) and a stack address
 * to produce a distinct seed per thread.  The state is never zero after
 * seeding because the algorithm would otherwise be stuck at 0.
 */
extern __thread uint64_t g_chaos_process_tls_prng_state;

/**
 * Process-wide entropy seed used to differentiate per-thread PRNG streams.
 *
 * Populated from `/dev/urandom` during library construction (via raw
 * `SYS_openat`/`SYS_read` syscalls to avoid recursion through our
 * interposed symbols).  Falls back to a mixing of a compile-time constant
 * XOR PID if the syscall path fails.  Written once; read-only thereafter.
 */
extern uint64_t g_chaos_process_process_seed;

/**
 * Per-operation FAIL_AFTER invocation counters.
 *
 * Array indexed by `chaos_process_operation_t` (0 through
 * `CHAOS_PROCESS_OP_COUNT - 1`):
 *
 *   [0] CHAOS_PROCESS_OP_PTHREAD_CREATE
 *   [1] CHAOS_PROCESS_OP_FORK
 *   [2] CHAOS_PROCESS_OP_POSIX_SPAWN
 *   [3] CHAOS_PROCESS_OP_POSIX_SPAWNP
 *   [4] CHAOS_PROCESS_OP_EXECVE
 *   [5] CHAOS_PROCESS_OP_EXECVEAT
 *   [6] CHAOS_PROCESS_OP_WAITPID
 *
 * Atomicity: each element is updated with `__sync_fetch_and_add` which
 * emits a full memory barrier (mfence / dmb ish) on all supported
 * architectures.  The counter is therefore safe to increment concurrently
 * from multiple threads without a lock.
 *
 * Semantics: the counter starts at 0.  The first call to the interposed
 * function increments it from 0 to 1 and receives the *pre-increment* value
 * 0 back from `__sync_fetch_and_add`.  A rule with `fail_after_count = N`
 * triggers when the observed pre-increment value is >= N, meaning the
 * (N+1)-th call and all subsequent calls fail.  With N=0, every call fails
 * starting from the very first.
 *
 * Overflow: the counter is uint64_t.  Wraparound at 2^64 is not guarded;
 * in practice it is unreachable (2^64 calls would take centuries at any
 * realistic call rate).  After overflow the counter restarts at 0, which
 * effectively re-arms the FAIL_AFTER trigger.
 *
 * Reset: all counters are zeroed atomically (non-atomically in a sequential
 * loop, but under the protection of the config-reload CAS) each time a new
 * config is published via `chaos_process_config_publish()`.
 *
 * Child inheritance: `fork()` duplicates the parent's process image.
 * Because the counter array lives in the data segment it is copied-on-write
 * into the child.  The child therefore starts with the same counter value
 * the parent had at the point of fork.  There is no post-fork reset.
 */
extern volatile uint64_t g_chaos_process_fail_after_counters[];

/** @} */

/** @defgroup chaos_process_guard Re-entrancy guard inline helpers
 *  @{
 */

/**
 * @brief Returns non-zero if the current thread is already executing inside
 *        library-internal code.
 *
 * Callers should call this before performing any chaos logic and skip
 * straight to the real function if it returns non-zero.
 *
 * @return Non-zero if re-entrant, 0 if safe to apply chaos.
 */
static inline int chaos_process_in_internal(void)
{
    return g_chaos_process_tls_guard != 0;
}

/**
 * @brief Marks the current thread as inside internal code and returns the
 *        previous guard value.
 *
 * Must be paired with `chaos_process_leave_internal(previous)` on all
 * exit paths to restore the guard correctly.  Correctly handles nesting:
 * if the guard was already set it returns 1 (non-zero previous) and the
 * paired `leave` restores it back to 1.
 *
 * @return The guard value before the call (0 = was not internal, 1 = was).
 */
static inline int chaos_process_enter_internal(void)
{
    int previous = g_chaos_process_tls_guard;
    g_chaos_process_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the re-entrancy guard to its state before the matching
 *        `chaos_process_enter_internal()` call.
 *
 * @param previous The value returned by the corresponding
 *                 `chaos_process_enter_internal()`.
 */
static inline void chaos_process_leave_internal(int previous)
{
    g_chaos_process_tls_guard = previous;
}

/** @} */

/** @defgroup chaos_process_atomics Atomic primitive wrappers
 *  @{
 *
 * All three functions map directly to GCC/Clang built-in synchronisation
 * primitives that compile to full memory-barrier instructions on all
 * supported architectures (x86_64: `mfence`/`lock xadd`; AArch64:
 * `dmb ish` + `ldxr`/`stxr` sequences).
 */

/**
 * @brief Atomically loads a uint64_t with a full memory barrier.
 *
 * The explicit `__sync_synchronize()` before the load prevents the compiler
 * and CPU from hoisting the load above a preceding store by another thread.
 *
 * @param value Pointer to the value to load.
 * @return The current value of *value.
 */
static inline uint64_t chaos_process_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Atomically compare-and-swap a uint64_t.
 *
 * If `*value == expected`, replaces `*value` with `desired` atomically and
 * returns non-zero (success).  Otherwise leaves `*value` unchanged and
 * returns 0 (failure).  Emits a full barrier on success.
 *
 * Used by the config reload path to serialise concurrent reload attempts:
 * exactly one thread wins the CAS from `observed_mtime` to
 * `CHAOS_PROCESS_MTIME_RELOADING` and performs the actual I/O.
 *
 * @param value    Pointer to the target.
 * @param expected Value that must be present for the swap to occur.
 * @param desired  Value to store on success.
 * @return Non-zero on success, 0 on failure.
 */
static inline int
chaos_process_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/**
 * @brief Atomically add `delta` to `*value` and return the pre-add value.
 *
 * Emits a full memory barrier.  The pre-add value is what drives FAIL_AFTER
 * semantics: the first call returns 0, the second returns 1, and so on.
 * A rule fires when the returned pre-add value >= `rule->fail_after_count`.
 *
 * @param value Pointer to the counter to increment.
 * @param delta Amount to add (always 1 in production use).
 * @return The value of `*value` before the addition.
 */
static inline uint64_t chaos_process_atomic_fetch_add_u64(volatile uint64_t *value, uint64_t delta)
{
    return (uint64_t)__sync_fetch_and_add(value, delta);
}

/** @} */

/** @defgroup chaos_process_prng Per-thread xorshift64* PRNG
 *  @{
 */

/**
 * @brief Returns an identifier for the current kernel thread.
 *
 * On Linux uses `SYS_gettid` to obtain the kernel thread ID, which is
 * unique among all threads in the process and persists across `fork()`.
 * On other platforms falls back to `getpid()` (adequate for single-threaded
 * processes; all threads will share the same value on those platforms).
 *
 * @return A uint64_t thread identifier, unique within the running system.
 */
static inline uint64_t chaos_process_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/**
 * @brief Finalisation mix (Murmur3 / SplitMix64 variant) for seeding.
 *
 * Applies the SplitMix64 finaliser to `value`.  This is an invertible
 * bijection that distributes entropy uniformly across all 64 bits,
 * making it suitable for deriving independent PRNG seeds from sequential
 * or structured inputs (e.g. incrementing PIDs or TIDs).
 *
 * @param value Raw seed material.
 * @return Well-mixed 64-bit output suitable for use as a PRNG state.
 */
static inline uint64_t chaos_process_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Lazily seeds the per-thread PRNG state on first use.
 *
 * Seeds are derived by XOR-ing three entropy sources:
 *  1. The process-wide seed (`g_chaos_process_process_seed`) drawn from
 *     `/dev/urandom` at startup.
 *  2. The kernel thread ID (`chaos_process_current_tid()`), ensuring that
 *     threads born from the same parent get different streams.
 *  3. The address of a local stack variable, adding ASLR entropy.
 *
 * The combined material is then passed through `chaos_process_prng_mix()`
 * to eliminate any structural correlation.  If the result is zero (a
 * degenerate state for xorshift), a compile-time non-zero constant is used
 * as a fallback.
 *
 * This function is a no-op if the thread is already seeded.
 */
static inline void chaos_process_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_process_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_process_process_seed;
    seed ^= chaos_process_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed);
    if (g_chaos_process_tls_prng_state == 0U)
    {
        g_chaos_process_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * @brief Explicitly seeds the per-thread PRNG state.
 *
 * Used during library initialisation to seed the main thread immediately
 * after the process-wide seed has been established.  A seed of 0 is
 * mapped to 1 before mixing to avoid the xorshift degenerate state.
 *
 * @param seed 64-bit seed material; 0 is treated as 1.
 */
static inline void chaos_process_prng_seed_thread(uint64_t seed)
{
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Advances the per-thread xorshift64* PRNG and returns 32 bits of
 *        output.
 *
 * The PRNG is the xorshift64 generator with the multiplier from Vigna
 * (2016), producing 32 bits by taking the high word of the 64-bit
 * state-times-multiplier product.  Statistical quality is sufficient for
 * probability sampling; this is not a cryptographic PRNG.
 *
 * Lazy seeding via `chaos_process_prng_ensure_seeded()` is called on every
 * invocation; it is a no-op after the first call.
 *
 * @return A pseudo-random uint32_t uniformly distributed over [0, 2^32).
 */
static inline uint32_t chaos_process_prng_next_u32(void)
{
    uint64_t state;

    chaos_process_prng_ensure_seeded();
    state = g_chaos_process_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_process_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

/** @} */

#endif
