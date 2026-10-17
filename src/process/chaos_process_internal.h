/**
 * @file chaos_process_internal.h
 * @brief Definitions shared by every translation unit of libchaos-process; not part of
 *        the ABI.
 *
 * @details
 * libchaos-process wraps thread and process creation, exec and child reaping. Seven
 * operations carry rules (selectors): pthread_create, fork, posix_spawn, posix_spawnp,
 * execve, execveat, waitpid. Further wrappers follow the rules of the operation they
 * are a form of (see chaos_process_hooks.c): the exec family, system(), popen() and the
 * wait family. vfork is not wrapped.
 *
 * Contents:
 *  - Paths of the rule file, status file and hits file, and the parser limits.
 *  - The change-stamp sentinels that double as the reload state machine.
 *  - Typedefs and globals for the real functions, resolved with `dlsym(RTLD_NEXT)`.
 *  - The per-operation FAIL_AFTER counters.
 *  - The per-thread reentrancy guard: while set, every wrapper calls the real function
 *    and injects nothing, so the library never faults its own work.
 *  - The per-thread xorshift64* PRNG behind the probability gate: no locks, independent
 *    streams per thread and per forked child.
 *
 * Everything inline here is async-signal-safe (TLS, `__sync` builtins, one gettid
 * system call) and leaves errno alone.
 */

#ifndef CHAOS_PROCESS_INTERNAL_H
#define CHAOS_PROCESS_INTERNAL_H

#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
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

/** Rule file; looked at no more than once per CHAOS_CHECK_INTERVAL_NS (1 ms) per process. */
#define CHAOS_PROCESS_CONFIG_PATH "/tmp/.chaos-process.conf"

/** Status file: outcome of the last load (see chaos_status.h). */
#define CHAOS_PROCESS_STATUS_PATH "/tmp/.chaos-process.status"

/** Hits file prefix; each image appends `.<n>` (see chaos_hits.h). */
#define CHAOS_PROCESS_HITS_PREFIX "/tmp/.chaos-process.hits"

/** Rules per snapshot; one more rejects the whole file (CHAOS_STATUS_REASON_TOO_MANY). */
#define CHAOS_PROCESS_MAX_RULES 256U

/** Nominal bytes per line; only used to size CHAOS_PROCESS_MAX_CONFIG_BYTES. */
#define CHAOS_PROCESS_MAX_LINE_LENGTH 1024U

/**
 * Rule-file size limit: 256 * 1024 bytes = 256 KiB.
 *
 * A file of this size or larger is rejected as a whole (CHAOS_STATUS_REASON_TOO_LARGE):
 * no rule applies and the status file reports the error until the file changes.
 */
#define CHAOS_PROCESS_MAX_CONFIG_BYTES (CHAOS_PROCESS_MAX_RULES * CHAOS_PROCESS_MAX_LINE_LENGTH)

/** Capacity of the value field (before `@probability`) including the NUL. */
#define CHAOS_PROCESS_MAX_VALUE 256U

/**
 * Default ELF visibility for the wrappers.
 *
 * The library is built with -fvisibility=hidden; only symbols marked with this macro enter
 * the dynamic symbol table, where LD_PRELOAD places them ahead of libc's definitions.
 */
#define CHAOS_PROCESS_EXPORT __attribute__((visibility("default")))

/**
 * stat() of the rule file failed (ENOENT or any other error).
 *
 * A load that observes it publishes an empty snapshot and removes the status file.
 */
#define CHAOS_PROCESS_MTIME_MISSING UINT64_C(0)

/**
 * A thread of this process owns the reload.
 *
 * Installed in g_chaos_process_cached_mtime by compare-and-swap before the file is read;
 * every other caller serves the active snapshot without waiting. The atfork child
 * handler turns an inherited value back into UNKNOWN.
 */
#define CHAOS_PROCESS_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * No load has completed yet (set by chaos_process_config_init()).
 *
 * The next call loads the file unconditionally, bypassing the 1 ms throttle.
 */
#define CHAOS_PROCESS_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/** @defgroup chaos_process_fptypes Function-pointer typedefs for real symbols
 *  @{
 *
 * Signatures of the real functions as glibc and musl declare them. The matching
 * `g_chaos_process_real_*` globals are filled by chaos_process_ensure_symbols().
 */

/** pthread_create(3); returns an error number, does not set errno. */
typedef int (*chaos_process_pthread_create_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);

/** fork(2). */
typedef pid_t (*chaos_process_fork_fn)(void);

/**
 * posix_spawn(3); returns an error number, does not set errno.
 *
 * @note glibc spawns through clone(CLONE_VM | CLONE_VFORK), not through the exported
 *       fork symbol, so a `fork` rule never reaches posix_spawn. Rules for spawning
 *       must name `posix_spawn` / `posix_spawnp`; this wrapper sits at that boundary
 *       whatever the libc does underneath.
 */
typedef int (*chaos_process_posix_spawn_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);

/** posix_spawnp(3); as posix_spawn, with a PATH search. */
typedef int (*chaos_process_posix_spawnp_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);

/** execve(2). */
typedef int (*chaos_process_execve_fn)(const char *, char *const[], char *const[]);

/**
 * execveat(2), Linux only. The pointer may stay NULL (a libc without the symbol, or not
 * resolved yet); the call helper then issues SYS_execveat directly.
 */
typedef int (*chaos_process_execveat_fn)(int, const char *, char *const[], char *const[], int);

/** waitpid(2). */
typedef pid_t (*chaos_process_waitpid_fn)(pid_t, int *, int);

/** execvpe(3), a GNU extension; the pointer is NULL when libc lacks it. */
typedef int (*chaos_process_execvpe_fn)(const char *, char *const[], char *const[]);

/** fexecve(3); the pointer is NULL when libc lacks it. */
typedef int (*chaos_process_fexecve_fn)(int, char *const[], char *const[]);

/** system(3). */
typedef int (*chaos_process_system_fn)(const char *);

/** popen(3). */
typedef FILE *(*chaos_process_popen_fn)(const char *, const char *);

/** wait4(2). */
typedef pid_t (*chaos_process_wait4_fn)(pid_t, int *, int, struct rusage *);

/** waitid(2). */
typedef int (*chaos_process_waitid_fn)(idtype_t, id_t, siginfo_t *, int);

/** @} */

/** @defgroup chaos_process_globals Global state variables
 *  @{
 *
 * chaos_process_ensure_symbols() fills each `g_chaos_process_real_*` pointer once; the
 * constructor and every wrapper call it first. pthread_create is the exception: while it
 * is unresolved (before glibc 2.34 it lives in libpthread) its wrapper retries the lookup
 * on each call, so a libpthread loaded later with dlopen() is picked up. A pointer is
 * NULL while resolution runs on this thread (dlsym -> preloaded allocator, or a signal
 * handler) or when no later object defines the symbol; the call helpers in
 * chaos_process_hooks.c then use a raw system call or fail with ENOSYS / EAGAIN.
 */

/** Real pthread_create; NULL until resolved (retried per call while NULL). */
extern chaos_process_pthread_create_fn g_chaos_process_real_pthread_create;

/** Real fork; NULL until resolved. */
extern chaos_process_fork_fn g_chaos_process_real_fork;

/** Real posix_spawn; NULL until resolved. */
extern chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn;

/** Real posix_spawnp; NULL until resolved. */
extern chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp;

/** Real execve; NULL until resolved. */
extern chaos_process_execve_fn g_chaos_process_real_execve;

/** Real execveat (Linux only); NULL when absent from libc. */
extern chaos_process_execveat_fn g_chaos_process_real_execveat;

/** Real waitpid; NULL until resolved. */
extern chaos_process_waitpid_fn g_chaos_process_real_waitpid;

/** Real execvpe; NULL when libc lacks it. */
extern chaos_process_execvpe_fn g_chaos_process_real_execvpe;

/** Real fexecve; NULL when libc lacks it. */
extern chaos_process_fexecve_fn g_chaos_process_real_fexecve;

/** Real system; NULL until resolved. */
extern chaos_process_system_fn g_chaos_process_real_system;

/** Real popen; NULL until resolved. */
extern chaos_process_popen_fn g_chaos_process_real_popen;

/** Real wait4; NULL until resolved. */
extern chaos_process_wait4_fn g_chaos_process_real_wait4;

/** Real waitid; NULL until resolved. */
extern chaos_process_waitid_fn g_chaos_process_real_waitid;

/**
 * Per-thread reentrancy guard: non-zero while this thread runs library code.
 *
 * Set around the rule-file stat and read, the urandom read and every call of a real
 * function. A wrapper entered while it is set calls the real function and injects
 * nothing, so a call a real function makes back into an exported wrapper is not faulted
 * a second time. A 0/1 flag, saved and restored (not a depth counter) by
 * chaos_process_enter_internal() / chaos_process_leave_internal().
 */
extern __thread int g_chaos_process_tls_guard;

/**
 * Per-thread xorshift64* state; 0 means "not seeded yet".
 *
 * chaos_process_prng_ensure_seeded() replaces 0 with an odd value on the next draw. The
 * atfork child handler resets the forking thread's state to 0, so each child draws its
 * own stream instead of repeating the parent's decisions.
 */
extern __thread uint64_t g_chaos_process_tls_prng_state;

/**
 * Process-wide seed: 8 bytes of /dev/urandom read by the constructor with raw system
 * calls; 0x6a09e667f3bcc909 XOR pid if that read fails.
 *
 * Before the constructor runs it holds a fixed constant; the thread id and a stack
 * address still separate threads that draw that early.
 */
extern uint64_t g_chaos_process_process_seed;

/**
 * FAIL_AFTER counters, one per operation, indexed by chaos_process_operation_t.
 *
 * A counter advances (`__sync_fetch_and_add`, full barrier) on every call of its
 * operation that reaches a matching FAIL_AFTER rule, i.e. one whose ERRNO rule did not
 * fire first. The pre-increment value is compared with the rule's count N: calls 1..N
 * pass, call N+1 onwards may fail. Wrappers that follow another operation's rules share
 * its counter (wait family -> waitpid, exec family -> execve, system/popen ->
 * posix_spawn, fexecve -> execveat).
 *
 * Shared by all threads of a process, which models a process-wide resource limit. Reset
 * to 0 by chaos_process_config_publish() on every load that publishes a snapshot (not by
 * a provisional re-read that finds the file unchanged) and by the atfork child handler,
 * so each forked child counts from 0 like chaos-init does. Wraparound at 2^64 is not
 * guarded.
 */
extern volatile uint64_t g_chaos_process_fail_after_counters[];

/** @} */

/** @defgroup chaos_process_guard Re-entrancy guard inline helpers
 *  @{
 *
 * Save/restore rather than set/clear: guarded regions nest (a real call made from inside
 * a reload), and only the outermost leave may return the guard to 0.
 */

/**
 * @brief Non-zero while the calling thread runs library code.
 *
 * Every wrapper tests this first and, when set, calls the real function unmodified.
 */
static inline int chaos_process_in_internal(void)
{
    return g_chaos_process_tls_guard != 0;
}

/**
 * @brief Raises the calling thread's guard.
 *
 * @return The previous value (0 or 1); pass it to the matching
 *         chaos_process_leave_internal() on every exit path.
 */
static inline int chaos_process_enter_internal(void)
{
    int previous = g_chaos_process_tls_guard;
    g_chaos_process_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the guard to its value before the matching enter.
 *
 * @param previous Value returned by chaos_process_enter_internal() on the same thread.
 */
static inline void chaos_process_leave_internal(int previous)
{
    g_chaos_process_tls_guard = previous;
}

/** @} */

/** @defgroup chaos_process_atomics Atomic primitive wrappers
 *  @{
 *
 * `__sync` builtins (the library is C99, so no `<stdatomic.h>`); each is a full barrier.
 * 64-bit loads and stores are single-copy atomic on amd64 and arm64.
 */

/**
 * @brief Loads @p value after a full barrier.
 *
 * @param value Variable to read.
 * @return The value; later loads are not reordered before it.
 */
static inline uint64_t chaos_process_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Replaces @p expected with @p desired atomically; a full barrier either way.
 *
 * The reload claim: exactly one thread swaps the cached stamp to
 * CHAOS_PROCESS_MTIME_RELOADING and does the I/O.
 *
 * @param value    Variable to update.
 * @param expected Value that must be stored for the swap to happen.
 * @param desired  Value to store.
 * @return Non-zero when the swap happened.
 */
static inline int
chaos_process_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/**
 * @brief Adds @p delta to @p value atomically (full barrier).
 *
 * @param value Counter.
 * @param delta Increment; the library always passes 1.
 * @return The value before the addition: 0 for the first FAIL_AFTER call, 1 for the
 *         second, and so on.
 */
static inline uint64_t chaos_process_atomic_fetch_add_u64(volatile uint64_t *value, uint64_t delta)
{
    return (uint64_t)__sync_fetch_and_add(value, delta);
}

/** @} */

/** @defgroup chaos_process_prng Per-thread xorshift64* PRNG
 *  @{
 *
 * Drives the probability gate only; not cryptographic. Seed material (process seed XOR
 * thread id XOR a stack address) goes through the SplitMix64 finaliser; the generator
 * is xorshift64* (shifts 12/25/27, period 2^64 - 1 over non-zero states, multiplier
 * 0x2545f4914f6cdd1d, upper 32 bits returned). State is `__thread`: no lock, no shared
 * cache line.
 */

/**
 * @brief Kernel thread id of the caller, as seed material only.
 *
 * Raw `SYS_gettid`: the gettid() wrapper exists only since glibc 2.30. Off Linux the pid
 * stands in and the stack address separates the threads.
 *
 * @return Thread id (pid off Linux).
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
 * @brief SplitMix64 finaliser: a bijective 64-bit mix, so structured inputs (sequential
 *        thread ids) give unrelated states.
 *
 * @param value Seed material of any quality.
 * @return Mixed value; may be 0, callers that need a non-zero state ensure it.
 */
static inline uint64_t chaos_process_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Seeds the calling thread's PRNG unless it already has a state.
 *
 * Process seed XOR thread id XOR the address of a local, mixed and forced odd, so the
 * state is never 0 (the one state xorshift64* never leaves).
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
    /* Odd, hence never 0: the one state xorshift64* cannot leave. */
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed) | 1U;
}

/**
 * @brief Seeds the calling thread's PRNG with mix(@p seed): the constructor seeds its
 *        thread this way, and unit tests use it for reproducible streams.
 *
 * Not forced odd; a mixed value of 0 only reads as "unseeded" and is replaced on the
 * next draw.
 *
 * @param seed Seed; 0 is replaced by 1 before mixing.
 */
static inline void chaos_process_prng_seed_thread(uint64_t seed)
{
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Next 32-bit value of the calling thread's xorshift64* stream; seeds it on first
 *        use.
 *
 * @return Uniform value in [0, 2^32).
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

/**
 * @brief Resolves the real functions once, on whichever call comes first.
 *
 * @details The constructor alone is not enough: ELF initialisers run in dependency
 * order, so another object's constructor can reach a wrapper before this library's
 * constructor has run. Every wrapper calls this first. Other threads wait (spinning on
 * sched_yield()) until resolution completes; a call re-entering from the resolving
 * thread (dlsym -> preloaded allocator, or a signal handler) returns at once and the
 * helpers fall back (see chaos_once.h). After completion the cost is one acquire load.
 */
void chaos_process_ensure_symbols(void);

/** @brief Looks up `pthread_create` if still unresolved; no abort when absent. */
void chaos_process_resolve_pthread_create(void);

#endif
