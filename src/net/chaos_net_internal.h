/**
 * @file chaos_net_internal.h
 * @brief Private implementation contracts shared across all libchaos-net translation units.
 *
 * @details
 * This header is the single internal seam that every .c file in the net subsystem includes.
 * It defines:
 *   - Compile-time constants (config path, buffer ceilings, sentinel mtime values).
 *   - The CHAOS_NET_EXPORT visibility macro that controls which symbols escape the DSO.
 *   - Platform-abstraction macros for the glibc sockaddr union vs. plain-pointer calling
 *     conventions, and for the flags type difference in sendmmsg/recvmmsg.
 *   - Function-pointer typedefs for every intercepted symbol; instances live in chaos_net.c.
 *   - Thread-local state: reentrancy guard (g_chaos_net_tls_guard) and per-thread PRNG state.
 *   - Inline helpers: TLS guard, acquire/release barriers, xorshift64* PRNG, tid fetch.
 *
 * Nothing in this file is part of the public ABI. All declarations are either
 * `static inline` or reference `extern` globals defined in chaos_net.c.
 *
 * @par Stability: private / internal
 * @par Module: chaos-net
 */

#ifndef CHAOS_NET_INTERNAL_H
#define CHAOS_NET_INTERNAL_H

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
/** @brief Fallback PATH_MAX when the platform header does not define it. */
#define PATH_MAX 4096
#endif

/**
 * @brief Filesystem path where libchaos-net looks for its rule configuration.
 *
 * @details The file is stat(2)ed on every hot-path invocation to detect changes.
 * A missing file is treated as "no rules" (fail-open). The path is in /tmp so
 * that unprivileged processes can create and modify it without root access.
 */
#define CHAOS_NET_CONFIG_PATH "/tmp/.chaos-net.conf"

/**
 * @brief Maximum number of fault-injection rules that can be loaded simultaneously.
 *
 * @details Sized to be large enough for real-world test suites while keeping the
 * two config snapshots (see chaos_net_config.c) completely stack- or BSS-allocated.
 * Exceeding this limit during a reload causes the entire reload to be rejected and
 * the previous snapshot to remain active.
 */
#define CHAOS_NET_MAX_RULES 256U

/**
 * @brief Maximum length (in bytes, including NUL) of a single config-file line.
 *
 * @details Enforced during buffer read, not during line parsing. Lines longer
 * than this value can only occur if the total config file is also truncated,
 * because CHAOS_NET_MAX_CONFIG_BYTES is derived from this constant.
 */
#define CHAOS_NET_MAX_LINE_LENGTH 1024U

/**
 * @brief Maximum total size (bytes) of the config file that will be read.
 *
 * @details Derived as CHAOS_NET_MAX_RULES * CHAOS_NET_MAX_LINE_LENGTH. If the
 * file is larger, chaos_net_config_read_file() returns -1 and the reload is
 * aborted, leaving the previous snapshot active (fail-open).
 * The read buffer is allocated as a __thread TLS array so it is never shared
 * between threads; this avoids a lock in the hot-path reload path.
 */
#define CHAOS_NET_MAX_CONFIG_BYTES (CHAOS_NET_MAX_RULES * CHAOS_NET_MAX_LINE_LENGTH)

/**
 * @brief Maximum text length (bytes, including NUL) for a UNIX socket path stored
 *        inside chaos_net_endpoint_t::value.text.
 *
 * @details Must be at least UNIX_PATH_MAX (108 on Linux). The value 256 gives
 * comfortable headroom and keeps the endpoint struct cache-friendly.
 */
#define CHAOS_NET_MAX_TEXT 256U

/**
 * @brief Visibility attribute used on every symbol that must be interposable.
 *
 * @details The shared library is built with -fvisibility=hidden, which hides all
 * symbols by default. Only the interposed syscall wrappers (bind, connect, recv,
 * etc.) carry this attribute; all internal helpers remain hidden. This prevents
 * accidental symbol clashes with the target application's own symbols and
 * reduces dynamic linker overhead.
 */
#define CHAOS_NET_EXPORT __attribute__((visibility("default")))

/**
 * @brief Sentinel mtime hash value meaning the config file does not exist.
 *
 * @details When stat(2) on CHAOS_NET_CONFIG_PATH fails, the hash function returns
 * this value. Distinguishing "missing" from "zero-hash-collision" is handled by
 * chaos_net_config_normalize_mtime_hash(), which maps any reserved sentinel to a
 * different value if the hash computation accidentally produces it.
 */
#define CHAOS_NET_MTIME_MISSING UINT64_C(0)

/**
 * @brief Sentinel mtime hash value used as a CAS lock during a reload.
 *
 * @details The reloading thread atomically swaps the cached mtime to this value
 * before touching the inactive config snapshot. Any other thread that observes
 * this value knows a reload is in progress and falls through to use the current
 * active snapshot without contending for a mutex.
 */
#define CHAOS_NET_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Sentinel mtime hash value used at library startup before the first stat.
 *
 * @details Set during chaos_net_config_init(). The first call to
 * chaos_net_config_prepare() will always see observed_mtime != cached_mtime
 * and perform an initial load, converting MTIME_UNKNOWN to the real value.
 */
#define CHAOS_NET_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/*---------------------------------------------------------------------------
 * glibc sockaddr ABI shim
 *
 * glibc wraps struct sockaddr * in a union (__SOCKADDR_ARG / __CONST_SOCKADDR_ARG)
 * to silence strict-aliasing warnings from its own headers.  Non-glibc toolchains
 * expose plain pointers.  These macros make the interposition wrappers source-
 * compatible with both ABIs without sacrificing type safety.
 *---------------------------------------------------------------------------*/

#if defined(__GLIBC__)
/** @brief Parameter type for a const sockaddr pointer in glibc function prototypes. */
#define CHAOS_NET_CONST_SOCKADDR_PARAM __CONST_SOCKADDR_ARG
/** @brief Unwraps the glibc sockaddr union to obtain the raw const struct sockaddr *. */
#define CHAOS_NET_CONST_SOCKADDR_VALUE(arg) ((arg).__sockaddr__)
/** @brief Parameter type for a mutable sockaddr pointer in glibc function prototypes. */
#define CHAOS_NET_SOCKADDR_PARAM __SOCKADDR_ARG
/** @brief Unwraps the glibc sockaddr union to obtain the raw struct sockaddr *. */
#define CHAOS_NET_SOCKADDR_VALUE(arg) ((arg).__sockaddr__)
/** @brief Type of the flags argument to sendmmsg/recvmmsg on glibc (signed int). */
#define CHAOS_NET_MMSG_FLAGS_TYPE int
#else
/** @brief Parameter type for a const sockaddr pointer on non-glibc platforms. */
#define CHAOS_NET_CONST_SOCKADDR_PARAM const struct sockaddr *
/** @brief Identity: non-glibc already uses a plain pointer. */
#define CHAOS_NET_CONST_SOCKADDR_VALUE(arg) (arg)
/** @brief Parameter type for a mutable sockaddr pointer on non-glibc platforms. */
#define CHAOS_NET_SOCKADDR_PARAM struct sockaddr *
/** @brief Identity: non-glibc already uses a plain pointer. */
#define CHAOS_NET_SOCKADDR_VALUE(arg) (arg)
/** @brief Type of the flags argument to sendmmsg/recvmmsg on non-glibc (unsigned int). */
#define CHAOS_NET_MMSG_FLAGS_TYPE unsigned int
#endif

/*---------------------------------------------------------------------------
 * Function-pointer typedefs for intercepted symbols
 *
 * One typedef per intercepted libc/libsocket symbol. The global variables
 * g_chaos_net_real_* are populated by dlsym(RTLD_NEXT, …) in chaos_net_init()
 * and are never written again after construction; reads on the hot path are
 * therefore safe without barriers (they observe the initialized value).
 *---------------------------------------------------------------------------*/

/** @brief Real bind(2) pointer; never NULL after library init. */
typedef int (*chaos_net_bind_fn)(int, const struct sockaddr *, socklen_t);
/** @brief Real listen(2) pointer; never NULL after library init. */
typedef int (*chaos_net_listen_fn)(int, int);
/** @brief Real connect(2) pointer; never NULL after library init. */
typedef int (*chaos_net_connect_fn)(int, const struct sockaddr *, socklen_t);
/** @brief Real accept(2) pointer; never NULL after library init. */
typedef int (*chaos_net_accept_fn)(int, struct sockaddr *, socklen_t *);
/** @brief Real socket(2) pointer; never NULL after library init. */
typedef int (*chaos_net_socket_fn)(int, int, int);
/** @brief Real socketpair(2) pointer; never NULL after library init. */
typedef int (*chaos_net_socketpair_fn)(int, int, int, int[2]);
/** @brief Real shutdown(2) pointer; never NULL after library init. */
typedef int (*chaos_net_shutdown_fn)(int, int);
/** @brief Real send(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_send_fn)(int, const void *, size_t, int);
/** @brief Real sendto(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_sendto_fn)(
    int, const void *, size_t, int, const struct sockaddr *, socklen_t
);
/** @brief Real sendmsg(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_sendmsg_fn)(int, const struct msghdr *, int);
/** @brief Real recv(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_recv_fn)(int, void *, size_t, int);
/** @brief Real recvfrom(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
/** @brief Real recvmsg(2) pointer; never NULL after library init. */
typedef ssize_t (*chaos_net_recvmsg_fn)(int, struct msghdr *, int);
/** @brief Real poll(2) pointer; never NULL after library init. */
typedef int (*chaos_net_poll_fn)(struct pollfd *, nfds_t, int);
/** @brief Real ppoll(2) pointer; never NULL after library init. */
typedef int (*chaos_net_ppoll_fn)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);
/** @brief Real select(2) pointer; never NULL after library init. */
typedef int (*chaos_net_select_fn)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
/** @brief Real pselect(2) pointer; never NULL after library init. */
typedef int (*chaos_net_pselect_fn)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);
/** @brief Real getsockname(2) pointer; used internally for endpoint resolution; never NULL after
 * init. */
typedef int (*chaos_net_getsockname_fn)(int, struct sockaddr *, socklen_t *);
/** @brief Real getpeername(2) pointer; used internally for endpoint resolution; never NULL after
 * init. */
typedef int (*chaos_net_getpeername_fn)(int, struct sockaddr *, socklen_t *);
/** @brief Real getsockopt(2) pointer; used to determine SOCK_STREAM vs SOCK_DGRAM; never NULL after
 * init. */
typedef int (*chaos_net_getsockopt_fn)(int, int, int, void *, socklen_t *);
#ifdef __linux__
/** @brief Real accept4(2) pointer; Linux-only; never NULL after library init on Linux. */
typedef int (*chaos_net_accept4_fn)(int, struct sockaddr *, socklen_t *, int);
/** @brief Real sendmmsg(2) pointer; Linux-only; never NULL after library init on Linux. */
typedef int (*chaos_net_sendmmsg_fn)(
    int, struct mmsghdr *, unsigned int, CHAOS_NET_MMSG_FLAGS_TYPE
);
/** @brief Real recvmmsg(2) pointer; Linux-only; never NULL after library init on Linux. */
typedef int (*chaos_net_recvmmsg_fn)(int, struct mmsghdr *, unsigned int, CHAOS_NET_MMSG_FLAGS_TYPE, struct timespec *);
/** @brief Real epoll_wait(2) pointer; Linux-only; never NULL after library init on Linux. */
typedef int (*chaos_net_epoll_wait_fn)(int, struct epoll_event *, int, int);
/** @brief Real epoll_pwait(2) pointer; Linux-only; never NULL after library init on Linux. */
typedef int (*chaos_net_epoll_pwait_fn)(int, struct epoll_event *, int, int, const sigset_t *);
#endif

/*---------------------------------------------------------------------------
 * Real-symbol pointer instances (defined in chaos_net.c)
 *---------------------------------------------------------------------------*/

extern chaos_net_bind_fn g_chaos_net_real_bind;
extern chaos_net_listen_fn g_chaos_net_real_listen;
extern chaos_net_connect_fn g_chaos_net_real_connect;
extern chaos_net_accept_fn g_chaos_net_real_accept;
extern chaos_net_socket_fn g_chaos_net_real_socket;
extern chaos_net_socketpair_fn g_chaos_net_real_socketpair;
extern chaos_net_shutdown_fn g_chaos_net_real_shutdown;
extern chaos_net_send_fn g_chaos_net_real_send;
extern chaos_net_sendto_fn g_chaos_net_real_sendto;
extern chaos_net_sendmsg_fn g_chaos_net_real_sendmsg;
extern chaos_net_recv_fn g_chaos_net_real_recv;
extern chaos_net_recvfrom_fn g_chaos_net_real_recvfrom;
extern chaos_net_recvmsg_fn g_chaos_net_real_recvmsg;
extern chaos_net_poll_fn g_chaos_net_real_poll;
extern chaos_net_ppoll_fn g_chaos_net_real_ppoll;
extern chaos_net_select_fn g_chaos_net_real_select;
extern chaos_net_pselect_fn g_chaos_net_real_pselect;
extern chaos_net_getsockname_fn g_chaos_net_real_getsockname;
extern chaos_net_getpeername_fn g_chaos_net_real_getpeername;
extern chaos_net_getsockopt_fn g_chaos_net_real_getsockopt;
#ifdef __linux__
extern chaos_net_accept4_fn g_chaos_net_real_accept4;
extern chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg;
extern chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg;
extern chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait;
extern chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait;
#endif

/*---------------------------------------------------------------------------
 * Thread-local state
 *---------------------------------------------------------------------------*/

/**
 * @brief Per-thread reentrancy guard preventing libchaos-net from intercepting
 *        its own internal socket calls.
 *
 * @details Set to 1 by chaos_net_enter_internal() before any syscall made by
 * libchaos-net itself (stat, getsockname, getpeername, getsockopt, read, open,
 * close, etc.), and restored to its previous value by chaos_net_leave_internal().
 * The save/restore idiom (not simple increment/decrement) makes the guard
 * reentrant: if a signal handler or a deeply nested call checks the guard while
 * it is already set, the flag is left set until the outermost frame restores it.
 *
 * All interposed symbols check chaos_net_in_internal() at entry and fast-path
 * directly to the real symbol when it returns non-zero, which prevents infinite
 * recursion when the endpoint-resolution code calls getsockname/getpeername.
 */
extern __thread int g_chaos_net_tls_guard;

/**
 * @brief Per-thread xorshift64* PRNG state.
 *
 * @details Zero means "not seeded yet". The first call to chaos_net_prng_next_u32()
 * on a new thread invokes chaos_net_prng_ensure_seeded(), which mixes the process
 * seed, the thread ID, and the stack address of a local variable to derive a
 * thread-unique starting state. This avoids any shared lock for PRNG advancement
 * while still giving different threads different random streams.
 */
extern __thread uint64_t g_chaos_net_tls_prng_state;

/**
 * @brief Process-wide seed used as the base for per-thread PRNG seeding.
 *
 * @details Initialised from /dev/urandom during library construction (chaos_net_init).
 * Falls back to a compile-time constant XORed with getpid() if the read fails.
 * Written exactly once (during the constructor), then read-only; no synchronisation
 * is required for subsequent reads.
 */
extern uint64_t g_chaos_net_process_seed;

/*---------------------------------------------------------------------------
 * Reentrancy-guard inline helpers
 *---------------------------------------------------------------------------*/

/**
 * @brief Returns non-zero when the calling thread is already executing inside
 *        libchaos-net's own implementation.
 *
 * @details Checked at the top of every interposed symbol. A non-zero result means
 * the call arrived from within libchaos-net itself (e.g. getsockname called while
 * resolving an endpoint for bind()), and the wrapper must forward directly to the
 * real symbol without any fault injection.
 *
 * @return Non-zero if reentrancy guard is set; 0 otherwise.
 * @par Thread-safety: reads a thread-local variable; inherently thread-safe.
 */
static inline int chaos_net_in_internal(void)
{
    return g_chaos_net_tls_guard != 0;
}

/**
 * @brief Sets the reentrancy guard for the current thread and returns the previous
 *        value so it can be restored with chaos_net_leave_internal().
 *
 * @details Call this before any internal syscall that could otherwise recurse back
 * through an interposed symbol. Example call sites: getsockname calls in
 * chaos_net_endpoint_from_local_fd, and stat calls in chaos_net_config_observed_mtime.
 *
 * @return Previous value of g_chaos_net_tls_guard (0 or 1). Must be passed to
 *         chaos_net_leave_internal() after the protected section completes.
 * @par Thread-safety: writes a thread-local variable; inherently thread-safe.
 */
static inline int chaos_net_enter_internal(void)
{
    int previous = g_chaos_net_tls_guard;
    g_chaos_net_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the reentrancy guard to the value captured before entering
 *        an internal section.
 *
 * @details Using save/restore rather than simple decrement preserves correctness
 * if signal handlers run between enter and leave, or if the same thread legitimately
 * nests internal sections (e.g., endpoint_from_local_fd calling getsockopt then
 * getsockname: each sets the guard to 1 and restores to 1, not to 0, so the outer
 * frame's restore to 0 is the only one that actually clears it).
 *
 * @param previous Value returned by a prior call to chaos_net_enter_internal().
 * @par Thread-safety: writes a thread-local variable; inherently thread-safe.
 */
static inline void chaos_net_leave_internal(int previous)
{
    g_chaos_net_tls_guard = previous;
}

/*---------------------------------------------------------------------------
 * Atomic helpers (GCC built-ins, C99 compatible)
 *---------------------------------------------------------------------------*/

/**
 * @brief Performs a full memory barrier then loads a 64-bit value from a
 *        volatile location.
 *
 * @details Used when reading g_chaos_net_cached_mtime and
 * g_chaos_net_active_config_index to ensure the reader observes any preceding
 * store from the reloading thread. The barrier is intentionally conservative
 * (full fence rather than acquire) to remain correct on all hardware without
 * pulling in C11 stdatomic.h.
 *
 * @param value Pointer to the volatile uint64_t to load. Must not be NULL.
 * @return The value observed after the memory barrier.
 */
static inline uint64_t chaos_net_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Atomic compare-and-swap on a 64-bit value.
 *
 * @details Attempts to atomically replace *value with @p desired if *value
 * currently equals @p expected. Used to claim the reload lock by swapping
 * g_chaos_net_cached_mtime from its observed value to CHAOS_NET_MTIME_RELOADING.
 * If two threads race to reload concurrently, exactly one wins; the loser skips
 * the reload and uses the current active snapshot.
 *
 * @param value    Pointer to the volatile uint64_t to update. Must not be NULL.
 * @param expected Value the caller believes is current.
 * @param desired  Value to write if the CAS succeeds.
 * @return Non-zero if the swap was performed; 0 if another thread changed *value first.
 */
static inline int
chaos_net_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/*---------------------------------------------------------------------------
 * Thread-ID helper
 *---------------------------------------------------------------------------*/

/**
 * @brief Returns a numeric identifier for the calling thread.
 *
 * @details On Linux, uses SYS_gettid (via raw syscall to avoid the reentrancy
 * problem: the glibc wrapper for gettid() may not exist on older kernels, and
 * using the raw syscall avoids any interposable symbol). On other platforms,
 * getpid() is used, which means threads within a process share a seed base and
 * differ only by stack-address XOR. This is sufficient for the PRNG seeding
 * purpose (low collision probability) without requiring pthreads.
 *
 * @return A uint64_t encoding the calling thread's OS-level identifier.
 */
static inline uint64_t chaos_net_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/*---------------------------------------------------------------------------
 * PRNG: xorshift64* with splitmix64 finalizer
 *---------------------------------------------------------------------------*/

/**
 * @brief Applies the splitmix64 finalizer to a 64-bit value, producing a
 *        well-distributed hash.
 *
 * @details Used when constructing initial PRNG state from heterogeneous inputs
 * (process seed, TID, stack address) that may have poor bit distribution on their
 * own. The three-step multiply-xorshift sequence is the Murmur3 finalizer adapted
 * for 64 bits; it passes BigCrush with negligible bias.
 *
 * @param value Input word to mix.
 * @return Mixed output with all bits dependent on all input bits.
 */
static inline uint64_t chaos_net_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Lazily seeds the calling thread's PRNG state if it has not been seeded yet.
 *
 * @details Called by chaos_net_prng_next_u32() before every draw. The seed is
 * derived from three sources to minimise the probability of two threads sharing a
 * PRNG stream:
 *   1. g_chaos_net_process_seed  — unique across processes (from /dev/urandom).
 *   2. chaos_net_current_tid()   — unique across threads within a process.
 *   3. The address of a local variable — adds ASLR entropy on systems that randomise
 *      stack layout, differentiating threads that share the same TID across fork.
 *
 * If the mixed value is zero (the only invalid xorshift64* state), it is replaced
 * with a fixed non-zero fallback constant.
 *
 * @par Thread-safety: reads/writes g_chaos_net_tls_prng_state (thread-local); safe.
 */
static inline void chaos_net_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_net_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_net_process_seed;
    seed ^= chaos_net_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_net_tls_prng_state = chaos_net_prng_mix(seed);
    if (g_chaos_net_tls_prng_state == 0U)
    {
        g_chaos_net_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

/**
 * @brief Explicitly seeds the calling thread's PRNG with a caller-supplied value.
 *
 * @details Passes the seed through chaos_net_prng_mix() before storing it to
 * guarantee good bit distribution even if @p seed is a small integer. If @p seed
 * is zero, the value 1 is used before mixing (xorshift64* state must be non-zero).
 * Called from chaos_net_init() to seed the main thread at library load time.
 *
 * @param seed Desired starting value. 0 is treated as 1.
 * @par Thread-safety: writes g_chaos_net_tls_prng_state (thread-local); safe.
 */
static inline void chaos_net_prng_seed_thread(uint64_t seed)
{
    g_chaos_net_tls_prng_state = chaos_net_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Advances the xorshift64* generator and returns the upper 32 bits of
 *        the output.
 *
 * @details The three-step xorshift sequence (right 12, left 25, right 27) is the
 * Marsaglia xorshift64 generator. Multiplying by the Knuth constant before
 * extracting the upper 32 bits applies a finalizer that removes the known
 * correlation between the raw xorshift output and simple linear combinations,
 * giving statistical quality comparable to xoroshiro128+.
 *
 * The function is allocation-free, branch-free (after the seed check), and
 * operates entirely on thread-local state, making it safe to call from the
 * hot interposition path without any locking.
 *
 * @return A pseudo-random 32-bit value drawn from the calling thread's stream.
 * @par Thread-safety: reads/writes g_chaos_net_tls_prng_state (thread-local); safe.
 */
static inline uint32_t chaos_net_prng_next_u32(void)
{
    uint64_t state;

    chaos_net_prng_ensure_seeded();
    state = g_chaos_net_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_net_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
