/**
 * @file chaos_memory_internal.h
 * @brief Shared internals of libchaos-memory: limits, real-function pointers, the
 *        reentrancy guard, the per-thread PRNG and the mmap kind classifier.
 *
 * @details
 * Included by every translation unit of libchaos-memory; not an API. It holds:
 *  - Platform shims (MAP_ANON spelling, gettid).
 *  - Paths of the rule file, status file and hits file, the parse limits and the
 *    three reserved change-stamp values of the reload protocol.
 *  - Typedefs and extern pointers for the real functions (`dlsym(RTLD_NEXT)`).
 *  - The thread-local reentrancy guard and PRNG state, with inline helpers.
 *
 * Why this library needs a reentrancy guard more than any other: the exported mmap(2)
 * is what preloaded allocators (jemalloc, tcmalloc) call to get memory. Work the
 * wrapper does (the stat and read of the rule file, the call into the next
 * definition) may allocate and so call mmap() again on the same thread. The guard
 * makes such nested calls go straight to the real function.
 *
 * @par Thread safety
 * Mutable state is either thread-local (`__thread`) or accessed with `__sync_*`
 * builtins. Every helper here is async-signal-safe: no locks, no allocation.
 *
 * @par Stability
 * Internal; changes without notice.
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
 * @brief Maps the historical BSD spelling MAP_ANON to MAP_ANONYMOUS.
 *
 * @details glibc and musl define both; the shim only keeps non-Linux builds of the
 * unit tests compiling.
 */
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

/**
 * @brief Rule file of libchaos-memory.
 *
 * @details Each process looks at it (one stat(2)) at most once per
 * CHAOS_CHECK_INTERVAL_NS (1 ms, vDSO CLOCK_MONOTONIC) after its first load, and on
 * every intercepted call where there is no vDSO clock (see chaos_clock.h). Replace
 * it atomically (temporary file, then rename(2)): a reload that sees the stamp
 * change during its read discards the copy and retries, but a writer that pauses
 * mid-file can still be read half-written. An absent file means no rules.
 */
#define CHAOS_MEMORY_CONFIG_PATH "/tmp/.chaos-memory.conf"

/** Status file reporting the outcome of the last load (see chaos_status.h). */
#define CHAOS_MEMORY_STATUS_PATH "/tmp/.chaos-memory.status"

/** Hits file of a process, without the `.<n>` suffix (see chaos_hits.h). */
#define CHAOS_MEMORY_HITS_PREFIX "/tmp/.chaos-memory.hits"

/**
 * @brief Maximum number of rules in the rule file.
 *
 * @details A file with more rules is rejected as a whole (status reason "too
 * many rules") and the process runs with no rules. The limit sizes the two static
 * snapshots, the hit pool (2 x 256 slots) and the static read buffer.
 */
#define CHAOS_MEMORY_MAX_RULES 256U

/**
 * @brief Nominal line length, in bytes, used only to size the read buffer
 *        (CHAOS_MEMORY_MAX_CONFIG_BYTES); individual lines are not checked against it.
 */
#define CHAOS_MEMORY_MAX_LINE_LENGTH 1024U

/**
 * @brief Size limit of the rule file: 256 x 1024 = 256 KiB.
 *
 * @details A file of this size or larger is rejected as a whole (status reason
 * "too large") instead of being parsed truncated: a read that fills the buffer
 * cannot tell whether more bytes follow.
 */
#define CHAOS_MEMORY_MAX_CONFIG_BYTES (CHAOS_MEMORY_MAX_RULES * CHAOS_MEMORY_MAX_LINE_LENGTH)

/**
 * @brief Size of the stack buffer that holds a rule's value field without its
 *        `@<probability>` suffix (errno name or latency); 255 characters plus NUL.
 */
#define CHAOS_MEMORY_MAX_VALUE 256U

/**
 * @brief Default ELF visibility for the wrappers, so that the dynamic linker binds
 *        the application's mmap()/munmap()/mprotect()/madvise()/posix_madvise()
 *        calls to them ahead of libc when the library is preloaded.
 */
#define CHAOS_MEMORY_EXPORT __attribute__((visibility("default")))

/**
 * @brief Reserved change stamp: the rule file does not exist (stat(2) failed).
 *
 * @details Not excluded from real stamps: a stamp of 0 (probability 2^-64) would
 * read as "missing" until the file changes again.
 */
#define CHAOS_MEMORY_MTIME_MISSING UINT64_C(0)

/**
 * @brief Reserved change stamp: a thread of this process owns the reload.
 *
 * @details The owner swaps the cached stamp to this value with a CAS before it
 * touches the inactive snapshot or the read buffer; every other thread that sees
 * it serves the active snapshot instead of reloading. The fork child handler turns
 * a claim inherited from the parent back into CHAOS_MEMORY_MTIME_UNKNOWN.
 * chaos_memory_config_normalize_mtime_hash() moves a real stamp equal to this value
 * down by one; see there for the one raw value that still maps onto it.
 */
#define CHAOS_MEMORY_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Reserved change stamp: nothing loaded yet; the next look always reloads
 *        and is never throttled.
 */
#define CHAOS_MEMORY_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/* =========================================================================
 * Real function signatures
 * =========================================================================
 * Each real function is resolved once and called through a pointer; a dlsym()
 * per call would cost a symbol lookup and could itself allocate.
 */

/** @brief Signature of the real mmap(2). */
typedef void *(*chaos_memory_mmap_fn)(void *, size_t, int, int, int, off_t);

/** @brief Signature of the real munmap(2). */
typedef int (*chaos_memory_munmap_fn)(void *, size_t);

/** @brief Signature of the real mprotect(2). */
typedef int (*chaos_memory_mprotect_fn)(void *, size_t, int);

/** @brief Signature of the real madvise(2). */
typedef int (*chaos_memory_madvise_fn)(void *, size_t, int);

/** @brief Signature of the real posix_madvise(3). */
typedef int (*chaos_memory_posix_madvise_fn)(void *, size_t, int);

/* =========================================================================
 * Real function pointers
 * =========================================================================
 * Filled by chaos_memory_ensure_symbols(), which every wrapper calls first, so a
 * wrapper reached from another object's constructor before this library's own
 * constructor still finds them. A pointer is NULL only while the lookup is in
 * progress (a call from inside dlsym()); the wrappers then issue the system call
 * directly (see chaos_memory_hooks.c).
 */

/** @brief Real mmap(2). */
extern chaos_memory_mmap_fn g_chaos_memory_real_mmap;

/** @brief Real munmap(2). */
extern chaos_memory_munmap_fn g_chaos_memory_real_munmap;

/** @brief Real mprotect(2). */
extern chaos_memory_mprotect_fn g_chaos_memory_real_mprotect;

/** @brief Real madvise(2). */
extern chaos_memory_madvise_fn g_chaos_memory_real_madvise;

/** @brief Real posix_madvise(3). */
extern chaos_memory_posix_madvise_fn g_chaos_memory_real_posix_madvise;

/* =========================================================================
 * Thread-local reentrancy guard and PRNG state
 * =========================================================================
 */

/**
 * @brief Non-zero while this thread runs library code; wrappers then pass the
 *        call to the real function without matching any rule.
 *
 * @details Set around everything the library does that can call back into a
 * wrapper on the same thread:
 *  - the call into the real function itself (another interposer below this one
 *    may allocate);
 *  - stat(2) of the rule file and its read (open, read, fstat, close);
 *  - the /dev/urandom read of the constructor.
 *
 * Reading the guard is safe even on a thread's first call: the library is loaded
 * at start-up (LD_PRELOAD), so its TLS lives in the static TLS block that glibc and
 * musl allocate with each thread, and accessing it maps nothing.
 *
 * @note Thread-local, zero-initialised, never touched by another thread.
 */
extern __thread int g_chaos_memory_tls_guard;

/**
 * @brief Lineage of this process: 0 in the one that loaded the library, mixed forward in
 *        every forked child (the atfork handler).
 *
 * @details XORed into a rule's draw key, so the children of a pre-forking server decide
 * differently from the parent and from each other without the key itself being rewritten
 * -- rewriting it would write every snapshot page in each child, the copy-on-write cost
 * chaos_hits.h goes out of its way to avoid. Deterministic: a child's lineage follows from
 * how many times this process has forked, which the test controls, not from a thread id or
 * an address, which it does not.
 */
extern uint64_t g_chaos_memory_lineage;

/**
 * @brief Process-wide seed: 8 bytes of /dev/urandom read by the constructor.
 *
 * @details Read with raw system calls (SYS_openat, SYS_read, SYS_close): nothing
 * allocates and no other preloaded library's open()/read() wrapper sees the read.
 * When /dev/urandom cannot be read the seed is `0x6a09e667f3bcc909 ^ getpid()`,
 * so decisions remain pseudo-random but repeat for the same PID.
 */
extern uint64_t g_chaos_memory_process_seed;

/* =========================================================================
 * Reentrancy guard helpers
 * =========================================================================
 */

/**
 * @brief Whether this thread is inside library code.
 *
 * @return Non-zero inside library code: the caller must pass the call to the real
 *         function without matching rules.
 */
static inline int chaos_memory_in_internal(void)
{
    return g_chaos_memory_tls_guard != 0;
}

/**
 * @brief Sets the reentrancy guard.
 *
 * @return The previous guard value, to be passed to chaos_memory_leave_internal();
 *         restoring the saved value instead of clearing keeps nested enter/leave
 *         pairs correct.
 */
static inline int chaos_memory_enter_internal(void)
{
    int previous = g_chaos_memory_tls_guard;
    g_chaos_memory_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the reentrancy guard.
 *
 * @param previous  Value returned by the matching chaos_memory_enter_internal().
 */
static inline void chaos_memory_leave_internal(int previous)
{
    g_chaos_memory_tls_guard = previous;
}

/* =========================================================================
 * Atomic helpers (GCC builtins, C99)
 * =========================================================================
 */

/**
 * @brief Loads a 64-bit value after a full barrier.
 *
 * @details Used for g_chaos_memory_cached_mtime. A naturally aligned 64-bit load
 * does not tear on the supported targets (amd64, arm64); the barrier orders it
 * after every earlier access of this thread.
 *
 * @param value  Variable to load.
 * @return The loaded value.
 */
static inline uint64_t chaos_memory_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Compare-and-swap of a 64-bit value (full barrier).
 *
 * @details Claims the reload: of all threads that see the same changed stamp,
 * exactly one swaps it to CHAOS_MEMORY_MTIME_RELOADING and reloads.
 *
 * @param value     Variable to update.
 * @param expected  Value that must be present for the swap to happen.
 * @param desired   Value stored on success.
 * @return 1 if the swap happened, 0 otherwise.
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

/* =========================================================================
 * PRNG: xorshift64* seeded through the splitmix64 finaliser
 * =========================================================================
 */

/**
 * @brief splitmix64 finaliser: spreads seed material (process seed ^ tid ^ stack
 *        address) over all 64 bits so that threads with close tids and stacks get
 *        unrelated streams.
 *
 * @details Pure function; no global state.
 */
static inline uint64_t chaos_memory_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Hash of a rule's text, for its draw key.
 *
 * @details splitmix64 over the bytes. From the text rather than the slot index, because
 * chaos_hits_assign() hands a slot out again when a rule leaves the file and the next rule
 * in that slot would inherit its decisions. Two rules with the same text are one rule.
 *
 * @param text Rule as written; NULL hashes as the empty string.
 * @return A well-mixed 64-bit hash.
 */
static inline uint64_t chaos_memory_rule_hash(const char *text)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    size_t index;

    if (text == NULL)
    {
        return chaos_memory_prng_mix(hash);
    }
    for (index = 0U; text[index] != '\0'; ++index)
    {
        hash = chaos_memory_prng_mix(hash + (uint64_t)(unsigned char)text[index]);
    }
    return hash;
}

/**
 * @brief Whether an mmap() flags word requests an anonymous mapping
 *        (selector `mmap/anon`) rather than a file or device one (`mmap/file`).
 *
 * @details In LD_PRELOAD mode a `mmap/anon` ERRNO:ENOMEM rule reaches only callers of
 * the exported mmap symbol: preloaded allocators (jemalloc, tcmalloc), language
 * runtimes and JITs, thread-stack setup in programs that map stacks themselves, and
 * application code. The C library's own malloc (glibc and musl) maps memory through
 * its internal `__mmap`, which never passes through the dynamic symbol table, so
 * malloc() and free() are not faulted by these rules.
 *
 * @param flags  The flags argument of mmap(2).
 * @return Non-zero when MAP_ANONYMOUS is set.
 */
static inline int chaos_memory_mmap_is_anonymous(int flags)
{
    return (flags & MAP_ANONYMOUS) != 0;
}

/**
 * @brief Resolves every real function once, whichever caller comes first.
 *
 * @details The constructor alone is not enough: ELF initialisers run in dependency
 * order, so another object's constructor can reach a wrapper before this
 * library's constructor has run. Every wrapper calls this first. Thread-safe
 * (chaos_once()); a concurrent caller waits until the lookup has finished, except
 * a nested call from inside the lookup on the same thread.
 */
void chaos_memory_ensure_symbols(void);

#endif
