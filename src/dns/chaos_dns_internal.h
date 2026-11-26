/**
 * @file chaos_dns_internal.h
 * @brief Private contracts shared by every libchaos-dns translation unit.
 *
 * @details
 * The one header every dns .c file includes. It owns:
 *   1. **Constants**: the fixed paths (rule file, status file, hits file prefix), the
 *      capacity limits (rules, rule-file bytes, selector and value text) and the
 *      reserved change-stamp values that double as the reload claim.
 *   2. **Real-function pointers**: one type and one `g_chaos_dns_real_*` pointer for
 *      getaddrinfo, getnameinfo, freeaddrinfo, gethostbyname2(_r) and
 *      gethostbyaddr(_r), defined in chaos_dns.c.
 *   3. **Thread-local state and inline helpers**: the reentrancy guard, the 64-bit
 *      atomic load and CAS, the thread id, and the per-thread xorshift64* PRNG.
 *
 * ### Visibility
 * The library builds with `-fvisibility=hidden`; only the wrappers carry
 * CHAOS_DNS_EXPORT: getaddrinfo, freeaddrinfo, getnameinfo, gethostbyname,
 * gethostbyname2, gethostbyname_r, gethostbyname2_r, gethostbyaddr, gethostbyaddr_r.
 *
 * ### Thread and signal safety
 * Every inline helper touches only thread-local data or one word behind a full barrier;
 * none takes a lock. Shared rule state is published by the two-snapshot protocol in
 * chaos_dns_config.c.
 *
 * @module  libchaos-dns internals
 * @stability  Private -- not part of any public API.
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

/** @brief Rule file of libchaos-dns; looked at (stat(2)) at most once per 1 ms per process. */
#define CHAOS_DNS_CONFIG_PATH "/tmp/.chaos-dns.conf"

/** @brief Status file: outcome of the last load of the rule file (see chaos_status.h). */
#define CHAOS_DNS_STATUS_PATH "/tmp/.chaos-dns.status"

/** @brief Hits file prefix; each image appends `.<n>` (see chaos_hits_file_number()). */
#define CHAOS_DNS_HITS_PREFIX "/tmp/.chaos-dns.hits"

/** @brief Most rules one snapshot holds; a file with more is rejected (TOO_MANY). */
#define CHAOS_DNS_MAX_RULES 256U

/** @brief Nominal line length, used only to size CHAOS_DNS_MAX_CONFIG_BYTES (not enforced). */
#define CHAOS_DNS_MAX_LINE_LENGTH 1024U

/**
 * @brief Rule file size limit in bytes: 256 x 1024 = 256 KiB.
 *
 * @details A file of this size or larger is rejected as a whole (status reason
 * TOO_LARGE): a snapshot with no rules is published and stays until the file changes.
 * The largest file accepted is one byte smaller.
 */
#define CHAOS_DNS_MAX_CONFIG_BYTES (CHAOS_DNS_MAX_RULES * CHAOS_DNS_MAX_LINE_LENGTH)

/** @brief Capacity, NUL included, of selector text (host name, suffix, IP text): 255 chars. */
#define CHAOS_DNS_MAX_TEXT 256U

/** @brief Capacity, NUL included, of a rule value (REWRITE name, OVERRIDE list, ...). */
#define CHAOS_DNS_MAX_VALUE 512U

/**
 * @brief Default visibility for the wrappers; every other symbol stays hidden.
 *
 * @details Applied only to the wrapped resolver entry points, so internal helpers can
 * neither clash with the application's symbols nor be interposed themselves.
 */
#define CHAOS_DNS_EXPORT __attribute__((visibility("default")))

/**
 * @name Reserved change-stamp values
 *
 * g_chaos_dns_cached_mtime holds either a change stamp (FNV-style hash of mtime s and
 * ns, size, inode and device) or one of these. chaos_dns_config_normalize_mtime_hash()
 * remaps a computed stamp that collides with one of them.
 * @{
 */
/** Stamp of a rule file that does not exist (stat(2) failed). */
#define CHAOS_DNS_MTIME_MISSING UINT64_C(0)
/** Held while a reload is in progress: the reload claim, taken by CAS. */
#define CHAOS_DNS_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
/** Before the first load: never equals an observed stamp, so the first prepare loads. */
#define CHAOS_DNS_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)
/** @} */

/* -------------------------------------------------------------------------
 * Function-pointer types of the real resolver functions. Filled once by
 * chaos_dns_ensure_symbols() via dlsym(RTLD_NEXT, ...).
 * ------------------------------------------------------------------------- */

/**
 * @brief Type of the real getaddrinfo(3).
 * @see g_chaos_dns_real_getaddrinfo
 */
typedef int (*chaos_dns_getaddrinfo_fn)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

/**
 * @brief Type of the real getnameinfo(3).
 * @see g_chaos_dns_real_getnameinfo
 */
typedef int (*chaos_dns_getnameinfo_fn)(
    const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int
);

/**
 * @brief Type of the real freeaddrinfo(3).
 *
 * @details Used to release lists the real getaddrinfo returned: whole lists the
 * application frees through the freeaddrinfo wrapper, single nodes FILTER_FAMILY drops,
 * the tail LIMIT cuts, and the per-literal results OVERRIDE copies. Never applied to a
 * list libchaos-dns built itself (chaos_dns_owned.h).
 *
 * @see g_chaos_dns_real_freeaddrinfo
 */
typedef void (*chaos_dns_freeaddrinfo_fn)(struct addrinfo *);

/** @brief Signature of the real gethostbyname2(3). */
typedef struct hostent *(*chaos_dns_gethostbyname2_fn)(const char *, int);

/** @brief Signature of the real gethostbyname2_r(3). */
typedef int (*chaos_dns_gethostbyname2_r_fn)(const char *, int, struct hostent *, char *, size_t, struct hostent **, int *);

/** @brief Signature of the real gethostbyaddr(3). */
typedef struct hostent *(*chaos_dns_gethostbyaddr_fn)(const void *, socklen_t, int);

/** @brief Signature of the real gethostbyaddr_r(3). */
typedef int (*chaos_dns_gethostbyaddr_r_fn)(const void *, socklen_t, int, struct hostent *, char *, size_t, struct hostent **, int *);

/* -------------------------------------------------------------------------
 * Real-function pointers and thread-local state, defined in chaos_dns.c.
 * ------------------------------------------------------------------------- */

/**
 * @brief The real getaddrinfo(3): the next definition after this DSO (RTLD_NEXT).
 *
 * @details NULL until chaos_dns_ensure_symbols() has run; a symbol that cannot be found
 * aborts the process. A call that arrives during the resolution sees NULL, and the
 * call_real helper then fails with EAI_SYSTEM / ENOSYS, since no system call can stand in
 * for a resolver.
 */
extern chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo;

/**
 * @brief The real getnameinfo(3).
 * @see g_chaos_dns_real_getaddrinfo for lifecycle notes.
 */
extern chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo;

/**
 * @brief The real freeaddrinfo(3).
 *
 * @details Releases nodes the real getaddrinfo allocated. Lists built by OVERRIDE
 * (chaos_dns_owned.h) are never passed to it; their nodes dropped by FILTER_FAMILY or
 * LIMIT are only unlinked.
 *
 * @see g_chaos_dns_real_getaddrinfo for lifecycle notes.
 */
extern chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo;

/** @brief The real hostent resolvers (gethostbyname2(_r), gethostbyaddr(_r)). */
extern chaos_dns_gethostbyname2_fn g_chaos_dns_real_gethostbyname2;
extern chaos_dns_gethostbyname2_r_fn g_chaos_dns_real_gethostbyname2_r;
extern chaos_dns_gethostbyaddr_fn g_chaos_dns_real_gethostbyaddr;
extern chaos_dns_gethostbyaddr_r_fn g_chaos_dns_real_gethostbyaddr_r;

/**
 * @brief Per-thread reentrancy guard: non-zero while libchaos-dns itself is calling out.
 *
 * @details Set around every real-function call, the rule-file stat/read and the seed
 * read. Every wrapper checks it first and forwards straight to the real function when
 * set, so a resolver that calls getaddrinfo internally, or the OVERRIDE path's own
 * getaddrinfo calls, are not matched against rules again.
 *
 * Access pattern:
 * @code
 *   int previous = chaos_dns_enter_internal();
 *   // ... call out ...
 *   chaos_dns_leave_internal(previous);
 * @endcode
 * Save/restore rather than a counter keeps nested sections and a signal handler that
 * runs a wrapper in the middle of one correct. The guard is per library; other preloaded
 * libraries still see these calls.
 */
extern __thread int g_chaos_dns_tls_guard;

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
extern uint64_t g_chaos_dns_lineage;

/**
 * @brief How often this process has forked, counted before the fork (the atfork prepare
 *        handler), so that the child sees its own ordinal among its siblings.
 *
 * @details Without it every child of one parent would mix the same value into its
 * lineage and the siblings of a pre-forking server would all make the *same* decision:
 * at `p=0.5` either all of them or none, which is not a probability any more. The child
 * resets it, so each process counts the children it forks itself.
 */
extern uint64_t g_chaos_dns_forks;

/**
 * @brief Process-wide seed, the base of every per-thread seed.
 *
 * @details Set once by chaos_dns_init() from /dev/urandom (raw system calls), else a
 * constant XOR getpid(). Read-only afterwards, so no lock is needed.
 */
extern uint64_t g_chaos_dns_process_seed;

/* -------------------------------------------------------------------------
 * Reentrancy guard
 * ------------------------------------------------------------------------- */

/**
 * @brief Whether the calling thread is inside a libchaos-dns section.
 *
 * @details Checked first by every wrapper: non-zero means the call comes from the
 * library itself and goes to the real function without rule matching.
 *
 * @return Non-zero inside a section; 0 for a call from application code.
 *
 * @threadsafety  Thread-local read; async-signal-safe.
 */
static inline int chaos_dns_in_internal(void)
{
    return g_chaos_dns_tls_guard != 0;
}

/**
 * @brief Sets the reentrancy guard and returns the value it replaces.
 *
 * @details Pair with chaos_dns_leave_internal(), passing the returned value back, so
 * nested sections do not clear the guard early.
 *
 * @return The guard value before the call (0 or 1).
 *
 * @threadsafety  Thread-local; async-signal-safe.
 */
static inline int chaos_dns_enter_internal(void)
{
    int previous = g_chaos_dns_tls_guard;
    g_chaos_dns_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the reentrancy guard saved by chaos_dns_enter_internal().
 *
 * @param previous  Value returned by the matching chaos_dns_enter_internal().
 *
 * @threadsafety  Thread-local; async-signal-safe.
 */
static inline void chaos_dns_leave_internal(int previous)
{
    g_chaos_dns_tls_guard = previous;
}

/* -------------------------------------------------------------------------
 * Atomic helpers (GCC __sync built-ins)
 * -------------------------------------------------------------------------
 * The reload claim and the active index are the only shared words written at run
 * time; one 64-bit CAS and full barriers suffice. C11 atomics are avoided because
 * the library is C99.
 * ------------------------------------------------------------------------- */

/**
 * @brief Full barrier, then a load of a 64-bit word.
 *
 * @details Reads g_chaos_dns_cached_mtime so that a reader sees the stores the reload
 * owner made before publishing it. On amd64 and arm64 an aligned 64-bit load is
 * single-copy atomic.
 *
 * @param value  Word to load; must not be NULL.
 * @return  The value after the barrier.
 *
 * @threadsafety  Lock-free.
 */
static inline uint64_t chaos_dns_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief 64-bit compare-and-swap with full-barrier semantics.
 *
 * @details Claims the reload: only the thread that swaps g_chaos_dns_cached_mtime from
 * the observed stamp to CHAOS_DNS_MTIME_RELOADING reloads; the others use the active
 * snapshot and do not wait.
 *
 * @param value     Word to update.
 * @param expected  Value the caller saw.
 * @param desired   Value to store on success.
 * @return  Non-zero if the swap happened; 0 if @p value no longer held @p expected.
 *
 * @threadsafety  Lock-free.
 */
static inline int
chaos_dns_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/* -------------------------------------------------------------------------
 * Thread id
 * ------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * xorshift64* PRNG
 * -------------------------------------------------------------------------
 * Marsaglia's xorshift64 step with Vigna's xorshift64* output multiplier; seeds pass
 * through the splitmix64 finaliser. One word of state per thread, no lock, no system
 * call. Used for probability draws and SHUFFLE; not cryptographic.
 * ------------------------------------------------------------------------- */

/**
 * @brief splitmix64 finaliser: maps a 64-bit word to a well-mixed one.
 *
 * @details Applied to seed material (process seed, small tids, stack addresses) so
 * every input bit affects the whole initial state.
 *
 * @param value  Seed material.
 * @return  Mixed word.
 *
 * @threadsafety  Pure function.
 */
static inline uint64_t chaos_dns_prng_mix(uint64_t value)
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
static inline uint64_t chaos_dns_rule_hash(const char *text)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    size_t index;

    if (text == NULL)
    {
        return chaos_dns_prng_mix(hash);
    }
    for (index = 0U; text[index] != '\0'; ++index)
    {
        hash = chaos_dns_prng_mix(hash + (uint64_t)(unsigned char)text[index]);
    }
    return hash;
}

/**
 * @brief Resolves every real function once, whichever caller comes first.
 *
 * @details The constructor alone is not enough: ELF initialisers run in dependency order,
 * so another object's constructor can reach a wrapper before this library's constructor
 * has run. Every wrapper calls this first; afterwards it is one acquire load
 * (chaos_once(), no libpthread needed before glibc 2.34).
 */
void chaos_dns_ensure_symbols(void);

#endif
