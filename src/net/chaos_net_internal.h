/**
 * @file chaos_net_internal.h
 * @brief Private contracts shared by every libchaos-net translation unit.
 *
 * @details
 * The one header every net .c file includes. It owns:
 *   - The fixed paths (rule file, status file, hits file prefix) and the capacity limits
 *     (rules, rule-file bytes, UNIX path text).
 *   - The reserved change-stamp values that double as the reload claim.
 *   - CHAOS_NET_EXPORT, the only way a symbol escapes the `-fvisibility=hidden` DSO.
 *   - The glibc/musl ABI shims for the sockaddr union and the sendmmsg/recvmmsg flags type.
 *   - One function-pointer type and one `g_chaos_net_real_*` pointer per real function.
 *   - Thread-local state: the reentrancy guard and the per-thread PRNG.
 *
 * Every helper here is `static inline` and touches only thread-local data or a single
 * word with a full barrier, so all of them are async-signal-safe and need no lock.
 * Nothing in this header is ABI: the pointers are defined in chaos_net.c, and
 * chaos-init (SECCOMP mode) includes the parser sources directly.
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
 * @brief Rule file of libchaos-net.
 *
 * @details Looked at (stat(2)) at most once per CHAOS_CHECK_INTERVAL_NS (1 ms) per process
 * once a first load has completed; see chaos_net_config_checked_recently(). A missing file
 * means no rules (fail-open). /tmp lets an unprivileged test harness create and rewrite it.
 */
#define CHAOS_NET_CONFIG_PATH "/tmp/.chaos-net.conf"

/** @brief Status file: outcome of the last load of the rule file (see chaos_status.h). */
#define CHAOS_NET_STATUS_PATH "/tmp/.chaos-net.status"

/** @brief Hits file prefix; each image appends `.<n>` (see chaos_hits_file_number()). */
#define CHAOS_NET_HITS_PREFIX "/tmp/.chaos-net.hits"

/**
 * @brief Most rules one snapshot holds.
 *
 * @details Bounds both snapshots, the hit-slot pool and the hits-file scratch buffer, all
 * of which are static (BSS), so no load allocates. A rule file with more rules is
 * rejected as a whole (status reason TOO_MANY): the published snapshot then has no rules.
 */
#define CHAOS_NET_MAX_RULES 256U

/**
 * @brief Nominal line length, used only to size CHAOS_NET_MAX_CONFIG_BYTES.
 *
 * @details No per-line limit is enforced: a long line is parsed like any other, and the
 * status file reports at most CHAOS_STATUS_TEXT_MAX (200) bytes of it.
 */
#define CHAOS_NET_MAX_LINE_LENGTH 1024U

/**
 * @brief Rule file size limit in bytes: 256 x 1024 = 256 KiB.
 *
 * @details A file of this size or larger is rejected as a whole (status reason TOO_LARGE)
 * and the published snapshot has no rules until the file changes; the largest file
 * accepted is one byte smaller. The read buffer is a single static array of this size plus
 * the NUL, used only by the reload owner. It is deliberately not `__thread`: see
 * g_chaos_net_config_buffer.
 */
#define CHAOS_NET_MAX_CONFIG_BYTES (CHAOS_NET_MAX_RULES * CHAOS_NET_MAX_LINE_LENGTH)

/**
 * @brief Capacity, NUL included, of chaos_net_endpoint_t::value.text (UNIX paths).
 *
 * @details Must exceed sizeof(sun_path) (108 on Linux); chaos_net_endpoint.c enforces this
 * at compile time. The parser rejects a `unix://` path of 256 bytes or more.
 */
#define CHAOS_NET_MAX_TEXT 256U

/**
 * @brief Default visibility for the wrappers; every other symbol stays hidden.
 *
 * @details The library builds with `-fvisibility=hidden`. Only the wrappers (bind,
 * connect, recv, read, close, ...) carry this attribute, so internal helpers can neither
 * clash with the application's symbols nor be interposed themselves.
 */
#define CHAOS_NET_EXPORT __attribute__((visibility("default")))

/**
 * @brief Change stamp of a rule file that does not exist (stat(2) failed).
 *
 * @details One of three reserved stamp values. chaos_net_config_normalize_mtime_hash()
 * remaps a computed stamp that collides with any of them, so a reserved value always
 * means what it says.
 */
#define CHAOS_NET_MTIME_MISSING UINT64_C(0)

/**
 * @brief Change stamp held while a reload is in progress: the reload claim.
 *
 * @details The reloading thread CASes the cached stamp from its observed value to this
 * one, fills the inactive snapshot, then publishes the real stamp. A thread that sees this
 * value uses the active snapshot and does not wait. A fork() child whose parent was
 * mid-reload resets it to CHAOS_NET_MTIME_UNKNOWN in its atfork handler.
 */
#define CHAOS_NET_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Change stamp before the first load.
 *
 * @details Set by chaos_net_config_init(). It never equals an observed stamp, so the first
 * chaos_net_config_prepare() always loads, and the 1 ms throttle stays off until then.
 */
#define CHAOS_NET_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/*---------------------------------------------------------------------------
 * glibc sockaddr ABI shim
 *
 * glibc declares the sockaddr parameters as transparent unions
 * (__SOCKADDR_ARG / __CONST_SOCKADDR_ARG); musl uses plain pointers. A wrapper must
 * match the libc prototype exactly or the header declaration conflicts, so the
 * parameter type and the unwrapping expression are selected per libc here. The
 * sendmmsg/recvmmsg flags parameter differs the same way (int on glibc, unsigned
 * int on musl).
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
 * Function-pointer types of the real functions
 *
 * One type per wrapped symbol, plus the non-wrapped getsockname, getpeername,
 * getsockopt and setsockopt that the library calls itself. The pointers are filled
 * by dlsym(RTLD_NEXT) in chaos_net_ensure_symbols() and never change afterwards, so
 * hot-path reads need no barrier. "Never NULL after init" below means after that
 * resolution: a call that arrives during it (a signal handler, or an allocator doing
 * I/O inside dlsym) still sees NULL, and the call_real helpers then issue the system
 * call directly.
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

/** @brief Type of the real setsockopt(2); resolved, not interposed. */
typedef int (*chaos_net_setsockopt_fn)(int, int, int, const void *, socklen_t);

/** @brief Type of the real read(2); interposed for sockets only. */
typedef ssize_t (*chaos_net_read_fn)(int, void *, size_t);

/** @brief Type of the real write(2); interposed for sockets only. */
typedef ssize_t (*chaos_net_write_fn)(int, const void *, size_t);

/** @brief Type of the real readv(2) and writev(2); interposed for sockets only. */
typedef ssize_t (*chaos_net_readv_fn)(int, const struct iovec *, int);

/** @brief Type of the real close(2); interposed for sockets only. */
typedef int (*chaos_net_close_fn)(int);
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
 * Real-function pointers (defined in chaos_net.c)
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

/** @brief How many descriptors hold a socket, as far as this process can tell. */
typedef enum chaos_net_ownership
{
    CHAOS_NET_OWNER_SOLE = 0,   /**< No other descriptor anywhere refers to it. */
    CHAOS_NET_OWNER_SHARED = 1, /**< Another descriptor, here or in another process, does. */
    CHAOS_NET_OWNER_UNKNOWN = 2 /**< Could not be established; treat as shared. */
} chaos_net_ownership_t;

/**
 * @brief Whether socket @p fd is held by more descriptors than this one.
 *
 * @details Reads the state out of `/proc/<pid>/fd`, so it covers every way of sharing an
 * open file description rather than the ones a tracker would know (chaos_net_owner.c).
 * Runs only for a close a RESET rule matched. Anything unreadable answers UNKNOWN, which
 * the caller must treat as shared: a wrong SOLE leaves SO_LINGER behind on a socket that
 * outlives the close.
 *
 * @param fd Socket about to be closed.
 * @return One of chaos_net_ownership_t.
 */
chaos_net_ownership_t chaos_net_socket_ownership(int fd);

/**
 * @brief Records that a matched RESET rule was suppressed on a socket this process does not
 *        own alone.
 *
 * @details The count reaches the test through the hits file's header lines
 * (`suppressed.shared=`, `suppressed.unknown=`), published by the existing write cadence --
 * no file I/O on the interposition path. Counted per matched close, independent of the
 * probability draw, because ownership is settled before the rule fires.
 *
 * @param ownership What the scan answered; anything but SHARED counts as unknown.
 */
void chaos_net_reset_suppressed(chaos_net_ownership_t ownership);

extern chaos_net_setsockopt_fn g_chaos_net_real_setsockopt;
extern chaos_net_read_fn g_chaos_net_real_read;
extern chaos_net_write_fn g_chaos_net_real_write;
extern chaos_net_readv_fn g_chaos_net_real_readv;
extern chaos_net_readv_fn g_chaos_net_real_writev;
extern chaos_net_close_fn g_chaos_net_real_close;

/**
 * @brief Resolves every real function once, whichever caller comes first.
 *
 * @details The constructor alone is not enough: ELF initialisers run in dependency order,
 * so another object's constructor can reach a wrapper (read, close, ...) before
 * chaos_net_init() has run. Every wrapper calls this first; after the first call it is
 * one acquire load (chaos_once(), which needs no libpthread before glibc 2.34). A call
 * from inside the resolution on the same thread returns at once with pointers still NULL.
 */
void chaos_net_ensure_symbols(void);
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
 * @brief Per-thread reentrancy guard: non-zero while libchaos-net itself is calling out.
 *
 * @details Set by chaos_net_enter_internal() around every call the library makes into an
 * interposable symbol (real functions, stat, getsockname, getpeername, getsockopt, the
 * fdinfo open/read/close) and restored by chaos_net_leave_internal(). Every wrapper
 * checks it first and forwards straight to the real function when set, which stops the
 * library from matching rules against its own traffic and from recursing (getsockname
 * inside endpoint resolution, read() inside the epoll fdinfo scan).
 *
 * Save/restore rather than a counter keeps it correct for nested sections and for a
 * signal handler that runs a wrapper in the middle of one: each frame restores exactly
 * the value it found. The guard is per library; it does not hide these calls from other
 * preloaded libraries such as libchaos-io.
 */
extern __thread int g_chaos_net_tls_guard;

/**
 * @brief Lineage of this process: 0 in the one that loaded the library, mixed forward in
 *        every forked child (the atfork handler).
 *
 * @details XORed into a rule's draw key, so the children of a pre-forking server decide
 * differently from the parent and from each other without the key itself being rewritten
 * -- rewriting it would write every snapshot page in each child, the copy-on-write cost
 * chaos_hits.h goes out of its way to avoid. Deterministic: a child's lineage follows
 * from how many times this process has forked, which the test controls.
 */
extern uint64_t g_chaos_net_lineage;

/**
 * @brief Process-wide seed, the base of every per-thread seed.
 *
 * @details Read from /dev/urandom by chaos_net_init() with raw system calls; if that
 * fails, a constant XOR getpid(). Written once in the constructor, read-only afterwards.
 */
extern uint64_t g_chaos_net_process_seed;

/*---------------------------------------------------------------------------
 * Reentrancy-guard inline helpers
 *---------------------------------------------------------------------------*/

/**
 * @brief Whether the calling thread is inside a libchaos-net section.
 *
 * @details Checked first by every wrapper. Non-zero means the call comes from the library
 * itself (getsockname during endpoint resolution, read() in the fdinfo scan) and must go
 * to the real function without rule matching.
 *
 * @return Non-zero when the guard is set; 0 otherwise.
 * @par Thread-safety: reads thread-local data; async-signal-safe.
 */
static inline int chaos_net_in_internal(void)
{
    return g_chaos_net_tls_guard != 0;
}

/**
 * @brief Sets the reentrancy guard and returns the value it replaces.
 *
 * @details Bracket every library call into an interposable symbol with this and
 * chaos_net_leave_internal(), e.g. getsockname in chaos_net_endpoint_from_local_fd() and
 * stat in chaos_net_config_observed_mtime().
 *
 * @return Previous guard value (0 or 1), to pass to chaos_net_leave_internal().
 * @par Thread-safety: writes thread-local data; async-signal-safe.
 */
static inline int chaos_net_enter_internal(void)
{
    int previous = g_chaos_net_tls_guard;
    g_chaos_net_tls_guard = 1;
    return previous;
}

/**
 * @brief Restores the reentrancy guard saved by chaos_net_enter_internal().
 *
 * @details Restoring the saved value, not clearing, keeps nested sections correct: the
 * epoll fdinfo scan sets the guard and calls read(), whose wrapper forwards through
 * chaos_net_call_real_read(), which saves 1 and restores 1; only the outermost frame
 * clears it.
 *
 * @param previous Value returned by the matching chaos_net_enter_internal().
 * @par Thread-safety: writes thread-local data; async-signal-safe.
 */
static inline void chaos_net_leave_internal(int previous)
{
    g_chaos_net_tls_guard = previous;
}

/*---------------------------------------------------------------------------
 * Atomic helpers (GCC __sync built-ins: C99, no stdatomic.h)
 *---------------------------------------------------------------------------*/

/**
 * @brief Full barrier, then a load of a 64-bit word.
 *
 * @details Reads g_chaos_net_cached_mtime so that a reader sees the stores the reload
 * owner made before publishing it. A full fence rather than an acquire load keeps the
 * code C99 (no stdatomic.h); on amd64 and arm64 a 64-bit aligned load is single-copy
 * atomic.
 *
 * @param value Word to load; must not be NULL.
 * @return The value after the barrier.
 */
static inline uint64_t chaos_net_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief 64-bit compare-and-swap with full-barrier semantics.
 *
 * @details Claims the reload by swapping g_chaos_net_cached_mtime from the observed stamp
 * to CHAOS_NET_MTIME_RELOADING. Of threads racing to reload, exactly one wins; the others
 * use the active snapshot.
 *
 * @param value    Word to update; must not be NULL.
 * @param expected Value the caller saw.
 * @param desired  Value to store on success.
 * @return Non-zero if the swap happened; 0 if @p value no longer held @p expected.
 */
static inline int
chaos_net_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/*---------------------------------------------------------------------------
 * Thread id
 *---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
 * Draws: counter-based, no stream
 *---------------------------------------------------------------------------*/

/**
 * @brief splitmix64 finaliser: maps a 64-bit word to a well-mixed one.
 *
 * @details This is the whole generator. There is no state to advance: a sample is a pure
 * function of the rule and the number of the evaluation it belongs to, so no other thread
 * can shift it and the decision for the nth evaluation of a rule is the same in every run
 * with the same CHAOS_SEED. Not cryptographic, and it need not be: what is wanted is that
 * neighbouring counters give unrelated samples, which is splitmix64's avalanche property.
 *
 * @param value Input word.
 * @return Mixed word.
 */
static inline uint64_t chaos_net_prng_mix(uint64_t value)
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
static inline uint64_t chaos_net_rule_hash(const char *text)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    size_t index;

    if (text == NULL)
    {
        return chaos_net_prng_mix(hash);
    }
    for (index = 0U; text[index] != '\0'; ++index)
    {
        hash = chaos_net_prng_mix(hash + (uint64_t)(unsigned char)text[index]);
    }
    return hash;
}

/**
 * @brief REDIRECT: the address `connect` is sent to instead of the one it was given.
 *
 * @details Not a chaos_net_endpoint_t, which carries a UNIX path and selector
 * bookkeeping a target has no use for: a redirect needs a family, an address and a port.
 */
typedef struct chaos_net_redirect
{
    int family;    /**< AF_INET or AF_INET6; 0 when the rule is no REDIRECT. */
    uint16_t port; /**< Host byte order; never 0, which `connect` could not use. */
    /** @brief Address storage; the active member follows @c family. */
    union
    {
        struct in_addr ipv4;  /**< Active when family is AF_INET. */
        struct in6_addr ipv6; /**< Active when family is AF_INET6. */
    } value;
} chaos_net_redirect_t;

/**
 * @brief Builds the sockaddr a REDIRECT rule sends a `connect` to instead of @p address.
 *
 * @details The socket decides what can be written into it, so the family of the address
 * the caller passed is what the target has to fit:
 * - same family: the target as it stands;
 * - an IPv4 target on an AF_INET6 socket: the IPv4-mapped form (`::ffff:a.b.c.d`), which
 *   is how such a socket reaches an IPv4 host and how `getpeername` reports it afterwards
 *   -- the case a runtime that opens AF_INET6 sockets and connects to a v4 address hits,
 *   and the one a `tcp4://` rule matched to get here;
 * - an IPv6 target on an AF_INET socket: nothing to build, so the rule does not fire and
 *   counts no hit, as DROP does not fire on a stream.
 *
 * The length never changes, because the family never does: a caller that passed 16 bytes
 * gets 16 back. Here rather than in one of the modules because both the `connect` wrapper
 * and chaos-init build the address, and from the same arithmetic.
 *
 * @param target      Parsed REDIRECT target.
 * @param address     The sockaddr the caller passed; its family decides.
 * @param out         Output storage, zeroed first.
 * @param out_length  Output: bytes of @p out that are valid.
 * @return 1 with @p out and @p out_length written, else 0.
 */
static inline int chaos_net_redirect_sockaddr(
    const chaos_net_redirect_t *target,
    const struct sockaddr *address,
    struct sockaddr_storage *out,
    socklen_t *out_length
)
{
    (void)memset(out, 0, sizeof(*out));
    if (address->sa_family == AF_INET && target->family == AF_INET)
    {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)(void *)out;

        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(target->port);
        ipv4->sin_addr = target->value.ipv4;
        *out_length = (socklen_t)sizeof(*ipv4);
        return 1;
    }
    if (address->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)(void *)out;

        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(target->port);
        if (target->family == AF_INET6)
        {
            ipv6->sin6_addr = target->value.ipv6;
        }
        else
        {
            unsigned char *bytes = (unsigned char *)&ipv6->sin6_addr;

            (void)memset(bytes, 0, 10U);
            bytes[10] = 0xffU;
            bytes[11] = 0xffU;
            (void)memcpy(bytes + 12, &target->value.ipv4, 4U);
        }
        *out_length = (socklen_t)sizeof(*ipv6);
        return 1;
    }
    return 0;
}

#endif
