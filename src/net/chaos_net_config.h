/**
 * @file chaos_net_config.h
 * @brief Rule model, rule-file parser and snapshot reload API of libchaos-net.
 *
 * @details
 * Domain types:
 *   - chaos_net_operation_t -- the operation a rule targets (a group of wrapped calls).
 *   - chaos_net_effect_t    -- what a rule does when it fires.
 *   - chaos_net_endpoint_t  -- a selector from the rule file, or an endpoint resolved
 *                              from a live socket; both share one normalised form.
 *   - chaos_net_rule_t      -- selector + operation + effect + parameter + qualifiers.
 *
 * Rule file grammar (`/tmp/.chaos-net.conf`, one rule per line, `#` starts a comment,
 * qualifiers such as `@first=N` may follow, see chaos_policy.h):
 * @code
 *   <selector> : <operation> : <ERRNO-name | effect> : <value>
 * @endcode
 * The value is a probability for ERRNO names, CORRUPT, TIMEOUT, DUP and RESET, a delay in
 * ms for LATENCY, and a chunk size in bytes for TRICKLE. Examples:
 * @code
 *   tcp4://127.0.0.1:8080 : connect : ECONNREFUSED : 0.5
 *   tcp4://\*:443         : recv    : LATENCY      : 200
 *   *                     : recv    : CORRUPT      : 0.1
 *   tcp4://\*:6379        : poll    : TIMEOUT      : 0.3
 *   tcp4://\*:6379        : recv    : TRICKLE      : 1
 * @endcode
 *
 * Reload: two snapshots and one CAS on the cached change stamp. At most one thread
 * reloads at a time, into the inactive snapshot; every other thread keeps using the
 * active one and never blocks. Details in chaos_net_config.c.
 *
 * @par Stability: private / internal
 * @par Module: chaos-net
 */

#ifndef CHAOS_NET_CONFIG_H
#define CHAOS_NET_CONFIG_H

#include "chaos_net_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

#include <netinet/in.h>
#include <sys/uio.h>

/**
 * @brief The operation a rule targets: a group of wrapped calls.
 *
 * @details The endpoint each group is matched on:
 *   - BIND, CONNECT: the sockaddr argument.
 *   - LISTEN, ACCEPT: the socket's local address (accept's sockaddr is an output).
 *   - SOCKET: (domain, type) only; no address exists yet, so only wildcard selectors
 *     are accepted for it.
 *   - SHUTDOWN, CLOSE: the local address, else the peer address.
 *   - POLL: each watched descriptor's local address, else its peer address.
 *   - SEND: the destination argument when given, else both ends of the connection
 *     (chaos_net_match_connected()).
 *   - RECV: both ends of the connection.
 *
 * CHAOS_NET_OP_INVALID (-1) is the parser's failure value.
 */
typedef enum chaos_net_operation
{
    CHAOS_NET_OP_INVALID = -1, /**< Parse failure or unrecognised token. */
    CHAOS_NET_OP_BIND,         /**< Targets bind(2). */
    CHAOS_NET_OP_LISTEN,       /**< Targets listen(2). */
    CHAOS_NET_OP_CONNECT,      /**< Targets connect(2). */
    CHAOS_NET_OP_ACCEPT,       /**< Targets accept(2) / accept4(2). */
    CHAOS_NET_OP_SOCKET,       /**< Targets socket(2) / socketpair(2). */
    CHAOS_NET_OP_SHUTDOWN,     /**< Targets shutdown(2). */
    CHAOS_NET_OP_POLL,         /**< Targets poll/ppoll/select/pselect/epoll_wait/epoll_pwait. */
    CHAOS_NET_OP_SEND, /**< Targets send/sendto/sendmsg/sendmmsg, and write/writev on sockets. */
    CHAOS_NET_OP_RECV, /**< Targets recv/recvfrom/recvmsg/recvmmsg, and read/readv on sockets. */
    CHAOS_NET_OP_CLOSE /**< Targets close(2) on sockets. */
} chaos_net_operation_t;

/**
 * @brief What a matched rule does when it fires.
 *
 * @details
 *   | Effect  | Operations | Behaviour when the rule fires |
 *   |---------|------------|-------------------------------|
 *   | ERRNO   | all        | -1 with the errno, real call skipped; close: closes, then -1 |
 *   | LATENCY | all        | Sleeps latency_ms, then makes the real call |
 *   | CORRUPT | recv       | Flips one bit inside the bytes the real call returned |
 *   | TIMEOUT | poll       | Waits out the call's own timeout, then returns 0 (nothing ready) |
 *   | RESET   | close      | SO_LINGER {1, 0} before the close: the peer gets an RST |
 *   | TRICKLE | recv       | A stream receive returns at most chunk_bytes |
 *   | DUP     | recv       | The socket's previous payload is delivered once more |
 *
 * chaos_net_effect_allowed() enforces the Operations column at parse time.
 * CHAOS_NET_EFFECT_INVALID (-1) is the parser's failure value.
 */
typedef enum chaos_net_effect
{
    CHAOS_NET_EFFECT_INVALID = -1, /**< Parse failure or unrecognised token. */
    CHAOS_NET_EFFECT_ERRNO,        /**< -1 with errnum instead of the call (close: after it). */
    CHAOS_NET_EFFECT_LATENCY,      /**< Sleep latency_ms before the real call. */
    CHAOS_NET_EFFECT_CORRUPT,      /**< RECV-only: flip one bit in the received bytes. */
    CHAOS_NET_EFFECT_TIMEOUT,      /**< POLL-only: wait out the timeout, return 0. */
    CHAOS_NET_EFFECT_RESET,        /**< CLOSE-only: abortive close, the peer receives an RST. */
    CHAOS_NET_EFFECT_TRICKLE,      /**< RECV-only: return at most chunk_bytes per call. */
    CHAOS_NET_EFFECT_DUP           /**< RECV-only: deliver the previous payload once more. */
} chaos_net_effect_t;

/**
 * @brief Address family and transport of an endpoint, as one discriminant.
 *
 * @details The selector scheme encodes both (tcp4, udp6, ...), and a sockaddr alone does
 * not tell TCP from UDP, so runtime endpoints take the transport from SO_TYPE. Matching
 * requires equal kinds: a tcp4 selector never matches a udp4 or tcp6 endpoint. The one
 * exception is an IPv4-mapped IPv6 address (::ffff:a.b.c.d), which is normalised to
 * TCP4/UDP4 so IPv4 rules match a dual-stack socket's IPv4 traffic.
 *
 * CHAOS_NET_ENDPOINT_ANY is produced only by the bare `*` selector and matches every
 * kind. CHAOS_NET_ENDPOINT_INVALID (-1) is the parser's failure value.
 */
typedef enum chaos_net_endpoint_kind
{
    CHAOS_NET_ENDPOINT_INVALID = -1, /**< Parse failure. */
    CHAOS_NET_ENDPOINT_ANY,          /**< Wildcard: matches any family/protocol. */
    CHAOS_NET_ENDPOINT_TCP4,         /**< IPv4 TCP (AF_INET + SOCK_STREAM). */
    CHAOS_NET_ENDPOINT_TCP6,         /**< IPv6 TCP (AF_INET6 + SOCK_STREAM). */
    CHAOS_NET_ENDPOINT_UDP4,         /**< IPv4 UDP (AF_INET + SOCK_DGRAM). */
    CHAOS_NET_ENDPOINT_UDP6,         /**< IPv6 UDP (AF_INET6 + SOCK_DGRAM). */
    CHAOS_NET_ENDPOINT_UNIX          /**< UNIX-domain socket (AF_UNIX). */
} chaos_net_endpoint_kind_t;

/**
 * @brief A selector or a resolved endpoint, in one normalised form.
 *
 * @details Two producers:
 *   1. **Selector** (chaos_net_endpoint_parse_selector()): kind ANY (`*`), an IP kind with
 *      `wildcard_host` set (`tcp4://\*:80`), an IP kind with a concrete address, or UNIX
 *      with a path or `*`.
 *   2. **Runtime endpoint** (chaos_net_endpoint_from_sockaddr_fd(), _from_local_fd(),
 *      _from_peer_fd()): a concrete address; kind from sa_family plus SO_TYPE.
 *      chaos_net_endpoint_from_socket_spec() is the exception: it describes a socket
 *      that has no address yet (wildcard_host set and port 0, or UNIX path `*`).
 *
 * @par Field invariants:
 *   - ANY: every other field is zero.
 *   - TCP4/UDP4: `value.ipv4` in network byte order (as in sockaddr_in), `port` in host
 *     byte order.
 *   - TCP6/UDP6: `value.ipv6` and `port`; flow label and scope id are not kept.
 *   - UNIX: `value.text` is a NUL-terminated path. An abstract name is written with `@`
 *     for each NUL (as /proc/net/unix shows it); an unnamed socket has an empty path,
 *     which only the wildcards match.
 *   - `wildcard_host != 0`: only `kind` and `port` take part in matching.
 *   - `selector_len`: strlen of the selector text; breaks ties between rules of equal
 *     rank (longer = more specific). 0 for runtime endpoints.
 *
 * @par Ownership: by value, no heap; runtime endpoints live on the wrapper's stack.
 */
typedef struct chaos_net_endpoint
{
    chaos_net_endpoint_kind_t kind; /**< Address family + socket type discriminant. */
    size_t selector_len;            /**< Byte length of the original selector text; tie-breaker. */
    uint16_t port;                  /**< Port in host byte order; 0 for UNIX or ANY endpoints. */
    int wildcard_host;              /**< Non-zero if the host part is `*` (or no address yet). */
    /** @brief Address storage; the active member follows @c kind. */
    union
    {
        struct in_addr ipv4;           /**< IPv4 address; active when kind is TCP4 or UDP4. */
        struct in6_addr ipv6;          /**< IPv6 address; active when kind is TCP6 or UDP6. */
        char text[CHAOS_NET_MAX_TEXT]; /**< UNIX socket path; active when kind is UNIX. */
    } value;
} chaos_net_endpoint_t;

/**
 * @brief One rule as parsed from the rule file, plus its per-snapshot hit slot.
 *
 * @details Parameters by effect:
 *   - ERRNO: `errnum` and `probability`.
 *   - CORRUPT, TIMEOUT, DUP, RESET: `probability`.
 *   - LATENCY: `latency_ms`; `probability` is unused (0). The qualifiers still gate it.
 *   - TRICKLE: `chunk_bytes` (>= 1); `probability` is fixed at 1.0.
 *
 * Probabilities are sampled per call from the calling thread's PRNG. Wrappers copy the
 * rule out of the snapshot (seqlock-validated) and may set `call_size` on their copy.
 *
 * @par Ownership: by value; embedded in chaos_net_config_state_t.
 * @par Thread-safety: read-only once its snapshot is published.
 */
typedef struct chaos_net_rule
{
    chaos_net_endpoint_t selector;   /**< Endpoint pattern this rule applies to. */
    chaos_net_operation_t operation; /**< Which syscall group to intercept. */
    chaos_net_effect_t effect;       /**< Fault category to inject when triggered. */
    int errnum;                      /**< errno value for ERRNO rules; 0 for others. */
    double probability;              /**< Firing probability [0.0, 1.0]; unused for LATENCY. */
    unsigned int latency_ms;         /**< LATENCY: delay in ms, at most UINT32_MAX. */
    unsigned int chunk_bytes;        /**< TRICKLE: most bytes one receive call returns. */
    /** Qualifiers written after the rule (`@first`, `@from`, `@until`, `@size`). */
    chaos_rule_policy_t policy;
    /**
     * Byte count of the call this copy is being decided for, set by wrappers that
     * move data; CHAOS_POLICY_NO_SIZE otherwise, which no `@size` gate passes.
     */
    uint64_t call_size;
    /** Hit counter of this rule (see chaos_hits.h); NULL for a rule outside a snapshot. */
    chaos_hit_slot_t *hit;
    /** Generation of @c hit when the rule was published; a later one means the rule left. */
    uint64_t hit_generation;
} chaos_net_rule_t;

/**
 * @brief Resets the rule subsystem to "nothing loaded yet".
 *
 * @details Empties both snapshots (parse_ok = 1), sets the cached stamp to
 * CHAOS_NET_MTIME_UNKNOWN so the next chaos_net_config_prepare() loads, resets the hit
 * pool and the hits-file identity, registers the fork handler once, and resolves the
 * vDSO clock so that no wrapper (possibly in a signal handler) does it first.
 *
 * @par Thread-safety: none. Called from chaos_net_init() (the constructor) and from
 *      unit-test setup, before other threads use the library.
 */
void chaos_net_config_init(void);

/**
 * @brief Reloads the rule file if it changed; reports whether any rule is active.
 *
 * @details Protocol (chaos_net_config.c):
 *   1. Throttle: after the first load the file is looked at no more than once per
 *      CHAOS_CHECK_INTERVAL_NS (1 ms), timed with the vDSO clock; without a vDSO clock,
 *      on every call.
 *   2. stat(2) the file into a change stamp (mtime, size, inode, device). Equal to the
 *      cached stamp, and the last load not provisional: done.
 *   3. CAS the cached stamp to CHAOS_NET_MTIME_RELOADING. Losing threads use the active
 *      snapshot.
 *   4. Read and parse into the inactive snapshot, write the status file, publish.
 *
 * Failure behaviour (all fail-open: the call is never blocked or failed by this):
 *   - File missing: an empty snapshot is published, the status file is removed.
 *   - Invalid line, too many rules, NUL byte, file >= 256 KiB, EACCES/EPERM/EISDIR: a
 *     snapshot with no rules is published and the status file says why, until the file
 *     changes.
 *   - Any other open/read failure, or a writer changing the file during the read: the
 *     active snapshot stays and the next look retries.
 *
 * @return Non-zero if the active snapshot has at least one rule; 0 otherwise.
 * @par Thread-safety: any thread; one CAS serialises reload ownership, nobody waits.
 * @par Blocking: a reload issues stat, openat, read and close, and writes the status
 *      file; the throttled path issues no system call.
 * @par errno: preserved.
 */
int chaos_net_config_prepare(void);

/**
 * @brief Searches the currently active config snapshot for a rule matching the
 *        given (operation, endpoint) pair without triggering a reload.
 *
 * @details For callers that already ran chaos_net_config_prepare() in this call and match
 * several endpoints (each descriptor of a poll set, each message of a sendmmsg batch). A
 * copy torn by a concurrent reload of the same snapshot is detected by its sequence
 * (seqlock) and reported as no match. A snapshot with parse_ok == 0 never matches.
 *
 * @param operation The operation class of the intercepted syscall.
 * @param endpoint  Runtime endpoint resolved from the socket fd. Must not be NULL.
 * @param rule      Output: populated with the best-matching rule if one is found.
 *                  Caller-allocated; not NULL.
 * @return Non-zero if a matching rule was found and written to @p rule; 0 otherwise.
 * @pre chaos_net_config_prepare() must have been called in the same interposed
 *      call frame before invoking this function.
 * @par Thread-safety: reads the active snapshot index and its rules; safe as long
 *      as the reload protocol is respected (see chaos_net_config.c).
 */
int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
);

/**
 * @brief Whether a rule matches @p endpoint that no rule for @p operation could outrank on
 *        another endpoint.
 *
 * @details For the two ends of a connection, where @p endpoint is the end that wins ties.
 * When this returns non-zero, chaos_net_config_match_either_loaded() would pick the same
 * rule whatever the other end is, so the caller need not resolve the other end (two
 * system calls). It returns 0, and the caller searches both ends, when nothing matches or
 * some rule for @p operation has a higher rank (chaos_net_endpoint_selector_rank()) or the
 * same rank with a longer selector than the match.
 *
 * @param operation The operation class of the intercepted call.
 * @param endpoint  The end that wins ties. Must not be NULL.
 * @param rule      Output: the matching rule when non-zero is returned.
 * @return Non-zero with @p rule written when the match is final; 0 otherwise.
 * @pre chaos_net_config_prepare() ran in the same interposed call.
 */
int chaos_net_config_match_final_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
);

/**
 * @brief chaos_net_config_match_endpoint_loaded() for the two ends of a connection:
 *        the most specific rule for either end, @p first's on a tie.
 *
 * @details One search over both ends, so a wildcard rule for @p first does not shadow a
 * more specific rule for @p second.
 *
 * @param first   The end that wins ties; NULL when it could not be resolved.
 * @param second  The other end; NULL when it could not be resolved.
 * @return Non-zero with @p rule written when either end matched.
 */
int chaos_net_config_match_either_loaded(
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *first,
    const chaos_net_endpoint_t *second,
    chaos_net_rule_t *rule
);

/**
 * @brief Triggers a config reload if necessary, then searches for a matching rule.
 *
 * @details chaos_net_config_prepare() followed by chaos_net_config_match_endpoint_loaded(),
 * for wrappers that match exactly one endpoint (bind, connect, listen, accept, socket,
 * shutdown, sendto/sendmsg with a destination). Returns 0 without matching while no rule
 * is active.
 *
 * @param operation The operation class of the intercepted syscall.
 * @param endpoint  Runtime endpoint resolved from the socket fd. May be NULL (returns 0).
 * @param rule      Output: populated with the best-matching rule if one is found.
 *                  Caller-allocated; may be NULL (returns 0).
 * @return Non-zero if a matching rule was found and written to @p rule; 0 otherwise.
 * @par Thread-safety: see chaos_net_config_prepare() and chaos_net_config_match_endpoint_loaded().
 * @par Blocking: see chaos_net_config_prepare().
 */
int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
);

/**
 * @brief Parses one text line from the config file into a rule struct.
 *
 * @details The line format is:
 * @code
 *   <selector> : <operation> : <effect-or-errno-name> : <value>
 * @endcode
 * Parsing strategy:
 *   1. Strip trailing comment (everything from '#' onwards).
 *   2. Trim leading/trailing whitespace.
 *   3. Blank/comment-only lines return 0 (skip).
 *   4. Split on the last three ':' characters (right-to-left, so IPv6 addresses
 *      embedded in the selector are not split).
 *   5. Parse and validate each field in order.
 *
 * @param line  NUL-terminated line buffer. Modified in place (stripped / tokenised).
 *              Must not be NULL. The buffer must be writable.
 * @param rule  Output rule struct. Must not be NULL.
 * @return  1 if a valid rule was parsed and stored in @p rule.
 * @return  0 if the line is blank or a comment (skip; @p rule is unchanged).
 * @return -1 if the line is invalid (@p rule may be partly written); the caller rejects
 *            the whole file.
 * @par Thread-safety: operates on caller-supplied buffers only; safe.
 */
int chaos_net_config_parse_line(char *line, chaos_net_rule_t *rule);

/**
 * @brief Parses a NUL-terminated text buffer containing multiple config lines.
 *
 * @details Splits @p buffer on newlines in place. Per line: qualifiers are extracted
 * (chaos_policy_extract()), then chaos_net_config_parse_line() runs on the rest. The first
 * failure rejects the whole file (all-or-nothing) and records the line and the reason for
 * the status file (chaos_net_config_last_error()): INVALID (bad line, or qualifiers
 * without a rule), TOO_MANY (more than CHAOS_NET_MAX_RULES), UNSUPPORTED (a rule this
 * build cannot apply, see CHAOS_NET_RULE_SUPPORTED). Each accepted rule's text is kept
 * for the hits file.
 *
 * @param buffer      Writable NUL-terminated rule text; newlines become NULs.
 * @param rules       Output array with room for CHAOS_NET_MAX_RULES rules.
 * @param rule_count  Output: rules written; 0 on failure.
 * @return 0 on success; -1 on the first rejected line.
 * @par Thread-safety: writes the file-scope error record and text table; only the reload
 *      owner calls it.
 */
int chaos_net_config_parse_buffer(char *buffer, chaos_net_rule_t *rules, size_t *rule_count);

/**
 * @brief The line the last chaos_net_config_parse_buffer() call rejected.
 *
 * @return The rejected line (`reason != NULL`), or a cleared record when the last
 *         parse succeeded. Valid until the next parse.
 */
const chaos_status_error_t *chaos_net_config_last_error(void);

/**
 * @brief Scans an array of rules for the best match for the given (operation, endpoint).
 *
 * @details Considers every rule for @p operation; order in the file matters only for a
 * full tie. "Best" is:
 *   1. Highest rank (chaos_net_endpoint_matches()): 4 exact UNIX path, 3 exact IP and
 *      port, 2 wildcard host with port or UNIX `*`, 1 bare `*`.
 *   2. Then the longer selector text (selector_len).
 *   3. Then the earlier rule.
 *
 * @param rules       Array of parsed rules. Must not be NULL.
 * @param rule_count  Number of valid entries in @p rules.
 * @param operation   Operation to filter on; only rules with matching operation are considered.
 * @param endpoint    Runtime endpoint to match against. Must not be NULL.
 * @param rule        Output: populated with the winning rule. Must not be NULL.
 * @return Non-zero if at least one matching rule was found; 0 otherwise.
 * @par Thread-safety: read-only on @p rules; safe.
 */
int chaos_net_config_select_endpoint_rule(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule
);

/** @brief Most iovec entries the kernel accepts; a longer array fails with EINVAL. */
#ifdef IOV_MAX
#define CHAOS_NET_IOV_MAX IOV_MAX
#else
#define CHAOS_NET_IOV_MAX 1024
#endif

/**
 * @brief Byte count of an iovec array for `@size` gates; CHAOS_POLICY_NO_SIZE if invalid.
 *
 * @details An array longer than the kernel accepts is not read: the call fails
 * anyway, and its count need not describe memory the caller owns.
 */
static inline uint64_t chaos_net_iovec_size(const struct iovec *iov, int iovcnt)
{
    uint64_t total = 0U;
    int index;

    if (iov == NULL || iovcnt < 0 || iovcnt > CHAOS_NET_IOV_MAX)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    for (index = 0; index < iovcnt; ++index)
    {
        total += (uint64_t)iov[index].iov_len;
    }
    return total;
}

/** @brief Byte count of a message for `@size` gates; CHAOS_POLICY_NO_SIZE if unknown. */
static inline uint64_t chaos_net_message_size(const struct msghdr *message)
{
    /* msg_iovlen is size_t on glibc: compare before narrowing it. */
    if (message == NULL || (size_t)message->msg_iovlen > (size_t)CHAOS_NET_IOV_MAX)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    return chaos_net_iovec_size(message->msg_iov, (int)message->msg_iovlen);
}

/**
 * @brief The rule for @p operation on connected socket @p fd, matched on one end of
 *        the connection and, failing that, the other.
 *
 * @details A rule names an address: a client writes the server's (its peer), a
 * server its own (its local end), for receives and sends alike. The most specific
 * rule for either end wins, as among the rules for one end; on a tie, receives
 * take the local end's, sends the peer's (@p peer_first). Nothing is looked up
 * while there are no rules.
 *
 * Defined in chaos_net_socket.c, with the socket wrappers it serves.
 */
int chaos_net_match_connected(
    int fd, chaos_net_operation_t operation, int peer_first, chaos_net_rule_t *rule
);

#endif
