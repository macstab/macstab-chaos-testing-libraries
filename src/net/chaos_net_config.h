/**
 * @file chaos_net_config.h
 * @brief Configuration data model, parser interface, and live-reload API for libchaos-net.
 *
 * @details
 * Declares the three core domain types:
 *   - chaos_net_operation_t   — which socket syscall a rule targets.
 *   - chaos_net_effect_t      — which fault category a rule injects.
 *   - chaos_net_endpoint_t    — a normalised, parsed representation of an endpoint selector.
 *   - chaos_net_rule_t        — one complete fault-injection rule (selector + op + effect + param).
 *
 * Config file format (one rule per line):
 * @code
 *   <selector> : <operation> : <effect-or-errno> : <value>
 * @endcode
 * Examples:
 * @code
 *   tcp4://127.0.0.1:8080 : connect : ECONNREFUSED : 0.5
 *   tcp4://\*:443           : recv    : LATENCY       : 200
 *   *                      : send    : CORRUPT        : 0.1
 *   tcp4://\*:0             : poll    : TIMEOUT        : 0.3
 * @endcode
 *
 * The reload mechanism is a two-snapshot copy-on-write scheme protected by a
 * single CAS on g_chaos_net_cached_mtime. At most one thread reloads at a time;
 * other threads continue using the previous active snapshot.
 *
 * @par Stability: private / internal
 * @par Module: chaos-net
 */

#ifndef CHAOS_NET_CONFIG_H
#define CHAOS_NET_CONFIG_H

#include "chaos_net_internal.h"

#include <netinet/in.h>

/**
 * @brief Identifies which socket lifecycle operation a rule targets.
 *
 * @details The set of operations maps directly to intercepted syscalls:
 *   - BIND, LISTEN, CONNECT, ACCEPT: connection-lifecycle calls; endpoint
 *     derived from the sockaddr argument (BIND/CONNECT) or the listening
 *     socket's local address (LISTEN/ACCEPT).
 *   - SOCKET: creation call; endpoint derived from (domain, type) only —
 *     there is no address yet, so selectors must use wildcard forms.
 *   - SHUTDOWN: teardown; endpoint resolved via getpeername/getsockname.
 *   - POLL: covers poll, ppoll, select, pselect, epoll_wait, epoll_pwait.
 *   - SEND: covers send, sendto, sendmsg, sendmmsg.
 *   - RECV: covers recv, recvfrom, recvmsg, recvmmsg.
 *
 * CHAOS_NET_OP_INVALID (-1) is the sentinel returned on parse failure.
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
    CHAOS_NET_OP_SEND,         /**< Targets send/sendto/sendmsg/sendmmsg. */
    CHAOS_NET_OP_RECV          /**< Targets recv/recvfrom/recvmsg/recvmmsg. */
} chaos_net_operation_t;

/**
 * @brief Identifies which fault category a matched rule injects.
 *
 * @details Effect semantics:
 *   - ERRNO:   The interposed function returns -1 with errno set before the
 *              real syscall is made. The real call is skipped entirely.
 *   - LATENCY: usleep() is called for rule->latency_ms milliseconds before
 *              the real call. The real call always executes afterwards.
 *   - CORRUPT: After the real call completes and returns bytes > 0, a single
 *              bit in the receive buffer is flipped. Only valid for RECV ops.
 *   - TIMEOUT: For POLL ops, all revents/fd_set bits are cleared and 0 is
 *              returned, simulating a timed-out wait with no ready fds.
 *              The real poll call is skipped.
 *
 * Effect / operation validity is enforced at parse time by chaos_net_effect_allowed().
 * CHAOS_NET_EFFECT_INVALID (-1) is the sentinel for parse failures.
 */
typedef enum chaos_net_effect
{
    CHAOS_NET_EFFECT_INVALID = -1, /**< Parse failure or unrecognised token. */
    CHAOS_NET_EFFECT_ERRNO,        /**< Pre-call: set errno and return -1. */
    CHAOS_NET_EFFECT_LATENCY,      /**< Pre-call: sleep for latency_ms milliseconds. */
    CHAOS_NET_EFFECT_CORRUPT,      /**< Post-call: flip one bit in the receive buffer. */
    CHAOS_NET_EFFECT_TIMEOUT       /**< POLL-only: return 0 with all events cleared. */
} chaos_net_effect_t;

/**
 * @brief Address-family / transport-protocol combination for an endpoint.
 *
 * @details Used in both selectors (from the config file) and normalised runtime
 * endpoints (derived from sockaddr structs or socket parameters).
 *
 * The kind doubles as a combined "protocol family + socket type" discriminant
 * because the config file syntax encodes both (tcp4, udp6, etc.) and the matching
 * logic requires an exact kind match (a tcp4 selector never matches a udp4 endpoint).
 *
 * CHAOS_NET_ENDPOINT_ANY (0) is a wildcard that matches any kind; it is produced by
 * the "*" config selector.
 * CHAOS_NET_ENDPOINT_INVALID (-1) is the parse-failure sentinel.
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
 * @brief Normalised representation of a network endpoint or endpoint selector.
 *
 * @details Used for two distinct purposes:
 *
 *   1. **Config selector** (populated by chaos_net_endpoint_parse_selector()):
 *      Represents a pattern specified in the config file. May be fully wildcarded
 *      (kind == ANY), family-and-port wildcarded (wildcard_host != 0), or fully
 *      specific (wildcard_host == 0, address bytes populated).
 *
 *   2. **Runtime endpoint** (populated by chaos_net_endpoint_from_sockaddr_fd()
 *      or chaos_net_endpoint_from_local_fd() / chaos_net_endpoint_from_peer_fd()):
 *      Always a concrete address. wildcard_host is 0 for runtime endpoints.
 *      The kind is determined by querying SO_TYPE via getsockopt on the socket fd.
 *
 * @par Field invariants:
 *   - `kind == CHAOS_NET_ENDPOINT_ANY`: all other fields are zero/ignored.
 *   - `kind == TCP4 / UDP4`: `value.ipv4` and `port` hold the parsed address in
 *     host byte order. `value.ipv6` and `value.text` are zero.
 *   - `kind == TCP6 / UDP6`: `value.ipv6` and `port` hold the address.
 *   - `kind == UNIX`: `value.text` holds the sun_path NUL-terminated string.
 *     `port` and address union members other than text are zero.
 *   - For selectors: `wildcard_host != 0` means the host portion is "*" and only
 *     `port` and `kind` are significant in comparisons.
 *   - `selector_len`: set by the parser to the length of the original text
 *     representation; used as a tie-breaker when two matching rules have equal
 *     specificity rank (longer text = more specific).
 *
 * @par Ownership: always by value; no heap allocation.
 * @par Thread-safety: endpoints are stack-allocated per interposed call; no sharing.
 */
typedef struct chaos_net_endpoint
{
    chaos_net_endpoint_kind_t kind; /**< Address family + socket type discriminant. */
    size_t selector_len;            /**< Byte length of the original selector text; tie-breaker. */
    uint16_t port;                  /**< Port in host byte order; 0 for UNIX or ANY endpoints. */
    int wildcard_host;              /**< Non-zero if the host part of the selector is "*". */
    /** @brief Address storage; active member determined by @c kind. */
    union
    {
        struct in_addr ipv4;           /**< IPv4 address; active when kind is TCP4 or UDP4. */
        struct in6_addr ipv6;          /**< IPv6 address; active when kind is TCP6 or UDP6. */
        char text[CHAOS_NET_MAX_TEXT]; /**< UNIX socket path; active when kind is UNIX. */
    } value;
} chaos_net_endpoint_t;

/**
 * @brief One complete fault-injection rule as loaded from the config file.
 *
 * @details A rule consists of:
 *   - A selector endpoint describing which connections to match.
 *   - An operation identifying the syscall group to intercept.
 *   - An effect type controlling how the fault is expressed.
 *   - Effect-specific parameters: either `errnum` (for ERRNO) or
 *     `probability` (for ERRNO, CORRUPT, TIMEOUT) or `latency_ms` (for LATENCY).
 *
 * @par Field semantics:
 *   - `probability`: in [0.0, 1.0]. For LATENCY rules it is unused (latency
 *     is always applied). For ERRNO/CORRUPT/TIMEOUT it is the per-call firing
 *     probability sampled via the PRNG.
 *   - `errnum`: the errno value to inject; only valid when effect == ERRNO.
 *   - `latency_ms`: sleep duration in milliseconds; only valid when effect == LATENCY.
 *
 * @par Ownership: always by value; embedded in chaos_net_config_state_t arrays.
 * @par Thread-safety: rules are read-only once the snapshot is published.
 */
typedef struct chaos_net_rule
{
    chaos_net_endpoint_t selector;   /**< Endpoint pattern this rule applies to. */
    chaos_net_operation_t operation; /**< Which syscall group to intercept. */
    chaos_net_effect_t effect;       /**< Fault category to inject when triggered. */
    int errnum;                      /**< errno value for ERRNO rules; 0 for others. */
    double probability;              /**< Firing probability [0.0, 1.0]; unused for LATENCY. */
    unsigned int latency_ms;         /**< Sleep time in ms for LATENCY rules; 0 for others. */
} chaos_net_rule_t;

/**
 * @brief Initialises the config subsystem to a clean, empty state.
 *
 * @details Zeroes both config snapshots and sets the cached mtime to
 * CHAOS_NET_MTIME_UNKNOWN, which guarantees the next call to
 * chaos_net_config_prepare() will perform a real stat and reload attempt.
 * Called exactly once from chaos_net_init() during library construction.
 *
 * @pre Must be called before any interposed socket symbol is invoked.
 * @par Thread-safety: not thread-safe; must be called from the constructor,
 *      which runs before any application threads are started.
 */
void chaos_net_config_init(void);

/**
 * @brief Checks whether the config file has changed and reloads it if necessary.
 *
 * @details Implements the two-snapshot CAS reload protocol:
 *   1. stat(CHAOS_NET_CONFIG_PATH) to obtain the current mtime hash.
 *   2. Compare against the cached mtime. If equal, return immediately.
 *   3. Attempt to claim the reload lock via CAS(cached, observed, RELOADING).
 *      If the CAS fails, another thread is reloading; skip and use the current
 *      active snapshot.
 *   4. Parse the file into the inactive snapshot.
 *   5. Publish by writing the new active index then the new mtime (two sequential
 *      full memory barriers).
 *
 * The function is fail-open: if stat, open, read, or parse fails, the inactive
 * snapshot is marked parse_ok=0 and published. Subsequent calls to
 * chaos_net_config_match_endpoint() check parse_ok and return 0 (no match)
 * when the config is invalid, so all syscalls pass through without injection.
 *
 * @return Non-zero if the active snapshot has at least one rule; 0 otherwise.
 * @par Thread-safety: safe; uses atomic CAS to serialise reload ownership.
 * @par Blocking: calls stat(2), open(2), read(2) — may block on I/O.
 * @note errno is not preserved; callers must save/restore if needed.
 */
int chaos_net_config_prepare(void);

/**
 * @brief Searches the currently active config snapshot for a rule matching the
 *        given (operation, endpoint) pair without triggering a reload.
 *
 * @details Used by the wait subsystem (chaos_net_wait.c) when it has already
 * called chaos_net_config_prepare() at the top of the interposed function and
 * needs to perform per-fd matching without re-checking the mtime on each fd.
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
 * @brief Triggers a config reload if necessary, then searches for a matching rule.
 *
 * @details Convenience wrapper: calls chaos_net_config_prepare() first, then
 * chaos_net_config_match_endpoint_loaded(). Used by all interposed symbols except
 * the wait family (which needs the two-phase approach to amortise the stat cost
 * across multiple fds).
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
 * @return -1 if the line is syntactically or semantically invalid (entire buffer
 *            should be rejected).
 * @par Thread-safety: operates on caller-supplied buffers only; safe.
 */
int chaos_net_config_parse_line(char *line, chaos_net_rule_t *rule);

/**
 * @brief Parses a NUL-terminated text buffer containing multiple config lines.
 *
 * @details Splits @p buffer on newlines in place and calls
 * chaos_net_config_parse_line() on each segment. Parsing stops and returns -1
 * on the first invalid line, enforcing all-or-nothing config validity: a file
 * with any bad line is rejected in full.
 *
 * @param buffer      Writable NUL-terminated buffer of config text. Modified in
 *                    place (newlines replaced with NULs).
 * @param rules       Output array of rules. Must have capacity >= CHAOS_NET_MAX_RULES.
 * @param rule_count  Output: number of valid rules written to @p rules.
 * @return  0 on success; -1 if any line is invalid or the rule count exceeds
 *          CHAOS_NET_MAX_RULES.
 * @par Thread-safety: operates on caller-supplied buffers only; safe.
 */
int chaos_net_config_parse_buffer(char *buffer, chaos_net_rule_t *rules, size_t *rule_count);

/**
 * @brief Scans an array of rules for the best match for the given (operation, endpoint).
 *
 * @details Iterates all rules, calling chaos_net_endpoint_matches() on each.
 * "Best" is defined as:
 *   1. Highest match rank (more specific selector type wins):
 *      rank 4 = exact UNIX path, rank 3 = exact IP+port, rank 2 = wildcard host,
 *      rank 1 = ANY wildcard.
 *   2. Among equal-rank matches, the rule with the longer selector text string
 *      (selector_len) wins, providing a deterministic tie-breaker.
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

#endif
