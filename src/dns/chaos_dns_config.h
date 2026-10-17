/**
 * @file chaos_dns_config.h
 * @brief Rule model, rule-file parser and snapshot matching API of libchaos-dns.
 *
 * @details
 * ### Rule grammar
 * One rule per line of `/tmp/.chaos-dns.conf`; `#` starts a comment; qualifiers
 * (`@first=N`, `@from=`, `@until=`, `@size`, see chaos_policy.h) are extracted first.
 * @code
 *   <selector> : <EAI-name | effect> : <value>
 * @endcode
 * Selectors:
 *   - `*` or `dns://\*` -- every forward lookup. A bare `*` must be followed directly by
 *     `:` (`*:EAI_AGAIN:0.5`); `* :` with a blank is rejected.
 *   - `dns://host` -- that name, ASCII case-insensitive.
 *   - `dns://\*.suffix` -- any name ending in `.suffix` (not `suffix` itself).
 *   - `rdns://\*`, `rdns://1.2.3.4`, `rdns://[::1]` -- reverse lookups of that address,
 *     compared in inet_ntop form.
 * Values by effect (`@p` is an optional probability, default 1.0):
 *   | Effect        | Value                         | Selector domains |
 *   |---------------|-------------------------------|------------------|
 *   | EAI_* name    | probability                   | dns, rdns        |
 *   | LATENCY       | `<ms>[@p]`                    | dns, rdns        |
 *   | REWRITE       | `<host name>[@p]`             | dns, rdns        |
 *   | SERVICE       | `<service>[@p]`               | dns, rdns        |
 *   | OVERRIDE      | `<ip>[,<ip>...][@p]` (max 32) | dns              |
 *   | FILTER_FAMILY | `inet4`, `inet6`, `ipv4`, `ipv6` or `any`, `[@p]` | dns |
 *   | LIMIT         | `<n >= 1>[@p]`                | dns              |
 *   | SHUFFLE       | probability                   | dns              |
 *
 * ### Reload
 * Two static snapshots and one CAS on the cached change stamp, as in libchaos-net:
 * chaos_dns_config_prepare() looks at the rule file at most once per
 * CHAOS_CHECK_INTERVAL_NS (1 ms, vDSO clock) after the first load; on a new stamp one
 * thread claims the reload, fills the inactive snapshot and publishes it; every other
 * thread keeps reading the active snapshot and never blocks.
 *
 * ### Selector precedence
 * Per effect, the most specific matching rule wins: EXACT (rank 3) over SUFFIX (2) over
 * ANY (1); on equal rank the longer selector text; on a full tie the earlier rule. Each
 * effect is matched separately, so one lookup can be shaped by several rules.
 *
 * ### Thread safety
 * - prepare and the match functions are safe from any thread; matching reads the
 *   active snapshot under its seqlock sequence.
 * - The parser writes a file-scope error record and text table; only the reload owner
 *   (or a single-threaded unit test) calls it.
 * - chaos_dns_config_init() runs in the constructor (or unit-test setup) only.
 *
 * @module  libchaos-dns configuration
 * @stability  Private
 */

#ifndef CHAOS_DNS_CONFIG_H
#define CHAOS_DNS_CONFIG_H

#include "chaos_dns_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

/* =========================================================================
 * Enumerations
 * ========================================================================= */

/**
 * @brief How a selector's text is compared with the queried name or address.
 *
 * | Kind    | Rank | Matches when                                            |
 * |---------|------|---------------------------------------------------------|
 * | ANY     |  1   | Always (text unused).                                   |
 * | SUFFIX  |  2   | The name ends in `.text`; the name `text` itself does not match. |
 * | EXACT   |  3   | The name equals text, ASCII case-insensitive.           |
 *
 * SUFFIX exists only for dns:// selectors; EXACT is a host name for dns:// and an
 * inet_ntop address for rdns://. INVALID marks a parse failure only.
 */
typedef enum chaos_dns_selector_kind
{
    CHAOS_DNS_SELECTOR_INVALID = -1, /**< Parse error sentinel; never stored in a live rule. */
    CHAOS_DNS_SELECTOR_ANY,          /**< Matches any query in the selector's domain. */
    CHAOS_DNS_SELECTOR_EXACT,        /**< Case-insensitive exact match against text. */
    CHAOS_DNS_SELECTOR_SUFFIX        /**< Dot-anchored suffix match (LOOKUP domain only). */
} chaos_dns_selector_kind_t;

/**
 * @brief Which call path a selector applies to.
 *
 * @details
 *   - **LOOKUP** -- forward lookups: getaddrinfo and the gethostbyname family. Written
 *     `dns://...` or bare `*`.
 *   - **REVERSE** -- reverse lookups: getnameinfo and the gethostbyaddr family. Written
 *     `rdns://...`.
 *
 * REVERSE selectors accept only GAI, LATENCY, REWRITE and SERVICE
 * (chaos_dns_effect_allowed()).
 */
typedef enum chaos_dns_selector_domain
{
    CHAOS_DNS_SELECTOR_DOMAIN_INVALID = -1, /**< Parse error sentinel. */
    CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP,       /**< Applies to getaddrinfo calls. */
    CHAOS_DNS_SELECTOR_DOMAIN_REVERSE       /**< Applies to getnameinfo calls. */
} chaos_dns_selector_domain_t;

/**
 * @brief What a rule does, grouped by when it acts.
 *
 * @details
 * **Before the resolver**
 *   - @c CHAOS_DNS_EFFECT_LATENCY -- sleep latency_ms, then continue.
 *   - @c CHAOS_DNS_EFFECT_GAI     -- return the EAI_* code (hostent APIs: the matching
 *     h_errno) without resolving.
 *
 * **Inputs and source of the answer**
 *   - @c CHAOS_DNS_EFFECT_REWRITE  -- getaddrinfo resolves `text` instead of the queried
 *     name; reverse lookups report `text` as the host name.
 *   - @c CHAOS_DNS_EFFECT_SERVICE  -- getaddrinfo uses `text` as the service; getnameinfo
 *     reports it as the service name.
 *   - @c CHAOS_DNS_EFFECT_OVERRIDE -- no resolver query: the answer is the IP literals in
 *     `text`, each expanded by the real getaddrinfo with AI_NUMERICHOST.
 *
 * **Result transforms**, in the fixed order FILTER_FAMILY, SHUFFLE, LIMIT: filtering
 * first means SHUFFLE and LIMIT act on the addresses that will be returned; shuffling
 * before limiting means LIMIT keeps a random subset, not the resolver's first entries.
 *   - @c CHAOS_DNS_EFFECT_FILTER_FAMILY -- drop addresses of the other family; none left
 *     is EAI_NONAME.
 *   - @c CHAOS_DNS_EFFECT_SHUFFLE       -- random order.
 *   - @c CHAOS_DNS_EFFECT_LIMIT         -- keep at most `limit` addresses.
 */
typedef enum chaos_dns_effect
{
    CHAOS_DNS_EFFECT_INVALID = -1,  /**< Parse error sentinel; never stored in a live rule. */
    CHAOS_DNS_EFFECT_GAI,           /**< Synthetic EAI_* failure before calling resolver. */
    CHAOS_DNS_EFFECT_LATENCY,       /**< Artificial sleep before calling resolver. */
    CHAOS_DNS_EFFECT_REWRITE,       /**< Substitute hostname in lookup or reverse result. */
    CHAOS_DNS_EFFECT_SERVICE,       /**< Substitute service/port string. */
    CHAOS_DNS_EFFECT_OVERRIDE,      /**< Replace result set with literal IP addresses. */
    CHAOS_DNS_EFFECT_FILTER_FAMILY, /**< Drop addrinfo nodes by address family. */
    CHAOS_DNS_EFFECT_LIMIT,         /**< Truncate addrinfo list to N entries. */
    CHAOS_DNS_EFFECT_SHUFFLE        /**< Fisher–Yates shuffle of addrinfo list. */
} chaos_dns_effect_t;

/**
 * @brief Family a FILTER_FAMILY rule keeps.
 *
 * @details Parsed from `inet4`/`ipv4`, `inet6`/`ipv6` and `any` (case-sensitive). A rule
 * with ANY parses but is skipped at lookup time without counting a hit.
 */
typedef enum chaos_dns_family_filter
{
    CHAOS_DNS_FAMILY_INVALID = -1, /**< Parse error sentinel; rule is rejected if set. */
    CHAOS_DNS_FAMILY_ANY,          /**< No filtering; all address families are kept. */
    CHAOS_DNS_FAMILY_INET4,        /**< Keep only AF_INET nodes; free all AF_INET6 nodes. */
    CHAOS_DNS_FAMILY_INET6         /**< Keep only AF_INET6 nodes; free all AF_INET nodes. */
} chaos_dns_family_filter_t;

/* =========================================================================
 * Structs
 * ========================================================================= */

/**
 * @brief The parsed selector of a rule; embedded by value in chaos_dns_rule_t.
 *
 * ### Field invariants
 * - `kind` and `domain` are valid members once parsed; INVALID values exist only on the
 *   failure path.
 * - `text` is NUL-terminated and non-empty for EXACT and SUFFIX, zero for ANY. It holds
 *   no `*`.
 * - SUFFIX: `text` without the leading `*.` (`example.com` for `dns://\*.example.com`).
 * - REVERSE EXACT: `text` in inet_ntop form, so `rdns://[0:0::1]` and a query for ::1
 *   compare equal.
 * - `selector_len` is strlen of the selector as written (`dns://\*.example.com`): the
 *   tie-breaker between equal ranks, longer winning.
 *
 * @threadsafety  Read-only once its snapshot is published.
 */
typedef struct chaos_dns_selector
{
    chaos_dns_selector_kind_t kind;     /**< Matching strategy (ANY, EXACT, SUFFIX). */
    chaos_dns_selector_domain_t domain; /**< Query domain this selector targets. */
    size_t selector_len;           /**< Length of original selector text; used as tiebreaker. */
    char text[CHAOS_DNS_MAX_TEXT]; /**< Normalised pattern text; NUL-terminated. */
} chaos_dns_selector_t;

/**
 * @brief One parsed rule, plus its per-snapshot hit slot.
 *
 * @details Fields by effect:
 *
 * | effect          | parameters                                      |
 * |-----------------|-------------------------------------------------|
 * | GAI             | gai_error, probability                          |
 * | LATENCY         | latency_ms, probability                         |
 * | REWRITE         | text (host name), probability                   |
 * | SERVICE         | text (service), probability                     |
 * | OVERRIDE        | text (comma-separated IP literals), probability |
 * | FILTER_FAMILY   | family, probability                             |
 * | LIMIT           | limit (>= 1), probability                       |
 * | SHUFFLE         | probability                                     |
 *
 * `probability` is in [0.0, 1.0]; effects with a `@p` suffix default to 1.0 without one.
 * Wrappers copy rules out of the snapshot and may set `call_size` on their copy.
 *
 * @threadsafety  Read-only once its snapshot is published; plain data, copied by value.
 */
typedef struct chaos_dns_rule
{
    chaos_dns_selector_t selector;    /**< Which queries this rule matches. */
    chaos_dns_effect_t effect;        /**< The fault category to apply. */
    int gai_error;                    /**< EAI_* code to return (GAI only). */
    double probability;               /**< Firing probability in [0.0, 1.0]. */
    unsigned int latency_ms;          /**< Delay in ms (LATENCY only), at most UINT32_MAX. */
    unsigned int limit;               /**< Most addresses kept, >= 1 (LIMIT only). */
    chaos_dns_family_filter_t family; /**< Family kept (FILTER_FAMILY only). */
    char text[CHAOS_DNS_MAX_VALUE];   /**< REWRITE/SERVICE/OVERRIDE value; NUL-terminated. */
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
} chaos_dns_rule_t;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/**
 * @brief Resets the rule subsystem to "nothing loaded yet".
 *
 * @details Empties both snapshots (parse_ok = 1), sets the cached stamp to
 * CHAOS_DNS_MTIME_UNKNOWN so the next chaos_dns_config_prepare() loads, resets the hit
 * pool and hits-file identity, registers the fork handler once, and resolves the vDSO
 * clock up front.
 *
 * @threadsafety  None: constructor (chaos_dns_init()) or unit-test setup only.
 */
void chaos_dns_config_init(void);

/**
 * @brief Reloads the rule file if it changed; reports whether any rule is active.
 *
 * @details
 *   1. Throttle: after the first load, at most one look per CHAOS_CHECK_INTERVAL_NS
 *      (1 ms, vDSO clock); without a vDSO clock, every call.
 *   2. stat(2) into a change stamp (mtime, size, inode, device). Unchanged, and the last
 *      load not provisional: done.
 *   3. CAS the cached stamp to CHAOS_DNS_MTIME_RELOADING; losers use the active snapshot.
 *   4. Read and parse into the inactive snapshot, write the status file, publish.
 *
 * Failure behaviour (fail-open throughout):
 *   - File missing: an empty snapshot is published and the status file removed.
 *   - Invalid line, too many rules, NUL byte, file >= 256 KiB, EACCES/EPERM/EISDIR: a
 *     snapshot with no rules is published and the status file says why, until the file
 *     changes. Stale rules are never kept.
 *   - Other open/read failures, or a writer changing the file during the read: the
 *     active snapshot stays and the next look retries.
 *
 * @return  Non-zero if the active snapshot has at least one rule; zero otherwise.
 *
 * @threadsafety  Any thread; one CAS serialises reload ownership, nobody waits. errno is
 *               preserved.
 */
int chaos_dns_config_prepare(void);

/**
 * @brief Best forward-lookup rule for @p effect and @p name in the active snapshot.
 *
 * @details Does not reload; for callers that already ran chaos_dns_config_prepare().
 * A copy torn by a concurrent reload of the same snapshot (seqlock) is reported as no
 * match, as is any match in a rejected snapshot (parse_ok == 0).
 *
 * @param effect  Effect to look for.
 * @param name    Queried host name, as the caller passed it.
 * @param rule    Output: the winning rule, copied by value.
 *
 * @return  Non-zero if a rule matched and @p rule is written; zero otherwise.
 *
 * @threadsafety  Any thread.
 */
int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
);

/**
 * @brief Best reverse-lookup rule for @p effect and @p address in the active snapshot.
 *
 * @details Reverse counterpart of chaos_dns_config_match_loaded(). @p address is the
 * inet_ntop text produced by chaos_dns_reverse_query_from_sockaddr() or
 * chaos_dns_reverse_query_from_address().
 *
 * @param effect   Effect to look for.
 * @param address  inet_ntop form of the address.
 * @param rule     Output: the winning rule.
 *
 * @return  Non-zero if a rule matched; zero otherwise.
 *
 * @threadsafety  Any thread.
 */
int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

/**
 * @brief chaos_dns_config_prepare(), then chaos_dns_config_match_loaded().
 *
 * @details Returns 0 without matching for a NULL or empty @p name, a NULL @p rule, or
 * while no rule is active.
 *
 * @param effect  Effect to look for.
 * @param name    Queried host name.
 * @param rule    Output: the winning rule.
 *
 * @return  Non-zero if a rule matched; zero otherwise.
 *
 * @threadsafety  Any thread.
 */
int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule);

/**
 * @brief chaos_dns_config_prepare(), then chaos_dns_config_match_reverse_loaded().
 *
 * @details Returns 0 without matching for a NULL or empty @p address, a NULL @p rule,
 * or while no rule is active.
 *
 * @param effect   Effect to look for.
 * @param address  inet_ntop form of the address.
 * @param rule     Output: the winning rule.
 *
 * @return  Non-zero if a rule matched; zero otherwise.
 *
 * @threadsafety  Any thread.
 */
int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

/**
 * @brief Parses one rule line (qualifiers already removed).
 *
 * @details @p line is modified in place (comment cut, fields split and trimmed).
 *
 * Return values:
 *   -  1  -- parsed; @p rule is written.
 *   -  0  -- blank or comment-only; @p rule is untouched.
 *   - -1  -- invalid (unknown selector or effect, effect not allowed for the selector
 *            domain, bad value); @p rule may be partly written. The caller rejects the
 *            whole file.
 *
 * @param line  Writable NUL-terminated line.
 * @param rule  Output.
 *
 * @return  1, 0 or -1 as above.
 *
 * @threadsafety  Caller-supplied buffers only.
 */
int chaos_dns_config_parse_line(char *line, chaos_dns_rule_t *rule);

/**
 * @brief Parses a whole rule file; all or nothing.
 *
 * @details Splits @p buffer on newlines in place; per line, qualifiers are extracted
 * (chaos_policy_extract()) and chaos_dns_config_parse_line() parses the rest. The first
 * failure rejects the file and records the line and the reason for the status file
 * (chaos_dns_config_last_error()): INVALID (bad line, or qualifiers without a rule) or
 * TOO_MANY (more than CHAOS_DNS_MAX_RULES). Each accepted rule's text is kept for the
 * hits file.
 *
 * @param buffer      Writable NUL-terminated rule text.
 * @param rules       Output array with room for CHAOS_DNS_MAX_RULES rules.
 * @param rule_count  Output: rules written; 0 on failure.
 *
 * @return  0 on success; -1 on the first rejected line.
 *
 * @threadsafety  Writes file-scope state; reload owner only.
 */
int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count);

/**
 * @brief The line the last chaos_dns_config_parse_buffer() call rejected.
 *
 * @return The rejected line (`reason != NULL`), or a cleared record when the last
 *         parse succeeded. Valid until the next parse.
 */
const chaos_status_error_t *chaos_dns_config_last_error(void);

/**
 * @brief Best forward-lookup rule in an explicit rule array.
 *
 * @details Precedence: rank (EXACT 3, SUFFIX 2, ANY 1), then longer selector text, then
 * the earlier rule. Used by chaos_dns_config_match_loaded() and by unit tests.
 *
 * @param rules       Rule array.
 * @param rule_count  Valid entries in @p rules.
 * @param effect      Effect to match.
 * @param name        Queried host name.
 * @param rule        Output: the winning rule.
 *
 * @return  Non-zero if a rule matched; zero otherwise.
 *
 * @threadsafety  Read-only on @p rules.
 */
int chaos_dns_config_select_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *name,
    chaos_dns_rule_t *rule
);

/**
 * @brief Best reverse-lookup rule in an explicit rule array.
 *
 * @details Reverse counterpart of chaos_dns_config_select_rule().
 *
 * @param rules       Rule array.
 * @param rule_count  Valid entries in @p rules.
 * @param effect      Effect to match.
 * @param address     inet_ntop form of the address.
 * @param rule        Output: the winning rule.
 *
 * @return  Non-zero if a rule matched; zero otherwise.
 *
 * @threadsafety  Read-only on @p rules.
 */
int chaos_dns_config_select_reverse_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *address,
    chaos_dns_rule_t *rule
);

#endif
