/**
 * @file chaos_dns_config.h
 * @brief Configuration types, parsing API, and rule-matching interface.
 *
 * @details
 * This header defines the complete data model for libchaos-dns fault rules
 * and exposes the functions that load, parse, and query those rules.
 *
 * ### Data model overview
 *
 * Each line in `/tmp/.chaos-dns.conf` maps to a `chaos_dns_rule_t`.  A rule
 * has three logical parts:
 *
 *   - A **selector** (`chaos_dns_selector_t`) — identifies which DNS queries
 *     the rule applies to.  The selector has both a *domain* (forward lookup
 *     vs reverse lookup) and a *kind* (any-wildcard, exact hostname/IP, or
 *     suffix pattern).
 *
 *   - An **effect** (`chaos_dns_effect_t`) — the category of fault or
 *     transform to apply.
 *
 *   - **Effect parameters** — fields inside `chaos_dns_rule_t` whose
 *     interpretation depends on the effect: `gai_error`, `probability`,
 *     `latency_ms`, `limit`, `family`, and `text`.
 *
 * ### Config reload protocol
 * Rules are held in a pair of static snapshots (`g_chaos_dns_config_states[2]`).
 * The active snapshot index is stored in `g_chaos_dns_active_config_index`.
 * On every lookup call, chaos_dns_config_prepare() compares the file's mtime
 * hash against a cached value; if they differ and a CAS succeeds, the calling
 * thread reloads the inactive snapshot and publishes it with a full memory
 * fence.  All other concurrent threads continue reading the previously active
 * snapshot throughout the reload.  This is the two-snapshot CAS protocol.
 *
 * ### Selector precedence
 * When multiple rules match the same query and effect, the most specific
 * selector wins:
 *   - EXACT (rank 3) > SUFFIX (rank 2) > ANY (rank 1)
 *   - Among equal ranks, the selector with the longer text wins.
 *
 * ### Thread safety
 * - chaos_dns_config_prepare(), chaos_dns_config_match(), and
 *   chaos_dns_config_match_reverse() are safe to call concurrently from
 *   multiple threads.  They use the CAS protocol for reload serialisation and
 *   read-only access to the active snapshot.
 * - chaos_dns_config_parse_line() and chaos_dns_config_parse_buffer() operate
 *   on caller-supplied buffers and have no shared state; they are safe to call
 *   from any thread.
 * - chaos_dns_config_init() is called exactly once from the library constructor
 *   and must not be called again after init completes.
 *
 * @module  libchaos-dns configuration
 * @stability  Private
 */

#ifndef CHAOS_DNS_CONFIG_H
#define CHAOS_DNS_CONFIG_H

#include "chaos_dns_internal.h"

/* =========================================================================
 * Enumerations
 * ========================================================================= */

/**
 * @brief Discriminates the matching strategy used by a selector's text field.
 *
 * @details The kind controls how `chaos_dns_selector_t::text` is compared
 * against an incoming hostname or IP-address string.
 *
 * | Kind    | Rank | Matches when …                                          |
 * |---------|------|---------------------------------------------------------|
 * | ANY     |  1   | Unconditionally (text field is unused).                 |
 * | SUFFIX  |  2   | Hostname ends with `.text` (dot-delimited label check). |
 * | EXACT   |  3   | Hostname equals text exactly (case-insensitive ASCII).  |
 *
 * SUFFIX is only meaningful for the LOOKUP domain; EXACT is used for both
 * LOOKUP (hostname) and REVERSE (normalised IP string) selectors.
 *
 * INVALID is not stored in live rules; it marks parse failure.
 */
typedef enum chaos_dns_selector_kind
{
    CHAOS_DNS_SELECTOR_INVALID = -1, /**< Parse error sentinel; never stored in a live rule. */
    CHAOS_DNS_SELECTOR_ANY     =  0, /**< Matches any query in the selector's domain. */
    CHAOS_DNS_SELECTOR_EXACT,        /**< Case-insensitive exact match against text. */
    CHAOS_DNS_SELECTOR_SUFFIX        /**< Dot-anchored suffix match (LOOKUP domain only). */
} chaos_dns_selector_kind_t;

/**
 * @brief Discriminates the call path a selector applies to.
 *
 * @details
 *   - **LOOKUP** — forward lookups via `getaddrinfo(3)`.  Selected by the
 *     `dns://` URI prefix or the bare `*` wildcard.
 *   - **REVERSE** — reverse lookups via `getnameinfo(3)`.  Selected by the
 *     `rdns://` URI prefix.
 *
 * Only a subset of effects is permitted on REVERSE selectors; see
 * chaos_dns_effect_allowed() in chaos_dns_config.c.
 */
typedef enum chaos_dns_selector_domain
{
    CHAOS_DNS_SELECTOR_DOMAIN_INVALID = -1, /**< Parse error sentinel. */
    CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP  =  0, /**< Applies to getaddrinfo calls. */
    CHAOS_DNS_SELECTOR_DOMAIN_REVERSE        /**< Applies to getnameinfo calls. */
} chaos_dns_selector_domain_t;

/**
 * @brief Identifies the class of fault or transform a rule applies.
 *
 * @details Effects fall into two execution phases:
 *
 * **Pre-call (intercept before real resolver)**
 *   - @c CHAOS_DNS_EFFECT_GAI     — return a synthetic EAI_* error immediately.
 *   - @c CHAOS_DNS_EFFECT_LATENCY — sleep for `latency_ms` milliseconds, then
 *     continue to the real resolver.
 *
 * **Name/service rewrite (substitute inputs to the real resolver)**
 *   - @c CHAOS_DNS_EFFECT_REWRITE  — replace the hostname passed to getaddrinfo
 *     or the hostname written back by getnameinfo.
 *   - @c CHAOS_DNS_EFFECT_SERVICE  — replace the service/port string.
 *   - @c CHAOS_DNS_EFFECT_OVERRIDE — skip the real resolver entirely; call the
 *     real getaddrinfo with each IP address literal in `rule->text`.
 *
 * **Post-call result-set transforms (mutate the addrinfo list in place)**
 *   Applied in fixed order: FILTER_FAMILY → SHUFFLE → LIMIT.  Order matters
 *   because: (1) filtering first reduces the set SHUFFLE and LIMIT operate on,
 *   making LIMIT semantics deterministic after family filtering; (2) shuffling
 *   before limiting means the limit selects from the randomised order, not the
 *   OS-determined order.
 *
 *   - @c CHAOS_DNS_EFFECT_FILTER_FAMILY — drop all nodes not matching the
 *     configured address family.
 *   - @c CHAOS_DNS_EFFECT_SHUFFLE       — randomise the node order in place.
 *   - @c CHAOS_DNS_EFFECT_LIMIT         — truncate the list to at most N nodes.
 */
typedef enum chaos_dns_effect
{
    CHAOS_DNS_EFFECT_INVALID       = -1, /**< Parse error sentinel; never stored in a live rule. */
    CHAOS_DNS_EFFECT_GAI           =  0, /**< Synthetic EAI_* failure before calling resolver. */
    CHAOS_DNS_EFFECT_LATENCY,            /**< Artificial sleep before calling resolver. */
    CHAOS_DNS_EFFECT_REWRITE,            /**< Substitute hostname in lookup or reverse result. */
    CHAOS_DNS_EFFECT_SERVICE,            /**< Substitute service/port string. */
    CHAOS_DNS_EFFECT_OVERRIDE,           /**< Replace result set with literal IP addresses. */
    CHAOS_DNS_EFFECT_FILTER_FAMILY,      /**< Drop addrinfo nodes by address family. */
    CHAOS_DNS_EFFECT_LIMIT,              /**< Truncate addrinfo list to N entries. */
    CHAOS_DNS_EFFECT_SHUFFLE             /**< Fisher–Yates shuffle of addrinfo list. */
} chaos_dns_effect_t;

/**
 * @brief Address-family filter specifier for FILTER_FAMILY rules.
 *
 * @details Parsed from the string tokens `inet4`/`ipv4`, `inet6`/`ipv6`, and
 * `any`.  The value @c ANY is stored in parsed rules but causes the filter to
 * be a no-op (chaos_dns_filter_result_list returns immediately).
 */
typedef enum chaos_dns_family_filter
{
    CHAOS_DNS_FAMILY_INVALID = -1, /**< Parse error sentinel; rule is rejected if set. */
    CHAOS_DNS_FAMILY_ANY     =  0, /**< No filtering; all address families are kept. */
    CHAOS_DNS_FAMILY_INET4,        /**< Keep only AF_INET nodes; free all AF_INET6 nodes. */
    CHAOS_DNS_FAMILY_INET6         /**< Keep only AF_INET6 nodes; free all AF_INET nodes. */
} chaos_dns_family_filter_t;

/* =========================================================================
 * Structs
 * ========================================================================= */

/**
 * @brief Parsed representation of the selector portion of a config rule.
 *
 * @details A selector binds a rule to a specific query domain and pattern.
 * It is embedded by value in @ref chaos_dns_rule_t and has the same lifetime.
 *
 * ### Field invariants
 * - `kind` and `domain` are always valid enum members when the selector has
 *   been successfully parsed; INVALID values are only present transiently
 *   during error handling.
 * - `text` is NUL-terminated and non-empty for EXACT and SUFFIX kinds;
 *   zero-initialised for ANY.
 * - `selector_len` is the length of the original selector string as written
 *   in the config file (e.g., `strlen("dns://\*.example.com")`).  It is used
 *   as a tiebreaker when two selectors have equal rank: the longer selector
 *   is considered more specific.
 * - For SUFFIX selectors, `text` holds the suffix *without* the leading `*.`
 *   (e.g., `"example.com"` for `dns://\*.example.com`).
 * - For REVERSE/EXACT selectors, `text` holds the normalised IP string as
 *   returned by inet_ntop(3) so that `1.2.3.004` and `1.2.3.4` compare equal.
 *
 * @threadsafety  Read-only after construction; safe to read from multiple threads.
 */
typedef struct chaos_dns_selector
{
    chaos_dns_selector_kind_t   kind;         /**< Matching strategy (ANY, EXACT, SUFFIX). */
    chaos_dns_selector_domain_t domain;       /**< Query domain this selector targets. */
    size_t                      selector_len; /**< Length of original selector text; used as tiebreaker. */
    char                        text[CHAOS_DNS_MAX_TEXT]; /**< Normalised pattern text; NUL-terminated. */
} chaos_dns_selector_t;

/**
 * @brief A fully parsed chaos rule ready for matching and application.
 *
 * @details One `chaos_dns_rule_t` corresponds to one non-blank, non-comment
 * line in the config file.  Rules are stored in
 * `chaos_dns_config_state_t::rules[]` and are never modified after parsing.
 *
 * Which fields are meaningful depends on `effect`:
 *
 * | effect          | meaningful additional fields               |
 * |-----------------|--------------------------------------------|
 * | GAI             | gai_error, probability                     |
 * | LATENCY         | latency_ms, probability                    |
 * | REWRITE         | text (target hostname), probability        |
 * | SERVICE         | text (target service string), probability  |
 * | OVERRIDE        | text (comma-separated IP literals), probability |
 * | FILTER_FAMILY   | family, probability                        |
 * | LIMIT           | limit (>0), probability                    |
 * | SHUFFLE         | probability                                |
 *
 * The `probability` field is always present (range [0.0, 1.0]).  A value of
 * 1.0 means the rule always triggers; 0.0 means it never triggers.
 *
 * @threadsafety  Read-only after construction; safe to copy by value (all
 *               fields are POD types).
 */
typedef struct chaos_dns_rule
{
    chaos_dns_selector_t    selector;    /**< Which queries this rule matches. */
    chaos_dns_effect_t      effect;      /**< The fault category to apply. */
    int                     gai_error;   /**< EAI_* code to return (GAI effect only). */
    double                  probability; /**< Trigger probability in [0.0, 1.0]. */
    unsigned int            latency_ms;  /**< Sleep duration in milliseconds (LATENCY only). */
    unsigned int            limit;       /**< Maximum result list length, ≥1 (LIMIT only). */
    chaos_dns_family_filter_t family;    /**< Address family to retain (FILTER_FAMILY only). */
    char                    text[CHAOS_DNS_MAX_VALUE]; /**< NUL-terminated value for REWRITE/SERVICE/OVERRIDE. */
} chaos_dns_rule_t;

/* =========================================================================
 * Function declarations
 * ========================================================================= */

/**
 * @brief Initialise the config subsystem to a clean, empty state.
 *
 * @details Zero-initialises both config snapshots, resets the active index to
 * 0, and sets the cached mtime to CHAOS_DNS_MTIME_UNKNOWN so that the first
 * call to chaos_dns_config_prepare() will always perform a stat(2) and
 * attempt a load.
 *
 * Called exactly once from the library constructor (chaos_dns_init).  Must
 * not be called again after initialisation is complete.
 *
 * @threadsafety  Not safe to call concurrently; single-threaded constructor only.
 */
void chaos_dns_config_init(void);

/**
 * @brief Check for config file changes and reload if the mtime hash differs.
 *
 * @details Implements the two-snapshot CAS reload protocol:
 *   1. Stat the config file and hash its mtime.
 *   2. If the hash matches the cached value, return immediately (fast path).
 *   3. Attempt to CAS the cached mtime from its current value to
 *      CHAOS_DNS_MTIME_RELOADING.  Only one thread wins; all others fall
 *      through to the still-active snapshot.
 *   4. The winning thread reads and parses the file into the inactive
 *      snapshot, then calls chaos_dns_config_publish() to swap the active
 *      index and update the cached mtime under full memory fences.
 *
 * On parse failure the inactive snapshot is reset to an empty-but-valid state
 * so that subsequent lookups fail-open (no rules active) rather than
 * continuing to use stale rules.
 *
 * @return  Non-zero if the active config has at least one rule; zero otherwise.
 *
 * @threadsafety  Safe to call concurrently from multiple threads.
 */
int chaos_dns_config_prepare(void);

/**
 * @brief Match a forward-lookup name against the currently active rule set.
 *
 * @details Queries the active config snapshot without triggering a reload.
 * Intended for use after chaos_dns_config_prepare() has been called.
 *
 * @param effect  The effect category to search for.
 * @param name    Hostname to match (NUL-terminated, non-empty).
 * @param rule    Output buffer for the matched rule (copied by value).
 *
 * @return  Non-zero if a matching rule was found and @p rule is populated.
 * @return  Zero if the active config failed to parse, or if no rule matches.
 *
 * @pre   chaos_dns_config_prepare() or chaos_dns_config_init() has been called.
 * @threadsafety  Safe — reads only the active snapshot (read-only after publish).
 */
int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
);

/**
 * @brief Match a reverse-lookup IP address string against the currently active rule set.
 *
 * @details Reverse-lookup counterpart to chaos_dns_config_match_loaded().
 * The @p address parameter must be a normalised IP string as produced by
 * chaos_dns_reverse_query_from_sockaddr() (i.e., the output of inet_ntop).
 *
 * @param effect   The effect category to search for.
 * @param address  Normalised IP address string (NUL-terminated, non-empty).
 * @param rule     Output buffer for the matched rule.
 *
 * @return  Non-zero if a matching rule was found; zero otherwise.
 *
 * @threadsafety  Safe — reads only the active snapshot.
 */
int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

/**
 * @brief Prepare config if needed, then match a forward-lookup hostname.
 *
 * @details Combines chaos_dns_config_prepare() and
 * chaos_dns_config_match_loaded() for the common case.  Returns zero
 * immediately if @p name is NULL or empty, @p rule is NULL, or the config has
 * no rules.
 *
 * @param effect  Effect category to search for.
 * @param name    Hostname to match.
 * @param rule    Output buffer for the matched rule.
 *
 * @return  Non-zero if a matching rule was found; zero otherwise.
 *
 * @threadsafety  Safe to call concurrently.
 */
int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule);

/**
 * @brief Prepare config if needed, then match a reverse-lookup IP address.
 *
 * @details Combines chaos_dns_config_prepare() and
 * chaos_dns_config_match_reverse_loaded() for the common case.
 *
 * @param effect   Effect category to search for.
 * @param address  Normalised IP address string to match.
 * @param rule     Output buffer for the matched rule.
 *
 * @return  Non-zero if a matching rule was found; zero otherwise.
 *
 * @threadsafety  Safe to call concurrently.
 */
int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
);

/**
 * @brief Parse a single mutable config file line into a rule.
 *
 * @details @p line is modified in place (comment stripping and tokenisation).
 * The caller must ensure @p line is writable.
 *
 * Return values:
 *   -  1  — line parsed successfully; @p rule is populated.
 *   -  0  — line is blank or a comment; @p rule is unmodified.
 *   - -1  — line is malformed; the rule set should be considered invalid.
 *
 * @param line  NUL-terminated, writable line buffer.  Modified in place.
 * @param rule  Output buffer; populated only on return value 1.
 *
 * @return  1, 0, or -1 as described above.
 *
 * @threadsafety  No shared state; safe from any thread given distinct buffers.
 */
int chaos_dns_config_parse_line(char *line, chaos_dns_rule_t *rule);

/**
 * @brief Parse an entire config file buffer into an array of rules.
 *
 * @details Splits @p buffer on newlines (modifying it in place) and calls
 * chaos_dns_config_parse_line() for each line.  Parsing stops and returns -1
 * on the first malformed line so that a partially updated config does not
 * take effect.
 *
 * @param buffer      NUL-terminated, writable buffer containing the file contents.
 * @param rules       Output array of at least CHAOS_DNS_MAX_RULES elements.
 * @param rule_count  Output: number of rules stored in @p rules on success.
 *
 * @return  0 on success; -1 if any line fails to parse or @p rules is full.
 *
 * @threadsafety  No shared state; safe from any thread given distinct buffers.
 */
int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count);

/**
 * @brief Select the best-matching forward-lookup rule from an explicit rule array.
 *
 * @details Used by the reload path to query a freshly-parsed snapshot before
 * it is published.  Delegates to the internal domain-agnostic selector with
 * `CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP`.
 *
 * @param rules       Rule array to search.
 * @param rule_count  Number of valid entries in @p rules.
 * @param effect      Effect category to match.
 * @param name        Hostname to match.
 * @param rule        Output buffer for the winning rule.
 *
 * @return  Non-zero if a match was found; zero otherwise.
 *
 * @threadsafety  No shared state; safe from any thread given distinct buffers.
 */
int chaos_dns_config_select_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *name,
    chaos_dns_rule_t *rule
);

/**
 * @brief Select the best-matching reverse-lookup rule from an explicit rule array.
 *
 * @details Reverse-lookup counterpart to chaos_dns_config_select_rule().
 * Delegates with `CHAOS_DNS_SELECTOR_DOMAIN_REVERSE`.
 *
 * @param rules       Rule array to search.
 * @param rule_count  Number of valid entries in @p rules.
 * @param effect      Effect category to match.
 * @param address     Normalised IP address string to match.
 * @param rule        Output buffer for the winning rule.
 *
 * @return  Non-zero if a match was found; zero otherwise.
 *
 * @threadsafety  No shared state; safe from any thread given distinct buffers.
 */
int chaos_dns_config_select_reverse_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *address,
    chaos_dns_rule_t *rule
);

#endif
