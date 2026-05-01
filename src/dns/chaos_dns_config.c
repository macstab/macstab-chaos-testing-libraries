/**
 * @file chaos_dns_config.c
 * @brief Config file parsing, mtime-based reload, and rule-matching implementation.
 *
 * @details
 * This translation unit owns the full lifecycle of the chaos rule set:
 * reading the config file from disk, parsing it into @ref chaos_dns_rule_t
 * structures, selecting the best-matching rule for a given query, and
 * publishing an updated snapshot when the file changes.
 *
 * ### Two-snapshot CAS reload protocol
 *
 * Two statically-allocated @ref chaos_dns_config_state_t snapshots are kept in
 * `g_chaos_dns_config_states[2]`.  At any moment one snapshot is *active* (its
 * index stored in `g_chaos_dns_active_config_index`) and one is *inactive* (the
 * reload target).  Readers always operate on the active snapshot without any
 * lock.
 *
 * When a thread detects a mtime change it races to set `g_chaos_dns_cached_mtime`
 * to `CHAOS_DNS_MTIME_RELOADING` via CAS.  The single winner:
 *   1. Fills the inactive snapshot with freshly parsed rules.
 *   2. Issues a full memory fence, then stores the new active index.
 *   3. Issues another full fence, then stores the observed mtime to clear the
 *      RELOADING sentinel.
 *
 * Losing threads fall back to the still-active (old) snapshot for their
 * current lookup.  The protocol guarantees:
 *   - No reader ever sees a partially-written snapshot.
 *   - At most one reload is in progress at any time.
 *   - The library is fail-open: if parsing fails, the snapshot is reset to
 *     empty-but-valid so the intercepted call passes through with no effect.
 *
 * ### Config file read buffer
 * The read buffer (`g_chaos_dns_config_buffer`) is allocated as a TLS array to
 * avoid a heap allocation on the reload path.  Because at most one thread
 * performs a reload at a time (CAS serialisation), only one thread ever writes
 * this buffer per reload cycle; the TLS storage is a pragmatic choice that
 * eliminates both locking and heap fragmentation.
 *
 * ### Platform portability
 * The mtime is read via `stat(2)`.  On Linux `st_mtim.tv_nsec` provides
 * sub-second resolution; on macOS the equivalent is `st_mtimespec.tv_nsec`.
 * The `CHAOS_DNS_STAT_SEC` / `CHAOS_DNS_STAT_NSEC` macros abstract this.
 *
 * ### Invariants maintained by this file
 * - `g_chaos_dns_active_config_index` is always 0 or 1.
 * - `g_chaos_dns_config_states[i].parse_ok` is 1 if the snapshot was parsed
 *   successfully (or is the zero-initialised empty state), and 0 if parsing
 *   failed for the snapshot at index i.
 * - Rules in a valid snapshot are ordered as they appeared in the file;
 *   rule selection iterates all rules and picks by rank/length rather than
 *   relying on order.
 *
 * @module  libchaos-dns configuration
 * @stability  Private
 */

#include "chaos_dns_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------------
 * Platform portability for stat mtime fields.
 * POSIX.1-2008 uses st_mtim; macOS uses st_mtimespec.
 * ------------------------------------------------------------------------- */
#if defined(__linux__)
#define CHAOS_DNS_STAT_SEC(st)  ((st)->st_mtim.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_DNS_STAT_SEC(st)  ((st)->st_mtimespec.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/* -------------------------------------------------------------------------
 * Internal config state type
 * ------------------------------------------------------------------------- */

/**
 * @brief One fully-parsed config snapshot.
 *
 * @details Two instances of this struct exist as global statics
 * (`g_chaos_dns_config_states[2]`).  The two-snapshot protocol ensures only
 * one is ever being written at a time, while the other is read lock-free.
 *
 * @invariant After chaos_dns_config_publish(), the newly-active snapshot's
 * `parse_ok` is 1; an empty (zero-rule) snapshot is valid and means
 * "no rules, pass all calls through unchanged".
 */
typedef struct chaos_dns_config_state
{
    chaos_dns_rule_t rules[CHAOS_DNS_MAX_RULES]; /**< Parsed rules in file order. */
    size_t           rule_count;                 /**< Number of valid entries in rules[]. */
    int              parse_ok;                   /**< 1 if this snapshot is usable; 0 if parse failed. */
} chaos_dns_config_state_t;

/* -------------------------------------------------------------------------
 * Module-level statics
 * ------------------------------------------------------------------------- */

/** Both config snapshots; indexed by g_chaos_dns_active_config_index. */
static chaos_dns_config_state_t g_chaos_dns_config_states[2];

/**
 * @brief Index (0 or 1) of the currently active config snapshot.
 *
 * @details Written only inside chaos_dns_config_publish() under full memory
 * fences.  Read by chaos_dns_config_active_state() under a fence.
 */
static volatile unsigned int g_chaos_dns_active_config_index = 0U;

/**
 * @brief Cached mtime hash of the config file as of the last completed reload.
 *
 * @details Three sentinel values exist alongside valid hashes:
 *   - CHAOS_DNS_MTIME_UNKNOWN   — initial value; triggers a reload on first use.
 *   - CHAOS_DNS_MTIME_MISSING   — file did not exist on last stat.
 *   - CHAOS_DNS_MTIME_RELOADING — a CAS winner is currently performing a reload.
 *
 * The normalization function ensures no real mtime hash collides with these.
 */
static volatile uint64_t g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;

/**
 * @brief Per-thread buffer for the raw config file contents.
 *
 * @details Sized for CHAOS_DNS_MAX_CONFIG_BYTES + 1 (NUL terminator).
 * TLS allocation avoids a malloc on the reload path and is safe because the
 * CAS protocol allows at most one thread to be reloading at a time, so only
 * one thread is ever writing this buffer.
 */
static __thread char g_chaos_dns_config_buffer[CHAOS_DNS_MAX_CONFIG_BYTES + 1U];

/* -------------------------------------------------------------------------
 * Internal helpers: state management
 * ------------------------------------------------------------------------- */

/**
 * @brief Reset a config snapshot to an empty-but-valid or parse-failed state.
 *
 * @details Uses memset to zero all fields, then sets `parse_ok`.  Called:
 *   - During init: sets both snapshots to empty-valid (parse_ok = 1).
 *   - Before a reload: resets the target snapshot to empty-valid.
 *   - After a parse failure: resets the target snapshot to parse-failed
 *     (parse_ok = 0) so that matchers return "no match" (fail-open).
 *
 * @param state     Snapshot to reset; no-op if NULL.
 * @param parse_ok  1 for empty-valid; 0 for parse-failed.
 */
static void chaos_dns_config_reset_state(chaos_dns_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * @brief Return a pointer to the currently active config snapshot.
 *
 * @details Issues a full memory fence before reading the index so that the
 * snapshot contents written by a concurrent reload are visible before the
 * index update is observed.  This is the reader side of the two-snapshot
 * protocol.
 *
 * @return  Pointer to the active snapshot; never NULL.
 *
 * @threadsafety  Safe — index read is fenced; snapshot is read-only after publish.
 */
static const chaos_dns_config_state_t *chaos_dns_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_dns_active_config_index;
    return &g_chaos_dns_config_states[index];
}

/**
 * @brief Publish a newly-loaded config snapshot as the active one.
 *
 * @details This is the writer side of the two-snapshot protocol.  Two memory
 * fences are used:
 *   1. Before storing the new index — ensures all writes to the snapshot
 *      are visible to readers that subsequently load the new index.
 *   2. Before storing the observed mtime — ensures the index update is
 *      visible before the RELOADING sentinel is cleared, preventing a second
 *      thread from starting another reload while the first index store is
 *      still in flight.
 *
 * @param next_index     Index (0 or 1) of the snapshot to make active.
 * @param observed_mtime The mtime hash that triggered this reload, or
 *                       CHAOS_DNS_MTIME_MISSING if the file was absent.
 */
static void chaos_dns_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_dns_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_dns_cached_mtime = observed_mtime;
}

/* -------------------------------------------------------------------------
 * Internal helpers: text utilities
 * ------------------------------------------------------------------------- */

/**
 * @brief Return non-zero if @p ch is an ASCII whitespace character.
 *
 * @details Recognises space, horizontal tab, carriage return, and newline.
 * Used by chaos_dns_trim() to strip leading and trailing whitespace.
 *
 * @param ch  Character to test.
 * @return  Non-zero if @p ch is a whitespace character; zero otherwise.
 */
static int chaos_dns_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Return a pointer to the first non-whitespace character of @p text,
 *        with trailing whitespace stripped in-place.
 *
 * @details Modifies @p text by overwriting the first trailing whitespace
 * character with a NUL terminator.  The returned pointer may point into the
 * middle of @p text.  The original buffer must remain valid for the lifetime
 * of the returned pointer.
 *
 * @param text  Mutable NUL-terminated string; may be NULL.
 * @return  Pointer to the trimmed start, or NULL if @p text was NULL.
 */
static char *chaos_dns_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_dns_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_dns_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

/**
 * @brief Truncate @p line at the first `#` character (inline comment removal).
 *
 * @details Overwrites the `#` with NUL so that subsequent processing sees only
 * the portion of the line before any comment.  This is intentionally simple:
 * `#` inside quoted strings is not supported because the config format does
 * not use quoted strings.
 *
 * @param line  Mutable NUL-terminated line buffer; no-op if NULL.
 */
static void chaos_dns_strip_comment(char *line)
{
    char *comment;

    if (line == NULL)
    {
        return;
    }

    comment = strchr(line, '#');
    if (comment != NULL)
    {
        *comment = '\0';
    }
}

/**
 * @brief Case-insensitive ASCII string equality comparison.
 *
 * @details Used for hostname matching so that `Example.COM` and `example.com`
 * compare equal, matching DNS case-insensitivity semantics (RFC 4343).  Only
 * the 26 ASCII letters are case-folded; non-ASCII bytes are compared as-is.
 *
 * @param left   First NUL-terminated string; NULL returns 0.
 * @param right  Second NUL-terminated string; NULL returns 0.
 * @return  Non-zero if both strings are equal length and equal content; zero otherwise.
 */
static int chaos_dns_ascii_case_equal(const char *left, const char *right)
{
    unsigned char left_ch;
    unsigned char right_ch;

    if (left == NULL || right == NULL)
    {
        return 0;
    }

    while (*left != '\0' && *right != '\0')
    {
        left_ch  = (unsigned char)*left++;
        right_ch = (unsigned char)*right++;
        if (tolower(left_ch) != tolower(right_ch))
        {
            return 0;
        }
    }

    return *left == '\0' && *right == '\0';
}

/**
 * @brief Return non-zero if @p text ends with @p suffix (case-insensitive ASCII).
 *
 * @details Used to implement SUFFIX selector matching.  A call to this
 * function is always preceded by a dot-separator check in
 * chaos_dns_selector_matches_domain() so that "fooexample.com" does not match
 * a selector for "*.example.com".
 *
 * @param text    NUL-terminated string to test; NULL returns 0.
 * @param suffix  NUL-terminated suffix to look for; NULL returns 0.
 * @return  Non-zero if @p text ends with @p suffix (ignoring case); zero otherwise.
 */
static int chaos_dns_ascii_case_ends_with(const char *text, const char *suffix)
{
    size_t text_len;
    size_t suffix_len;

    if (text == NULL || suffix == NULL)
    {
        return 0;
    }

    text_len   = strlen(text);
    suffix_len = strlen(suffix);
    if (text_len < suffix_len)
    {
        return 0;
    }

    return chaos_dns_ascii_case_equal(text + (text_len - suffix_len), suffix);
}

/* -------------------------------------------------------------------------
 * Internal helpers: selector parsing
 * ------------------------------------------------------------------------- */

/**
 * @brief Parse the address body of an `rdns://` selector into @p selector.
 *
 * @details The body may be:
 *   - `"*"` — wildcard; sets kind=ANY, domain=REVERSE.
 *   - An IPv4 string (e.g., `"192.168.1.1"`) — parsed and re-serialised via
 *     inet_pton/inet_ntop to produce a canonical form.
 *   - A bracketed IPv6 string (e.g., `"[::1]"`) — brackets are stripped
 *     before the inet_pton call.
 *
 * Re-serialising via inet_ntop ensures that selectors like `1.2.3.004` and
 * `1.2.3.4` end up with the same text, so comparisons with the normalised
 * query string from chaos_dns_reverse_query_from_sockaddr() are exact.
 *
 * @param body      The part of the selector after `rdns://`.
 * @param selector  Output; domain is set to REVERSE on success.
 * @return  Non-zero on success; zero if the body is empty, malformed, or
 *          an unsupported format (e.g., hostname instead of IP).
 */
static int chaos_dns_parse_reverse_selector_body(const char *body, chaos_dns_selector_t *selector)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr  ipv4;
    struct in6_addr ipv6;
    const char *source = body;
    size_t body_len;

    if (body == NULL || selector == NULL || *body == '\0')
    {
        return 0;
    }
    if (strcmp(body, "*") == 0)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind   = CHAOS_DNS_SELECTOR_ANY;
        return 1;
    }

    body_len = strlen(body);
    if (body[0] == '[')
    {
        /* IPv6 addresses may be written as [::1]; strip the brackets. */
        if (body_len <= 2U || body[body_len - 1U] != ']')
        {
            return 0;
        }
        if (body_len - 2U >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, body + 1, body_len - 2U);
        host[body_len - 2U] = '\0';
        source = host;
    }
    else if (body_len >= sizeof(host))
    {
        return 0;
    }

    if (inet_pton(AF_INET, source, &ipv4) == 1)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind   = CHAOS_DNS_SELECTOR_EXACT;
        /* Canonicalise: re-serialise so that 1.2.3.004 → 1.2.3.4, etc. */
        return inet_ntop(AF_INET, &ipv4, selector->text, sizeof(selector->text)) != NULL;
    }
    if (inet_pton(AF_INET6, source, &ipv6) == 1)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind   = CHAOS_DNS_SELECTOR_EXACT;
        return inet_ntop(AF_INET6, &ipv6, selector->text, sizeof(selector->text)) != NULL;
    }

    return 0;
}

/**
 * @brief Parse a complete selector string into a @ref chaos_dns_selector_t.
 *
 * @details Accepts the following forms:
 *   - `"*"`                — LOOKUP/ANY
 *   - `"dns://\*"`          — LOOKUP/ANY
 *   - `"dns://hostname"`   — LOOKUP/EXACT
 *   - `"dns://\*.suffix"`   — LOOKUP/SUFFIX (text = "suffix", leading `*.` stripped)
 *   - `"rdns://..."`       — delegates to chaos_dns_parse_reverse_selector_body()
 *
 * The `selector_len` field is set to `strlen(text)` (the full original string
 * length) before any trimming.  This is used as a tiebreaker in rule selection:
 * longer selectors are considered more specific when rank is equal.
 *
 * A `*` anywhere inside the body (after any leading `*.`) is rejected to
 * prevent ambiguous glob-like patterns; only the specific forms above are
 * supported.
 *
 * @param text      NUL-terminated selector string from the config file.
 * @param selector  Output.
 * @return  Non-zero on success; zero if @p text is NULL, empty, or unrecognised.
 */
static int chaos_dns_selector_parse(const char *text, chaos_dns_selector_t *selector)
{
    const char *body;
    size_t body_len;

    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP;
        selector->kind   = CHAOS_DNS_SELECTOR_ANY;
        return 1;
    }
    if (strncmp(text, "dns://", 6) == 0)
    {
        body = text + 6;
        if (*body == '\0')
        {
            return 0;
        }
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP;
        if (strcmp(body, "*") == 0)
        {
            selector->kind = CHAOS_DNS_SELECTOR_ANY;
            return 1;
        }
        if (strncmp(body, "*.", 2) == 0)
        {
            body += 2;                          /* strip the leading "*." */
            selector->kind = CHAOS_DNS_SELECTOR_SUFFIX;
        }
        else
        {
            selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        }

        body_len = strlen(body);
        if (body_len == 0U || body_len >= sizeof(selector->text) || strchr(body, '*') != NULL)
        {
            return 0;
        }

        (void)memcpy(selector->text, body, body_len + 1U);
        return 1;
    }
    if (strncmp(text, "rdns://", 7) == 0)
    {
        return chaos_dns_parse_reverse_selector_body(text + 7, selector);
    }

    return 0;
}

/**
 * @brief Test whether a selector matches a given domain and name, computing
 *        a specificity rank.
 *
 * @details Rank values (written to @p rank_out):
 *   - 3 — EXACT match
 *   - 2 — SUFFIX match
 *   - 1 — ANY match
 *   - 0 — no match (return value is 0)
 *
 * For SUFFIX matching, the function checks that the character immediately
 * before the suffix in @p name is a `.`  to prevent `fooexample.com` from
 * matching `*.example.com`.
 *
 * @param selector  Selector to test.
 * @param domain    Domain of the incoming query (LOOKUP or REVERSE).
 * @param name      Hostname or IP string to test against the selector.
 * @param rank_out  Output; set to the match rank if non-NULL and matched.
 *
 * @return  Non-zero if the selector matches; zero otherwise.
 */
static int chaos_dns_selector_matches_domain(
    const chaos_dns_selector_t *selector,
    chaos_dns_selector_domain_t domain,
    const char *name,
    unsigned int *rank_out
)
{
    size_t name_len;
    size_t suffix_len;

    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL || name == NULL || *name == '\0' || selector->domain != domain)
    {
        return 0;
    }
    if (selector->kind == CHAOS_DNS_SELECTOR_ANY)
    {
        if (rank_out != NULL)
        {
            *rank_out = 1U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_DNS_SELECTOR_EXACT)
    {
        if (!chaos_dns_ascii_case_equal(selector->text, name))
        {
            return 0;
        }
        if (rank_out != NULL)
        {
            *rank_out = 3U;
        }
        return 1;
    }
    if (domain != CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP || selector->kind != CHAOS_DNS_SELECTOR_SUFFIX)
    {
        return 0;
    }

    name_len   = strlen(name);
    suffix_len = strlen(selector->text);
    if (name_len <= suffix_len)
    {
        return 0;
    }
    if (!chaos_dns_ascii_case_ends_with(name, selector->text))
    {
        return 0;
    }
    /* Require a dot separator: "fooexample.com" must not match "*.example.com". */
    if (name[name_len - suffix_len - 1U] != '.')
    {
        return 0;
    }
    if (rank_out != NULL)
    {
        *rank_out = 2U;
    }
    return 1;
}

/* -------------------------------------------------------------------------
 * Internal helpers: value parsing
 * ------------------------------------------------------------------------- */

/**
 * @brief Parse a probability value from a NUL-terminated string.
 *
 * @details Accepts any decimal floating-point representation recognised by
 * strtod(3) in the range [0.0, 1.0].  Any trailing non-whitespace after the
 * number causes failure.
 *
 * @param text         Input string.
 * @param probability  Output; set on success.
 * @return  0 on success; -1 on parse failure or out-of-range value.
 */
static int chaos_dns_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_dns_trim(end) != '\0')
    {
        return -1;
    }
    if (value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

/**
 * @brief Parse a latency value (milliseconds) from a NUL-terminated string.
 *
 * @details Accepts a non-negative decimal integer up to UINT_MAX.  The value
 * is stored as `unsigned int` (milliseconds).  Values larger than 0xffffffff
 * are rejected because the sleep loop uses `useconds_t` chunks.
 *
 * @param text        Input string.
 * @param latency_ms  Output; set on success.
 * @return  0 on success; -1 on failure.
 */
static int chaos_dns_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_dns_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/**
 * @brief Parse a list-length limit value from a NUL-terminated string.
 *
 * @details Accepts a positive decimal integer in [1, UINT_MAX].  Zero is
 * explicitly rejected: a limit of zero would silently discard all results,
 * which is almost certainly a config error.
 *
 * @param text   Input string.
 * @param limit  Output; set on success; guaranteed >= 1.
 * @return  0 on success; -1 on failure or zero value.
 */
static int chaos_dns_parse_limit(const char *text, unsigned int *limit)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || limit == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    /* Reject zero: a zero limit is a config mistake, not a valid no-op. */
    if (end == text || *chaos_dns_trim(end) != '\0' || value == 0UL || value > 0xffffffffUL)
    {
        return -1;
    }

    *limit = (unsigned int)value;
    return 0;
}

/**
 * @brief Return non-zero if @p effect is permitted for @p selector's domain.
 *
 * @details LOOKUP selectors (dns://) allow all effects.  REVERSE selectors
 * (rdns://) only allow a subset: GAI (EAI_* errors), LATENCY, REWRITE
 * (hostname replacement), and SERVICE (port replacement).  Result-set
 * transforms (OVERRIDE, FILTER_FAMILY, SHUFFLE, LIMIT) are meaningless for
 * getnameinfo because it does not return an addrinfo list.
 *
 * @param selector  The parsed selector.
 * @param effect    The effect to check.
 * @return  Non-zero if allowed; zero if the combination is invalid.
 */
static int chaos_dns_effect_allowed(const chaos_dns_selector_t *selector, chaos_dns_effect_t effect)
{
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP)
    {
        return 1;
    }
    if (selector->domain != CHAOS_DNS_SELECTOR_DOMAIN_REVERSE)
    {
        return 0;
    }

    return effect == CHAOS_DNS_EFFECT_GAI     ||
           effect == CHAOS_DNS_EFFECT_LATENCY ||
           effect == CHAOS_DNS_EFFECT_REWRITE ||
           effect == CHAOS_DNS_EFFECT_SERVICE;
}

/**
 * @brief Parse an address-family filter token string into the enum value.
 *
 * @details Accepted tokens (case-sensitive):
 *   - `"inet4"` or `"ipv4"` → CHAOS_DNS_FAMILY_INET4
 *   - `"inet6"` or `"ipv6"` → CHAOS_DNS_FAMILY_INET6
 *   - `"any"`               → CHAOS_DNS_FAMILY_ANY
 *
 * Both `inet4`/`ipv4` spellings are accepted for user convenience.
 *
 * @param text  Token string; NULL returns INVALID.
 * @return  The parsed family filter value, or CHAOS_DNS_FAMILY_INVALID.
 */
static chaos_dns_family_filter_t chaos_dns_parse_family_filter(const char *text)
{
    if (text == NULL)
    {
        return CHAOS_DNS_FAMILY_INVALID;
    }
    if (strcmp(text, "inet4") == 0 || strcmp(text, "ipv4") == 0)
    {
        return CHAOS_DNS_FAMILY_INET4;
    }
    if (strcmp(text, "inet6") == 0 || strcmp(text, "ipv6") == 0)
    {
        return CHAOS_DNS_FAMILY_INET6;
    }
    if (strcmp(text, "any") == 0)
    {
        return CHAOS_DNS_FAMILY_ANY;
    }
    return CHAOS_DNS_FAMILY_INVALID;
}

/**
 * @brief Map an EAI_* error name string to its integer constant.
 *
 * @details Returns `0x7fffffff` (a sentinel that cannot be a real EAI code)
 * if @p text does not match any known name.  This sentinel is used by the
 * caller to distinguish a successfully-parsed EAI code from an unrecognised
 * effect keyword.
 *
 * Supported names: EAI_AGAIN, EAI_FAIL, EAI_NONAME, EAI_MEMORY, EAI_SYSTEM.
 *
 * @param text  Effect field text from a config line.
 * @return  The EAI_* constant, or 0x7fffffff if not recognised.
 */
static int chaos_dns_parse_gai_name(const char *text)
{
    if (text == NULL)
    {
        return 0x7fffffff;
    }
    if (strcmp(text, "EAI_AGAIN") == 0)
    {
        return EAI_AGAIN;
    }
    if (strcmp(text, "EAI_FAIL") == 0)
    {
        return EAI_FAIL;
    }
    if (strcmp(text, "EAI_NONAME") == 0)
    {
        return EAI_NONAME;
    }
    if (strcmp(text, "EAI_MEMORY") == 0)
    {
        return EAI_MEMORY;
    }
    if (strcmp(text, "EAI_SYSTEM") == 0)
    {
        return EAI_SYSTEM;
    }
    return 0x7fffffff;
}

/**
 * @brief Copy a non-empty string into a fixed-size buffer.
 *
 * @details Fails if @p text is empty, or if its length (including NUL) would
 * exceed @p target_size.  Uses memcpy rather than strncpy to avoid the
 * zero-fill overhead on large buffers.
 *
 * @param text         Source string.
 * @param target       Destination buffer.
 * @param target_size  Size of @p target in bytes.
 * @return  0 on success; -1 if @p text is empty, too long, or any pointer is NULL.
 */
static int chaos_dns_copy_text_value(const char *text, char *target, size_t target_size)
{
    size_t len;

    if (text == NULL || target == NULL || target_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len == 0U || len >= target_size)
    {
        return -1;
    }
    (void)memcpy(target, text, len + 1U);
    return 0;
}

/**
 * @brief Split an effect value field into a payload and an optional probability.
 *
 * @details The optional probability is appended to the payload with an `@`
 * separator, e.g. `"192.168.1.1@0.5"`.  `strrchr` is used (not `strchr`) so
 * that IPv6 addresses containing `@` in user data are handled — though in
 * practice no IP address contains `@`; the rightmost `@` is the separator.
 *
 * If no `@` is present, probability defaults to 1.0 (always trigger).
 *
 * @param text          The raw value field text.
 * @param payload       Output buffer for the payload portion.
 * @param payload_size  Size of @p payload in bytes.
 * @param probability   Output; set to the parsed probability or 1.0.
 * @return  0 on success; -1 on any parse or copy failure.
 */
static int chaos_dns_parse_payload_probability(
    const char *text, char *payload, size_t payload_size, double *probability
)
{
    const char *separator;
    size_t payload_len;
    char probability_text[64];
    char payload_text[CHAOS_DNS_MAX_VALUE];

    if (text == NULL || payload == NULL || probability == NULL)
    {
        return -1;
    }

    separator = strrchr(text, '@');
    if (separator == NULL)
    {
        *probability = 1.0;
        return chaos_dns_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(separator - text);
    if (payload_len == 0U || payload_len >= sizeof(payload_text))
    {
        return -1;
    }
    (void)memcpy(payload_text, text, payload_len);
    payload_text[payload_len] = '\0';
    if (chaos_dns_copy_text_value(chaos_dns_trim(payload_text), payload, payload_size) != 0)
    {
        return -1;
    }
    if (chaos_dns_copy_text_value(separator + 1, probability_text, sizeof(probability_text)) != 0)
    {
        return -1;
    }

    return chaos_dns_parse_probability(probability_text, probability);
}

/**
 * @brief Return non-zero if @p token is a valid IPv4 or IPv6 address literal.
 *
 * @details Accepts bare IPv4 (`"192.168.1.1"`), bare IPv6 (`"::1"`), or
 * bracketed IPv6 (`"[::1]"`).  Uses inet_pton for validation, not a regex,
 * so the accepted set is exactly the set of addresses the real getaddrinfo
 * can resolve with AI_NUMERICHOST.
 *
 * @param token  NUL-terminated address token.
 * @return  Non-zero if valid; zero otherwise.
 */
static int chaos_dns_override_token_valid(const char *token)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr  ipv4;
    struct in6_addr ipv6;
    size_t len;

    if (token == NULL || *token == '\0')
    {
        return 0;
    }

    len = strlen(token);
    if (len >= sizeof(host))
    {
        return 0;
    }
    if (token[0] == '[' && len > 2U && token[len - 1U] == ']')
    {
        if (len - 2U >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, token + 1, len - 2U);
        host[len - 2U] = '\0';
    }
    else
    {
        (void)memcpy(host, token, len + 1U);
    }

    (void)memset(&ipv4, 0, sizeof(ipv4));
    (void)memset(&ipv6, 0, sizeof(ipv6));

    return inet_pton(AF_INET, host, &ipv4) == 1 || inet_pton(AF_INET6, host, &ipv6) == 1;
}

/**
 * @brief Validate that @p text is a non-empty comma-separated list of IP literals.
 *
 * @details Splits on commas (in a copy of @p text to avoid modifying the caller's
 * buffer), trims each token, and calls chaos_dns_override_token_valid() on each.
 * Returns 0 if any token is invalid or if the list is empty.
 *
 * @param text  The raw override value string (not modified).
 * @return  Non-zero if all tokens are valid IP literals; zero otherwise.
 */
static int chaos_dns_validate_override_value(const char *text)
{
    char buffer[CHAOS_DNS_MAX_VALUE];
    char *cursor;
    int found = 0;

    if (chaos_dns_copy_text_value(text, buffer, sizeof(buffer)) != 0)
    {
        return 0;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *token     = cursor;
        char *separator = strchr(cursor, ',');

        if (separator != NULL)
        {
            *separator++ = '\0';
            cursor = separator;
        }
        else
        {
            cursor += strlen(cursor);
        }

        token = chaos_dns_trim(token);
        if (*token == '\0' || !chaos_dns_override_token_valid(token))
        {
            return 0;
        }
        found = 1;
    }

    return found;
}

/* -------------------------------------------------------------------------
 * mtime hashing
 * ------------------------------------------------------------------------- */

/**
 * @brief Ensure a computed mtime hash does not collide with a sentinel value.
 *
 * @details If the FNV-style hash of the mtime fields coincidentally equals one
 * of the three sentinel constants (MISSING, RELOADING, UNKNOWN), XOR it with
 * the golden-ratio constant to produce a different, non-sentinel value.  The
 * probability of a natural collision is negligible (3 out of 2^64), but the
 * consequence of a collision — a missed reload or an incorrect RELOADING
 * state — is severe enough to guard against.
 *
 * @param value  Raw mtime hash from chaos_dns_config_hash_mtime().
 * @return  A value that is guaranteed not to equal any sentinel.
 */
static uint64_t chaos_dns_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_DNS_MTIME_MISSING    ||
        value == CHAOS_DNS_MTIME_RELOADING  ||
        value == CHAOS_DNS_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

/**
 * @brief Compute a 64-bit hash of a struct stat's modification time.
 *
 * @details Uses a pair of FNV-prime multiplications over the second and
 * nanosecond fields to spread the time domain across the full 64-bit output
 * space.  Both fields are incorporated so that a file modified within the same
 * second (nanosecond granularity) still produces a different hash.
 *
 * The base value (0x1469598103934665603) is an arbitrary non-zero odd
 * constant; the multiplier (FNV prime 1099511628211) is the standard FNV-1a
 * 64-bit prime.
 *
 * Returns CHAOS_DNS_MTIME_MISSING if @p st is NULL (file absent).
 *
 * @param st  Pointer to the struct stat of the config file; NULL if absent.
 * @return  Hash value guaranteed not to collide with RELOADING or UNKNOWN.
 */
static uint64_t chaos_dns_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    value  = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_DNS_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_DNS_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_dns_config_normalize_mtime_hash(value);
}

/**
 * @brief Stat the config file and return its mtime hash.
 *
 * @details Sets the reentrancy guard around the stat(2) call so that if the
 * stat itself triggers any interposed call (unlikely but possible on exotic
 * filesystems), the guard prevents re-entrant chaos injection.
 *
 * @return  Mtime hash for the current file state, or CHAOS_DNS_MTIME_MISSING
 *          if the file does not exist or stat fails.
 */
static uint64_t chaos_dns_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc       = stat(CHAOS_DNS_CONFIG_PATH, &st);
    chaos_dns_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    return chaos_dns_config_hash_mtime(&st);
}

/**
 * @brief Read the config file into the TLS buffer.
 *
 * @details Opens the file at CHAOS_DNS_CONFIG_PATH, reads it in a loop to
 * handle partial reads, and NUL-terminates the result.  The reentrancy guard
 * is held for the entire duration so that no other interposed call can observe
 * partial state.  The file is rejected (returns -1) if it is larger than
 * CHAOS_DNS_MAX_CONFIG_BYTES; this prevents unbounded memory use.
 *
 * @param size_out  Output: number of bytes read (not including NUL terminator).
 * @return  0 on success; -1 on open/read failure, or if the file is too large.
 *
 * @post  On success, g_chaos_dns_config_buffer[0..*size_out] is the file
 *        contents with a NUL terminator at [*size_out].
 */
static int chaos_dns_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_dns_enter_internal();
    fd       = open(CHAOS_DNS_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_dns_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_dns_config_buffer + total, CHAOS_DNS_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_dns_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        /* Reject files that hit the size cap to avoid silent truncation. */
        if (total == CHAOS_DNS_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_dns_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_dns_leave_internal(previous);
    g_chaos_dns_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Split a trimmed config line into selector, effect, and value fields.
 *
 * @details A config line has the form:
 * @code
 *   <selector> : <effect> : <value>
 * @endcode
 * where `<selector>` is one of the URI-prefixed patterns and the two `:`
 * delimiters are found after the selector (skipping the `://` in the URI).
 * This function modifies @p line in place by NUL-terminating each field.
 *
 * The function handles the special case of `rdns://[...]` selectors where the
 * IPv6 address is bracketed: it locates the closing `]` first, then expects
 * a `:` immediately after the bracket, avoiding false splits on the `:` inside
 * the address.
 *
 * @param line           Mutable, trimmed line buffer (comment already stripped).
 * @param selector_text  Output pointer to the selector field start.
 * @param effect_text    Output pointer to the effect field start.
 * @param value_text     Output pointer to the value field start.
 * @return  Non-zero on successful split; zero if the line has unrecognised format.
 */
static int
chaos_dns_split_rule_fields(char *line, char **selector_text, char **effect_text, char **value_text)
{
    char *selector_end;
    char *effect_end;

    if (line == NULL || selector_text == NULL || effect_text == NULL || value_text == NULL)
    {
        return 0;
    }

    if (line[0] == '*' && line[1] == ':')
    {
        selector_end = line + 1;
    }
    else if (strncmp(line, "dns://", 6) == 0)
    {
        selector_end = strchr(line + 6, ':');
    }
    else if (strncmp(line, "rdns://[", 8) == 0)
    {
        /* Bracketed IPv6: find the closing ']', then expect ':' immediately after. */
        char *close = strchr(line + 8, ']');

        if (close == NULL || close[1] != ':')
        {
            return 0;
        }
        selector_end = close + 1;
    }
    else if (strncmp(line, "rdns://", 7) == 0)
    {
        selector_end = strchr(line + 7, ':');
    }
    else
    {
        return 0;
    }
    if (selector_end == NULL)
    {
        return 0;
    }

    *selector_end++ = '\0';
    effect_end = strchr(selector_end, ':');
    if (effect_end == NULL)
    {
        return 0;
    }
    *effect_end++ = '\0';

    *selector_text = chaos_dns_trim(line);
    *effect_text   = chaos_dns_trim(selector_end);
    *value_text    = chaos_dns_trim(effect_end);
    return 1;
}

/* =========================================================================
 * Public API implementation
 * ========================================================================= */

/**
 * @brief Initialise the config subsystem.  See chaos_dns_config.h.
 */
void chaos_dns_config_init(void)
{
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[0], 1);
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[1], 1);
    g_chaos_dns_active_config_index = 0U;
    g_chaos_dns_cached_mtime        = CHAOS_DNS_MTIME_UNKNOWN;
}

/**
 * @brief Parse one line into a rule.  See chaos_dns_config.h for the contract.
 *
 * @details The effect is identified first by trying to parse an EAI_* name
 * (which cannot be confused with keyword effects), then by strcmp against the
 * known keyword strings.  Each effect branch validates that the selector
 * domain permits that effect before attempting to parse the value field,
 * avoiding partial population of @p rule on mismatched combinations.
 */
int chaos_dns_config_parse_line(char *line, chaos_dns_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_DNS_MAX_VALUE];
    int gai_error;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_dns_strip_comment(line);
    line = chaos_dns_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_dns_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_dns_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    gai_error = chaos_dns_parse_gai_name(effect_text);
    if (gai_error != 0x7fffffff)
    {
        rule->effect    = CHAOS_DNS_EFFECT_GAI;
        rule->gai_error = gai_error;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        return chaos_dns_parse_probability(value_text, &rule->probability) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_LATENCY;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "REWRITE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_REWRITE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "SERVICE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_SERVICE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "OVERRIDE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_OVERRIDE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        if (!chaos_dns_validate_override_value(payload))
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "FILTER_FAMILY") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_FILTER_FAMILY;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        rule->family = chaos_dns_parse_family_filter(payload);
        return rule->family != CHAOS_DNS_FAMILY_INVALID ? 1 : -1;
    }
    if (strcmp(effect_text, "LIMIT") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_LIMIT;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_parse_limit(payload, &rule->limit) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "SHUFFLE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_SHUFFLE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        return chaos_dns_parse_probability(value_text, &rule->probability) == 0 ? 1 : -1;
    }

    return -1;
}

/**
 * @brief Parse a complete config buffer into a rule array.  See chaos_dns_config.h.
 *
 * @details Stops and returns -1 on the first malformed non-blank line.  This
 * fail-fast behaviour ensures that a partially-valid file never results in a
 * partial rule set: either all rules parse successfully or the snapshot is
 * reset to empty.
 */
int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;

    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        int rc;

        if (count >= CHAOS_DNS_MAX_RULES)
        {
            return -1;
        }
        while (*cursor != '\0' && *cursor != '\n')
        {
            ++cursor;
        }
        if (*cursor == '\n')
        {
            *cursor++ = '\0';
        }

        rc = chaos_dns_config_parse_line(line, &rules[count]);
        if (rc < 0)
        {
            return -1;
        }
        if (rc == 0)
        {
            continue;
        }

        ++count;
    }

    *rule_count = count;
    return 0;
}

/**
 * @brief Internal: select the best-matching rule for a given domain, effect, and name.
 *
 * @details Scans all rules, computing a rank for each matching rule.
 * The winner is the rule with the highest rank; ties are broken by
 * selector_len (longer = more specific).  The winning rule is copied by value
 * into @p rule so the caller does not need to hold any snapshot reference.
 *
 * @param rules       Rule array to scan.
 * @param rule_count  Number of valid entries.
 * @param effect      Effect category to filter by.
 * @param domain      LOOKUP or REVERSE.
 * @param name        Hostname or IP string.
 * @param rule        Output for the winning rule.
 * @return  Non-zero if a match was found; zero otherwise.
 */
static int chaos_dns_config_select_rule_domain(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    chaos_dns_selector_domain_t domain,
    const char *name,
    chaos_dns_rule_t *rule
)
{
    size_t       index;
    unsigned int best_rank = 0U;
    size_t       best_len  = 0U;
    int          found     = 0;

    if (rules == NULL || name == NULL || rule == NULL)
    {
        return 0;
    }

    for (index = 0U; index < rule_count; ++index)
    {
        unsigned int rank = 0U;

        if (rules[index].effect != effect)
        {
            continue;
        }
        if (!chaos_dns_selector_matches_domain(&rules[index].selector, domain, name, &rank))
        {
            continue;
        }
        if (!found || rank > best_rank ||
            (rank == best_rank && rules[index].selector.selector_len > best_len))
        {
            *rule      = rules[index];
            best_rank  = rank;
            best_len   = rules[index].selector.selector_len;
            found      = 1;
        }
    }

    return found;
}

/**
 * @brief Select the best forward-lookup rule.  See chaos_dns_config.h.
 */
int chaos_dns_config_select_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *name,
    chaos_dns_rule_t *rule
)
{
    return chaos_dns_config_select_rule_domain(
        rules, rule_count, effect, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, name, rule
    );
}

/**
 * @brief Select the best reverse-lookup rule.  See chaos_dns_config.h.
 */
int chaos_dns_config_select_reverse_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *address,
    chaos_dns_rule_t *rule
)
{
    return chaos_dns_config_select_rule_domain(
        rules, rule_count, effect, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, address, rule
    );
}

/**
 * @brief Check for file changes and reload if needed.  See chaos_dns_config.h.
 *
 * @details The two-snapshot CAS protocol is:
 *   1. Stat the file, compute the mtime hash.
 *   2. Load the cached mtime with a fence.
 *   3. If equal, no reload needed — return immediately.
 *   4. CAS the cached mtime from `cached_mtime` to RELOADING.
 *      Only one thread succeeds; losers use the current active snapshot.
 *   5. Determine next_index = 1 - active_index.
 *   6. Reset next_state, attempt to read and parse into it.
 *   7. On parse failure, reset next_state to empty (fail-open).
 *   8. Publish: fence + store next_index + fence + store observed_mtime.
 */
int chaos_dns_config_prepare(void)
{
    uint64_t                   observed_mtime;
    uint64_t                   cached_mtime;
    unsigned int               active_index;
    unsigned int               next_index;
    size_t                     config_size;
    chaos_dns_config_state_t  *next_state;

    observed_mtime = chaos_dns_config_observed_mtime();
    cached_mtime   = chaos_dns_atomic_load_u64(&g_chaos_dns_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    if (!chaos_dns_atomic_cas_u64(
            &g_chaos_dns_cached_mtime, cached_mtime, CHAOS_DNS_MTIME_RELOADING
        ))
    {
        /* Another thread is already reloading; use whatever is currently active. */
        return chaos_dns_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_dns_active_config_index;
    next_index   = active_index == 0U ? 1U : 0U;
    next_state   = &g_chaos_dns_config_states[next_index];
    chaos_dns_config_reset_state(next_state, 1);   /* start with a clean, valid-but-empty snapshot */

    if (observed_mtime != CHAOS_DNS_MTIME_MISSING &&
        chaos_dns_config_read_file(&config_size) == 0 &&
        config_size > 0U &&
        chaos_dns_config_parse_buffer(
            g_chaos_dns_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        /* Parse failed: reset to empty-but-parse_ok=0 so matchers return "no match". */
        chaos_dns_config_reset_state(next_state, 0);
    }

    chaos_dns_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Match against the active snapshot (forward lookup).  See chaos_dns_config.h.
 */
int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_rule(state->rules, state->rule_count, effect, name, rule);
}

/**
 * @brief Match against the active snapshot (reverse lookup).  See chaos_dns_config.h.
 */
int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_reverse_rule(
        state->rules, state->rule_count, effect, address, rule
    );
}

/**
 * @brief Prepare then match (forward lookup).  See chaos_dns_config.h.
 */
int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule)
{
    if (name == NULL || *name == '\0' || rule == NULL || !chaos_dns_config_prepare())
    {
        return 0;
    }

    return chaos_dns_config_match_loaded(effect, name, rule);
}

/**
 * @brief Prepare then match (reverse lookup).  See chaos_dns_config.h.
 */
int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    if (address == NULL || *address == '\0' || rule == NULL || !chaos_dns_config_prepare())
    {
        return 0;
    }

    return chaos_dns_config_match_reverse_loaded(effect, address, rule);
}
