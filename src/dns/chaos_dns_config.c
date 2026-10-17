/**
 * @file chaos_dns_config.c
 * @brief Rule-file loading, parsing, lock-free two-snapshot reload and rule selection for
 *        libchaos-dns.
 *
 * @details
 * The same reload design as libchaos-net (chaos_net_config.c); the rule grammar is
 * documented in chaos_dns_config.h.
 *
 * ### Throttled change detection
 * chaos_dns_config_prepare() looks at the rule file at most once per
 * CHAOS_CHECK_INTERVAL_NS (1 ms) per process, timed with the vDSO CLOCK_MONOTONIC
 * (chaos_clock.h); every call looks until the first load completes, and always when no
 * vDSO clock exists. A look is one stat(2), hashed (FNV-style) over mtime s and ns,
 * size, inode and device into a 64-bit stamp: an append changes the size and a
 * rename-over rewrite (`sed -i`) the inode even inside one mtime tick. A same-size
 * in-place rewrite inside one tick is caught by the provisional rule: a load whose mtime
 * is under CHAOS_RACY_WINDOW_MS (20 ms) old is re-read on the next look and replaced only
 * if its content hash changed.
 *
 * ### Two-snapshot CAS reload
 * Two static snapshots; wrappers read the active one without a lock. The thread that
 * sees a new stamp CASes `g_chaos_dns_cached_mtime` to `CHAOS_DNS_MTIME_RELOADING`;
 * losers, and threads that see RELOADING, use the active snapshot and never wait. The
 * winner:
 *   1. reads the file into the static buffer and parses it into the inactive snapshot;
 *   2. writes the status file;
 *   3. ends the snapshot's write sequence, stores the index, then the stamp, each behind
 *      a full barrier; the stamp store releases the claim.
 * A reader copying a rule out of a snapshot that a later reload rewrites detects it by
 * the snapshot's seqlock sequence and treats the copy as no match.
 *
 * ### Failure behaviour (fail-open)
 *   - Missing file: an empty snapshot (parse_ok = 1), status file removed.
 *   - Rejected file (invalid line, too many rules, NUL byte, >= 256 KiB, EACCES/EPERM,
 *     EISDIR): a snapshot with parse_ok = 0 and no rules, status file state=error. Stale
 *     rules are never kept; the file is not re-read until its stamp changes.
 *   - Transient failure (other open/read errors, or the file changing during the read):
 *     nothing is published, the claim is released with the old stamp, the next look
 *     retries.
 *
 * ### Fork and exec
 * A pthread_atfork child handler releases a reload claim and the hits-writer flag held
 * by parent threads, restarts hit counts for the child's pid and reseeds the PRNG.
 * vfork() children run no handler; they share the parent's memory and the pid check
 * keeps them from writing its hits file. exec() starts from scratch.
 *
 * ### Invariants
 * - `g_chaos_dns_active_config_index` is 0 or 1.
 * - Only the claim holder writes the inactive snapshot, the read buffer, the error
 *   record and the text table.
 * - Rules keep file order; selection compares every rule by rank and selector length,
 *   so order decides only full ties (the earlier rule wins).
 *
 * ### Test seams
 * CHAOS_CONFIG_FILE_OPEN/READ/CLOSE (chaos_status.h), g_chaos_dns_check_interval_ns (0
 * disables the throttle), CHAOS_RACY_WINDOW_MS.
 *
 * @module  libchaos-dns configuration
 * @stability  Private
 */

#include "chaos_dns_config.h"
#include "chaos_clock.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * mtime of a struct stat: st_mtim on Linux (POSIX.1-2008), st_mtimespec on macOS/BSD.
 * ------------------------------------------------------------------------- */
#if defined(__linux__)
#define CHAOS_DNS_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_DNS_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/* -------------------------------------------------------------------------
 * Internal config state type
 * ------------------------------------------------------------------------- */

/**
 * @brief One complete rule snapshot.
 *
 * @details Two static instances (`g_chaos_dns_config_states[2]`): the reload owner fills
 * the inactive one while wrappers copy rules out of the active one.
 *
 * `parse_ok` is 1 for a usable snapshot (an empty one means "no rules, pass every call
 * through") and 0 for a rejected file, which never matches. `sequence` is odd while a
 * reload rewrites the snapshot.
 */
typedef struct chaos_dns_config_state
{
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    chaos_dns_rule_t rules[CHAOS_DNS_MAX_RULES]; /**< Parsed rules in file order. */
    size_t rule_count;                           /**< Number of valid entries in rules[]. */
    int parse_ok; /**< 1 usable (possibly empty); 0 rejected file, never matches. */
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t *hits[CHAOS_DNS_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_DNS_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_dns_config_state_t;

/* -------------------------------------------------------------------------
 * Module-level statics
 * ------------------------------------------------------------------------- */

/** @brief Both snapshots; indexed by g_chaos_dns_active_config_index. */
static chaos_dns_config_state_t g_chaos_dns_config_states[2];

/** @brief Hit slots of the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_dns_hit_pool[2U * CHAOS_DNS_MAX_RULES];

/**
 * @brief Index (0 or 1) of the active snapshot.
 *
 * @details Written by chaos_dns_config_publish() (behind full barriers) and
 * chaos_dns_config_init(); read by chaos_dns_config_active_state() behind a barrier.
 */
static volatile unsigned int g_chaos_dns_active_config_index = 0U;

/**
 * @brief Change stamp of the loaded rule file, and the reload claim.
 *
 * @details Holds a chaos_dns_config_hash_mtime() stamp or a reserved value:
 *   - CHAOS_DNS_MTIME_UNKNOWN   -- before the first load (and in a fork child whose
 *     parent was mid-reload); forces a load.
 *   - CHAOS_DNS_MTIME_MISSING   -- no rule file at the last load.
 *   - CHAOS_DNS_MTIME_RELOADING -- a thread owns a reload.
 * chaos_dns_config_normalize_mtime_hash() keeps computed stamps off these values.
 */
static volatile uint64_t g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;

/**
 * @brief The loaded file's mtime was within CHAOS_RACY_WINDOW_MS of the clock, so its
 *        stamp cannot be trusted (chaos_clock_stamp_is_recent()): the next look re-reads.
 */
static volatile int g_chaos_dns_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_dns_config_content = 0U;

/**
 * @brief The reload owner's read buffer for the rule file.
 *
 * @details CHAOS_DNS_MAX_CONFIG_BYTES + 1 for the NUL that chaos_dns_config_read_file()
 * appends. Only the holder of the CHAOS_DNS_MTIME_RELOADING claim touches it, so one
 * process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves in
 * every thread of the preloaded process and adds to each thread's minimum stack size.
 * Runtimes that create threads with small explicit stacks (the Erlang VM, for one) then
 * fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_dns_config_buffer[CHAOS_DNS_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The line the last parse rejected and why, for the status file.
 *
 * @details Written only by the reload owner (or a unit test calling the parser).
 */
static chaos_status_error_t g_chaos_dns_config_error;

/** @brief Text of each rule accepted by the last parse; copied into the next snapshot. */
static char g_chaos_dns_config_texts[CHAOS_DNS_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Hits-writer flag: set (by CAS) while one thread writes the hits file. */
static volatile int g_chaos_dns_hits_writing = 0;

/** @brief Whether the pthread_atfork handler is registered (once per image). */
static int g_chaos_dns_atfork_registered = 0;

static void chaos_dns_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_dns_hits_pending = 0;

/** @brief Hits recorded by this process since start or fork; drives the eager phase. */
static uint64_t g_chaos_dns_hits_total = 0U;

/** @brief CLOCK_MONOTONIC time of the last hits-file write, in ms. */
static uint64_t g_chaos_dns_hits_last_ms = 0U;

/** @brief Pid the counts belong to; set at init and in a fork() child. */
static volatile uint64_t g_chaos_dns_hits_pid = 0U;

/** @brief Number `<n>` of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_dns_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_dns_hits_owned = 0;

/** @brief Scratch for formatting the hits file; used only by the hits writer. */
static char g_chaos_dns_hits_buffer[CHAOS_DNS_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/* -------------------------------------------------------------------------
 * Internal helpers: state management
 * ------------------------------------------------------------------------- */

/**
 * @brief Empties a snapshot and sets its parse_ok, leaving its sequence odd.
 *
 * @details Starts the write sequence first (idempotent), so a reader still copying from
 * this snapshot sees the change; chaos_dns_config_publish() or chaos_dns_config_init()
 * ends it. Called for both snapshots by init, for the inactive one before a reload, and
 * with parse_ok = 0 after a rejected parse.
 *
 * @param state     Snapshot to reset; NULL is a no-op.
 * @param parse_ok  1 usable (empty); 0 rejected.
 */
static void chaos_dns_config_reset_state(chaos_dns_config_state_t *state, int parse_ok)
{
    uint64_t sequence;

    if (state == NULL)
    {
        return;
    }

    /* Odd before the memset: a reader still holding this snapshot sees the rewrite. */
    chaos_snapshot_write_begin(&state->sequence);
    sequence = state->sequence;
    (void)memset(state, 0, sizeof(*state));
    state->sequence = sequence;
    state->parse_ok = parse_ok;
}

/**
 * @brief The active snapshot.
 *
 * @details Full barrier, then the index load: the reader side of
 * chaos_dns_config_publish(). The snapshot can be rewritten two reloads later; readers
 * that copy rules validate the copy with its sequence.
 *
 * @return  The active snapshot; never NULL.
 *
 * @threadsafety  Any thread.
 */
static const chaos_dns_config_state_t *chaos_dns_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_dns_active_config_index;
    return &g_chaos_dns_config_states[index];
}

/**
 * @brief Publishes the freshly loaded snapshot and releases the reload claim.
 *
 * @details Writer side of the protocol:
 *   1. End the snapshot's write sequence.
 *   2. Full barrier, store the index: a reader that sees it sees the complete rules.
 *   3. Full barrier, store the observed stamp in place of RELOADING: the claim is
 *      released only after the index is visible, so the next reload cannot start
 *      writing the snapshot that is still active.
 *
 * @param next_index     Index (0 or 1) of the snapshot to activate.
 * @param observed_mtime Stamp that triggered this reload, or CHAOS_DNS_MTIME_MISSING.
 */
static void chaos_dns_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_snapshot_write_end(&g_chaos_dns_config_states[next_index].sequence);
    __sync_synchronize();
    g_chaos_dns_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_dns_cached_mtime = observed_mtime;
}

/* -------------------------------------------------------------------------
 * Internal helpers: text utilities
 * ------------------------------------------------------------------------- */

/**
 * @brief Whether @p ch is a blank for trimming: space, tab, CR or LF.
 *
 * @param ch  Character to test.
 * @return  Non-zero for a blank; zero otherwise.
 */
static int chaos_dns_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims blanks in place.
 *
 * @details Writes a NUL over the first trailing blank and returns a pointer to the first
 * non-blank, which may be inside @p text; the buffer must outlive the result.
 *
 * @param text  Writable NUL-terminated string; NULL returns NULL.
 * @return  The trimmed start (the terminator for an all-blank string), or NULL.
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
 * @brief Cuts @p line at its first `#`.
 *
 * @details The format has no quoting or escape: a `#` anywhere starts a comment.
 *
 * @param line  Writable NUL-terminated line; NULL is a no-op.
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
 * @brief ASCII case-insensitive string equality (DNS names are case-insensitive, RFC
 *        4343).
 *
 * @details Uses tolower(), which folds only A-Z in the C locale; a program that set a
 * single-byte locale may also fold bytes above 0x7f.
 *
 * @param left   NUL-terminated string; NULL yields 0.
 * @param right  NUL-terminated string; NULL yields 0.
 * @return  Non-zero if both have the same length and equal characters; zero otherwise.
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
        left_ch = (unsigned char)*left++;
        right_ch = (unsigned char)*right++;
        if (tolower(left_ch) != tolower(right_ch))
        {
            return 0;
        }
    }

    return *left == '\0' && *right == '\0';
}

/**
 * @brief Whether @p text ends with @p suffix, ASCII case-insensitive.
 *
 * @details For SUFFIX matching; chaos_dns_selector_matches_domain() also requires a `.`
 * right before the suffix, so `fooexample.com` does not match `*.example.com`.
 *
 * @param text    NUL-terminated string; NULL yields 0.
 * @param suffix  NUL-terminated suffix; NULL yields 0.
 * @return  Non-zero if @p text ends with @p suffix; zero otherwise.
 */
static int chaos_dns_ascii_case_ends_with(const char *text, const char *suffix)
{
    size_t text_len;
    size_t suffix_len;

    if (text == NULL || suffix == NULL)
    {
        return 0;
    }

    text_len = strlen(text);
    suffix_len = strlen(suffix);
    if (text_len < suffix_len)
    {
        return 0;
    }

    return chaos_dns_ascii_case_equal(text + (text_len - suffix_len), suffix);
}

/* -------------------------------------------------------------------------
 * Selector parsing
 * ------------------------------------------------------------------------- */

/**
 * @brief Parses the part of an `rdns://` selector after the scheme.
 *
 * @details Accepted:
 *   - `*` -- any reverse lookup (ANY).
 *   - An IPv4 literal (`192.168.1.1`).
 *   - An IPv6 literal, bare (`::1`) or bracketed (`[::1]`).
 * Literals are parsed with inet_pton and stored in inet_ntop form, so `[0:0::1]` and
 * the query text for ::1 compare equal. inet_pton(AF_INET) accepts only dotted-quad
 * decimal without leading zeros: glibc and musl reject `1.2.3.004` rather than
 * canonicalise it.
 *
 * @param body      Text after `rdns://`.
 * @param selector  Output; domain REVERSE on success.
 * @return  Non-zero on success; zero for an empty body, a host name, or a malformed
 *          literal.
 */
static int chaos_dns_parse_reverse_selector_body(const char *body, chaos_dns_selector_t *selector)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr ipv4;
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
        selector->kind = CHAOS_DNS_SELECTOR_ANY;
        return 1;
    }

    body_len = strlen(body);
    if (body[0] == '[')
    {
        /* IPv6 may be written [::1]: strip the brackets. */
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
        selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        /* Store the inet_ntop form, the form query keys are built in. */
        return inet_ntop(AF_INET, &ipv4, selector->text, sizeof(selector->text)) != NULL;
    }
    if (inet_pton(AF_INET6, source, &ipv6) == 1)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        return inet_ntop(AF_INET6, &ipv6, selector->text, sizeof(selector->text)) != NULL;
    }

    return 0;
}

/**
 * @brief Parses a selector into @p selector.
 *
 * @details Forms:
 *   - `*`               -- LOOKUP/ANY
 *   - `dns://\*`        -- LOOKUP/ANY
 *   - `dns://host`      -- LOOKUP/EXACT
 *   - `dns://\*.suffix` -- LOOKUP/SUFFIX, text = "suffix"
 *   - `rdns://...`      -- chaos_dns_parse_reverse_selector_body()
 *
 * selector_len is strlen(@p text), the selector as written: the tie-breaker between
 * equal ranks. A `*` anywhere else in a dns:// body is rejected; there are no globs.
 * Host and suffix text are limited to CHAOS_DNS_MAX_TEXT - 1 (255) bytes.
 *
 * @param text      NUL-terminated selector.
 * @param selector  Output; zeroed first.
 * @return  Non-zero on success; zero if @p text is NULL, empty or not a selector.
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
        selector->kind = CHAOS_DNS_SELECTOR_ANY;
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
            body += 2; /* drop the "*." */
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
 * @brief Whether @p selector matches @p name in @p domain, and how specifically.
 *
 * @details Ranks written to @p rank_out: 3 EXACT, 2 SUFFIX, 1 ANY, 0 no match. Domains
 * must be equal. SUFFIX requires @p name to be longer than the suffix, to end with it,
 * and to have a `.` right before it.
 *
 * @param selector  Selector to test.
 * @param domain    Domain of the query (LOOKUP or REVERSE).
 * @param name      Queried host name or address text; NULL or empty yields 0.
 * @param rank_out  Optional output: the rank, 0 when there is no match.
 *
 * @return  Non-zero on a match; zero otherwise.
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

    name_len = strlen(name);
    suffix_len = strlen(selector->text);
    if (name_len <= suffix_len)
    {
        return 0;
    }
    if (!chaos_dns_ascii_case_ends_with(name, selector->text))
    {
        return 0;
    }
    /* A dot must precede the suffix: "fooexample.com" must not match "*.example.com". */
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
 * Value parsing
 * ------------------------------------------------------------------------- */

/**
 * @brief Parses a probability, locale-independently (chaos_policy_parse_probability()).
 *
 * @details Accepts "0", "1", "0." followed by digits, or "1." followed by zeros.
 *
 * @param text         Probability text; must not be NULL.
 * @param probability  Output; must not be NULL.
 * @return 0 on success; -1 when @p text is not a probability.
 */
static int chaos_dns_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
}

/**
 * @brief Parses a LATENCY delay in ms.
 *
 * @details strtoul semantics (leading blanks and a sign accepted; "-1" wraps above the
 * limit and is rejected), trailing blanks allowed, nothing else after the digits. The
 * limit, 0xffffffff ms, is the range of the unsigned int field: about 49.7 days.
 *
 * @param text        Decimal text.
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
 * @brief Parses a LIMIT count in [1, 0xffffffff].
 *
 * @details Same syntax as chaos_dns_parse_latency(). Zero is rejected: a limit of zero
 * would turn every lookup into EAI_NONAME, which a GAI rule expresses explicitly.
 *
 * @param text   Decimal text.
 * @param limit  Output; >= 1 on success.
 * @return  0 on success; -1 on failure or zero.
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
    /* Zero is rejected: an empty answer is a GAI rule's job, not a LIMIT's. */
    if (end == text || *chaos_dns_trim(end) != '\0' || value == 0UL || value > 0xffffffffUL)
    {
        return -1;
    }

    *limit = (unsigned int)value;
    return 0;
}

/**
 * @brief Whether @p effect may be used with @p selector's domain.
 *
 * @details dns:// selectors accept every effect. rdns:// selectors accept only GAI,
 * LATENCY, REWRITE (the returned host name) and SERVICE (the returned service name):
 * OVERRIDE, FILTER_FAMILY, SHUFFLE and LIMIT shape an address list, which a reverse
 * lookup does not return.
 *
 * @param selector  The parsed selector.
 * @param effect    The effect to check.
 * @return  Non-zero if allowed; zero otherwise.
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

    return effect == CHAOS_DNS_EFFECT_GAI || effect == CHAOS_DNS_EFFECT_LATENCY ||
           effect == CHAOS_DNS_EFFECT_REWRITE || effect == CHAOS_DNS_EFFECT_SERVICE;
}

/**
 * @brief Parses a FILTER_FAMILY value.
 *
 * @details Case-sensitive tokens:
 *   - `inet4` or `ipv4` -> CHAOS_DNS_FAMILY_INET4
 *   - `inet6` or `ipv6` -> CHAOS_DNS_FAMILY_INET6
 *   - `any`             -> CHAOS_DNS_FAMILY_ANY (parses, but filters nothing)
 *
 * @param text  Token; NULL yields INVALID.
 * @return  The family, or CHAOS_DNS_FAMILY_INVALID.
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
 * @brief Maps an EAI_* name to its value.
 *
 * @details Accepted (exact, case-sensitive): EAI_AGAIN, EAI_FAIL, EAI_NONAME, EAI_MEMORY,
 * EAI_SYSTEM. Anything else yields 0x7fffffff, which no EAI_* constant equals (they are
 * small negative numbers on glibc and musl), so the caller can tell "not an EAI name"
 * from a valid code.
 *
 * @param text  Effect field of a rule line.
 * @return  The EAI_* value, or 0x7fffffff.
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
 * @brief Copies a non-empty string into a fixed buffer.
 *
 * @param text         Source string.
 * @param target       Destination buffer.
 * @param target_size  Size of @p target in bytes.
 * @return  0 on success; -1 if @p text is empty, does not fit with its NUL, or a pointer
 *          is NULL.
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
 * @brief Splits `<payload>[@<probability>]` into the payload and the probability.
 *
 * @details The last `@` is the separator, so a payload may itself contain `@`. Without
 * one, the probability is 1.0. The payload is trimmed; it and the probability text must
 * both be non-empty.
 *
 * @param text          The value field.
 * @param payload       Output buffer for the payload.
 * @param payload_size  Size of @p payload.
 * @param probability   Output: the parsed probability, or 1.0.
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
 * @brief Whether @p token is an IPv4 or IPv6 literal (`192.168.1.1`, `::1`, `[::1]`).
 *
 * @details Validated with inet_pton, so the accepted set is the set the real
 * getaddrinfo resolves under AI_NUMERICHOST without a query.
 *
 * @param token  NUL-terminated token.
 * @return  Non-zero if valid; zero otherwise.
 */
static int chaos_dns_override_token_valid(const char *token)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr ipv4;
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
 * @brief Whether @p text is a non-empty comma-separated list of IP literals.
 *
 * @details Splits a copy on commas, trims each token and validates it with
 * chaos_dns_override_token_valid(); an empty token (`a,,b`) is invalid. The count limit
 * of 32 literals is enforced at lookup time (chaos_dns_apply_override()), not here.
 *
 * @param text  Override value; not modified.
 * @return  Non-zero if every token is a valid literal; zero otherwise.
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
        char *token = cursor;
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
 * Change stamp
 * ------------------------------------------------------------------------- */

/**
 * @brief Moves a computed stamp off the three reserved values.
 *
 * @details A stamp equal to MISSING (0), RELOADING (2^64 - 2) or UNKNOWN (2^64 - 1) is
 * XORed with the golden-ratio constant; for these three inputs the result is never
 * itself reserved. A collision would be rare (3 in 2^64) but would misread as "no file",
 * "reload in progress" or "never loaded".
 *
 * @param value  Stamp from chaos_dns_config_hash_mtime().
 * @return  @p value, or the remapped value on a collision.
 */
static uint64_t chaos_dns_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_DNS_MTIME_MISSING || value == CHAOS_DNS_MTIME_RELOADING ||
        value == CHAOS_DNS_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

/**
 * @brief 64-bit change stamp of the rule file: FNV-1a-style mix of mtime, size, inode and
 *        device.
 *
 * @details mtime alone is not enough: file systems stamp it from a coarse clock (a few
 * ms), so two writes in one tick leave it unchanged. The size catches an append, the
 * inode a rewrite through a temporary file and rename(2) (`sed -i`), even within one
 * tick; a same-size in-place rewrite within one tick is left to the provisional re-read.
 * The multiplier is the FNV-1a 64-bit prime; the start value 1469598103934665603 is the
 * FNV offset basis (14695981039346656037) without its last digit. Any fixed start works
 * for change detection, so this costs nothing but the name.
 *
 * @param st  stat/fstat result, or NULL for a missing file.
 * @return  The normalised stamp, or CHAOS_DNS_MTIME_MISSING for NULL.
 */
static uint64_t chaos_dns_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_DNS_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_DNS_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
    value *= UINT64_C(1099511628211);
    return chaos_dns_config_normalize_mtime_hash(value);
}

/**
 * @brief stat(2)s the rule file and returns its change stamp.
 *
 * @details stat goes through libc, so other preloaded libraries that wrap it see it; the
 * guard only keeps libchaos-dns's own wrappers out.
 *
 * @return  The stamp, or CHAOS_DNS_MTIME_MISSING if stat fails for any reason.
 * @par errno: clobbered; chaos_dns_config_prepare() restores it.
 */
static uint64_t chaos_dns_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = stat(CHAOS_DNS_CONFIG_PATH, &st);
    chaos_dns_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    return chaos_dns_config_hash_mtime(&st);
}

/**
 * @brief Reads the whole rule file into g_chaos_dns_config_buffer and checks it is still
 *        the file whose stamp triggered the reload.
 *
 * @details CHAOS_CONFIG_FILE_OPEN/READ/CLOSE are raw openat/read/close system calls on
 * Linux, so libchaos-io neither sees nor faults the library's own read. EINTR is retried.
 * After EOF, fstat must reproduce @p expected_stamp; a writer that rewrote or appended
 * meanwhile could have left a half-old, half-new copy. On success the mtime decides
 * whether the load is provisional, and the buffer is NUL-terminated.
 *
 * @param size_out        Output: bytes read, NUL not counted.
 * @param expected_stamp  Stamp observed by the stat that triggered this reload.
 * @return  0 on success; -1 transient (open/read error, file changed): retry later;
 *          -2 file is CHAOS_DNS_MAX_CONFIG_BYTES or larger; -3 EACCES/EPERM on open or
 *          EISDIR on read. -2 and -3 reject the file until it changes.
 */
static int chaos_dns_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_dns_enter_internal();
    do
    {
        fd = CHAOS_CONFIG_FILE_OPEN(CHAOS_DNS_CONFIG_PATH);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* EACCES/EPERM persist until the file changes; anything else (gone since the
         * stat, out of descriptors, ...) is retried on the next look. */
        const int open_error = errno;

        chaos_dns_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = CHAOS_CONFIG_FILE_READ(
            fd, g_chaos_dns_config_buffer + total, CHAOS_DNS_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_dns_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        /* Filling the buffer means the file is at or over the limit: reject, do not cut. */
        if (total == CHAOS_DNS_MAX_CONFIG_BYTES)
        {
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_dns_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose stamp triggered this reload. A writer that
     * rewrote or appended to it during the read leaves a different stamp; the copy may
     * be half old, half new, so it is discarded and the next look reloads the finished
     * file. */
    if (fstat(fd, &st) != 0 || chaos_dns_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_dns_leave_internal(previous);
        return -1;
    }
    g_chaos_dns_config_provisional = chaos_clock_stamp_is_recent(
        (int64_t)CHAOS_DNS_STAT_SEC(&st), (long)CHAOS_DNS_STAT_NSEC(&st)
    );

    CHAOS_CONFIG_FILE_CLOSE(fd);
    chaos_dns_leave_internal(previous);
    g_chaos_dns_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Splits a trimmed rule line into selector, effect and value.
 *
 * @details Form:
 * @code
 *   <selector> : <effect> : <value>
 * @endcode
 * The selector end is found by its scheme, so the `:` of `://` and of an IPv6 address
 * are not taken as separators:
 *   - `*:` -- a bare `*` immediately followed by `:` (no blank in between);
 *   - `dns://...` and unbracketed `rdns://...` -- the first `:` after the scheme;
 *   - `rdns://[...]` -- the `]` must be followed directly by `:`.
 * The effect ends at the next `:`; the value is the rest (it may contain `:`, e.g. an
 * OVERRIDE list of IPv6 literals). Fields are trimmed; @p line is modified in place.
 *
 * @param line           Writable line, comment already cut.
 * @param selector_text  Output: selector field.
 * @param effect_text    Output: effect field.
 * @param value_text     Output: value field.
 * @return  Non-zero on success; zero for an unrecognised selector or a missing `:`.
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
        /* Bracketed IPv6: the ']' must be followed directly by ':'. */
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
    *effect_text = chaos_dns_trim(selector_end);
    *value_text = chaos_dns_trim(effect_end);
    return 1;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

/**
 * @brief Resets the rule subsystem (contract in chaos_dns_config.h).
 *
 * @details Also records the pid and hits-file number for the hits report. Both snapshots
 * end with an even sequence, index 0 active, stamp CHAOS_DNS_MTIME_UNKNOWN.
 */
void chaos_dns_config_init(void)
{
    g_chaos_dns_hits_pid = (uint64_t)getpid();
    g_chaos_dns_hits_file = chaos_hits_file_number(CHAOS_DNS_HITS_PREFIX);
    g_chaos_dns_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_dns_hit_pool, sizeof(g_chaos_dns_hit_pool) / sizeof(g_chaos_dns_hit_pool[0])
    );
    if (!g_chaos_dns_atfork_registered)
    {
        g_chaos_dns_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_dns_config_after_fork);
    }
    /* Resolve the vDSO clock now, not first inside a wrapper a signal handler re-entered. */
    (void)chaos_clock_now_ns();
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[0], 1);
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_dns_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_dns_config_states[1].sequence);
    g_chaos_dns_active_config_index = 0U;
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;
}

/**
 * @brief Parses one rule line (contract in chaos_dns_config.h).
 *
 * @details The effect field is tried as an EAI_* name first (effect GAI), then against
 * the keywords. OVERRIDE, FILTER_FAMILY, LIMIT and SHUFFLE check the selector domain
 * before parsing their value; GAI, LATENCY, REWRITE and SERVICE are valid in both
 * domains.
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

    /* GAI, LATENCY, REWRITE and SERVICE apply to lookups and reverse lookups alike, the
     * only domains chaos_dns_selector_parse() produces: only the other effects ask
     * chaos_dns_effect_allowed(). */
    gai_error = chaos_dns_parse_gai_name(effect_text);
    if (gai_error != 0x7fffffff)
    {
        rule->effect = CHAOS_DNS_EFFECT_GAI;
        rule->gai_error = gai_error;
        return chaos_dns_parse_probability(value_text, &rule->probability) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_LATENCY;
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
 * @brief Parses a whole rule file (contract in chaos_dns_config.h).
 *
 * @details All or nothing: the first rejected line ends the parse with -1, so a partly
 * valid file never yields a partial rule set. The line as written is kept in the error
 * record before the parser edits it; the same copy becomes the rule's hits-file text.
 */
int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;
    size_t number = 0U;

    chaos_status_clear(&g_chaos_dns_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_dns_rule_t parsed;
        chaos_rule_policy_t policy;
        int rc;

        while (*cursor != '\0' && *cursor != '\n')
        {
            ++cursor;
        }
        if (*cursor == '\n')
        {
            *cursor++ = '\0';
        }

        /* The parser edits the line in place; keep it as written for the report. */
        chaos_status_keep_line(&g_chaos_dns_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_dns_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_dns_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_dns_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers on a blank or comment-only line: invalid. */
                chaos_status_reject(&g_chaos_dns_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_DNS_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_dns_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_dns_config_texts[count],
            g_chaos_dns_config_error.text,
            sizeof(g_chaos_dns_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_dns_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_dns_config_last_error(void)
{
    return &g_chaos_dns_config_error;
}

/**
 * @brief Best rule for @p domain, @p effect and @p name in @p rules.
 *
 * @details Considers every rule: highest rank wins, then the longer selector text, then
 * (strict comparisons) the earlier rule. The winner is copied by value, so the caller
 * holds no reference into a snapshot.
 *
 * @param rules       Rule array.
 * @param rule_count  Valid entries.
 * @param effect      Effect to match.
 * @param domain      LOOKUP or REVERSE.
 * @param name        Host name or address text.
 * @param rule        Output: the winning rule.
 * @return  Non-zero if a rule matched; zero otherwise.
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
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

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
            *rule = rules[index];
            best_rank = rank;
            best_len = rules[index].selector.selector_len;
            found = 1;
        }
    }

    return found;
}

/**
 * @brief Best forward-lookup rule (contract in chaos_dns_config.h).
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
 * @brief Best reverse-lookup rule (contract in chaos_dns_config.h).
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
 * @brief Publishes @p state as "file rejected as a whole" with @p reason.
 *
 * @details For conditions that persist until the file changes: too large (TOO_LARGE),
 * not openable (EACCES/EPERM) or a directory (UNREADABLE), a NUL byte (NUL). Unlike a
 * transient read failure the file is not re-read on every look: the snapshot has no
 * rules, the status file says state=error, and the next stamp change retries.
 */
static void chaos_dns_config_reject_file(chaos_dns_config_state_t *state, const char *reason)
{
    chaos_dns_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_dns_config_error);
    chaos_status_reject(&g_chaos_dns_config_error, reason);
}

/**
 * @brief Writes this process's hit counts after a hit on @p slot (NULL: forced, at exit
 *        or after an idle interval).
 *
 * @details Rate: each of the first CHAOS_HITS_EAGER (64) hits, then at most every
 * CHAOS_HITS_INTERVAL_MS (100 ms); a NULL call writes whatever is pending. One writer at
 * a time, chosen by CAS, never by waiting (a signal handler may hit while this thread
 * writes): a hit that finds the writer busy leaves `pending` set, and the writer loops
 * until nothing is pending. Only the pid the counts belong to writes, which keeps a
 * vfork() child, sharing this memory, out. A fork() child starts from zero (atfork).
 */
static void chaos_dns_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_dns_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_dns_hits_total;
        if (g_chaos_dns_hits_pending == 0)
        {
            g_chaos_dns_hits_pending = 1;
        }
        /* Past the eager phase and inside the interval: counters only, no system
         * call. */
        if (g_chaos_dns_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_dns_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_dns_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but is another process and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_dns_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_dns_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_dns_config_state_t *)chaos_dns_config_active_state();
        while (g_chaos_dns_hits_pending != 0)
        {
            g_chaos_dns_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_DNS_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_dns_hits_file,
                &g_chaos_dns_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_dns_hits_buffer,
                sizeof(g_chaos_dns_hits_buffer)
            );
        }
        g_chaos_dns_hits_last_ms = now;
        __sync_lock_release(&g_chaos_dns_hits_writing);
        __sync_synchronize();
        /* A hit that found the writer busy after the last check is written now. */
    } while (g_chaos_dns_hits_pending != 0);
}

/**
 * @brief fork() child handler: drops the state of parent threads that do not exist here.
 *
 * @details Registered with pthread_atfork() by chaos_dns_config_init(). A reload claim
 * held at the fork reverts to CHAOS_DNS_MTIME_UNKNOWN (the next call reloads), the hits
 * writer flag is cleared, counts restart at zero for the child's pid and hits file, the
 * PRNG is reseeded on its next draw, and @first claims restart
 * (chaos_hits_pool_after_fork()). vfork() children and posix_spawn run no handler: they
 * share the parent's memory, see its claims as busy and write nothing.
 */
static void chaos_dns_config_after_fork(void)
{
    if (g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_RELOADING)
    {
        g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;
    }
    g_chaos_dns_hits_writing = 0;
    g_chaos_dns_hits_pending = 0;
    g_chaos_dns_hits_total = 0U;
    g_chaos_dns_hits_last_ms = 0U;
    g_chaos_dns_hits_pid = (uint64_t)getpid();
    g_chaos_dns_hits_file = chaos_hits_file_number(CHAOS_DNS_HITS_PREFIX);
    g_chaos_dns_hits_owned = 0;
    /* The child must not draw the parent's numbers (pre-fork workers would all decide
     * alike): its PRNG reseeds from its own thread id on the next draw. */
    g_chaos_dns_tls_prng_state = 0U;
    chaos_hits_pool_after_fork(
        g_chaos_dns_hit_pool,
        sizeof(g_chaos_dns_hit_pool) / sizeof(g_chaos_dns_hit_pool[0]),
        chaos_dns_config_active_state()->hits,
        chaos_dns_config_active_state()->rule_count
    );
}

/** @brief Writes pending hit counts at normal exit (exit() or return from main). */
__attribute__((destructor)) static void chaos_dns_config_report_hits_at_exit(void)
{
    chaos_dns_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its text, hit slot and generation.
 *
 * @details A rule whose text equals one in the active snapshot keeps that rule's slot
 * (chaos_hits_assign()), so adding a rule does not reset the others' counts, and a firing
 * through a rule copy taken before the reload still lands on the right counter.
 */
static void chaos_dns_config_attach_hits(chaos_dns_config_state_t *next_state)
{
    const chaos_dns_config_state_t *active = chaos_dns_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index],
            g_chaos_dns_config_texts[index],
            sizeof(next_state->text[index])
        );
    }
    chaos_hits_assign(
        g_chaos_dns_hit_pool,
        sizeof(g_chaos_dns_hit_pool) / sizeof(g_chaos_dns_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_dns_config_report_hits
    );
    for (index = 0U; index < next_state->rule_count; ++index)
    {
        next_state->rules[index].hit = next_state->hits[index];
        next_state->rules[index].hit_generation =
            next_state->hits[index] != NULL ? next_state->hits[index]->generation : 0U;
    }
}

/**
 * @brief Writes the status file for the load that produced @p state.
 *
 * @details Called by the reload owner before publishing. No rule file: the status file
 * is removed. Rejected file: state=error with line and reason. Otherwise state=ok with
 * the rule count.
 */
static void chaos_dns_config_report(uint64_t observed_mtime, const chaos_dns_config_state_t *state)
{
    if (observed_mtime == CHAOS_DNS_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_DNS_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(
            CHAOS_DNS_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_dns_config_error
        );
    }
    else
    {
        chaos_status_write(CHAOS_DNS_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/** @brief Last look at the rule file (vDSO CLOCK_MONOTONIC, ns); see chaos_clock.h. */
static volatile uint64_t g_chaos_dns_last_check_ns = 0U;

/** @brief Look throttle in ns: CHAOS_CHECK_INTERVAL_NS (1 ms); unit tests set 0 (every call). */
static uint64_t g_chaos_dns_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details A look is a stat(2), the largest part of a wrapper's cost. After the first
 * completed load the file is looked at no more than once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms) per process, so a change takes effect within 1 ms instead of on the next call.
 * Every call looks while no load has completed (UNKNOWN), while another thread holds the
 * claim (RELOADING), and when no vDSO clock is available (chaos_clock_now_ns() returns 0).
 * The timestamp is a plain word: two threads racing on it at worst both look.
 */
static int chaos_dns_config_checked_recently(void)
{
    const uint64_t cached = chaos_dns_atomic_load_u64(&g_chaos_dns_cached_mtime);

    if (cached == CHAOS_DNS_MTIME_UNKNOWN || cached == CHAOS_DNS_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(&g_chaos_dns_last_check_ns, g_chaos_dns_check_interval_ns);
}

/**
 * @brief Looks for a change of the rule file and reloads it if needed.
 *
 * @details The protocol and failure behaviour of the file header. Also flushes hits
 * pending for longer than CHAOS_HITS_INTERVAL_MS, so a process that stopped hitting
 * still reports its last hits. Every early return reports the active snapshot.
 *
 * @return  Non-zero if the snapshot active afterwards parsed and has at least one rule.
 * @par errno: clobbered; see chaos_dns_config_prepare().
 */
static int chaos_dns_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size = 0U;
    uint64_t content = 0U;
    chaos_dns_config_state_t *next_state;

    if (chaos_dns_config_checked_recently())
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    /* Hits of an interval that is over are written now, not only at the next hit or at
     * exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_dns_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_dns_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_dns_config_report_hits(NULL);
    }
    observed_mtime = chaos_dns_config_observed_mtime();
    cached_mtime = chaos_dns_atomic_load_u64(&g_chaos_dns_cached_mtime);

    if (observed_mtime == cached_mtime && !g_chaos_dns_config_provisional)
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    /* Another thread of this process owns the reload: use the active snapshot. Without
     * this check the CAS below would succeed as RELOADING -> RELOADING and two threads
     * would fill the same inactive snapshot and read buffer. A claim inherited through
     * fork() was already released by the atfork handler; a vfork child must not take
     * over its parent's. */
    if (cached_mtime == CHAOS_DNS_MTIME_RELOADING)
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    if (!chaos_dns_atomic_cas_u64(
            &g_chaos_dns_cached_mtime, cached_mtime, CHAOS_DNS_MTIME_RELOADING
        ))
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    g_chaos_dns_config_provisional = 0;

    active_index = g_chaos_dns_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_dns_config_states[next_index];
    chaos_dns_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_DNS_MTIME_MISSING)
    {
        const int read_rc = chaos_dns_config_read_file(&config_size, observed_mtime);

        if (read_rc == -2 || read_rc == -3)
        {
            chaos_dns_config_reject_file(
                next_state,
                read_rc == -2 ? CHAOS_STATUS_REASON_TOO_LARGE : CHAOS_STATUS_REASON_UNREADABLE
            );
            config_size = 0U;
        }
        else if (read_rc != 0)
        {
            /* A failed read says nothing about the rules: keep the active snapshot and
             * release the claim with the previous stamp, so the next look retries
             * instead of running with no rules until the file changes again. */
            __sync_synchronize();
            g_chaos_dns_cached_mtime = cached_mtime;
            return chaos_dns_config_active_state()->rule_count != 0U;
        }
        if (read_rc == 0)
        {
            content = chaos_config_content_hash(g_chaos_dns_config_buffer, config_size);
            if (observed_mtime == cached_mtime && content == g_chaos_dns_config_content)
            {
                /* A provisional load re-read and found the same bytes: the snapshot
                 * stays, with its hit counts and @first claims. */
                __sync_synchronize();
                g_chaos_dns_cached_mtime = cached_mtime;
                return chaos_dns_config_active_state()->rule_count != 0U;
            }
        }
        if (config_size > 0U && memchr(g_chaos_dns_config_buffer, '\0', config_size) != NULL)
        {
            /* The parser would stop at the NUL and drop every later rule unreported. */
            chaos_dns_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
            config_size = 0U;
        }
        if (config_size > 0U &&
            chaos_dns_config_parse_buffer(
                g_chaos_dns_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Rejected: parse_ok = 0, so this snapshot never matches. */
            chaos_dns_config_reset_state(next_state, 0);
        }
    }

    g_chaos_dns_config_content = content;
    chaos_dns_config_attach_hits(next_state);
    chaos_dns_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load are freed and marked outdated for rule
     * copies still held. Done before the publish, while this thread holds the claim. */
    chaos_hits_release(
        g_chaos_dns_hit_pool,
        sizeof(g_chaos_dns_hit_pool) / sizeof(g_chaos_dns_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_dns_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Reloads the rule file if it changed, preserving errno.
 *
 * @details The stat, openat, read and status-file calls of a reload belong to the
 * library: a wrapped call that then succeeds must not report, say, the ENOENT of a
 * missing rule file.
 */
int chaos_dns_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_dns_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @brief Forward match in the active snapshot, seqlock-validated (contract in the header).
 */
int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_rule(state->rules, state->rule_count, effect, name, rule) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
}

/**
 * @brief Reverse match in the active snapshot, seqlock-validated (contract in the header).
 */
int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_reverse_rule(
               state->rules, state->rule_count, effect, address, rule
           ) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
}

/**
 * @brief Prepare, then forward match (contract in chaos_dns_config.h).
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
 * @brief Prepare, then reverse match (contract in chaos_dns_config.h).
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
