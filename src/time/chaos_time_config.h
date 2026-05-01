/**
 * @file chaos_time_config.h
 * @brief Configuration data model and config-access API for libchaos-time.
 *
 * Declares the types that represent a parsed chaos rule and the functions that
 * load, reload, parse, and query rules from the config file at
 * CHAOS_TIME_CONFIG_PATH (/tmp/.chaos-time.conf).
 *
 * ### Config file format
 *
 * Each non-blank, non-comment line has the form:
 * @verbatim
 *   <selector> : <effect> : <value>[@<probability>]
 * @endverbatim
 *
 * **Selectors** identify which call sites are affected:
 *  - `*`                        — all intercepted functions
 *  - `clock_gettime`            — all clock_gettime calls regardless of clock
 *  - `clock_gettime/monotonic`  — clock_gettime for CLOCK_MONOTONIC only
 *  - `nanosleep`                — all nanosleep calls
 *  - `usleep`                   — all usleep calls
 *
 * **Effects** and their value syntax:
 *  - `ERRNO EINVAL[@0.5]`    — return -1/errno before the real call
 *  - `LATENCY 250[@0.1]`     — sleep 250 ms before the real call
 *  - `OFFSET -1000[@1.0]`    — shift the returned timespec by -1000 ms
 *
 * **OFFSET restriction**: OFFSET is only valid on clock_gettime selectors
 * (not on `*`, `nanosleep`, or `usleep`) because it operates on the
 * struct timespec output parameter, which sleep functions do not produce.
 *
 * ### Live reload
 *
 * The config file is re-read on every intercepted call that finds the file's
 * mtime hash has changed.  Reload uses a two-snapshot CAS protocol (see
 * chaos_time_config.c) so that readers on other threads always see either the
 * previous complete ruleset or the new complete ruleset — never a partially
 * written one.
 *
 * @module chaos-time
 * @stability Internal.
 */

#ifndef CHAOS_TIME_CONFIG_H
#define CHAOS_TIME_CONFIG_H

#include "chaos_time_internal.h"

/**
 * @brief Identifies which libc symbol an interceptor invocation came from.
 *
 * Used as a discriminant when matching rules: a rule whose selector names
 * "nanosleep" will only match calls that arrived through the nanosleep wrapper,
 * not through clock_gettime.
 */
typedef enum chaos_time_operation
{
    CHAOS_TIME_OP_INVALID = -1,   /**< Sentinel — never stored in a valid rule. */
    CHAOS_TIME_OP_CLOCK_GETTIME = 0, /**< Call originated from clock_gettime(2). */
    CHAOS_TIME_OP_NANOSLEEP,      /**< Call originated from nanosleep(2). */
    CHAOS_TIME_OP_USLEEP          /**< Call originated from usleep(3). */
} chaos_time_operation_t;

/**
 * @brief Describes the type of match a selector performs.
 *
 * Determines which fields of chaos_time_selector_t are meaningful and what
 * specificity rank the selector receives during rule selection.
 */
typedef enum chaos_time_selector_kind
{
    CHAOS_TIME_SELECTOR_INVALID = -1, /**< Unparseable or uninitialised selector. */
    /**
     * Matches every intercepted function (config text: `*`).
     * Lowest specificity rank (1); overridden by any operation or clock-ID
     * selector on the same effect.
     */
    CHAOS_TIME_SELECTOR_ANY = 0,
    /**
     * Matches all calls to a specific operation regardless of clock_id
     * (e.g. `clock_gettime`, `nanosleep`, `usleep`).
     * Medium specificity rank (2).
     */
    CHAOS_TIME_SELECTOR_OPERATION,
    /**
     * Matches a specific operation restricted to a specific POSIX clock ID
     * (e.g. `clock_gettime/monotonic`).
     * Highest specificity rank (3).
     * Only valid for CHAOS_TIME_OP_CLOCK_GETTIME.
     */
    CHAOS_TIME_SELECTOR_CLOCK_ID
} chaos_time_selector_kind_t;

/**
 * @brief The chaos fault type that a rule injects.
 */
typedef enum chaos_time_effect
{
    CHAOS_TIME_EFFECT_INVALID = -1, /**< Unparseable or uninitialised effect. */
    /**
     * Pre-call fault: sets errno and returns -1 without calling the real
     * function.  Probability-gated.
     */
    CHAOS_TIME_EFFECT_ERRNO = 0,
    /**
     * Pre-call delay: sleeps for a configured number of milliseconds before
     * calling the real function.  Uses the real sleep implementation to avoid
     * recursion.  Probability-gated.
     */
    CHAOS_TIME_EFFECT_LATENCY,
    /**
     * Post-call time shift: applies a signed millisecond delta to the
     * struct timespec returned by clock_gettime(2).  See chaos_time_rule_t
     * for the precise semantics and the monotonicity caveat.
     * Only valid with CHAOS_TIME_SELECTOR_CLOCK_ID or
     * CHAOS_TIME_SELECTOR_OPERATION on CHAOS_TIME_OP_CLOCK_GETTIME.
     * Probability-gated.
     */
    CHAOS_TIME_EFFECT_OFFSET
} chaos_time_effect_t;

/**
 * @brief Parsed representation of a config-file selector token.
 *
 * A selector identifies the set of call sites that a rule applies to.  The
 * @c kind field determines which other fields carry meaningful data.
 *
 * @invariant  For CHAOS_TIME_SELECTOR_CLOCK_ID, @c clock_id holds a valid
 *             POSIX clock constant and @c text holds the clock name string
 *             (NUL-terminated, length < CHAOS_TIME_MAX_TEXT).
 * @invariant  For CHAOS_TIME_SELECTOR_ANY, @c operation is
 *             CHAOS_TIME_OP_INVALID and @c clock_id is 0.
 * @invariant  @c selector_len is strlen(original_text_token) at parse time;
 *             used as a tiebreaker during rule selection (longer text = more
 *             specific, though in practice all clock names are distinct).
 */
typedef struct chaos_time_selector
{
    chaos_time_selector_kind_t kind;  /**< Selector type; determines which other fields are valid. */
    chaos_time_operation_t operation; /**< Intercepted function; INVALID for SELECTOR_ANY. */
    clockid_t clock_id;               /**< POSIX clock constant; meaningful for SELECTOR_CLOCK_ID only. */
    size_t selector_len;              /**< Length of the original selector text, used as a specificity tiebreaker. */
    char text[CHAOS_TIME_MAX_TEXT];   /**< Clock name string for SELECTOR_CLOCK_ID (e.g. "monotonic"); NUL-terminated. */
} chaos_time_selector_t;

/**
 * @brief A single parsed chaos injection rule.
 *
 * One rule corresponds to one non-blank, non-comment line in the config file.
 * Rules are stored in a fixed-size array inside chaos_time_config_state_t and
 * matched at call time by chaos_time_config_match().
 *
 * ### Effect-specific field semantics
 *
 * - **ERRNO** uses @c errnum and @c probability.
 *   @c latency_ms and @c offset_ms are zero.
 *
 * - **LATENCY** uses @c latency_ms and @c probability.
 *   @c errnum and @c offset_ms are zero.
 *
 * - **OFFSET** uses @c offset_ms and @c probability.
 *   @c errnum and @c latency_ms are zero.
 *   The signed delta is applied after the real clock_gettime returns; it does
 *   **not** modify the kernel clock.  For CLOCK_MONOTONIC this deliberately
 *   breaks the monotonicity guarantee at the ABI boundary — two consecutive
 *   calls that straddle a config reload or are subject to different probability
 *   outcomes may return timestamps that go backwards.  This is intentional: the
 *   purpose is to exercise application code that should tolerate such
 *   conditions.  Thread-safety: the offset is stateless — every call applies
 *   the same delta independently; there is no per-thread accumulation.
 *
 * @invariant  @c probability is in [0.0, 1.0].
 * @invariant  @c effect is not CHAOS_TIME_EFFECT_INVALID in a stored rule.
 * @invariant  @c selector.kind is not CHAOS_TIME_SELECTOR_INVALID in a stored rule.
 */
typedef struct chaos_time_rule
{
    chaos_time_selector_t selector;  /**< Identifies the call sites this rule applies to. */
    chaos_time_effect_t effect;      /**< The fault type to inject. */
    int errnum;                      /**< Errno value to set for EFFECT_ERRNO; 0 for other effects. */
    double probability;              /**< Injection probability in [0.0, 1.0]; 1.0 = always inject. */
    unsigned int latency_ms;         /**< Pre-call delay in milliseconds for EFFECT_LATENCY; 0 otherwise. */
    int64_t offset_ms;               /**< Signed time shift in milliseconds for EFFECT_OFFSET; 0 otherwise. */
} chaos_time_rule_t;

/**
 * Initialises the config subsystem to a known clean state.
 *
 * Zeros both config state snapshots, sets the active index to 0, and marks
 * the cached mtime as CHAOS_TIME_MTIME_UNKNOWN so that the very first call to
 * chaos_time_config_prepare() triggers a file reload.
 *
 * Called once from chaos_time_init() during library construction.
 * Not thread-safe; must be called before any wrapper is invoked.
 */
void chaos_time_config_init(void);

/**
 * Checks whether the config file has changed and, if so, reloads it.
 *
 * Implements the two-snapshot CAS reload protocol:
 *
 *  1. Stat the config file to obtain its current mtime hash.
 *  2. Compare against the cached mtime with an atomic load.
 *  3. If equal, return immediately (no change).
 *  4. Attempt a CAS from the cached value to CHAOS_TIME_MTIME_RELOADING.
 *     If the CAS fails, another thread is already reloading; return the
 *     current active state.
 *  5. Determine the inactive snapshot index (the one not currently pointed to
 *     by g_chaos_time_active_config_index), load and parse the file into it,
 *     then publish it by updating the active index and mtime atomically.
 *
 * @return  Non-zero if at least one rule is currently loaded and the config
 *          parsed without error; zero otherwise.
 */
int chaos_time_config_prepare(void);

/**
 * Queries the active config snapshot for a matching rule without triggering
 * a reload.
 *
 * Reads the active snapshot index with a full memory barrier, then delegates
 * to chaos_time_config_select_rule().  Intended for internal use when a fresh
 * reload has just been performed by chaos_time_config_prepare().
 *
 * @param effect     The fault type to search for.
 * @param operation  The intercepted function the call came from.
 * @param clock_id   The POSIX clock ID; ignored for non-clock_gettime
 *                   operations.
 * @param rule       Output: populated with the matched rule on success.
 * @return           Non-zero if a matching rule was found, zero otherwise.
 */
int chaos_time_config_match_loaded(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

/**
 * Full-featured rule lookup: reloads config if needed, then searches for a
 * matching rule.
 *
 * This is the primary entry point used by the hook wrappers in
 * chaos_time_hooks.c.  Calls chaos_time_config_prepare() first; if the config
 * is empty or unparseable, returns 0 without populating @p rule.
 *
 * @param effect     The fault type to search for.
 * @param operation  The intercepted function the call came from.
 * @param clock_id   The POSIX clock ID; ignored for non-clock_gettime
 *                   operations.
 * @param rule       Output: populated with the matched rule on success.
 *                   Must not be NULL.
 * @return           Non-zero if a matching rule was found, zero otherwise.
 */
int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

/**
 * Parses a single config file line into a chaos_time_rule_t.
 *
 * The line is mutated in-place (comment stripped, trimmed, split on ':').
 * Blank and pure-comment lines return 0 (skip); malformed lines return -1
 * (parse error that aborts the whole buffer parse); valid rules return 1.
 *
 * @param line  Mutable NUL-terminated line buffer.  Modified in-place.
 * @param rule  Output: populated on return value 1.
 * @return      1 on success, 0 on blank/comment line, -1 on parse error.
 */
int chaos_time_config_parse_line(char *line, chaos_time_rule_t *rule);

/**
 * Parses a complete NUL-terminated config file buffer into an array of rules.
 *
 * Splits @p buffer on newline characters (modifying it in-place) and calls
 * chaos_time_config_parse_line() for each segment.  Stops and returns -1 if
 * any line fails to parse or if the rule count would exceed
 * CHAOS_TIME_MAX_RULES.
 *
 * @param buffer      Mutable NUL-terminated config file content.
 * @param rules       Caller-allocated array of at least CHAOS_TIME_MAX_RULES
 *                    elements.
 * @param rule_count  Output: number of rules written to @p rules.
 * @return            0 on success, -1 on any parse error.
 */
int chaos_time_config_parse_buffer(char *buffer, chaos_time_rule_t *rules, size_t *rule_count);

/**
 * Selects the best-matching rule from a rule array for a given
 * (effect, operation, clock_id) triple.
 *
 * Iterates the entire array and picks the rule with the highest specificity
 * rank (CLOCK_ID > OPERATION > ANY).  If two matching rules share the same
 * rank, the one with the longer selector text string wins (longer text
 * indicates a more specific config line, e.g. "clock_gettime/monotonic" beats
 * "clock_gettime").
 *
 * @param rules       Array of parsed rules.
 * @param rule_count  Number of entries in @p rules.
 * @param effect      The fault type to match.
 * @param operation   The intercepted function to match.
 * @param clock_id    The POSIX clock ID to match (for SELECTOR_CLOCK_ID rules).
 * @param rule        Output: set to the winning rule on success.
 * @return            Non-zero if any matching rule was found, zero otherwise.
 */
int chaos_time_config_select_rule(
    const chaos_time_rule_t *rules,
    size_t rule_count,
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

#endif
