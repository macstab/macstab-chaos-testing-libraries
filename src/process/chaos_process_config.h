/**
 * @file chaos_process_config.h
 * @brief Rule model, config lifecycle, and rule-matching API for the
 *        libchaos-process fault-injection subsystem.
 *
 * @details
 * This header defines the data model used to represent chaos rules and
 * exposes the functions that load, parse, and query those rules at runtime.
 *
 * ## Rule file format
 *
 * Rules are read from `CHAOS_PROCESS_CONFIG_PATH` (`/tmp/.chaos-process.conf`
 * by default) on demand.  Each non-blank, non-comment line has the form:
 *
 * @code
 *   <selector> : <effect> : <value>[@<probability>]
 * @endcode
 *
 * Examples:
 * @code
 *   *            : ERRNO    : EAGAIN@0.1      # 10% chance on any operation
 *   fork         : LATENCY  : 50             # delay fork by 50 ms, always
 *   pthread_create : FAIL_AFTER : ENOMEM,100 # fail after 100 calls
 * @endcode
 *
 * ## Hot reload
 *
 * The config file is stat(2)-checked on every call to
 * `chaos_process_config_match()`.  If the mtime hash has changed since the
 * last load, a single thread wins a compare-and-swap on
 * `g_chaos_process_cached_mtime` and performs the reload; competing threads
 * fall through to the currently active config.  The active slot is one of two
 * ping-pong states (`g_chaos_process_config_states[0/1]`) published with a
 * full barrier so readers always see a consistent view.
 *
 * Reloading resets all `g_chaos_process_fail_after_counters[]` to zero,
 * effectively re-arming any FAIL_AFTER rules.
 *
 * ## Stability
 * Private — not part of the public API.
 */

#ifndef CHAOS_PROCESS_CONFIG_H
#define CHAOS_PROCESS_CONFIG_H

#include "chaos_process_internal.h"

/**
 * @brief Enumeration of all interposed operations.
 *
 * Values are contiguous starting at 0 so they can be used directly as array
 * indices into `g_chaos_process_fail_after_counters[]`.
 *
 * CHAOS_PROCESS_OP_INVALID (-1) is a sentinel for "not set" — it is never
 * stored in a valid rule and never used as an array index.
 *
 * CHAOS_PROCESS_OP_COUNT is the array size sentinel; it must remain the last
 * named enumerator.
 */
typedef enum chaos_process_operation
{
    CHAOS_PROCESS_OP_INVALID = -1,   /**< Sentinel: invalid / not set. */
    CHAOS_PROCESS_OP_PTHREAD_CREATE, /**< pthread_create(3) — index 0. */
    CHAOS_PROCESS_OP_FORK,           /**< fork(2) — index 1. */
    CHAOS_PROCESS_OP_POSIX_SPAWN,    /**< posix_spawn(3) — index 2. */
    CHAOS_PROCESS_OP_POSIX_SPAWNP,   /**< posix_spawnp(3) — index 3. */
    CHAOS_PROCESS_OP_EXECVE,         /**< execve(2) — index 4. */
    CHAOS_PROCESS_OP_EXECVEAT,       /**< execveat(2) — index 5 (Linux only). */
    CHAOS_PROCESS_OP_WAITPID,        /**< waitpid(2) — index 6. */
    CHAOS_PROCESS_OP_COUNT           /**< Total number of operations; array size. */
} chaos_process_operation_t;

/**
 * @brief How a rule targets operations.
 *
 * A selector is either a wildcard that matches every operation, or a
 * specific-operation match.  During rule selection the specific-operation
 * match wins over the wildcard (higher rank = 2 vs rank = 1).
 */
typedef enum chaos_process_selector_kind
{
    CHAOS_PROCESS_SELECTOR_INVALID = -1, /**< Sentinel: invalid / parse error. */
    CHAOS_PROCESS_SELECTOR_ANY,          /**< Wildcard `*` — matches any operation. */
    CHAOS_PROCESS_SELECTOR_OPERATION     /**< Exact operation name match. */
} chaos_process_selector_kind_t;

/**
 * @brief The class of chaos effect a rule applies.
 *
 * CHAOS_PROCESS_EFFECT_INVALID is a sentinel for "not set".
 */
typedef enum chaos_process_effect
{
    CHAOS_PROCESS_EFFECT_INVALID = -1,  /**< Sentinel: invalid / parse error. */
    CHAOS_PROCESS_EFFECT_ERRNO = 0,     /**< Inject an immediate errno failure. */
    CHAOS_PROCESS_EFFECT_LATENCY = 1,   /**< Insert an artificial delay (ms). */
    CHAOS_PROCESS_EFFECT_FAIL_AFTER = 2 /**< Fail after N successful calls. */
} chaos_process_effect_t;

/**
 * @brief Parsed representation of the selector portion of a rule line.
 *
 * Thread safety: read-only after parsing; no locking required.
 */
typedef struct chaos_process_selector
{
    /**
     * Whether this selector is a wildcard (`ANY`) or a specific operation
     * (`OPERATION`).  Drives the match rank during rule selection.
     */
    chaos_process_selector_kind_t kind;

    /**
     * The specific operation this selector targets.  Only meaningful when
     * `kind == CHAOS_PROCESS_SELECTOR_OPERATION`; set to
     * `CHAOS_PROCESS_OP_INVALID` for wildcard selectors.
     */
    chaos_process_operation_t operation;

    /**
     * Byte length of the selector text as it appeared in the config file.
     * Used as a tiebreaker when two rules have the same rank: the longer
     * (more-specific) selector wins.  For current selectors this is always
     * the length of the operation name string.
     */
    size_t selector_len;
} chaos_process_selector_t;

/**
 * @brief A fully parsed chaos rule ready for effect evaluation.
 *
 * A rule is immutable once parsed.  The active rule set is owned by one of
 * the two ping-pong `chaos_process_config_state_t` slots and replaced
 * atomically on config reload.
 *
 * Thread safety: read-only after publishing; no locking required for reads.
 */
typedef struct chaos_process_rule
{
    /**
     * The selector that determines which operations this rule applies to.
     */
    chaos_process_selector_t selector;

    /**
     * The type of fault this rule injects.  Determines which fields below
     * are meaningful.
     */
    chaos_process_effect_t effect;

    /**
     * Errno value to inject on ERRNO or FAIL_AFTER effects.
     * For `pthread_create`, this value is returned directly (not via errno),
     * matching the POSIX specification that `pthread_create` returns the
     * error number rather than setting `errno` and returning -1.
     * For all other interposed functions the wrapper sets `errno = errnum`
     * and returns -1.
     * Common values:
     *   - EAGAIN: thread/process limit exceeded
     *   - ENOMEM: stack or address-space allocation failure
     *   - ECHILD: no child process (waitpid)
     *   - EINTR:  interrupted by signal (waitpid)
     */
    int errnum;

    /**
     * Probability in [0.0, 1.0] that the effect fires on any given call.
     * 0.0 means the effect never fires; 1.0 means it always fires.
     * Evaluated against a per-thread PRNG sample.
     * Parsed from the `@<probability>` suffix of the value field; defaults
     * to 1.0 if no `@` suffix is present.
     */
    double probability;

    /**
     * Latency to inject in milliseconds (LATENCY effect only).
     * Applied before calling the real function.  The delay is broken into
     * 1-second chunks to avoid exceeding `usleep`'s POSIX maximum.
     *
     * @warning For the `fork` wrapper, latency is applied in the *parent*
     *          before the real `fork()` call.  The child inherits the
     *          post-fork state and does not experience the delay.
     *
     * @warning For the `vfork` wrapper (if implemented): calling `usleep`
     *          or `nanosleep` in the vfork window (between `vfork()` return
     *          and the child's `exec`/`_exit`) violates the POSIX
     *          async-signal-safe constraint for vfork.  See
     *          `chaos_process_hooks.c` for how this is handled.
     *
     * @warning For `execve`/`execveat`: latency is applied before the exec
     *          syscall.  If the exec succeeds, the process image is replaced
     *          and the library is no longer loaded; no cleanup of library
     *          state occurs.  The delay is real and observable (e.g. by the
     *          parent monitoring the child's startup time).
     *
     * @warning For `waitpid`: latency is applied before the real `waitpid`
     *          call, so the total observed delay is `latency_ms` plus the
     *          time `waitpid` itself blocks.  This may confuse caller-side
     *          timeout logic that expects `waitpid` to return promptly.
     */
    unsigned int latency_ms;

    /**
     * Invocation threshold for FAIL_AFTER effect.
     *
     * The interposed function is allowed to succeed for the first
     * `fail_after_count` calls (when the pre-increment counter value is
     * < `fail_after_count`) and fails on all subsequent calls.
     *
     * The counter used is `g_chaos_process_fail_after_counters[operation]`,
     * incremented atomically with `__sync_fetch_and_add`.  The
     * pre-increment value is compared against this field:
     *
     *   - pre-increment == 0, fail_after_count == 0: fails on the 1st call
     *   - pre-increment == 0, fail_after_count == 1: succeeds on 1st call,
     *     fails from the 2nd onwards (pre-increment == 1 >= 1)
     *
     * The counter is shared across all threads (intentional — models a
     * realistic system-wide resource exhaustion scenario).
     *
     * The counter is reset to 0 on every config reload.
     */
    uint64_t fail_after_count;
} chaos_process_rule_t;

/**
 * @brief Initialises the config subsystem to a clean state.
 *
 * Zeroes both ping-pong config states, resets the active index to 0,
 * sets `g_chaos_process_cached_mtime` to `CHAOS_PROCESS_MTIME_UNKNOWN`
 * (forcing a reload on the next call), and resets all FAIL_AFTER counters.
 *
 * Called once from the library constructor `chaos_process_init()`.
 * Must not be called concurrently with any config reader.
 */
void chaos_process_config_init(void);

/**
 * @brief Checks whether the config file has changed and reloads if necessary.
 *
 * Stats the config file, hashes its mtime, and compares against the cached
 * hash.  If different, races to win a CAS on `g_chaos_process_cached_mtime`
 * to become the sole reloader.  The winner reads and parses the file into the
 * inactive ping-pong slot, then publishes the new slot atomically.
 *
 * A failed parse leaves the new slot with `parse_ok = 0` and zero rules;
 * the library behaves as if no config exists (passthrough for all calls).
 *
 * @return Non-zero if the active config is valid and has at least one rule;
 *         0 if no rules are active (either no file or a parse error).
 */
int chaos_process_config_prepare(void);

/**
 * @brief Queries the already-loaded (active) config without triggering a
 *        reload.
 *
 * Selects the best-matching rule for the given effect and operation from the
 * currently active config state.  Useful in hot paths where the reload check
 * has already been performed by a prior call to `chaos_process_config_match`.
 *
 * @param effect    The effect type to search for (ERRNO, LATENCY, FAIL_AFTER).
 * @param operation The operation being intercepted.
 * @param rule      Output: populated with the matched rule on success.
 * @return Non-zero if a matching rule was found; 0 if no match.
 */
int chaos_process_config_match_loaded(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

/**
 * @brief Full entry point: reload-if-stale then match.
 *
 * Calls `chaos_process_config_prepare()` to ensure the config is current,
 * then calls `chaos_process_config_match_loaded()` to find the best rule.
 *
 * This is the function called by every interposition hook.
 *
 * @param effect    The effect type to search for.
 * @param operation The operation being intercepted.
 * @param rule      Output: populated with the matched rule on success.
 * @return Non-zero if a matching rule was found and the config is valid;
 *         0 if no match, invalid config, or @p rule is NULL.
 */
int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

/**
 * @brief Parses a single line from the config file into a rule.
 *
 * Strips comments (everything from `#` onwards), trims whitespace, and
 * splits the line on `:` separators into selector, effect, and value fields.
 * Returns 0 for blank/comment-only lines, 1 for a successfully parsed rule,
 * and -1 for a malformed line.
 *
 * @param line  A mutable NUL-terminated string (modified in-place by the
 *              comment stripper and trimmer).
 * @param rule  Output: populated on successful parse (return value == 1).
 * @return  1  Line parsed successfully; @p rule is populated.
 * @return  0  Blank or comment-only line; @p rule is not modified.
 * @return -1  Parse error; rule file should be treated as invalid.
 */
int chaos_process_config_parse_line(char *line, chaos_process_rule_t *rule);

/**
 * @brief Parses a NUL-terminated buffer of config text into an array of rules.
 *
 * Splits @p buffer on newline characters, calls `chaos_process_config_parse_line`
 * on each, and accumulates valid rules into @p rules.  Stops and returns -1 on
 * the first parse error, or if the rule count would exceed
 * `CHAOS_PROCESS_MAX_RULES`.
 *
 * @param buffer      Mutable NUL-terminated config text (modified in-place).
 * @param rules       Output array of at least `CHAOS_PROCESS_MAX_RULES` elements.
 * @param rule_count  Output: number of rules written to @p rules.
 * @return 0 on success, -1 on parse error or overflow.
 */
int chaos_process_config_parse_buffer(
    char *buffer, chaos_process_rule_t *rules, size_t *rule_count
);

/**
 * @brief Selects the best-matching rule from an array for a given
 *        effect/operation pair.
 *
 * Iterates over all rules that match the requested effect and tests each
 * selector against `operation`.  Among matching rules the winner is chosen by:
 *  1. Higher selector rank (OPERATION rank=2 beats ANY rank=1).
 *  2. On equal rank: longer selector text (for future extensibility; in the
 *     current grammar this never differs within a rank).
 *
 * @param rules       Array of parsed rules.
 * @param rule_count  Number of elements in @p rules.
 * @param effect      Effect type to filter on.
 * @param operation   Operation to match against.
 * @param rule        Output: populated with the winning rule if found.
 * @return Non-zero if a matching rule was found; 0 otherwise.
 */
int chaos_process_config_select_rule(
    const chaos_process_rule_t *rules,
    size_t rule_count,
    chaos_process_effect_t effect,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule
);

#endif
