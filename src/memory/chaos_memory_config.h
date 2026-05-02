/**
 * @file chaos_memory_config.h
 * @brief Configuration data model and public interface for the chaos-memory
 *        rule engine.
 *
 * @details
 * This header defines the complete type system used to represent, parse, and
 * match fault-injection rules for the memory chaos module.  It is included by
 * both the config implementation (chaos_memory_config.c) and the hook
 * implementations (chaos_memory_hooks.c, chaos_memory_actions.c).
 *
 * The config file lives at CHAOS_MEMORY_CONFIG_PATH (/tmp/.chaos-memory.conf).
 * It is a line-oriented text file; each non-comment, non-blank line has the
 * form:
 *
 * @code
 *   <selector> : <effect> : <value>[@<probability>]
 * @endcode
 *
 * Examples:
 * @code
 *   mmap/anon : ERRNO : ENOMEM@0.05   # fail 5% of anonymous mmaps
 *   mmap/file : LATENCY : 20          # add 20ms latency to file-backed mmaps
 *   mprotect  : ERRNO : EPERM         # always fail mprotect
 *   *         : LATENCY : 5@0.1       # 10% chance of 5ms latency on anything
 * @endcode
 *
 * @par Rule selection
 * When multiple rules match a given call, the most-specific match wins.
 * Specificity rank (ascending priority): ANY (`*`) < OPERATION (`mmap`,
 * `munmap`, etc.) < MMAP_KIND (`mmap/anon`, `mmap/file`).  Within equal rank,
 * the rule with the longer selector text is preferred.  LATENCY and ERRNO
 * rules are matched independently — both can fire on a single call.
 *
 * @par Config reload protocol
 * The config is checked for modification on every intercepted call via a
 * stat(2) mtime hash.  If the hash has changed, the inactive slot in a
 * two-snapshot buffer is updated atomically.  A CAS on the cached mtime
 * ensures exactly one thread performs the reload; concurrent callers observe
 * the RELOADING sentinel and fall back to the current active snapshot.
 *
 * @par Stability
 * Internal — do not include from outside the memory chaos module.
 */
#ifndef CHAOS_MEMORY_CONFIG_H
#define CHAOS_MEMORY_CONFIG_H

#include "chaos_memory_internal.h"

/* =========================================================================
 * Enumerations
 * =========================================================================
 */

/**
 * @brief Identifies which memory syscall a rule targets.
 *
 * @details
 * Assigned at parse time from the selector text and stored in
 * chaos_memory_selector_t::operation.  The value CHAOS_MEMORY_OP_INVALID is
 * used by the SELECTOR_ANY kind where the operation field is irrelevant.
 */
typedef enum chaos_memory_operation
{
    /** Sentinel: operation field is not meaningful for this selector kind. */
    CHAOS_MEMORY_OP_INVALID = -1,
    /** Matches calls to mmap(2), potentially further refined by mmap_kind. */
    CHAOS_MEMORY_OP_MMAP,
    /** Matches calls to mprotect(2). */
    CHAOS_MEMORY_OP_MPROTECT,
    /** Matches calls to madvise(2). */
    CHAOS_MEMORY_OP_MADVISE,
    /** Matches calls to munmap(2). */
    CHAOS_MEMORY_OP_MUNMAP
} chaos_memory_operation_t;

/**
 * @brief Discriminator for the three selector granularities.
 *
 * @details
 * Controls how chaos_memory_selector_matches() interprets the rest of the
 * chaos_memory_selector_t fields and determines the specificity rank returned
 * via rank_out:
 *
 *  - ANY (rank 1): matches every intercepted call regardless of operation or
 *    mmap flags.  Corresponds to the `*` selector token.
 *  - OPERATION (rank 2): matches all calls to a specific syscall.  Corresponds
 *    to `mmap`, `munmap`, `mprotect`, `madvise`.
 *  - MMAP_KIND (rank 3): matches mmap calls further filtered by the
 *    MAP_ANONYMOUS flag.  Corresponds to `mmap/anon` and `mmap/file`.
 */
typedef enum chaos_memory_selector_kind
{
    /** Sentinel: invalid or uninitialised selector. */
    CHAOS_MEMORY_SELECTOR_INVALID = -1,
    /** Matches all intercepted operations (wildcard selector `*`). */
    CHAOS_MEMORY_SELECTOR_ANY,
    /** Matches a specific operation (e.g., `mmap`, `munmap`). */
    CHAOS_MEMORY_SELECTOR_OPERATION,
    /**
     * Matches a specific mmap mapping kind (`mmap/anon` or `mmap/file`).
     * Only valid when operation == CHAOS_MEMORY_OP_MMAP.
     */
    CHAOS_MEMORY_SELECTOR_MMAP_KIND
} chaos_memory_selector_kind_t;

/**
 * @brief Discriminates between anonymous and file-backed mmap mappings.
 *
 * @details
 * Used only when selector kind is CHAOS_MEMORY_SELECTOR_MMAP_KIND.  The
 * classification is driven by chaos_memory_mmap_is_anonymous(flags):
 *
 *  - ANON: MAP_ANONYMOUS is set.  This is the path used by:
 *    - glibc's malloc for allocations > MMAP_THRESHOLD (default 128 KiB).
 *      Injecting ERRNO:ENOMEM on `mmap/anon` fails large glibc allocations;
 *      small allocations via brk() are unaffected.
 *    - musl's malloc for all allocations (no brk path).  ERRNO:ENOMEM on
 *      `mmap/anon` fails every malloc() call under musl immediately.
 *    - Stack growth, JIT code buffers, shared-memory IPC.
 *
 *  - FILE: MAP_ANONYMOUS is clear.  This is the path used for memory-mapped
 *    files (mmap of an open fd), device mappings, and POSIX shared memory
 *    objects.  Injecting ERRNO:EACCES here tests file-mapping error paths
 *    without disturbing the allocator.
 */
typedef enum chaos_memory_mmap_kind
{
    /** Sentinel: not applicable or uninitialised. */
    CHAOS_MEMORY_MMAP_KIND_INVALID = -1,
    /** MAP_ANONYMOUS is set — anonymous private or shared mapping. */
    CHAOS_MEMORY_MMAP_KIND_ANON = 0,
    /** MAP_ANONYMOUS is clear — file-backed or device mapping. */
    CHAOS_MEMORY_MMAP_KIND_FILE
} chaos_memory_mmap_kind_t;

/**
 * @brief Enumerates the injectable effects.
 *
 * @details
 * A rule carries exactly one effect.  Two independent matching passes are
 * performed per intercepted call — one for LATENCY, one for ERRNO — so both
 * can fire on the same call if two matching rules exist.
 *
 *  - ERRNO (pre-call): sets errno to rule->errnum and returns the
 *    syscall-specific error sentinel without invoking the real function.
 *    For mmap(2) the sentinel is MAP_FAILED ((void*)-1); for munmap(2),
 *    mprotect(2), and madvise(2) it is -1.
 *
 *  - LATENCY (pre-call): sleeps for rule->latency_ms milliseconds before
 *    passing the call through to the real function.  Does not suppress the
 *    call.
 *
 * @note CORRUPT and OFFSET effects are intentionally absent for mmap.  The
 *       result of mmap(2) is a raw pointer to newly-mapped memory.  Corrupting
 *       that pointer after a successful mapping would mean either (a) writing
 *       into the mapping itself — undefined behaviour for file-backed mappings
 *       and data corruption for anonymous ones — or (b) returning a pointer
 *       that does not correspond to any mapping, causing an immediate SIGSEGV
 *       on first access.  Neither is a useful fault mode; pre-call ERRNO is
 *       the correct abstraction for testing allocator error paths.
 */
typedef enum chaos_memory_effect
{
    /** Sentinel: invalid or uninitialised effect. */
    CHAOS_MEMORY_EFFECT_INVALID = -1,
    /** Pre-call error injection: set errno and return MAP_FAILED / -1. */
    CHAOS_MEMORY_EFFECT_ERRNO = 0,
    /** Pre-call latency injection: sleep for latency_ms before the call. */
    CHAOS_MEMORY_EFFECT_LATENCY
} chaos_memory_effect_t;

/* =========================================================================
 * Structs
 * =========================================================================
 */

/**
 * @brief Parsed selector — identifies which calls a rule applies to.
 *
 * @details
 * Populated by chaos_memory_selector_parse().  The active fields depend on
 * @c kind:
 *
 *  - kind == ANY:        @c operation and @c mmap_kind are ignored.
 *  - kind == OPERATION:  @c operation identifies the syscall; @c mmap_kind is
 *                        ignored.
 *  - kind == MMAP_KIND:  both @c operation (always MMAP) and @c mmap_kind are
 *                        meaningful.
 *
 * @note Ownership: embedded by value in chaos_memory_rule_t.  No heap
 *       allocation; lifetime is that of the enclosing rule.
 */
typedef struct chaos_memory_selector
{
    /**
     * @brief Discriminator that controls interpretation of the other fields.
     * Never CHAOS_MEMORY_SELECTOR_INVALID in a successfully parsed selector.
     */
    chaos_memory_selector_kind_t kind;

    /**
     * @brief The target syscall.
     * Meaningful when kind is OPERATION or MMAP_KIND; set to
     * CHAOS_MEMORY_OP_INVALID when kind is ANY.
     */
    chaos_memory_operation_t operation;

    /**
     * @brief Anonymous vs file-backed mapping discriminator.
     * Meaningful only when kind is MMAP_KIND; set to
     * CHAOS_MEMORY_MMAP_KIND_INVALID otherwise.
     */
    chaos_memory_mmap_kind_t mmap_kind;

    /**
     * @brief Byte length of the original selector text (e.g., 9 for "mmap/anon").
     * Used as a tiebreaker within equal-rank selectors: longer text wins.
     * This ensures `mmap/anon` beats `mmap` when both match an anonymous call.
     */
    size_t selector_len;
} chaos_memory_selector_t;

/**
 * @brief A single parsed fault-injection rule.
 *
 * @details
 * Produced by chaos_memory_config_parse_line() and stored in the active
 * config snapshot.  Fields not relevant to a given effect are zero-initialised
 * but must not be read by code that has not checked @c effect first.
 *
 * @note Ownership: stored by value in chaos_memory_config_state_t::rules[].
 *       Copied by value into the caller's stack when matched by
 *       chaos_memory_config_select_rule(), so callers own their copy.
 */
typedef struct chaos_memory_rule
{
    /** @brief Selector describing which calls this rule matches. */
    chaos_memory_selector_t selector;

    /**
     * @brief The effect to apply when this rule fires.
     * Never CHAOS_MEMORY_EFFECT_INVALID in a successfully parsed rule.
     */
    chaos_memory_effect_t effect;

    /**
     * @brief The errno value to inject when effect == ERRNO.
     * One of: ENOMEM, EINVAL, EACCES, EPERM, EBADF, ENODEV, EAGAIN,
     * EFAULT, ENOSYS, ENFILE, EMFILE, or a positive integer literal.
     * Zero when effect != ERRNO.
     */
    int errnum;

    /**
     * @brief Probability that this rule fires on any given matching call.
     * Range: [0.0, 1.0].  0.0 means never fire; 1.0 means always fire.
     * Evaluated by chaos_memory_probability_hit() against the per-thread PRNG.
     * Parsed from the optional `@<p>` suffix in the config value field;
     * defaults to 1.0 if no suffix is present.
     */
    double probability;

    /**
     * @brief Delay in milliseconds when effect == LATENCY.
     * Applied as a pre-call sleep; the real syscall is still issued afterwards.
     * Zero when effect != LATENCY.
     */
    unsigned int latency_ms;
} chaos_memory_rule_t;

/* =========================================================================
 * Public API
 * =========================================================================
 */

/**
 * @brief Initialise the config subsystem to a clean, zero-rule state.
 *
 * @details
 * Called once from chaos_memory_init() at constructor time.  Zeroes both
 * config snapshots, sets the active index to 0, and resets the cached mtime
 * to CHAOS_MEMORY_MTIME_UNKNOWN so that the first call to
 * chaos_memory_config_prepare() triggers an unconditional reload.
 *
 * Not thread-safe — must only be called from the module constructor before
 * any intercepted syscall can be made.
 */
void chaos_memory_config_init(void);

/**
 * @brief Check for config file changes and reload if necessary.
 *
 * @details
 * Called at the top of chaos_memory_config_match() on every intercepted call.
 * The implementation stats the config file, hashes the mtime, and compares it
 * to the cached hash.  If they differ it attempts a CAS on the cached mtime to
 * claim the reload slot; exactly one thread wins and updates the inactive
 * snapshot, then publishes it atomically.  All other threads fall back to the
 * currently active snapshot.
 *
 * Fail-open: if the config file is absent, unreadable, or syntactically
 * invalid, the active snapshot is set to zero rules and all calls pass
 * through without fault injection.
 *
 * @return Non-zero if the active config has at least one valid rule after the
 *         prepare step, zero otherwise.
 */
int chaos_memory_config_prepare(void);

/**
 * @brief Match a rule from the already-loaded active config snapshot.
 *
 * @details
 * Does not stat or reload the config file.  Used when the caller has already
 * called chaos_memory_config_prepare() and wants to avoid a second reload
 * check.  Selects the best-matching rule (highest rank, then longest selector)
 * for the given effect/operation/flags combination.
 *
 * @param effect      The effect to match (ERRNO or LATENCY).
 * @param operation   The intercepted syscall being matched.
 * @param mmap_flags  The @p flags argument from the mmap(2) call.  Ignored
 *                    (passed as 0) for non-mmap operations; used by
 *                    chaos_memory_mmap_is_anonymous() for mmap/anon vs
 *                    mmap/file discrimination.
 * @param[out] rule   Populated with a copy of the matched rule on success.
 *                    Undefined on failure.
 * @return            Non-zero if a matching rule was found, zero otherwise.
 */
int chaos_memory_config_match_loaded(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

/**
 * @brief Prepare the config (reload if stale) then match a rule.
 *
 * @details
 * Combines chaos_memory_config_prepare() and chaos_memory_config_match_loaded()
 * in one call.  This is the entry point used by the hook wrappers in
 * chaos_memory_hooks.c for each effect pass.
 *
 * Returns zero immediately if @p rule is NULL or if config_prepare reports
 * no rules are active (fast path with no matching work).
 *
 * @param effect      The effect to match (ERRNO or LATENCY).
 * @param operation   The intercepted syscall being matched.
 * @param mmap_flags  The @p flags argument from mmap(2), or 0 for other ops.
 * @param[out] rule   Populated with a copy of the matched rule on success.
 * @return            Non-zero if a matching rule was found, zero otherwise.
 */
int chaos_memory_config_match(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

/**
 * @brief Parse a single line from the config file into a rule.
 *
 * @details
 * Strips trailing comments (`#` through end-of-line), trims whitespace, and
 * splits the line into selector, effect, and value fields on `:` delimiters.
 * The @p probability suffix is parsed from the value field if an `@` character
 * is present.
 *
 * @param[in,out] line  Null-terminated line buffer.  Modified in place
 *                      (comment stripping, token splitting).
 * @param[out]    rule  Populated on success (return value 1).
 *                      Zeroed but otherwise undefined on failure (return -1).
 *                      Not written on blank/comment lines (return 0).
 * @return   1  if a valid rule was parsed into @p rule.
 * @return   0  if the line is blank or a comment (not an error).
 * @return  -1  if the line is syntactically invalid.
 */
int chaos_memory_config_parse_line(char *line, chaos_memory_rule_t *rule);

/**
 * @brief Parse a complete null-terminated config buffer into a rule array.
 *
 * @details
 * Splits @p buffer on newlines and calls chaos_memory_config_parse_line() for
 * each line.  Accumulates valid rules into @p rules up to
 * CHAOS_MEMORY_MAX_RULES.  Returns -1 if any line is syntactically invalid or
 * if the rule count exceeds the limit; in that case @p rules and
 * @p rule_count are in an indeterminate state and the caller should discard
 * the entire buffer.
 *
 * @param[in,out] buffer      Null-terminated config text.  Modified in place
 *                            (newline splitting).
 * @param[out]    rules       Array of at least CHAOS_MEMORY_MAX_RULES entries.
 * @param[out]    rule_count  Number of valid rules written to @p rules.
 * @return   0 on success, -1 on any parse error or rule count overflow.
 */
int chaos_memory_config_parse_buffer(char *buffer, chaos_memory_rule_t *rules, size_t *rule_count);

/**
 * @brief Select the best-matching rule from an array for a given call context.
 *
 * @details
 * Iterates @p rules, skipping entries whose effect does not match or whose
 * selector does not match the operation/flags combination.  Among matching
 * rules, chooses the one with the highest specificity rank; ties are broken by
 * the longer selector text (selector_len).
 *
 * This function is the core of the rule-matching algorithm and is separated
 * from the config state management so it can be unit-tested with arbitrary
 * rule arrays.
 *
 * @param rules       Array of parsed rules.  May be NULL (returns 0).
 * @param rule_count  Number of entries in @p rules.
 * @param effect      Effect to filter on.
 * @param operation   Syscall to match against each selector.
 * @param mmap_flags  mmap(2) flags word; unused (should be 0) for non-mmap ops.
 * @param[out] rule   Populated with a copy of the winning rule on success.
 * @return            Non-zero if at least one rule matched, zero otherwise.
 */
int chaos_memory_config_select_rule(
    const chaos_memory_rule_t *rules,
    size_t rule_count,
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

#endif
