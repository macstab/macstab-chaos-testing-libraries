/**
 * @file chaos_time_config.h
 * @brief Rule model and rule-file API of libchaos-time.
 *
 * @details
 * ### Rule grammar
 *
 * One rule per line of /tmp/.chaos-time.conf; blank lines and `#` comments are ignored:
 * @verbatim
 *   <selector>:<EFFECT>:<value>[@<probability>] [<qualifier> ...] [# comment]
 * @endverbatim
 * Fields are split at the first two `:` and trimmed. The probability (default 1) follows
 * the last `@` of the value field and uses the locale-independent grammar of
 * chaos_policy_parse_probability(). Qualifiers (`@first=N`, `@from=T`, `@until=T`,
 * `@size>N`, `@size<N`) are separate words (chaos_policy.h); no time wrapper passes a
 * byte count, so a rule with `@size` never fires.
 *
 * | Selector                  | Matches                                                |
 * |---------------------------|--------------------------------------------------------|
 * | `*`                       | every operation (rank 1)                               |
 * | `clock_gettime`           | every clock read, any clock (rank 2)                   |
 * | `clock_gettime/<clock>`   | reads of one clock (rank 3); `realtime`, `monotonic`,  |
 * |                           | `monotonic_raw`, `realtime_coarse`, `monotonic_coarse`,|
 * |                           | `boottime`, `tai`, `process_cputime_id`,               |
 * |                           | `thread_cputime_id` where defined, or a decimal id     |
 * | `nanosleep`               | nanosleep, clock_nanosleep and sleep (rank 2)          |
 * | `usleep`                  | usleep (rank 2)                                        |
 *
 * "Clock read" covers clock_gettime, gettimeofday, time and timespec_get(TIME_UTC); the
 * last three read CLOCK_REALTIME.
 *
 * | Effect    | Value                                   | Selectors                  |
 * |-----------|-----------------------------------------|----------------------------|
 * | `ERRNO`   | EINVAL, EFAULT, EINTR, EPERM, ENOSYS,   | any                        |
 * |           | EAGAIN, or a decimal 1..2147483647      |                            |
 * | `LATENCY` | ms, 0..4294967295, before the call      | any                        |
 * | `OFFSET`  | signed ms, at most 100 years either way | clock_gettime[/<clock>]    |
 * | `REGRESS` | ms > 0, at most 100 years               | clock_gettime/<clock> only |
 *
 * Example: `clock_gettime/monotonic:OFFSET:-5000@0.5 @first=10`.
 *
 * Any invalid line rejects the whole file: no rule applies (fail-open) and the status
 * file names the line.
 *
 * ### Reload
 *
 * Each process looks at the rule file at most once per CHAOS_CHECK_INTERVAL_NS (1 ms),
 * timed by the vDSO CLOCK_MONOTONIC (chaos_clock.h); without a vDSO clock it looks on
 * every call. The first load is never throttled. A look is one stat(); the file is read
 * only when its change stamp (mtime, size, inode, device) differs, or when the last
 * load was provisional (an mtime younger than CHAOS_RACY_WINDOW_MS, 20 ms). Readers see
 * the previous or the new rule set, never a mix (chaos_time_config.c).
 *
 * @module chaos-time
 * @stability Internal.
 */

#ifndef CHAOS_TIME_CONFIG_H
#define CHAOS_TIME_CONFIG_H

#include "chaos_time_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

/**
 * @brief Operation a call is matched as; several wrappers share one operation.
 */
typedef enum chaos_time_operation
{
    CHAOS_TIME_OP_INVALID = -1,  /**< Never stored in a valid rule; operation of `*`. */
    CHAOS_TIME_OP_CLOCK_GETTIME, /**< clock_gettime, gettimeofday, time, timespec_get. */
    CHAOS_TIME_OP_NANOSLEEP,     /**< nanosleep, clock_nanosleep, sleep. */
    CHAOS_TIME_OP_USLEEP         /**< usleep. */
} chaos_time_operation_t;

/**
 * @brief Selector form; also its specificity rank in chaos_time_config_select_rule().
 */
typedef enum chaos_time_selector_kind
{
    CHAOS_TIME_SELECTOR_INVALID = -1, /**< Unparseable; never stored. */
    /** `*`: every operation; rank 1. */
    CHAOS_TIME_SELECTOR_ANY,
    /** `clock_gettime`, `nanosleep` or `usleep`: one operation, any clock; rank 2. */
    CHAOS_TIME_SELECTOR_OPERATION,
    /** `clock_gettime/<clock>`: clock reads of one clock id; rank 3. */
    CHAOS_TIME_SELECTOR_CLOCK_ID
} chaos_time_selector_kind_t;

/**
 * @brief Effect of a rule. Each call resolves at most one rule per effect.
 */
typedef enum chaos_time_effect
{
    CHAOS_TIME_EFFECT_INVALID = -1, /**< Unparseable; never stored. */
    /** Before the call: fail it with errnum without calling the real function. */
    CHAOS_TIME_EFFECT_ERRNO,
    /** Before the call: sleep latency_ms through the real usleep/nanosleep. */
    CHAOS_TIME_EFFECT_LATENCY,
    /**
     * After a successful clock read: add offset_ms to the returned time, independently on
     * every read where the rule fires. The kernel clock is untouched. A rule with
     * probability < 1 makes CLOCK_MONOTONIC jump back and forth between reads; that is
     * the intended fault.
     */
    CHAOS_TIME_EFFECT_OFFSET,
    /**
     * After a successful clock read: step the clock back by offset_ms once. The first
     * read under the rule is real, the first later read where the rule fires jumps,
     * and every read after that stays shifted, so the clock advances again from the
     * earlier time. State lives in the rule's hit slot (chaos_time_rule_apply_regress()).
     */
    CHAOS_TIME_EFFECT_REGRESS,
    /**
     * After a successful clock read: stop the clock at the reading of the call that fired
     * the rule. Every later read of that clock returns the kept value, so the application
     * sees time standing still -- a watchdog that waits for a deadline waits for ever, a
     * cache that expires by wall clock never expires. The probability decides when the
     * freeze starts, not each read. The kept value lives in the rule's hit slot
     * (chaos_time_rule_apply_freeze()), so every thread and a reload that keeps the rule
     * see the same frozen time.
     */
    CHAOS_TIME_EFFECT_FREEZE
} chaos_time_effect_t;

/**
 * @brief Parsed selector.
 *
 * @invariant  CLOCK_ID: @c operation is CLOCK_GETTIME, @c clock_id the parsed clock and
 *             @c text the clock as written (NUL-terminated, < CHAOS_TIME_MAX_TEXT bytes).
 * @invariant  ANY: @c operation is CHAOS_TIME_OP_INVALID and @c clock_id is 0.
 */
typedef struct chaos_time_selector
{
    chaos_time_selector_kind_t kind;  /**< Form; decides which fields below are valid. */
    chaos_time_operation_t operation; /**< Operation; CHAOS_TIME_OP_INVALID for `*`. */
    clockid_t clock_id;               /**< Clock id; CLOCK_ID selectors only. */
    size_t selector_len; /**< strlen of the selector as written; tie-breaker within a rank
                            (`clock_gettime/monotonic` beats `clock_gettime/1`). */
    char text[CHAOS_TIME_MAX_TEXT]; /**< Clock as written, e.g. "monotonic"; CLOCK_ID only. */
} chaos_time_selector_t;

/**
 * @brief One parsed rule, as stored in a snapshot and copied out per call.
 *
 * Effect fields not used by @c effect are 0: ERRNO uses @c errnum, LATENCY
 * @c latency_ms, OFFSET and REGRESS @c offset_ms. A wrapper decides on its own copy,
 * validated against the snapshot sequence, so a concurrent reload cannot tear it.
 *
 * @invariant  @c probability is in [0.0, 1.0].
 * @invariant  @c effect and @c selector.kind are not INVALID in a stored rule.
 */
typedef struct chaos_time_rule
{
    chaos_time_selector_t selector; /**< Calls the rule applies to. */
    chaos_time_effect_t effect;     /**< What it does to them. */
    int errnum;                     /**< ERRNO: errno to fail with, > 0. */
    double probability;             /**< Chance per eligible call, [0.0, 1.0]; default 1.0. */
    unsigned int latency_ms;        /**< LATENCY: delay in ms. */
    int64_t offset_ms; /**< OFFSET: signed shift in ms; REGRESS: step back in ms, > 0. */
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
    /**
     * Draw key of the rule: `mix(process seed ^ hash(rule text))`, set when the snapshot is
     * published. From the text, not the slot index: chaos_hits_assign() hands slots out
     * again and another rule would inherit the key.
     */
    uint64_t key;
    /**
     * Base of this call's draws, set by chaos_time_rule_should_trigger() from the key and the
     * rule's evaluation number; the effects derive their samples from it. Belongs to the one
     * call this copy was made for, not to the rule as parsed.
     */
    uint64_t draw_base;
} chaos_time_rule_t;

/**
 * @brief Starts this call's draws: records the rule's evaluation number and derives the
 *        base every sample of this call comes from.
 *
 * @details Two stages, not one. The first turns (rule, evaluation) into a base, the second
 * turns (base, draw number) into a sample, so a rule that takes several draws cannot
 * collide with its own next evaluation -- which is what a single `key + n * K + d` does as
 * soon as `d` reaches K, a constant the next effect added would break silently.
 *
 * @param rule Rule copy for this call; NULL is a no-op returning 0. A rule outside a
 *             snapshot (unit tests) has no slot and is evaluation 1 every time.
 * @return The number of this evaluation of the rule, counting from 1; what `@every=N`
 *         divides and what the draws are derived from.
 */
static inline uint64_t chaos_time_rule_draw_begin(chaos_time_rule_t *rule)
{
    uint64_t evaluation = 0U;

    if (rule == NULL)
    {
        return 0U;
    }
    /* Only through a slot that is still this rule's: every other use of a slot checks
     * the generation, and a rule copy held across a reload would otherwise bump the
     * counter of whoever owns the slot now -- shifting that rule's `@every` phase and
     * its draw numbering. */
    if (rule->hit != NULL && chaos_hit_slot_current(rule->hit, rule->hit_generation))
    {
        evaluation = CHAOS_COUNT_RELAXED(rule->hit->evaluations);
    }
    rule->draw_base = chaos_time_prng_mix((rule->key ^ g_chaos_time_lineage) + evaluation);
    return evaluation + 1U;
}

/**
 * @brief Sample @p draw of this call, uniform in [0, 2^32).
 *
 * @param rule Rule copy whose chaos_time_rule_draw_begin() ran.
 * @param draw Which draw of this call: 0 is the probability, the effects follow.
 * @return The sample.
 */
static inline uint32_t chaos_time_rule_draw(const chaos_time_rule_t *rule, uint64_t draw)
{
    return (uint32_t)(chaos_time_prng_mix(rule->draw_base + draw) >> 32);
}

/** @brief Draw number of the probability decision; effects number their draws after it. */
#define CHAOS_TIME_DRAW_PROBABILITY UINT64_C(0)

/** @brief First draw an effect may take after the probability. */
#define CHAOS_TIME_DRAW_FIRST_EFFECT UINT64_C(1)

/**
 * Resets the rule state: both snapshots empty, hit pool cleared, change stamp unknown.
 *
 * Also records the process id and hits-file number, registers the atfork child handler
 * (once) and resolves the vDSO clock, so no wrapper does that lookup first inside a
 * signal handler. Called by the constructor before any rule is loaded; not thread-safe.
 */
void chaos_time_config_init(void);

/**
 * Reloads the rule file if it changed; errno is preserved.
 *
 * Throttled to one look per CHAOS_CHECK_INTERVAL_NS (1 ms) per process once a first
 * load has completed and while no reload is in progress; without a vDSO clock every
 * call looks. A look is one stat(); the file is read and parsed into the
 * inactive snapshot only when its change stamp differs (or the last load was
 * provisional), and that snapshot is then published. A caller that finds a reload in
 * progress on another thread does not wait: it uses the active snapshot. Writes the
 * status file after each load and the hits file when an interval is overdue.
 *
 * Never blocks except for the file I/O of the thread that owns a reload.
 *
 * @return Non-zero when the active snapshot holds at least one rule.
 */
int chaos_time_config_prepare(void);

/**
 * Copies the best rule of the active snapshot for one call into @p rule; no reload.
 *
 * Lock-free: the copy is validated against the snapshot's sequence afterwards, and a
 * copy that a concurrent reload may have torn is discarded (0: this call injects
 * nothing, which is the fail-open choice).
 *
 * @param effect     Effect to look for.
 * @param operation  Operation of the call.
 * @param clock_id   Clock of a clock read; ignored by non-CLOCK_ID selectors.
 * @param rule       Receives the rule; may be written even when 0 is returned.
 * @return           Non-zero when a rule matched and the copy is consistent.
 */
int chaos_time_config_match_loaded(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

/**
 * The wrappers' lookup: chaos_time_config_prepare(), then chaos_time_config_match_loaded().
 *
 * @param effect     Effect to look for.
 * @param operation  Operation of the call.
 * @param clock_id   Clock of a clock read; ignored by non-CLOCK_ID selectors.
 * @param rule       Receives the rule. NULL returns 0.
 * @return           Non-zero when a rule matched; 0 when none did or no rule is loaded.
 */
int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
);

/**
 * Parses one rule line whose qualifiers chaos_policy_extract() has already removed.
 *
 * Edits @p line in place (comment cut, trimmed, split at the first two ':').
 *
 * @param line  Mutable line.
 * @param rule  Receives the rule; zeroed and filled on 1, partly written on -1.
 * @return      1 for a rule, 0 for a blank or comment-only line, -1 for an invalid line
 *              (bad field count, selector, effect, value, probability, or an effect the
 *              selector does not allow).
 */
int chaos_time_config_parse_line(char *line, chaos_time_rule_t *rule);

/**
 * Parses a whole rule file; any invalid line rejects all of it.
 *
 * Splits @p buffer at '\n' in place, extracts each line's qualifiers, parses the rest
 * and keeps each accepted line's text for the hits file. Stops at the first invalid
 * line (or qualifiers on a line without a rule), or at rule CHAOS_TIME_MAX_RULES + 1,
 * and records that line for chaos_time_config_last_error(). Not thread-safe: only the
 * reload owner calls it.
 *
 * @param buffer      Mutable NUL-terminated file content.
 * @param rules       Array of CHAOS_TIME_MAX_RULES entries.
 * @param rule_count  Receives the rule count; 0 on failure.
 * @return            0 on success, -1 when the file is rejected.
 */
int chaos_time_config_parse_buffer(char *buffer, chaos_time_rule_t *rules, size_t *rule_count);

/**
 * @brief The line the last chaos_time_config_parse_buffer() call rejected.
 *
 * @return The rejected line (`reason != NULL`), or a cleared record when the last
 *         parse succeeded. Valid until the next parse.
 */
const chaos_status_error_t *chaos_time_config_last_error(void);

/**
 * Picks the most specific rule for (effect, operation, clock_id) from @p rules.
 *
 * Highest rank wins (CLOCK_ID 3 > OPERATION 2 > ANY 1); within a rank the longer
 * selector text wins (`clock_gettime/monotonic` over `clock_gettime/1`); on a full tie
 * the earlier line wins. O(rule_count).
 *
 * @param rules       Rules to search; NULL returns 0.
 * @param rule_count  Number of rules.
 * @param effect      Effect to match exactly.
 * @param operation   Operation of the call.
 * @param clock_id    Clock of a clock read.
 * @param rule        Receives the winner; NULL returns 0.
 * @return            Non-zero when a rule matched.
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
