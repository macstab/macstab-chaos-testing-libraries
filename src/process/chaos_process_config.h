/**
 * @file chaos_process_config.h
 * @brief Rule model and rule-file API of libchaos-process.
 *
 * @details
 * ### Rule grammar
 *
 * One rule per line of /tmp/.chaos-process.conf; blank lines and `#` comments are
 * ignored:
 * @code
 *   <selector>:<EFFECT>:<value>[@<probability>] [<qualifier> ...] [# comment]
 * @endcode
 * Fields are split at the first two `:` and trimmed. The probability (default 1)
 * follows the last `@` of the value field and uses the locale-independent grammar of
 * chaos_policy_parse_probability(). Qualifiers (`@first=N`, `@from=T`, `@until=T`,
 * `@size>N`, `@size<N`) are separate words (chaos_policy.h); no wrapper of this library
 * passes a byte count (call_size is always CHAOS_POLICY_NO_SIZE), so a rule with
 * `@size` never fires.
 *
 * Selectors: `*` (rank 1) or one operation (rank 2): `pthread_create`, `fork`,
 * `posix_spawn`, `posix_spawnp`, `execve`, `execveat`, `waitpid`. Wrappers without a
 * selector of their own use another operation's rules (chaos_process_hooks.c).
 *
 * | Effect       | Value                       | Behaviour                                |
 * |--------------|-----------------------------|------------------------------------------|
 * | `ERRNO`      | errno name or 1..2147483647 | fail the call without calling libc       |
 * | `LATENCY`    | ms, 0..4294967295           | sleep before the call (chaos_sleep_ms()) |
 * | `FAIL_AFTER` | `<errno>,<N>`               | let N calls through, then fail           |
 *
 * Errno names: EAGAIN, ENOMEM, EACCES, ENOENT, EINTR, ECHILD, EPERM, ESRCH, EBUSY,
 * EINVAL, ENOSYS, EMFILE, ENFILE, E2BIG.
 *
 * @code
 *   *:ERRNO:EAGAIN@0.1                 # 10 % of every wrapped call fails with EAGAIN
 *   fork:LATENCY:50                    # every fork waits 50 ms first
 *   pthread_create:FAIL_AFTER:ENOMEM,100 @first=5
 * @endcode
 *
 * Any invalid line rejects the whole file: no rule applies (fail-open) and the status
 * file names the line.
 *
 * ### Reload
 *
 * Each process looks at the rule file at most once per CHAOS_CHECK_INTERVAL_NS (1 ms),
 * timed by the vDSO CLOCK_MONOTONIC (chaos_clock.h); without a vDSO clock it looks on
 * every call. The first load and a call during a reload are never throttled. A look is
 * one stat(); the file is read only when its change stamp (mtime, size, inode, device)
 * differs, or when the last load was provisional (an mtime younger than
 * CHAOS_RACY_WINDOW_MS, 20 ms). Readers see the previous or the new rule set, never a
 * mix. Every published load resets the FAIL_AFTER counters.
 */

#ifndef CHAOS_PROCESS_CONFIG_H
#define CHAOS_PROCESS_CONFIG_H

#include "chaos_process_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

/**
 * @brief Operation a call is matched as; also the index into
 *        g_chaos_process_fail_after_counters[].
 *
 * Contiguous from 0; CHAOS_PROCESS_OP_COUNT must stay last.
 */
typedef enum chaos_process_operation
{
    CHAOS_PROCESS_OP_INVALID = -1,   /**< Never stored in a valid rule; operation of `*`. */
    CHAOS_PROCESS_OP_PTHREAD_CREATE, /**< pthread_create. */
    CHAOS_PROCESS_OP_FORK,           /**< fork. */
    CHAOS_PROCESS_OP_POSIX_SPAWN,    /**< posix_spawn, system, popen. */
    CHAOS_PROCESS_OP_POSIX_SPAWNP,   /**< posix_spawnp. */
    CHAOS_PROCESS_OP_EXECVE,         /**< execve, execv, execvp, execvpe, execl, execlp, execle. */
    CHAOS_PROCESS_OP_EXECVEAT,       /**< execveat, fexecve (Linux only). */
    CHAOS_PROCESS_OP_WAITPID,        /**< waitpid, wait, wait3, wait4, waitid. */
    CHAOS_PROCESS_OP_COUNT           /**< Number of operations. */
} chaos_process_operation_t;

/**
 * @brief Selector form; also its rank in chaos_process_config_select_rule().
 */
typedef enum chaos_process_selector_kind
{
    CHAOS_PROCESS_SELECTOR_INVALID = -1, /**< Unparseable; never stored. */
    CHAOS_PROCESS_SELECTOR_ANY,          /**< `*`: every operation; rank 1. */
    CHAOS_PROCESS_SELECTOR_OPERATION     /**< One operation by name; rank 2. */
} chaos_process_selector_kind_t;

/**
 * @brief Effect of a rule. A call applies at most one rule per effect, in the order
 *        LATENCY, ERRNO, FAIL_AFTER.
 */
typedef enum chaos_process_effect
{
    CHAOS_PROCESS_EFFECT_INVALID = -1,  /**< Unparseable; never stored. */
    CHAOS_PROCESS_EFFECT_ERRNO = 0,     /**< Fail the call without calling libc. */
    CHAOS_PROCESS_EFFECT_LATENCY = 1,   /**< Sleep latency_ms before the call. */
    CHAOS_PROCESS_EFFECT_FAIL_AFTER = 2 /**< Let N calls through, then fail. */
} chaos_process_effect_t;

/**
 * @brief Parsed selector.
 */
typedef struct chaos_process_selector
{
    /** Form; decides the rank. */
    chaos_process_selector_kind_t kind;

    /** Operation; CHAOS_PROCESS_OP_INVALID for `*`. */
    chaos_process_operation_t operation;

    /**
     * strlen of the selector as written; tie-breaker within a rank. In this grammar it
     * never differs within a rank, so on equal rank the earlier line wins.
     */
    size_t selector_len;
} chaos_process_selector_t;

/**
 * @brief One parsed rule, as stored in a snapshot and copied out per call.
 *
 * A wrapper decides on its own copy, validated against the snapshot sequence, so a
 * concurrent reload cannot tear it.
 */
typedef struct chaos_process_rule
{
    /** Calls the rule applies to. */
    chaos_process_selector_t selector;

    /** What it does to them; decides which fields below are used. */
    chaos_process_effect_t effect;

    /**
     * ERRNO and FAIL_AFTER: the error to report, > 0. pthread_create and
     * posix_spawn(p) return it; every other wrapper sets errno to it and returns -1
     * (NULL for popen).
     */
    int errnum;

    /**
     * Chance per eligible call, [0.0, 1.0], from the `@<probability>` suffix; default
     * 1.0. Drawn from the calling thread's PRNG.
     */
    double probability;

    /**
     * LATENCY: delay in ms, slept with chaos_sleep_ms() before the real call.
     *
     * - fork: the parent sleeps before forking; the child sees no delay.
     * - execve/execveat: the sleep happens before the exec; a successful exec then
     *   discards all library state, including hits not yet written to the hits file.
     * - waitpid family: the caller waits latency_ms plus however long the real call
     *   blocks, even with WNOHANG.
     */
    unsigned int latency_ms;

    /**
     * FAIL_AFTER: number N of calls let through before failures start.
     *
     * g_chaos_process_fail_after_counters[operation] counts up once per call that
     * reaches this rule; a call whose pre-increment value is >= N fails (subject to
     * probability and qualifiers). N = 0 fails from the first call. The counter is
     * per operation and process-wide (all threads), and is reset on every published
     * load and in a forked child.
     */
    uint64_t fail_after_count;
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
} chaos_process_rule_t;

/**
 * @brief Resets the rule state: both snapshots empty, hit pool and FAIL_AFTER counters
 *        cleared, change stamp unknown.
 *
 * Also records the process id and hits-file number, registers the atfork child handler
 * (once) and resolves the vDSO clock, so no wrapper does that lookup first inside a
 * signal handler. Called by the constructor before any rule is loaded; not thread-safe.
 */
void chaos_process_config_init(void);

/**
 * @brief Reloads the rule file if it changed; errno is preserved.
 *
 * Throttled to one look per CHAOS_CHECK_INTERVAL_NS (1 ms) per process once a first
 * load has completed and while no reload is in progress; without a vDSO clock every
 * call looks. A look is one stat(); the file is read and parsed into the inactive
 * snapshot only when its change stamp differs (or the last load was provisional), and
 * that snapshot is then published. A caller that finds a reload in progress does not
 * wait: it uses the active snapshot. Writes the status file after each load and the
 * hits file when a report is overdue.
 *
 * @return Non-zero when the active snapshot holds at least one rule.
 */
int chaos_process_config_prepare(void);

/**
 * @brief Copies the best rule of the active snapshot for one call into @p rule; no
 *        reload.
 *
 * Lock-free: the copy is validated against the snapshot's sequence afterwards, and a
 * copy a concurrent reload may have torn is discarded (0: this call injects nothing).
 *
 * @param effect    Effect to look for.
 * @param operation Operation of the call.
 * @param rule      Receives the rule; may be written even when 0 is returned.
 * @return Non-zero when a rule matched and the copy is consistent.
 */
int chaos_process_config_match_loaded(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

/**
 * @brief The wrappers' lookup: chaos_process_config_prepare(), then
 *        chaos_process_config_match_loaded().
 *
 * @param effect    Effect to look for.
 * @param operation Operation of the call.
 * @param rule      Receives the rule. NULL returns 0.
 * @return Non-zero when a rule matched; 0 when none did or no rule is loaded.
 */
int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
);

/**
 * @brief Parses one rule line whose qualifiers chaos_policy_extract() has already
 *        removed.
 *
 * Edits @p line in place (comment cut, trimmed, split at the first two ':').
 *
 * @param line  Mutable line.
 * @param rule  Receives the rule; zeroed and filled on 1, partly written on -1.
 * @return  1  A rule.
 * @return  0  Blank or comment-only line; @p rule untouched.
 * @return -1  Invalid line (field count, selector, effect, value or probability); the
 *             whole file is then rejected.
 */
int chaos_process_config_parse_line(char *line, chaos_process_rule_t *rule);

/**
 * @brief Parses a whole rule file; any invalid line rejects all of it.
 *
 * Splits @p buffer at '\n' in place, extracts each line's qualifiers, parses the rest
 * and keeps each accepted line's text for the hits file. Stops at the first invalid
 * line (or qualifiers on a line without a rule), at rule CHAOS_PROCESS_MAX_RULES + 1,
 * or at a rule CHAOS_PROCESS_RULE_SUPPORTED rejects (chaos-init), and records that line
 * for chaos_process_config_last_error(). Not thread-safe: only the reload owner calls
 * it.
 *
 * @param buffer      Mutable NUL-terminated file content.
 * @param rules       Array of CHAOS_PROCESS_MAX_RULES entries.
 * @param rule_count  Receives the rule count; 0 on failure.
 * @return 0 on success, -1 when the file is rejected.
 */
int chaos_process_config_parse_buffer(
    char *buffer, chaos_process_rule_t *rules, size_t *rule_count
);

/**
 * @brief The line the last chaos_process_config_parse_buffer() call rejected.
 *
 * @return The rejected line (`reason != NULL`), or a cleared record when the last
 *         parse succeeded. Valid until the next parse.
 */
const chaos_status_error_t *chaos_process_config_last_error(void);

/**
 * @brief Picks the most specific rule for (effect, operation) from @p rules.
 *
 * Highest rank wins (OPERATION 2 > ANY 1); within a rank the longer selector text
 * (never different in this grammar); on a full tie the earlier line. O(rule_count).
 *
 * @param rules       Rules to search; NULL returns 0.
 * @param rule_count  Number of rules.
 * @param effect      Effect to match exactly.
 * @param operation   Operation of the call.
 * @param rule        Receives the winner, by value; NULL returns 0.
 * @return Non-zero when a rule matched.
 */
int chaos_process_config_select_rule(
    const chaos_process_rule_t *rules,
    size_t rule_count,
    chaos_process_effect_t effect,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule
);

#endif
