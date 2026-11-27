/**
 * @file chaos_io_config.h
 * @brief libchaos-io rule file (`/tmp/.chaos-io.conf`): grammar, parser, reload and rule
 *        selection.
 *
 * @details
 * Wrappers hard-code no fault behaviour; each one asks this module for the rule that
 * applies to its operation and path. A running process picks up an edited rule file at
 * the first intercepted call made CHAOS_CHECK_INTERVAL_NS (1 ms) or more after its
 * previous check; no restart and no signal are needed.
 *
 * @par Rule grammar
 * One rule per line; blank lines and `#` comments are ignored; qualifiers
 * (chaos_policy.h) go after the rule:
 * @code
 * <path_prefix>:<operation>:<effect>:<parameter> [@first=N] [@from=T] [@until=T] [@size>N]
 * /data:write:EIO:0.5
 * /data/wal:fsync:LATENCY:200 @first=3
 * *:read:CORRUPT:0.01
 * @endcode
 * Fields are split on the first three `:` and trimmed, so a path prefix cannot contain
 * `:`. Effect and parameter:
 *
 * | Effect | Parameter | Operations |
 * |--------|-----------|------------|
 * | EIO, ENOSPC, EDQUOT, EROFS, EACCES, EMFILE, ENFILE, ENOENT (ERRNO) | probability | all |
 * | LATENCY | delay in ms, 0 to 4294967295 | all |
 * | TORN | probability | write, pwrite |
 * | CORRUPT | probability | read, pread |
 *
 * `*` matches every absolute file path except memfds. At most one rule applies to a call:
 * the one with the longest matching prefix for the call's operation, the earlier one in
 * the file on a tie (chaos_io_config_select_rule()).
 *
 * Where TORN and CORRUPT take effect: TORN shortens write, pwrite, sendfile,
 * copy_file_range, and writev/pwritev of at most 64 entries; the stdio write functions
 * match `write` rules but ignore
 * TORN (a short fwrite means an error in stdio, not a partial success). CORRUPT applies
 * to read, readv, pread, preadv and the stdio reads.
 *
 * @par All or nothing
 * One invalid line, more than CHAOS_IO_MAX_RULES (256) rules, a file of
 * CHAOS_IO_MAX_CONFIG_BYTES (256 KiB) or more, an unreadable file or a NUL byte leaves
 * the library with no rules, and the status file `/tmp/.chaos-io.status` names the
 * reason. A partial rule set the operator did not intend is never applied.
 *
 * @par Snapshots and reload
 * Two statically allocated snapshots; one is active, the other is rewritten by the
 * single thread that wins the reload claim (a CAS on the cached change stamp) and then
 * published. Readers never block and never take a lock; a seqlock per snapshot
 * (chaos_hits.h) discards a rule copied while a reload rewrote it. The full protocol is
 * documented in chaos_io_config.c.
 *
 * @par Thread safety
 * Every function except chaos_io_config_init() may be called concurrently. errno is
 * preserved by chaos_io_config_prepare() and everything that calls it.
 */

#ifndef CHAOS_IO_CONFIG_H
#define CHAOS_IO_CONFIG_H

#include "chaos_io_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

/**
 * @brief Operation field of a rule, and the wrappers that consult it.
 *
 * @details Parsed once so the per-call match compares integers, not strings. The
 * `rename_from` / `rename_to` split lets a rule target either side of a rename, e.g.
 * only the final name of a write-to-temp-then-rename commit. stdio wrappers use `read`
 * and `write` on the stream's descriptor.
 */
typedef enum chaos_io_operation
{
    CHAOS_IO_OP_INVALID = -1, /**< Parse failure; never stored in a parsed rule. */
    CHAOS_IO_OP_READ,         /**< `read`: read, readv, fread, fgets, fgetc, getc, getdelim. */
    CHAOS_IO_OP_WRITE,        /**< `write`: write, writev, sendfile, copy_file_range, stdio. */
    CHAOS_IO_OP_OPEN,         /**< `open`: open, openat, creat, fopen, freopen. */
    CHAOS_IO_OP_CLOSE,        /**< `close`: close (ERRNO reported after the real close). */
    CHAOS_IO_OP_FSYNC,        /**< `fsync`: fsync. */
    CHAOS_IO_OP_FDATASYNC,    /**< `fdatasync`: fdatasync. */
    CHAOS_IO_OP_PREAD,        /**< `pread`: pread, preadv. */
    CHAOS_IO_OP_PWRITE,       /**< `pwrite`: pwrite, pwritev. */
    CHAOS_IO_OP_TRUNCATE,     /**< `truncate`: ftruncate, truncate. */
    CHAOS_IO_OP_ALLOCATE,     /**< `allocate`: fallocate, posix_fallocate. */
    CHAOS_IO_OP_UNLINK,       /**< `unlink`: unlinkat, unlink, rmdir, remove. */
    CHAOS_IO_OP_RENAME_FROM,  /**< `rename_from`: source of renameat, renameat2, rename. */
    CHAOS_IO_OP_RENAME_TO,    /**< `rename_to`: target of renameat, renameat2, rename. */
    CHAOS_IO_OP_STATFS        /**< `statfs`: statfs, fstatfs, statvfs, fstatvfs. */
} chaos_io_operation_t;

/**
 * @brief Effect of a rule.
 *
 * @details The parser rejects effect/operation pairs that make no sense, so wrappers never
 * check them: TORN only with `write`/`pwrite`, CORRUPT only with `read`/`pread`; ERRNO
 * and LATENCY with every operation.
 */
typedef enum chaos_io_effect
{
    CHAOS_IO_EFFECT_INVALID = -1, /**< Parse failure; never stored in a parsed rule. */
    CHAOS_IO_EFFECT_ERRNO,        /**< Fail before the real call with `errnum`. */
    CHAOS_IO_EFFECT_LATENCY,      /**< Delay the real call by `latency_ms`. */
    CHAOS_IO_EFFECT_TORN,         /**< Real write with a byte count in [1, n-1]. */
    CHAOS_IO_EFFECT_CORRUPT,      /**< Flip one bit of the bytes a read returned. */
    CHAOS_IO_EFFECT_DROP,         /**< Report the whole write as done without writing it. */
    CHAOS_IO_EFFECT_FREE,         /**< Report `free_bytes` of free space on the filesystem. */
    CHAOS_IO_EFFECT_FULL,         /**< Report the filesystem as having no free space. */
    CHAOS_IO_EFFECT_THROTTLE      /**< Hold a write to `rate_bps` bytes per second. */
} chaos_io_effect_t;

/**
 * @brief One parsed rule, as stored in a snapshot and copied to a wrapper.
 *
 * @details Wrappers receive a by-value copy (chaos_io_config_match_loaded()), so a copy
 * stays usable while a reload replaces the snapshot. Two members still point into shared
 * state and are protected by other means: `resolved_prefix` (into the snapshot; used only
 * during selection, under the seqlock) and `hit` (into the slot pool; guarded by
 * `hit_generation`, see chaos_hits.h).
 *
 * Invariants of a rule chaos_io_config_parse_line() returned 1 for: `operation` and
 * `effect` are valid, the pair is allowed, and `path_len == strlen(path_prefix)`.
 */
typedef struct chaos_io_rule
{
    char path_prefix[CHAOS_IO_MAX_RULE_PATH]; /**< Prefix as written; absolute ones normalised. */
    size_t path_len;                          /**< `strlen(path_prefix)`; the selection key. */
    /**
     * The prefix with symbolic links resolved, when that differs (`/lib` -> `/usr/lib`):
     * descriptors resolve to the kernel's name for their file. Points into the snapshot;
     * NULL when the resolution equals the prefix or failed.
     */
    const char *resolved_prefix;
    size_t resolved_len;            /**< `strlen(resolved_prefix)`; 0 when NULL. */
    chaos_io_operation_t operation; /**< Operation the rule applies to. */
    chaos_io_effect_t effect;       /**< Effect applied when the rule fires. */
    int errnum;                     /**< errno for ERRNO; 0 otherwise. */
    double probability;      /**< Probability in [0, 1]; 1.0 for `LATENCY:ms` without `@p`. */
    unsigned int latency_ms; /**< Delay in ms for LATENCY; 0 otherwise. */
    uint64_t free_bytes;     /**< Free space to report for FREE; 0 otherwise (and for FULL). */
    uint64_t rate_bps;       /**< THROTTLE: bytes per second, 1 .. 4294967295; 0 otherwise. */
    /** Qualifiers written after the rule (`@first`, `@from`, `@until`, `@size`). */
    chaos_rule_policy_t policy;
    /**
     * Byte count of the call this copy is decided for, set by wrappers that move data;
     * CHAOS_POLICY_NO_SIZE otherwise, which fails every `@size` gate.
     */
    uint64_t call_size;
    /** Hit slot of the rule (chaos_hits.h); NULL for a rule outside a snapshot (tests). */
    chaos_hit_slot_t *hit;
    /** Slot generation at publication; a newer slot generation means the rule left the file. */
    uint64_t hit_generation;
    /**
     * Draw key of the rule: `mix(process seed ^ hash(rule text))`, set when the snapshot is
     * published. From the text, not the slot index, because chaos_hits_assign() hands slots
     * out again and another rule would inherit the key. See chaos_io_rule_draw().
     */
    uint64_t key;
    /**
     * Base of this call's draws, set by chaos_io_rule_should_trigger() from the key and the
     * rule's evaluation number; the effects derive their samples from it. Not part of the
     * rule as parsed -- it belongs to the one call this copy was made for.
     */
    uint64_t draw_base;
} chaos_io_rule_t;

/**
 * @brief Starts this call's draws: records the rule's evaluation number and derives the
 *        base every sample of this call comes from.
 *
 * @details Two stages, not one. The first turns (rule, evaluation) into a base, the second
 * turns (base, draw number) into a sample, so a rule that takes three draws cannot collide
 * with the next evaluation of itself -- which is what a single `key + n * K + sub` does as
 * soon as `sub` reaches K, a constant the next effect added would break silently.
 *
 * The evaluation number comes from the hit slot, so it survives a reload that keeps the
 * rule, and restarts in a forked child, whose lineage differs anyway.
 *
 * @param rule  Rule copy for this call; NULL is a no-op. A rule outside a snapshot (unit
 *              tests) has no slot and evaluates as number 0 every time.
 */
static inline uint64_t chaos_io_rule_draw_begin(chaos_io_rule_t *rule)
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
    rule->draw_base = chaos_io_prng_mix((rule->key ^ g_chaos_io_lineage) + evaluation);
    return evaluation + 1U;
}

/**
 * @brief Sample @p draw of this call, uniform in [0, 2^32).
 *
 * @param[in] rule  Rule copy whose chaos_io_rule_draw_begin() ran.
 * @param[in] draw  Which draw of this call: 0 is the probability, the effects follow.
 * @return The sample.
 */
static inline uint32_t chaos_io_rule_draw(const chaos_io_rule_t *rule, uint64_t draw)
{
    return (uint32_t)(chaos_io_prng_mix(rule->draw_base + draw) >> 32);
}

/** @brief Draw number of the probability decision; effects number their draws after it. */
#define CHAOS_IO_DRAW_PROBABILITY UINT64_C(0)

/** @brief Draw number of TORN's byte count, and of CORRUPT's byte index. */
#define CHAOS_IO_DRAW_FIRST_EFFECT UINT64_C(1)

/** @brief Draw number of CORRUPT's bit index. */
#define CHAOS_IO_DRAW_SECOND_EFFECT UINT64_C(2)

/**
 * @brief Resets the rule cache to "no rules" and forces a rule-file read on the next
 *        chaos_io_config_prepare().
 *
 * @details Zeroes both snapshots (`parse_ok = 1`), resets the hit-slot pool, picks this
 * image's hits-file suffix, registers the atfork child handler once, looks up the vDSO
 * clock (so the first lookup does not happen inside a wrapper a signal handler may
 * re-enter), and sets the cached change stamp to CHAOS_IO_MTIME_UNKNOWN.
 *
 * Not thread-safe: call from the constructor or a single-threaded test set-up only.
 */
void chaos_io_config_init(void);

/**
 * @brief Reloads the rule file when it changed, then reports whether any rule is active.
 *
 * @details Throttled to one `stat()` per CHAOS_CHECK_INTERVAL_NS once a change stamp is
 * cached. When the stamp (mtime, size, inode, device) differs, or the last load was
 * provisional, or link-dependent rule paths are due for re-resolution, the caller tries
 * to claim the reload with a CAS; the winner reads, parses and publishes the inactive
 * snapshot, and every other thread continues with the current snapshot (at most one
 * version stale, always consistent). Never blocks on another thread.
 *
 * Failure behaviour: fail-open. A missing, unreadable, oversized or invalid rule file
 * yields no rules (and a status file that says why); a transient read failure keeps the
 * current rules and retries on the next check. The application's call is never failed
 * by the library itself. errno is preserved.
 *
 * @return Non-zero when the active snapshot holds at least one rule; 0 otherwise.
 */
int chaos_io_config_prepare(void);

/**
 * @brief Copies the active snapshot's best rule for @p operation on @p path into @p rule.
 *
 * @details Lock-free: samples the snapshot's seqlock, selects with
 * chaos_io_config_select_rule(), and reports no match when a reload rewrote the snapshot
 * during the copy. Does not reload and does not check exclusions; call
 * chaos_io_config_prepare() first. Probability and qualifiers are not evaluated here;
 * see chaos_io_rule_should_trigger().
 *
 * @param[in]  operation  Operation to match.
 * @param[in]  path       Normalised absolute path; NULL returns 0.
 * @param[out] rule       Receives the copy; may be written even when 0 is returned (a
 *                        torn copy). NULL returns 0.
 * @return Non-zero when a rule matched and the copy is consistent; 0 otherwise.
 */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
);

/**
 * @brief Exclusion check, chaos_io_config_prepare(), then chaos_io_config_match_loaded():
 *        the lookup for wrappers that receive a path rather than a descriptor.
 *
 * @details Excluded paths (chaos_io_is_excluded_path()) return 0 before the rule file is
 * even checked.
 *
 * @param[in]  operation  Operation to match.
 * @param[in]  path       Normalised absolute path; NULL returns 0.
 * @param[out] rule       Receives the matching rule; NULL returns 0.
 * @return Non-zero when a rule matched; 0 to pass the call through.
 */
int chaos_io_config_match_path(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
);

/**
 * @brief Parses one rule line (qualifiers already removed) into @p rule.
 *
 * @details Strips a `#` comment, trims, splits on the first three `:`, trims each field
 * and validates operation, effect, parameter and the effect/operation pair. The path
 * prefix must be shorter than CHAOS_IO_MAX_RULE_PATH (1024) bytes and is not normalised
 * here.
 *
 * @param[in,out] line  Mutable NUL-terminated line; modified in place. NULL returns -1.
 * @param[out]    rule  Receives the rule; NULL returns -1.
 * @return 1 for a rule; 0 for a blank or comment-only line (@p rule untouched); -1 for an
 *         invalid line (@p rule partially written).
 */
int chaos_io_config_parse_line(char *line, chaos_io_rule_t *rule);

/**
 * @brief Parses a whole rule file, all or nothing.
 *
 * @details Splits @p buffer in place on LF; for each line keeps a copy for the status
 * report, extracts the qualifiers (chaos_policy_extract()) and parses the rule. The first
 * failure stops the parse: an invalid line or qualifier, qualifiers without a rule, rule
 * number CHAOS_IO_MAX_RULES + 1, or a rule this build cannot apply
 * (CHAOS_IO_RULE_SUPPORTED, used by chaos-init). The reason is available from
 * chaos_io_config_last_error(). Not reentrant: uses module-level scratch, so only the
 * reload owner (or a single-threaded test) may call it.
 *
 * @param[in,out] buffer      Mutable NUL-terminated file contents; NULL returns -1.
 * @param[out]    rules       Room for CHAOS_IO_MAX_RULES rules; NULL returns -1.
 * @param[out]    rule_count  Rules parsed on success, 0 on failure; NULL returns -1.
 * @return 0 on success; -1 on the first failure.
 */
int chaos_io_config_parse_buffer(char *buffer, chaos_io_rule_t *rules, size_t *rule_count);

/**
 * @brief The rejection record of the last chaos_io_config_parse_buffer() or whole-file
 *        rejection.
 *
 * @return Never NULL. `reason != NULL` when something was rejected; a cleared record
 *         after a successful parse. Overwritten by the next reload.
 */
const chaos_status_error_t *chaos_io_config_last_error(void);

/**
 * @brief Selects the rule for @p operation whose prefix covers @p path with the longest
 *        written prefix.
 *
 * @details Linear scan, O(rule_count). A prefix covers a path when the path equals it
 * or continues with `/` after it (so `/data` covers `/data/x` but not `/database`); the
 * prefix as written and its link-resolved form are both tried. `*` covers every absolute
 * path except `/memfd:` names. The key is `path_len` of the written prefix: `*` has
 * length 1 and loses to every longer prefix; on equal length the earlier rule in the file
 * wins.
 *
 * @param[in]  rules       Rules to search; NULL returns 0.
 * @param[in]  rule_count  Entries in @p rules.
 * @param[in]  operation   Operation to filter by.
 * @param[in]  path        Normalised absolute path; NULL returns 0.
 * @param[out] rule        Receives a copy of the winner; NULL returns 0.
 * @return Non-zero when a rule matched; 0 otherwise.
 */
int chaos_io_config_select_rule(
    const chaos_io_rule_t *rules,
    size_t rule_count,
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule
);

#endif
