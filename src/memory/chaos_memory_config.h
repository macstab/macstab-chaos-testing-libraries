/**
 * @file chaos_memory_config.h
 * @brief Rule model of libchaos-memory: selectors, effects, the rule struct, and
 *        the load/match API over the rule file.
 *
 * @details
 * Rule file: CHAOS_MEMORY_CONFIG_PATH (`/tmp/.chaos-memory.conf`). One rule per
 * line; blank lines and `#` comments are ignored; blanks around fields are trimmed:
 *
 * @code
 *   <selector>:<effect>:<value>[@<probability>] [qualifiers] [# comment]
 * @endcode
 *
 * | Field       | Values                                                         |
 * |-------------|----------------------------------------------------------------|
 * | selector    | `*`, `mmap`, `mmap/anon`, `mmap/file`, `munmap`, `mprotect`, `madvise` |
 * | effect      | `ERRNO` (value: errno name or positive decimal), `LATENCY` (ms) |
 * | probability | `0`, `1`, `0.<digits>`, `1.<zeros>`; default 1                  |
 * | qualifiers  | `@first=N`, `@from=T`, `@until=T`, `@size>N`, `@size<N`         |
 *
 * @code
 *   mmap/anon : ERRNO : ENOMEM@0.05   # fail 5% of anonymous mmaps
 *   mmap/file : LATENCY : 20          # add 20 ms to file-backed mmaps
 *   mprotect  : ERRNO : EPERM         # always fail mprotect
 *   *         : LATENCY : 5@0.1       # 10% chance of 5 ms on any call
 *   mmap/anon:ERRNO:ENOMEM @size>1048576 @first=3
 * @endcode
 *
 * Any invalid line rejects the whole file: the process then runs with no rules
 * and the status file names the line (fail-open, but visible).
 *
 * @par Rule selection
 * Per call, the LATENCY rules and the ERRNO rules are matched separately, so one
 * call can be both delayed and failed. Among the matching rules of one effect the
 * most specific selector wins: `*` (rank 1) < operation (rank 2) < `mmap/anon` /
 * `mmap/file` (rank 3); equal rank goes to the longer selector text, then to the
 * earlier line.
 *
 * @par Reload
 * After the first load, each process looks at the rule file (one stat(2)) at most
 * once per CHAOS_CHECK_INTERVAL_NS (1 ms, vDSO CLOCK_MONOTONIC); without a vDSO
 * clock it looks on every call. A changed change stamp (mtime, size, inode,
 * device) makes one thread, chosen by CAS on the cached stamp, parse the file
 * into the inactive of two snapshots and publish it; other threads keep serving
 * the active snapshot meanwhile. Details in chaos_memory_config.c.
 *
 * @par Stability
 * Internal.
 */
#ifndef CHAOS_MEMORY_CONFIG_H
#define CHAOS_MEMORY_CONFIG_H

#include "chaos_memory_internal.h"
#include "chaos_hits.h"
#include "chaos_policy.h"
#include "chaos_status.h"

/* =========================================================================
 * Enumerations
 * =========================================================================
 */

/**
 * @brief Intercepted function a selector names.
 *
 * @details posix_madvise() is matched as CHAOS_MEMORY_OP_MADVISE; mmap64() as
 * CHAOS_MEMORY_OP_MMAP.
 */
typedef enum chaos_memory_operation
{
    /** No operation: used by the `*` selector, which ignores the field. */
    CHAOS_MEMORY_OP_INVALID = -1,
    /** mmap(2), mmap64; `mmap/anon` and `mmap/file` refine it. */
    CHAOS_MEMORY_OP_MMAP,
    /** mprotect(2). */
    CHAOS_MEMORY_OP_MPROTECT,
    /** madvise(2) and posix_madvise(3). */
    CHAOS_MEMORY_OP_MADVISE,
    /** munmap(2). */
    CHAOS_MEMORY_OP_MUNMAP
} chaos_memory_operation_t;

/**
 * @brief Granularity of a selector; determines its rank in rule selection.
 *
 * @details
 * | Kind      | Selector text                                 | Rank |
 * |-----------|-----------------------------------------------|------|
 * | ANY       | `*`                                           | 1    |
 * | OPERATION | `mmap`, `munmap`, `mprotect`, `madvise`       | 2    |
 * | MMAP_KIND | `mmap/anon`, `mmap/file`                      | 3    |
 */
typedef enum chaos_memory_selector_kind
{
    /** Not a parsed selector. */
    CHAOS_MEMORY_SELECTOR_INVALID = -1,
    /** `*`: every intercepted call. */
    CHAOS_MEMORY_SELECTOR_ANY,
    /** One operation, e.g. `mmap`. */
    CHAOS_MEMORY_SELECTOR_OPERATION,
    /** `mmap/anon` or `mmap/file`; operation is always CHAOS_MEMORY_OP_MMAP. */
    CHAOS_MEMORY_SELECTOR_MMAP_KIND
} chaos_memory_selector_kind_t;

/**
 * @brief Anonymous versus file-backed mapping, decided by MAP_ANONYMOUS
 *        (chaos_memory_mmap_is_anonymous()).
 *
 * @details
 *  - ANON (`mmap/anon`): memory of preloaded allocators and runtimes, JIT code
 *    buffers, MAP_SHARED|MAP_ANONYMOUS memory shared with children. Not libc
 *    malloc, which calls its internal `__mmap` (see chaos_memory_mmap_is_anonymous()).
 *  - FILE (`mmap/file`): mappings of a descriptor: files, devices, POSIX shared
 *    memory objects. A rule here tests file-mapping error paths without touching
 *    a preloaded allocator.
 */
typedef enum chaos_memory_mmap_kind
{
    /** Not a `mmap/...` selector. */
    CHAOS_MEMORY_MMAP_KIND_INVALID = -1,
    /** MAP_ANONYMOUS set. */
    CHAOS_MEMORY_MMAP_KIND_ANON = 0,
    /** MAP_ANONYMOUS clear. */
    CHAOS_MEMORY_MMAP_KIND_FILE
} chaos_memory_mmap_kind_t;

/**
 * @brief Effect of a rule. Both act before the real function is called.
 *
 * @details
 *  - ERRNO: set errno to errnum and return the failure value (MAP_FAILED; -1;
 *    posix_madvise(): the error number) without calling the real function.
 *  - LATENCY: sleep latency_ms, then call the real function.
 *
 * @note There is deliberately no CORRUPT or OFFSET effect: the only output of
 *       mmap() is an address, and altering it yields SIGSEGV or corrupted data
 *       rather than an error path (see chaos_memory_actions.c).
 */
typedef enum chaos_memory_effect
{
    /** Not a parsed effect. */
    CHAOS_MEMORY_EFFECT_INVALID = -1,
    /** `ERRNO`: fail the call with errnum. */
    CHAOS_MEMORY_EFFECT_ERRNO = 0,
    /** `LATENCY`: delay the call by latency_ms. */
    CHAOS_MEMORY_EFFECT_LATENCY
} chaos_memory_effect_t;

/* =========================================================================
 * Structs
 * =========================================================================
 */

/**
 * @brief Parsed selector (chaos_memory_selector_parse()).
 *
 * @details Embedded by value in a rule; no heap memory.
 */
typedef struct chaos_memory_selector
{
    /** Granularity; never CHAOS_MEMORY_SELECTOR_INVALID after a successful parse. */
    chaos_memory_selector_kind_t kind;

    /** Target operation; CHAOS_MEMORY_OP_INVALID for `*`. */
    chaos_memory_operation_t operation;

    /** Mapping kind for MMAP_KIND; CHAOS_MEMORY_MMAP_KIND_INVALID otherwise. */
    chaos_memory_mmap_kind_t mmap_kind;

    /**
     * Length of the selector text (9 for "mmap/anon"): tie-breaker between matching
     * rules of equal rank, longer wins. Two selectors of equal rank that match the
     * same call have the same text, so rank alone decides today (`mmap/anon` beats
     * `mmap` by rank 3 > 2, not by length).
     */
    size_t selector_len;
} chaos_memory_selector_t;

/**
 * @brief One parsed rule.
 *
 * @details Stored by value in a snapshot; chaos_memory_config_select_rule() copies
 * the winner to the caller, which owns the copy. Fields of the other effect are 0.
 */
typedef struct chaos_memory_rule
{
    /** Which calls the rule matches. */
    chaos_memory_selector_t selector;

    /** ERRNO or LATENCY; never CHAOS_MEMORY_EFFECT_INVALID after a successful parse. */
    chaos_memory_effect_t effect;

    /**
     * errno to inject (ERRNO): ENOMEM, EINVAL, EACCES, EPERM, EBADF, ENODEV, EAGAIN,
     * EFAULT, ENOSYS, ENFILE, EMFILE, or a decimal number in 1..2147483647.
     */
    int errnum;

    /** Firing probability in [0.0, 1.0], from the `@<p>` suffix of the value; default 1.0. */
    double probability;

    /** Delay in milliseconds (LATENCY), 0..4294967295; 0 is accepted and sleeps nothing. */
    unsigned int latency_ms;
    /** Qualifiers written after the rule (`@first`, `@from`, `@until`, `@size`). */
    chaos_rule_policy_t policy;
    /**
     * Length in bytes of the call this copy is being decided for, set by the
     * wrappers; CHAOS_POLICY_NO_SIZE in a snapshot, which fails every `@size` gate.
     */
    uint64_t call_size;
    /** Hit counter of this rule (see chaos_hits.h); NULL for a rule outside a snapshot. */
    chaos_hit_slot_t *hit;
    /** Generation of @c hit when the rule was published; a later one means the rule left. */
    uint64_t hit_generation;
} chaos_memory_rule_t;

/* =========================================================================
 * API
 * =========================================================================
 */

/**
 * @brief Resets the rule state: both snapshots empty, active index 0, cached stamp
 *        CHAOS_MEMORY_MTIME_UNKNOWN (so the next look reloads unthrottled).
 *
 * @details Also resets the hit pool and the hits-file identity, registers the fork
 * child handler (once per process), and finds the vDSO clock outside any wrapper.
 * Not thread-safe: called by the constructor (and unit tests) before any other
 * thread uses the library.
 */
void chaos_memory_config_init(void);

/**
 * @brief Reloads the rule file if it changed; returns whether rules are active.
 *
 * @details Called by chaos_memory_config_match() on every intercepted call (once
 * per pass). The look at the file is throttled to once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms) after the first load; on a changed stamp exactly one thread reloads (CAS
 * on the cached stamp) while the others serve the active snapshot. errno is
 * preserved.
 *
 * Failure behaviour: an absent, unopenable (EACCES/EPERM), oversized, NUL-containing
 * or invalid file publishes an empty snapshot (no injection); a transient read
 * failure or a read that raced a writer keeps the previous snapshot and retries
 * on the next look.
 *
 * @return Non-zero if the active snapshot holds at least one rule.
 */
int chaos_memory_config_prepare(void);

/**
 * @brief Selects the best rule of the active snapshot without looking at the file.
 *
 * @details For callers that already ran chaos_memory_config_prepare(). Reads the
 * snapshot without a lock and validates it with its sequence counter: a result
 * from a snapshot that a reload rewrote meanwhile is discarded (returns 0).
 *
 * @param effect      ERRNO or LATENCY.
 * @param operation   Intercepted operation.
 * @param mmap_flags  mmap() flags (for `mmap/anon` / `mmap/file`); 0 for other calls.
 * @param[out] rule   Copy of the winning rule; unspecified when 0 is returned.
 * @return Non-zero if a rule matched.
 */
int chaos_memory_config_match_loaded(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

/**
 * @brief chaos_memory_config_prepare() then chaos_memory_config_match_loaded(): the
 *        entry point of the wrappers, once per effect pass.
 *
 * @details Returns 0 without scanning when @p rule is NULL or no rule is active.
 *
 * @param effect      ERRNO or LATENCY.
 * @param operation   Intercepted operation.
 * @param mmap_flags  mmap() flags, or 0.
 * @param[out] rule   Copy of the winning rule.
 * @return Non-zero if a rule matched.
 */
int chaos_memory_config_match(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
);

/**
 * @brief Parses one rule line (qualifiers already removed by chaos_policy_extract()).
 *
 * @details Cuts the line at the first `#`, trims it, splits it at the first two
 * `:` into selector, effect and value, and splits the value at its last `@` into
 * payload and probability.
 *
 * @param[in,out] line  NUL-terminated line; modified in place.
 * @param[out]    rule  Filled on 1; not written on 0; unspecified on -1.
 * @return 1 for a rule, 0 for a blank or comment line, -1 for an invalid line.
 */
int chaos_memory_config_parse_line(char *line, chaos_memory_rule_t *rule);

/**
 * @brief Parses a whole rule file buffer, all or nothing.
 *
 * @details Splits at '\n', extracts each line's qualifiers, then parses it. The first
 * invalid line, qualifiers on a line without a rule, or a 257th rule rejects the
 * buffer: *rule_count is set to 0 and chaos_memory_config_last_error() names the line
 * and the reason. On success each rule's text is kept for the status and hits files
 * and call_size is CHAOS_POLICY_NO_SIZE.
 *
 * @param[in,out] buffer      NUL-terminated text; modified in place.
 * @param[out]    rules       Array of CHAOS_MEMORY_MAX_RULES entries.
 * @param[out]    rule_count  Number of rules, 0 on failure.
 * @return 0 on success, -1 on rejection.
 */
int chaos_memory_config_parse_buffer(char *buffer, chaos_memory_rule_t *rules, size_t *rule_count);

/**
 * @brief The line the last chaos_memory_config_parse_buffer() call rejected.
 *
 * @return The rejected line (`reason != NULL`), or a cleared record when the last
 *         parse succeeded. Valid until the next parse.
 */
const chaos_status_error_t *chaos_memory_config_last_error(void);

/**
 * @brief Selects the most specific rule of @p effect that matches a call.
 *
 * @details Highest rank wins; equal rank goes to the longer selector text, then to
 * the earlier rule. O(rule_count), no allocation. Separate from the snapshot code
 * so tests can feed arbitrary rule arrays.
 *
 * @param rules       Rules; NULL returns 0.
 * @param rule_count  Number of entries in @p rules.
 * @param effect      Effect to select.
 * @param operation   Intercepted operation.
 * @param mmap_flags  mmap() flags; 0 for other operations.
 * @param[out] rule   Copy of the winner; NULL returns 0.
 * @return Non-zero if a rule matched.
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
