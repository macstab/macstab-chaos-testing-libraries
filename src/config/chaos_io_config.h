/**
 * @file chaos_io_config.h
 * @brief Config parsing, snapshot management, and rule-selection declarations.
 *
 * @details
 * The runtime is entirely data-driven: wrapper code never hard-codes failure
 * behavior.  Instead, every intercepted operation asks this module for the
 * active rule set and acts on whatever was found.  That design lets operators
 * change injection scenarios by editing a text file without restarting the
 * target process.
 *
 * **Snapshot model.**
 * The module maintains two statically allocated `chaos_io_config_state_t`
 * structures (indexed 0 and 1) and a volatile active-index integer.  One
 * snapshot is always readable; the other is the reload target.  A lock-free
 * CAS on the cached mtime decides which thread performs the next reload.
 * After parsing completes, the new index is published with a full memory
 * barrier so all subsequent readers see the fresh rule set.
 *
 * **Rule format (config file).**
 * Each non-blank, non-comment line contains four colon-delimited fields:
 * ```
 * <path_prefix> : <operation> : <effect_or_errno> : <param>
 * ```
 * Parsing is strict: any field error causes the entire config to be treated
 * as empty (passthrough), rather than applying a partial rule set that the
 * operator did not intend.
 *
 * **Module ownership:** config/
 * **Stability:** internal – not part of any public ABI
 * **Thread-safety:** all exported functions are safe to call concurrently
 * from multiple threads; shared state is protected by lock-free CAS and
 * full memory barriers.
 */

#ifndef CHAOS_IO_CONFIG_H
#define CHAOS_IO_CONFIG_H

/*
 * Config parsing and rule-selection declarations for fault injection.
 *
 * The runtime stays data-driven: wrappers ask this module for the current rule
 * snapshot instead of baking failure behavior into code. That keeps scenarios
 * easy to express and keeps the wrapper layer focused on interception.
 */

#include "chaos_io_internal.h"

/**
 * @brief Enumeration of the intercepted I/O operations understood by the config system.
 *
 * @details Config text is parsed into enum values once so the hot path can match rules
 * without repeated string comparisons.
 *
 * The `RENAME_FROM` / `RENAME_TO` split lets operators write independent
 * rules for the source and destination sides of an atomic rename, which is
 * important for testing write-barrier scenarios where only the destination
 * path is significant.
 *
 * `CHAOS_IO_OP_INVALID` is the sentinel for parse errors; it must never be
 * stored in a successfully parsed rule.
 */
typedef enum chaos_io_operation
{
    CHAOS_IO_OP_INVALID = -1, /**< Sentinel: parse failure; not a valid rule operation. */
    CHAOS_IO_OP_READ = 0,     /**< `read(2)` and `readv(2)`. */
    CHAOS_IO_OP_WRITE,        /**< `write(2)`, `writev(2)`, `sendfile(2)`, `copy_file_range(2)`. */
    CHAOS_IO_OP_OPEN,         /**< `open(2)` and `openat(2)`. */
    CHAOS_IO_OP_CLOSE,        /**< `close(2)`. */
    CHAOS_IO_OP_FSYNC,        /**< `fsync(2)`. */
    CHAOS_IO_OP_FDATASYNC,    /**< `fdatasync(2)`. */
    CHAOS_IO_OP_PREAD,        /**< `pread(2)` and `preadv(2)`. */
    CHAOS_IO_OP_PWRITE,       /**< `pwrite(2)` and `pwritev(2)`. */
    CHAOS_IO_OP_TRUNCATE,     /**< `ftruncate(2)`. */
    CHAOS_IO_OP_ALLOCATE,     /**< `fallocate(2)` (Linux only). */
    CHAOS_IO_OP_UNLINK,       /**< `unlinkat(2)`. */
    CHAOS_IO_OP_RENAME_FROM,  /**< Source side of `renameat(2)`. */
    CHAOS_IO_OP_RENAME_TO     /**< Destination side of `renameat(2)`. */
} chaos_io_operation_t;

/**
 * @brief Enumeration of the fault effects that may be attached to a matched rule.
 *
 * @details Validation happens at parse time, so wrappers can switch on the enum directly
 * without re-checking string tokens or unsupported combinations.
 *
 * Effect/operation compatibility is enforced by `chaos_io_effect_allowed()`:
 * - `ERRNO` and `LATENCY` are valid for any operation.
 * - `TORN` is valid only for write-class operations (`write`, `pwrite`).
 * - `CORRUPT` is valid only for read-class operations (`read`, `pread`).
 *
 * `CHAOS_IO_EFFECT_INVALID` is the sentinel for parse errors and must never
 * be stored in a successfully parsed rule.
 */
typedef enum chaos_io_effect
{
    CHAOS_IO_EFFECT_INVALID = -1, /**< Sentinel: parse failure; not a valid effect. */
    CHAOS_IO_EFFECT_ERRNO = 0,    /**< Pre-call synthetic error: sets `errno` and returns -1. */
    CHAOS_IO_EFFECT_LATENCY,      /**< Pre-call blocking delay of `latency_ms` milliseconds. */
    CHAOS_IO_EFFECT_TORN,         /**< Partial write: real call with shortened byte count. */
    CHAOS_IO_EFFECT_CORRUPT       /**< Post-read single-bit flip in the returned buffer. */
} chaos_io_effect_t;

/**
 * @brief The parsed, ready-to-use representation of one configuration rule.
 *
 * @details Rules are stored in the active snapshot exactly in this form so wrapper code
 * can make decisions without reparsing text or allocating temporary structures.
 *
 * **Field semantics:**
 * - `path_prefix` – null-terminated prefix string used for path matching.
 *   The wildcard `"*"` matches any path.  A prefix that ends with `/`
 *   matches all children of that directory without requiring the slash in the
 *   target path.
 * - `path_len` – cached `strlen(path_prefix)` used by the hot-path prefix
 *   comparison to avoid recomputing the length on every call.
 * - `operation` – parsed operation enum; never `CHAOS_IO_OP_INVALID` in a
 *   valid rule.
 * - `effect` – parsed effect enum; never `CHAOS_IO_EFFECT_INVALID` in a
 *   valid rule.
 * - `errnum` – errno value to inject; meaningful only when
 *   `effect == CHAOS_IO_EFFECT_ERRNO`.
 * - `probability` – floating-point trigger probability in [0.0, 1.0];
 *   meaningful for `ERRNO`, `TORN`, and `CORRUPT` effects.
 * - `latency_ms` – millisecond sleep duration; meaningful only when
 *   `effect == CHAOS_IO_EFFECT_LATENCY`.
 *
 * **Ownership:** `chaos_io_rule_t` values are always copied out of the
 * shared snapshot into caller-owned stack storage before use, so there are
 * no lifetime concerns after `chaos_io_config_match_*` returns.
 *
 * **Invariants:** a value written by `chaos_io_config_parse_line()` with
 * return value 1 satisfies: `operation != CHAOS_IO_OP_INVALID`,
 * `effect != CHAOS_IO_EFFECT_INVALID`, and `path_len == strlen(path_prefix)`.
 */
typedef struct chaos_io_rule
{
    char path_prefix[CHAOS_IO_MAX_RULE_PATH]; /**< Null-terminated rule path prefix. */
    size_t path_len;                          /**< Cached `strlen(path_prefix)`. */
    chaos_io_operation_t operation;           /**< Operation this rule applies to. */
    chaos_io_effect_t effect;                 /**< Fault effect to apply when triggered. */
    int errnum;                               /**< errno code for ERRNO effect; 0 otherwise. */
    double probability;      /**< Trigger probability [0.0, 1.0] for probabilistic effects. */
    unsigned int latency_ms; /**< Sleep duration in milliseconds for LATENCY effect. */
} chaos_io_rule_t;

/**
 * @brief Resets the global config cache to an empty passthrough state.
 *
 * @details Both config snapshots are zeroed and their `parse_ok` flags are set
 * to 1 (representing an empty but valid config).  The active index is reset
 * to 0 and the cached mtime is set to `CHAOS_IO_MTIME_UNKNOWN` so the next
 * call to `chaos_io_config_prepare()` unconditionally reads the config file.
 *
 * Startup and tests use this to guarantee that no stale snapshot survives from
 * an earlier run.
 *
 * @note Not thread-safe; must be called before the library begins serving
 * interposed calls (i.e. from the constructor or a single-threaded test setup).
 */
void chaos_io_config_init(void);

/**
 * @brief Refreshes the cached config if the on-disk file changed.
 *
 * @details Stat's the config file and compares the hashed mtime against the
 * cached value.  If they differ and no other thread is already reloading (CAS
 * on `CHAOS_IO_MTIME_RELOADING`), this thread reads and parses the config file
 * into the inactive snapshot, then publishes the new snapshot with a full
 * memory barrier.
 *
 * A thread that loses the CAS race (another thread is reloading) returns
 * immediately using the current snapshot, which may be one version stale but
 * is always consistent.
 *
 * @return Non-zero when the active snapshot contains at least one rule;
 *         zero when the config is empty or absent (passthrough mode).
 *
 * @note Fail-open: any error during stat, read, or parse results in an empty
 * rule set rather than a library error, preserving the "never block the
 * target application" contract.
 */
int chaos_io_config_prepare(void);

/**
 * @brief Matches a path against the active in-memory rule snapshot.
 *
 * @details Reads the active snapshot index with an acquire barrier and scans
 * its rule array for the longest-prefix match for the given operation.  Does
 * not trigger a config reload; the caller is responsible for having called
 * `chaos_io_config_prepare()` first.
 *
 * @param[in]  operation  The operation to match against.
 * @param[in]  path       Null-terminated absolute path.  Must not be NULL.
 * @param[out] rule       Populated with a copy of the matched rule on success.
 *                        Must not be NULL.
 *
 * @return Non-zero when a rule was found and written to `*rule`;
 *         zero when no rule matched or the snapshot is empty.
 *
 * @pre `chaos_io_config_prepare()` has been called and returned non-zero in
 *      the current request context.
 */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
);

/**
 * @brief Refreshes config state if necessary and then matches a path.
 *
 * @details Combines `chaos_io_is_excluded_path()`, `chaos_io_config_prepare()`,
 * and `chaos_io_config_match_loaded()` into a single call for path-based
 * wrappers (e.g. `open()`) that receive the path directly rather than through
 * a file descriptor.
 *
 * @param[in]  operation  The operation to match against.
 * @param[in]  path       Null-terminated path to check.  May be NULL.
 * @param[out] rule       Populated on a successful match.  Must not be NULL.
 *
 * @return Non-zero when a rule was found; zero to pass through without injection.
 */
int chaos_io_config_match_path(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
);

/**
 * @brief Parses one config line into a single `chaos_io_rule_t`.
 *
 * @details The parser trims whitespace, strips inline comments, validates the four-field
 * format, and fills the rule in place.
 *
 * Fields are separated by `:`.  After splitting, each field is trimmed of
 * leading/trailing whitespace.  The path prefix length is bounded by
 * `CHAOS_IO_MAX_RULE_PATH`; longer paths are rejected.
 *
 * @param[in,out] line   Mutable null-terminated line buffer.  The function
 *                       modifies the buffer in place (NUL-terminates fields
 *                       and strips comments).
 * @param[out]    rule   Populated with the parsed rule on success.  The
 *                       caller owns this storage.  Must not be NULL.
 *
 * @return
 * - `1`  – a valid rule was parsed and written to `*rule`
 * - `0`  – the line was blank or comment-only; `*rule` is not modified
 * - `-1` – a syntactic or semantic error; `*rule` contents are undefined
 *
 * @note Called with `line == NULL` returns `-1` immediately.
 */
int chaos_io_config_parse_line(char *line, chaos_io_rule_t *rule);

/**
 * @brief Parses a mutable config buffer into an array of rules.
 *
 * @details The buffer is split in place on `'\n'` boundaries; each segment is
 * passed to `chaos_io_config_parse_line()`.  A single parse error anywhere in
 * the buffer causes the entire batch to fail (`*rule_count` is set to 0 and
 * -1 is returned), so the reload code never applies a partial rule set.
 *
 * @param[in,out] buffer      Mutable null-terminated config file contents.
 *                            Modified in place (newlines replaced by NUL).
 * @param[out]    rules       Array of at least `CHAOS_IO_MAX_RULES` elements
 *                            to receive the parsed rules.  Must not be NULL.
 * @param[out]    rule_count  Receives the number of rules written on success;
 *                            set to 0 on failure.  Must not be NULL.
 *
 * @return 0 on success; -1 if any line failed to parse or the rule count
 *         exceeded `CHAOS_IO_MAX_RULES`.
 */
int chaos_io_config_parse_buffer(char *buffer, chaos_io_rule_t *rules, size_t *rule_count);

/**
 * @brief Selects the best matching rule from a caller-supplied rule array.
 *
 * @details Matching is deterministic: the function iterates the rule array
 * linearly and tracks the rule whose `path_prefix` is the longest string that
 * is a prefix of `path` for the requested operation.  "Longest prefix" is
 * evaluated by `path_len`, not by match quality, so a wildcard `"*"` rule has
 * effective length 0 and is always beaten by any explicit prefix.
 *
 * @param[in]  rules       Rule array to search.  Must not be NULL.
 * @param[in]  rule_count  Number of valid entries in `rules`.
 * @param[in]  operation   The operation to filter by.
 * @param[in]  path        The resolved path to match against.  Must not be NULL.
 * @param[out] rule        Populated with a copy of the winning rule.
 *                         Must not be NULL.
 *
 * @return Non-zero when a match was found; zero otherwise.
 */
int chaos_io_config_select_rule(
    const chaos_io_rule_t *rules,
    size_t rule_count,
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule
);

#endif
