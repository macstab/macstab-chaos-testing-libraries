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

/*
 * The supported intercepted I/O operations.
 *
 * Config text is parsed into enum values once so the hot path can match rules
 * without repeated string comparisons.
 */
typedef enum chaos_io_operation {
    CHAOS_IO_OP_INVALID = -1,
    CHAOS_IO_OP_READ = 0,
    CHAOS_IO_OP_WRITE,
    CHAOS_IO_OP_OPEN,
    CHAOS_IO_OP_CLOSE,
    CHAOS_IO_OP_FSYNC,
    CHAOS_IO_OP_FDATASYNC,
    CHAOS_IO_OP_PREAD,
    CHAOS_IO_OP_PWRITE
} chaos_io_operation_t;

/*
 * The supported fault effects that may be attached to a matched rule.
 *
 * Validation happens at parse time, so wrappers can switch on the enum directly
 * without re-checking string tokens or unsupported combinations.
 */
typedef enum chaos_io_effect {
    CHAOS_IO_EFFECT_INVALID = -1,
    CHAOS_IO_EFFECT_ERRNO = 0,
    CHAOS_IO_EFFECT_LATENCY,
    CHAOS_IO_EFFECT_TORN,
    CHAOS_IO_EFFECT_CORRUPT
} chaos_io_effect_t;

/*
 * The parsed representation of one config rule.
 *
 * Rules are stored in the active snapshot exactly in this form so wrapper code
 * can make decisions without reparsing text or allocating temporary structures.
 */
typedef struct chaos_io_rule {
    char path_prefix[CHAOS_IO_MAX_RULE_PATH];
    size_t path_len;
    chaos_io_operation_t operation;
    chaos_io_effect_t effect;
    int errnum;
    double probability;
    unsigned int latency_ms;
} chaos_io_rule_t;

/*
 * Resets the global config cache to an empty passthrough state.
 *
 * Startup and tests use this to guarantee that no stale snapshot survives from
 * an earlier run.
 */
void chaos_io_config_init(void);

/*
 * Refreshes the cached config if the on-disk file changed.
 *
 * Callers use this before matching so they see the current rule set without
 * reparsing the config file on every intercepted operation. The function
 * returns non-zero when the active snapshot contains at least one rule.
 */
int chaos_io_config_prepare(void);

/*
 * Matches a path against the active in-memory rule snapshot.
 *
 * Use this when the caller already knows the snapshot is current and wants the
 * cheapest possible lookup path.
 */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule);

/*
 * Refreshes config state if necessary and then matches a path.
 *
 * Path-based wrappers such as `open()` use this single call to handle snapshot
 * freshness, permanent exclusions, and longest-prefix rule selection.
 */
int chaos_io_config_match_path(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule);

/*
 * Parses one config line into a single `chaos_io_rule_t`.
 *
 * The parser trims whitespace, strips inline comments, validates the four-field
 * format, and fills the rule in place.
 *
 * Return values:
 * - `1` for a valid rule
 * - `0` for a blank or comment-only line
 * - `-1` for a syntactic or semantic error
 */
int chaos_io_config_parse_line(char *line, chaos_io_rule_t *rule);

/*
 * Parses a mutable config buffer into an array of rules.
 *
 * Reload code uses this after reading the whole config file into memory. The
 * buffer is split in place and each line is delegated to
 * `chaos_io_config_parse_line()`.
 */
int chaos_io_config_parse_buffer(char *buffer, chaos_io_rule_t *rules, size_t *rule_count);

/*
 * Selects the best matching rule from an explicit rule array.
 *
 * Matching is deterministic: only rules for the requested operation are
 * considered, and the longest path prefix wins.
 */
int chaos_io_config_select_rule(
    const chaos_io_rule_t *rules,
    size_t rule_count,
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule);

#endif
