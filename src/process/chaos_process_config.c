/**
 * @file chaos_process_config.c
 * @brief Config file I/O, parsing, hot-reload, and rule-matching
 *        implementation for the libchaos-process fault-injection subsystem.
 *
 * @details
 * This translation unit owns the full config lifecycle:
 *
 *  - **State storage**: Two ping-pong `chaos_process_config_state_t` slots
 *    (`g_chaos_process_config_states[0/1]`) hold the current and in-flight
 *    rule sets.  Only one slot is "active" at any moment, identified by
 *    `g_chaos_process_active_config_index`.
 *
 *  - **Hot reload**: `chaos_process_config_prepare()` stats the config file
 *    on every call and triggers a reload when the mtime hash changes.  A
 *    compare-and-swap on `g_chaos_process_cached_mtime` ensures that only
 *    one thread performs I/O at a time; concurrent threads fall through to
 *    the current active slot.
 *
 *  - **Parsing**: The config text is read into a thread-local buffer
 *    (`g_chaos_process_config_buffer`) to avoid dynamic allocation.  Because
 *    the buffer is TLS, parallel threads each have their own copy; only the
 *    reload winner actually uses it during the I/O phase.
 *
 *  - **Publish**: After a successful parse the new slot is published by
 *    flipping `g_chaos_process_active_config_index` under a full barrier.
 *    All FAIL_AFTER counters are reset before the flip.
 *
 * ## Invariants
 *
 *  - `g_chaos_process_active_config_index` is always 0 or 1.
 *  - The slot pointed to by `g_chaos_process_active_config_index` is always
 *    fully written before the index is published.
 *  - A slot with `parse_ok == 0` has `rule_count == 0` and is treated as
 *    "no rules active" by all callers.
 *  - `g_chaos_process_fail_after_counters[]` is reset to all-zeros every
 *    time a new config is published, regardless of whether any FAIL_AFTER
 *    rules appear in the new config.
 *
 * ## Thread safety
 *
 *  - Reads from the active config state (via `chaos_process_config_active_state`)
 *    are lock-free and safe from any thread at any time; the full barrier
 *    in `chaos_process_config_active_state` ensures visibility.
 *  - Concurrent reloads are serialised via the CAS in
 *    `chaos_process_config_prepare`; at most one thread writes to the
 *    inactive slot at any time.
 *
 * ## Stability
 * Private implementation — not part of the public API.
 */

#include "chaos_process_config.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* -------------------------------------------------------------------------
 * Platform-specific mtime accessor macros
 * ---------------------------------------------------------------------- */

#if defined(__linux__)
/** Extract the seconds component of `struct stat` mtime on Linux. */
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtim.tv_sec)
/** Extract the nanoseconds component of `struct stat` mtime on Linux. */
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
/** Extract the seconds component of `struct stat` mtime on macOS/BSD. */
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
/** Extract the nanoseconds component of `struct stat` mtime on macOS/BSD. */
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/* -------------------------------------------------------------------------
 * Internal config state type
 * ---------------------------------------------------------------------- */

/**
 * @brief One slot in the ping-pong config pair.
 *
 * There are exactly two of these (`g_chaos_process_config_states[0]` and
 * `g_chaos_process_config_states[1]`).  At any moment one is "active" (read
 * by hooks) and the other is either idle or being written by the reload
 * winner.  After a successful write the new slot is published atomically by
 * updating `g_chaos_process_active_config_index`.
 */
typedef struct chaos_process_config_state
{
    /** Parsed rules for this config slot. */
    chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    /** Number of valid entries in `rules[]`. */
    size_t rule_count;
    /**
     * Non-zero if the most recent parse of this slot succeeded.
     * A slot with `parse_ok == 0` is treated as empty by
     * `chaos_process_config_match_loaded()`.
     */
    int parse_ok;
} chaos_process_config_state_t;

/* -------------------------------------------------------------------------
 * Module-level static state
 * ---------------------------------------------------------------------- */

/**
 * The two ping-pong config states.  Index 0 is active at startup.
 * Protected by the CAS protocol on `g_chaos_process_cached_mtime`:
 * only one thread writes the inactive slot at any time.
 */
static chaos_process_config_state_t g_chaos_process_config_states[2];

/**
 * Index (0 or 1) of the currently active config state.
 * Read by hook threads with a preceding `__sync_synchronize()`.
 * Written by the reload winner after fully populating the new slot.
 */
static volatile unsigned int g_chaos_process_active_config_index = 0U;

/**
 * Cached mtime hash of the config file as last seen by a successful reload.
 *
 * Special sentinel values:
 *   - `CHAOS_PROCESS_MTIME_UNKNOWN`    (0xfff...f): initial state; triggers
 *     unconditional reload on first call.
 *   - `CHAOS_PROCESS_MTIME_MISSING`    (0): file does not exist.
 *   - `CHAOS_PROCESS_MTIME_RELOADING`  (0xfff...e): CAS lock held by the
 *     thread currently performing a reload.
 *
 * All other values are FNV-inspired hashes of (st_mtim.tv_sec, st_mtim.tv_nsec).
 * The hash is chosen to be collision-resistant for typical file modification
 * patterns; exact hash collisions would result in a missed reload cycle
 * (acceptable — the next file modification will trigger a retry).
 */
static volatile uint64_t g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;

/**
 * Per-thread buffer for reading the config file.
 *
 * Sized to hold `CHAOS_PROCESS_MAX_CONFIG_BYTES + 1` bytes (the +1 is for
 * the NUL terminator appended after the read).  Using TLS avoids dynamic
 * allocation and stack pressure; only the reload winner's buffer is used for
 * I/O, so there is no cross-thread sharing.
 */
static __thread char g_chaos_process_config_buffer[CHAOS_PROCESS_MAX_CONFIG_BYTES + 1U];

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/**
 * @brief Resets all FAIL_AFTER invocation counters to zero.
 *
 * Called unconditionally before publishing a new config, regardless of
 * whether any FAIL_AFTER rules appear in the new config.  This ensures that
 * a config reload always provides a clean slate for counted-failure testing.
 *
 * Note: the reset is a sequential loop with no atomic operations.  It is
 * safe because it is called only by the reload winner (protected by the CAS
 * lock) and the counter writes are sequenced before the barrier in
 * `chaos_process_config_publish()`.
 */
static void chaos_process_reset_fail_after_counters(void)
{
    size_t index;

    for (index = 0U; index < (size_t)CHAOS_PROCESS_OP_COUNT; ++index)
    {
        g_chaos_process_fail_after_counters[index] = 0U;
    }
}

/**
 * @brief Zeroes a config state slot and sets its parse status.
 *
 * @param state    The slot to reset.  Passing NULL is a no-op.
 * @param parse_ok The parse status to record: 1 = valid, 0 = invalid.
 */
static void chaos_process_config_reset_state(chaos_process_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * @brief Returns a pointer to the currently active config state.
 *
 * Issues a full memory barrier before reading the active index to ensure
 * that all writes performed by the reload winner (including the rule array
 * and the index flip) are visible to this thread.
 *
 * @return Pointer to the active `chaos_process_config_state_t`.  Never NULL.
 */
static const chaos_process_config_state_t *chaos_process_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_process_active_config_index;
    return &g_chaos_process_config_states[index];
}

/**
 * @brief Atomically publishes the new config slot and updates the mtime cache.
 *
 * The sequence is:
 *  1. Reset all FAIL_AFTER counters (before making rules visible).
 *  2. Full barrier — ensures counter resets are visible before the index flip.
 *  3. Flip the active index to `next_index`.
 *  4. Full barrier — ensures the index flip is visible before releasing
 *     the CAS lock.
 *  5. Store `observed_mtime` into `g_chaos_process_cached_mtime`,
 *     releasing the `CHAOS_PROCESS_MTIME_RELOADING` CAS lock.
 *
 * After step 5, other threads that lost the CAS will observe either the new
 * mtime (which matches the file, so they do nothing) or a future mtime (if
 * the file changes again immediately, triggering another reload cycle).
 *
 * @param next_index     The slot index (0 or 1) to make active.
 * @param observed_mtime The mtime hash observed at the start of this reload.
 */
static void chaos_process_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_process_reset_fail_after_counters();
    __sync_synchronize();
    g_chaos_process_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_process_cached_mtime = observed_mtime;
}

/**
 * @brief Returns non-zero if `ch` is a whitespace character for trimming.
 */
static int chaos_process_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims leading and trailing whitespace from a C string in-place.
 *
 * Returns a pointer to the first non-whitespace character.  The trailing
 * whitespace is replaced with NUL.  Returns the original pointer advanced
 * to the first non-whitespace character; if the string is entirely
 * whitespace, returns a pointer to the NUL terminator.
 *
 * @param text Mutable C string.  Passing NULL returns NULL.
 * @return Pointer into @p text after leading whitespace is skipped.
 */
static char *chaos_process_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_process_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_process_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

/**
 * @brief Truncates a config line at the first `#` character.
 *
 * Modifies @p line in-place.  Passing NULL is a no-op.
 *
 * @param line Mutable NUL-terminated config line.
 */
static void chaos_process_strip_comment(char *line)
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
 * @brief Parses a selector token into a `chaos_process_selector_t`.
 *
 * Recognised tokens: `"*"` (ANY), `"pthread_create"`, `"fork"`,
 * `"posix_spawn"`, `"posix_spawnp"`, `"execve"`, `"execveat"`, `"waitpid"`.
 *
 * @param text     NUL-terminated selector token (already trimmed).
 * @param selector Output structure to populate.
 * @return Non-zero on success; 0 if the token is unrecognised.
 */
static int chaos_process_selector_parse(const char *text, chaos_process_selector_t *selector)
{
    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_ANY;
        selector->operation = CHAOS_PROCESS_OP_INVALID;
        return 1;
    }
    if (strcmp(text, "pthread_create") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_PTHREAD_CREATE;
        return 1;
    }
    if (strcmp(text, "fork") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_FORK;
        return 1;
    }
    if (strcmp(text, "posix_spawn") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_POSIX_SPAWN;
        return 1;
    }
    if (strcmp(text, "posix_spawnp") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_POSIX_SPAWNP;
        return 1;
    }
    if (strcmp(text, "execve") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_EXECVE;
        return 1;
    }
    if (strcmp(text, "execveat") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_EXECVEAT;
        return 1;
    }
    if (strcmp(text, "waitpid") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_WAITPID;
        return 1;
    }

    return 0;
}

/**
 * @brief Tests whether a selector matches a given operation and returns the
 *        match rank.
 *
 * Ranks:
 *   - ANY selector:       rank = 1 (lowest priority)
 *   - OPERATION selector: rank = 2 (higher priority than wildcard)
 *   - No match:           rank = 0 (not set)
 *
 * @param selector  The selector to test.
 * @param operation The operation being looked up.
 * @param rank_out  Output: match rank (0 if no match).  May be NULL.
 * @return Non-zero if the selector matches; 0 otherwise.
 */
static int chaos_process_selector_matches(
    const chaos_process_selector_t *selector,
    chaos_process_operation_t operation,
    unsigned int *rank_out
)
{
    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_PROCESS_SELECTOR_ANY)
    {
        if (rank_out != NULL)
        {
            *rank_out = 1U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_PROCESS_SELECTOR_OPERATION && selector->operation == operation)
    {
        if (rank_out != NULL)
        {
            *rank_out = 2U;
        }
        return 1;
    }
    return 0;
}

/**
 * @brief Parses an errno name or decimal integer string.
 *
 * Accepts the following symbolic names:
 *   EAGAIN, ENOMEM, EACCES, ENOENT, EINTR, ECHILD, EPERM, ESRCH,
 *   EBUSY, EINVAL, ENOSYS, EMFILE, ENFILE, E2BIG.
 * Also accepts decimal integer strings for any errno value in (0, 0x7fffffff].
 *
 * @param text  NUL-terminated errno name or decimal string.
 * @return The positive errno value on success; -1 if unrecognised or invalid.
 */
static int chaos_process_parse_errno_name(const char *text)
{
    char *end = NULL;
    long value;

    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }
    if (strcmp(text, "ENOMEM") == 0)
    {
        return ENOMEM;
    }
    if (strcmp(text, "EACCES") == 0)
    {
        return EACCES;
    }
    if (strcmp(text, "ENOENT") == 0)
    {
        return ENOENT;
    }
    if (strcmp(text, "EINTR") == 0)
    {
        return EINTR;
    }
    if (strcmp(text, "ECHILD") == 0)
    {
        return ECHILD;
    }
    if (strcmp(text, "EPERM") == 0)
    {
        return EPERM;
    }
    if (strcmp(text, "ESRCH") == 0)
    {
        return ESRCH;
    }
    if (strcmp(text, "EBUSY") == 0)
    {
        return EBUSY;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "ENOSYS") == 0)
    {
        return ENOSYS;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "E2BIG") == 0)
    {
        return E2BIG;
    }

    value = strtol(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0' || value <= 0L || value > 0x7fffffffL)
    {
        return -1;
    }
    return (int)value;
}

/**
 * @brief Parses a probability string in [0.0, 1.0].
 *
 * Uses `strtod`.  Rejects any trailing non-whitespace after the number
 * and values outside [0.0, 1.0].
 *
 * @param text        NUL-terminated decimal string.
 * @param probability Output: the parsed probability value.
 * @return 0 on success; -1 on parse error or out-of-range.
 */
static int chaos_process_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_process_trim(end) != '\0' || value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

/**
 * @brief Copies a non-empty text value into a fixed-size buffer.
 *
 * Fails if the source is empty, NULL, or >= `buffer_size` bytes.
 *
 * @param text        Source string.
 * @param buffer      Destination buffer.
 * @param buffer_size Capacity of @p buffer including NUL terminator.
 * @return 0 on success; -1 if the value is missing, empty, or too long.
 */
static int chaos_process_copy_text_value(const char *text, char *buffer, size_t buffer_size)
{
    size_t len;

    if (text == NULL || buffer == NULL || buffer_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len == 0U || len >= buffer_size)
    {
        return -1;
    }

    (void)memcpy(buffer, text, len + 1U);
    return 0;
}

/**
 * @brief Parses a value field of the form `<payload>[@<probability>]`.
 *
 * Splits on the last `@` character.  If no `@` is present, the entire
 * `text` is the payload and probability defaults to 1.0.  If `@` is
 * present, everything before it is the payload and everything after is
 * parsed as a probability in [0.0, 1.0].
 *
 * @param text         NUL-terminated value field text.
 * @param payload      Output buffer for the payload (e.g. "EAGAIN" or "50").
 * @param payload_size Capacity of @p payload including NUL terminator.
 * @param probability  Output: the parsed probability (1.0 if no `@`).
 * @return 0 on success; -1 on any parse error.
 */
static int chaos_process_parse_payload_probability(
    const char *text, char *payload, size_t payload_size, double *probability
)
{
    const char *at_sign;
    size_t payload_len;

    if (text == NULL || payload == NULL || probability == NULL)
    {
        return -1;
    }

    *probability = 1.0;
    at_sign = strrchr(text, '@');
    if (at_sign == NULL)
    {
        return chaos_process_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(at_sign - text);
    if (payload_len == 0U || payload_len >= payload_size)
    {
        return -1;
    }

    (void)memcpy(payload, text, payload_len);
    payload[payload_len] = '\0';
    if (chaos_process_parse_probability(at_sign + 1, probability) != 0)
    {
        return -1;
    }
    return 0;
}

/**
 * @brief Parses a LATENCY value (unsigned integer milliseconds).
 *
 * Accepts values in [0, UINT_MAX].
 *
 * @param text       NUL-terminated decimal millisecond string.
 * @param latency_ms Output: the parsed latency in milliseconds.
 * @return 0 on success; -1 on parse error or overflow.
 */
static int chaos_process_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/**
 * @brief Parses a FAIL_AFTER count (unsigned 64-bit integer).
 *
 * @param text  NUL-terminated decimal count string.
 * @param count Output: the parsed count.
 * @return 0 on success; -1 on parse error.
 */
static int chaos_process_parse_fail_after_count(const char *text, uint64_t *count)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || count == NULL)
    {
        return -1;
    }

    value = strtoull(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0')
    {
        return -1;
    }

    *count = (uint64_t)value;
    return 0;
}

/**
 * @brief Parses the value field of a FAIL_AFTER rule: `<errno>,<count>`.
 *
 * Splits on the first `,`.  Trims whitespace around both halves.  Both
 * fields must be non-empty.
 *
 * @param payload Mutable NUL-terminated value string (modified in-place).
 * @param errnum  Output: parsed errno value.
 * @param count   Output: parsed call count.
 * @return 0 on success; -1 on any parse error.
 */
static int chaos_process_parse_fail_after_value(char *payload, int *errnum, uint64_t *count)
{
    char *comma;

    if (payload == NULL || errnum == NULL || count == NULL)
    {
        return -1;
    }

    comma = strchr(payload, ',');
    if (comma == NULL)
    {
        return -1;
    }
    *comma++ = '\0';
    payload = chaos_process_trim(payload);
    comma = chaos_process_trim(comma);
    if (*payload == '\0' || *comma == '\0')
    {
        return -1;
    }

    *errnum = chaos_process_parse_errno_name(payload);
    if (*errnum < 0)
    {
        return -1;
    }
    return chaos_process_parse_fail_after_count(comma, count);
}

/**
 * @brief Maps a raw mtime hash to a value that is not a sentinel.
 *
 * If the FNV hash of the mtime bytes happens to collide with either of the
 * special sentinel values (`CHAOS_PROCESS_MTIME_UNKNOWN` or
 * `CHAOS_PROCESS_MTIME_RELOADING`), subtract 1 to produce a valid non-
 * sentinel hash.  The probability of collision with any specific 64-bit
 * sentinel is 2^-64 per file modification, which is negligible.
 *
 * @param value Raw hash value.
 * @return A hash value guaranteed not to equal either sentinel.
 */
static uint64_t chaos_process_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_PROCESS_MTIME_UNKNOWN || value == CHAOS_PROCESS_MTIME_RELOADING)
    {
        return value - 1U;
    }
    return value;
}

/**
 * @brief Hashes the mtime fields of a `struct stat` into a 64-bit value.
 *
 * Uses FNV-inspired XOR-multiply mixing on (tv_sec, tv_nsec).  The result
 * is normalised to avoid sentinel collisions.  Returns
 * `CHAOS_PROCESS_MTIME_MISSING` if `st` is NULL.
 *
 * @param st Pointer to a populated `struct stat`, or NULL.
 * @return 64-bit mtime hash, or `CHAOS_PROCESS_MTIME_MISSING` if st is NULL.
 */
static uint64_t chaos_process_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_PROCESS_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_PROCESS_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_PROCESS_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_process_config_normalize_mtime_hash(value);
}

/**
 * @brief Stats the config file and returns its mtime hash.
 *
 * Uses the standard `stat(2)` syscall inside the re-entrancy guard.
 * Returns `CHAOS_PROCESS_MTIME_MISSING` if the file does not exist.
 *
 * @return The mtime hash of the config file, or
 *         `CHAOS_PROCESS_MTIME_MISSING` if stat fails.
 */
static uint64_t chaos_process_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = stat(CHAOS_PROCESS_CONFIG_PATH, &st);
    chaos_process_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_PROCESS_MTIME_MISSING;
    }

    return chaos_process_config_hash_mtime(&st);
}

/**
 * @brief Reads the config file into the thread-local buffer.
 *
 * Opens `CHAOS_PROCESS_CONFIG_PATH` with `O_RDONLY` and reads up to
 * `CHAOS_PROCESS_MAX_CONFIG_BYTES` bytes.  Returns -1 if:
 *   - The file cannot be opened.
 *   - A `read` call fails.
 *   - The file is exactly `CHAOS_PROCESS_MAX_CONFIG_BYTES` bytes (treated as
 *     truncation — the buffer is not large enough to hold the file).
 *
 * On success, appends a NUL terminator at offset `*size_out` in the buffer.
 * The entire I/O is wrapped in `chaos_process_enter_internal()` /
 * `chaos_process_leave_internal()` to suppress re-entrancy into our wrappers
 * from any libc paths called by `open`/`read`/`close`.
 *
 * @param size_out Output: number of bytes read (excluding NUL terminator).
 * @return 0 on success; -1 on any failure.
 */
static int chaos_process_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_process_enter_internal();
    fd = open(CHAOS_PROCESS_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_process_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_process_config_buffer + total, CHAOS_PROCESS_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_process_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_PROCESS_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_process_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_process_leave_internal(previous);
    g_chaos_process_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Splits a config line into three colon-delimited fields.
 *
 * Modifies @p line in-place by replacing the first two `:` characters with
 * NUL and returning trimmed pointers to each field.  Returns 0 if the line
 * does not contain at least two `:` characters.
 *
 * @param line           Mutable NUL-terminated config line.
 * @param selector_text  Output: pointer to the selector field.
 * @param effect_text    Output: pointer to the effect field.
 * @param value_text     Output: pointer to the value field.
 * @return Non-zero if splitting succeeded; 0 if the line is malformed.
 */
static int chaos_process_split_rule_fields(
    char *line, char **selector_text, char **effect_text, char **value_text
)
{
    char *selector_end;
    char *effect_end;

    if (line == NULL || selector_text == NULL || effect_text == NULL || value_text == NULL)
    {
        return 0;
    }

    selector_end = strchr(line, ':');
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

    *selector_text = chaos_process_trim(line);
    *effect_text = chaos_process_trim(selector_end);
    *value_text = chaos_process_trim(effect_end);
    return 1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/**
 * @copydoc chaos_process_config_init
 */
void chaos_process_config_init(void)
{
    chaos_process_config_reset_state(&g_chaos_process_config_states[0], 1);
    chaos_process_config_reset_state(&g_chaos_process_config_states[1], 1);
    g_chaos_process_active_config_index = 0U;
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
    chaos_process_reset_fail_after_counters();
}

/**
 * @copydoc chaos_process_config_parse_line
 *
 * Implementation notes:
 *
 *  - The line is trimmed and stripped of any `#` comment suffix in place
 *    before splitting; blank lines return 0 and leave `*rule` untouched.
 *  - All three colon-delimited fields (`selector:effect:value`) must be
 *    non-empty after trimming; the function returns -1 on any structural
 *    or semantic error rather than applying a partial rule.
 *  - The effect dispatch uses `strcmp` against `"ERRNO"`, `"LATENCY"`, and
 *    `"FAIL_AFTER"`; the value field is parsed in two passes — the
 *    optional `,probability` suffix is stripped first by
 *    `chaos_process_parse_payload_probability`, then the leading payload is
 *    interpreted according to the effect kind.
 */
int chaos_process_config_parse_line(char *line, chaos_process_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_PROCESS_MAX_VALUE];
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_process_strip_comment(line);
    line = chaos_process_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_process_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_process_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    if (strcmp(effect_text, "ERRNO") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_ERRNO;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        errnum = chaos_process_parse_errno_name(payload);
        if (errnum < 0)
        {
            return -1;
        }
        rule->errnum = errnum;
        return 1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_LATENCY;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_process_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "FAIL_AFTER") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_process_parse_fail_after_value(
                   payload, &rule->errnum, &rule->fail_after_count
               ) == 0
                   ? 1
                   : -1;
    }

    return -1;
}

/**
 * @copydoc chaos_process_config_parse_buffer
 *
 * Implementation notes:
 *
 *  - Splits the buffer on `'\n'` by writing NUL terminators in place, so the
 *    caller's buffer is mutated.
 *  - Adopts an all-or-nothing parse policy: the first invalid line aborts
 *    parsing and returns -1 without writing the rule count, so a partially
 *    parsed snapshot can never be published.
 *  - Enforces `CHAOS_PROCESS_MAX_RULES` as a hard upper bound; exceeding it
 *    is treated as a parse error rather than truncation, to keep the
 *    operator-visible failure mode unambiguous.
 */
int chaos_process_config_parse_buffer(char *buffer, chaos_process_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;

    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        int parsed;

        cursor = strchr(cursor, '\n');
        if (cursor != NULL)
        {
            *cursor++ = '\0';
        }
        else
        {
            cursor = line + strlen(line);
        }

        parsed = chaos_process_config_parse_line(line, &rules[count]);
        if (parsed < 0)
        {
            return -1;
        }
        if (parsed == 0)
        {
            continue;
        }
        ++count;
        if (count > CHAOS_PROCESS_MAX_RULES)
        {
            return -1;
        }
    }

    *rule_count = count;
    return 0;
}

/**
 * @copydoc chaos_process_config_select_rule
 *
 * Implementation notes:
 *
 *  - Linear scan over the rule array.  Rules whose effect or operation does
 *    not match the requested pair are skipped without further work.
 *  - Tie-breaking: when two rules produce the same selector rank, the rule
 *    with the longer `selector_len` text wins, so a more specific selector
 *    (e.g. `pthread_create`) beats a wildcard (`*`).
 *  - The winning rule is copied out by value into `*rule`; the caller has
 *    no lifetime dependency on the snapshot after this returns.
 */
int chaos_process_config_select_rule(
    const chaos_process_rule_t *rules,
    size_t rule_count,
    chaos_process_effect_t effect,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule
)
{
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

    if (rules == NULL || rule == NULL)
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
        if (!chaos_process_selector_matches(&rules[index].selector, operation, &rank))
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
 * @copydoc chaos_process_config_prepare
 *
 * Implementation notes:
 *
 *  - Implements the two-snapshot CAS reload protocol.  When the observed
 *    mtime equals the cached value, the function returns immediately with
 *    the active snapshot's rule count — no I/O, no allocations.
 *  - If the CAS to the `RELOADING` sentinel fails, another thread is
 *    already reloading; the loser returns the current (possibly one
 *    version stale, but always consistent) snapshot rather than spinning.
 *  - Reload errors (file missing, read failure, parse failure) cause the
 *    inactive snapshot to be reset with `parse_ok == 0` and published
 *    anyway, so subsequent match queries see an empty rule set instead of
 *    the previous one — and the cached mtime is advanced so we do not
 *    repeatedly re-read a corrupt file until the operator edits it.
 */
int chaos_process_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_process_config_state_t *next_state;

    observed_mtime = chaos_process_config_observed_mtime();
    cached_mtime = chaos_process_atomic_load_u64(&g_chaos_process_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    if (!chaos_process_atomic_cas_u64(
            &g_chaos_process_cached_mtime, cached_mtime, CHAOS_PROCESS_MTIME_RELOADING
        ))
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_process_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_process_config_states[next_index];
    chaos_process_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_PROCESS_MTIME_MISSING &&
        chaos_process_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_process_config_parse_buffer(
            g_chaos_process_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_process_config_reset_state(next_state, 0);
    }

    chaos_process_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @copydoc chaos_process_config_match_loaded
 *
 * Implementation notes:
 *
 *  - Reads the active snapshot pointer with an acquire barrier (provided by
 *    `chaos_process_config_active_state`) and inspects its `parse_ok`
 *    field; a snapshot whose parse failed never produces a match.
 *  - Does not invoke `chaos_process_config_prepare()`: callers in the hot
 *    path (where reload checks would add a stat() per call) must invoke
 *    `prepare()` once and then call this function for each candidate.
 */
int chaos_process_config_match_loaded(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
)
{
    const chaos_process_config_state_t *state = chaos_process_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_process_config_select_rule(
        state->rules, state->rule_count, effect, operation, rule
    );
}

/**
 * @copydoc chaos_process_config_match
 *
 * Implementation notes:
 *
 *  - Convenience wrapper that combines `chaos_process_config_prepare()`
 *    and `chaos_process_config_match_loaded()` into one call, used by
 *    wrappers (e.g. fork, posix_spawn) that have no external trigger to
 *    decide when to refresh the snapshot.
 *  - Returns 0 immediately when `prepare()` reports an empty rule set, so
 *    the caller never inspects an unprepared snapshot.
 */
int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
)
{
    if (rule == NULL || !chaos_process_config_prepare())
    {
        return 0;
    }

    return chaos_process_config_match_loaded(effect, operation, rule);
}
