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
 *  - **Parsing**: The config text is read into a static buffer
 *    (`g_chaos_process_config_buffer`) to avoid dynamic allocation.  Only the
 *    reload winner uses it during the I/O phase; callers that see a reload in
 *    progress return early rather than starting another.
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
#include "chaos_clock.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
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
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t *hits[CHAOS_PROCESS_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_PROCESS_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
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

/** @brief Hit slots of the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_process_hit_pool[2U * CHAOS_PROCESS_MAX_RULES];

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
 * @brief The loaded file's mtime was too recent to trust its stamp
 *        (chaos_clock_stamp_is_recent): the next look reads it again.
 */
static volatile int g_chaos_process_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_process_config_content = 0U;

/**
 * @brief Buffer the reload thread reads the config file into.
 *
 * @details Sized CHAOS_PROCESS_MAX_CONFIG_BYTES + 1 for the NUL terminator appended by
 * chaos_process_config_read_file().  Only the thread holding the reload marker
 * (CHAOS_PROCESS_MTIME_RELOADING) touches it, so one process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves
 * in every thread of the preloaded process and adds to each thread's minimum stack
 * size.  Runtimes that create threads with small explicit stacks -- the Erlang VM, for
 * one -- then fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_process_config_buffer[CHAOS_PROCESS_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The first line the last parse rejected, reported in the status file.
 *
 * @details Written only by the thread that owns the reload claim.
 */
static chaos_status_error_t g_chaos_process_config_error;

/** @brief Text of each accepted rule of the last parse, copied into the snapshot. */
static char g_chaos_process_config_texts[CHAOS_PROCESS_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Set while a thread writes the hits file. */
static volatile int g_chaos_process_hits_writing = 0;

/** @brief Set once the atfork handler is registered. */
static int g_chaos_process_atfork_registered = 0;

static void chaos_process_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_process_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_process_hits_total = 0U;

/** @brief CLOCK_MONOTONIC time of the last write, in milliseconds. */
static uint64_t g_chaos_process_hits_last_ms = 0U;

/** @brief Process the counters belong to: set at start and in a forked child. */
static volatile uint64_t g_chaos_process_hits_pid = 0U;

/** @brief Number of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_process_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_process_hits_owned = 0;

/** @brief Scratch for the hits file; used only by the thread that writes it. */
static char g_chaos_process_hits_buffer[CHAOS_PROCESS_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

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
    uint64_t sequence;

    if (state == NULL)
    {
        return;
    }

    /* A reader still holding this snapshot sees that it changed. */
    chaos_snapshot_write_begin(&state->sequence);
    sequence = state->sequence;
    (void)memset(state, 0, sizeof(*state));
    state->sequence = sequence;
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
    chaos_snapshot_write_end(&g_chaos_process_config_states[next_index].sequence);
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
 * @brief Parses a probability (see chaos_policy_parse_probability()): "0", "1",
 *        "0." and digits, or "1." and zeros, whatever the locale.
 *
 * @param text         Probability string. Must not be NULL.
 * @param probability  Output: receives the parsed value. Must not be NULL.
 * @return 0 on success; -1 when @p text is not a probability.
 */
static int chaos_process_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
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
    const int saved_errno = errno;
    char *end = NULL;
    unsigned long long value;
    int out_of_range;

    if (text == NULL || count == NULL)
    {
        return -1;
    }
    /* Digits only (the caller trims the blanks around it): strtoull() would take
     * "-1" as the largest count, one that never fails. */
    if (*text < '0' || *text > '9')
    {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    out_of_range = errno == ERANGE;
    errno = saved_errno;
    if (out_of_range || *chaos_process_trim(end) != '\0')
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
 * @brief Computes a 64-bit change stamp of the file: mtime, size, inode and device.
 *
 * Uses FNV-inspired XOR-multiply mixing on (tv_sec, tv_nsec, size, inode,
 * device). The mtime alone is not enough: file systems stamp it from a coarse clock (a
 * few milliseconds), so two writes in one tick leave it unchanged. Mixing in the
 * size catches an append, and the inode catches a rewrite through a temporary
 * file and rename(2) (`sed -i`), even within one tick.
 *
 * The result is normalised to avoid sentinel collisions.  Returns
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
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
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
 * @brief Reads the config file into the shared read buffer.
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
static int chaos_process_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_process_enter_internal();
    do
    {
        fd = CHAOS_CONFIG_FILE_OPEN(CHAOS_PROCESS_CONFIG_PATH);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* No permission lasts until the file changes; anything else (gone since
         * the stat, out of descriptors, ...) is retried on the next check. */
        const int open_error = errno;

        chaos_process_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = CHAOS_CONFIG_FILE_READ(
            fd, g_chaos_process_config_buffer + total, CHAOS_PROCESS_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_process_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_PROCESS_MAX_CONFIG_BYTES)
        {
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_process_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer
     * that rewrote or appended to it while it was read leaves a different stamp; the
     * copy may then be half old, half new, so it is not used and the next call
     * reloads the finished file. */
    if (fstat(fd, &st) != 0 || chaos_process_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_process_leave_internal(previous);
        return -1;
    }
    g_chaos_process_config_provisional = chaos_clock_stamp_is_recent(
        (int64_t)CHAOS_PROCESS_STAT_SEC(&st), (long)CHAOS_PROCESS_STAT_NSEC(&st)
    );

    CHAOS_CONFIG_FILE_CLOSE(fd);
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
    g_chaos_process_hits_pid = (uint64_t)getpid();
    g_chaos_process_hits_file = chaos_hits_file_number(CHAOS_PROCESS_HITS_PREFIX);
    g_chaos_process_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_process_hit_pool,
        sizeof(g_chaos_process_hit_pool) / sizeof(g_chaos_process_hit_pool[0])
    );
    if (!g_chaos_process_atfork_registered)
    {
        g_chaos_process_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_process_config_after_fork);
    }
    /* Find the vDSO clock now, not first inside a wrapper a signal handler may re-enter. */
    (void)chaos_clock_now_ns();
    chaos_process_config_reset_state(&g_chaos_process_config_states[0], 1);
    chaos_process_config_reset_state(&g_chaos_process_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_process_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_process_config_states[1].sequence);
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
 * @brief Whether this build can apply @p rule.
 *
 * @details Every rule the parser accepts, in the library. chaos-init, which applies
 * rules from outside the process through seccomp, defines it before including this
 * file: a rule it cannot apply rejects the file like an invalid line would, with
 * its own reason, so the status file says so instead of the rule doing nothing.
 */
#ifndef CHAOS_PROCESS_RULE_SUPPORTED
#define CHAOS_PROCESS_RULE_SUPPORTED(rule) 1
#endif

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
    size_t number = 0U;

    chaos_status_clear(&g_chaos_process_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_process_rule_t parsed;
        chaos_rule_policy_t policy;
        int rc;

        while (*cursor != '\0' && *cursor != '\n')
        {
            ++cursor;
        }
        if (*cursor == '\n')
        {
            *cursor++ = '\0';
        }

        /* The parser edits the line in place; keep it as written for the report. */
        chaos_status_keep_line(&g_chaos_process_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_process_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_process_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_process_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers without a rule. */
                chaos_status_reject(&g_chaos_process_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_PROCESS_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_process_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        if (!CHAOS_PROCESS_RULE_SUPPORTED(&parsed))
        {
            chaos_status_reject(&g_chaos_process_config_error, CHAOS_STATUS_REASON_UNSUPPORTED);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_process_config_texts[count],
            g_chaos_process_config_error.text,
            sizeof(g_chaos_process_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_process_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_process_config_last_error(void)
{
    return &g_chaos_process_config_error;
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
 * @brief Marks @p state as the result of a rule file that cannot be used as a whole.
 *
 * @details A file at or over the size limit, or one this process may not open
 * (EACCES) or read (a directory), stays so until it changes, unlike a read that
 * failed or met a concurrent writer: it is reported like a rejected file (no
 * rules, state=error) and not re-read until the file changes.
 */
static void
chaos_process_config_reject_file(chaos_process_config_state_t *state, const char *reason)
{
    chaos_process_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_process_config_error);
    chaos_status_reject(&g_chaos_process_config_error, reason);
}

/**
 * @brief Reports this process's hit counts after a hit on @p slot (NULL: at exit).
 *
 * @details Writes the hits file on each of the first CHAOS_HITS_EAGER hits, then at
 * most every CHAOS_HITS_INTERVAL_MS; the exit report covers the rest. One thread
 * writes at a time: a hit that finds the writer busy leaves `pending` set, and the
 * writer repeats the write before it lets go. A forked child inherits the parent's
 * counts; they are cleared at the child's first hit so no hit is reported twice.
 */
static void chaos_process_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_process_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_process_hits_total;
        if (g_chaos_process_hits_pending == 0)
        {
            g_chaos_process_hits_pending = 1;
        }
        /* Past the eager hits and inside the interval there is nothing to write:
         * no system call, no shared write beyond the counters. */
        if (g_chaos_process_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_process_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_process_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but is another process and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_process_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_process_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_process_config_state_t *)chaos_process_config_active_state();
        while (g_chaos_process_hits_pending != 0)
        {
            g_chaos_process_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_PROCESS_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_process_hits_file,
                &g_chaos_process_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_process_hits_buffer,
                sizeof(g_chaos_process_hits_buffer)
            );
        }
        g_chaos_process_hits_last_ms = now;
        __sync_lock_release(&g_chaos_process_hits_writing);
        __sync_synchronize();
        /* A hit that found the writer busy after its last check is written now. */
    } while (g_chaos_process_hits_pending != 0);
}

/**
 * @brief Child side of fork(): forgets what threads of the parent were doing.
 *
 * @details Registered with pthread_atfork(). The thread that held a reload claim,
 * the hits writer flag or a REGRESS decision does not exist in the child, so those
 * are released; counts and @first claims start from zero for the new process, and
 * its hits file is its own. vfork children and posix_spawn run no atfork handler:
 * they share the parent's memory, see its claims as busy and write nothing.
 */
static void chaos_process_config_after_fork(void)
{
    if (g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING)
    {
        g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
    }
    g_chaos_process_hits_writing = 0;
    g_chaos_process_hits_pending = 0;
    g_chaos_process_hits_total = 0U;
    g_chaos_process_hits_last_ms = 0U;
    g_chaos_process_hits_pid = (uint64_t)getpid();
    g_chaos_process_hits_file = chaos_hits_file_number(CHAOS_PROCESS_HITS_PREFIX);
    g_chaos_process_hits_owned = 0;
    /* The child must not draw the parent's numbers (pre-fork workers would all
     * decide alike): its PRNG reseeds from its own thread id on the next draw. */
    g_chaos_process_tls_prng_state = 0U;
    /* FAIL_AFTER counts per process, like @first, and as chaos-init counts it. */
    chaos_process_reset_fail_after_counters();
    chaos_hits_pool_after_fork(
        g_chaos_process_hit_pool,
        sizeof(g_chaos_process_hit_pool) / sizeof(g_chaos_process_hit_pool[0]),
        chaos_process_config_active_state()->hits,
        chaos_process_config_active_state()->rule_count
    );
}

/** @brief Reports the hits not yet written when the process exits normally. */
__attribute__((destructor)) static void chaos_process_config_report_hits_at_exit(void)
{
    chaos_process_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its counter and text.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its slot
 * (chaos_hits_assign()), so adding one rule does not reset the counts of the
 * others and a firing through an older rule copy still lands.
 */
static void chaos_process_config_attach_hits(chaos_process_config_state_t *next_state)
{
    const chaos_process_config_state_t *active = chaos_process_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index],
            g_chaos_process_config_texts[index],
            sizeof(next_state->text[index])
        );
    }
    chaos_hits_assign(
        g_chaos_process_hit_pool,
        sizeof(g_chaos_process_hit_pool) / sizeof(g_chaos_process_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_process_config_report_hits
    );
    for (index = 0U; index < next_state->rule_count; ++index)
    {
        next_state->rules[index].hit = next_state->hits[index];
        next_state->rules[index].hit_generation =
            next_state->hits[index] != NULL ? next_state->hits[index]->generation : 0U;
    }
}

/**
 * @brief Writes the status file for a load that produced @p state.
 *
 * @details Called by the reload owner before the snapshot is published. No rule
 * file means nothing to report, so the status file is removed.
 */
static void
chaos_process_config_report(uint64_t observed_mtime, const chaos_process_config_state_t *state)
{
    if (observed_mtime == CHAOS_PROCESS_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_PROCESS_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(
            CHAOS_PROCESS_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_process_config_error
        );
    }
    else
    {
        chaos_status_write(CHAOS_PROCESS_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/** @brief When this process last looked at the rule file (vDSO CLOCK_MONOTONIC, ns). */
static volatile uint64_t g_chaos_process_last_check_ns = 0U;

/** @brief Throttle for looking at the rule file; 0 looks on every call (unit tests). */
static uint64_t g_chaos_process_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details Each look is a stat() system call, the largest part of a wrapper's cost.
 * Once rules are loaded the file is looked at no more than every
 * CHAOS_CHECK_INTERVAL_NS, so a change takes effect within that time instead of on
 * the very next call. The first load, and any call while no rules are loaded yet,
 * always looks.
 */
static int chaos_process_config_checked_recently(void)
{
    const uint64_t cached = chaos_process_atomic_load_u64(&g_chaos_process_cached_mtime);

    if (cached == CHAOS_PROCESS_MTIME_UNKNOWN || cached == CHAOS_PROCESS_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(
        &g_chaos_process_last_check_ns, g_chaos_process_check_interval_ns
    );
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
static int chaos_process_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size = 0U;
    uint64_t content = 0U;
    chaos_process_config_state_t *next_state;

    if (chaos_process_config_checked_recently())
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    /* Hits of an interval that is over are written now, not only at the next hit
     * or at exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_process_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_process_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_process_config_report_hits(NULL);
    }
    observed_mtime = chaos_process_config_observed_mtime();
    cached_mtime = chaos_process_atomic_load_u64(&g_chaos_process_cached_mtime);

    if (observed_mtime == cached_mtime && !g_chaos_process_config_provisional)
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    /* Another thread owns this reload cycle; use the current snapshot.  Without this
     * check the CAS below succeeds as RELOADING -> RELOADING and a second thread would
     * reload into the same inactive snapshot and read buffer concurrently. */
    /* Another thread of this process owns the reload; a claim inherited through
     * fork() was released by the atfork handler, and a vfork child must not take
     * over its parent's. */
    if (cached_mtime == CHAOS_PROCESS_MTIME_RELOADING)
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    if (!chaos_process_atomic_cas_u64(
            &g_chaos_process_cached_mtime, cached_mtime, CHAOS_PROCESS_MTIME_RELOADING
        ))
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    g_chaos_process_config_provisional = 0;

    active_index = g_chaos_process_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_process_config_states[next_index];
    chaos_process_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_PROCESS_MTIME_MISSING)
    {
        const int read_rc = chaos_process_config_read_file(&config_size, observed_mtime);

        if (read_rc == -2 || read_rc == -3)
        {
            chaos_process_config_reject_file(
                next_state,
                read_rc == -2 ? CHAOS_STATUS_REASON_TOO_LARGE : CHAOS_STATUS_REASON_UNREADABLE
            );
            config_size = 0U;
        }
        else if (read_rc != 0)
        {
            /* A failed read says nothing about the rules: keep the active snapshot and
             * release the claim with the previous stamp, so the next call retries
             * instead of running with no rules until the file changes again. */
            __sync_synchronize();
            g_chaos_process_cached_mtime = cached_mtime;
            return chaos_process_config_active_state()->rule_count != 0U;
        }
        if (read_rc == 0)
        {
            content = chaos_config_content_hash(g_chaos_process_config_buffer, config_size);
            if (observed_mtime == cached_mtime && content == g_chaos_process_config_content)
            {
                /* A provisional load read again and found nothing new: the snapshot
                 * stays, with its counts, claims and FAIL_AFTER counters. */
                __sync_synchronize();
                g_chaos_process_cached_mtime = cached_mtime;
                return chaos_process_config_active_state()->rule_count != 0U;
            }
        }
        if (config_size > 0U && memchr(g_chaos_process_config_buffer, '\0', config_size) != NULL)
        {
            /* The parser would stop at the NUL and drop every rule after it unreported. */
            chaos_process_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
            config_size = 0U;
        }
        if (config_size > 0U &&
            chaos_process_config_parse_buffer(
                g_chaos_process_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Parse failed: mark the snapshot invalid so match queries return 0. */
            chaos_process_config_reset_state(next_state, 0);
        }
    }

    g_chaos_process_config_content = content;
    chaos_process_config_attach_hits(next_state);
    chaos_process_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load: freed, and outdated in rule copies
     * still held. Before the publish, while this thread still holds the claim. */
    chaos_hits_release(
        g_chaos_process_hit_pool,
        sizeof(g_chaos_process_hit_pool) / sizeof(g_chaos_process_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_process_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Refreshes the snapshot if the config file changed, leaving errno untouched.
 *
 * @details The stat, open and read calls of a refresh belong to the library, not to
 * the caller: an interposed call that then succeeds must not report the errno of a
 * missing config file.
 */
int chaos_process_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_process_config_refresh();

    errno = saved_errno;
    return result;
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
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_process_config_select_rule(
               state->rules, state->rule_count, effect, operation, rule
           ) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
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
