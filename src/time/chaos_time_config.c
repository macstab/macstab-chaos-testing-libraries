/**
 * @file chaos_time_config.c
 * @brief Config file loading, parsing, and live-reload logic for libchaos-time.
 *
 * This translation unit owns the full lifecycle of the configuration state:
 * reading the file from disk, parsing it into rule arrays, and publishing new
 * snapshots to readers on other threads without locking.
 *
 * ### Two-snapshot lock-free reload protocol
 *
 * Two config state snapshots (g_chaos_time_config_states[0] and [1]) are kept
 * in a static array.  At any instant exactly one is "active" (indexed by
 * g_chaos_time_active_config_index).  The inactive snapshot is used as the
 * write target during a reload.  The protocol is:
 *
 *  1. Atomically load the cached mtime hash.
 *  2. Stat the config file to get the observed mtime hash.
 *  3. If they match, no work is needed.
 *  4. CAS the cached mtime from its observed value to CHAOS_TIME_MTIME_RELOADING.
 *     - If the CAS fails, another thread is already reloading; read the current
 *       active state and return.
 *     - If the CAS succeeds, this thread owns the reload.
 *  5. Write into the inactive snapshot.
 *  6. Publish: store the new active index, then store the new mtime hash.
 *
 * The two-store publish sequence (index first, mtime second) means a racing
 * reader that loaded the old index before step 6 will see the old state, which
 * is still valid.  A reader that loads the new index will see the fully written
 * new state because the write to the inactive snapshot completed before the
 * index store.  Full memory barriers (__sync_synchronize) surround each
 * index/mtime access to prevent the CPU and compiler from reordering loads and
 * stores across the protocol boundary.
 *
 * ### Per-thread read buffer
 *
 * g_chaos_time_config_buffer is TLS-allocated at CHAOS_TIME_MAX_CONFIG_BYTES+1
 * bytes.  It is only used by the thread that wins the reload CAS, so there is
 * no sharing.  TLS allocation avoids a large stack frame (256 KB) in what is
 * nominally a hot path.
 *
 * ### Reentrancy during file I/O
 *
 * stat(), open(), read(), and close() calls are wrapped in
 * chaos_time_enter_internal() / chaos_time_leave_internal() so that any
 * intercepted symbols called by the C runtime's implementation of those
 * functions will bypass chaos injection.
 *
 * @invariant  g_chaos_time_config_states[g_chaos_time_active_config_index]
 *             always contains a coherent, fully parsed ruleset or an empty
 *             ruleset with parse_ok == 1.  It is never partially written.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_time_config.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Platform abstraction for struct stat mtime fields.
 *
 * Linux exposes sub-second precision through st_mtim (POSIX.1-2008 timespec
 * member), while macOS and BSDs expose it through st_mtimespec.  Both are
 * incorporated into the mtime hash so that a file written and immediately
 * re-written within the same second still triggers a reload.
 */
#if defined(__linux__)
#define CHAOS_TIME_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_TIME_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_TIME_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_TIME_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/**
 * @brief One complete, coherent snapshot of the parsed config state.
 *
 * Two instances of this struct are kept in static storage.  The reload
 * protocol always writes into the inactive instance and then publishes it
 * atomically, so readers never observe a partially populated state.
 *
 * @invariant  If parse_ok == 1, the first rule_count entries of rules[] are
 *             fully initialised.  If parse_ok == 0, the config file was
 *             present but contained at least one unparseable line; the whole
 *             snapshot is treated as empty (no rules applied).
 */
typedef struct chaos_time_config_state
{
    chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES]; /**< Parsed rules, indices [0, rule_count). */
    size_t rule_count;                              /**< Number of valid entries in rules[]. */
    int parse_ok;                                   /**< 1 = config parsed cleanly; 0 = parse error. */
} chaos_time_config_state_t;

/** The two config snapshots; index 0 is the initial active snapshot. */
static chaos_time_config_state_t g_chaos_time_config_states[2];

/**
 * Index into g_chaos_time_config_states[] identifying the currently active
 * (readable) snapshot.  Updated atomically by the reload thread before
 * writing the new mtime.  Readers load this value under a memory barrier.
 */
static volatile unsigned int g_chaos_time_active_config_index = 0U;

/**
 * Hash of the config file's mtime at the last successful reload, or one of
 * the CHAOS_TIME_MTIME_* sentinel values.
 *
 * Acts as both the "have we checked recently?" cache and the CAS mutex for
 * the reload protocol.  See chaos_time_config_prepare() for the full state
 * machine.
 */
static volatile uint64_t g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;

/**
 * Per-thread buffer used to hold the raw config file content during a reload.
 *
 * Only the thread that wins the reload CAS uses this buffer.  TLS storage
 * avoids putting 256 KB on the call stack.  The extra byte beyond
 * CHAOS_TIME_MAX_CONFIG_BYTES provides space for a NUL terminator written by
 * chaos_time_config_read_file() after the last byte of file content.
 */
static __thread char g_chaos_time_config_buffer[CHAOS_TIME_MAX_CONFIG_BYTES + 1U];

/**
 * Resets a config state snapshot to a known-empty state.
 *
 * Zeroes the entire struct via memset (which zero-initialises all rule fields
 * and sets rule_count to 0) then writes parse_ok.
 *
 * @param state     Snapshot to reset.  Ignored if NULL.
 * @param parse_ok  Value to store in state->parse_ok after the memset.
 */
static void chaos_time_config_reset_state(chaos_time_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * Returns a read-only pointer to the currently active config snapshot.
 *
 * Issues a full memory barrier before reading the active index to prevent
 * the CPU from speculating the index load before stores by the last publishing
 * thread have become visible.
 *
 * @return  Pointer to the active chaos_time_config_state_t.  Never NULL.
 */
static const chaos_time_config_state_t *chaos_time_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_time_active_config_index;
    return &g_chaos_time_config_states[index];
}

/**
 * Publishes a newly loaded snapshot as the active config.
 *
 * The two-store ordering is critical:
 *
 *  1. Full barrier + store active index — from this point, readers that load
 *     the index will see the new snapshot, which has already been fully written.
 *  2. Full barrier + store observed mtime — subsequent calls to
 *     chaos_time_config_prepare() by any thread will see the current mtime and
 *     skip redundant reloads.
 *
 * The mtime is stored after the index because a thread that reads the new
 * index but the old mtime will correctly serve the new rules and simply
 * schedule a premature (but harmless) re-stat on the next call.  The reverse
 * order would risk a window where the new mtime is visible but the old index
 * is still active, causing readers to serve stale rules until the next reload.
 *
 * @param next_index      Index into g_chaos_time_config_states[] to activate.
 * @param observed_mtime  Mtime hash to cache; future calls comparing against
 *                        this value will skip a reload if the file is unchanged.
 */
static void chaos_time_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_time_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_time_cached_mtime = observed_mtime;
}

/**
 * Returns non-zero if a character is considered whitespace for trimming.
 *
 * Recognises space, tab, carriage return, and newline — the set of characters
 * that can appear at the margins of a config line on any platform.
 *
 * @param ch  Character to test.
 * @return    Non-zero if @p ch is blank, zero otherwise.
 */
static int chaos_time_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * Trims leading and trailing whitespace from a string in-place.
 *
 * Advances the pointer past any leading blank characters, then writes a NUL
 * terminator after the last non-blank character.  The returned pointer may
 * point into the interior of the original buffer; the original pointer is
 * not valid as an argument to free() after this call.
 *
 * @param text  Mutable NUL-terminated string.  May be NULL.
 * @return      Pointer to the first non-blank character, or a pointer to a
 *              NUL byte if the string is entirely whitespace.  NULL if @p text
 *              is NULL.
 */
static char *chaos_time_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_time_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_time_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

/**
 * Truncates a line at the first '#' character, removing any comment.
 *
 * Writes a NUL byte over the '#', so subsequent parsing does not see the
 * comment text.  The function is idempotent: if no '#' is present the buffer
 * is unchanged.
 *
 * @param line  Mutable NUL-terminated line buffer.  May be NULL (no-op).
 */
static void chaos_time_strip_comment(char *line)
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
 * Maps a clock name string or decimal integer to a POSIX clockid_t.
 *
 * Recognises the portable names ("realtime", "monotonic") as well as
 * platform-specific names guarded by the appropriate preprocessor symbols
 * (e.g. "monotonic_raw" on Linux, "tai" on kernels with CLOCK_TAI).  Falls
 * back to strtol() parsing for numeric clock IDs not covered by the string
 * table, allowing future or non-standard clocks to be targeted without
 * recompiling the library.
 *
 * @param text      NUL-terminated clock name or decimal string.
 * @param clock_id  Output: set to the corresponding clockid_t on success.
 * @return          1 on success, 0 if @p text is unrecognised or malformed.
 */
static int chaos_time_parse_clock_id(const char *text, clockid_t *clock_id)
{
    char *end = NULL;
    long value;

    if (text == NULL || clock_id == NULL || *text == '\0')
    {
        return 0;
    }
    if (strcmp(text, "realtime") == 0)
    {
        *clock_id = CLOCK_REALTIME;
        return 1;
    }
    if (strcmp(text, "monotonic") == 0)
    {
        *clock_id = CLOCK_MONOTONIC;
        return 1;
    }
#ifdef CLOCK_MONOTONIC_RAW
    if (strcmp(text, "monotonic_raw") == 0)
    {
        *clock_id = CLOCK_MONOTONIC_RAW;
        return 1;
    }
#endif
#ifdef CLOCK_REALTIME_COARSE
    if (strcmp(text, "realtime_coarse") == 0)
    {
        *clock_id = CLOCK_REALTIME_COARSE;
        return 1;
    }
#endif
#ifdef CLOCK_MONOTONIC_COARSE
    if (strcmp(text, "monotonic_coarse") == 0)
    {
        *clock_id = CLOCK_MONOTONIC_COARSE;
        return 1;
    }
#endif
#ifdef CLOCK_BOOTTIME
    if (strcmp(text, "boottime") == 0)
    {
        *clock_id = CLOCK_BOOTTIME;
        return 1;
    }
#endif
#ifdef CLOCK_TAI
    if (strcmp(text, "tai") == 0)
    {
        *clock_id = CLOCK_TAI;
        return 1;
    }
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
    if (strcmp(text, "process_cputime_id") == 0)
    {
        *clock_id = CLOCK_PROCESS_CPUTIME_ID;
        return 1;
    }
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
    if (strcmp(text, "thread_cputime_id") == 0)
    {
        *clock_id = CLOCK_THREAD_CPUTIME_ID;
        return 1;
    }
#endif

    value = strtol(text, &end, 10);
    if (end == text || *chaos_time_trim(end) != '\0')
    {
        return 0;
    }

    *clock_id = (clockid_t)value;
    return 1;
}

/**
 * Parses the selector token from a config line into a chaos_time_selector_t.
 *
 * Recognises the following forms:
 *  - `*`                       → SELECTOR_ANY
 *  - `clock_gettime`           → SELECTOR_OPERATION / OP_CLOCK_GETTIME
 *  - `clock_gettime/<clock>`   → SELECTOR_CLOCK_ID; <clock> parsed via
 *                                chaos_time_parse_clock_id()
 *  - `nanosleep`               → SELECTOR_OPERATION / OP_NANOSLEEP
 *  - `usleep`                  → SELECTOR_OPERATION / OP_USLEEP
 *
 * @p selector is zeroed before any fields are written.
 *
 * @param text      NUL-terminated selector token (not modified).
 * @param selector  Output: populated on success.
 * @return          1 on success, 0 if the text is unrecognised or malformed.
 */
static int chaos_time_selector_parse(const char *text, chaos_time_selector_t *selector)
{
    const char *clock_text;
    size_t text_len;

    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->kind = CHAOS_TIME_SELECTOR_ANY;
        selector->operation = CHAOS_TIME_OP_INVALID;
        return 1;
    }
    if (strcmp(text, "clock_gettime") == 0)
    {
        selector->kind = CHAOS_TIME_SELECTOR_OPERATION;
        selector->operation = CHAOS_TIME_OP_CLOCK_GETTIME;
        return 1;
    }
    if (strncmp(text, "clock_gettime/", 14) == 0)
    {
        clock_text = text + 14;
        if (!chaos_time_parse_clock_id(clock_text, &selector->clock_id))
        {
            return 0;
        }
        selector->kind = CHAOS_TIME_SELECTOR_CLOCK_ID;
        selector->operation = CHAOS_TIME_OP_CLOCK_GETTIME;
        text_len = strlen(clock_text);
        if (text_len >= sizeof(selector->text))
        {
            return 0;
        }
        (void)memcpy(selector->text, clock_text, text_len + 1U);
        return 1;
    }
    if (strcmp(text, "nanosleep") == 0)
    {
        selector->kind = CHAOS_TIME_SELECTOR_OPERATION;
        selector->operation = CHAOS_TIME_OP_NANOSLEEP;
        return 1;
    }
    if (strcmp(text, "usleep") == 0)
    {
        selector->kind = CHAOS_TIME_SELECTOR_OPERATION;
        selector->operation = CHAOS_TIME_OP_USLEEP;
        return 1;
    }

    return 0;
}

/**
 * Tests whether a selector matches a (operation, clock_id) pair and, if so,
 * computes a specificity rank.
 *
 * Specificity ranks (higher = more specific, wins over lower):
 *  - 3 — SELECTOR_CLOCK_ID with matching operation and clock_id
 *  - 2 — SELECTOR_OPERATION with matching operation
 *  - 1 — SELECTOR_ANY (matches everything)
 *
 * The rank is used by chaos_time_config_select_rule() to choose the most
 * specific applicable rule when multiple rules match the same call site.
 *
 * @param selector    Selector to test.  May be NULL (returns 0).
 * @param operation   Operation from the intercepted call.
 * @param clock_id    Clock ID from the intercepted call.
 * @param rank_out    Optional output: set to the specificity rank on a match,
 *                    0 on no-match.  May be NULL.
 * @return            Non-zero if the selector matches, zero otherwise.
 */
static int chaos_time_selector_matches(
    const chaos_time_selector_t *selector,
    chaos_time_operation_t operation,
    clockid_t clock_id,
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
    if (selector->kind == CHAOS_TIME_SELECTOR_ANY)
    {
        if (rank_out != NULL)
        {
            *rank_out = 1U;
        }
        return 1;
    }
    if (selector->operation != operation)
    {
        return 0;
    }
    if (selector->kind == CHAOS_TIME_SELECTOR_OPERATION)
    {
        if (rank_out != NULL)
        {
            *rank_out = 2U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_TIME_SELECTOR_CLOCK_ID && selector->clock_id == clock_id)
    {
        if (rank_out != NULL)
        {
            *rank_out = 3U;
        }
        return 1;
    }
    return 0;
}

/**
 * Parses an errno name string or decimal integer into a positive int.
 *
 * Recognises the six errno symbols that are meaningful for the intercepted
 * functions: EINVAL, EFAULT, EINTR, EPERM, ENOSYS, EAGAIN.  Falls back to
 * strtol() for other values, allowing numeric errno codes to be specified
 * directly.  Negative values and zero are rejected.
 *
 * @param text  NUL-terminated errno name or decimal string.
 * @return      Positive errno value, or -1 if @p text is unrecognised or
 *              out of range.
 */
static int chaos_time_parse_errno_name(const char *text)
{
    char *end = NULL;
    long value;

    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "EFAULT") == 0)
    {
        return EFAULT;
    }
    if (strcmp(text, "EINTR") == 0)
    {
        return EINTR;
    }
    if (strcmp(text, "EPERM") == 0)
    {
        return EPERM;
    }
    if (strcmp(text, "ENOSYS") == 0)
    {
        return ENOSYS;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }

    value = strtol(text, &end, 10);
    if (end == text || *chaos_time_trim(end) != '\0' || value <= 0L || value > 0x7fffffffL)
    {
        return -1;
    }
    return (int)value;
}

/**
 * Parses a probability string in [0.0, 1.0] from decimal text.
 *
 * Uses strtod() for parsing.  Values outside the closed interval [0.0, 1.0]
 * are rejected; trailing non-whitespace after the number is also rejected.
 *
 * @param text         NUL-terminated decimal probability string.
 * @param probability  Output: set on success.
 * @return             0 on success, -1 on parse error or out-of-range value.
 */
static int chaos_time_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_time_trim(end) != '\0' || value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

/**
 * Copies a NUL-terminated string into a fixed-size buffer with bounds checking.
 *
 * Fails if the source string is empty or if it would not fit with its NUL
 * terminator within @p buffer_size bytes.
 *
 * @param text         Source string to copy.
 * @param buffer       Destination buffer.
 * @param buffer_size  Total byte capacity of @p buffer including the NUL.
 * @return             0 on success, -1 on NULL argument or overflow.
 */
static int chaos_time_copy_text_value(const char *text, char *buffer, size_t buffer_size)
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
 * Splits a combined "value[@probability]" token into its two components.
 *
 * Looks for the last '@' in @p text.  If found, copies everything before it
 * into @p payload and parses everything after it as a probability.  If no '@'
 * is present, copies the entire text into @p payload and sets *probability to
 * 1.0 (always trigger).
 *
 * The last '@' is used (not the first) to allow values that themselves contain
 * '@' characters, though no current value syntax requires this.
 *
 * @param text          NUL-terminated combined token.
 * @param payload       Output buffer for the value portion.
 * @param payload_size  Byte capacity of @p payload including NUL.
 * @param probability   Output: probability in [0.0, 1.0].
 * @return              0 on success, -1 on NULL argument, parse error, or
 *                      payload overflow.
 */
static int chaos_time_parse_payload_probability(
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
        return chaos_time_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(at_sign - text);
    if (payload_len == 0U || payload_len >= payload_size)
    {
        return -1;
    }

    (void)memcpy(payload, text, payload_len);
    payload[payload_len] = '\0';
    if (chaos_time_parse_probability(at_sign + 1, probability) != 0)
    {
        return -1;
    }
    return 0;
}

/**
 * Parses a latency duration in milliseconds from a decimal string.
 *
 * Accepts values in [0, UINT_MAX].  The value 0 is valid and produces a
 * no-op LATENCY rule (triggers probability check but sleeps for zero time).
 *
 * @param text        NUL-terminated decimal millisecond count.
 * @param latency_ms  Output: latency in milliseconds.
 * @return            0 on success, -1 on parse error or overflow.
 */
static int chaos_time_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_time_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/**
 * Parses a signed time offset in milliseconds from a decimal string.
 *
 * Accepts the full range of int64_t (negative offsets move time backwards).
 * No range restriction is imposed beyond what strtoll() provides; callers
 * that receive very large offsets will clamp the result to zero (see
 * chaos_time_add_offset_ms()).
 *
 * @param text       NUL-terminated signed decimal millisecond value.
 * @param offset_ms  Output: offset in milliseconds.
 * @return           0 on success, -1 on parse error.
 */
static int chaos_time_parse_offset(const char *text, int64_t *offset_ms)
{
    char *end = NULL;
    long long value;

    if (text == NULL || offset_ms == NULL)
    {
        return -1;
    }

    value = strtoll(text, &end, 10);
    if (end == text || *chaos_time_trim(end) != '\0')
    {
        return -1;
    }

    *offset_ms = (int64_t)value;
    return 0;
}

/**
 * Checks whether an effect is valid for the given selector.
 *
 * ERRNO and LATENCY are universally applicable: they can be attached to any
 * selector kind.  OFFSET is restricted to selectors that target
 * clock_gettime (SELECTOR_OPERATION or SELECTOR_CLOCK_ID with
 * OP_CLOCK_GETTIME) because OFFSET modifies the returned struct timespec,
 * which sleep functions do not produce.  The wildcard selector (`*`) is also
 * rejected for OFFSET because it would implicitly target nanosleep and usleep,
 * which is meaningless.
 *
 * @param selector  The selector from the rule being validated.
 * @param effect    The effect to validate.
 * @return          Non-zero if the combination is permitted, zero otherwise.
 */
static int
chaos_time_effect_allowed(const chaos_time_selector_t *selector, chaos_time_effect_t effect)
{
    if (selector == NULL)
    {
        return 0;
    }
    if (effect == CHAOS_TIME_EFFECT_ERRNO || effect == CHAOS_TIME_EFFECT_LATENCY)
    {
        return 1;
    }
    if (effect != CHAOS_TIME_EFFECT_OFFSET)
    {
        return 0;
    }
    return selector->kind != CHAOS_TIME_SELECTOR_ANY &&
           selector->operation == CHAOS_TIME_OP_CLOCK_GETTIME;
}

/**
 * Ensures that a computed mtime hash does not collide with the two reserved
 * sentinel values CHAOS_TIME_MTIME_UNKNOWN and CHAOS_TIME_MTIME_RELOADING.
 *
 * If a hash happens to equal one of the sentinels (probability ≈ 2/2^64), it
 * is shifted by −1.  This is safe because the only property required of the
 * hash is that it changes when the mtime changes; a single collision on a
 * given file state causes an extra reload on that state, which is harmless.
 *
 * @param value  Raw hash value.
 * @return       @p value if not a sentinel, otherwise value − 1.
 */
static uint64_t chaos_time_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_TIME_MTIME_UNKNOWN || value == CHAOS_TIME_MTIME_RELOADING)
    {
        return value - 1U;
    }
    return value;
}

/**
 * Produces a 64-bit hash of a struct stat's mtime fields.
 *
 * Combines the second and nanosecond fields of the mtime using FNV-inspired
 * multiply-and-XOR steps seeded with a non-trivial initialisation constant.
 * Sub-second precision is included so that a file replaced within the same
 * second is still detected as changed.
 *
 * If @p st is NULL, returns CHAOS_TIME_MTIME_MISSING (indicating the file
 * does not exist).
 *
 * @param st  Stat result.  May be NULL.
 * @return    Normalised hash, or CHAOS_TIME_MTIME_MISSING if @p st is NULL.
 */
static uint64_t chaos_time_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_TIME_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_TIME_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_TIME_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_time_config_normalize_mtime_hash(value);
}

/**
 * Stats the config file and returns a normalised mtime hash.
 *
 * Wraps the stat(2) call in the reentrancy guard so that any internal
 * function calls made by the C runtime's stat() implementation do not
 * recurse into the chaos wrappers.
 *
 * @return  Normalised mtime hash, or CHAOS_TIME_MTIME_MISSING if the file
 *          does not exist or stat() fails for any reason.
 */
static uint64_t chaos_time_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_time_enter_internal();
    rc = stat(CHAOS_TIME_CONFIG_PATH, &st);
    chaos_time_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_TIME_MTIME_MISSING;
    }

    return chaos_time_config_hash_mtime(&st);
}

/**
 * Reads the config file into g_chaos_time_config_buffer.
 *
 * Opens the file, reads it in a loop until EOF or until
 * CHAOS_TIME_MAX_CONFIG_BYTES have been consumed, then NUL-terminates the
 * buffer.  Files larger than CHAOS_TIME_MAX_CONFIG_BYTES are rejected to
 * prevent truncated rule sets (the caller would parse an incomplete rule and
 * either produce wrong rules or hit a parse error).
 *
 * All I/O calls are guarded by chaos_time_enter_internal() so that they do
 * not trigger chaos injection recursively.
 *
 * @param size_out  Output: number of bytes read on success (not including the
 *                  NUL terminator).  Unchanged on failure.
 * @return          0 on success, -1 on any I/O error or if the file is too
 *                  large.
 */
static int chaos_time_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_time_enter_internal();
    fd = open(CHAOS_TIME_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_time_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_time_config_buffer + total, CHAOS_TIME_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_time_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_TIME_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_time_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_time_leave_internal(previous);
    g_chaos_time_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * Splits a trimmed rule line into its three colon-delimited fields.
 *
 * Writes NUL bytes over the first and second ':' separators and returns
 * trimmed pointers to each segment through the output parameters.
 *
 * @param line           Mutable NUL-terminated line content (comment already
 *                       stripped, not yet trimmed).
 * @param selector_text  Output: pointer to the trimmed selector field.
 * @param effect_text    Output: pointer to the trimmed effect name field.
 * @param value_text     Output: pointer to the trimmed value/probability field.
 * @return               Non-zero on success, zero if fewer than two ':' found
 *                       or if any argument is NULL.
 */
static int chaos_time_split_rule_fields(
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

    *selector_text = chaos_time_trim(line);
    *effect_text = chaos_time_trim(selector_end);
    *value_text = chaos_time_trim(effect_end);
    return 1;
}

/**
 * @copydoc chaos_time_config_init
 */
void chaos_time_config_init(void)
{
    chaos_time_config_reset_state(&g_chaos_time_config_states[0], 1);
    chaos_time_config_reset_state(&g_chaos_time_config_states[1], 1);
    g_chaos_time_active_config_index = 0U;
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;
}

/**
 * @copydoc chaos_time_config_parse_line
 *
 * Implementation notes:
 *
 *  - The line is stripped of comments and trimmed before splitting; an
 *    empty result after trimming produces return value 0 (skip).
 *  - Fields are split on exactly two ':' characters; missing separators
 *    produce return value -1.
 *  - For OFFSET rules, chaos_time_effect_allowed() enforces the restriction
 *    that OFFSET is only valid on clock_gettime selectors.
 */
int chaos_time_config_parse_line(char *line, chaos_time_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_TIME_MAX_VALUE];
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_time_strip_comment(line);
    line = chaos_time_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_time_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_time_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    if (strcmp(effect_text, "ERRNO") == 0)
    {
        rule->effect = CHAOS_TIME_EFFECT_ERRNO;
        if (chaos_time_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        errnum = chaos_time_parse_errno_name(payload);
        if (errnum < 0)
        {
            return -1;
        }
        rule->errnum = errnum;
        return 1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_TIME_EFFECT_LATENCY;
        if (chaos_time_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_time_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "OFFSET") == 0)
    {
        rule->effect = CHAOS_TIME_EFFECT_OFFSET;
        if (!chaos_time_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_time_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_time_parse_offset(payload, &rule->offset_ms) == 0 ? 1 : -1;
    }

    return -1;
}

/**
 * @copydoc chaos_time_config_parse_buffer
 *
 * Implementation notes:
 *
 *  - The buffer is modified in-place: newlines are replaced with NUL bytes
 *    to produce individual line strings without additional allocation.
 *  - parse_line() return value 0 (blank/comment) is silently skipped;
 *    return value -1 causes immediate failure so the caller can mark the
 *    snapshot as parse_ok == 0 and treat the entire config as empty.
 */
int chaos_time_config_parse_buffer(char *buffer, chaos_time_rule_t *rules, size_t *rule_count)
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

        parsed = chaos_time_config_parse_line(line, &rules[count]);
        if (parsed < 0)
        {
            return -1;
        }
        if (parsed == 0)
        {
            continue;
        }
        ++count;
        if (count > CHAOS_TIME_MAX_RULES)
        {
            return -1;
        }
    }

    *rule_count = count;
    return 0;
}

/**
 * @copydoc chaos_time_config_select_rule
 *
 * Implementation notes:
 *
 *  - The entire array is scanned linearly; the first matching rule
 *    initialises the "best" candidate.  Subsequent matches replace it only
 *    if they have a strictly higher rank, or the same rank with a longer
 *    selector text.
 *  - Selector text length is used as a secondary tiebreaker rather than
 *    file order, so reordering lines in the config does not change which rule
 *    is chosen (assuming no two lines are exactly identical).
 */
int chaos_time_config_select_rule(
    const chaos_time_rule_t *rules,
    size_t rule_count,
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
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
        if (!chaos_time_selector_matches(&rules[index].selector, operation, clock_id, &rank))
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
 * @copydoc chaos_time_config_prepare
 *
 * Implementation notes:
 *
 *  - The CAS target is CHAOS_TIME_MTIME_RELOADING: a second thread that
 *    arrives while a reload is in progress loses the CAS and falls back to
 *    the current active state, which is the last successfully loaded config.
 *  - parse_buffer() returning non-zero (error) causes the next_state to be
 *    reset with parse_ok == 0.  The snapshot is still published so that the
 *    mtime advances past the broken file; otherwise every call would re-try
 *    the failing parse on every intercepted function call.
 *  - An empty file (config_size == 0) leaves the snapshot empty with
 *    parse_ok == 1 (no rules, no injection) and is treated the same as a
 *    missing file from the caller's perspective.
 */
int chaos_time_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_time_config_state_t *next_state;

    observed_mtime = chaos_time_config_observed_mtime();
    cached_mtime = chaos_time_atomic_load_u64(&g_chaos_time_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }
    if (!chaos_time_atomic_cas_u64(
            &g_chaos_time_cached_mtime, cached_mtime, CHAOS_TIME_MTIME_RELOADING
        ))
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_time_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_time_config_states[next_index];
    chaos_time_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_TIME_MTIME_MISSING &&
        chaos_time_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_time_config_parse_buffer(
            g_chaos_time_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_time_config_reset_state(next_state, 0);
    }

    chaos_time_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @copydoc chaos_time_config_match_loaded
 */
int chaos_time_config_match_loaded(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
)
{
    const chaos_time_config_state_t *state = chaos_time_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_time_config_select_rule(
        state->rules, state->rule_count, effect, operation, clock_id, rule
    );
}

/**
 * @copydoc chaos_time_config_match
 */
int chaos_time_config_match(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
)
{
    if (rule == NULL || !chaos_time_config_prepare())
    {
        return 0;
    }

    return chaos_time_config_match_loaded(effect, operation, clock_id, rule);
}
