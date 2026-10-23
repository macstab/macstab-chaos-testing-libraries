/**
 * @file chaos_time_config.c
 * @brief Rule-file reload, parsing, rule selection, status and hits reporting for
 *        libchaos-time.
 *
 * @details
 * ### Reload protocol (two snapshots, lock-free readers)
 *
 * g_chaos_time_config_states[2] holds the active snapshot (g_chaos_time_active_config_index)
 * and a spare. g_chaos_time_cached_mtime is the change stamp of the loaded file and, as
 * CHAOS_TIME_MTIME_RELOADING, the reload lock. chaos_time_config_refresh():
 *
 *  1. Returns at once if the file was looked at less than CHAOS_CHECK_INTERVAL_NS (1 ms)
 *     ago (vDSO CLOCK_MONOTONIC; never throttled before the first load or during a
 *     reload, always looks when there is no vDSO clock).
 *  2. Writes the hits file if a report is overdue.
 *  3. stat()s the file. Same stamp and not provisional: done.
 *  4. Claims the reload by CAS of the cached stamp to RELOADING; a loser, or a caller that
 *     sees RELOADING, uses the active snapshot without waiting.
 *  5. Marks the spare odd (sequence) and empties it; reads the file with raw system calls;
 *     fstat()s the open descriptor and drops the read if the stamp moved meanwhile.
 *  6. Rejects a file with a NUL byte, parses the rest, carries hit slots over by rule text,
 *     writes the status file and frees slots of rules that left.
 *  7. Publishes: sequence even, then the index, then the stamp, each behind a full barrier.
 *
 * Index before stamp: a thread that already sees the new stamp must also see the new
 * index, or it could conclude the file is unchanged and serve the old rules. Readers copy a
 * rule out and validate the copy with the snapshot's sequence (chaos_hits.h), because
 * the spare they may still hold is rewritten by the next reload.
 *
 * ### Failure behaviour
 *
 * | Condition                                   | Rules applied | Status   | Retried    |
 * |---------------------------------------------|---------------|----------|------------|
 * | no file (stat fails)                        | none          | removed  | on change  |
 * | invalid line, > 256 rules, NUL byte         | none          | error    | on change  |
 * | >= 256 KiB, EACCES/EPERM on open, EISDIR    | none          | error    | on change  |
 * | other open/read error, stamp moved mid-read | previous set  | as before| next look  |
 *
 * Rejecting a file means no rule applies: the library fails open and the program runs
 * unfaulted. A stamp younger than CHAOS_RACY_WINDOW_MS (20 ms) makes the load
 * provisional: the next look re-reads the file and keeps the snapshot (with its hit
 * counts and `@first` claims) if the content hash is unchanged.
 *
 * ### Reentrancy and errno
 *
 * The guard is held around stat() and the file read, so nothing they call reaches a
 * libchaos-time wrapper. The read uses raw openat/read/close (CHAOS_CONFIG_FILE_*), so
 * another preloaded library (libchaos-io) neither sees nor faults it.
 * chaos_time_config_prepare() restores errno.
 *
 * ### Fork
 *
 * An atfork child handler releases a reload claim, the hits-writer flag and the hit
 * counts inherited from the parent and reseeds the forking thread's PRNG. vfork and
 * posix_spawn children run no handler; they share the parent's memory and write nothing.
 *
 * @invariant  The active snapshot is complete: its sequence is even and its rules,
 *             counts and texts belong to one load.
 *
 * @module chaos-time
 * @stability Internal.
 */

#include "chaos_time_config.h"
#include "chaos_clock.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * mtime with nanoseconds: st_mtim (POSIX.1-2008) on Linux, st_mtimespec on macOS and
 * the BSDs. Both halves enter the change stamp, so two writes within one second differ
 * whenever the file system's timestamp granularity separates them.
 */
#if defined(__linux__)
#define CHAOS_TIME_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_TIME_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_TIME_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_TIME_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/**
 * @brief One load of the rule file: rules, their hit slots and their text.
 *
 * Two live in static storage; nothing is allocated. Only the reload owner writes one,
 * and only the inactive one.
 *
 * @invariant  parse_ok == 1: rules[0, rule_count) are valid (rule_count may be 0).
 *             parse_ok == 0: the file was rejected (invalid line, too many rules, NUL
 *             byte, too large or unreadable); rule_count is 0 and nothing applies.
 */
typedef struct chaos_time_config_state
{
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES]; /**< Rules in file order. */
    size_t rule_count;                             /**< Valid entries of rules[]. */
    int parse_ok; /**< 1: loaded (possibly empty); 0: file rejected. */
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t *hits[CHAOS_TIME_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_TIME_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_time_config_state_t;

/** The active snapshot and the spare; 0 is active after init. */
static chaos_time_config_state_t g_chaos_time_config_states[2];

/** @brief Hit slots for the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_time_hit_pool[2U * CHAOS_TIME_MAX_RULES];

/**
 * @brief Non-zero once a snapshot with rules was attached to the pool. Until then a
 * forked child has no slot to reset and skips the pool, touching none of its pages.
 */
static int g_chaos_time_hit_pool_used = 0;

/** Index of the active snapshot; stored by the reload owner before the stamp. */
static volatile unsigned int g_chaos_time_active_config_index = 0U;

/**
 * Change stamp of the loaded file, or a CHAOS_TIME_MTIME_* sentinel.
 *
 * Doubles as the reload lock: the thread that CASes it to CHAOS_TIME_MTIME_RELOADING
 * owns the reload until it stores a stamp again (chaos_time_config_refresh()).
 */
static volatile uint64_t g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;

/**
 * @brief The loaded file's mtime was too recent to trust its stamp
 *        (chaos_clock_stamp_is_recent()): the next look re-reads it.
 */
static volatile int g_chaos_time_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_time_config_content = 0U;

/**
 * @brief Read buffer for the rule file: 256 KiB plus the NUL terminator.
 *
 * @details Only the reload owner (CHAOS_TIME_MTIME_RELOADING) touches it, so one
 * process-wide buffer suffices; on the stack it would be a 256 KiB frame inside a
 * wrapper.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves
 * in every thread of the preloaded process and adds to each thread's minimum stack
 * size.  Runtimes that create threads with small explicit stacks -- the Erlang VM, for
 * one -- then fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_time_config_buffer[CHAOS_TIME_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The first line the last parse rejected, reported in the status file.
 *
 * @details Written only by the thread that owns the reload claim.
 */
static chaos_status_error_t g_chaos_time_config_error;

/** @brief Text of each accepted rule of the last parse; copied into the snapshot. */
static char g_chaos_time_config_texts[CHAOS_TIME_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Hits-writer lock: set (by CAS) while a thread writes the hits file. */
static volatile int g_chaos_time_hits_writing = 0;

/** @brief Set once the atfork handler is registered; pthread_atfork() cannot unregister. */
static int g_chaos_time_atfork_registered = 0;

static void chaos_time_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_time_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_time_hits_total = 0U;

/** @brief chaos_hits_now_ms() at the last write, in ms. */
static uint64_t g_chaos_time_hits_last_ms = 0U;

/** @brief Process the counters belong to: set at init and in a forked child. */
static volatile uint64_t g_chaos_time_hits_pid = 0U;

/** @brief Number `<n>` of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_time_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_time_hits_owned = 0;

/** @brief Scratch for the hits file; used only by the holder of the writer lock. */
static char g_chaos_time_hits_buffer[CHAOS_TIME_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/**
 * Empties @p state and sets parse_ok; marks its sequence odd first.
 *
 * The sequence stays odd, so a reader still copying from this snapshot discards its
 * copy; chaos_time_config_publish() (or init) makes it even again.
 *
 * @param state     Snapshot to reset; NULL is ignored.
 * @param parse_ok  Value for state->parse_ok.
 */
static void chaos_time_config_reset_state(chaos_time_config_state_t *state, int parse_ok)
{
    uint64_t sequence;

    if (state == NULL)
    {
        return;
    }

    /* Odd before the memset: a reader still copying from this snapshot discards it. */
    chaos_snapshot_write_begin(&state->sequence);
    sequence = state->sequence;
    (void)memset(state, 0, sizeof(*state));
    state->sequence = sequence;
    state->parse_ok = parse_ok;
}

/**
 * The active snapshot, read after a full barrier.
 *
 * The pointer stays valid, but the snapshot behind it becomes the spare at the next
 * publish and is rewritten by the reload after that; callers validate what they copy
 * with chaos_snapshot_read_begin() / chaos_snapshot_read_valid().
 *
 * @return Never NULL.
 */
static const chaos_time_config_state_t *chaos_time_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_time_active_config_index;
    return &g_chaos_time_config_states[index];
}

/**
 * Makes snapshot @p next_index active and releases the reload claim.
 *
 * Order, each step behind a full barrier: sequence even (the snapshot is complete),
 * active index, then the stamp. Storing the stamp last both releases the claim and
 * guarantees that whoever sees the new stamp also sees the new index; the reverse
 * order would let a thread decide "unchanged" and serve the previous rules.
 *
 * @param next_index      Snapshot to activate; written completely by the caller.
 * @param observed_mtime  Change stamp the snapshot was loaded from.
 */
static void chaos_time_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_snapshot_write_end(&g_chaos_time_config_states[next_index].sequence);
    __sync_synchronize();
    g_chaos_time_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_time_cached_mtime = observed_mtime;
}

/**
 * Space, tab, CR or LF. Not isspace(): that depends on the locale the program set.
 *
 * @param ch  Character to test.
 * @return    Non-zero for a blank.
 */
static int chaos_time_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * Trims blanks in place: writes a NUL after the last non-blank character.
 *
 * @param text  Mutable string; NULL returns NULL.
 * @return      First non-blank character inside @p text, or its terminating NUL.
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
 * Cuts @p line at its first '#'. No value of this grammar contains '#'.
 *
 * @param line  Mutable line; NULL is ignored.
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
 * Parses a clock name or a decimal clock id.
 *
 * Names: realtime, monotonic, and, where the C library defines the constant,
 * monotonic_raw, realtime_coarse, monotonic_coarse, boottime, tai, process_cputime_id,
 * thread_cputime_id. Any other text is read as a decimal id (strtol, trailing blanks
 * allowed, sign allowed) and not range-checked, so dynamic clock ids (negative, e.g.
 * per-process CPU clocks) and newer clocks can be selected; an unused id never matches.
 *
 * @param text      Clock text; NULL or empty returns 0.
 * @param clock_id  Receives the id.
 * @return          1 on success, 0 when @p text is neither a name nor a number.
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
 * Parses a selector: `*`, `clock_gettime`, `clock_gettime/<clock>`, `nanosleep`, `usleep`.
 *
 * Exact, case-sensitive names. @p selector is zeroed first.
 *
 * @param text      Trimmed selector text; not modified.
 * @param selector  Receives the selector.
 * @return          1 on success, 0 for anything else (including a clock text of
 *                  CHAOS_TIME_MAX_TEXT bytes or more).
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
 * Whether @p selector matches a call, and how specifically.
 *
 * Rank 3: CLOCK_ID with equal operation and clock id; 2: OPERATION with equal
 * operation; 1: ANY.
 *
 * @param selector  Selector; NULL never matches.
 * @param operation Operation of the call.
 * @param clock_id  Clock of the call; compared for CLOCK_ID selectors only.
 * @param rank_out  Receives the rank, 0 on no match; may be NULL.
 * @return          Non-zero on a match.
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
 * Parses an ERRNO value: EINVAL, EFAULT, EINTR, EPERM, ENOSYS, EAGAIN, or a decimal.
 *
 * The names are the errors the wrapped functions document; any other errno is given as
 * a number in [1, 2147483647].
 *
 * @param text  Value text; NULL returns -1.
 * @return      The errno (> 0), or -1 when @p text is neither.
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
 * @brief Parses a probability (see chaos_policy_parse_probability()): "0", "1",
 *        "0." and digits, or "1." and zeros, whatever the locale.
 *
 * @param text         Probability string. Must not be NULL.
 * @param probability  Output: receives the parsed value. Must not be NULL.
 * @return 0 on success; -1 when @p text is not a probability.
 */
static int chaos_time_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
}

/**
 * Copies a non-empty @p text into @p buffer, NUL included.
 *
 * @param text         Source.
 * @param buffer       Destination.
 * @param buffer_size  Capacity of @p buffer in bytes, NUL included.
 * @return             0 on success; -1 for NULL arguments, empty text or overflow.
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
 * Splits `value[@probability]` at its last '@'.
 *
 * Without '@' the probability is 1.0. The value part must be non-empty and shorter than
 * @p payload_size; the probability must satisfy chaos_policy_parse_probability().
 *
 * @param text          Value field.
 * @param payload       Receives the value part.
 * @param payload_size  Capacity of @p payload in bytes, NUL included.
 * @param probability   Receives the probability; set to 1.0 first.
 * @return              0 on success, -1 otherwise.
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
 * Parses a LATENCY value: decimal ms in [0, 4294967295] (about 49.7 days).
 *
 * 0 is valid: the rule still draws, counts hits and claims `@first`, but sleeps 0 ms.
 * On LP64 a negative value wraps above the limit in strtoul and is rejected.
 *
 * @param text        Value text.
 * @param latency_ms  Receives the delay in ms.
 * @return            0 on success, -1 on malformed or out-of-range text.
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

/** @brief Largest OFFSET or REGRESS shift accepted: 100 years in milliseconds. */
#define CHAOS_TIME_MAX_OFFSET_MS INT64_C(3155760000000)

/**
 * Parses an OFFSET or REGRESS value: signed decimal ms, |value| <= 3155760000000.
 *
 * The bound (100 years) exists because strtoll clamps an overflow silently and the
 * shift is negated (REGRESS, absolute deadlines), which INT64_MIN does not survive.
 * Negative values move the clock back.
 *
 * @param text       Value text.
 * @param offset_ms  Receives the shift in ms.
 * @return           0 on success, -1 on malformed or out-of-range text.
 */
static int chaos_time_parse_offset(const char *text, int64_t *offset_ms)
{
    char *end = NULL;
    long long value;

    if (text == NULL || offset_ms == NULL)
    {
        return -1;
    }

    errno = 0;
    value = strtoll(text, &end, 10);
    if (end == text || *chaos_time_trim(end) != '\0' || errno == ERANGE ||
        value > CHAOS_TIME_MAX_OFFSET_MS || value < -CHAOS_TIME_MAX_OFFSET_MS)
    {
        return -1;
    }

    *offset_ms = (int64_t)value;
    return 0;
}

/**
 * Whether @p effect may be combined with @p selector.
 *
 * ERRNO and LATENCY: any selector. OFFSET and REGRESS change a returned time, which
 * only clock reads have: `clock_gettime` or `clock_gettime/<clock>`, not `*`.
 * (REGRESS is further limited to `clock_gettime/<clock>` by its parser.)
 *
 * @param selector  Parsed selector; NULL returns 0.
 * @param effect    Effect.
 * @return          Non-zero when allowed.
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
    if (effect != CHAOS_TIME_EFFECT_OFFSET && effect != CHAOS_TIME_EFFECT_REGRESS)
    {
        return 0;
    }
    return selector->kind != CHAOS_TIME_SELECTOR_ANY &&
           selector->operation == CHAOS_TIME_OP_CLOCK_GETTIME;
}

/**
 * Keeps a change stamp off CHAOS_TIME_MTIME_UNKNOWN and CHAOS_TIME_MTIME_RELOADING.
 *
 * A stamp equal to either (probability 2/2^64) is decremented. MISSING (0) is not
 * remapped (see the sentinel group in chaos_time_internal.h).
 *
 * Known defect: UNKNOWN - 1 is RELOADING, so a raw stamp equal to UNKNOWN is published
 * as RELOADING, and every later refresh then treats the reload as owned by another
 * thread: the process stops reloading until it forks or restarts. Probability 2^-64
 * per stamp.
 *
 * @param value  Raw stamp.
 * @return       @p value, or value - 1 for a sentinel.
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
 * 64-bit change stamp of a file: FNV-1a-style mix of mtime (s, ns), size, inode, device.
 *
 * mtime alone misses changes: file systems stamp it from a coarse clock (a few ms), so
 * two writes in one tick leave it equal. The size catches an append, the inode a
 * rewrite through a temporary file and rename(2) (`sed -i`). A same-size rewrite in
 * place within one tick is caught only by the provisional re-read
 * (chaos_clock_stamp_is_recent()).
 *
 * @param st  stat result; NULL returns CHAOS_TIME_MTIME_MISSING.
 * @return    Normalised stamp.
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
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
    value *= UINT64_C(1099511628211);
    return chaos_time_config_normalize_mtime_hash(value);
}

/**
 * stat()s the rule file under the guard; one system call, the cost of every look.
 *
 * @return Change stamp, or CHAOS_TIME_MTIME_MISSING when stat() fails for any reason.
 *         errno may change (chaos_time_config_prepare() restores it).
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
 * Reads the rule file into g_chaos_time_config_buffer and NUL-terminates it.
 *
 * Raw openat (O_CLOEXEC)/read/close under the guard, each retried on EINTR. After EOF
 * the open descriptor is fstat()ed: if its stamp is not @p expected_stamp a writer
 * changed the file during the read, the copy may mix old and new bytes, and it is
 * discarded. Sets g_chaos_time_config_provisional from the file's mtime age. Reload
 * owner only.
 *
 * @param size_out        Receives the byte count (without the NUL) on success.
 * @param expected_stamp  Stamp observed by the stat() that triggered this read.
 * @return  0 on success;
 *          -1 transient failure (open or read error, stamp moved): retry at next look;
 *          -2 file of CHAOS_TIME_MAX_CONFIG_BYTES (256 KiB) or more: reject;
 *          -3 open failed with EACCES/EPERM or read with EISDIR: reject.
 *          errno may change.
 */
static int chaos_time_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_time_enter_internal();
    do
    {
        fd = CHAOS_CONFIG_FILE_OPEN(CHAOS_TIME_CONFIG_PATH);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* Missing permission lasts until the file changes; anything else (removed since
         * the stat, EMFILE, ...) is retried at the next look. */
        const int open_error = errno;

        chaos_time_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = CHAOS_CONFIG_FILE_READ(
            fd, g_chaos_time_config_buffer + total, CHAOS_TIME_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_time_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_TIME_MAX_CONFIG_BYTES)
        {
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_time_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer
     * that rewrote or appended to it during the read leaves a different stamp; the
     * copy may be half old, half new, so it is dropped and the next look reloads. */
    if (fstat(fd, &st) != 0 || chaos_time_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_time_leave_internal(previous);
        return -1;
    }
    g_chaos_time_config_provisional = chaos_clock_stamp_is_recent(
        (int64_t)CHAOS_TIME_STAT_SEC(&st), (long)CHAOS_TIME_STAT_NSEC(&st)
    );

    CHAOS_CONFIG_FILE_CLOSE(fd);
    chaos_time_leave_internal(previous);
    g_chaos_time_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * Splits @p line at its first two ':' (overwritten with NUL) and trims each field.
 *
 * Further ':' stay in the value field, where the value parser rejects them.
 *
 * @param line           Mutable line, comment already cut.
 * @param selector_text  Receives the selector field.
 * @param effect_text    Receives the effect field.
 * @param value_text     Receives the value field (`value[@probability]`).
 * @return               Non-zero on success; 0 for fewer than two ':' or a NULL argument.
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
    g_chaos_time_hits_pid = (uint64_t)getpid();
    g_chaos_time_hits_file = chaos_hits_file_number(CHAOS_TIME_HITS_PREFIX);
    g_chaos_time_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_time_hit_pool, sizeof(g_chaos_time_hit_pool) / sizeof(g_chaos_time_hit_pool[0])
    );
    if (!g_chaos_time_atfork_registered)
    {
        g_chaos_time_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_time_config_after_fork);
    }
    /* Resolve the vDSO clock now, not first inside a wrapper a signal handler re-enters
     * (a lookup in progress there makes the throttle look on every call meanwhile). */
    (void)chaos_clock_now_ns();
    chaos_time_config_reset_state(&g_chaos_time_config_states[0], 1);
    chaos_time_config_reset_state(&g_chaos_time_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_time_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_time_config_states[1].sequence);
    g_chaos_time_active_config_index = 0U;
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;
}

/**
 * @copydoc chaos_time_config_parse_line
 *
 * Effect names are exact and case-sensitive. The selector is checked against the
 * effect before the value is parsed.
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
    if (strcmp(effect_text, "REGRESS") == 0)
    {
        rule->effect = CHAOS_TIME_EFFECT_REGRESS;
        /* One clock per rule, offset > 0: the jump state is per rule, and a rule over
         * all clocks would arm on one clock and jump on another. */
        if (!chaos_time_effect_allowed(&rule->selector, rule->effect) ||
            rule->selector.kind != CHAOS_TIME_SELECTOR_CLOCK_ID ||
            chaos_time_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0 ||
            chaos_time_parse_offset(payload, &rule->offset_ms) != 0 || rule->offset_ms <= 0)
        {
            return -1;
        }
        return 1;
    }

    return -1;
}

/**
 * @copydoc chaos_time_config_parse_buffer
 *
 * Line numbers in the error record count from 1, blank and comment lines included.
 */
int chaos_time_config_parse_buffer(char *buffer, chaos_time_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;
    size_t number = 0U;

    chaos_status_clear(&g_chaos_time_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_time_rule_t parsed;
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

        /* The parsers edit the line in place; keep it as written for the reports. */
        chaos_status_keep_line(&g_chaos_time_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_time_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_time_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_time_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers without a rule: an operator error, not a blank line. */
                chaos_status_reject(&g_chaos_time_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_TIME_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_time_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_time_config_texts[count],
            g_chaos_time_config_error.text,
            sizeof(g_chaos_time_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_time_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_time_config_last_error(void)
{
    return &g_chaos_time_config_error;
}

/**
 * @copydoc chaos_time_config_select_rule
 *
 * A later match replaces the candidate only with a strictly higher rank or, at equal
 * rank, a strictly longer selector; hence the earlier line wins a full tie, and two
 * rules with the same selector and effect resolve to the first one in the file.
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
 * @brief Empties @p state as a rejected file (parse_ok 0) and records @p reason.
 *
 * @details For conditions that persist until the file changes: size limit reached,
 * EACCES/EPERM on open, EISDIR on read, a NUL byte. Reported like an invalid line
 * (no rules, state=error) and, since the snapshot is published with the file's stamp,
 * not re-read until the stamp changes. A transient read failure takes a different path
 * (the previous snapshot stays).
 */
static void chaos_time_config_reject_file(chaos_time_config_state_t *state, const char *reason)
{
    chaos_time_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_time_config_error);
    chaos_status_reject(&g_chaos_time_config_error, reason);
}

/**
 * @brief Records a hit on @p slot and writes the hits file when due; NULL flushes.
 *
 * @details Writes on each of the first CHAOS_HITS_EAGER (64) hits, then at most every
 * CHAOS_HITS_INTERVAL_MS (100 ms); between writes a hit costs no system call. NULL
 * (at exit, or from a reload look with an overdue report) writes only if hits are
 * pending. One writer at a time, elected by CAS: a hit that finds the writer busy
 * leaves `pending` set, and the writer loops until it is clear, re-checking after
 * releasing the lock so no hit is lost. Only the process the counts belong to writes:
 * a vfork child shares this memory but must not write the parent's file. A forked
 * child starts from zero (chaos_time_config_after_fork()).
 */
static void chaos_time_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_time_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_time_hits_total;
        if (g_chaos_time_hits_pending == 0)
        {
            g_chaos_time_hits_pending = 1;
        }
        /* Past the eager hits and inside the interval: nothing to write, no system
         * call, no shared write beyond the counters. */
        if (g_chaos_time_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_time_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_time_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but is another process and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_time_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_time_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_time_config_state_t *)chaos_time_config_active_state();
        while (g_chaos_time_hits_pending != 0)
        {
            g_chaos_time_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_TIME_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_time_hits_file,
                &g_chaos_time_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_time_hits_buffer,
                sizeof(g_chaos_time_hits_buffer)
            );
        }
        g_chaos_time_hits_last_ms = now;
        __sync_lock_release(&g_chaos_time_hits_writing);
        __sync_synchronize();
        /* A hit that found the lock taken after the inner loop's last check is written
         * by this thread now, since its own CAS failed. */
    } while (g_chaos_time_hits_pending != 0);
}

/**
 * @brief pthread_atfork() child handler: drops state owned by parent threads.
 *
 * @details Only the forking thread exists in the child, so a reload claim
 * (RELOADING -> UNKNOWN), the hits-writer lock and an in-progress REGRESS decision
 * (via chaos_hits_pool_after_fork()) are released. Hit counts and `@first` claims start
 * from zero, the child gets its own hits file, and the forking thread's PRNG reseeds.
 * vfork children and posix_spawn run no atfork handler: they share the parent's
 * memory, see its claims as busy and write nothing.
 */
static void chaos_time_config_after_fork(void)
{
    if (g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING)
    {
        g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;
    }
    /* Stores only what changed (CHAOS_STORE_IF_CHANGED): every page written here is
     * a copy-on-write fault in each child. */
    CHAOS_STORE_IF_CHANGED(g_chaos_time_hits_writing, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_time_hits_pending, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_time_hits_total, 0U);
    CHAOS_STORE_IF_CHANGED(g_chaos_time_hits_last_ms, 0U);
    g_chaos_time_hits_pid = (uint64_t)getpid();
    /* The child's own pid, without probing /tmp: a stale file of an earlier process with
     * this pid is caught by the exclusive first write, which then picks another suffix. */
    g_chaos_time_hits_file = (long)g_chaos_time_hits_pid;
    CHAOS_STORE_IF_CHANGED(g_chaos_time_hits_owned, 0);
    /* The child must not replay the parent's stream (pre-fork workers would all decide
     * alike): the forking thread reseeds from its new thread id on the next draw. */
    CHAOS_STORE_IF_CHANGED(g_chaos_time_tls_prng_state, 0U);
    if (g_chaos_time_hit_pool_used)
    {
        chaos_hits_pool_after_fork(
            g_chaos_time_hit_pool,
            sizeof(g_chaos_time_hit_pool) / sizeof(g_chaos_time_hit_pool[0]),
            chaos_time_config_active_state()->hits,
            chaos_time_config_active_state()->rule_count
        );
    }
}

/** @brief Writes pending hits at normal exit (exit() or return from main; not _exit). */
__attribute__((destructor)) static void chaos_time_config_report_hits_at_exit(void)
{
    chaos_time_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of the new snapshot its text, hit slot and slot generation.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its slot
 * (chaos_hits_assign()): editing one rule resets neither the counts, `@first` claims
 * nor REGRESS state of the others, and a firing through a rule copy taken before the
 * reload still lands. Reload owner only.
 */
static void chaos_time_config_attach_hits(chaos_time_config_state_t *next_state)
{
    const chaos_time_config_state_t *active = chaos_time_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index],
            g_chaos_time_config_texts[index],
            sizeof(next_state->text[index])
        );
    }
    if (next_state->rule_count > 0U)
    {
        g_chaos_time_hit_pool_used = 1;
    }
    chaos_hits_assign(
        g_chaos_time_hit_pool,
        sizeof(g_chaos_time_hit_pool) / sizeof(g_chaos_time_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_time_config_report_hits
    );
    for (index = 0U; index < next_state->rule_count; ++index)
    {
        next_state->rules[index].hit = next_state->hits[index];
        next_state->rules[index].hit_generation =
            next_state->hits[index] != NULL ? next_state->hits[index]->generation : 0U;
    }
}

/**
 * @brief Writes the status file for the load that produced @p state.
 *
 * @details state=ok with the rule count, state=error with the rejected line, or, with
 * no rule file, removes the status file. Called by the reload owner before the
 * publish.
 */
static void
chaos_time_config_report(uint64_t observed_mtime, const chaos_time_config_state_t *state)
{
    if (observed_mtime == CHAOS_TIME_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_TIME_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(
            CHAOS_TIME_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_time_config_error
        );
    }
    else
    {
        chaos_status_write(CHAOS_TIME_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/** @brief When this process last looked at the rule file (vDSO CLOCK_MONOTONIC, ns). */
static volatile uint64_t g_chaos_time_last_check_ns = 0U;

/** @brief Look interval, CHAOS_CHECK_INTERVAL_NS (1 ms); 0 looks on every call (unit tests). */
static uint64_t g_chaos_time_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether this call may skip looking at the rule file.
 *
 * @details A look is a stat() system call, the largest part of a wrapper's cost, so
 * after the first load the file is looked at no more than once per interval; a change
 * takes effect within 1 ms instead of at the very next call. Never skips while the
 * stamp is UNKNOWN (no load yet) or RELOADING, or when there is no vDSO clock
 * (chaos_clock_checked_recently() then returns 0). A missing or empty rule file is
 * throttled like any other. Concurrent callers may race on the timestamp; the worst
 * case is one extra stat().
 */
static int chaos_time_config_checked_recently(void)
{
    const uint64_t cached = chaos_time_atomic_load_u64(&g_chaos_time_cached_mtime);

    if (cached == CHAOS_TIME_MTIME_UNKNOWN || cached == CHAOS_TIME_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(
        &g_chaos_time_last_check_ns, g_chaos_time_check_interval_ns
    );
}

/**
 * @brief chaos_time_config_prepare() without the errno save; see the file header for
 *        the protocol and the failure table.
 *
 * @details A rejected file is still published (empty, parse_ok 0) with its stamp, so
 * the bad file is parsed once, not again at every look. An empty file publishes an
 * empty snapshot with parse_ok 1 and status ok, 0 rules.
 *
 * @return Non-zero when the snapshot in effect after this call holds at least one rule.
 */
static int chaos_time_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size = 0U;
    uint64_t content = 0U;
    chaos_time_config_state_t *next_state;

    if (chaos_time_config_checked_recently())
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }
    /* Hits of an elapsed interval are written now, not only at the next hit or at
     * exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_time_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_time_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_time_config_report_hits(NULL);
    }
    observed_mtime = chaos_time_config_observed_mtime();
    cached_mtime = chaos_time_atomic_load_u64(&g_chaos_time_cached_mtime);

    if (observed_mtime == cached_mtime && !g_chaos_time_config_provisional)
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }
    /* Another thread of this process owns the reload: use the active snapshot. Without
     * this test the CAS below would succeed as RELOADING -> RELOADING, and two threads
     * would fill the same spare snapshot and read buffer at once. A claim inherited
     * through fork() was released by the atfork handler; a vfork child must not take
     * over its parent's. */
    if (cached_mtime == CHAOS_TIME_MTIME_RELOADING)
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }
    if (!chaos_time_atomic_cas_u64(
            &g_chaos_time_cached_mtime, cached_mtime, CHAOS_TIME_MTIME_RELOADING
        ))
    {
        return chaos_time_config_active_state()->rule_count != 0U;
    }
    g_chaos_time_config_provisional = 0;

    active_index = g_chaos_time_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_time_config_states[next_index];
    chaos_time_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_TIME_MTIME_MISSING)
    {
        const int read_rc = chaos_time_config_read_file(&config_size, observed_mtime);

        if (read_rc == -2 || read_rc == -3)
        {
            chaos_time_config_reject_file(
                next_state,
                read_rc == -2 ? CHAOS_STATUS_REASON_TOO_LARGE : CHAOS_STATUS_REASON_UNREADABLE
            );
            config_size = 0U;
        }
        else if (read_rc != 0)
        {
            /* A failed read says nothing about the rules: keep the active snapshot and
             * release the claim with the previous stamp, so the next look retries
             * instead of running with no rules until the file changes again. */
            __sync_synchronize();
            g_chaos_time_cached_mtime = cached_mtime;
            return chaos_time_config_active_state()->rule_count != 0U;
        }
        if (read_rc == 0)
        {
            content = chaos_config_content_hash(g_chaos_time_config_buffer, config_size);
            if (observed_mtime == cached_mtime && content == g_chaos_time_config_content)
            {
                /* A provisional load re-read with identical content: the snapshot stays,
                 * with its hit counts, `@first` claims and REGRESS state. */
                __sync_synchronize();
                g_chaos_time_cached_mtime = cached_mtime;
                return chaos_time_config_active_state()->rule_count != 0U;
            }
        }
        if (config_size > 0U && memchr(g_chaos_time_config_buffer, '\0', config_size) != NULL)
        {
            /* The parser would stop at the NUL and drop every rule after it unreported. */
            chaos_time_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
            config_size = 0U;
        }
        if (config_size > 0U &&
            chaos_time_config_parse_buffer(
                g_chaos_time_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Rejected: publish an empty snapshot (parse_ok 0), so no rule applies. */
            chaos_time_config_reset_state(next_state, 0);
        }
    }

    g_chaos_time_config_content = content;
    chaos_time_config_attach_hits(next_state);
    chaos_time_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load are freed and outdated in rule copies
     * still held; done before the publish, while this thread still holds the claim. */
    chaos_hits_release(
        g_chaos_time_hit_pool,
        sizeof(g_chaos_time_hit_pool) / sizeof(g_chaos_time_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_time_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief chaos_time_config_refresh() with errno preserved.
 *
 * @details The stat, open and read of a refresh are the library's, not the caller's: a
 * wrapped call that then succeeds must not carry the ENOENT of a missing rule file.
 */
int chaos_time_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_time_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @copydoc chaos_time_config_match_loaded
 *
 * A rejected snapshot (parse_ok 0) has no rules and returns 0 before the scan.
 */
int chaos_time_config_match_loaded(
    chaos_time_effect_t effect,
    chaos_time_operation_t operation,
    clockid_t clock_id,
    chaos_time_rule_t *rule
)
{
    const chaos_time_config_state_t *state = chaos_time_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_time_config_select_rule(
               state->rules, state->rule_count, effect, operation, clock_id, rule
           ) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
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
