/**
 * @file chaos_process_config.c
 * @brief Rule-file reload, parsing, rule selection, status and hits reporting for
 *        libchaos-process. Also compiled into chaos-init (src/init/chaos_init_process.c).
 *
 * @details
 * ### Reload protocol (two snapshots, lock-free readers)
 *
 * g_chaos_process_config_states[2] holds the active snapshot and a spare.
 * g_chaos_process_cached_mtime is the change stamp of the loaded file and, as
 * CHAOS_PROCESS_MTIME_RELOADING, the reload lock. chaos_process_config_refresh():
 *
 *  1. Returns at once if the file was looked at less than CHAOS_CHECK_INTERVAL_NS (1 ms)
 *     ago (vDSO CLOCK_MONOTONIC; never throttled before the first load or during a
 *     reload; always looks when there is no vDSO clock).
 *  2. Writes the hits file if a report is overdue.
 *  3. stat()s the file. Same stamp and not provisional: done.
 *  4. Claims the reload by CAS of the cached stamp to RELOADING; a loser, or a caller that
 *     sees RELOADING, uses the active snapshot without waiting.
 *  5. Marks the spare odd (sequence) and empties it; reads the file with raw system
 *     calls; fstat()s the descriptor and drops the read if the stamp moved meanwhile.
 *  6. Rejects a file with a NUL byte, parses the rest, carries hit slots over by rule
 *     text, writes the status file and frees slots of rules that left.
 *  7. Publishes: sequence even, FAIL_AFTER counters reset, then the index, then the
 *     stamp, each behind a full barrier.
 *
 * Index before stamp: whoever sees the new stamp also sees the new index, and storing
 * the stamp releases the claim. Readers copy a rule out and validate the copy with the
 * snapshot's sequence (chaos_hits.h), because the spare they may still hold is rewritten
 * by the next reload.
 *
 * ### Failure behaviour
 *
 * | Condition                                   | Rules applied | Status    | Retried   |
 * |---------------------------------------------|---------------|-----------|-----------|
 * | no file (stat fails)                        | none          | removed   | on change |
 * | invalid line, > 256 rules, NUL byte         | none          | error     | on change |
 * | >= 256 KiB, EACCES/EPERM on open, EISDIR    | none          | error     | on change |
 * | other open/read error, stamp moved mid-read | previous set  | unchanged | next look |
 *
 * A rejected file means no rule applies: the library fails open. A stamp younger than
 * CHAOS_RACY_WINDOW_MS (20 ms) makes the load provisional: the next look re-reads the
 * file and keeps the snapshot (with its hit counts, `@first` claims and FAIL_AFTER
 * counters) if the content hash is unchanged.
 *
 * @par Known defect
 * chaos_process_config_normalize_mtime_hash() maps a raw stamp equal to
 * CHAOS_PROCESS_MTIME_UNKNOWN to UNKNOWN - 1, which is CHAOS_PROCESS_MTIME_RELOADING.
 * Publishing that stamp leaves the lock looking held: every later call sees RELOADING,
 * looks without throttle and never reloads again in that process. Probability 2^-64
 * per stamp.
 *
 * ### Reentrancy, errno, fork
 *
 * The guard is held around stat() and the file read; the read uses raw
 * openat/read/close (CHAOS_CONFIG_FILE_*), invisible to other preloaded libraries.
 * chaos_process_config_prepare() restores errno. An atfork child handler releases an
 * inherited reload claim and hits-writer flag, zeroes hit counts, `@first` claims and
 * FAIL_AFTER counters, and reseeds the forking thread's PRNG. vfork and posix_spawn
 * children run no handler.
 *
 * @invariant  The active snapshot is complete (even sequence); parse_ok == 0 implies
 *             rule_count == 0.
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
 * mtime with nanoseconds: st_mtim (POSIX.1-2008) on Linux, st_mtimespec on macOS/BSD
 * ---------------------------------------------------------------------- */

#if defined(__linux__)
/** mtime seconds (Linux). */
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtim.tv_sec)
/** mtime nanoseconds (Linux). */
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
/** mtime seconds (macOS/BSD). */
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
/** mtime nanoseconds (macOS/BSD). */
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/* -------------------------------------------------------------------------
 * Internal config state type
 * ---------------------------------------------------------------------- */

/**
 * @brief One load of the rule file: rules, their hit slots and their text.
 *
 * Two live in static storage; nothing is allocated. Only the reload owner writes one,
 * and only the inactive one.
 */
typedef struct chaos_process_config_state
{
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    /** Rules in file order. */
    chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    /** Valid entries of `rules[]`. */
    size_t rule_count;
    /**
     * 1: loaded (possibly empty). 0: file rejected (invalid line, too many rules, NUL
     * byte, too large or unreadable); rule_count is 0 and nothing matches.
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

/** The active snapshot and the spare; 0 is active after init. */
static chaos_process_config_state_t g_chaos_process_config_states[2];

/** @brief Hit slots for the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_process_hit_pool[2U * CHAOS_PROCESS_MAX_RULES];

/** Index of the active snapshot; stored by the reload owner before the stamp. */
static volatile unsigned int g_chaos_process_active_config_index = 0U;

/**
 * Change stamp of the loaded file (hash of mtime s/ns, size, inode, device), or a
 * CHAOS_PROCESS_MTIME_* sentinel.
 *
 * Doubles as the reload lock: the thread that CASes it to CHAOS_PROCESS_MTIME_RELOADING
 * owns the reload until it stores a stamp again. Two file states with the same stamp
 * (a hash collision) would miss one reload, until the next change.
 */
static volatile uint64_t g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;

/**
 * @brief The loaded file's mtime was too recent to trust its stamp
 *        (chaos_clock_stamp_is_recent()): the next look re-reads it.
 */
static volatile int g_chaos_process_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_process_config_content = 0U;

/**
 * @brief Read buffer for the rule file: 256 KiB plus the NUL terminator.
 *
 * @details Only the reload owner (CHAOS_PROCESS_MTIME_RELOADING) touches it, so one
 * process-wide buffer suffices; on the stack it would be a 256 KiB frame inside a
 * wrapper.
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

/** @brief Text of each accepted rule of the last parse; copied into the snapshot. */
static char g_chaos_process_config_texts[CHAOS_PROCESS_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Hits-writer lock: set (by CAS) while a thread writes the hits file. */
static volatile int g_chaos_process_hits_writing = 0;

/** @brief Set once the atfork handler is registered; pthread_atfork() cannot unregister. */
static int g_chaos_process_atfork_registered = 0;

static void chaos_process_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_process_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_process_hits_total = 0U;

/** @brief chaos_hits_now_ms() at the last write, in ms. */
static uint64_t g_chaos_process_hits_last_ms = 0U;

/** @brief Process the counters belong to: set at init and in a forked child. */
static volatile uint64_t g_chaos_process_hits_pid = 0U;

/** @brief Number `<n>` of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_process_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_process_hits_owned = 0;

/** @brief Scratch for the hits file; used only by the holder of the writer lock. */
static char g_chaos_process_hits_buffer[CHAOS_PROCESS_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/**
 * @brief Zeroes every FAIL_AFTER counter.
 *
 * Called at init, on every publish (whether or not the new file has FAIL_AFTER rules)
 * and in a forked child. Plain stores, not atomic exchanges: a wrapper incrementing
 * concurrently may land its increment just before or after the reset, which at most
 * shifts the count by the calls in flight. 64-bit stores are single-copy atomic on the
 * supported targets, so no counter is ever torn.
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
 * @brief Empties @p state and sets parse_ok; marks its sequence odd first.
 *
 * The sequence stays odd, so a reader still copying from this snapshot discards its
 * copy; chaos_process_config_publish() (or init) makes it even again.
 *
 * @param state    Snapshot to reset; NULL is ignored.
 * @param parse_ok Value for state->parse_ok.
 */
static void chaos_process_config_reset_state(chaos_process_config_state_t *state, int parse_ok)
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
 * @brief The active snapshot, read after a full barrier.
 *
 * The snapshot behind the pointer becomes the spare at the next publish and is
 * rewritten by the reload after that; callers validate what they copy with
 * chaos_snapshot_read_begin() / chaos_snapshot_read_valid().
 *
 * @return Never NULL.
 */
static const chaos_process_config_state_t *chaos_process_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_process_active_config_index;
    return &g_chaos_process_config_states[index];
}

/**
 * @brief Makes snapshot @p next_index active and releases the reload claim.
 *
 * Order: sequence even (the snapshot is complete), FAIL_AFTER counters reset, barrier,
 * active index, barrier, stamp. Counters are reset before the new rules become visible,
 * so the new rules count from 0 (a call still in flight under the old rules may add
 * one). The stamp goes last: storing it
 * releases the claim, and whoever sees it also sees the new index.
 *
 * @param next_index     Snapshot to activate; written completely by the caller.
 * @param observed_mtime Change stamp the snapshot was loaded from.
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
 * @brief Space, tab, CR or LF. Not isspace(): that depends on the program's locale.
 */
static int chaos_process_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims blanks in place: writes a NUL after the last non-blank character.
 *
 * @param text Mutable string; NULL returns NULL.
 * @return First non-blank character inside @p text, or its terminating NUL.
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
 * @brief Cuts @p line at its first `#`. No value of this grammar contains `#`.
 *
 * @param line Mutable line; NULL is ignored.
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
 * @brief Parses a selector: `*`, `pthread_create`, `fork`, `posix_spawn`,
 *        `posix_spawnp`, `execve`, `execveat`, `waitpid` (exact, case-sensitive).
 *
 * The derived wrappers (wait, system, execvp, ...) have no selector of their own.
 *
 * @param text     Trimmed selector text.
 * @param selector Receives the selector; zeroed first.
 * @return Non-zero on success; 0 for anything else.
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
 * @brief Whether @p selector matches @p operation, and how specifically.
 *
 * @param selector  Selector; NULL never matches.
 * @param operation Operation of the call.
 * @param rank_out  Receives 2 (operation), 1 (`*`) or 0 (no match); may be NULL.
 * @return Non-zero on a match.
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
 * @brief Parses an errno: EAGAIN, ENOMEM, EACCES, ENOENT, EINTR, ECHILD, EPERM, ESRCH,
 *        EBUSY, EINVAL, ENOSYS, EMFILE, ENFILE, E2BIG, or a decimal in [1, 2147483647].
 *
 * The names are the errors the wrapped functions document; any other errno is given as
 * a number.
 *
 * @param text  Value text; NULL returns -1.
 * @return The errno (> 0), or -1 when @p text is neither.
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
 * @brief Copies a non-empty @p text into @p buffer, NUL included.
 *
 * @param text        Source.
 * @param buffer      Destination.
 * @param buffer_size Capacity of @p buffer in bytes, NUL included.
 * @return 0 on success; -1 for NULL arguments, empty text or overflow.
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
 * @brief Splits `value[@probability]` at its last `@`.
 *
 * Without `@` the probability is 1.0. The value part must be non-empty and shorter than
 * @p payload_size; the probability must satisfy chaos_policy_parse_probability().
 *
 * @param text         Value field.
 * @param payload      Receives the value part (e.g. "EAGAIN", "50", "ENOMEM,100").
 * @param payload_size Capacity of @p payload in bytes, NUL included.
 * @param probability  Receives the probability; set to 1.0 first.
 * @return 0 on success; -1 otherwise.
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
 * @brief Parses a LATENCY value: decimal ms in [0, 4294967295] (about 49.7 days).
 *
 * 0 is valid: the rule still draws, counts hits and claims `@first`, but sleeps 0 ms.
 * On LP64 a negative value wraps above the limit in strtoul and is rejected.
 *
 * @param text       Value text.
 * @param latency_ms Receives the delay in ms.
 * @return 0 on success; -1 on malformed or out-of-range text.
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
 * @brief Parses a FAIL_AFTER count: decimal digits, 0..18446744073709551615.
 *
 * errno is preserved (strtoull's ERANGE is read and then restored).
 *
 * @param text  Trimmed count text; must start with a digit.
 * @param count Receives the count.
 * @return 0 on success; -1 on malformed or out-of-range text.
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
 * @brief Parses a FAIL_AFTER value: `<errno>,<count>`, split at the first `,`, both
 *        halves trimmed and non-empty.
 *
 * @param payload Mutable value text; edited in place.
 * @param errnum  Receives the errno (chaos_process_parse_errno_name()).
 * @param count   Receives the count (chaos_process_parse_fail_after_count()).
 * @return 0 on success; -1 otherwise.
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
 * @brief Moves a change stamp equal to UNKNOWN or RELOADING down by one.
 *
 * @warning Defect: UNKNOWN - 1 is RELOADING, so a raw stamp equal to UNKNOWN comes out
 *          as RELOADING, and publishing it stops reloads for the life of the process
 *          (see the file header). RELOADING - 1 is safe. MISSING (0) is not remapped
 *          either. Each case has probability 2^-64 per stamp.
 *
 * @param value Raw stamp.
 * @return @p value, or value - 1 for a sentinel.
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
 * @brief 64-bit change stamp of a file: FNV-1a-style mix of mtime (s, ns), size, inode,
 *        device.
 *
 * mtime alone misses changes: file systems stamp it from a coarse clock (a few ms), so
 * two writes in one tick leave it equal. The size catches an append, the inode a
 * rewrite through a temporary file and rename(2) (`sed -i`). A same-size rewrite in
 * place within one tick is caught only by the provisional re-read
 * (chaos_clock_stamp_is_recent()).
 *
 * @param st stat result; NULL returns CHAOS_PROCESS_MTIME_MISSING.
 * @return Normalised stamp.
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
 * @brief stat()s the rule file under the guard: one system call, the cost of every look.
 *
 * @return Change stamp, or CHAOS_PROCESS_MTIME_MISSING when stat() fails for any reason.
 *         errno may change (chaos_process_config_prepare() restores it).
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
 * @brief Reads the rule file into g_chaos_process_config_buffer and NUL-terminates it.
 *
 * Raw openat/read/close (CHAOS_CONFIG_FILE_*, O_CLOEXEC) under the guard, each retried
 * on EINTR. After the read the open descriptor is fstat()ed: if its stamp is no longer
 * @p expected_stamp a writer changed the file mid-read and the copy is dropped. Sets
 * g_chaos_process_config_provisional when the mtime is younger than
 * CHAOS_RACY_WINDOW_MS. Called only by the reload owner.
 *
 * @param size_out       Receives the byte count, NUL excluded; unchanged on failure.
 * @param expected_stamp Stamp from the stat() that triggered this reload.
 * @return  0  success.
 * @return -1  transient: open failed (other than EACCES/EPERM), read failed, or the
 *             stamp moved; the caller keeps the active snapshot and retries next look.
 * @return -2  file of CHAOS_PROCESS_MAX_CONFIG_BYTES (256 KiB) or more.
 * @return -3  open failed with EACCES/EPERM, or read failed with EISDIR.
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
     * copy may then be half old, half new, so it is not used and the next look
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
 * @brief Splits @p line at its first two `:` into trimmed selector, effect and value.
 *
 * Further `:` stay in the value field.
 *
 * @param line           Mutable line; the two separators become NUL.
 * @param selector_text  Receives the selector field.
 * @param effect_text    Receives the effect field.
 * @param value_text     Receives the value field.
 * @return Non-zero on success; 0 with fewer than two `:` or a NULL argument.
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
 * Implementation notes: the effect name is matched exactly (`ERRNO`, `LATENCY`,
 * `FAIL_AFTER`). The value field is parsed in two passes: the `@probability` suffix is
 * split off first (chaos_process_parse_payload_probability()), then the rest is read
 * according to the effect.
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
 * @brief Whether this build can apply @p rule; always 1 in the library.
 *
 * @details chaos-init, which applies rules from outside the tracee through seccomp,
 * defines it before including this file (src/init/chaos_init_process.c). A rule it
 * cannot apply rejects the file like an invalid line, with
 * CHAOS_STATUS_REASON_UNSUPPORTED, so the status file says so instead of the rule
 * silently doing nothing.
 */
#ifndef CHAOS_PROCESS_RULE_SUPPORTED
#define CHAOS_PROCESS_RULE_SUPPORTED(rule) 1
#endif

/**
 * @copydoc chaos_process_config_parse_buffer
 *
 * Implementation notes: all or nothing. The first rejected line sets *rule_count to 0
 * and returns -1, so a partial rule set is never published; exceeding
 * CHAOS_PROCESS_MAX_RULES is a rejection, not a truncation, so the operator sees it in
 * the status file.
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
 * Implementation notes: `pthread_create` beats `*` by rank, not by length. The winner
 * is copied out by value; the caller validates the copy against the snapshot sequence.
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
 * @details A file at or over 256 KiB, one this process may not open (EACCES, EPERM),
 * a directory (EISDIR) or one containing a NUL byte stays unusable until it changes,
 * unlike a read that failed transiently or met a concurrent writer. It is reported
 * like a rejected file (no rules, status error with @p reason) and not re-read until
 * its stamp changes.
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
 * writer repeats the write before it lets go. A forked child's inherited counts are
 * cleared by the atfork child handler, so no hit is reported twice; a vfork child
 * (another pid sharing this memory) writes nothing.
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
 * @details Registered with pthread_atfork(). The thread that held a reload claim or
 * the hits-writer flag does not exist in the child, so both are released. Hit counts,
 * `@first` claims and FAIL_AFTER counters start from zero for the new process, its
 * hits file is its own, and the forking thread's PRNG reseeds. vfork children and
 * posix_spawn run no atfork handler: they share the parent's memory, see its claims as
 * busy and write nothing. A raw clone() bypassing libc's fork skips this handler too.
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
 * Once a first load has completed the file is looked at no more than once per
 * CHAOS_CHECK_INTERVAL_NS (1 ms), so a change takes effect within about 1 ms instead of
 * on the very next call. The throttle is off only while the stamp is UNKNOWN (no load
 * yet) or RELOADING; a missing or empty rule file is throttled like any other. Without
 * a vDSO clock (chaos_clock_now_ns() returns 0) every call looks.
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
 * Implementation notes (protocol and failure table in the file header):
 *
 *  - Unchanged stamp: returns after one stat(), with no allocation.
 *  - A lost CAS returns the active snapshot (one version stale at most, never torn)
 *    instead of spinning.
 *  - Missing file: an empty snapshot with parse_ok == 1 is published. Rejected file
 *    (invalid line, size, permission, NUL): an empty snapshot with parse_ok == 0 is
 *    published under the new stamp, so the bad file is not re-read until it changes.
 *    Transient read failure: nothing is published and the old stamp is restored, so
 *    the next look retries with the previous rules still active.
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
    /* Another thread of this process owns the reload: use the current snapshot.
     * Without this check the CAS below would succeed as RELOADING -> RELOADING and a
     * second thread would load into the same spare and read buffer concurrently. A
     * claim inherited through fork() was released by the atfork handler; a vfork child
     * must not take over its parent's. */
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
             * release the claim with the previous stamp, so the next look retries
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
            /* Rejected: publish an empty snapshot with parse_ok == 0 (no rule applies). */
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
 * @brief chaos_process_config_refresh() with errno preserved.
 *
 * @details The stat, open and read calls of a refresh belong to the library, not to
 * the caller: a wrapped call that then succeeds must not report the ENOENT of a
 * missing rule file.
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
 * Implementation notes: the sequence is read before parse_ok and the rules and checked
 * again after the copy; a rejected snapshot (parse_ok == 0) never matches.
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
 * Implementation notes: every wrapper calls this once per effect, so a wrapped call
 * runs prepare() up to three times; with a vDSO clock, the 1 ms throttle makes all but
 * the first a clock read. An empty active snapshot returns 0 without a search.
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
