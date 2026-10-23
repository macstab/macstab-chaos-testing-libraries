/**
 * @file chaos_memory_config.c
 * @brief libchaos-memory rule engine: throttled look at the rule file, lock-free
 *        two-snapshot reload, parsing, rule selection, status and hits reporting.
 *
 * @details
 * @par Reload protocol
 * Rules live in two static snapshots; g_chaos_memory_active_config_index names the
 * one readers use. On each intercepted call chaos_memory_config_refresh():
 *  1. Skips the look if the file was looked at less than CHAOS_CHECK_INTERVAL_NS
 *     (1 ms, vDSO CLOCK_MONOTONIC) ago. Never skipped while the cached stamp is
 *     UNKNOWN or RELOADING, nor when there is no vDSO clock.
 *  2. stat(2)s the file into a change stamp (mtime s+ns, size, inode, device).
 *     Unchanged and not provisional: done.
 *  3. Claims the reload by CAS of the cached stamp to CHAOS_MEMORY_MTIME_RELOADING.
 *     A thread that sees RELOADING, or loses the CAS, serves the active snapshot.
 *  4. Reads the file into the static buffer with raw system calls and fstat(2)s
 *     the open descriptor: a stamp different from step 2 means a writer raced the
 *     read; the copy is dropped and the claim released with the old stamp, so the
 *     next look retries.
 *  5. Parses into the inactive snapshot (all or nothing), carries hit slots over
 *     for unchanged rule texts, writes the status file, frees the slots of rules
 *     that left.
 *  6. Publishes: snapshot sequence even, barrier, active index, barrier, stamp.
 *
 * Readers copy a rule out of the active snapshot without a lock and validate the
 * copy with the snapshot's sequence counter (chaos_snapshot_read_begin()/valid()),
 * because two reloads in a row rewrite the snapshot a slow reader may still hold.
 *
 * @par Racy-clean files
 * A file whose mtime is within CHAOS_RACY_WINDOW_MS (20 ms) of now is loaded
 * provisionally: it may be rewritten with the same size inside one mtime tick
 * without its stamp changing. The next unthrottled look reads it again until the
 * stamp is old enough; when the content hash is unchanged the snapshot (counts,
 * `@first` claims) is kept.
 *
 * @par Failure behaviour (fail-open, but reported)
 * | Condition                                   | Result                          |
 * |---------------------------------------------|---------------------------------|
 * | no file                                     | no rules, status file removed   |
 * | invalid line, > 256 rules, NUL byte         | no rules, status: error + line  |
 * | >= 256 KiB, EACCES/EPERM on open, EISDIR    | no rules, status: error         |
 * | other open/read error, writer raced the read | previous snapshot kept, retried |
 * A rejected file is not read again until its stamp changes.
 *
 * @par Reentrancy and errno
 * stat(2) and the read run under the reentrancy guard; anything they map passes
 * through. chaos_memory_config_prepare() preserves errno.
 *
 * @par Fork
 * The child handler releases a reload claim and the hits-writer flag inherited
 * from the parent, restarts counting and `@first` claims, and reseeds the PRNG.
 * vfork children and posix_spawn run no atfork handler: they share the parent's
 * memory, see its claims as busy and write no hits file.
 *
 * @par Test seams
 * g_chaos_memory_check_interval_ns (0 disables the throttle);
 * CHAOS_CONFIG_FILE_OPEN/READ/CLOSE (chaos_status.h).
 */

#include "chaos_memory_config.h"
#include "chaos_clock.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* =========================================================================
 * Platform compatibility: struct stat mtime accessor macros
 * =========================================================================
 */

/**
 * @brief mtime seconds and nanoseconds of a struct stat: st_mtim on Linux
 *        (POSIX.1-2008), st_mtimespec on the BSD/macOS hosts the unit tests also
 *        build on.
 */
#if defined(__linux__)
#define CHAOS_MEMORY_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_MEMORY_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_MEMORY_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_MEMORY_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/* =========================================================================
 * Config state
 * =========================================================================
 */

/**
 * @brief One loaded rule file.
 *
 * @details Two instances exist. The active one is read by every thread without a
 * lock; the inactive one is written only by the reload owner and becomes visible
 * when the index flips.
 *
 * @invariant parse_ok == 0 exactly when the file was rejected as a whole (invalid
 *            line, too many rules, too large, unreadable, NUL byte); rule_count is
 *            then 0. An absent or empty file gives parse_ok == 1, rule_count == 0.
 */
typedef struct chaos_memory_config_state
{
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    /** Rules [0, rule_count); the rest zeroed. */
    chaos_memory_rule_t rules[CHAOS_MEMORY_MAX_RULES];

    /** Number of rules; 0 for an absent, empty or rejected file. */
    size_t rule_count;

    /** 0 when the file was rejected; chaos_memory_config_match_loaded() then matches nothing. */
    int parse_ok;
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t *hits[CHAOS_MEMORY_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_MEMORY_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_memory_config_state_t;

/**
 * @brief The two snapshots: [active index] is served, the other is the next
 *        reload's target. Static (2 x 256 rules plus texts) so nothing allocates.
 */
static chaos_memory_config_state_t g_chaos_memory_config_states[2];

/** @brief Hit slots of the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_memory_hit_pool[2U * CHAOS_MEMORY_MAX_RULES];

/**
 * @brief Non-zero once a snapshot with rules was attached to the pool. Until then a
 * forked child has no slot to reset and skips the pool, touching none of its pages.
 */
static int g_chaos_memory_hit_pool_used = 0;

/**
 * @brief Index (0 or 1) of the active snapshot.
 *
 * @details Written by chaos_memory_config_publish() after a full barrier, read by
 * chaos_memory_config_active_state() after one, so a reader that sees the new
 * index also sees the snapshot written before it.
 */
static volatile unsigned int g_chaos_memory_active_config_index = 0U;

/**
 * @brief Change stamp of the loaded rule file, or a reserved value.
 *
 * @details UNKNOWN before the first load (forces an unthrottled reload); RELOADING
 * while a thread owns a reload (claimed by CAS); MISSING when the last load found
 * no file; otherwise the stamp the active snapshot was loaded from.
 */
static volatile uint64_t g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;

/**
 * @brief The loaded file's mtime was too recent to trust its stamp
 *        (chaos_clock_stamp_is_recent): the next look reads it again.
 */
static volatile int g_chaos_memory_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_memory_config_content = 0U;

/**
 * @brief Buffer the reload owner reads the rule file into.
 *
 * @details CHAOS_MEMORY_MAX_CONFIG_BYTES + 1 bytes, for the NUL terminator appended by
 * chaos_memory_config_read_file(). Only the thread holding the reload claim
 * (CHAOS_MEMORY_MTIME_RELOADING) touches it, so one process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves
 * in every thread of the preloaded process and adds to each thread's minimum stack
 * size.  Runtimes that create threads with small explicit stacks -- the Erlang VM, for
 * one -- then fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_memory_config_buffer[CHAOS_MEMORY_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The first line the last parse rejected, reported in the status file.
 *
 * @details Written only by the thread that owns the reload claim.
 */
static chaos_status_error_t g_chaos_memory_config_error;

/** @brief Text of each accepted rule of the last parse, copied into the snapshot. */
static char g_chaos_memory_config_texts[CHAOS_MEMORY_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Set while a thread writes the hits file (CAS-claimed; one writer at a time). */
static volatile int g_chaos_memory_hits_writing = 0;

/** @brief Set once the fork child handler is registered; a re-init must not add a second. */
static int g_chaos_memory_atfork_registered = 0;

static void chaos_memory_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_memory_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_memory_hits_total = 0U;

/** @brief chaos_hits_now_ms() at the last hits-file write, in ms. */
static uint64_t g_chaos_memory_hits_last_ms = 0U;

/** @brief Process the counters belong to: set at start and in a forked child. */
static volatile uint64_t g_chaos_memory_hits_pid = 0U;

/** @brief Number of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_memory_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_memory_hits_owned = 0;

/** @brief Scratch for the hits file; used only by the thread that writes it. */
static char g_chaos_memory_hits_buffer[CHAOS_MEMORY_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/* =========================================================================
 * Internal helpers — state management
 * =========================================================================
 */

/**
 * @brief Empties a snapshot and opens a write on it.
 *
 * @details Makes the sequence counter odd first, so a reader still holding a copy
 * of this snapshot from an earlier cycle discards it; the counter survives the
 * memset. The matching chaos_snapshot_write_end() is in publish() (or init()).
 *
 * @param state     Snapshot; NULL is a no-op.
 * @param parse_ok  1 for "loaded, no rules yet", 0 for "file rejected".
 */
static void chaos_memory_config_reset_state(chaos_memory_config_state_t *state, int parse_ok)
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
 * @brief The active snapshot; never NULL.
 *
 * @details The barrier before the index load pairs with the one in publish(). The
 * snapshot may still be rewritten by two later reloads while the caller reads it;
 * callers that copy rules validate with the sequence counter.
 */
static const chaos_memory_config_state_t *chaos_memory_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_memory_active_config_index;
    return &g_chaos_memory_config_states[index];
}

/**
 * @brief Makes snapshot @p next_index active and releases the reload claim.
 *
 * @details Order: close the snapshot's write (sequence even), barrier, flip the
 * index, barrier, store the stamp. The index goes first so that the stamp, which
 * releases the claim, is never visible before the rules it describes. A thread
 * between the two stores still sees RELOADING and serves the (already new)
 * active snapshot.
 *
 * @param next_index      Snapshot to activate (0 or 1).
 * @param observed_mtime  Stamp the snapshot was loaded from; not RELOADING.
 */
static void chaos_memory_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_snapshot_write_end(&g_chaos_memory_config_states[next_index].sequence);
    __sync_synchronize();
    g_chaos_memory_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_memory_cached_mtime = observed_mtime;
}

/* =========================================================================
 * Internal helpers — text parsing utilities
 * =========================================================================
 */

/** @brief Whether @p ch is a blank for trimming: space, tab, CR or LF (locale-independent). */
static int chaos_memory_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims blanks in place.
 *
 * @param text  NUL-terminated string; trailing blanks are overwritten with NUL.
 * @return Pointer to the first non-blank character inside @p text (its terminator
 *         when all blank); NULL for NULL.
 */
static char *chaos_memory_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_memory_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_memory_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

/**
 * @brief Cuts @p line at its first `#` (no escaping: no field of this grammar can
 *        contain `#`). NULL is a no-op.
 */
static void chaos_memory_strip_comment(char *line)
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
 * @brief Parses a selector (exact, case-sensitive match).
 *
 * @details
 *  - `*`          → kind=ANY,       operation=INVALID,  mmap_kind=INVALID
 *  - `mmap`       → kind=OPERATION, operation=MMAP,     mmap_kind=INVALID
 *  - `mmap/anon`  → kind=MMAP_KIND, operation=MMAP,     mmap_kind=ANON
 *  - `mmap/file`  → kind=MMAP_KIND, operation=MMAP,     mmap_kind=FILE
 *  - `mprotect`   → kind=OPERATION, operation=MPROTECT, mmap_kind=INVALID
 *  - `munmap`     → kind=OPERATION, operation=MUNMAP,   mmap_kind=INVALID
 *  - `madvise`    → kind=OPERATION, operation=MADVISE,  mmap_kind=INVALID
 *
 *
 * @param text      Trimmed selector text.
 * @param selector  Output; zeroed, then filled (selector_len = strlen(text)).
 * @return 1 on success; 0 for an unknown, empty or NULL selector.
 */
static int chaos_memory_selector_parse(const char *text, chaos_memory_selector_t *selector)
{
    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_ANY;
        selector->operation = CHAOS_MEMORY_OP_INVALID;
        return 1;
    }
    if (strcmp(text, "mmap") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_OPERATION;
        selector->operation = CHAOS_MEMORY_OP_MMAP;
        return 1;
    }
    if (strcmp(text, "mmap/anon") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_MMAP_KIND;
        selector->operation = CHAOS_MEMORY_OP_MMAP;
        selector->mmap_kind = CHAOS_MEMORY_MMAP_KIND_ANON;
        return 1;
    }
    if (strcmp(text, "mmap/file") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_MMAP_KIND;
        selector->operation = CHAOS_MEMORY_OP_MMAP;
        selector->mmap_kind = CHAOS_MEMORY_MMAP_KIND_FILE;
        return 1;
    }
    if (strcmp(text, "mprotect") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_OPERATION;
        selector->operation = CHAOS_MEMORY_OP_MPROTECT;
        return 1;
    }
    if (strcmp(text, "munmap") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_OPERATION;
        selector->operation = CHAOS_MEMORY_OP_MUNMAP;
        return 1;
    }
    if (strcmp(text, "madvise") == 0)
    {
        selector->kind = CHAOS_MEMORY_SELECTOR_OPERATION;
        selector->operation = CHAOS_MEMORY_OP_MADVISE;
        return 1;
    }

    return 0;
}

/**
 * @brief Whether @p selector matches a call, and with which rank.
 *
 * @details Ranks: 1 for `*`, 2 for an operation, 3 for `mmap/anon` / `mmap/file`;
 * the highest wins in chaos_memory_config_select_rule().
 *
 * @param selector       Selector; NULL never matches.
 * @param operation      Intercepted operation.
 * @param mmap_flags     mmap() flags; read only for MMAP_KIND selectors.
 * @param[out] rank_out  Rank on a match, 0 otherwise; may be NULL.
 * @return 1 on a match, 0 otherwise.
 */
static int chaos_memory_selector_matches(
    const chaos_memory_selector_t *selector,
    chaos_memory_operation_t operation,
    int mmap_flags,
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
    if (selector->kind == CHAOS_MEMORY_SELECTOR_ANY)
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
    if (selector->kind == CHAOS_MEMORY_SELECTOR_OPERATION)
    {
        if (rank_out != NULL)
        {
            *rank_out = 2U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_MEMORY_SELECTOR_MMAP_KIND && operation == CHAOS_MEMORY_OP_MMAP)
    {
        int is_anonymous = chaos_memory_mmap_is_anonymous(mmap_flags);

        if ((selector->mmap_kind == CHAOS_MEMORY_MMAP_KIND_ANON && is_anonymous) ||
            (selector->mmap_kind == CHAOS_MEMORY_MMAP_KIND_FILE && !is_anonymous))
        {
            if (rank_out != NULL)
            {
                *rank_out = 3U;
            }
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Parses the value of an ERRNO rule.
 *
 * @details Accepted names, chosen for what mmap(2) and its relatives return:
 *  - ENOMEM  — out of memory (most common for mmap/anon injection)
 *  - EINVAL  — invalid argument (length not page-aligned, bad flags, etc.)
 *  - EACCES  — permission denied (MAP_SHARED + read-only fd, PROT_EXEC on noexec)
 *  - EPERM   — operation not permitted (sealed file, seccomp restriction)
 *  - EBADF   — bad file descriptor (invalid fd for file-backed mmap)
 *  - ENODEV  — no such device (file system does not support mmap)
 *  - EAGAIN  — resource temporarily unavailable (mlock limit exceeded)
 *  - EFAULT  — bad address (address argument outside accessible range)
 *  - ENOSYS  — function not implemented (madvise advice not supported)
 *  - ENFILE  — file table overflow
 *  - EMFILE  — too many open files
 *
 * Any other text must be a decimal number in 1..2147483647 (strtol base 10;
 * trailing blanks allowed). Hexadecimal is not accepted.
 *
 * @param text  Errno name or number.
 * @return The errno value, or -1 when @p text is neither.
 */
static int chaos_memory_parse_errno_name(const char *text)
{
    char *end = NULL;
    long value;

    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "ENOMEM") == 0)
    {
        return ENOMEM;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "EACCES") == 0)
    {
        return EACCES;
    }
    if (strcmp(text, "EPERM") == 0)
    {
        return EPERM;
    }
    if (strcmp(text, "EBADF") == 0)
    {
        return EBADF;
    }
    if (strcmp(text, "ENODEV") == 0)
    {
        return ENODEV;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }
    if (strcmp(text, "EFAULT") == 0)
    {
        return EFAULT;
    }
    if (strcmp(text, "ENOSYS") == 0)
    {
        return ENOSYS;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }

    value = strtol(text, &end, 10);
    if (end == text || *chaos_memory_trim(end) != '\0' || value <= 0L || value > 0x7fffffffL)
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
static int chaos_memory_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
}

/**
 * @brief Copies a non-empty @p text, terminator included, into @p buffer.
 *
 * @return 0 on success; -1 when @p text is NULL, empty, or does not fit in
 *         @p buffer_size bytes.
 */
static int chaos_memory_copy_text_value(const char *text, char *buffer, size_t buffer_size)
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
 * @brief Splits a value field `<payload>[@<probability>]` (e.g. `ENOMEM@0.05`).
 *
 * @details Splits at the last `@`. Without one the probability is 1.0. The payload
 * must be non-empty and shorter than @p payload_size.
 *
 * @param text              Trimmed value field.
 * @param[out] payload      Payload, NUL-terminated.
 * @param payload_size      Size of @p payload, bytes.
 * @param[out] probability  Parsed probability, or 1.0.
 * @return 0 on success, -1 on any error.
 */
static int chaos_memory_parse_payload_probability(
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
        return chaos_memory_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(at_sign - text);
    if (payload_len == 0U || payload_len >= payload_size)
    {
        return -1;
    }

    (void)memcpy(payload, text, payload_len);
    payload[payload_len] = '\0';
    if (chaos_memory_parse_probability(at_sign + 1, probability) != 0)
    {
        return -1;
    }
    return 0;
}

/**
 * @brief Parses a LATENCY value: decimal milliseconds, 0..4294967295 (about 49.7
 *        days). 0 is accepted and sleeps nothing.
 *
 * @param text             Decimal text; trailing blanks allowed.
 * @param[out] latency_ms  Parsed value.
 * @return 0 on success; -1 for non-numeric text or a value above 4294967295.
 */
static int chaos_memory_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_memory_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/* =========================================================================
 * Internal helpers — change stamp
 * =========================================================================
 */

/**
 * @brief Keeps a real stamp off UNKNOWN and RELOADING, which the protocol must be
 *        able to tell apart from any file state.
 *
 * @details Each maps to value - 1, so two file states may share a stamp, which can
 * hide one change. Caveat: UNKNOWN - 1 equals RELOADING, so a raw stamp of
 * 0xffffffffffffffff (probability 2^-64) still yields RELOADING, and after its
 * publish no further reload would happen. MISSING (0) is not excluded either.
 *
 * @return @p value, or @p value - 1 when it equals a reserved value.
 */
static uint64_t chaos_memory_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_MEMORY_MTIME_UNKNOWN || value == CHAOS_MEMORY_MTIME_RELOADING)
    {
        return value - 1U;
    }
    return value;
}

/**
 * @brief 64-bit change stamp of a file: mtime (s, ns), size, inode and device.
 *
 * @details The mtime alone is not enough: file systems stamp it from a coarse
 * clock (a few milliseconds), so two writes in one tick leave it unchanged. The
 * size catches an append, the inode a rewrite through a temporary file and
 * rename(2) (`sed -i`), even within one tick. A same-size in-place rewrite within
 * one tick is caught by the provisional reload instead (chaos_clock_stamp_is_recent()).
 *
 * The fields are folded FNV-1a style (xor, then multiply by the 64-bit FNV prime
 * 1099511628211) from the start value 1469598103934665603 (0x14650fb0739d0383).
 * The stamp only has to change when a field changes; it is not a quality hash.
 *
 * @param st  stat result, or NULL when stat(2) failed.
 * @return The normalised stamp; CHAOS_MEMORY_MTIME_MISSING for NULL.
 */
static uint64_t chaos_memory_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_MEMORY_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_MEMORY_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_MEMORY_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
    value *= UINT64_C(1099511628211);
    return chaos_memory_config_normalize_mtime_hash(value);
}

/**
 * @brief stat(2)s the rule file under the reentrancy guard and returns its stamp.
 *
 * @details The one system call of a look that finds nothing changed. Goes through
 * libc's stat(), so another preloaded library that wraps stat() sees it.
 *
 * @return The stamp, or CHAOS_MEMORY_MTIME_MISSING when stat(2) fails for any reason.
 */
static uint64_t chaos_memory_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_memory_enter_internal();
    rc = stat(CHAOS_MEMORY_CONFIG_PATH, &st);
    chaos_memory_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_MEMORY_MTIME_MISSING;
    }

    return chaos_memory_config_hash_mtime(&st);
}

/* =========================================================================
 * Internal helpers — file I/O
 * =========================================================================
 */

/**
 * @brief Reads the whole rule file into g_chaos_memory_config_buffer and
 *        NUL-terminates it. Called by the reload owner only.
 *
 * @details Uses CHAOS_CONFIG_FILE_OPEN/READ/CLOSE (raw openat/read/close on Linux,
 * O_CLOEXEC), so libchaos-io cannot see or fail the read; EINTR is retried. Runs
 * under the reentrancy guard. After the read, fstat(2) of the descriptor must
 * give @p expected_stamp, or a writer changed the file meanwhile. Also records
 * whether the stamp is recent enough to make the load provisional.
 *
 * @param[out] size_out       Bytes read, excluding the terminator.
 * @param expected_stamp      Stamp from the stat(2) that triggered the reload.
 * @return  0 success;
 *         -1 transient (open error other than EACCES/EPERM, read error other than
 *            EISDIR, or the stamp changed): keep the old snapshot and retry;
 *         -2 the file reaches CHAOS_MEMORY_MAX_CONFIG_BYTES (256 KiB): reject;
 *         -3 EACCES/EPERM on open or EISDIR on read: reject until the file changes.
 */
static int chaos_memory_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_memory_enter_internal();
    do
    {
        fd = CHAOS_CONFIG_FILE_OPEN(CHAOS_MEMORY_CONFIG_PATH);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* No permission lasts until the file changes; anything else (gone since
         * the stat, out of descriptors, ...) is retried on the next check. */
        const int open_error = errno;

        chaos_memory_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = CHAOS_CONFIG_FILE_READ(
            fd, g_chaos_memory_config_buffer + total, CHAOS_MEMORY_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_memory_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_MEMORY_MAX_CONFIG_BYTES)
        {
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_memory_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer
     * that rewrote or appended to it while it was read leaves a different stamp; the
     * copy may then be half old, half new, so it is not used and the next call
     * reloads the finished file. */
    if (fstat(fd, &st) != 0 || chaos_memory_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_memory_leave_internal(previous);
        return -1;
    }
    g_chaos_memory_config_provisional = chaos_clock_stamp_is_recent(
        (int64_t)CHAOS_MEMORY_STAT_SEC(&st), (long)CHAOS_MEMORY_STAT_NSEC(&st)
    );

    CHAOS_CONFIG_FILE_CLOSE(fd);
    chaos_memory_leave_internal(previous);
    g_chaos_memory_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/* =========================================================================
 * Internal helpers — line splitting
 * =========================================================================
 */

/**
 * @brief Splits @p line in place at its first two `:` into trimmed selector,
 *        effect and value fields; further `:` stay in the value (and make it invalid).
 *
 * @return 1 on success, 0 when the line has fewer than two `:` or an argument is NULL.
 */
static int chaos_memory_split_rule_fields(
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

    *selector_text = chaos_memory_trim(line);
    *effect_text = chaos_memory_trim(selector_end);
    *value_text = chaos_memory_trim(effect_end);
    return 1;
}

/* =========================================================================
 * Public API implementation
 * =========================================================================
 */

/**
 * @brief Resets the rule state (contract in chaos_memory_config.h).
 *
 * @details Both snapshots end empty with parse_ok = 1 and an even sequence.
 */
void chaos_memory_config_init(void)
{
    g_chaos_memory_hits_pid = (uint64_t)getpid();
    g_chaos_memory_hits_file = chaos_hits_file_number(CHAOS_MEMORY_HITS_PREFIX);
    g_chaos_memory_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_memory_hit_pool,
        sizeof(g_chaos_memory_hit_pool) / sizeof(g_chaos_memory_hit_pool[0])
    );
    if (!g_chaos_memory_atfork_registered)
    {
        g_chaos_memory_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_memory_config_after_fork);
    }
    /* Find the vDSO clock now, not first inside a wrapper a signal handler may re-enter. */
    (void)chaos_clock_now_ns();
    chaos_memory_config_reset_state(&g_chaos_memory_config_states[0], 1);
    chaos_memory_config_reset_state(&g_chaos_memory_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_memory_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_memory_config_states[1].sequence);
    g_chaos_memory_active_config_index = 0U;
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;
}

/**
 * @brief Parses one rule line (contract in chaos_memory_config.h).
 *
 * @details The comment is cut before trimming, so a comment-only line is blank.
 * Effect names are exact and case-sensitive (`ERRNO`, `LATENCY`).
 */
int chaos_memory_config_parse_line(char *line, chaos_memory_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_MEMORY_MAX_VALUE];
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_memory_strip_comment(line);
    line = chaos_memory_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_memory_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_memory_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    if (strcmp(effect_text, "ERRNO") == 0)
    {
        rule->effect = CHAOS_MEMORY_EFFECT_ERRNO;
        if (chaos_memory_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        errnum = chaos_memory_parse_errno_name(payload);
        if (errnum < 0)
        {
            return -1;
        }
        rule->errnum = errnum;
        return 1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_MEMORY_EFFECT_LATENCY;
        if (chaos_memory_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_memory_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }

    return -1;
}

/**
 * @brief Parses a whole buffer, all or nothing (contract in chaos_memory_config.h).
 *
 * @details Lines are numbered from 1 for the status report. Rules already written
 * to @p rules before a rejection are left there; the caller resets the snapshot.
 */
int chaos_memory_config_parse_buffer(char *buffer, chaos_memory_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;
    size_t number = 0U;

    chaos_status_clear(&g_chaos_memory_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_memory_rule_t parsed;
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
        chaos_status_keep_line(&g_chaos_memory_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_memory_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_memory_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_memory_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers without a rule. */
                chaos_status_reject(&g_chaos_memory_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_MEMORY_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_memory_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_memory_config_texts[count],
            g_chaos_memory_config_error.text,
            sizeof(g_chaos_memory_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_memory_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_memory_config_last_error(void)
{
    return &g_chaos_memory_config_error;
}

/**
 * @brief Selects the most specific matching rule (contract in chaos_memory_config.h).
 *
 * @details One pass; a later rule replaces the current best only if strictly more
 * specific, so the earliest line wins a full tie.
 */
int chaos_memory_config_select_rule(
    const chaos_memory_rule_t *rules,
    size_t rule_count,
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
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
        if (!chaos_memory_selector_matches(&rules[index].selector, operation, mmap_flags, &rank))
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
 * @details For conditions that persist until the file changes: at or over 256 KiB,
 * EACCES/EPERM on open, a directory, a NUL byte. Unlike a transient read failure,
 * the outcome is published: no rules, status file "error" with @p reason, and no
 * re-read until the stamp changes.
 */
static void chaos_memory_config_reject_file(chaos_memory_config_state_t *state, const char *reason)
{
    chaos_memory_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_memory_config_error);
    chaos_status_reject(&g_chaos_memory_config_error, reason);
}

/**
 * @brief Reports this process's hit counts after a hit on @p slot (NULL: flush, as
 *        at exit or after an idle interval).
 *
 * @details Writes the hits file on each of the first CHAOS_HITS_EAGER (64) hits,
 * then at most once per CHAOS_HITS_INTERVAL_MS (100 ms); a later look at the rule
 * file or the exit destructor flushes the rest. One thread writes at a time (CAS
 * on the writer flag): a hit that finds the writer busy leaves `pending` set, and
 * the writer repeats the write before it lets go. A forked child starts from zero
 * (the fork child handler), so no hit is reported twice.
 */
static void chaos_memory_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_memory_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_memory_hits_total;
        if (g_chaos_memory_hits_pending == 0)
        {
            g_chaos_memory_hits_pending = 1;
        }
        /* Past the eager hits and inside the interval there is nothing to write:
         * no system call, no shared write beyond the counters. */
        if (g_chaos_memory_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_memory_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_memory_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but is another process and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_memory_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_memory_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_memory_config_state_t *)chaos_memory_config_active_state();
        while (g_chaos_memory_hits_pending != 0)
        {
            g_chaos_memory_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_MEMORY_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_memory_hits_file,
                &g_chaos_memory_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_memory_hits_buffer,
                sizeof(g_chaos_memory_hits_buffer)
            );
        }
        g_chaos_memory_hits_last_ms = now;
        __sync_lock_release(&g_chaos_memory_hits_writing);
        __sync_synchronize();
        /* A hit that found the writer busy after its last check is written now. */
    } while (g_chaos_memory_hits_pending != 0);
}

/**
 * @brief Child side of fork(): forgets what threads of the parent were doing.
 *
 * @details Registered with pthread_atfork(). The thread that held a reload claim
 * or the hits-writer flag does not exist in the child, so both are released;
 * counts and `@first` claims start from zero for the new process, its hits file is
 * its own, and the forking thread's PRNG reseeds. vfork children and posix_spawn
 * run no atfork handler: they share the parent's memory, see its claims as busy
 * and write nothing.
 */
static void chaos_memory_config_after_fork(void)
{
    if (g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_RELOADING)
    {
        g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;
    }
    /* Stores only what changed (CHAOS_STORE_IF_CHANGED): every page written here is
     * a copy-on-write fault in each child. */
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_hits_writing, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_hits_pending, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_hits_total, 0U);
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_hits_last_ms, 0U);
    g_chaos_memory_hits_pid = (uint64_t)getpid();
    /* The child's own pid, without probing /tmp: a stale file of an earlier process with
     * this pid is caught by the exclusive first write, which then picks another suffix. */
    g_chaos_memory_hits_file = (long)g_chaos_memory_hits_pid;
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_hits_owned, 0);
    /* The child must not draw the parent's numbers (pre-fork workers would all
     * decide alike): its PRNG reseeds from its own thread id on the next draw. */
    CHAOS_STORE_IF_CHANGED(g_chaos_memory_tls_prng_state, 0U);
    if (g_chaos_memory_hit_pool_used)
    {
        chaos_hits_pool_after_fork(
            g_chaos_memory_hit_pool,
            sizeof(g_chaos_memory_hit_pool) / sizeof(g_chaos_memory_hit_pool[0]),
            chaos_memory_config_active_state()->hits,
            chaos_memory_config_active_state()->rule_count
        );
    }
}

/**
 * @brief Writes the hits not yet reported when the process exits through exit() or
 *        a return from main(); _exit() and fatal signals lose the hits recorded
 *        since the last write.
 */
__attribute__((destructor)) static void chaos_memory_config_report_hits_at_exit(void)
{
    chaos_memory_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its text and hit slot.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its slot
 * (chaos_hits_assign()), so adding one rule does not reset the counts of the
 * others, and a firing through a rule copy taken before the reload still lands.
 * Called by the reload owner only.
 */
static void chaos_memory_config_attach_hits(chaos_memory_config_state_t *next_state)
{
    const chaos_memory_config_state_t *active = chaos_memory_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index],
            g_chaos_memory_config_texts[index],
            sizeof(next_state->text[index])
        );
    }
    if (next_state->rule_count > 0U)
    {
        g_chaos_memory_hit_pool_used = 1;
    }
    chaos_hits_assign(
        g_chaos_memory_hit_pool,
        sizeof(g_chaos_memory_hit_pool) / sizeof(g_chaos_memory_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_memory_config_report_hits
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
chaos_memory_config_report(uint64_t observed_mtime, const chaos_memory_config_state_t *state)
{
    if (observed_mtime == CHAOS_MEMORY_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_MEMORY_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(
            CHAOS_MEMORY_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_memory_config_error
        );
    }
    else
    {
        chaos_status_write(CHAOS_MEMORY_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/** @brief When this process last looked at the rule file (vDSO CLOCK_MONOTONIC, ns). */
static volatile uint64_t g_chaos_memory_last_check_ns = 0U;

/** @brief Throttle for looking at the rule file; 0 looks on every call (unit tests). */
static uint64_t g_chaos_memory_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details Each look is a stat(2), the largest part of a wrapper's cost. After the
 * first load the file is looked at no more than once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms), so a change takes effect within about 1 ms instead of on the next call.
 * The throttle applies whatever the last load found, rules, an empty file or no
 * file; it is bypassed only while the stamp is UNKNOWN (nothing loaded) or
 * RELOADING (so a thread retries once the owner finishes), and when there is no
 * vDSO clock (chaos_clock_now_ns() returns 0). The timestamp is a plain racy
 * store: concurrent threads may both look, which costs one extra stat(2).
 */
static int chaos_memory_config_checked_recently(void)
{
    const uint64_t cached = chaos_memory_atomic_load_u64(&g_chaos_memory_cached_mtime);

    if (cached == CHAOS_MEMORY_MTIME_UNKNOWN || cached == CHAOS_MEMORY_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(
        &g_chaos_memory_last_check_ns, g_chaos_memory_check_interval_ns
    );
}

/**
 * @brief One step of the reload protocol (see the file header): throttle, stat,
 *        claim, read, parse, publish.
 *
 * @details Also flushes hits that have been pending longer than
 * CHAOS_HITS_INTERVAL_MS, so a process that stopped hitting still reports. Not
 * errno-safe on its own; chaos_memory_config_prepare() wraps it.
 *
 * @return Non-zero if the active snapshot (new or kept) holds at least one rule.
 */
static int chaos_memory_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size = 0U;
    uint64_t content = 0U;
    chaos_memory_config_state_t *next_state;

    if (chaos_memory_config_checked_recently())
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }
    /* Hits of an interval that is over are written now, not only at the next hit
     * or at exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_memory_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_memory_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_memory_config_report_hits(NULL);
    }
    observed_mtime = chaos_memory_config_observed_mtime();
    cached_mtime = chaos_memory_atomic_load_u64(&g_chaos_memory_cached_mtime);

    if (observed_mtime == cached_mtime && !g_chaos_memory_config_provisional)
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }
    /* Another thread of this process owns the reload: serve the current snapshot.
     * Without this check the CAS below would succeed as RELOADING -> RELOADING and a
     * second thread would reload into the same inactive snapshot and read buffer.
     * A claim inherited through fork() was released by the child handler; a vfork
     * child must not take over its parent's. */
    if (cached_mtime == CHAOS_MEMORY_MTIME_RELOADING)
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }
    if (!chaos_memory_atomic_cas_u64(
            &g_chaos_memory_cached_mtime, cached_mtime, CHAOS_MEMORY_MTIME_RELOADING
        ))
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }
    g_chaos_memory_config_provisional = 0;

    active_index = g_chaos_memory_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_memory_config_states[next_index];
    chaos_memory_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_MEMORY_MTIME_MISSING)
    {
        const int read_rc = chaos_memory_config_read_file(&config_size, observed_mtime);

        if (read_rc == -2 || read_rc == -3)
        {
            chaos_memory_config_reject_file(
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
            g_chaos_memory_cached_mtime = cached_mtime;
            return chaos_memory_config_active_state()->rule_count != 0U;
        }
        if (read_rc == 0)
        {
            content = chaos_config_content_hash(g_chaos_memory_config_buffer, config_size);
            if (observed_mtime == cached_mtime && content == g_chaos_memory_config_content)
            {
                /* A provisional load read again and found nothing new: the snapshot
                 * stays, with its hit counts and `@first` claims. */
                __sync_synchronize();
                g_chaos_memory_cached_mtime = cached_mtime;
                return chaos_memory_config_active_state()->rule_count != 0U;
            }
        }
        if (config_size > 0U && memchr(g_chaos_memory_config_buffer, '\0', config_size) != NULL)
        {
            /* The parser would stop at the NUL and drop every rule after it unreported. */
            chaos_memory_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
            config_size = 0U;
        }
        if (config_size > 0U &&
            chaos_memory_config_parse_buffer(
                g_chaos_memory_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Rejected: publish an empty snapshot (parse_ok = 0) so nothing matches;
             * the status file names the line. */
            chaos_memory_config_reset_state(next_state, 0);
        }
    }

    g_chaos_memory_config_content = content;
    chaos_memory_config_attach_hits(next_state);
    chaos_memory_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load: freed, and outdated in rule copies
     * still held. Before the publish, while this thread still holds the claim. */
    chaos_hits_release(
        g_chaos_memory_hit_pool,
        sizeof(g_chaos_memory_hit_pool) / sizeof(g_chaos_memory_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_memory_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief chaos_memory_config_refresh() with errno preserved.
 *
 * @details The stat, open and read calls of a refresh belong to the library, not to
 * the caller: an intercepted call that then succeeds must not report the ENOENT of
 * a missing rule file.
 */
int chaos_memory_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_memory_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @brief Selects from the active snapshot (contract in chaos_memory_config.h).
 *
 * @details Lock-free read validated by the snapshot's sequence counter: if a
 * reload rewrote the snapshot during the scan, the copy may be torn and the call
 * reports no match rather than act on it.
 */
int chaos_memory_config_match_loaded(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
)
{
    const chaos_memory_config_state_t *state = chaos_memory_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_memory_config_select_rule(
               state->rules, state->rule_count, effect, operation, mmap_flags, rule
           ) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
}

/**
 * @brief Prepare, then select (contract in chaos_memory_config.h); with no rules
 *        active the scan is skipped.
 */
int chaos_memory_config_match(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
)
{
    if (rule == NULL || !chaos_memory_config_prepare())
    {
        return 0;
    }

    return chaos_memory_config_match_loaded(effect, operation, mmap_flags, rule);
}
