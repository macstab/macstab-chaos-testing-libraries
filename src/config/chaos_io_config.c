/**
 * @file chaos_io_config.c
 * @brief libchaos-io rule file: reading, parsing, lock-free reload, rule selection, and
 *        the status and hits files.
 *
 * @details
 * @par Invariants
 * - Exactly one of the two snapshots in g_chaos_io_config_states is active, named by
 *   g_chaos_io_active_config_index. Only the inactive one is ever written.
 * - g_chaos_io_cached_mtime holds the change stamp of the loaded file or one of the
 *   sentinels MISSING, RELOADING, UNKNOWN. RELOADING doubles as the reload claim: at most
 *   one thread per process reloads, and only that thread touches the read buffer, the
 *   parse scratch and the slot pool's `used` flags.
 * - A file that cannot be used as a whole (invalid line, too many rules, too large,
 *   unreadable, NUL byte) publishes an empty snapshot with `parse_ok == 0`; the previous
 *   rules never stay active by accident. A transient read failure instead keeps the
 *   active snapshot and retries.
 * - The library never faults its own control plane: the rule file is read through the
 *   real functions inside the re-entrancy guard, and every `/tmp/.chaos-*` path is
 *   excluded from matching.
 *
 * @par Reload protocol (no mutex)
 * 1. chaos_io_config_prepare() returns at once when the file was checked less than
 *    CHAOS_CHECK_INTERVAL_NS ago (never while the stamp is UNKNOWN or RELOADING), after
 *    flushing hits that are due.
 * 2. It `stat()`s the rule file. The change stamp hashes mtime (s and ns), size, inode and
 *    device, so a same-tick rewrite, an append and a rename-over (`sed -i`) all change it.
 * 3. Equal stamp, no provisional load and no link re-check due: the snapshot is current.
 * 4. Stamp RELOADING: another thread reloads; use the current snapshot.
 * 5. Otherwise CAS(cached, RELOADING). The winner reloads; a loser uses the current
 *    snapshot.
 * 6. chaos_io_config_reload() fills the inactive snapshot, writes the status file,
 *    assigns and releases hit slots, and chaos_io_config_publish() swaps the index and
 *    stores the new stamp, which releases the claim. On a transient failure, or when a
 *    provisional re-read found identical bytes, it restores the previous stamp instead.
 *
 * @par Provisional loads
 * A file whose mtime is within CHAOS_RACY_WINDOW_MS (20 ms) of now may still be rewritten
 * in the same clock tick without its stamp changing. Such a load is provisional: the file
 * is re-read on every check until its mtime leaves the window, and the content hash
 * (chaos_config_content_hash()) avoids a reparse, and a reset of counts, when nothing
 * changed.
 *
 * @par Links
 * Descriptors resolve to the kernel's name for a file, links resolved; rules are written
 * with the names programs use. Each absolute rule prefix is therefore also resolved with
 * realpath() at load. When any prefix went through a link or did not fully exist, the
 * resolution is repeated every CHAOS_IO_LINKS_RECHECK_MS (1000 ms), because a Kubernetes
 * ConfigMap's `..data` link moves on every update without the rule file changing.
 *
 * @par fork
 * The atfork child handler releases a reload claim and a hits-writer flag held by parent
 * threads that do not exist in the child, resets counts and `@first` claims, picks a new
 * hits-file suffix and forces the PRNG to reseed. vfork children and posix_spawn run no
 * atfork handler; they see the parent's claims as busy and write nothing.
 *
 * @par Memory
 * All state is static (no allocation): two snapshots of CHAOS_IO_MAX_RULES rules each,
 * a 256 KiB + 1 read buffer, and 2 * CHAOS_IO_MAX_RULES hit slots.
 */

#include "chaos_io_config.h"
#include "chaos_clock.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief mtime seconds and nanoseconds of a `struct stat`: `st_mtim` on Linux (POSIX.1-2008),
 *        `st_mtimespec` on macOS and the BSDs (host unit tests).
 */
#if defined(__linux__)
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/**
 * @brief One rule snapshot: rules, their texts and hit slots, link resolutions, metadata.
 *
 * @details Two static instances. Readers use the active one without a lock; the reload
 * owner rewrites the inactive one, with the seqlock odd, and publishes it behind full
 * barriers. A reader that still holds the snapshot two reloads later detects the rewrite
 * through `sequence`.
 *
 * `parse_ok` separates "no rules because there is no file or it holds none" (1) from "no
 * rules because the file was rejected" (0); it selects the status file's `state=`.
 */
typedef struct chaos_io_config_state
{
    /** Seqlock: odd while a reload rewrites the snapshot (chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    chaos_io_rule_t rules[CHAOS_IO_MAX_RULES]; /**< Parsed rules, in file order. */
    size_t rule_count;                         /**< Valid entries in `rules`. */
    int parse_ok;                              /**< 1: file absent or accepted; 0: file rejected. */
    /** Hit slot per rule (chaos_hits.h); shared with the other snapshot for kept rules. */
    chaos_hit_slot_t *hits[CHAOS_IO_MAX_RULES];
    /** Each rule as written (sanitised, at most 200 bytes), the hits file's line text. */
    char text[CHAOS_IO_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
    /** Storage behind chaos_io_rule_t::resolved_prefix. */
    char resolved[CHAOS_IO_MAX_RULES][CHAOS_IO_MAX_RULE_PATH];
    /** Non-zero when a rule path went through a link or did not fully exist, so its
     *  resolution can change while the rule file does not (chaos_io_config_links_due()). */
    int links;
    /** Monotonic ms of the last link resolution (chaos_hits_now_ms()). */
    uint64_t resolved_ms;
} chaos_io_config_state_t;

/**
 * @brief Interval in ms after which link-dependent rule paths are resolved again; a
 *        Kubernetes ConfigMap's `..data` link moves to a new directory on every update
 *        without the rule file changing. Unit tests may predefine it.
 */
#ifndef CHAOS_IO_LINKS_RECHECK_MS
#define CHAOS_IO_LINKS_RECHECK_MS 1000U
#endif

/** @brief The two snapshots; see chaos_io_config_state_t. */
static chaos_io_config_state_t g_chaos_io_config_states[2];

/** @brief Hit-slot pool for both snapshots: 2 * CHAOS_IO_MAX_RULES (chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_io_hit_pool[2U * CHAOS_IO_MAX_RULES];

/**
 * @brief Index (0 or 1) of the active snapshot.
 *
 * @details Written by chaos_io_config_publish() (and chaos_io_config_init()) between full
 * barriers; read by chaos_io_config_active_state() after a full barrier.
 */
static volatile unsigned int g_chaos_io_active_config_index = 0U;

/**
 * @brief Change stamp of the loaded rule file, or a sentinel (CHAOS_IO_MTIME_*).
 *
 * @details Freshness token and, as CHAOS_IO_MTIME_RELOADING, the reload claim; see the
 * reload protocol in the file header.
 */
static volatile uint64_t g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;

/**
 * @brief Non-zero when the loaded file's mtime was too recent to trust its stamp
 *        (chaos_clock_stamp_is_recent()); the next check re-reads the file.
 */
static volatile int g_chaos_io_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded bytes; 0 when none were read. */
static uint64_t g_chaos_io_config_content = 0U;

/**
 * @brief Buffer the reload owner reads the rule file into; CHAOS_IO_MAX_CONFIG_BYTES + 1
 *        bytes for the appended NUL.
 *
 * @details Only the holder of the reload claim (CHAOS_IO_MTIME_RELOADING) touches it, so
 * one process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object in a preloaded library is static TLS,
 * which glibc reserves in every thread and adds to each thread's minimum stack size.
 * Runtimes that create threads with small explicit stacks (the Erlang VM, for one) then
 * fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_io_config_buffer[CHAOS_IO_MAX_CONFIG_BYTES + 1U];

/**
 * @brief Rejection record of the last reload, reported in the status file; also the
 *        per-line copy the parser keeps. Written only by the reload owner.
 */
static chaos_status_error_t g_chaos_io_config_error;

/** @brief Text of each accepted rule of the last parse; copied into the new snapshot. */
static char g_chaos_io_config_texts[CHAOS_IO_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Hits-writer flag: non-zero while one thread writes the hits file. */
static volatile int g_chaos_io_hits_writing = 0;

/** @brief Non-zero once the atfork handler is registered (once per image, not per init). */
static int g_chaos_io_atfork_registered = 0;

static void chaos_io_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_io_hits_pending = 0;

/**
 * @brief Hits counted by this process over all rules (reset in a forked child); drives the
 *        CHAOS_HITS_EAGER threshold. Not atomic: a lost increment only shifts when the
 *        interval starts.
 */
static uint64_t g_chaos_io_hits_total = 0U;

/** @brief Monotonic ms of the last hits-file write. */
static uint64_t g_chaos_io_hits_last_ms = 0U;

/**
 * @brief Pid the counters belong to; set at init and in a forked child. A vfork child has
 *        another pid and therefore writes nothing.
 */
static volatile uint64_t g_chaos_io_hits_pid = 0U;

/** @brief Suffix of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_io_hits_file = 0L;
/** @brief Non-zero once this image created that file (chaos_hits_write_for()). */
static int g_chaos_io_hits_owned = 0;

/** @brief Hits-file scratch, 256 lines of CHAOS_HITS_LINE_MAX; used only by the writer. */
static char g_chaos_io_hits_buffer[CHAOS_IO_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/* --- Internal helpers ------------------------------------------------------------ */

/**
 * @brief Empties @p state (no rules) and sets its `parse_ok`; leaves the seqlock odd.
 *
 * @details The sequence is made odd before the memset and preserved across it, so a reader
 * still copying from this snapshot discards its copy. The caller ends the write with
 * chaos_snapshot_write_end() (chaos_io_config_publish() or chaos_io_config_init()).
 *
 * @param[out] state     Snapshot to empty; NULL is a no-op.
 * @param[in]  parse_ok  1 for "no file / accepted", 0 for "rejected".
 */
static void chaos_io_config_reset_state(chaos_io_config_state_t *state, int parse_ok)
{
    uint64_t sequence;

    if (state == NULL)
    {
        return;
    }

    /* Odd before the clear, kept through it: a reader still holding this snapshot sees
     * that it changed. */
    chaos_snapshot_write_begin(&state->sequence);
    sequence = state->sequence;
    (void)memset(state, 0, sizeof(*state));
    state->sequence = sequence;
    state->parse_ok = parse_ok;
}

/**
 * @brief The active snapshot; never NULL.
 *
 * @details Full barrier, then the index load; pairs with the barrier
 * chaos_io_config_publish() issues before storing the index. Rules read from the result
 * must still be validated with the snapshot's seqlock: the snapshot may be rewritten two
 * reloads later while the caller still uses it.
 */
static const chaos_io_config_state_t *chaos_io_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_io_active_config_index;
    return &g_chaos_io_config_states[index];
}

/**
 * @brief Publishes snapshot @p next_index and releases the reload claim.
 *
 * @details Order:
 * 1. End the snapshot's seqlock write (even sequence).
 * 2. Full barrier: all snapshot writes are visible before the index changes.
 * 3. Store the index.
 * 4. Full barrier: the index is visible before the stamp leaves RELOADING; otherwise
 *    another thread could see the new stamp with the old index and start a redundant
 *    reload.
 * 5. Store @p observed_mtime, which ends the claim.
 *
 * @param[in] next_index      Index (0 or 1) of the filled snapshot.
 * @param[in] observed_mtime  Stamp observed before the claim; the new cached stamp.
 */
static void chaos_io_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_snapshot_write_end(&g_chaos_io_config_states[next_index].sequence);
    __sync_synchronize();
    g_chaos_io_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_io_cached_mtime = observed_mtime;
}

/** @brief Non-zero for rule-file whitespace: space, tab, CR, LF. */
static int chaos_io_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims rule-file whitespace in place.
 *
 * @param[in,out] text  Mutable string; NULL returns NULL.
 * @return Pointer into @p text at the first non-blank byte (the terminating NUL for an
 *         all-blank string); trailing blanks are overwritten with NUL.
 */
static char *chaos_io_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_io_is_blank_char(*text))
    {
        ++text;
    }

    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_io_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';

    return text;
}

/**
 * @brief Cuts @p line at its first `#`; a path containing `#` therefore cannot be written.
 *
 * @param[in,out] line  Mutable line; NULL is a no-op.
 */
static void chaos_io_strip_comment(char *line)
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
 * @brief Maps an operation field (`read`, `write`, `open`, `close`, `fsync`, `fdatasync`,
 *        `pread`, `pwrite`, `truncate`, `allocate`, `unlink`, `rename_from`, `rename_to`;
 *        case-sensitive) to its enum.
 *
 * @param[in] text  Trimmed field; NULL allowed.
 * @return The operation, or CHAOS_IO_OP_INVALID.
 */
static chaos_io_operation_t chaos_io_parse_operation(const char *text)
{
    if (text == NULL)
    {
        return CHAOS_IO_OP_INVALID;
    }
    if (strcmp(text, "read") == 0)
    {
        return CHAOS_IO_OP_READ;
    }
    if (strcmp(text, "write") == 0)
    {
        return CHAOS_IO_OP_WRITE;
    }
    if (strcmp(text, "open") == 0)
    {
        return CHAOS_IO_OP_OPEN;
    }
    if (strcmp(text, "close") == 0)
    {
        return CHAOS_IO_OP_CLOSE;
    }
    if (strcmp(text, "fsync") == 0)
    {
        return CHAOS_IO_OP_FSYNC;
    }
    if (strcmp(text, "fdatasync") == 0)
    {
        return CHAOS_IO_OP_FDATASYNC;
    }
    if (strcmp(text, "pread") == 0)
    {
        return CHAOS_IO_OP_PREAD;
    }
    if (strcmp(text, "pwrite") == 0)
    {
        return CHAOS_IO_OP_PWRITE;
    }
    if (strcmp(text, "truncate") == 0)
    {
        return CHAOS_IO_OP_TRUNCATE;
    }
    if (strcmp(text, "allocate") == 0)
    {
        return CHAOS_IO_OP_ALLOCATE;
    }
    if (strcmp(text, "unlink") == 0)
    {
        return CHAOS_IO_OP_UNLINK;
    }
    if (strcmp(text, "rename_from") == 0)
    {
        return CHAOS_IO_OP_RENAME_FROM;
    }
    if (strcmp(text, "rename_to") == 0)
    {
        return CHAOS_IO_OP_RENAME_TO;
    }
    return CHAOS_IO_OP_INVALID;
}

/**
 * @brief Maps an ERRNO effect name to its value: EIO, ENOSPC, EDQUOT, EROFS, EACCES,
 *        EMFILE, ENFILE, ENOENT.
 *
 * @details A closed list of names, not numbers: errno values differ between
 * architectures, and the list keeps rule files auditable and limited to errors that
 * storage really produces.
 *
 * @param[in] text  Trimmed field; NULL allowed.
 * @return The errno value, or -1 for any other text.
 */
static int chaos_io_parse_errno_name(const char *text)
{
    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "EIO") == 0)
    {
        return EIO;
    }
    if (strcmp(text, "ENOSPC") == 0)
    {
        return ENOSPC;
    }
    if (strcmp(text, "EDQUOT") == 0)
    {
        return EDQUOT;
    }
    if (strcmp(text, "EROFS") == 0)
    {
        return EROFS;
    }
    if (strcmp(text, "EACCES") == 0)
    {
        return EACCES;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "ENOENT") == 0)
    {
        return ENOENT;
    }
    return -1;
}

/** @brief Locale-independent probability parser; see chaos_policy_parse_probability(). */
static int chaos_io_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
}

/**
 * @brief Parses a LATENCY parameter: decimal milliseconds, 0 to 4294967295 (about 49.7
 *        days).
 *
 * @details strtoul() base 10 with the whole token consumed (trailing blanks allowed).
 * strtoul() also accepts leading blanks and a sign; "-N" wraps to a value above the limit
 * on LP64 and is rejected, except "-0", which reads as 0.
 *
 * @param[in]  text        Field; NULL returns -1.
 * @param[out] latency_ms  Receives the value; NULL returns -1.
 * @return 0 on success; -1 on a syntax or range error.
 */
static int chaos_io_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_io_trim(end) != '\0')
    {
        return -1;
    }
    if (value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/**
 * @brief Non-zero when @p effect may be combined with @p operation.
 *
 * @details
 * - ERRNO, LATENCY: every operation.
 * - TORN: `write`, `pwrite` only. A short read is already legal and common (EOF, pipes),
 *   so a "torn read" would add nothing a caller does not already handle.
 * - CORRUPT: `read`, `pread` only. Flipping a bit in the caller's buffer after a write
 *   changes nothing the caller can observe in the file.
 */
static int chaos_io_effect_allowed(chaos_io_operation_t operation, chaos_io_effect_t effect)
{
    if (effect == CHAOS_IO_EFFECT_ERRNO || effect == CHAOS_IO_EFFECT_LATENCY)
    {
        return 1;
    }
    if (effect == CHAOS_IO_EFFECT_TORN)
    {
        return operation == CHAOS_IO_OP_WRITE || operation == CHAOS_IO_OP_PWRITE;
    }
    if (effect == CHAOS_IO_EFFECT_CORRUPT)
    {
        return operation == CHAOS_IO_OP_READ || operation == CHAOS_IO_OP_PREAD;
    }
    return 0;
}

/**
 * @brief Moves a change stamp that equals a sentinel (MISSING, RELOADING, UNKNOWN) off it.
 *
 * @details XOR with 0x9e3779b97f4a7c15 (2^64 / golden ratio) maps each of the three
 * sentinels to a value that is none of them, so the reload protocol never mistakes a real
 * stamp for a sentinel.
 */
static uint64_t chaos_io_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_IO_MTIME_MISSING || value == CHAOS_IO_MTIME_RELOADING ||
        value == CHAOS_IO_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

/**
 * @brief Change stamp of a rule file: FNV-1a-style hash of mtime (s, ns), size, inode and
 *        device, never equal to a sentinel.
 *
 * @details mtime alone misses changes: file systems take it from a coarse tick (a few
 * ms), so two writes in one tick leave it unchanged. The size catches an append, the
 * inode a rewrite through a temporary file and rename(2) (`sed -i`), even within one tick.
 * A same-size in-place rewrite within one tick is still invisible; provisional loads
 * cover that case.
 *
 * @param[in] st  stat result; NULL returns CHAOS_IO_MTIME_MISSING.
 */
static uint64_t chaos_io_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_IO_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_IO_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_IO_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
    value *= UINT64_C(1099511628211);

    return chaos_io_config_normalize_mtime_hash(value);
}

/**
 * @brief `stat()`s the rule file and returns its change stamp; CHAOS_IO_MTIME_MISSING when
 *        stat fails for any reason.
 *
 * @details libchaos-io does not interpose stat; the guard is held anyway so that a libc
 * whose stat calls an interposed symbol cannot re-enter a wrapper. May change errno;
 * chaos_io_config_prepare() restores it.
 */
static uint64_t chaos_io_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_io_enter_internal();
    rc = stat(CHAOS_IO_CONFIG_PATH, &st);
    chaos_io_leave_internal(previous);

    if (rc != 0)
    {
        return CHAOS_IO_MTIME_MISSING;
    }

    return chaos_io_config_hash_mtime(&st);
}

/**
 * @brief Reads the whole rule file into g_chaos_io_config_buffer and NUL-terminates it.
 *
 * @details Uses the real open/read/close inside the re-entrancy guard, so libchaos-io
 * never faults its own rule file. EINTR is retried on open and read; short reads loop
 * until EOF. A file that fills CHAOS_IO_MAX_CONFIG_BYTES is rejected rather than
 * truncated, so a partial rule set is never parsed. After EOF, fstat() must yield
 * @p expected_stamp: a writer that rewrote or appended to the file during the read could
 * leave a half-old, half-new copy, which is then discarded and retried. Sets
 * g_chaos_io_config_provisional from the file's mtime.
 *
 * @param[out] size_out        Bytes read; NULL returns -1.
 * @param[in]  expected_stamp  Stamp that triggered this reload.
 * @return 0 on success; -1 for a transient failure (retry at the next check, e.g. file
 *         gone since the stat, EMFILE, concurrent writer, real functions not resolved);
 *         -2 when the file is CHAOS_IO_MAX_CONFIG_BYTES or larger; -3 when it can never
 *         be read as it is (EACCES or EPERM on open, EISDIR on read).
 */
static int chaos_io_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL || g_chaos_io_real_open == NULL || g_chaos_io_real_read == NULL ||
        g_chaos_io_real_close == NULL)
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    do
    {
        fd = g_chaos_io_real_open(CHAOS_IO_CONFIG_PATH, O_RDONLY);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* A permission error lasts until the file changes (-3, reported); anything else
         * (gone since the stat, out of descriptors, ...) is retried on the next check. */
        const int open_error = errno;

        chaos_io_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = g_chaos_io_real_read(
            fd, g_chaos_io_config_buffer + total, CHAOS_IO_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_IO_MAX_CONFIG_BYTES)
        {
            /* Exactly full: the file may be longer, and a truncated rule set must not be
             * parsed. */
            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer that
     * rewrote or appended to it during the read leaves a different stamp; the copy may be
     * half old, half new, so it is dropped and the next check reloads the finished file. */
    if (fstat(fd, &st) != 0 || chaos_io_config_hash_mtime(&st) != expected_stamp)
    {
        (void)g_chaos_io_real_close(fd);
        chaos_io_leave_internal(previous);
        return -1;
    }
    g_chaos_io_config_provisional =
        chaos_clock_stamp_is_recent((int64_t)CHAOS_IO_STAT_SEC(&st), (long)CHAOS_IO_STAT_NSEC(&st));

    (void)g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);

    g_chaos_io_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Non-zero when the first @p length bytes of @p prefix cover @p path at a component
 *        boundary.
 *
 * @details Covered: @p path equals the prefix, or continues with `/` after it, or the
 * prefix itself ends with `/` (only `/` after normalisation). So `/foo` covers `/foo` and
 * `/foo/bar` but not `/foobar`.
 */
static int chaos_io_prefix_covers(const char *prefix, size_t length, const char *path)
{
    if (strncmp(path, prefix, length) != 0)
    {
        return 0;
    }
    return path[length] == '\0' || (length > 0U && prefix[length - 1U] == '/') ||
           path[length] == '/';
}

/**
 * @brief Non-zero when @p rule's prefix, as written or link-resolved, covers @p path.
 *
 * @details `*` covers every absolute path except memfds (`/memfd:<name>`); pipes, sockets
 * and anonymous inodes resolve to names without a leading `/` and are reached only by a
 * rule that names them. A relative prefix never covers anything, since every path matched
 * is absolute.
 */
static int chaos_io_rule_prefix_matches(const chaos_io_rule_t *rule, const char *path)
{
    if (rule == NULL || path == NULL)
    {
        return 0;
    }
    if (strcmp(rule->path_prefix, "*") == 0)
    {
        /* Files only. Pipes, sockets and anonymous inodes (eventfd, timerfd, ...) resolve
         * to pipe:[N], socket:[N] and anon_inode:[...], memfds to /memfd:<name>: a TORN or
         * CORRUPT meant for files would break their protocols (an 8-byte eventfd write).
         * A rule that names them explicitly still reaches them. */
        return path[0] == '/' && strncmp(path, "/memfd:", 7U) != 0;
    }
    return chaos_io_prefix_covers(rule->path_prefix, rule->path_len, path) ||
           (rule->resolved_prefix != NULL &&
            chaos_io_prefix_covers(rule->resolved_prefix, rule->resolved_len, path));
}

/**
 * @brief Empties @p state as a rejected file (`parse_ok = 0`) and records @p reason with
 *        line 0.
 *
 * @details For conditions that persist until the file changes: too large, unreadable
 * (EACCES, EPERM, a directory) or containing a NUL byte. Unlike a transient read failure,
 * the result is published with the observed stamp, reported as `state=error`, and the
 * file is not re-read until its stamp changes.
 */
static void chaos_io_config_reject_file(chaos_io_config_state_t *state, const char *reason)
{
    chaos_io_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_io_config_error);
    chaos_status_reject(&g_chaos_io_config_error, reason);
}

/**
 * @brief Report hook of every hit slot: writes this process's hits file when due.
 *
 * @details With @p slot non-NULL (a hit): counts it and writes on each of the first
 * CHAOS_HITS_EAGER (64) hits, then at most every CHAOS_HITS_INTERVAL_MS (100 ms); a hit
 * that is not due returns without a system call. With NULL (exit, or a rule-file check
 * after the interval): writes when anything is pending.
 *
 * Only the process the counters belong to writes (a vfork child shares this memory but
 * has another pid). One writer at a time, chosen by a CAS on the writer flag; a hit that
 * finds the writer busy leaves `pending` set, and the writer loops until `pending` stays
 * clear after it releases the flag, so no hit is left unreported. A forked child starts
 * from zero (chaos_io_config_after_fork()).
 *
 * Called from wrappers, possibly in signal handlers; the write uses raw system calls and
 * preserves errno.
 */
static void chaos_io_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_io_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_io_hits_total;
        if (g_chaos_io_hits_pending == 0)
        {
            g_chaos_io_hits_pending = 1;
        }
        /* Past the eager hits and inside the interval: nothing to write, no system call. */
        if (g_chaos_io_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_io_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_io_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but has another pid and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_io_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_io_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_io_config_state_t *)chaos_io_config_active_state();
        while (g_chaos_io_hits_pending != 0)
        {
            g_chaos_io_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_IO_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_io_hits_file,
                &g_chaos_io_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_io_hits_buffer,
                sizeof(g_chaos_io_hits_buffer)
            );
        }
        g_chaos_io_hits_last_ms = now;
        __sync_lock_release(&g_chaos_io_hits_writing);
        __sync_synchronize();
        /* A hit that found the writer busy after the last inner check is written now. */
    } while (g_chaos_io_hits_pending != 0);
}

/**
 * @brief pthread_atfork() child handler: discards state owned by parent threads that do
 *        not exist in the child.
 *
 * @details Releases a reload claim (stamp RELOADING becomes UNKNOWN, forcing a reload) and
 * the hits-writer flag; zeroes hit totals, counts and `@first` claims; adopts the child's
 * pid and a new hits-file suffix; releases slots of a half-built snapshot; and clears the
 * calling thread's PRNG state so it reseeds from its own tid. Without the reseed,
 * pre-forked workers would draw identical sequences and fault in lockstep.
 *
 * vfork children and posix_spawn run no atfork handler: they share the parent's memory,
 * see its claims as busy and write nothing.
 */
static void chaos_io_config_after_fork(void)
{
    if (g_chaos_io_cached_mtime == CHAOS_IO_MTIME_RELOADING)
    {
        g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    }
    g_chaos_io_hits_writing = 0;
    g_chaos_io_hits_pending = 0;
    g_chaos_io_hits_total = 0U;
    g_chaos_io_hits_last_ms = 0U;
    g_chaos_io_hits_pid = (uint64_t)getpid();
    g_chaos_io_hits_file = chaos_hits_file_number(CHAOS_IO_HITS_PREFIX);
    g_chaos_io_hits_owned = 0;
    /* Zero forces a reseed on the next draw, mixing in the child's own tid. */
    g_chaos_io_tls_prng_state = 0U;
    chaos_hits_pool_after_fork(
        g_chaos_io_hit_pool,
        sizeof(g_chaos_io_hit_pool) / sizeof(g_chaos_io_hit_pool[0]),
        chaos_io_config_active_state()->hits,
        chaos_io_config_active_state()->rule_count
    );
}

/**
 * @brief ELF destructor: writes hits not yet reported when the process exits normally
 *        (exit() or return from main). _exit(), a fatal signal or exec skip it.
 */
__attribute__((destructor)) static void chaos_io_config_report_hits_at_exit(void)
{
    chaos_io_config_report_hits(NULL);
}

/**
 * @brief Non-zero when the active snapshot depends on links and its last resolution is
 *        CHAOS_IO_LINKS_RECHECK_MS or older; the next check then reloads.
 */
static int chaos_io_config_links_due(void)
{
    const chaos_io_config_state_t *state = chaos_io_config_active_state();

    return state->links && chaos_hits_now_ms() - state->resolved_ms >= CHAOS_IO_LINKS_RECHECK_MS;
}

/** @brief Compile-time check: a rule path (CHAOS_IO_MAX_RULE_PATH) fits a PATH_MAX buffer. */
typedef char chaos_io_rule_path_fits_path_max[CHAOS_IO_MAX_RULE_PATH <= PATH_MAX ? 1 : -1];

/**
 * @brief realpath() of @p path or, when its tail does not exist yet, of its longest
 *        existing ancestor with the remainder appended and normalised; a rule may name a
 *        file created after the rules were loaded.
 *
 * @details Runs on the reload path only (realpath() is a libc call that touches the
 * file system), never per intercepted call.
 *
 * @param[in]  path   Absolute, normalised rule prefix shorter than PATH_MAX.
 * @param[out] out    PATH_MAX bytes; receives the resolved name.
 * @param[out] whole  1 when @p path resolved completely, 0 when only an ancestor did.
 * @return 1 on success; 0 when no ancestor below `/` resolves or the result would exceed
 *         PATH_MAX.
 */
static int chaos_io_config_resolve_path(const char *path, char *out, int *whole)
{
    char head[PATH_MAX]; /* a rule's path fits: chaos_io_rule_path_fits_path_max */

    *whole = 1;
    if (realpath(path, out) != NULL)
    {
        return 1;
    }
    *whole = 0;
    (void)memcpy(head, path, strlen(path) + 1U);
    for (;;)
    {
        char *slash = strrchr(head, '/');

        if (slash == NULL || slash == head)
        {
            return 0;
        }
        *slash = '\0';
        if (realpath(head, out) != NULL)
        {
            const char *rest = path + (slash - head);

            if (strlen(out) + strlen(rest) >= PATH_MAX)
            {
                return 0;
            }
            (void)strcat(out, rest);
            chaos_io_normalize_path(out);
            return 1;
        }
    }
}

/**
 * @brief Normalises every absolute rule prefix of @p state and records its link-resolved
 *        form where that differs.
 *
 * @details Descriptors resolve through `/proc/self/fd` to the kernel's name, links
 * resolved, while a rule uses the name the program uses: `/lib` where it links to
 * `/usr/lib`, a ConfigMap path under its `..data` link. Prefixes are normalised lexically
 * because the paths they are matched against are. Sets `links` when any prefix went
 * through a link or did not fully exist, which schedules periodic re-resolution.
 * Runs on the reload owner, before publication.
 */
static void chaos_io_config_resolve_rules(chaos_io_config_state_t *state)
{
    char resolved[PATH_MAX];
    size_t index;

    state->links = 0;
    state->resolved_ms = chaos_hits_now_ms();

    for (index = 0U; index < state->rule_count; ++index)
    {
        chaos_io_rule_t *rule = &state->rules[index];
        int whole;
        int found;

        rule->resolved_prefix = NULL;
        rule->resolved_len = 0U;
        if (rule->path_prefix[0] != '/')
        {
            continue;
        }
        /* Matched against normalised paths, so normalised the same way. */
        chaos_io_normalize_path(rule->path_prefix);
        rule->path_len = strlen(rule->path_prefix);
        found = chaos_io_config_resolve_path(rule->path_prefix, resolved, &whole);
        if (!found || !whole || strcmp(resolved, rule->path_prefix) != 0)
        {
            state->links = 1;
        }
        if (found && strcmp(resolved, rule->path_prefix) != 0 &&
            strlen(resolved) < sizeof(state->resolved[index]))
        {
            (void)memcpy(state->resolved[index], resolved, strlen(resolved) + 1U);
            rule->resolved_prefix = state->resolved[index];
            rule->resolved_len = strlen(resolved);
        }
    }
}

/**
 * @brief When a link re-check is due: non-zero if any active rule path now resolves
 *        differently; otherwise restarts the re-check interval and returns 0.
 *
 * @details Lets a due re-check that finds nothing new skip the reparse, so counts and
 * `@first` claims survive. Called by the reload owner only.
 */
static int chaos_io_config_links_moved(void)
{
    chaos_io_config_state_t *state = &g_chaos_io_config_states[g_chaos_io_active_config_index];
    char resolved[PATH_MAX];
    size_t index;

    if (!chaos_io_config_links_due())
    {
        return 0;
    }
    for (index = 0U; index < state->rule_count; ++index)
    {
        const chaos_io_rule_t *rule = &state->rules[index];
        int whole;

        if (rule->path_prefix[0] == '/' &&
            chaos_io_config_resolve_path(rule->path_prefix, resolved, &whole) &&
            strcmp(
                resolved, rule->resolved_prefix != NULL ? rule->resolved_prefix : rule->path_prefix
            ) != 0)
        {
            return 1;
        }
    }
    state->resolved_ms = chaos_hits_now_ms();
    return 0;
}

/**
 * @brief Copies rule texts into @p next_state and assigns each rule its hit slot and the
 *        slot's current generation.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its slot
 * (chaos_hits_assign()), so adding one rule resets no other rule's count, and a hit
 * through a rule copy taken before the reload still lands. When @p next_state is the
 * active snapshot (first init), nothing is inherited.
 */
static void chaos_io_config_attach_hits(chaos_io_config_state_t *next_state)
{
    const chaos_io_config_state_t *active = chaos_io_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index], g_chaos_io_config_texts[index], sizeof(next_state->text[index])
        );
    }
    chaos_hits_assign(
        g_chaos_io_hit_pool,
        sizeof(g_chaos_io_hit_pool) / sizeof(g_chaos_io_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_io_config_report_hits
    );
    for (index = 0U; index < next_state->rule_count; ++index)
    {
        next_state->rules[index].hit = next_state->hits[index];
        next_state->rules[index].hit_generation =
            next_state->hits[index] != NULL ? next_state->hits[index]->generation : 0U;
    }
}

/**
 * @brief Writes `/tmp/.chaos-io.status` for the load that produced @p state, or removes
 *        it when there is no rule file.
 *
 * @details Called by the reload owner before publication, so a reader that sees the new
 * rules' effects finds a status file that already describes them.
 */
static void chaos_io_config_report(uint64_t observed_mtime, const chaos_io_config_state_t *state)
{
    if (observed_mtime == CHAOS_IO_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_IO_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(CHAOS_IO_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_io_config_error);
    }
    else
    {
        chaos_status_write(CHAOS_IO_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/**
 * @brief Builds the inactive snapshot from the rule file and publishes it; the reload
 *        owner's whole job.
 *
 * @details Precondition: the caller holds the claim (stamp CAS'ed to RELOADING). Outcomes:
 * - No file (@p observed_mtime MISSING): empty snapshot, status file removed, published.
 * - Too large or unreadable: empty rejected snapshot, published with the observed stamp.
 * - Transient read failure: nothing published; the claim is released by restoring
 *   @p previous_mtime, so the next check retries with the active rules intact.
 * - Same stamp, same bytes and no link change (a provisional re-read): nothing published;
 *   @p previous_mtime restored, so counts and claims stay.
 * - NUL byte or parse failure: empty rejected snapshot, published.
 * - Otherwise: the parsed rules, link-resolved, with hit slots, published.
 * Before every publication the status file is written and slots of rules that left are
 * released (their copies outdated) while the claim is still held.
 *
 * @param[in] observed_mtime  Stamp observed before the claim; cached on publication.
 * @param[in] previous_mtime  Stamp cached before the claim; restored when nothing is
 *                            published.
 */
static void chaos_io_config_reload(uint64_t observed_mtime, uint64_t previous_mtime)
{
    unsigned int next_index = 1U - g_chaos_io_active_config_index;
    chaos_io_config_state_t *next_state = &g_chaos_io_config_states[next_index];
    size_t file_size = 0U;
    int read_rc;
    uint64_t content = 0U;

    chaos_io_config_reset_state(next_state, 1);

    if (observed_mtime == CHAOS_IO_MTIME_MISSING)
    {
        g_chaos_io_config_content = 0U;
        chaos_io_config_report(CHAOS_IO_MTIME_MISSING, next_state);
        /* Every slot is released (the new snapshot has none) and outdated in rule copies
         * still held; before the publish, while this thread still holds the claim. */
        chaos_hits_release(
            g_chaos_io_hit_pool,
            sizeof(g_chaos_io_hit_pool) / sizeof(g_chaos_io_hit_pool[0]),
            next_state->hits,
            next_state->rule_count
        );
        chaos_io_config_publish(next_index, CHAOS_IO_MTIME_MISSING);
        return;
    }

    read_rc = chaos_io_config_read_file(&file_size, observed_mtime);
    if (read_rc == -2 || read_rc == -3)
    {
        chaos_io_config_reject_file(
            next_state,
            read_rc == -2 ? CHAOS_STATUS_REASON_TOO_LARGE : CHAOS_STATUS_REASON_UNREADABLE
        );
    }
    else if (read_rc != 0)
    {
        /* A failed read says nothing about the rules: keep the active snapshot and release
         * the claim with the previous stamp, so the next check retries instead of running
         * without rules until the file changes again. The barrier orders the release after
         * every write this thread made under the claim. */
        __sync_synchronize();
        g_chaos_io_cached_mtime = previous_mtime;
        return;
    }
    if (read_rc == 0)
    {
        content = chaos_config_content_hash(g_chaos_io_config_buffer, file_size);
        if (observed_mtime == previous_mtime && content == g_chaos_io_config_content &&
            !chaos_io_config_links_moved())
        {
            /* A provisional re-read found nothing new: the snapshot stays, with its counts
             * and claims. */
            __sync_synchronize();
            g_chaos_io_cached_mtime = previous_mtime;
            return;
        }
    }

    if (read_rc == 0 && memchr(g_chaos_io_config_buffer, '\0', file_size) != NULL)
    {
        /* The string parser would stop at the NUL and drop every later rule unreported. */
        chaos_io_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
        read_rc = -4;
    }

    if (read_rc == 0 && chaos_io_config_parse_buffer(
                            g_chaos_io_config_buffer, next_state->rules, &next_state->rule_count
                        ) != 0)
    {
        chaos_io_config_reset_state(next_state, 0);
    }
    chaos_io_config_resolve_rules(next_state);

    g_chaos_io_config_content = content;
    chaos_io_config_attach_hits(next_state);
    chaos_io_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load: freed, and outdated in rule copies still
     * held. Before the publish, while this thread still holds the claim. */
    chaos_hits_release(
        g_chaos_io_hit_pool,
        sizeof(g_chaos_io_hit_pool) / sizeof(g_chaos_io_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_io_config_publish(next_index, observed_mtime);
}

/* --- Public API ------------------------------------------------------------------ */

/** @copydoc chaos_io_config_init */
void chaos_io_config_init(void)
{
    g_chaos_io_hits_pid = (uint64_t)getpid();
    g_chaos_io_hits_file = chaos_hits_file_number(CHAOS_IO_HITS_PREFIX);
    g_chaos_io_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_io_hit_pool, sizeof(g_chaos_io_hit_pool) / sizeof(g_chaos_io_hit_pool[0])
    );
    if (!g_chaos_io_atfork_registered)
    {
        g_chaos_io_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_io_config_after_fork);
    }
    /* Look up the vDSO clock now, not first inside a wrapper a signal handler may
     * re-enter (a lookup in progress makes the clock read 0 and disables the throttle). */
    (void)chaos_clock_now_ns();
    chaos_io_config_reset_state(&g_chaos_io_config_states[0], 1);
    chaos_io_config_reset_state(&g_chaos_io_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_io_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_io_config_states[1].sequence);
    g_chaos_io_active_config_index = 0U;
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
}

/** @brief Monotonic ns (vDSO) of this process's last rule-file check. */
static volatile uint64_t g_chaos_io_last_check_ns = 0U;

/** @brief Throttle interval in ns; unit tests set 0 to check on every call. */
static uint64_t g_chaos_io_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Non-zero when the rule file was checked less than CHAOS_CHECK_INTERVAL_NS ago,
 *        so this call skips the check.
 *
 * @details A check is a stat() system call, the largest part of a wrapper's cost. Once a
 * stamp is cached, including MISSING (no file), checks happen at most once per interval
 * per process. While the stamp is UNKNOWN (before the first load) or RELOADING, every
 * call checks. Without a vDSO clock every call checks.
 */
static int chaos_io_config_checked_recently(void)
{
    const uint64_t cached = chaos_io_atomic_load_u64(&g_chaos_io_cached_mtime);

    if (cached == CHAOS_IO_MTIME_UNKNOWN || cached == CHAOS_IO_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(&g_chaos_io_last_check_ns, g_chaos_io_check_interval_ns);
}

/**
 * @brief Steps 1-5 of the reload protocol (file header); chaos_io_config_prepare() without
 *        the errno protection.
 *
 * @details Returning early on RELOADING loses no update: the owner publishes the new
 * snapshot shortly, and this call is served once more from the previous one.
 *
 * @return Non-zero when the active snapshot holds at least one rule.
 */
static int chaos_io_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;

    if (chaos_io_config_checked_recently())
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    /* Hits of an interval that is over are written now, not only at the next hit or at
     * exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_io_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_io_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_io_config_report_hits(NULL);
    }
    observed_mtime = chaos_io_config_observed_mtime();
    cached_mtime = chaos_io_atomic_load_u64(&g_chaos_io_cached_mtime);

    if (cached_mtime == observed_mtime && !g_chaos_io_config_provisional &&
        !chaos_io_config_links_due())
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    /* Another thread of this process owns the reload; use the current snapshot. A claim
     * inherited through fork() was released by the atfork handler, and a vfork child must
     * not take over its parent's. */
    if (cached_mtime == CHAOS_IO_MTIME_RELOADING)
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    if (chaos_io_atomic_cas_u64(&g_chaos_io_cached_mtime, cached_mtime, CHAOS_IO_MTIME_RELOADING))
    {
        g_chaos_io_config_provisional = 0;
        chaos_io_config_reload(observed_mtime, cached_mtime);
    }
    return chaos_io_config_active_state()->rule_count != 0U;
}

/**
 * @copydoc chaos_io_config_prepare
 *
 * The stat, open and read of a refresh belong to the library, not to the caller: an
 * intercepted call that then succeeds must not carry the ENOENT of a missing rule file.
 */
int chaos_io_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_io_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @copydoc chaos_io_config_parse_line
 *
 * The tokenizer replaces the first three `:` with NUL so `fields[]` point into the line;
 * any later `:` stays in the fourth field, where the parameter parser rejects it.
 */
int chaos_io_config_parse_line(char *line, chaos_io_rule_t *rule)
{
    char *fields[4];
    char *cursor;
    size_t field_index = 0U;
    int parsed_errno;
    double probability;
    unsigned int latency_ms;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_io_strip_comment(line);
    cursor = chaos_io_trim(line);
    if (*cursor == '\0')
    {
        return 0;
    }

    fields[field_index++] = cursor;
    while (*cursor != '\0' && field_index < 4U)
    {
        if (*cursor == ':')
        {
            *cursor = '\0';
            fields[field_index++] = cursor + 1;
        }
        ++cursor;
    }

    if (field_index != 4U)
    {
        return -1;
    }

    fields[0] = chaos_io_trim(fields[0]);
    fields[1] = chaos_io_trim(fields[1]);
    fields[2] = chaos_io_trim(fields[2]);
    fields[3] = chaos_io_trim(fields[3]);

    if (*fields[0] == '\0' || *fields[1] == '\0' || *fields[2] == '\0' || *fields[3] == '\0')
    {
        return -1;
    }
    if (strlen(fields[0]) >= CHAOS_IO_MAX_RULE_PATH)
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    (void)memcpy(rule->path_prefix, fields[0], strlen(fields[0]) + 1U);
    rule->path_len = strlen(rule->path_prefix);
    rule->operation = chaos_io_parse_operation(fields[1]);
    if (rule->operation == CHAOS_IO_OP_INVALID)
    {
        return -1;
    }

    parsed_errno = chaos_io_parse_errno_name(fields[2]);
    if (parsed_errno >= 0)
    {
        rule->effect = CHAOS_IO_EFFECT_ERRNO;
        rule->errnum = parsed_errno;
        if (chaos_io_parse_probability(fields[3], &probability) != 0)
        {
            return -1;
        }
        rule->probability = probability;
    }
    else if (strcmp(fields[2], "LATENCY") == 0)
    {
        rule->effect = CHAOS_IO_EFFECT_LATENCY;
        if (chaos_io_parse_latency(fields[3], &latency_ms) != 0)
        {
            return -1;
        }
        rule->latency_ms = latency_ms;
    }
    else if (strcmp(fields[2], "TORN") == 0)
    {
        rule->effect = CHAOS_IO_EFFECT_TORN;
        if (chaos_io_parse_probability(fields[3], &probability) != 0)
        {
            return -1;
        }
        rule->probability = probability;
    }
    else if (strcmp(fields[2], "CORRUPT") == 0)
    {
        rule->effect = CHAOS_IO_EFFECT_CORRUPT;
        if (chaos_io_parse_probability(fields[3], &probability) != 0)
        {
            return -1;
        }
        rule->probability = probability;
    }
    else
    {
        return -1;
    }

    if (!chaos_io_effect_allowed(rule->operation, rule->effect))
    {
        return -1;
    }

    return 1;
}

/**
 * @brief Non-zero when this build can apply @p rule; always 1 in libchaos-io.
 *
 * @details chaos-init (SECCOMP mode) compiles this file with its own definition: a rule
 * it cannot apply from outside the process rejects the whole file with
 * CHAOS_STATUS_REASON_UNSUPPORTED, so the status file says so instead of the rule
 * silently doing nothing.
 */
#ifndef CHAOS_IO_RULE_SUPPORTED
#define CHAOS_IO_RULE_SUPPORTED(rule) 1
#endif

/**
 * @copydoc chaos_io_config_parse_buffer
 *
 * A final line without LF is parsed like any other. Line numbers count every line,
 * including blank and comment lines, so `line=` in the status file matches an editor.
 */
int chaos_io_config_parse_buffer(char *buffer, chaos_io_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;
    size_t number = 0U;

    chaos_status_clear(&g_chaos_io_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_io_rule_t parsed;
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

        /* The parser edits the line in place; keep it as written for the status report and
         * as the rule's hits-file text. */
        chaos_status_keep_line(&g_chaos_io_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_io_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers on a line that holds no rule. */
                chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_IO_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        if (!CHAOS_IO_RULE_SUPPORTED(&parsed))
        {
            chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_UNSUPPORTED);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_io_config_texts[count],
            g_chaos_io_config_error.text,
            sizeof(g_chaos_io_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_io_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_io_config_last_error(void)
{
    return &g_chaos_io_config_error;
}

/**
 * @copydoc chaos_io_config_select_rule
 *
 * Strict `>` keeps the first of several equally long prefixes, so file order breaks ties.
 * `/` (length 1) ties with `*`; the earlier of the two wins.
 */
int chaos_io_config_select_rule(
    const chaos_io_rule_t *rules,
    size_t rule_count,
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule
)
{
    const chaos_io_rule_t *best = NULL;
    size_t index;

    if (rules == NULL || path == NULL || rule == NULL)
    {
        return 0;
    }

    for (index = 0U; index < rule_count; ++index)
    {
        const chaos_io_rule_t *candidate = &rules[index];
        if (candidate->operation != operation)
        {
            continue;
        }
        if (!chaos_io_rule_prefix_matches(candidate, path))
        {
            continue;
        }
        if (best == NULL || candidate->path_len > best->path_len)
        {
            best = candidate;
        }
    }

    if (best == NULL)
    {
        return 0;
    }

    *rule = *best;
    return 1;
}

/** @copydoc chaos_io_config_match_loaded */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    const chaos_io_config_state_t *state;
    uint64_t sequence;

    if (path == NULL || rule == NULL)
    {
        return 0;
    }

    state = chaos_io_config_active_state();
    sequence = chaos_snapshot_read_begin(&state->sequence);
    if (state->rule_count == 0U)
    {
        return 0;
    }

    /* Seqlock check after the copy: a copy made while a reload rewrote this snapshot is
     * discarded (the call passes through once). */
    return chaos_io_config_select_rule(state->rules, state->rule_count, operation, path, rule) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
}

/**
 * @copydoc chaos_io_config_match_path
 *
 * The exclusion check runs first so a path that can never match (`/proc`, `/dev`, the
 * control files) costs no rule-file check.
 */
int chaos_io_config_match_path(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    if (path == NULL || rule == NULL || chaos_io_is_excluded_path(path))
    {
        return 0;
    }
    if (!chaos_io_config_prepare())
    {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}
