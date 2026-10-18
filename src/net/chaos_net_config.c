/**
 * @file chaos_net_config.c
 * @brief Rule-file loading, parsing and lock-free two-snapshot reload for libchaos-net.
 *
 * @details
 * Lifecycle of the rules of one process:
 *
 *   1. **Snapshots.** Two static chaos_net_config_state_t instances; the active one is
 *      g_chaos_net_config_states[g_chaos_net_active_config_index]. Wrappers read only the
 *      active one; a reload writes only the other one.
 *
 *   2. **Throttled change detection.** chaos_net_config_prepare() looks at the file at
 *      most once per CHAOS_CHECK_INTERVAL_NS (1 ms), timed with the vDSO CLOCK_MONOTONIC
 *      (chaos_clock.h): the stat(2) was the largest part of a wrapper's cost. Without a
 *      vDSO clock, and until the first load completes, every call looks. A look hashes
 *      mtime (s, ns), size, inode and device into one 64-bit stamp, so it fits one CAS
 *      word and also catches a same-tick append (size) and a rename-over rewrite such as
 *      `sed -i` (inode). A rewrite with the same size inside one mtime tick is caught by
 *      the provisional rule: a load whose mtime is under CHAOS_RACY_WINDOW_MS (20 ms) old
 *      is re-read on the next look and replaced only if its content hash changed.
 *
 *   3. **Reload claim.** The thread that sees a new stamp CASes the cached stamp to
 *      CHAOS_NET_MTIME_RELOADING. Exactly one thread wins; everyone else, including a
 *      thread that sees RELOADING, uses the active snapshot and never blocks. The winner
 *      reads the file into the static buffer, parses into the inactive snapshot, writes
 *      the status file, and publishes the index and then the stamp, which releases the
 *      claim.
 *
 *   4. **Torn-copy protection.** Two reloads later a snapshot is reused, possibly while
 *      a preempted reader is still copying a rule out of it. Each snapshot carries a
 *      seqlock sequence (chaos_hits.h): odd while rewritten; a reader validates its copy
 *      and treats a torn one as no match.
 *
 *   5. **All-or-nothing parsing.** One bad line rejects the file: a snapshot with
 *      parse_ok = 0 and no rules is published (so the bad file is not re-parsed on every
 *      look) and the status file names the line. A transient failure (open or read error
 *      other than EACCES/EPERM/EISDIR, or a writer changing the file during the read)
 *      publishes nothing: the claim is released with the old stamp and the next look
 *      retries.
 *
 *   6. **Hit counting.** Each rule gets a slot from a static pool; a rule whose text is
 *      unchanged across a reload keeps its slot and count. Counts go to the hits file on
 *      each of the first CHAOS_HITS_EAGER (64) hits, then at most every
 *      CHAOS_HITS_INTERVAL_MS (100 ms), and at exit.
 *
 * @par Fork and exec:
 *   A pthread_atfork child handler releases a reload claim and the hits-writer flag held
 *   by parent threads, restarts hit counts for the new pid and reseeds the PRNG. vfork()
 *   children and posix_spawn run no handler; they share the parent's memory, see its
 *   claims as busy, and the pid check keeps them from writing its hits file. exec()
 *   discards everything; the new image loads the rule file afresh.
 *
 * @par Invariants:
 *   - g_chaos_net_active_config_index is 0 or 1.
 *   - Only the claim holder writes the inactive snapshot, the read buffer, the error
 *     record and the text table.
 *   - chaos_net_config_publish() ends the snapshot's write sequence, then stores the index,
 *     then the stamp, each behind a full barrier.
 *   - A published snapshot is read-only until it becomes inactive again.
 *
 * @par Test seams:
 *   CHAOS_CONFIG_FILE_OPEN/READ/CLOSE (chaos_status.h), g_chaos_net_check_interval_ns (0
 *   disables the throttle), CHAOS_RACY_WINDOW_MS, CHAOS_NET_RULE_SUPPORTED (chaos-init).
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_config.h"
#include "chaos_clock.h"

#include "chaos_net_endpoint.h"

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*---------------------------------------------------------------------------
 * Platform mtime extraction
 *---------------------------------------------------------------------------*/

/** @brief mtime of a struct stat: st_mtim on Linux, st_mtimespec on macOS/BSD. */
#if defined(__linux__)
#define CHAOS_NET_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_NET_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_NET_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_NET_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/*---------------------------------------------------------------------------
 * Internal state types
 *---------------------------------------------------------------------------*/

/**
 * @brief One complete rule snapshot.
 *
 * @details Two static instances exist (g_chaos_net_config_states[0] and [1]). The reload
 * owner fills the inactive one; wrappers copy rules out of the active one.
 *
 * @par Field semantics:
 *   - `sequence`: seqlock counter, odd while a reload rewrites this snapshot.
 *   - `rules[0..rule_count)`: the parsed rules.
 *   - `parse_ok`: 0 when the file was rejected as a whole (invalid line, too many rules,
 *     NUL byte, too large, unreadable); such a snapshot never matches. 1 otherwise, also
 *     for an empty or missing file.
 *   - `hits[i]`: hit slot of rules[i] (chaos_hits.h).
 *   - `text[i]`: rules[i] as written in the file, reported in the hits file.
 */
typedef struct chaos_net_config_state
{
    /** Odd while a reload rewrites the snapshot (see chaos_snapshot_read_begin()). */
    volatile uint64_t sequence;
    chaos_net_rule_t rules[CHAOS_NET_MAX_RULES]; /**< Parsed rule array. */
    size_t rule_count;                           /**< Number of valid rules in @c rules. */
    int parse_ok;                                /**< Non-zero if parse succeeded. */
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t *hits[CHAOS_NET_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_NET_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_net_config_state_t;

/** @brief The two config snapshots. Index 0 and 1 alternate as active/inactive. */
static chaos_net_config_state_t g_chaos_net_config_states[2];

/** @brief Hit slots of the rules of both snapshots (see chaos_hits_assign()). */
static chaos_hit_slot_t g_chaos_net_hit_pool[2U * CHAOS_NET_MAX_RULES];

/**
 * @brief Non-zero once a snapshot with rules was attached to the pool. Until then a
 * forked child has no slot to reset and skips the pool, touching none of its pages.
 */
static int g_chaos_net_hit_pool_used = 0;

/**
 * @brief Index (0 or 1) of the active snapshot.
 *
 * @details Written only by the reload owner in chaos_net_config_publish() and by
 * chaos_net_config_init(); read by every wrapper behind a full barrier.
 */
static volatile unsigned int g_chaos_net_active_config_index = 0U;

/**
 * @brief Change stamp of the loaded rule file, and the reload claim.
 *
 * @details Holds a chaos_net_config_hash_mtime() stamp or one of three reserved values:
 * CHAOS_NET_MTIME_UNKNOWN before the first load, CHAOS_NET_MTIME_MISSING when no file
 * existed, CHAOS_NET_MTIME_RELOADING while a thread owns a reload. A look compares it
 * with the observed stamp; a reload is claimed by CAS on it.
 */
static volatile uint64_t g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;

/**
 * @brief The loaded file's mtime was within CHAOS_RACY_WINDOW_MS of the clock, so its
 *        stamp cannot be trusted (chaos_clock_stamp_is_recent()): the next look re-reads.
 */
static volatile int g_chaos_net_config_provisional = 0;

/** @brief chaos_config_content_hash() of the loaded file; 0 when none was read. */
static uint64_t g_chaos_net_config_content = 0U;

/**
 * @brief The reload owner's read buffer for the rule file.
 *
 * @details CHAOS_NET_MAX_CONFIG_BYTES + 1 for the NUL that chaos_net_config_read_file()
 * appends. Only the holder of the CHAOS_NET_MTIME_RELOADING claim touches it, so one
 * process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves in
 * every thread of the preloaded process and adds to each thread's minimum stack size.
 * Runtimes that create threads with small explicit stacks (the Erlang VM, for one) then
 * fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_net_config_buffer[CHAOS_NET_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The line the last parse rejected and why, for the status file.
 *
 * @details Written only by the reload owner (or a unit test calling the parser).
 */
static chaos_status_error_t g_chaos_net_config_error;

/** @brief Text of each rule accepted by the last parse; copied into the next snapshot. */
static char g_chaos_net_config_texts[CHAOS_NET_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Hits-writer flag: set (by CAS) while one thread writes the hits file. */
static volatile int g_chaos_net_hits_writing = 0;

/** @brief Whether the pthread_atfork handler is registered (once per image). */
static int g_chaos_net_atfork_registered = 0;

static void chaos_net_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_net_hits_pending = 0;

/** @brief Hits recorded by this process since start or fork; drives the eager phase. */
static uint64_t g_chaos_net_hits_total = 0U;

/** @brief CLOCK_MONOTONIC time of the last hits-file write, in ms. */
static uint64_t g_chaos_net_hits_last_ms = 0U;

/** @brief Pid the counts belong to; set at init and in a fork() child. */
static volatile uint64_t g_chaos_net_hits_pid = 0U;

/** @brief Number `<n>` of this image's hits file (chaos_hits_file_number()). */
static long g_chaos_net_hits_file = 0L;
/** @brief Whether this image created that file (chaos_hits_write_for()). */
static int g_chaos_net_hits_owned = 0;

/** @brief Scratch for formatting the hits file; used only by the hits writer. */
static char g_chaos_net_hits_buffer[CHAOS_NET_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/*---------------------------------------------------------------------------
 * Internal helpers
 *---------------------------------------------------------------------------*/

/**
 * @brief Empties a snapshot and sets its parse_ok, keeping its sequence odd.
 *
 * @details Starts (idempotently) the snapshot's write sequence first, so a reader still
 * copying from it detects the change; chaos_net_config_publish() or chaos_net_config_init()
 * ends the sequence.
 *
 * @param state    Snapshot to reset; NULL is a no-op.
 * @param parse_ok 1 for a usable (possibly empty) snapshot, 0 for a rejected file.
 */
static void chaos_net_config_reset_state(chaos_net_config_state_t *state, int parse_ok)
{
    uint64_t sequence;

    if (state == NULL)
    {
        return;
    }

    /* Odd before the memset: a reader still holding this snapshot sees the rewrite. */
    chaos_snapshot_write_begin(&state->sequence);
    sequence = state->sequence;
    (void)memset(state, 0, sizeof(*state));
    state->sequence = sequence;
    state->parse_ok = parse_ok;
}

/**
 * @brief The active snapshot.
 *
 * @details Full barrier, then the index load: the reader side of chaos_net_config_publish().
 * The returned snapshot can still be rewritten two reloads later; readers that copy rules
 * validate the copy with its sequence.
 *
 * @return The active snapshot; never NULL.
 */
static const chaos_net_config_state_t *chaos_net_config_active_state(void)
{
    unsigned int index;

    /* Pairs with the barrier before the index store in chaos_net_config_publish(). */
    __sync_synchronize();
    index = g_chaos_net_active_config_index;
    return &g_chaos_net_config_states[index];
}

/**
 * @brief Publishes the freshly loaded snapshot and releases the reload claim.
 *
 * @details Order:
 *   1. End the snapshot's write sequence (even again).
 *   2. Full barrier; store the active index. New readers now see the new rules.
 *   3. Full barrier; store the observed stamp in place of CHAOS_NET_MTIME_RELOADING.
 *      The claim is released, and a later change can start the next reload.
 *
 * A reader that sees the new index therefore sees the complete rules, and a thread that
 * sees the released claim also sees the new index.
 *
 * @param next_index     Index (0 or 1) of the snapshot just loaded.
 * @param observed_mtime Stamp observed when this reload was claimed.
 */
static void chaos_net_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_snapshot_write_end(&g_chaos_net_config_states[next_index].sequence);
    /* Release: the snapshot's contents before the index. */
    __sync_synchronize();
    g_chaos_net_active_config_index = next_index;
    /* The index before the claim release. */
    __sync_synchronize();
    g_chaos_net_cached_mtime = observed_mtime;
}

/**
 * @brief Whether @p ch is a blank for rule-line trimming (space, tab, CR, LF).
 */
static int chaos_net_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims leading and trailing blanks in place.
 *
 * @param text  Writable NUL-terminated string; NULL returns NULL.
 * @return Pointer into @p text at the first non-blank, with trailing blanks cut by a
 *         NUL; points at the terminator when @p text is all blanks.
 */
static char *chaos_net_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_net_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_net_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

/**
 * @brief Cuts a rule line at its first `#`.
 *
 * @details No escape exists: a `#` anywhere, including inside a UNIX path, starts a
 * comment.
 *
 * @param line  Writable NUL-terminated line; NULL is a no-op.
 */
static void chaos_net_strip_comment(char *line)
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
 * @brief Maps an operation name to chaos_net_operation_t.
 *
 * @details Exact, case-sensitive names: bind, listen, connect, accept, socket, shutdown,
 * poll, send, recv, close.
 *
 * @param text  Operation token; NULL yields CHAOS_NET_OP_INVALID.
 * @return The operation, or CHAOS_NET_OP_INVALID.
 */
static chaos_net_operation_t chaos_net_parse_operation(const char *text)
{
    if (text == NULL)
    {
        return CHAOS_NET_OP_INVALID;
    }
    if (strcmp(text, "bind") == 0)
    {
        return CHAOS_NET_OP_BIND;
    }
    if (strcmp(text, "listen") == 0)
    {
        return CHAOS_NET_OP_LISTEN;
    }
    if (strcmp(text, "connect") == 0)
    {
        return CHAOS_NET_OP_CONNECT;
    }
    if (strcmp(text, "accept") == 0)
    {
        return CHAOS_NET_OP_ACCEPT;
    }
    if (strcmp(text, "socket") == 0)
    {
        return CHAOS_NET_OP_SOCKET;
    }
    if (strcmp(text, "shutdown") == 0)
    {
        return CHAOS_NET_OP_SHUTDOWN;
    }
    if (strcmp(text, "poll") == 0)
    {
        return CHAOS_NET_OP_POLL;
    }
    if (strcmp(text, "send") == 0)
    {
        return CHAOS_NET_OP_SEND;
    }
    if (strcmp(text, "recv") == 0)
    {
        return CHAOS_NET_OP_RECV;
    }
    if (strcmp(text, "close") == 0)
    {
        return CHAOS_NET_OP_CLOSE;
    }
    return CHAOS_NET_OP_INVALID;
}

/**
 * @brief Maps an errno name to its value, from a fixed whitelist.
 *
 * @details Accepted (exact, case-sensitive): ECONNREFUSED, ETIMEDOUT, ECONNRESET,
 * EHOSTUNREACH, ENETUNREACH, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EPROTONOSUPPORT,
 * EPIPE, ENOTCONN, EOPNOTSUPP, EINVAL, EINTR, ENOMEM, ENOBUFS, EMFILE, ENFILE, EAGAIN.
 * The list is closed on purpose: errnos such as EFAULT or EBADF describe caller bugs no
 * network can cause, and would send applications down paths that test nothing real.
 *
 * @param text  Errno name; NULL yields -1.
 * @return The errno value (> 0), or -1 if not on the list.
 */
static int chaos_net_parse_errno_name(const char *text)
{
    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "ECONNREFUSED") == 0)
    {
        return ECONNREFUSED;
    }
    if (strcmp(text, "ETIMEDOUT") == 0)
    {
        return ETIMEDOUT;
    }
    if (strcmp(text, "ECONNRESET") == 0)
    {
        return ECONNRESET;
    }
    if (strcmp(text, "EHOSTUNREACH") == 0)
    {
        return EHOSTUNREACH;
    }
    if (strcmp(text, "ENETUNREACH") == 0)
    {
        return ENETUNREACH;
    }
    if (strcmp(text, "EADDRINUSE") == 0)
    {
        return EADDRINUSE;
    }
    if (strcmp(text, "EADDRNOTAVAIL") == 0)
    {
        return EADDRNOTAVAIL;
    }
    if (strcmp(text, "EAFNOSUPPORT") == 0)
    {
        return EAFNOSUPPORT;
    }
    if (strcmp(text, "EPROTONOSUPPORT") == 0)
    {
        return EPROTONOSUPPORT;
    }
    if (strcmp(text, "EPIPE") == 0)
    {
        return EPIPE;
    }
    if (strcmp(text, "ENOTCONN") == 0)
    {
        return ENOTCONN;
    }
    if (strcmp(text, "EOPNOTSUPP") == 0)
    {
        return EOPNOTSUPP;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "EINTR") == 0)
    {
        return EINTR;
    }
    if (strcmp(text, "ENOMEM") == 0)
    {
        return ENOMEM;
    }
    if (strcmp(text, "ENOBUFS") == 0)
    {
        return ENOBUFS;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }
    return -1;
}

/**
 * @brief Parses a probability, locale-independently (chaos_policy_parse_probability()).
 *
 * @details Accepts "0", "1", "0." followed by digits, or "1." followed by zeros.
 *
 * @param text         Probability text; must not be NULL.
 * @param probability  Output; must not be NULL.
 * @return 0 on success; -1 when @p text is not a probability.
 */
static int chaos_net_parse_probability(const char *text, double *probability)
{
    return chaos_policy_parse_probability(text, probability);
}

/**
 * @brief Parses an unsigned decimal integer of at most 32 bits (LATENCY ms, TRICKLE bytes).
 *
 * @details strtoul semantics, so leading blanks and a sign are accepted ("-1" wraps to a
 * value above UINT32_MAX and is rejected on 64-bit longs). Trailing blanks are allowed,
 * anything else after the digits is not. The upper bound, 4294967295 ms, is about 49.7
 * days.
 *
 * @param text        Decimal text; NULL yields -1.
 * @param latency_ms  Output; NULL yields -1.
 * @return 0 on success; -1 if no digits, trailing garbage, or above 0xffffffff.
 */
static int chaos_net_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text)
    {
        return -1;
    }
    /* Trailing blanks are skipped here; the caller's text is not modified. */
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
    {
        ++end;
    }
    if (*end != '\0')
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
 * @brief Whether @p effect may be used with @p operation.
 *
 * @details The compatibility matrix:
 *   - LATENCY, ERRNO: every operation.
 *   - CORRUPT, TRICKLE, DUP: RECV only; they act on received bytes.
 *   - TIMEOUT: POLL only; it fakes a wait that found nothing ready.
 *   - RESET: CLOSE only; it turns the close into an abortive one.
 *
 * @param operation  The rule's operation.
 * @param effect     The rule's effect.
 * @return Non-zero if the combination is allowed; 0 otherwise.
 */
static int chaos_net_effect_allowed(chaos_net_operation_t operation, chaos_net_effect_t effect)
{
    if (effect == CHAOS_NET_EFFECT_LATENCY)
    {
        return operation != CHAOS_NET_OP_INVALID;
    }
    if (effect == CHAOS_NET_EFFECT_ERRNO)
    {
        return operation == CHAOS_NET_OP_BIND || operation == CHAOS_NET_OP_LISTEN ||
               operation == CHAOS_NET_OP_CONNECT || operation == CHAOS_NET_OP_ACCEPT ||
               operation == CHAOS_NET_OP_SOCKET || operation == CHAOS_NET_OP_SHUTDOWN ||
               operation == CHAOS_NET_OP_POLL || operation == CHAOS_NET_OP_SEND ||
               operation == CHAOS_NET_OP_RECV || operation == CHAOS_NET_OP_CLOSE;
    }
    if (effect == CHAOS_NET_EFFECT_CORRUPT || effect == CHAOS_NET_EFFECT_TRICKLE ||
        effect == CHAOS_NET_EFFECT_DUP)
    {
        return operation == CHAOS_NET_OP_RECV;
    }
    if (effect == CHAOS_NET_EFFECT_TIMEOUT)
    {
        return operation == CHAOS_NET_OP_POLL;
    }
    if (effect == CHAOS_NET_EFFECT_RESET)
    {
        return operation == CHAOS_NET_OP_CLOSE;
    }
    return 0;
}

/**
 * @brief Whether @p selector may be used with @p operation.
 *
 * @details A socket() call has no address yet, so SOCKET rules accept only selectors
 * that describe a kind of socket:
 *   - `*` (ANY);
 *   - an IP selector with wildcard host and port 0 (`tcp4://\*:0`);
 *   - `unix://\*`.
 * Every other operation accepts any valid selector.
 *
 * @param operation  The rule's operation.
 * @param selector   Parsed selector; NULL yields 0.
 * @return Non-zero if allowed; 0 otherwise.
 */
static int
chaos_net_selector_allowed(chaos_net_operation_t operation, const chaos_net_endpoint_t *selector)
{
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_ANY)
    {
        return 1;
    }
    if (operation == CHAOS_NET_OP_SOCKET)
    {
        /* No address exists at socket() time: only kind-describing wildcards. */
        if ((selector->kind == CHAOS_NET_ENDPOINT_TCP4 ||
             selector->kind == CHAOS_NET_ENDPOINT_TCP6 ||
             selector->kind == CHAOS_NET_ENDPOINT_UDP4 ||
             selector->kind == CHAOS_NET_ENDPOINT_UDP6) &&
            selector->wildcard_host != 0 && selector->port == 0U)
        {
            return 1;
        }
        return selector->kind == CHAOS_NET_ENDPOINT_UNIX && strcmp(selector->value.text, "*") == 0;
    }
    return selector->kind == CHAOS_NET_ENDPOINT_TCP4 || selector->kind == CHAOS_NET_ENDPOINT_TCP6 ||
           selector->kind == CHAOS_NET_ENDPOINT_UDP4 || selector->kind == CHAOS_NET_ENDPOINT_UDP6 ||
           selector->kind == CHAOS_NET_ENDPOINT_UNIX;
}

/**
 * @brief Moves a computed stamp off the three reserved values.
 *
 * @details CHAOS_NET_MTIME_MISSING (0), _RELOADING (2^64 - 2) and _UNKNOWN (2^64 - 1)
 * carry protocol meaning. A stamp equal to one of them is XORed with the golden-ratio
 * constant; for these three inputs the result is never itself reserved.
 *
 * @param value Computed stamp.
 * @return @p value, or the remapped value on a collision.
 */
static uint64_t chaos_net_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_NET_MTIME_MISSING || value == CHAOS_NET_MTIME_RELOADING ||
        value == CHAOS_NET_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

/**
 * @brief 64-bit change stamp of the rule file: FNV-1a-style mix of mtime, size, inode
 *        and device.
 *
 * @details mtime alone is not enough: file systems stamp it from a coarse clock (a few
 * ms), so two writes in one tick leave it unchanged. An append changes the size, and a
 * rewrite through a temporary file and rename(2) (`sed -i`) changes the inode, so both
 * are seen within one tick. A same-size in-place rewrite within one tick is left to the
 * provisional re-read (g_chaos_net_config_provisional).
 *
 * @param st  Result of stat/fstat, or NULL for a missing file.
 * @return The normalised stamp, or CHAOS_NET_MTIME_MISSING when @p st is NULL.
 */
static uint64_t chaos_net_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_NET_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_NET_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_NET_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_size;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_ino;
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)st->st_dev;
    value *= UINT64_C(1099511628211);
    return chaos_net_config_normalize_mtime_hash(value);
}

/**
 * @brief stat(2)s the rule file and returns its change stamp.
 *
 * @details stat goes through libc and so through any other preloaded library that wraps
 * it; the reentrancy guard only keeps libchaos-net's own wrappers out.
 *
 * @return The stamp, or CHAOS_NET_MTIME_MISSING if stat fails for any reason.
 * @par errno: clobbered; chaos_net_config_prepare() restores it.
 */
static uint64_t chaos_net_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = stat(CHAOS_NET_CONFIG_PATH, &st);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_NET_MTIME_MISSING;
    }

    return chaos_net_config_hash_mtime(&st);
}

/**
 * @brief Reads the whole rule file into g_chaos_net_config_buffer and checks that it is
 *        still the file whose stamp triggered the reload.
 *
 * @details Uses CHAOS_CONFIG_FILE_OPEN/READ/CLOSE: raw openat/read/close system calls on
 * Linux, so libchaos-io neither sees nor faults the library's own read. EINTR is retried.
 * After EOF, fstat must reproduce @p expected_stamp; a writer that rewrote or appended
 * meanwhile could have left a half-old, half-new copy. On success the mtime decides
 * whether the load is provisional, and the buffer is NUL-terminated.
 *
 * @param size_out        Output: bytes read; must not be NULL.
 * @param expected_stamp  Stamp observed by the stat that triggered this reload.
 * @return  0 on success;
 *         -1 transient (open/read error, file changed during the read): retry later;
 *         -2 file is CHAOS_NET_MAX_CONFIG_BYTES or larger: reject until it changes;
 *         -3 EACCES/EPERM on open or EISDIR on read: reject until it changes.
 * @par Caller: the reload owner only.
 */
static int chaos_net_config_read_file(size_t *size_out, uint64_t expected_stamp)
{
    struct stat st;
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_net_enter_internal();
    do
    {
        fd = CHAOS_CONFIG_FILE_OPEN(CHAOS_NET_CONFIG_PATH);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
    {
        /* EACCES/EPERM persist until the file changes; anything else (gone since the
         * stat, out of descriptors, ...) is retried on the next look. */
        const int open_error = errno;

        chaos_net_leave_internal(previous);
        return open_error == EACCES || open_error == EPERM ? -3 : -1;
    }

    for (;;)
    {
        ssize_t rc = CHAOS_CONFIG_FILE_READ(
            fd, g_chaos_net_config_buffer + total, CHAOS_NET_MAX_CONFIG_BYTES - total
        );
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        if (rc < 0)
        {
            const int read_error = errno;

            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_net_leave_internal(previous);
            return read_error == EISDIR ? -3 : -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_NET_MAX_CONFIG_BYTES)
        {
            /* Filling the buffer means the file is at or over the limit. */
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_net_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose stamp triggered this reload. A writer that
     * rewrote or appended to it during the read leaves a different stamp; the copy may
     * be half old, half new, so it is discarded and the next look reloads the finished
     * file. */
    if (fstat(fd, &st) != 0 || chaos_net_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_net_leave_internal(previous);
        return -1;
    }
    g_chaos_net_config_provisional = chaos_clock_stamp_is_recent(
        (int64_t)CHAOS_NET_STAT_SEC(&st), (long)CHAOS_NET_STAT_NSEC(&st)
    );

    CHAOS_CONFIG_FILE_CLOSE(fd);
    chaos_net_leave_internal(previous);
    g_chaos_net_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Splits a rule line into selector, operation, effect and value.
 *
 * @details Splits right to left at the last three `:` so that colons inside the selector
 * (`tcp6://[::1]:443`, the port separator) stay in it. Each field is trimmed.
 *
 * @param line            Writable NUL-terminated rule line; modified in place.
 * @param selector_text   Output: selector field.
 * @param operation_text  Output: operation field.
 * @param effect_text     Output: errno name or effect field.
 * @param value_text      Output: value field.
 * @return 1 if three separators were found; 0 otherwise (fields then unset).
 */
static int chaos_net_split_rule_fields(
    char *line, char **selector_text, char **operation_text, char **effect_text, char **value_text
)
{
    char *value_sep;
    char *effect_sep;
    char *operation_sep;

    if (line == NULL || selector_text == NULL || operation_text == NULL || effect_text == NULL ||
        value_text == NULL)
    {
        return 0;
    }

    value_sep = strrchr(line, ':');
    if (value_sep == NULL)
    {
        return 0;
    }
    *value_sep++ = '\0';

    effect_sep = strrchr(line, ':');
    if (effect_sep == NULL)
    {
        return 0;
    }
    *effect_sep++ = '\0';

    operation_sep = strrchr(line, ':');
    if (operation_sep == NULL)
    {
        return 0;
    }
    *operation_sep++ = '\0';

    *selector_text = chaos_net_trim(line);
    *operation_text = chaos_net_trim(operation_sep);
    *effect_text = chaos_net_trim(effect_sep);
    *value_text = chaos_net_trim(value_sep);
    return 1;
}

/*---------------------------------------------------------------------------
 * Public API
 *---------------------------------------------------------------------------*/

/**
 * @copydoc chaos_net_config_init
 *
 * Also records the pid and hits-file number for chaos_net_config_report_hits(). Both
 * snapshots end with an even sequence, index 0 active, stamp CHAOS_NET_MTIME_UNKNOWN.
 */
void chaos_net_config_init(void)
{
    g_chaos_net_hits_pid = (uint64_t)getpid();
    g_chaos_net_hits_file = chaos_hits_file_number(CHAOS_NET_HITS_PREFIX);
    g_chaos_net_hits_owned = 0;
    chaos_hits_pool_reset(
        g_chaos_net_hit_pool, sizeof(g_chaos_net_hit_pool) / sizeof(g_chaos_net_hit_pool[0])
    );
    if (!g_chaos_net_atfork_registered)
    {
        g_chaos_net_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_net_config_after_fork);
    }
    /* Resolve the vDSO clock now, not first inside a wrapper a signal handler re-entered. */
    (void)chaos_clock_now_ns();
    chaos_net_config_reset_state(&g_chaos_net_config_states[0], 1);
    chaos_net_config_reset_state(&g_chaos_net_config_states[1], 1);
    chaos_snapshot_write_end(&g_chaos_net_config_states[0].sequence);
    chaos_snapshot_write_end(&g_chaos_net_config_states[1].sequence);
    g_chaos_net_active_config_index = 0U;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
}

/**
 * @brief Parses one rule line into @p rule (contract in chaos_net_config.h).
 *
 * @details Steps:
 *   1. Cut at `#`; trim; a blank line returns 0.
 *   2. Split into four fields right to left; any empty field is invalid.
 *   3. Parse the selector, then the operation, then check the selector is allowed for it.
 *   4. The third field is an errno name (effect ERRNO) or an effect keyword.
 *   5. Parse the value for that effect; check the effect is allowed for the operation.
 */
int chaos_net_config_parse_line(char *line, chaos_net_rule_t *rule)
{
    char *selector_text;
    char *operation_text;
    char *effect_text;
    char *value_text;
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_net_strip_comment(line);
    line = chaos_net_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_net_split_rule_fields(
            line, &selector_text, &operation_text, &effect_text, &value_text
        ))
    {
        return -1;
    }
    if (*selector_text == '\0' || *operation_text == '\0' || *effect_text == '\0' ||
        *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_net_endpoint_parse_selector(selector_text, &rule->selector))
    {
        return -1;
    }

    rule->operation = chaos_net_parse_operation(operation_text);
    if (rule->operation == CHAOS_NET_OP_INVALID)
    {
        return -1;
    }
    if (!chaos_net_selector_allowed(rule->operation, &rule->selector))
    {
        return -1;
    }

    /* An errno name in the effect field means ERRNO; otherwise it must be an effect
     * keyword. */
    errnum = chaos_net_parse_errno_name(effect_text);
    if (errnum >= 0)
    {
        rule->effect = CHAOS_NET_EFFECT_ERRNO;
        rule->errnum = errnum;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_LATENCY;
        if (chaos_net_parse_latency(value_text, &rule->latency_ms) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "CORRUPT") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_CORRUPT;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "TIMEOUT") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_TIMEOUT;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "TRICKLE") == 0)
    {
        /* The data stays complete and correct; only its chunking is pathological. */
        rule->effect = CHAOS_NET_EFFECT_TRICKLE;
        rule->probability = 1.0;
        if (chaos_net_parse_latency(value_text, &rule->chunk_bytes) != 0 || rule->chunk_bytes == 0U)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "DUP") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_DUP;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "RESET") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_RESET;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    return chaos_net_effect_allowed(rule->operation, rule->effect) ? 1 : -1;
}

/**
 * @brief Whether this build can apply @p rule.
 *
 * @details Always 1 in the library. chaos-init (SECCOMP mode), which applies rules from
 * outside the tracee, defines it before including this file: a rule it cannot apply then
 * rejects the file like an invalid line, with reason UNSUPPORTED, so the status file says
 * so instead of the rule silently doing nothing.
 */
#ifndef CHAOS_NET_RULE_SUPPORTED
#define CHAOS_NET_RULE_SUPPORTED(rule) 1
#endif

/**
 * @brief Parses a whole rule file (contract in chaos_net_config.h).
 *
 * @details Lines are split on '\n' in place. The line as written is kept in the error
 * record before the parser edits it, so a rejection reports the original text, and the
 * same copy becomes the rule's text for the hits file.
 */
int chaos_net_config_parse_buffer(char *buffer, chaos_net_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;
    size_t number = 0U;

    chaos_status_clear(&g_chaos_net_config_error);
    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        chaos_net_rule_t parsed;
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
        chaos_status_keep_line(&g_chaos_net_config_error, ++number, line);
        if (chaos_policy_extract(line, &policy) != 0)
        {
            chaos_status_reject(&g_chaos_net_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        memset(&parsed, 0, sizeof(parsed));
        rc = chaos_net_config_parse_line(line, &parsed);
        if (rc < 0)
        {
            chaos_status_reject(&g_chaos_net_config_error, CHAOS_STATUS_REASON_INVALID);
            *rule_count = 0U;
            return -1;
        }
        if (rc == 0)
        {
            if (!chaos_policy_is_empty(&policy))
            {
                /* Qualifiers on a blank or comment-only line: invalid. */
                chaos_status_reject(&g_chaos_net_config_error, CHAOS_STATUS_REASON_INVALID);
                *rule_count = 0U;
                return -1;
            }
            continue;
        }
        parsed.policy = policy;
        parsed.call_size = CHAOS_POLICY_NO_SIZE;
        if (count >= CHAOS_NET_MAX_RULES)
        {
            chaos_status_reject(&g_chaos_net_config_error, CHAOS_STATUS_REASON_TOO_MANY);
            *rule_count = 0U;
            return -1;
        }
        if (!CHAOS_NET_RULE_SUPPORTED(&parsed))
        {
            chaos_status_reject(&g_chaos_net_config_error, CHAOS_STATUS_REASON_UNSUPPORTED);
            *rule_count = 0U;
            return -1;
        }
        (void)memcpy(
            g_chaos_net_config_texts[count],
            g_chaos_net_config_error.text,
            sizeof(g_chaos_net_config_texts[count])
        );
        rules[count++] = parsed;
    }

    chaos_status_clear(&g_chaos_net_config_error);
    *rule_count = count;
    return 0;
}

const chaos_status_error_t *chaos_net_config_last_error(void)
{
    return &g_chaos_net_config_error;
}

/** @brief Running best match while scanning rules for one or more endpoints. */
typedef struct chaos_net_best_rule
{
    unsigned int rank;
    size_t length;
    int found;
} chaos_net_best_rule_t;

/**
 * @brief Updates @p rule and @p best with any rule for @p operation that matches
 *        @p endpoint more specifically (higher rank, then longer selector) than @p best.
 *
 * @details Strict comparisons: on a full tie the rule found first is kept. That makes the
 * first endpoint passed by chaos_net_config_match_either_loaded() win ties.
 */
static void chaos_net_config_select_better(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule,
    chaos_net_best_rule_t *best
)
{
    size_t index;

    for (index = 0U; index < rule_count; ++index)
    {
        unsigned int rank = 0U;

        if (rules[index].operation != operation)
        {
            continue;
        }
        if (!chaos_net_endpoint_matches(&rules[index].selector, endpoint, &rank))
        {
            continue;
        }
        /* Higher rank wins; equal rank, the longer (more specific) selector text. */
        if (!best->found || rank > best->rank ||
            (rank == best->rank && rules[index].selector.selector_len > best->length))
        {
            *rule = rules[index];
            best->rank = rank;
            best->length = rules[index].selector.selector_len;
            best->found = 1;
        }
    }
}

int chaos_net_config_select_endpoint_rule(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule
)
{
    chaos_net_best_rule_t best = {0U, 0U, 0};

    if (rules == NULL || endpoint == NULL || rule == NULL)
    {
        return 0;
    }
    chaos_net_config_select_better(rules, rule_count, operation, endpoint, rule, &best);
    return best.found;
}

/**
 * @brief Publishes @p state as "file rejected as a whole" with @p reason.
 *
 * @details For conditions that persist until the file changes: too large (TOO_LARGE),
 * not openable (EACCES/EPERM) or a directory (UNREADABLE), a NUL byte (NUL). Unlike a
 * transient read failure, the file is not re-read on every look: the snapshot has no
 * rules, the status file says state=error, and the next change of the stamp retries.
 */
static void chaos_net_config_reject_file(chaos_net_config_state_t *state, const char *reason)
{
    chaos_net_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_net_config_error);
    chaos_status_reject(&g_chaos_net_config_error, reason);
}

/**
 * @brief Writes this process's hit counts after a hit on @p slot (NULL: forced, e.g. at
 *        exit or after an idle interval).
 *
 * @details Rate: the hits file is written on each of the first CHAOS_HITS_EAGER (64) hits,
 * then at most every CHAOS_HITS_INTERVAL_MS (100 ms); a NULL call writes whatever is
 * pending. One writer at a time, chosen by CAS on g_chaos_net_hits_writing, never by
 * waiting (a signal handler may hit while this thread writes): a hit that finds the writer
 * busy leaves `pending` set, and the writer loops until nothing is pending. Only the pid
 * the counts belong to writes, which keeps a vfork() child, sharing this memory, out.
 */
static void chaos_net_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_net_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();

    if (slot != NULL)
    {
        ++g_chaos_net_hits_total;
        if (g_chaos_net_hits_pending == 0)
        {
            g_chaos_net_hits_pending = 1;
        }
        /* Past the eager phase and inside the interval: counters only, no system
         * call. */
        if (g_chaos_net_hits_total > CHAOS_HITS_EAGER &&
            now - g_chaos_net_hits_last_ms < CHAOS_HITS_INTERVAL_MS)
        {
            return;
        }
    }
    else if (g_chaos_net_hits_pending == 0)
    {
        return;
    }
    /* Only the process the counts belong to writes them. A vfork child shares this
     * memory but is another process and runs no atfork handler. */
    if ((uint64_t)getpid() != g_chaos_net_hits_pid)
    {
        return;
    }
    do
    {
        if (!__sync_bool_compare_and_swap(&g_chaos_net_hits_writing, 0, 1))
        {
            return;
        }
        state = (chaos_net_config_state_t *)chaos_net_config_active_state();
        while (g_chaos_net_hits_pending != 0)
        {
            g_chaos_net_hits_pending = 0;
            __sync_synchronize();
            chaos_hits_write_for(
                CHAOS_NET_HITS_PREFIX,
                (long)getpid(),
                &g_chaos_net_hits_file,
                &g_chaos_net_hits_owned,
                state->hits,
                (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
                state->rule_count,
                g_chaos_net_hits_buffer,
                sizeof(g_chaos_net_hits_buffer)
            );
        }
        g_chaos_net_hits_last_ms = now;
        __sync_lock_release(&g_chaos_net_hits_writing);
        __sync_synchronize();
        /* A hit that found the writer busy after the last check is written now. */
    } while (g_chaos_net_hits_pending != 0);
}

/**
 * @brief fork() child handler: drops the state of parent threads that do not exist here.
 *
 * @details Registered with pthread_atfork() by chaos_net_config_init(). A reload claim
 * held at the fork reverts to CHAOS_NET_MTIME_UNKNOWN (the next call reloads), the hits
 * writer flag is cleared, counts restart at zero for the child's pid and hits file, the
 * PRNG is reseeded on its next draw, and @first claims restart (chaos_hits_pool_after_fork()).
 * vfork() children and posix_spawn run no atfork handler: they share the parent's memory,
 * see its claims as busy and write nothing.
 */
static void chaos_net_config_after_fork(void)
{
    if (g_chaos_net_cached_mtime == CHAOS_NET_MTIME_RELOADING)
    {
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
    }
    /* Stores only what changed (CHAOS_STORE_IF_CHANGED): every page written here is
     * a copy-on-write fault in each child. */
    CHAOS_STORE_IF_CHANGED(g_chaos_net_hits_writing, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_net_hits_pending, 0);
    CHAOS_STORE_IF_CHANGED(g_chaos_net_hits_total, 0U);
    CHAOS_STORE_IF_CHANGED(g_chaos_net_hits_last_ms, 0U);
    g_chaos_net_hits_pid = (uint64_t)getpid();
    /* The child's own pid, without probing /tmp: a stale file of an earlier process with
     * this pid is caught by the exclusive first write, which then picks another suffix. */
    g_chaos_net_hits_file = (long)g_chaos_net_hits_pid;
    CHAOS_STORE_IF_CHANGED(g_chaos_net_hits_owned, 0);
    /* The child must not draw the parent's numbers (pre-fork workers would all decide
     * alike): its PRNG reseeds from its own thread id on the next draw. */
    CHAOS_STORE_IF_CHANGED(g_chaos_net_tls_prng_state, 0U);
    if (g_chaos_net_hit_pool_used)
    {
        chaos_hits_pool_after_fork(
            g_chaos_net_hit_pool,
            sizeof(g_chaos_net_hit_pool) / sizeof(g_chaos_net_hit_pool[0]),
            chaos_net_config_active_state()->hits,
            chaos_net_config_active_state()->rule_count
        );
    }
}

/** @brief Writes pending hit counts at normal exit (exit() or return from main). */
__attribute__((destructor)) static void chaos_net_config_report_hits_at_exit(void)
{
    chaos_net_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its text, hit slot and generation.
 *
 * @details A rule whose text equals one in the active snapshot keeps that rule's slot
 * (chaos_hits_assign()), so adding a rule does not reset the others' counts, and a firing
 * through a rule copy taken before the reload still lands on the right counter.
 */
static void chaos_net_config_attach_hits(chaos_net_config_state_t *next_state)
{
    const chaos_net_config_state_t *active = chaos_net_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        (void)memcpy(
            next_state->text[index],
            g_chaos_net_config_texts[index],
            sizeof(next_state->text[index])
        );
    }
    if (next_state->rule_count > 0U)
    {
        g_chaos_net_hit_pool_used = 1;
    }
    chaos_hits_assign(
        g_chaos_net_hit_pool,
        sizeof(g_chaos_net_hit_pool) / sizeof(g_chaos_net_hit_pool[0]),
        active->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) active->text,
        active != next_state ? active->rule_count : 0U,
        next_state->hits,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) next_state->text,
        next_state->rule_count,
        chaos_net_config_report_hits
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
 * @details Called by the reload owner before publishing. No rule file: the status file
 * is removed. Rejected file: state=error with the line and reason. Otherwise state=ok with
 * the rule count.
 */
static void chaos_net_config_report(uint64_t observed_mtime, const chaos_net_config_state_t *state)
{
    if (observed_mtime == CHAOS_NET_MTIME_MISSING)
    {
        chaos_status_remove(CHAOS_NET_STATUS_PATH);
    }
    else if (state->parse_ok == 0)
    {
        chaos_status_write(
            CHAOS_NET_STATUS_PATH, CHAOS_STATUS_ERROR, 0U, &g_chaos_net_config_error
        );
    }
    else
    {
        chaos_status_write(CHAOS_NET_STATUS_PATH, CHAOS_STATUS_OK, state->rule_count, NULL);
    }
}

/** @brief Last look at the rule file (vDSO CLOCK_MONOTONIC, ns); see chaos_clock.h. */
static volatile uint64_t g_chaos_net_last_check_ns = 0U;

/** @brief Look throttle in ns: CHAOS_CHECK_INTERVAL_NS (1 ms); unit tests set 0 (every call). */
static uint64_t g_chaos_net_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details A look is a stat(2), the largest part of a wrapper's cost. After the first
 * completed load the file is looked at no more than once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms) per process, so a change takes effect within 1 ms instead of on the next call.
 * Every call looks while no load has completed (UNKNOWN), while another thread holds the
 * claim (RELOADING), and when no vDSO clock is available (chaos_clock_now_ns() returns 0).
 * The timestamp is a plain word: two threads racing on it at worst both look.
 */
static int chaos_net_config_checked_recently(void)
{
    const uint64_t cached = chaos_net_atomic_load_u64(&g_chaos_net_cached_mtime);

    if (cached == CHAOS_NET_MTIME_UNKNOWN || cached == CHAOS_NET_MTIME_RELOADING)
    {
        return 0;
    }
    return chaos_clock_checked_recently(&g_chaos_net_last_check_ns, g_chaos_net_check_interval_ns);
}

/**
 * @brief Looks for a change of the rule file and reloads it if needed.
 *
 * @details The protocol of the file header, steps 2 to 5. Also flushes hits pending for
 * longer than CHAOS_HITS_INTERVAL_MS, so a process that stopped hitting still reports its
 * last hits before exit. Every early return reports the active snapshot.
 *
 * @return Non-zero if the snapshot active afterwards has at least one rule and parsed.
 * @par errno: clobbered; see chaos_net_config_prepare().
 */
static int chaos_net_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size = 0U;
    uint64_t content = 0U;
    chaos_net_config_state_t *next_state;

    if (chaos_net_config_checked_recently())
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    /* Hits of an interval that is over are written now, not only at the next hit or at
     * exit: a long-running process that stopped hitting reports them too. */
    if (g_chaos_net_hits_pending != 0 &&
        chaos_hits_now_ms() - g_chaos_net_hits_last_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_net_config_report_hits(NULL);
    }
    observed_mtime = chaos_net_config_observed_mtime();
    cached_mtime = chaos_net_atomic_load_u64(&g_chaos_net_cached_mtime);

    if (observed_mtime == cached_mtime && !g_chaos_net_config_provisional)
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    /* Another thread of this process owns the reload: use the active snapshot. Without
     * this check the CAS below would succeed as RELOADING -> RELOADING and two threads
     * would fill the same inactive snapshot and read buffer. A claim inherited through
     * fork() was already released by the atfork handler; a vfork child must not take
     * over its parent's. */
    if (cached_mtime == CHAOS_NET_MTIME_RELOADING)
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    if (!chaos_net_atomic_cas_u64(
            &g_chaos_net_cached_mtime, cached_mtime, CHAOS_NET_MTIME_RELOADING
        ))
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    g_chaos_net_config_provisional = 0;

    active_index = g_chaos_net_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_net_config_states[next_index];
    chaos_net_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_NET_MTIME_MISSING)
    {
        const int read_rc = chaos_net_config_read_file(&config_size, observed_mtime);

        if (read_rc == -2 || read_rc == -3)
        {
            chaos_net_config_reject_file(
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
            g_chaos_net_cached_mtime = cached_mtime;
            return chaos_net_config_active_state()->rule_count != 0U;
        }
        if (read_rc == 0)
        {
            content = chaos_config_content_hash(g_chaos_net_config_buffer, config_size);
            if (observed_mtime == cached_mtime && content == g_chaos_net_config_content)
            {
                /* A provisional load re-read and found the same bytes: the snapshot
                 * stays, with its hit counts and @first claims. */
                __sync_synchronize();
                g_chaos_net_cached_mtime = cached_mtime;
                return chaos_net_config_active_state()->rule_count != 0U;
            }
        }
        if (config_size > 0U && memchr(g_chaos_net_config_buffer, '\0', config_size) != NULL)
        {
            /* The parser would stop at the NUL and drop every later rule unreported. */
            chaos_net_config_reject_file(next_state, CHAOS_STATUS_REASON_NUL);
            config_size = 0U;
        }
        if (config_size > 0U &&
            chaos_net_config_parse_buffer(
                g_chaos_net_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Rejected: parse_ok = 0, so this snapshot never matches. */
            chaos_net_config_reset_state(next_state, 0);
        }
    }

    g_chaos_net_config_content = content;
    chaos_net_config_attach_hits(next_state);
    chaos_net_config_report(observed_mtime, next_state);
    /* Slots of rules that leave with this load are freed and marked outdated for rule
     * copies still held. Done before the publish, while this thread holds the claim. */
    chaos_hits_release(
        g_chaos_net_hit_pool,
        sizeof(g_chaos_net_hit_pool) / sizeof(g_chaos_net_hit_pool[0]),
        next_state->hits,
        next_state->rule_count
    );
    chaos_net_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Reloads the rule file if it changed, preserving errno.
 *
 * @details The stat, openat, read and status-file calls of a reload belong to the
 * library: a wrapped call that then succeeds must not report, say, the ENOENT of a
 * missing rule file.
 */
int chaos_net_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_net_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @copydoc chaos_net_config_match_endpoint_loaded
 *
 * Reads the active snapshot without refreshing it, under its seqlock sequence: a copy
 * made while a reload rewrote the snapshot is discarded and reported as no match.
 */
int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_net_config_select_endpoint_rule(
               state->rules, state->rule_count, operation, endpoint, rule
           ) &&
           chaos_snapshot_read_valid(&state->sequence, sequence);
}

int chaos_net_config_match_final_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);
    chaos_net_best_rule_t best = {0U, 0U, 0};
    size_t index;

    if (state->parse_ok == 0)
    {
        return 0;
    }
    chaos_net_config_select_better(
        state->rules, state->rule_count, operation, endpoint, rule, &best
    );
    if (!best.found)
    {
        return 0;
    }
    /* Final unless a rule could beat it on the other end; ties go to this end. */
    for (index = 0U; index < state->rule_count; ++index)
    {
        const unsigned int rank = chaos_net_endpoint_selector_rank(&state->rules[index].selector);

        if (state->rules[index].operation == operation &&
            (rank > best.rank ||
             (rank == best.rank && state->rules[index].selector.selector_len > best.length)))
        {
            return 0;
        }
    }
    return chaos_snapshot_read_valid(&state->sequence, sequence);
}

int chaos_net_config_match_either_loaded(
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *first,
    const chaos_net_endpoint_t *second,
    chaos_net_rule_t *rule
)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();
    const uint64_t sequence = chaos_snapshot_read_begin(&state->sequence);
    chaos_net_best_rule_t best = {0U, 0U, 0};

    if (state->parse_ok == 0)
    {
        return 0;
    }
    /* One search over both ends: a wildcard rule for the end tried first must not
     * shadow a more specific rule for the other. */
    if (first != NULL)
    {
        chaos_net_config_select_better(
            state->rules, state->rule_count, operation, first, rule, &best
        );
    }
    if (second != NULL)
    {
        chaos_net_config_select_better(
            state->rules, state->rule_count, operation, second, rule, &best
        );
    }
    return best.found && chaos_snapshot_read_valid(&state->sequence, sequence);
}

/**
 * @copydoc chaos_net_config_match_endpoint
 *
 * chaos_net_config_prepare(), then chaos_net_config_match_endpoint_loaded(); returns 0
 * at once for a NULL argument or while no rule is active.
 */
int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    if (endpoint == NULL || rule == NULL || !chaos_net_config_prepare())
    {
        return 0;
    }

    return chaos_net_config_match_endpoint_loaded(operation, endpoint, rule);
}
