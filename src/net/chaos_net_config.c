/**
 * @file chaos_net_config.c
 * @brief Config file loading, parsing, and two-snapshot live-reload implementation.
 *
 * @details
 * This file implements the full config lifecycle for libchaos-net:
 *
 *   1. **Data structures**: `chaos_net_config_state_t` holds one complete parsed
 *      snapshot (up to CHAOS_NET_MAX_RULES rules). Two instances exist
 * (g_chaos_net_config_states[0/1]); at most one is "active" at any time, indexed by
 * g_chaos_net_active_config_index.
 *
 *   2. **Mtime-based change detection**: On every call to chaos_net_config_prepare(),
 *      stat(2) is called on the config file and its mtime is hashed to a uint64_t.
 *      The hash avoids direct st_mtime comparison because st_mtime is a struct
 *      timespec on modern kernels (seconds + nanoseconds) and we need to fit the
 *      comparison in a single atomic word.
 *
 *   3. **Two-snapshot CAS reload protocol**: Reloading proceeds as follows:
 *      a. The calling thread atomically swaps g_chaos_net_cached_mtime from the
 *         observed value to MTIME_RELOADING via CAS. If the CAS fails, another
 *         thread won the race and this thread returns immediately using the
 *         current active snapshot.
 *      b. The winner reads the inactive snapshot index (1 - active_index), fills it
 *         from disk, then publishes by writing active_index then cached_mtime
 *         (two full memory barriers ensure the new rules are visible before
 *         readers switch to the new index).
 *      c. Readers that observe g_chaos_net_cached_mtime == MTIME_RELOADING
 *         simply use the current active snapshot; they never block.
 *
 *   4. **Read buffer**: g_chaos_net_config_buffer is a single static buffer. Only
 *      the thread that wins the CAS reads the file, and callers that observe
 *      MTIME_RELOADING return before the CAS, so two reloads never overlap.
 *
 *   5. **All-or-nothing parsing**: If any line in the config file is invalid,
 *      chaos_net_config_parse_buffer() returns -1 and the new snapshot is marked
 *      parse_ok=0. The snapshot is still published (so future stat results do not
 *      cause repeated failed reloads) but parse_ok=0 causes all match queries to
 *      return 0, passing all syscalls through without injection.
 *
 * @par Platform differences:
 *   - st_mtim (Linux) vs st_mtimespec (macOS / BSDs): handled by CHAOS_NET_STAT_SEC
 *     and CHAOS_NET_STAT_NSEC macros.
 *
 * @par Invariants maintained by this file:
 *   - g_chaos_net_active_config_index is always 0 or 1.
 *   - The inactive snapshot is only modified by the thread holding the reload lock
 *     (the one that successfully CAS'd MTIME_RELOADING).
 *   - chaos_net_config_publish() always issues two full memory barriers (one before
 *     writing active_index, one before writing cached_mtime) so readers observing
 *     either value see a consistent snapshot.
 *   - Rules in the active snapshot are read-only after publication.
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

/** @brief Extracts the seconds component of the file modification time. */
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
 * @brief One complete parsed configuration snapshot.
 *
 * @details Two instances of this struct exist as process-global BSS objects
 * (g_chaos_net_config_states[0] and [1]). The inactive one is populated by the
 * reload thread; the active one is read by interposition hot-paths.
 *
 * @par Field semantics:
 *   - `rules`: array of parsed rules; the first `rule_count` entries are valid.
 *   - `rule_count`: number of valid rules; 0 means no active rules.
 *   - `parse_ok`: non-zero if the last reload succeeded (even if rule_count is 0
 *     because the file was empty or had only comments). Zero means the file was
 *     present but contained at least one invalid line; in this case match queries
 *     return 0 (fail-open).
 */
typedef struct chaos_net_config_state
{
    chaos_net_rule_t rules[CHAOS_NET_MAX_RULES]; /**< Parsed rule array. */
    size_t rule_count;                           /**< Number of valid rules in @c rules. */
    int parse_ok;                                /**< Non-zero if parse succeeded. */
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t hits[CHAOS_NET_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_NET_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_net_config_state_t;

/** @brief The two config snapshots. Index 0 and 1 alternate as active/inactive. */
static chaos_net_config_state_t g_chaos_net_config_states[2];

/**
 * @brief Index (0 or 1) of the currently active snapshot.
 *
 * @details Written by the reload thread under the MTIME_RELOADING lock, then
 * read by all threads. Marked volatile to prevent the compiler from caching the
 * value across the synchronise barrier in chaos_net_config_active_state().
 */
static volatile unsigned int g_chaos_net_active_config_index = 0U;

/**
 * @brief Cached mtime hash of the last successfully observed config file state.
 *
 * @details Serves two purposes:
 *   1. Change detection: compared against the freshly computed mtime hash on
 *      each call to chaos_net_config_prepare().
 *   2. Reload lock: the CAS target. While a reload is in progress, this is set
 *      to CHAOS_NET_MTIME_RELOADING; threads that observe this skip the reload.
 *
 * Initial value is CHAOS_NET_MTIME_UNKNOWN so the first call always performs a
 * full reload attempt.
 */
static volatile uint64_t g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;

/**
 * @brief Buffer the reload thread reads the config file into.
 *
 * @details Sized CHAOS_NET_MAX_CONFIG_BYTES + 1 for the NUL terminator appended by
 * chaos_net_config_read_file().  Only the thread holding the reload marker
 * (CHAOS_NET_MTIME_RELOADING) touches it, so one process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves
 * in every thread of the preloaded process and adds to each thread's minimum stack
 * size.  Runtimes that create threads with small explicit stacks -- the Erlang VM, for
 * one -- then fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_net_config_buffer[CHAOS_NET_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The first line the last parse rejected, reported in the status file.
 *
 * @details Written only by the thread that owns the reload claim.
 */
static chaos_status_error_t g_chaos_net_config_error;

/** @brief Text of each accepted rule of the last parse, copied into the snapshot. */
static char g_chaos_net_config_texts[CHAOS_NET_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Set while a thread writes the hits file. */
static volatile int g_chaos_net_hits_writing = 0;

/** @brief Set once the atfork handler is registered. */
static int g_chaos_net_atfork_registered = 0;

static void chaos_net_config_after_fork(void);

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_net_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_net_hits_total = 0U;

/** @brief CLOCK_MONOTONIC time of the last write, in milliseconds. */
static uint64_t g_chaos_net_hits_last_ms = 0U;

/** @brief Process the counters belong to: set at start and in a forked child. */
static volatile uint64_t g_chaos_net_hits_pid = 0U;

/** @brief Scratch for the hits file; used only by the thread that writes it. */
static char g_chaos_net_hits_buffer[CHAOS_NET_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/*---------------------------------------------------------------------------
 * Internal helpers
 *---------------------------------------------------------------------------*/

/**
 * @brief Zeroes a config snapshot and sets its parse_ok flag.
 *
 * @details Used to reset the inactive snapshot before a reload, and to mark it
 * as parse_ok=0 if the reload fails.
 *
 * @param state    Snapshot to reset. No-op if NULL.
 * @param parse_ok Initial parse_ok value; 1 = clean state, 0 = failed state.
 */
static void chaos_net_config_reset_state(chaos_net_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * @brief Returns a pointer to the currently active config snapshot.
 *
 * @details Issues a full memory barrier before reading g_chaos_net_active_config_index
 * to ensure the snapshot contents written by the reload thread are visible before
 * the index value is read. This is the reader side of the two-barrier publish
 * protocol; the writer side is chaos_net_config_publish().
 *
 * @return Pointer to the active snapshot; never NULL.
 */
static const chaos_net_config_state_t *chaos_net_config_active_state(void)
{
    unsigned int index;

    /* Acquire: ensure we see all rule data written before the index was published. */
    __sync_synchronize();
    index = g_chaos_net_active_config_index;
    return &g_chaos_net_config_states[index];
}

/**
 * @brief Publishes a newly-loaded snapshot by updating the active index and cached mtime.
 *
 * @details The publication order is critical for correctness:
 *   1. Full memory barrier.
 *   2. Write g_chaos_net_active_config_index = next_index. After this, new readers
 *      will begin reading from the new snapshot.
 *   3. Full memory barrier.
 *   4. Write g_chaos_net_cached_mtime = observed_mtime. This releases the reload
 *      lock (replaces MTIME_RELOADING) and allows the next mtime change to trigger
 *      a new reload.
 *
 * The two-barrier ordering ensures that a reader cannot see the new active_index
 * before the snapshot's rule data is fully written, and cannot see the new
 * cached_mtime before active_index has been updated.
 *
 * @param next_index     Index (0 or 1) of the snapshot just loaded.
 * @param observed_mtime Mtime hash observed at the start of this reload cycle.
 */
static void chaos_net_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    /* Release: ensure all rule writes are visible before the index is updated. */
    __sync_synchronize();
    g_chaos_net_active_config_index = next_index;
    /* Second barrier: ensure the index update is visible before we release the lock. */
    __sync_synchronize();
    g_chaos_net_cached_mtime = observed_mtime;
}

/**
 * @brief Returns non-zero if @p ch is a whitespace character for config trimming.
 */
static int chaos_net_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims leading and trailing whitespace from a string in place.
 *
 * @details Returns a pointer into the original buffer (no copy). The trailing NUL
 * is written over the last trailing whitespace character. The returned pointer
 * is always within the original buffer.
 *
 * @param text  Writable NUL-terminated string. May be NULL (returns NULL).
 * @return Pointer to the first non-whitespace character, with trailing whitespace
 *         removed. Points to the NUL terminator if the input is all whitespace.
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
 * @brief Terminates a config line at the first '#' character.
 *
 * @details Modifies @p line in place. The '#' and everything after it is discarded.
 * No-op if @p line is NULL or contains no '#'.
 *
 * @param line  Writable NUL-terminated config line.
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
 * @brief Maps an operation name string to its chaos_net_operation_t value.
 *
 * @details Performs exact string comparisons against the set of recognised
 * operation names. Case-sensitive. Returns CHAOS_NET_OP_INVALID for any
 * unrecognised input including NULL.
 *
 * @param text  Operation name token (e.g., "bind", "recv"). Must not be NULL.
 * @return The corresponding operation enum value, or CHAOS_NET_OP_INVALID.
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
 * @brief Maps an errno name string to its numeric value.
 *
 * @details The whitelist of supported errno names covers the common network error
 * codes that are meaningful to inject. An exhaustive mapping is avoided to
 * prevent config files from injecting errnos that would cause undefined or
 * dangerous behaviour in common application error-handling paths (e.g., EFAULT).
 *
 * @param text  Errno macro name (e.g., "ECONNREFUSED"). Must not be NULL.
 * @return The numeric errno value (>= 0) if recognised; -1 if NULL or unrecognised.
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
 * @brief Parses a probability value from a NUL-terminated string.
 *
 * @details Calls strtod with strict validation: the entire string (after trimming
 * trailing whitespace) must have been consumed, and the resulting value must be in
 * [0.0, 1.0]. Probability 0.0 means "never fire"; probability 1.0 means "always fire".
 *
 * @param text         Decimal probability string. Must not be NULL.
 * @param probability  Output: receives the parsed value. Must not be NULL.
 * @return 0 on success; -1 if parsing fails or the value is out of [0.0, 1.0].
 */
static int chaos_net_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_net_trim(end) != '\0')
    {
        return -1;
    }
    if (value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

/**
 * @brief Parses a latency value (milliseconds) from a NUL-terminated string.
 *
 * @details Requires a pure decimal integer with no trailing non-numeric characters.
 * The value is capped at UINT_MAX (0xffffffff) which is approximately 49 days —
 * sufficient for any practical test scenario.
 *
 * @param text        Decimal millisecond string. Must not be NULL.
 * @param latency_ms  Output: receives the parsed value. Must not be NULL.
 * @return 0 on success; -1 if parsing fails or the value exceeds UINT_MAX.
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
    if (end == text || *chaos_net_trim(end) != '\0')
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
 * @brief Validates that an effect is applicable to an operation.
 *
 * @details Enforces the effect/operation compatibility matrix:
 *   - LATENCY:  valid for all operations.
 *   - ERRNO:    valid for all operations that can meaningfully return -1 with errno.
 *   - CORRUPT:  only valid for RECV (buffer content is only available post-call for recv).
 *   - TIMEOUT:  only valid for POLL (polls are the only multiplexed-wait operations).
 *
 * @param operation  The operation parsed from the rule.
 * @param effect     The effect parsed from the rule.
 * @return Non-zero if the combination is permitted; 0 otherwise.
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
 * @brief Validates that an endpoint selector is acceptable for a given operation.
 *
 * @details Socket-creation operations (CHAOS_NET_OP_SOCKET) can only be matched
 * by selectors that describe a socket type without a specific address — the socket
 * does not have one yet. Permitted selectors for socket are:
 *   - The ANY wildcard.
 *   - An IP selector with wildcard_host=1 and port=0 (e.g., `tcp4://\*:0`).
 *   - A UNIX selector with path `"*"`.
 * All other operations accept any non-INVALID endpoint kind.
 *
 * @param operation  The operation to validate against.
 * @param selector   Parsed endpoint selector. Must not be NULL.
 * @return Non-zero if the selector is valid for the operation; 0 otherwise.
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
        /* socket() rules may only use wildcard selectors because no address exists yet. */
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
 * @brief Adjusts a computed mtime hash to avoid collisions with sentinel values.
 *
 * @details The sentinel values MTIME_MISSING, MTIME_RELOADING, and MTIME_UNKNOWN are
 * reserved for internal state signalling. If the FNV-based mtime hash accidentally
 * produces one of these values, XOR it with a constant to obtain a different
 * non-reserved value. The XOR constant is chosen to be non-zero and to differ
 * sufficiently from all three sentinels (the probability of a double collision
 * is negligible for a 64-bit hash).
 *
 * @param value Raw computed mtime hash.
 * @return The value itself, or a remapped non-reserved value if it collides.
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
 * @brief Computes a 64-bit change stamp of the file: mtime, size, inode and device.
 *
 * @details Uses a modified FNV-like mixing over the mtime seconds, mtime
 * nanoseconds, size, inode and device. The mtime alone is not enough: file
 * systems stamp it from a coarse clock (a few milliseconds), so two writes in
 * one tick leave it unchanged. An append changes the size, and a rewrite through
 * a temporary file and rename(2) (`sed -i`) changes the inode, so both are seen
 * even within one tick. The result is adjusted to avoid sentinel collisions. If
 * @p st is NULL (file does not exist), returns CHAOS_NET_MTIME_MISSING.
 *
 * @param st  Pointer to a populated struct stat, or NULL for a missing file.
 * @return 64-bit mtime hash.
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
 * @brief Stats the config file and returns its mtime hash.
 *
 * @details Sets the reentrancy guard around the stat(2) call to prevent
 * libchaos-io (if also loaded) from intercepting it, and to ensure libchaos-net
 * does not re-enter its own config load path.
 *
 * @return The mtime hash, or CHAOS_NET_MTIME_MISSING if stat fails.
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
 * @brief Reads the entire config file into the shared read buffer.
 *
 * @details Opens the file and reads in a loop (to handle short reads on slow
 * devices or large files). The loop terminates when:
 *   - read() returns 0 (EOF): success.
 *   - read() returns < 0: I/O error; returns -1.
 *   - total bytes reaches CHAOS_NET_MAX_CONFIG_BYTES: file too large; returns -1.
 *
 * On success, writes a NUL terminator at g_chaos_net_config_buffer[total] so
 * the buffer is safe to use as a C string.
 *
 * The reentrancy guard is held for the duration of open/read/close to prevent
 * libchaos-net from intercepting these calls.
 *
 * @param size_out  Output: number of bytes read. Must not be NULL.
 * @return 0 on success; -1 on I/O error or file-too-large.
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
        /* No permission lasts until the file changes; anything else (gone since
         * the stat, out of descriptors, ...) is retried on the next check. */
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
            /* File is at or over the size limit; treat as an error. */
            CHAOS_CONFIG_FILE_CLOSE(fd);
            chaos_net_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer
     * that rewrote or appended to it while it was read leaves a different stamp; the
     * copy may then be half old, half new, so it is not used and the next call
     * reloads the finished file. */
    if (fstat(fd, &st) != 0 || chaos_net_config_hash_mtime(&st) != expected_stamp)
    {
        CHAOS_CONFIG_FILE_CLOSE(fd);
        chaos_net_leave_internal(previous);
        return -1;
    }

    CHAOS_CONFIG_FILE_CLOSE(fd);
    chaos_net_leave_internal(previous);
    g_chaos_net_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Splits a config rule line into its four colon-delimited fields.
 *
 * @details Parsing proceeds right-to-left using strrchr(':') to split off the
 * value, effect, and operation fields in order. The remaining prefix is the
 * selector. This right-to-left strategy is necessary because IPv6 addresses in
 * the selector (e.g., `tcp6://[::1]:443`) contain colons that must not be
 * treated as field separators.
 *
 * Each field pointer is trimmed of leading/trailing whitespace before being
 * returned so that callers receive clean tokens without embedded spaces.
 *
 * @param line            Writable NUL-terminated rule line (modified in place).
 * @param selector_text   Output: pointer to the selector field token.
 * @param operation_text  Output: pointer to the operation field token.
 * @param effect_text     Output: pointer to the effect/errno field token.
 * @param value_text      Output: pointer to the value (probability or ms) token.
 * @return 1 if exactly three ':' separators were found; 0 otherwise.
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
 * Implementation notes: resets both snapshots to a `parse_ok == 1` empty
 * state, sets the active index to 0, and seeds the cached mtime to
 * `CHAOS_NET_MTIME_UNKNOWN` so the next `prepare()` call unconditionally
 * reads the on-disk config.  Not thread-safe; intended for the library
 * constructor or test-fixture setup only.
 */
void chaos_net_config_init(void)
{
    g_chaos_net_hits_pid = (uint64_t)getpid();
    if (!g_chaos_net_atfork_registered)
    {
        g_chaos_net_atfork_registered = 1;
        (void)pthread_atfork(NULL, NULL, chaos_net_config_after_fork);
    }
    /* Find the vDSO clock now, not first inside a wrapper a signal handler may re-enter. */
    (void)chaos_clock_now_ns();
    chaos_net_config_reset_state(&g_chaos_net_config_states[0], 1);
    chaos_net_config_reset_state(&g_chaos_net_config_states[1], 1);
    g_chaos_net_active_config_index = 0U;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
}

/**
 * @brief Parses one config line into a rule.
 *
 * @details See chaos_net_config.h for the full contract. The parsing sequence:
 *   1. Strip '#' comment suffix.
 *   2. Trim whitespace; skip blank lines (return 0).
 *   3. Split into four fields (right-to-left on ':').
 *   4. Reject if any field is empty after trimming.
 *   5. Parse selector, operation, effect/errno, and value.
 *   6. Validate effect/operation compatibility.
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

    /* Determine effect by trying errno name first (it also identifies ERRNO effect),
     * then falling through to the named effects. */
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
        /* The data is complete and correct; only the chunking is pathological. */
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
 * @details Every rule the parser accepts, in the library. chaos-init, which applies
 * rules from outside the process through seccomp, defines it before including this
 * file: a rule it cannot apply rejects the file like an invalid line would, with
 * its own reason, so the status file says so instead of the rule doing nothing.
 */
#ifndef CHAOS_NET_RULE_SUPPORTED
#define CHAOS_NET_RULE_SUPPORTED(rule) 1
#endif

/**
 * @brief Parses all lines from the config read buffer into a rules array.
 *
 * @details Splits on '\n' by writing NUL terminators in place. Stops and returns
 * -1 on the first invalid line (all-or-nothing policy). The rule count is written
 * only if the entire buffer is parsed successfully.
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
                /* Qualifiers without a rule. */
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

/**
 * @brief Finds the best-matching rule in a rule array for an (operation, endpoint) pair.
 *
 * @details Iterates the entire array to find the highest-rank match. On a tie
 * in rank, the rule with the longer selector_len text wins. This tie-breaking
 * convention ensures that `tcp4://127.0.0.1:8080` beats `tcp4://\*:8080` which
 * beats `*`, giving operators intuitive precedence without requiring an
 * explicit rule ordering in the config file.
 */
int chaos_net_config_select_endpoint_rule(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule
)
{
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

    if (rules == NULL || endpoint == NULL || rule == NULL)
    {
        return 0;
    }

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
        /* Prefer higher rank; break ties by longer selector text (more specific). */
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
static void chaos_net_config_reject_file(chaos_net_config_state_t *state, const char *reason)
{
    chaos_net_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_net_config_error);
    chaos_status_reject(&g_chaos_net_config_error, reason);
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
        /* Past the eager hits and inside the interval there is nothing to write:
         * no system call, no shared write beyond the counters. */
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
            chaos_hits_write(
                CHAOS_NET_HITS_PREFIX,
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
        /* A hit that found the writer busy after its last check is written now. */
    } while (g_chaos_net_hits_pending != 0);
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
static void chaos_net_config_after_fork(void)
{
    size_t which;

    if (g_chaos_net_cached_mtime == CHAOS_NET_MTIME_RELOADING)
    {
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
    }
    g_chaos_net_hits_writing = 0;
    g_chaos_net_hits_pending = 0;
    g_chaos_net_hits_total = 0U;
    g_chaos_net_hits_last_ms = 0U;
    g_chaos_net_hits_pid = (uint64_t)getpid();
    /* The child must not draw the parent's numbers (pre-fork workers would all
     * decide alike): its PRNG reseeds from its own thread id on the next draw. */
    g_chaos_net_tls_prng_state = 0U;
    for (which = 0U; which < 2U; ++which)
    {
        chaos_hit_slot_t *slots = g_chaos_net_config_states[which].hits;
        size_t index;

        for (index = 0U; index < CHAOS_NET_MAX_RULES; ++index)
        {
            slots[index].count = 0U;
            slots[index].claimed = 0U;
            if (slots[index].state == 3U)
            {
                slots[index].state = 1U;
            }
        }
    }
}

/** @brief Reports the hits not yet written when the process exits normally. */
__attribute__((destructor)) static void chaos_net_config_report_hits_at_exit(void)
{
    chaos_net_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its counter and text.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its count,
 * so adding one rule does not reset the counts of the others.
 */
static void chaos_net_config_attach_hits(chaos_net_config_state_t *next_state)
{
    const chaos_net_config_state_t *active = chaos_net_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        size_t previous;

        (void)memcpy(
            next_state->text[index],
            g_chaos_net_config_texts[index],
            sizeof(next_state->text[index])
        );
        next_state->hits[index].report = chaos_net_config_report_hits;
        for (previous = 0U; active != next_state && previous < active->rule_count; ++previous)
        {
            if (strcmp(active->text[previous], next_state->text[index]) == 0)
            {
                next_state->hits[index].count = active->hits[previous].count;
                next_state->hits[index].claimed = active->hits[previous].claimed;
                /* A REGRESS decision in progress belongs to the old slot. */
                next_state->hits[index].state =
                    active->hits[previous].state == 3U ? 1U : active->hits[previous].state;
                break;
            }
        }
        next_state->rules[index].hit = &next_state->hits[index];
    }
}

/**
 * @brief Writes the status file for a load that produced @p state.
 *
 * @details Called by the reload owner before the snapshot is published. No rule
 * file means nothing to report, so the status file is removed.
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

/** @brief When this process last looked at the rule file (vDSO CLOCK_MONOTONIC, ns). */
static volatile uint64_t g_chaos_net_last_check_ns = 0U;

/** @brief Throttle for looking at the rule file; 0 looks on every call (unit tests). */
static uint64_t g_chaos_net_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details Each look is a stat() system call, the largest part of a wrapper's cost.
 * Once rules are loaded the file is looked at no more than every
 * CHAOS_CHECK_INTERVAL_NS, so a change takes effect within that time instead of on
 * the very next call. The first load, and any call while no rules are loaded yet,
 * always looks.
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
 * @brief Checks for config changes and reloads if necessary.
 *
 * @details Implements the two-snapshot CAS reload protocol. If the CAS to claim
 * the reload lock fails (another thread is already reloading), returns immediately
 * with the current snapshot's rule count, so the caller can still proceed with
 * fault injection using whatever rules are currently active.
 *
 * On reload failure (file missing, read error, parse error), the inactive snapshot
 * is marked parse_ok=0 and published, so repeated reload attempts on a corrupt file
 * do not repeatedly re-read it until the mtime changes.
 */
static int chaos_net_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_net_config_state_t *next_state;

    if (chaos_net_config_checked_recently())
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    observed_mtime = chaos_net_config_observed_mtime();
    cached_mtime = chaos_net_atomic_load_u64(&g_chaos_net_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    /* Another thread owns this reload cycle; use the current snapshot.  Without this
     * check the CAS below succeeds as RELOADING -> RELOADING and a second thread would
     * reload into the same inactive snapshot and read buffer concurrently. */
    /* Another thread of this process owns the reload; a claim inherited through
     * fork() was released by the atfork handler, and a vfork child must not take
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
             * release the claim with the previous stamp, so the next call retries
             * instead of running with no rules until the file changes again. */
            __sync_synchronize();
            g_chaos_net_cached_mtime = cached_mtime;
            return chaos_net_config_active_state()->rule_count != 0U;
        }
        if (config_size > 0U &&
            chaos_net_config_parse_buffer(
                g_chaos_net_config_buffer, next_state->rules, &next_state->rule_count
            ) != 0)
        {
            /* Parse failed: mark the snapshot invalid so match queries return 0. */
            chaos_net_config_reset_state(next_state, 0);
        }
    }

    chaos_net_config_attach_hits(next_state);
    chaos_net_config_report(observed_mtime, next_state);
    chaos_net_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Refreshes the snapshot if the config file changed, leaving errno untouched.
 *
 * @details The stat, open and read calls of a refresh belong to the library, not to
 * the caller: an interposed call that then succeeds must not report the errno of a
 * missing config file.
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
 * Implementation notes: reads the active snapshot pointer with an acquire
 * barrier (provided by `chaos_net_config_active_state`) and rejects any
 * snapshot whose `parse_ok == 0`, so a corrupt config is treated as
 * passthrough rather than producing arbitrary matches.  Does not refresh
 * the snapshot — callers in the hot path call `prepare()` once and then
 * dispatch through this function for each socket operation.
 */
int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_net_config_select_endpoint_rule(
        state->rules, state->rule_count, operation, endpoint, rule
    );
}

/**
 * @copydoc chaos_net_config_match_endpoint
 *
 * Implementation notes: convenience wrapper that combines
 * `chaos_net_config_prepare()` and `chaos_net_config_match_endpoint_loaded()`
 * into one call.  Used by socket wrappers that have no external trigger to
 * decide when to refresh; returns 0 immediately when the snapshot is empty
 * so the caller never inspects an unprepared rule set.
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
