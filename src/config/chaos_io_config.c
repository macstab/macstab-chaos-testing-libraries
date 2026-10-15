/**
 * @file chaos_io_config.c
 * @brief Config parsing, snapshot management, and rule-selection implementation.
 *
 * @details
 * This file implements the data pipeline from on-disk config text to
 * in-memory `chaos_io_rule_t` arrays, and the lock-free protocol that keeps
 * that array consistent across concurrent wrapper calls.
 *
 * **Invariants maintained by this file:**
 * - Exactly one of the two `g_chaos_io_config_states` entries is the
 *   "active" snapshot at any moment, identified by
 *   `g_chaos_io_active_config_index`.
 * - `g_chaos_io_cached_mtime` is either a hashed mtime value, or one of
 *   the three sentinels (`MISSING`, `RELOADING`, `UNKNOWN`).
 * - At most one thread at a time performs a config reload; others serve from
 *   the current active snapshot.
 * - A parse failure results in an empty (`rule_count == 0`, `parse_ok == 0`)
 *   snapshot being published rather than leaving the previous (possibly stale)
 *   rules active.
 * - The config file itself is never injected with faults: all reads of
 *   `CHAOS_IO_CONFIG_PATH` go through the real libc open/read/close via the
 *   internal guard.
 *
 * **Config reload protocol (CAS-based, no mutex):**
 * 1. `chaos_io_config_prepare()` stats the config file and hashes its mtime.
 * 2. If the hash equals `g_chaos_io_cached_mtime`, the snapshot is current.
 * 3. If `g_chaos_io_cached_mtime == CHAOS_IO_MTIME_RELOADING`, another thread
 *    is already reloading; fall back to the current snapshot immediately.
 * 4. Otherwise, attempt CAS(`cached_mtime`, `observed`, `RELOADING`).  The
 *    winner calls `chaos_io_config_reload()`; losers fall back to step 3.
 * 5. `chaos_io_config_reload()` writes the inactive snapshot, then calls
 *    `chaos_io_config_publish()` which swaps the active index (full barrier)
 *    and stores the new mtime (second full barrier), clearing `RELOADING`.
 *
 * **Config read buffer:**
 * `g_chaos_io_config_buffer` is a single static buffer.  The CAS on the
 * reload marker, together with the early return for callers that observe
 * `RELOADING`, ensures only one thread reloads at a time, so no per-thread
 * copy, dynamic allocation or mutex is needed.
 *
 * **Module ownership:** config/
 * **Stability:** internal
 */

/*
 * Config parsing, validation, snapshot management, and rule selection.
 *
 * The wrapper layer depends on this module for current rule state, but the
 * implementation stays intentionally small: two snapshots, in-place parsing, and
 * deterministic longest-prefix matching.
 */

#include "chaos_io_config.h"
#include "chaos_clock.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Platform-portable accessor for the mtime seconds field of `struct stat`.
 *
 * @details POSIX defines `st_mtim` (a `struct timespec`) on Linux; macOS and
 * other BSDs expose `st_mtimespec` instead.  These macros hide that
 * difference so the rest of the file uses a single spelling.
 */
#if defined(__linux__)
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

/**
 * @brief One parsed config snapshot: a fixed-size rule array plus metadata.
 *
 * @details Two instances (`g_chaos_io_config_states[0/1]`) are statically
 * allocated.  The "active" one is always readable by any thread; the
 * "inactive" one is overwritten by the reloading thread before being
 * published.  There is no reader lock because readers only ever read the
 * active snapshot, and publication is protected by a full memory barrier.
 *
 * `parse_ok` distinguishes "empty because the config was absent or blank"
 * (ok == 1) from "empty because parsing failed" (ok == 0).  Currently both
 * result in passthrough behavior, but the flag is preserved for future
 * observability hooks.
 */
typedef struct chaos_io_config_state
{
    chaos_io_rule_t rules[CHAOS_IO_MAX_RULES]; /**< Parsed rule array for this snapshot. */
    size_t rule_count;                         /**< Number of valid entries in `rules`. */
    int parse_ok; /**< Non-zero if the last parse succeeded (including empty file). */
    /** Hit counters, one per rule (see chaos_hits.h). */
    chaos_hit_slot_t hits[CHAOS_IO_MAX_RULES];
    /** Each rule as written in the file, reported with its count. */
    char text[CHAOS_IO_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_io_config_state_t;

/** @brief The two interchangeable config snapshots. */
static chaos_io_config_state_t g_chaos_io_config_states[2];

/**
 * @brief Index (0 or 1) of the currently active config snapshot.
 *
 * @details Written only by `chaos_io_config_publish()` under full barriers.
 * Read by `chaos_io_config_active_state()` under a load barrier.
 */
static volatile unsigned int g_chaos_io_active_config_index = 0U;

/**
 * @brief Hashed mtime of the most recently loaded config file, or a sentinel.
 *
 * @details Acts as both a freshness token and the CAS lock for reload
 * ownership.  See the reload protocol in the file-level documentation.
 */
static volatile uint64_t g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;

/**
 * @brief Process id of the thread that last claimed the reload marker.
 *
 * @details Written before every claim attempt. A forked child inherits a
 * CHAOS_IO_MTIME_RELOADING marker whose claiming thread does not exist in the
 * child; the pid recorded here differs from the child's, which is how the child
 * recognises an orphaned claim and takes the reload over instead of serving a
 * stale snapshot forever.
 */
static volatile uint64_t g_chaos_io_reload_pid = 0U;

/**
 * @brief Buffer the reload thread reads the config file into.
 *
 * @details Sized CHAOS_IO_MAX_CONFIG_BYTES + 1 for the NUL terminator appended by
 * chaos_io_config_read_file().  Only the thread holding the reload marker
 * (CHAOS_IO_MTIME_RELOADING) touches it, so one process-wide buffer suffices.
 *
 * Deliberately not `__thread`: a 256 KiB TLS object is static TLS, which glibc reserves
 * in every thread of the preloaded process and adds to each thread's minimum stack
 * size.  Runtimes that create threads with small explicit stacks -- the Erlang VM, for
 * one -- then fail pthread_create() with EINVAL and cannot start at all.
 */
static char g_chaos_io_config_buffer[CHAOS_IO_MAX_CONFIG_BYTES + 1U];

/**
 * @brief The first line the last parse rejected, reported in the status file.
 *
 * @details Written only by the thread that owns the reload claim.
 */
static chaos_status_error_t g_chaos_io_config_error;

/** @brief Text of each accepted rule of the last parse, copied into the snapshot. */
static char g_chaos_io_config_texts[CHAOS_IO_MAX_RULES][CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief Pid of the process whose thread writes the hits file; 0 when nobody does. */
static volatile uint64_t g_chaos_io_hits_writing = 0U;

/** @brief Set by every hit, cleared by the write that reports it. */
static volatile int g_chaos_io_hits_pending = 0;

/** @brief Hits recorded by this process (reset in a forked child). */
static uint64_t g_chaos_io_hits_total = 0U;

/** @brief CLOCK_MONOTONIC time of the last write, in milliseconds. */
static uint64_t g_chaos_io_hits_last_ms = 0U;

/** @brief Process the counters belong to; differs in a forked child. */
static uint64_t g_chaos_io_hits_pid = 0U;

/** @brief Scratch for the hits file; used only by the thread that writes it. */
static char g_chaos_io_hits_buffer[CHAOS_IO_MAX_RULES * CHAOS_HITS_LINE_MAX + 1U];

/* --- Internal helpers ------------------------------------------------------------ */

/**
 * @brief Resets a config state to an empty passthrough configuration.
 *
 * @param[out] state     State to zero and mark.  Ignored if NULL.
 * @param[in]  parse_ok  Value to store in `state->parse_ok` after zeroing.
 */
static void chaos_io_config_reset_state(chaos_io_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * @brief Returns the current active config state with an acquire barrier.
 *
 * @details The full barrier before the index load ensures that the snapshot
 * data written by `chaos_io_config_publish()` (which used a release barrier)
 * is visible to this thread before it reads any rule.
 *
 * @return Pointer to the currently active `chaos_io_config_state_t`.
 *         Always non-NULL; points into the static `g_chaos_io_config_states` array.
 */
static const chaos_io_config_state_t *chaos_io_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_io_active_config_index;
    return &g_chaos_io_config_states[index];
}

/**
 * @brief Atomically publishes a freshly loaded config snapshot.
 *
 * @details The two-barrier sequence is intentional:
 * 1. The first `__sync_synchronize()` ensures that all writes to the
 *    `next_index` snapshot (rule array, rule_count, parse_ok) are visible
 *    to other threads before the active index changes.
 * 2. After storing the new index, the second barrier ensures the index is
 *    globally visible before `g_chaos_io_cached_mtime` is updated.
 *    Clearing `RELOADING` from `cached_mtime` before the new index is
 *    visible would let another thread enter a redundant reload cycle.
 *
 * @param[in] next_index     Index (0 or 1) of the freshly populated snapshot.
 * @param[in] observed_mtime The mtime hash that was current when the reload
 *                           began; stored as the new cached value.
 */
static void chaos_io_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_io_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_io_cached_mtime = observed_mtime;
}

/**
 * @brief Returns non-zero when the character is insignificant config whitespace.
 */
static int chaos_io_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trims leading and trailing config whitespace in place.
 *
 * @details Returns a pointer into the original buffer (no copy is made).
 * The trailing whitespace is removed by writing a NUL byte.
 *
 * @param[in,out] text  Mutable string to trim.  May be NULL.
 * @return Pointer to the first non-whitespace character, or the original
 *         pointer if the string is all whitespace (points at `'\0'`).
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
 * @brief Removes an inline comment from a config line.
 *
 * @details A `#` character and everything after it is treated as a comment.
 * The comment start is replaced with NUL so subsequent parsing sees only the
 * payload.
 *
 * @param[in,out] line  Mutable line buffer.  No-op if NULL.
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
 * @brief Parses the string name of an operation into its enum value.
 *
 * @param[in] text  Null-terminated operation token from the config.  May be NULL.
 * @return The matching `chaos_io_operation_t`, or `CHAOS_IO_OP_INVALID`.
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
 * @brief Parses an errno name from the config into the corresponding integer value.
 *
 * @details Only the errno names that represent realistic storage-layer errors
 * are accepted.  Accepting arbitrary errno numbers by value would make
 * configs fragile across kernels and harder to audit.
 *
 * @param[in] text  Null-terminated errno name token.  May be NULL.
 * @return The integer errno value, or -1 if `text` is not a recognized name.
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

/**
 * @brief Parses a floating-point probability value from the config.
 *
 * @details Uses `strtod()` and validates that the entire token was consumed
 * and the value lies in [0.0, 1.0].  Any trailing non-whitespace after the
 * number is treated as an error to prevent silently ignoring garbage.
 *
 * @param[in]  text         Null-terminated probability token.  May be NULL.
 * @param[out] probability  Receives the parsed value.  Must not be NULL.
 * @return 0 on success; -1 on parse or range error.
 */
static int chaos_io_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_io_trim(end) != '\0')
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
 * @brief Parses a millisecond latency value from the config.
 *
 * @details Uses `strtoul()` with base 10 and validates that the entire token
 * was consumed and the value fits in a `uint32_t` (cap at 0xffffffff ms ≈ 49
 * days, which is clearly an operator error if exceeded).
 *
 * @param[in]  text        Null-terminated latency token.  May be NULL.
 * @param[out] latency_ms  Receives the parsed value.  Must not be NULL.
 * @return 0 on success; -1 on parse or range error.
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
 * @brief Returns non-zero when the effect is semantically valid for the selected operation.
 *
 * @details Enforces the effect/operation compatibility matrix at parse time so
 * wrappers never receive a rule with an inapplicable effect:
 * - `ERRNO` and `LATENCY` are universal.
 * - `TORN` requires a write-class operation (`write` or `pwrite`), because a
 *   "torn read" has no well-defined meaning: the kernel already handles short
 *   reads transparently and the library would have to truncate the count,
 *   which is indistinguishable from a genuine EOF.
 * - `CORRUPT` requires a read-class operation (`read` or `pread`), because
 *   post-write buffer corruption would not be observable by the target.
 *
 * @param[in] operation  Parsed operation value.
 * @param[in] effect     Parsed effect value.
 * @return Non-zero if the combination is permitted; zero otherwise.
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
 * @brief Normalizes a hashed mtime so it never collides with a sentinel value.
 *
 * @details The three sentinels (`MISSING`, `RELOADING`, `UNKNOWN`) have
 * specific numeric values that the CAS protocol relies on.  A genuine mtime
 * hash that happens to produce one of those values is remapped by XOR-ing
 * with the golden-ratio constant, which has good diffusion properties and
 * makes a second collision extremely unlikely.
 *
 * @param[in] value  Raw mtime hash.
 * @return The same value if it is not a sentinel; otherwise a remapped value.
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
 * @brief Hashes mtime, size, inode and device from a `struct stat` into a 64-bit cache key.
 *
 * @details Uses a FNV-inspired multiply-XOR chain over the mtime seconds and
 * nanoseconds, the size, the inode and the device, so that a change in any of
 * them produces a different hash.
 *
 * The mtime alone is not enough: file systems stamp it from a coarse clock (a
 * few milliseconds), so two writes in one tick leave it unchanged. Mixing in the
 * size catches an append, and the inode catches a rewrite through a temporary
 * file and rename(2) (`sed -i`), even within one tick.
 *
 * @param[in] st  Pointer to the stat result.  NULL is treated as
 *                "file not present" and returns `CHAOS_IO_MTIME_MISSING`.
 * @return A 64-bit change stamp, guaranteed not to equal any sentinel.
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
 * @brief Stats the config file and returns its hashed mtime.
 *
 * @details Calls `stat()` inside the internal guard to prevent the stat from
 * being intercepted by this library's own `open`/`read` wrappers (stat does
 * not go through those, but the guard is set for consistency and in case
 * future code in the stat path calls an interposed symbol).
 *
 * @return The hashed mtime of `CHAOS_IO_CONFIG_PATH`, or
 *         `CHAOS_IO_MTIME_MISSING` if the file does not exist or stat fails.
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
 * @brief Reads the config file into the shared read buffer.
 *
 * @details Opens and reads `CHAOS_IO_CONFIG_PATH` via the real libc symbols
 * (not through the interposed wrappers) using the internal guard.  Rejects
 * files that exactly fill `CHAOS_IO_MAX_CONFIG_BYTES` because that signals
 * a truncated read; operators must keep configs within the budget.
 *
 * A NUL terminator is appended after the last byte read so callers can treat
 * `g_chaos_io_config_buffer` as a C string.
 *
 * Short reads from `g_chaos_io_real_read` are handled correctly by the inner
 * loop: reading continues until 0 (EOF) or an error.  The EINTR case is not
 * handled explicitly; a library that is being preloaded into an interactive
 * application may receive signals, but a short read just triggers another
 * iteration.
 *
 * @param[out] size_out  Receives the number of bytes read.  Must not be NULL.
 * @return 0 on success; -1 if any step failed or the buffer limit was hit.
 *
 * @pre `g_chaos_io_real_open`, `g_chaos_io_real_read`, and
 *      `g_chaos_io_real_close` are all non-NULL.
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
        chaos_io_leave_internal(previous);
        return -1;
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
            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_IO_MAX_CONFIG_BYTES)
        {
            /* File exactly fills or exceeds the budget – treat as truncation error. */
            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return -2;
        }
    }

    /* The file must still be the one whose change triggered this reload. A writer
     * that rewrote or appended to it while it was read leaves a different stamp; the
     * copy may then be half old, half new, so it is not used and the next call
     * reloads the finished file. */
    if (fstat(fd, &st) != 0 || chaos_io_config_hash_mtime(&st) != expected_stamp)
    {
        (void)g_chaos_io_real_close(fd);
        chaos_io_leave_internal(previous);
        return -1;
    }

    (void)g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);

    g_chaos_io_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/**
 * @brief Returns non-zero when a rule prefix matches the supplied path.
 *
 * @details The wildcard `"*"` matches any non-NULL path unconditionally.
 * For explicit prefixes the match is boundary-aware:
 * - An exact match (`path == prefix`) succeeds.
 * - A prefix that ends with `/` succeeds when the path has the same
 *   leading bytes (the trailing `/` itself counts as the boundary).
 * - Otherwise a `/` must appear in the path at exactly `path_len` to
 *   prevent `/foo` from matching `/foobar`.
 *
 * @param[in] rule  The rule whose `path_prefix` and `path_len` are used.
 * @param[in] path  The resolved path to test.
 * @return Non-zero when the rule matches the path.
 */
static int chaos_io_rule_prefix_matches(const chaos_io_rule_t *rule, const char *path)
{
    if (rule == NULL || path == NULL)
    {
        return 0;
    }
    if (strcmp(rule->path_prefix, "*") == 0)
    {
        return 1;
    }
    if (strncmp(path, rule->path_prefix, rule->path_len) != 0)
    {
        return 0;
    }
    if (path[rule->path_len] == '\0')
    {
        return 1;
    }
    if (rule->path_len > 0U && rule->path_prefix[rule->path_len - 1U] == '/')
    {
        return 1;
    }
    return path[rule->path_len] == '/';
}

/**
 * @brief Marks @p state as the result of a rule file at or over the size limit.
 *
 * @details Unlike a read that failed or met a concurrent writer, the size is a
 * lasting property of this version of the file: it is reported like a rejected
 * file (no rules, state=error) and not re-read until the file changes.
 */
static void chaos_io_config_reject_file(chaos_io_config_state_t *state)
{
    chaos_io_config_reset_state(state, 0);
    chaos_status_clear(&g_chaos_io_config_error);
    chaos_status_reject(&g_chaos_io_config_error, CHAOS_STATUS_REASON_TOO_LARGE);
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
static void chaos_io_config_report_hits(chaos_hit_slot_t *slot)
{
    chaos_io_config_state_t *state;
    const uint64_t now = chaos_hits_now_ms();
    uint64_t owner;
    uint64_t pid;

    if (slot != NULL)
    {
        ++g_chaos_io_hits_total;
        if (g_chaos_io_hits_pending == 0)
        {
            g_chaos_io_hits_pending = 1;
        }
        /* Past the eager hits and inside the interval there is nothing to write:
         * no system call, no shared write beyond the counters. */
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
    pid = (uint64_t)getpid();
    if (slot == NULL && g_chaos_io_hits_pid != pid)
    {
        return;
    }
    /* The writer flag holds the writer's pid. One inherited from a parent that forked
     * while writing belongs to no thread of this process and is released. */
    owner = g_chaos_io_hits_writing;
    if (owner != 0U && owner != pid)
    {
        (void)__sync_bool_compare_and_swap(&g_chaos_io_hits_writing, owner, 0U);
    }
    if (!__sync_bool_compare_and_swap(&g_chaos_io_hits_writing, 0U, pid))
    {
        return;
    }
    state = (chaos_io_config_state_t *)chaos_io_config_active_state();
    if (slot != NULL && g_chaos_io_hits_pid != pid)
    {
        size_t index;

        for (index = 0U; index < state->rule_count; ++index)
        {
            state->hits[index].count = 0U;
        }
        slot->count = 1U;
        g_chaos_io_hits_pid = pid;
        g_chaos_io_hits_total = 1U;
    }
    while (g_chaos_io_hits_pending != 0)
    {
        g_chaos_io_hits_pending = 0;
        __sync_synchronize();
        chaos_hits_write(
            CHAOS_IO_HITS_PREFIX,
            state->hits,
            (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) state->text,
            state->rule_count,
            g_chaos_io_hits_buffer,
            sizeof(g_chaos_io_hits_buffer)
        );
    }
    g_chaos_io_hits_last_ms = now;
    __sync_lock_release(&g_chaos_io_hits_writing);
}

/** @brief Reports the hits not yet written when the process exits normally. */
__attribute__((destructor)) static void chaos_io_config_report_hits_at_exit(void)
{
    chaos_io_config_report_hits(NULL);
}

/**
 * @brief Gives each rule of a freshly parsed snapshot its counter and text.
 *
 * @details A rule whose text is unchanged from the active snapshot keeps its count,
 * so adding one rule does not reset the counts of the others.
 */
static void chaos_io_config_attach_hits(chaos_io_config_state_t *next_state)
{
    const chaos_io_config_state_t *active = chaos_io_config_active_state();
    size_t index;

    for (index = 0U; index < next_state->rule_count; ++index)
    {
        size_t previous;

        (void)memcpy(
            next_state->text[index], g_chaos_io_config_texts[index], sizeof(next_state->text[index])
        );
        next_state->hits[index].report = chaos_io_config_report_hits;
        for (previous = 0U; active != next_state && previous < active->rule_count; ++previous)
        {
            if (strcmp(active->text[previous], next_state->text[index]) == 0)
            {
                next_state->hits[index].count = active->hits[previous].count;
                next_state->hits[index].claimed = active->hits[previous].claimed;
                next_state->hits[index].claimed_pid = active->hits[previous].claimed_pid;
                next_state->hits[index].state = active->hits[previous].state;
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
 * @brief Reloads the inactive config state from disk, or clears it on passthrough conditions.
 *
 * @details Called exclusively by the thread that won the CAS race in
 * `chaos_io_config_prepare()`.  The "inactive" slot is always the one whose
 * index differs from `g_chaos_io_active_config_index`.
 *
 * When `observed_mtime == CHAOS_IO_MTIME_MISSING` the config file is absent;
 * publish an empty snapshot immediately without attempting a read.
 *
 * When the file read or parse fails, `parse_ok` is set to 0 in the new
 * snapshot to distinguish from a legitimately empty config.
 *
 * @param[in] observed_mtime  The hashed mtime observed just before the CAS.
 *                            Stored as the new cached mtime after publication.
 */
static void chaos_io_config_reload(uint64_t observed_mtime, uint64_t previous_mtime)
{
    unsigned int next_index = 1U - g_chaos_io_active_config_index;
    chaos_io_config_state_t *next_state = &g_chaos_io_config_states[next_index];
    size_t file_size = 0U;
    int read_rc;

    chaos_io_config_reset_state(next_state, 1);

    if (observed_mtime == CHAOS_IO_MTIME_MISSING)
    {
        chaos_io_config_report(CHAOS_IO_MTIME_MISSING, next_state);
        chaos_io_config_publish(next_index, CHAOS_IO_MTIME_MISSING);
        return;
    }

    read_rc = chaos_io_config_read_file(&file_size, observed_mtime);
    if (read_rc == -2)
    {
        chaos_io_config_reject_file(next_state);
    }
    else if (read_rc != 0)
    {
        /* A failed read says nothing about the rules: keep the active snapshot and
         * release the claim with the previous stamp, so the next call retries
         * instead of running without rules until the file changes again. */
        __sync_synchronize();
        g_chaos_io_cached_mtime = previous_mtime;
        return;
    }

    if (read_rc == 0 && chaos_io_config_parse_buffer(
                            g_chaos_io_config_buffer, next_state->rules, &next_state->rule_count
                        ) != 0)
    {
        chaos_io_config_reset_state(next_state, 0);
    }

    (void)file_size;
    chaos_io_config_attach_hits(next_state);
    chaos_io_config_report(observed_mtime, next_state);
    chaos_io_config_publish(next_index, observed_mtime);
}

/* --- Public API ------------------------------------------------------------------ */

/**
 * @brief Initializes the global config cache to an empty passthrough state.
 */
void chaos_io_config_init(void)
{
    /* Find the vDSO clock now, not first inside a wrapper a signal handler may re-enter. */
    (void)chaos_clock_now_ns();
    chaos_io_config_reset_state(&g_chaos_io_config_states[0], 1);
    chaos_io_config_reset_state(&g_chaos_io_config_states[1], 1);
    g_chaos_io_active_config_index = 0U;
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
}

/** @brief When this process last looked at the rule file (vDSO CLOCK_MONOTONIC, ns). */
static volatile uint64_t g_chaos_io_last_check_ns = 0U;

/** @brief Throttle for looking at the rule file; 0 looks on every call (unit tests). */
static uint64_t g_chaos_io_check_interval_ns = CHAOS_CHECK_INTERVAL_NS;

/**
 * @brief Whether the rule file was looked at too recently to look again.
 *
 * @details Each look is a stat() system call, the largest part of a wrapper's cost.
 * Once rules are loaded the file is looked at no more than every
 * CHAOS_CHECK_INTERVAL_NS, so a change takes effect within that time instead of on
 * the very next call. The first load, and any call while no rules are loaded yet,
 * always looks.
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
 * @brief Refreshes the cached config if the config file mtime changed.
 *
 * @details See the file-level reload protocol documentation.  The early exit
 * for `CHAOS_IO_MTIME_RELOADING` is not a lost update: that thread will
 * publish the new snapshot soon, and the current thread can safely serve one
 * more request from the previous snapshot.
 */
static int chaos_io_config_refresh(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;

    if (chaos_io_config_checked_recently())
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    observed_mtime = chaos_io_config_observed_mtime();
    cached_mtime = chaos_io_atomic_load_u64(&g_chaos_io_cached_mtime);

    if (cached_mtime == observed_mtime)
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    /* Another thread already owns this reload cycle; use the current snapshot. */
    if (cached_mtime == CHAOS_IO_MTIME_RELOADING)
    {
        if (chaos_io_atomic_load_u64(&g_chaos_io_reload_pid) == (uint64_t)getpid())
        {
            return chaos_io_config_active_state()->rule_count != 0U;
        }
        /* The claim was made in the parent before fork(); its thread does not exist in
         * this child and will never publish. Release the orphaned claim; if another
         * thread released it first, the claim below decides which of them reloads. */
        (void)chaos_io_atomic_cas_u64(
            &g_chaos_io_cached_mtime, CHAOS_IO_MTIME_RELOADING, CHAOS_IO_MTIME_UNKNOWN
        );
        cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    }
    /* The pid is recorded first so a thread that sees the claim can tell it is this
     * process's. */
    g_chaos_io_reload_pid = (uint64_t)getpid();
    if (chaos_io_atomic_cas_u64(&g_chaos_io_cached_mtime, cached_mtime, CHAOS_IO_MTIME_RELOADING))
    {
        chaos_io_config_reload(observed_mtime, cached_mtime);
    }
    return chaos_io_config_active_state()->rule_count != 0U;
}

/**
 * @brief Refreshes the snapshot if the config file changed, leaving errno untouched.
 *
 * @details The stat, open and read calls of a refresh belong to the library, not to
 * the caller: an interposed call that then succeeds must not report the errno of a
 * missing config file.
 */
int chaos_io_config_prepare(void)
{
    const int saved_errno = errno;
    const int result = chaos_io_config_refresh();

    errno = saved_errno;
    return result;
}

/**
 * @brief Parses a single config line into a rule.
 *
 * @details The colon-split tokenizer advances a cursor through the line,
 * replacing `:` separators with NUL so that `fields[]` point directly into
 * the mutable buffer.  Exactly four fields must be present; three or fewer
 * is always a format error (it is not possible to have a valid rule with
 * fewer than four fields).
 *
 * Effect dispatch order: errno name first (via `chaos_io_parse_errno_name`),
 * then `LATENCY`, then `TORN`, then `CORRUPT`.  This means an operator
 * cannot use these four strings as path prefixes, but they would be
 * pathological rule paths in practice.
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
 * @brief Parses an entire config buffer in place.
 *
 * @details Splits on `'\n'` by replacing each newline with NUL and calling
 * `chaos_io_config_parse_line()` for each segment.  The last segment (no
 * trailing newline) is handled by the `next == NULL` exit condition.
 *
 * Any parse error causes an immediate return with `*rule_count = 0` and
 * `-1` rather than accumulating a partial result.  This all-or-nothing
 * behavior ensures operators always see their complete intended config or
 * passthrough, never a silently truncated rule set.
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

        /* The parser edits the line in place; keep it as written for the report. */
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
                /* Qualifiers without a rule. */
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
 * @brief Selects the longest-prefix matching rule from a caller-supplied rule set.
 *
 * @details The wildcard `"*"` rule has `path_len == 1` (the length of the
 * literal `"*"` string stored in `path_prefix`), but `chaos_io_rule_prefix_matches()`
 * treats it specially so it always matches.  Any explicit prefix rule beats it
 * as long as the explicit rule's `path_len` is greater than 1.
 *
 * The function copies the winning rule into `*rule` so the caller is
 * independent of the snapshot array's lifetime.
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

/**
 * @brief Matches a path against the current loaded config without forcing a refresh.
 *
 * @details Reads the active snapshot index under an acquire barrier and
 * delegates directly to `chaos_io_config_select_rule()`.  Returns 0
 * immediately when the snapshot is empty (no rules, so nothing to match).
 */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    const chaos_io_config_state_t *state;

    if (path == NULL || rule == NULL)
    {
        return 0;
    }

    state = chaos_io_config_active_state();
    if (state->rule_count == 0U)
    {
        return 0;
    }

    return chaos_io_config_select_rule(state->rules, state->rule_count, operation, path, rule);
}

/**
 * @brief Refreshes the config if needed and then matches a path against it.
 *
 * @details The exclusion check runs before `chaos_io_config_prepare()` to
 * avoid the stat overhead for paths that can never match a user rule (e.g.
 * `/proc/self/fd/N` resolved during fd-cache lookups, or the config file
 * itself).
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
