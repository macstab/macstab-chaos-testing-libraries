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
 * **Thread-local config buffer:**
 * `g_chaos_io_config_buffer` is `__thread` so that concurrent reloads on
 * different threads do not clobber each other's read buffer.  In practice
 * the CAS ensures only one thread reloads at a time, but the TLS placement
 * avoids needing a dynamic allocation or a mutex-protected static buffer.
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

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
    int parse_ok;                              /**< Non-zero if the last parse succeeded (including empty file). */
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
 * @brief Per-thread buffer for reading the config file contents.
 *
 * @details Sized to `CHAOS_IO_MAX_CONFIG_BYTES + 1` to hold the entire
 * maximum-size file plus a terminating NUL appended by
 * `chaos_io_config_read_file()`.  Using TLS avoids the need for either
 * a mutex-protected static buffer or a heap allocation in the reload path.
 */
static __thread char g_chaos_io_config_buffer[CHAOS_IO_MAX_CONFIG_BYTES + 1U];

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
 * @brief Hashes the mtime from a `struct stat` into a 64-bit cache key.
 *
 * @details Uses a FNV-inspired multiply-XOR chain over seconds and
 * nanoseconds so that any change in either component produces a different
 * hash.  Nanosecond resolution avoids the false "no change" result that
 * would occur if the file were written and re-written within the same
 * second.
 *
 * @param[in] st  Pointer to the stat result.  NULL is treated as
 *                "file not present" and returns `CHAOS_IO_MTIME_MISSING`.
 * @return A 64-bit hash of the mtime, guaranteed not to equal any sentinel.
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
 * @brief Reads the config file into the thread-local buffer.
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
static int chaos_io_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL || g_chaos_io_real_open == NULL || g_chaos_io_real_read == NULL ||
        g_chaos_io_real_close == NULL)
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    fd = g_chaos_io_real_open(CHAOS_IO_CONFIG_PATH, O_RDONLY);
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
            return -1;
        }
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
static void chaos_io_config_reload(uint64_t observed_mtime)
{
    unsigned int next_index = 1U - g_chaos_io_active_config_index;
    chaos_io_config_state_t *next_state = &g_chaos_io_config_states[next_index];
    size_t file_size = 0U;

    chaos_io_config_reset_state(next_state, 1);

    if (observed_mtime == CHAOS_IO_MTIME_MISSING)
    {
        chaos_io_config_publish(next_index, CHAOS_IO_MTIME_MISSING);
        return;
    }

    if (chaos_io_config_read_file(&file_size) != 0)
    {
        chaos_io_config_reset_state(next_state, 0);
        chaos_io_config_publish(next_index, observed_mtime);
        return;
    }

    if (chaos_io_config_parse_buffer(
            g_chaos_io_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_io_config_reset_state(next_state, 0);
    }

    (void)file_size;
    chaos_io_config_publish(next_index, observed_mtime);
}

/* --- Public API ------------------------------------------------------------------ */

/**
 * @brief Initializes the global config cache to an empty passthrough state.
 */
void chaos_io_config_init(void)
{
    chaos_io_config_reset_state(&g_chaos_io_config_states[0], 1);
    chaos_io_config_reset_state(&g_chaos_io_config_states[1], 1);
    g_chaos_io_active_config_index = 0U;
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
}

/**
 * @brief Refreshes the cached config if the config file mtime changed.
 *
 * @details See the file-level reload protocol documentation.  The early exit
 * for `CHAOS_IO_MTIME_RELOADING` is not a lost update: that thread will
 * publish the new snapshot soon, and the current thread can safely serve one
 * more request from the previous snapshot.
 */
int chaos_io_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;

    observed_mtime = chaos_io_config_observed_mtime();
    cached_mtime = chaos_io_atomic_load_u64(&g_chaos_io_cached_mtime);

    if (cached_mtime == observed_mtime)
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    /* Another thread already owns this reload cycle; use the current snapshot. */
    if (cached_mtime == CHAOS_IO_MTIME_RELOADING)
    {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    if (chaos_io_atomic_cas_u64(&g_chaos_io_cached_mtime, cached_mtime, CHAOS_IO_MTIME_RELOADING))
    {
        chaos_io_config_reload(observed_mtime);
    }
    return chaos_io_config_active_state()->rule_count != 0U;
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
    char *line;
    size_t count = 0U;

    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    line = buffer;
    for (;;)
    {
        char *next = strchr(line, '\n');
        chaos_io_rule_t parsed_rule;
        int parse_result;

        if (next != NULL)
        {
            *next = '\0';
        }

        parse_result = chaos_io_config_parse_line(line, &parsed_rule);
        if (parse_result < 0)
        {
            *rule_count = 0U;
            return -1;
        }
        if (parse_result > 0)
        {
            if (count >= CHAOS_IO_MAX_RULES)
            {
                *rule_count = 0U;
                return -1;
            }
            rules[count++] = parsed_rule;
        }

        if (next == NULL)
        {
            break;
        }
        line = next + 1;
    }

    *rule_count = count;
    return 0;
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
