/**
 * @file chaos_memory_config.c
 * @brief Config file parsing, mtime-based reload, and rule-matching engine for
 *        libchaos-memory.
 *
 * @details
 * This translation unit implements the full lifecycle of the fault-injection
 * configuration: reading from disk, parsing into rule structs, and selecting
 * the best-matching rule for a given intercepted call.
 *
 * @par Two-snapshot reload protocol
 * Config state is stored in a pair of chaos_memory_config_state_t slots
 * (g_chaos_memory_config_states[0..1]).  At any moment one slot is "active"
 * (index held in g_chaos_memory_active_config_index) and one is "inactive".
 * A reload proceeds as follows:
 *
 *  1. stat(2) the config file and hash its mtime into a 64-bit value.
 *  2. Atomically CAS the cached mtime from its current value to the sentinel
 *     CHAOS_MEMORY_MTIME_RELOADING.  If the CAS fails another thread is
 *     already reloading; skip and return the current active state.
 *  3. Write the new rules into the inactive slot.
 *  4. Store the new active index (full memory barrier).
 *  5. Store the observed mtime hash (full memory barrier).  Steps 4 and 5 are
 *     not atomic with each other, but the worst case is a redundant reload on
 *     the next call — not a safety issue.
 *
 * The read-side path (chaos_memory_config_active_state) issues a memory
 * barrier before reading the index, ensuring it sees the index update from
 * step 4 before reading the slot contents.
 *
 * @par Per-thread read buffer
 * The config file is read into a per-thread TLS buffer
 * (g_chaos_memory_config_buffer) to avoid heap allocation in the hot path.
 * The buffer is sized for CHAOS_MEMORY_MAX_CONFIG_BYTES + 1 to accommodate the
 * null terminator.  Only the thread that wins the CAS race in
 * chaos_memory_config_prepare() uses its buffer for any given reload.
 *
 * @par Reentrancy
 * stat(2) and open()/read() calls set the TLS reentrancy guard so that any
 * mmap call emitted by glibc's wrappers (for file descriptor table growth or
 * similar) passes through to the real mmap without fault injection.
 *
 * @par Invariants maintained
 *  - g_chaos_memory_active_config_index is always 0 or 1.
 *  - The active slot's parse_ok field is non-zero iff the last reload parsed
 *    successfully (zero rules from an absent file is still parse_ok == 1).
 *  - Sentinel mtime values (MISSING, RELOADING, UNKNOWN) are never produced
 *    from real stat timestamps thanks to chaos_memory_config_normalize_mtime_hash().
 *
 * @par Stability
 * Internal — do not depend on the symbols or types in this file from outside
 * the memory chaos module.
 */

#include "chaos_memory_config.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* =========================================================================
 * Platform compatibility: struct stat mtime accessor macros
 * =========================================================================
 */

/**
 * @brief Access the mtime seconds field from struct stat.
 *
 * @details
 * POSIX.1-2008 (Linux) exposes mtime as st_mtim.tv_sec (struct timespec).
 * Pre-POSIX BSDs use st_mtimespec.  The macros abstract this difference so
 * chaos_memory_config_hash_mtime() compiles cleanly on both.
 *
 * Since this library targets Linux, the Linux branch is always active in
 * production.
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
 * @brief Internal snapshot of a fully parsed config file.
 *
 * @details
 * Two instances are held in g_chaos_memory_config_states[].  One is active
 * (pointed to by g_chaos_memory_active_config_index) and visible to all
 * concurrent callers.  The other is written exclusively by the thread that
 * wins the CAS reload race and is invisible until the index is atomically
 * updated.
 *
 * @invariant parse_ok is non-zero whenever the last parse of this slot
 *            succeeded (including when rule_count is zero, meaning the file
 *            is absent or empty).  parse_ok is zero only when a parse
 *            attempt was made and produced a syntax error.
 */
typedef struct chaos_memory_config_state
{
    /**
     * @brief Array of parsed rules from the most recent successful load.
     * Valid entries are [0, rule_count).  Remaining entries are zeroed.
     */
    chaos_memory_rule_t rules[CHAOS_MEMORY_MAX_RULES];

    /**
     * @brief Number of valid rules in the @c rules array.
     * Zero when the file is absent, empty, or rule parsing failed.
     */
    size_t rule_count;

    /**
     * @brief Non-zero if the last parse attempt succeeded; zero on error.
     * When zero, chaos_memory_config_match_loaded() returns 0 immediately
     * (fail-open: calls pass through without fault injection).
     */
    int parse_ok;
} chaos_memory_config_state_t;

/**
 * @brief The two config snapshots used by the double-buffering reload protocol.
 *
 * @details
 * Slot [g_chaos_memory_active_config_index] is the current live config.
 * Slot [1 - active_index] is the inactive buffer available for the next reload.
 * Access to the active slot's contents is unsynchronised on the read path
 * (the memory barrier in chaos_memory_config_active_state() ensures the index
 * is current, and the write side always completes its writes before publishing
 * the new index).
 */
static chaos_memory_config_state_t g_chaos_memory_config_states[2];

/**
 * @brief Index into g_chaos_memory_config_states[] of the active snapshot.
 *
 * @details
 * Holds 0 or 1.  Written by chaos_memory_config_publish() under a full memory
 * barrier.  Read by chaos_memory_config_active_state() under a full memory
 * barrier so that the reader observes the completed write to the corresponding
 * slot before it accesses rule data.
 */
static volatile unsigned int g_chaos_memory_active_config_index = 0U;

/**
 * @brief Cached mtime hash of the config file from the most recent stat(2).
 *
 * @details
 * Starts at CHAOS_MEMORY_MTIME_UNKNOWN to force an unconditional first reload.
 * Updated atomically using CAS in chaos_memory_config_prepare().
 * Takes the sentinel value CHAOS_MEMORY_MTIME_RELOADING while a reload is in
 * progress; any thread observing this sentinel yields to the active snapshot.
 * Set to CHAOS_MEMORY_MTIME_MISSING when stat(2) fails (file absent).
 */
static volatile uint64_t g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;

/**
 * @brief Per-thread buffer for reading the config file.
 *
 * @details
 * Holds the raw config file text during a reload.  TLS placement avoids heap
 * allocation and mutex serialisation — only the winning reload thread uses its
 * copy during any given reload, and multiple threads may reload concurrently
 * on pathological workloads (the CAS ensures at most one winner per mtime
 * change, but separate mtime changes can race across threads).
 *
 * Sized CHAOS_MEMORY_MAX_CONFIG_BYTES + 1 to hold the null terminator appended
 * by chaos_memory_config_read_file().
 */
static __thread char g_chaos_memory_config_buffer[CHAOS_MEMORY_MAX_CONFIG_BYTES + 1U];

/* =========================================================================
 * Internal helpers — state management
 * =========================================================================
 */

/**
 * @brief Zero a config state slot and set its parse_ok flag.
 *
 * @details
 * Called before writing new rule data into the inactive slot to guarantee a
 * clean starting state regardless of what the slot held previously.
 *
 * @param state     Slot to reset.  No-op if NULL.
 * @param parse_ok  Value to write into state->parse_ok after the memset.
 *                  Pass 1 to mark the slot as "ok but empty"; pass 0 to mark
 *                  it as "parse error" (used when chaos_memory_config_parse_buffer
 *                  returns -1).
 */
static void chaos_memory_config_reset_state(chaos_memory_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/**
 * @brief Return a read-only pointer to the currently active config snapshot.
 *
 * @details
 * Emits a full memory barrier before reading g_chaos_memory_active_config_index
 * so that subsequent accesses to the returned slot observe all prior writes
 * that were completed before the index was published.
 *
 * @return Pointer to the active chaos_memory_config_state_t.  Never NULL.
 */
static const chaos_memory_config_state_t *chaos_memory_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_memory_active_config_index;
    return &g_chaos_memory_config_states[index];
}

/**
 * @brief Atomically publish a new active config slot and update the mtime cache.
 *
 * @details
 * Stores @p next_index into g_chaos_memory_active_config_index under a full
 * memory barrier (ensuring all rule writes to the new slot are visible before
 * the index flip), then stores @p observed_mtime into g_chaos_memory_cached_mtime
 * under a second barrier.
 *
 * The two stores are not a single atomic operation, but the ordering guarantee
 * is sufficient: the index update makes new rules visible to concurrent readers,
 * and the mtime update clears the RELOADING sentinel so future reload checks
 * compare against the correct timestamp.  A reader that races between the two
 * stores will see either the old mtime (RELOADING) or the new one; in both
 * cases it correctly skips the reload.
 *
 * @param next_index     The index (0 or 1) to make active.
 * @param observed_mtime The mtime hash that was observed for this reload.
 *                       Must not be CHAOS_MEMORY_MTIME_RELOADING.
 */
static void chaos_memory_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_memory_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_memory_cached_mtime = observed_mtime;
}

/* =========================================================================
 * Internal helpers — text parsing utilities
 * =========================================================================
 */

/**
 * @brief Test whether a character is considered whitespace for trimming.
 *
 * @param ch  Character to test.
 * @return    Non-zero if ch is space, tab, carriage return, or newline.
 */
static int chaos_memory_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/**
 * @brief Trim leading and trailing whitespace from a string in place.
 *
 * @details
 * Returns a pointer into @p text past any leading whitespace, and places a
 * null terminator after the last non-whitespace character.  The returned
 * pointer may point to the terminator of an all-whitespace input (empty
 * result) or into the interior of @p text (leading spaces stripped).
 *
 * @param text  Null-terminated string to trim.  Modified in place.
 * @return      Pointer to the first non-whitespace character, or the null
 *              terminator if the string is all whitespace.  Returns NULL if
 *              @p text is NULL.
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
 * @brief Truncate a line at the first `#` character to strip inline comments.
 *
 * @details
 * The `#` is replaced with `\0`, discarding the comment and everything after
 * it.  No-op on lines without `#`.
 *
 * @param line  Null-terminated line buffer.  Modified in place.  No-op if NULL.
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
 * @brief Parse a selector token string into a chaos_memory_selector_t.
 *
 * @details
 * Recognised tokens and their mappings:
 *  - `*`          → kind=ANY,       operation=INVALID,  mmap_kind=INVALID
 *  - `mmap`       → kind=OPERATION, operation=MMAP,     mmap_kind=INVALID
 *  - `mmap/anon`  → kind=MMAP_KIND, operation=MMAP,     mmap_kind=ANON
 *  - `mmap/file`  → kind=MMAP_KIND, operation=MMAP,     mmap_kind=FILE
 *  - `mprotect`   → kind=OPERATION, operation=MPROTECT, mmap_kind=INVALID
 *  - `munmap`     → kind=OPERATION, operation=MUNMAP,   mmap_kind=INVALID
 *  - `madvise`    → kind=OPERATION, operation=MADVISE,  mmap_kind=INVALID
 *
 * selector_len is set to strlen(@p text) regardless of kind.
 *
 * @param text      Null-terminated selector token (already trimmed).
 * @param selector  Output struct.  Zero-initialised before population.
 * @return          1 on success, 0 if the token is unrecognised or @p text
 *                  is NULL/empty.
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
 * @brief Test whether a selector matches a given call and return its rank.
 *
 * @details
 * Returns 1 if the selector fires for the given operation and mmap_flags
 * combination; 0 otherwise.  When returning 1, writes the specificity rank to
 * @p rank_out:
 *  - 1: ANY selector (wildcard)
 *  - 2: OPERATION selector (matches specific syscall)
 *  - 3: MMAP_KIND selector (matches specific mmap mapping type)
 *
 * Higher ranks win in chaos_memory_config_select_rule().
 *
 * @param selector    The selector to evaluate.
 * @param operation   The syscall being intercepted.
 * @param mmap_flags  The mmap(2) flags word; consumed by
 *                    chaos_memory_mmap_is_anonymous() only when selector kind
 *                    is MMAP_KIND.
 * @param[out] rank_out  Set to the specificity rank on match.  Set to 0 on
 *                       no-match or if NULL.
 * @return  1 if the selector matches, 0 otherwise.
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
 * @brief Parse an errno name or integer string into the corresponding errno value.
 *
 * @details
 * Recognises the symbolic names for the errno values that are meaningful for
 * mmap(2) and related syscalls:
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
 * If the text is not a recognised name, strtol() is attempted to parse a
 * positive decimal or hexadecimal integer literal.
 *
 * @param text  Null-terminated errno name or positive integer string.
 * @return      The positive errno value on success, -1 on failure.
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
 * @brief Parse a probability value from a decimal string.
 *
 * @details
 * Uses strtod() and validates that the result is in [0.0, 1.0].  Whitespace
 * after the number (but before the null terminator) is tolerated.
 *
 * @param text         Null-terminated probability string (e.g., "0.05", "1.0").
 * @param[out] probability  Set to the parsed value on success.
 * @return  0 on success, -1 on parse error or out-of-range value.
 */
static int chaos_memory_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_memory_trim(end) != '\0' || value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

/**
 * @brief Copy a non-empty string value into a fixed-size buffer.
 *
 * @details
 * Validates that @p text is non-NULL, non-empty, and fits in @p buffer_size
 * (including the null terminator), then copies it.  Used to extract the
 * payload portion of a value field before further parsing.
 *
 * @param text         Source string.
 * @param buffer       Destination buffer.
 * @param buffer_size  Size of @p buffer in bytes.
 * @return  0 on success, -1 if @p text is NULL/empty or too long.
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
 * @brief Split a config value field into its payload and optional probability.
 *
 * @details
 * The value field of a config rule may have the form `<payload>@<probability>`
 * (e.g., `ENOMEM@0.05`, `20@0.1`) or just `<payload>` with an implicit
 * probability of 1.0.  This function splits on the last `@` character to
 * handle payloads that might themselves contain `@` (though none currently do).
 *
 * @param text          The raw value text (already trimmed).
 * @param[out] payload  Buffer populated with the payload substring.
 * @param payload_size  Size of @p payload in bytes.
 * @param[out] probability  Set to the parsed probability (1.0 if no `@` suffix).
 * @return  0 on success, -1 on any parse error.
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
 * @brief Parse a latency value in milliseconds from a decimal string.
 *
 * @details
 * Accepts non-negative integers up to UINT_MAX.  Zero is valid (zero-latency
 * LATENCY rules are parsed successfully but have no observable effect).
 *
 * @param text          Null-terminated decimal string.
 * @param[out] latency_ms  Set to the parsed latency on success.
 * @return  0 on success, -1 on parse error or overflow.
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
 * Internal helpers — mtime hashing
 * =========================================================================
 */

/**
 * @brief Shift mtime hash values that collide with sentinel constants.
 *
 * @details
 * The two sentinels CHAOS_MEMORY_MTIME_UNKNOWN (0xffffffffffffffff) and
 * CHAOS_MEMORY_MTIME_RELOADING (0xfffffffffffffffe) must never be produced
 * from a real stat timestamp, otherwise the CAS logic cannot distinguish a
 * real timestamp from a control value.  This function maps colliding values
 * down by 1, accepting a negligible (2^-63) probability of a false mtime-
 * change detection.
 *
 * @param value  Raw mtime hash value.
 * @return       @p value unchanged, or @p value - 1 if it equals either
 *               sentinel.
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
 * @brief Hash the mtime fields of a struct stat into a 64-bit value.
 *
 * @details
 * Uses a FNV-inspired multiplicative scheme to combine the seconds and
 * nanosecond components into a single 64-bit hash.  The starting constant
 * (1469598103934665603 == 0x146E2A4B67B1DA03) is a prime close to a power of
 * 2; the multiplier (1099511628211) is the FNV-1a 64-bit prime.  This
 * combination has good avalanche for the range of values produced by real
 * kernel timestamps.
 *
 * Returns CHAOS_MEMORY_MTIME_MISSING if @p st is NULL (caller signals that
 * stat failed, which is distinguished from a zero-valued mtime).
 *
 * @param st  Pointer to the stat structure, or NULL if stat(2) failed.
 * @return    A 64-bit mtime hash, or CHAOS_MEMORY_MTIME_MISSING if @p st
 *            is NULL.  Never equals CHAOS_MEMORY_MTIME_UNKNOWN or
 *            CHAOS_MEMORY_MTIME_RELOADING.
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
    return chaos_memory_config_normalize_mtime_hash(value);
}

/**
 * @brief Stat the config file and return its mtime hash.
 *
 * @details
 * Sets the TLS reentrancy guard around the stat(2) call so that any internal
 * mmap call (e.g., from glibc's stat wrapper path) bypasses fault injection.
 *
 * @return  A 64-bit mtime hash, or CHAOS_MEMORY_MTIME_MISSING if stat(2) failed.
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
 * @brief Read the entire config file into the per-thread TLS buffer.
 *
 * @details
 * Opens CHAOS_MEMORY_CONFIG_PATH, reads it in a loop, appends a null
 * terminator, and reports the number of bytes read.  Returns -1 if:
 *  - open(2) fails.
 *  - read(2) returns an error.
 *  - The file is exactly CHAOS_MEMORY_MAX_CONFIG_BYTES (ambiguous: the file
 *    may be larger than the buffer).
 *
 * A partial read at buffer capacity is treated as failure so the config
 * subsystem never processes a truncated rule set.
 *
 * The TLS reentrancy guard is held for the duration of the I/O so any
 * internal mmap call from glibc's file-handling code bypasses injection.
 *
 * @param[out] size_out  Number of bytes read (excluding the null terminator).
 * @return  0 on success, -1 on any error.
 */
static int chaos_memory_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_memory_enter_internal();
    fd = open(CHAOS_MEMORY_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_memory_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_memory_config_buffer + total, CHAOS_MEMORY_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_memory_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_MEMORY_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_memory_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
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
 * @brief Split a rule line into three colon-delimited fields.
 *
 * @details
 * Splits @p line on the first and second `:` characters, replacing them with
 * null terminators.  Returns pointers to the trimmed field values.  Returns 0
 * if either `:` is absent (invalid rule format).
 *
 * @param[in,out] line          Line buffer (modified in place).
 * @param[out]    selector_text Pointer to the trimmed selector text.
 * @param[out]    effect_text   Pointer to the trimmed effect text.
 * @param[out]    value_text    Pointer to the trimmed value text.
 * @return  1 on success, 0 if the line does not contain two `:` delimiters.
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
 * @brief Initialise the config subsystem to a clean, zero-rule state.
 *
 * @details
 * Zeroes both snapshots with parse_ok = 1 (empty config is valid), resets the
 * active index to 0, and sets the cached mtime to CHAOS_MEMORY_MTIME_UNKNOWN
 * so that the first call to chaos_memory_config_prepare() unconditionally
 * reloads.
 *
 * Called once from chaos_memory_init() before any intercepted syscall.
 */
void chaos_memory_config_init(void)
{
    chaos_memory_config_reset_state(&g_chaos_memory_config_states[0], 1);
    chaos_memory_config_reset_state(&g_chaos_memory_config_states[1], 1);
    g_chaos_memory_active_config_index = 0U;
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;
}

/**
 * @brief Parse a single config line into a rule.
 *
 * @details
 * See the header declaration for the full contract.  Implementation notes:
 *
 *  - Comment stripping is done first (before trimming) so that a line
 *    containing only a comment after the `#` is correctly treated as blank.
 *  - The probability suffix (`@<p>`) is parsed as part of the value field by
 *    chaos_memory_parse_payload_probability(), which splits on the last `@`
 *    and sets probability = 1.0 if no `@` is present.
 *  - For ERRNO rules, the payload is further parsed by
 *    chaos_memory_parse_errno_name() which accepts both symbolic names and
 *    positive integer literals.
 *  - For LATENCY rules, the payload is parsed by chaos_memory_parse_latency()
 *    as an unsigned millisecond count.
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
 * @brief Parse a complete config buffer into a rule array.
 *
 * @details
 * Splits @p buffer on newline characters (replacing them with `\0`) and
 * processes each line through chaos_memory_config_parse_line().  Blank lines
 * and comments (return value 0) are silently skipped.  Any syntax error
 * (return value -1) causes the entire parse to fail — partial results are
 * discarded by the caller (chaos_memory_config_prepare resets the slot).
 *
 * The rule count is bounded by CHAOS_MEMORY_MAX_RULES; exceeding it returns -1.
 */
int chaos_memory_config_parse_buffer(char *buffer, chaos_memory_rule_t *rules, size_t *rule_count)
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

        parsed = chaos_memory_config_parse_line(line, &rules[count]);
        if (parsed < 0)
        {
            return -1;
        }
        if (parsed == 0)
        {
            continue;
        }
        ++count;
        if (count > CHAOS_MEMORY_MAX_RULES)
        {
            return -1;
        }
    }

    *rule_count = count;
    return 0;
}

/**
 * @brief Select the best-matching rule from an array for a given call context.
 *
 * @details
 * Iterates the entire rule array in order, keeping track of the highest-ranked
 * matching rule seen so far.  Ties in rank are broken by selector_len (longer
 * wins).  The first match at a given rank+length beats all subsequent matches
 * at the same rank+length (stable priority for rules appearing earlier in the
 * config file).
 *
 * Time complexity: O(rule_count).  No allocation.
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
 * @brief Check for config file changes and reload the inactive snapshot if
 *        the file has been modified.
 *
 * @details
 * Core of the two-snapshot reload protocol.  The sequence is:
 *
 *  1. Stat the file and hash its mtime.
 *  2. Load the cached mtime atomically and compare.  If equal, the file has
 *     not changed; return based on the current rule count.
 *  3. CAS the cached mtime to CHAOS_MEMORY_MTIME_RELOADING.  If the CAS
 *     fails, another thread is reloading; fall back to the active snapshot.
 *  4. Determine the inactive slot index (1 - active).
 *  5. Reset the inactive slot to parse_ok=1, rule_count=0.
 *  6. If the file exists: read it into the TLS buffer and parse it.  On parse
 *     error, reset the slot to parse_ok=0 (fail-open: zero rules, no
 *     injection).
 *  7. Publish the new active index and the observed mtime.
 *
 * Returns non-zero if the published snapshot has at least one valid rule.
 */
int chaos_memory_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_memory_config_state_t *next_state;

    observed_mtime = chaos_memory_config_observed_mtime();
    cached_mtime = chaos_memory_atomic_load_u64(&g_chaos_memory_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }
    if (!chaos_memory_atomic_cas_u64(
            &g_chaos_memory_cached_mtime, cached_mtime, CHAOS_MEMORY_MTIME_RELOADING
        ))
    {
        return chaos_memory_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_memory_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_memory_config_states[next_index];
    chaos_memory_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_MEMORY_MTIME_MISSING &&
        chaos_memory_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_memory_config_parse_buffer(
            g_chaos_memory_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_memory_config_reset_state(next_state, 0);
    }

    chaos_memory_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

/**
 * @brief Match a rule from the already-loaded active snapshot.
 *
 * @details
 * Skips matching entirely if the active snapshot has parse_ok == 0 (last parse
 * failed; fail-open).  Delegates to chaos_memory_config_select_rule().
 */
int chaos_memory_config_match_loaded(
    chaos_memory_effect_t effect,
    chaos_memory_operation_t operation,
    int mmap_flags,
    chaos_memory_rule_t *rule
)
{
    const chaos_memory_config_state_t *state = chaos_memory_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_memory_config_select_rule(
        state->rules, state->rule_count, effect, operation, mmap_flags, rule
    );
}

/**
 * @brief Prepare the config then match a rule (combined entry point for hooks).
 *
 * @details
 * Returns 0 immediately if @p rule is NULL or if chaos_memory_config_prepare()
 * reports no active rules, avoiding the matching scan entirely on the common
 * no-rules path.
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
