/**
 * @file test_time_config.c
 * @brief Unit tests for TIME-domain config parsing, selector matching, rule selection,
 *   and reload state machine.
 *
 * Subsystem under test: `src/time/chaos_time_config.c`
 *
 * Coverage approach:
 * - Production source is included directly after replacing `open`, `read`, `close`, and
 *   `chaos_time_atomic_cas_u64` with test-controlled stubs, exercising the full config
 *   pipeline without LD_PRELOAD.
 * - `write_config_text()` uses `futimens` to stamp deterministic mtime values so successive
 *   writes always trigger a reload regardless of wall-clock precision.
 * - The existing config file at `CHAOS_TIME_CONFIG_PATH` is backed up and restored.
 *
 * Properties under test:
 * - Primitive helpers: `is_blank_char`, `config_reset_state`, `trim`, `strip_comment`,
 *   `parse_errno_name` (4 symbolic + numeric "4" + NULL + "bad"),
 *   `parse_probability`, `parse_latency`, `parse_offset` (negative value, NULL args, bad text),
 *   `copy_text_value`, `parse_payload_probability` (bare / `value@p` / empty / p>1.0),
 *   `parse_clock_id` (realtime, monotonic, platform conditionals, numeric "7", "bad-clock"),
 *   `selector_parse` (NULL / "" / "clock_gettime/" / overlong),
 *   `split_rule_fields` (valid / NULL / one-colon / missing second colon),
 *   `selector_matches` (NULL selector), `effect_allowed` (NULL / valid / INVALID),
 *   mtime sentinels (MTIME_MISSING, MTIME_UNKNOWN, MTIME_RELOADING normalization).
 * - Selector matching: `*` (ANY, rank=1), `clock_gettime` (OPERATION, rank=2),
 *   `clock_gettime/monotonic` (CLOCK_ID, rank=3); non-matching clock_id → false;
 *   `nanosleep` and `usleep` selectors; "clock_gettime/", "sleep", "bad-clock" all rejected.
 * - Line and buffer parsing: ERRNO / LATENCY / OFFSET effects; 11 invalid-line categories
 *   (OFFSET on wildcard/usleep, out-of-range p, bad clock, unknown effect, etc.);
 *   buffer with blank/comment lines; no-newline EOF; NULL guards.
 * - Rule selection: clock_gettime/monotonic beats clock_gettime beats * (rank hierarchy);
 *   CLOCK_REALTIME falls back to operation selector; usleep falls back to ANY;
 *   nanosleep LATENCY direct match; NULL guards; `selector_len` tie-break.
 * - Prepare-and-match state machine: no file → false; valid OFFSET rule; same mtime → no reload;
 *   new mtime reloads; `match` after new file; `match_loaded` bypass; bad rule → prepare false;
 *   oversized file → read_file negative; open/read/CAS failures all false.
 * - Buffer limit: `CHAOS_TIME_MAX_RULES + 1` rules → parse_buffer returns negative.
 *
 * What is NOT tested here:
 * - Action helpers (offset math, latency, errno): tested in test_time_actions.c.
 * - Wrapper call paths: tested in test_chaos_time.c.
 */

/* The rule file is read through these stubs (defined below) instead of raw system calls. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

#include "../support/test_time_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/** @brief When non-zero, the open stub returns ENOENT rather than delegating to the real open. */
static int g_test_config_force_open_fail = 0;
/**
 * @brief When non-zero, the open stub returns `g_test_config_fake_fd`; subsequent reads on
 *   that fd return EIO.
 */
static int g_test_config_force_read_fail = 0;

/** Number of upcoming config reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;
/** @brief When non-zero, the CAS stub always returns 0 (failure). */
static int g_test_config_force_cas_fail = 0;
/**
 * @brief Sentinel fd returned by the open stub when `g_test_config_force_read_fail` is set.
 *   Chosen to be outside normal fd ranges to avoid aliasing.
 */
static const int g_test_config_fake_fd = 8124;

/**
 * @brief Stub for `open(2)` / `open(2)` with O_CREAT.
 *
 * Behaviour depends on fault-injection flags:
 * - `g_test_config_force_open_fail`: returns -1 with errno=ENOENT.
 * - `g_test_config_force_read_fail`: returns `g_test_config_fake_fd`.
 * - O_CREAT: extracts mode from va_args and delegates to the real `open`.
 * - Otherwise: delegates without mode argument.
 *
 * @param path   Filesystem path.
 * @param flags  Open flags.
 * @param ...    Optional mode_t when flags include O_CREAT.
 * @return Opened fd, `g_test_config_fake_fd`, or -1.
 */
static int chaos_time_test_config_open(const char *path, int flags, ...)
{
    if (g_test_config_force_open_fail != 0)
    {
        errno = ENOENT;
        return -1;
    }
    if (g_test_config_force_read_fail != 0)
    {
        (void)path;
        (void)flags;
        return g_test_config_fake_fd;
    }
    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        mode_t mode;

        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        return open(path, flags, mode);
    }
    return open(path, flags);
}

/**
 * @brief Stub for `read(2)`.
 *
 * When `g_test_config_force_read_fail` is set and @p fd equals `g_test_config_fake_fd`,
 * returns -1 with errno=EIO. Otherwise delegates to the real read.
 *
 * @param fd      File descriptor.
 * @param buffer  Destination buffer.
 * @param count   Maximum bytes to read.
 * @return Bytes read, or -1 with errno=EIO on injected failure.
 */
static ssize_t chaos_time_test_config_read(int fd, void *buffer, size_t count)
{
    if (g_test_config_read_eintr > 0)
    {
        --g_test_config_read_eintr;
        errno = EINTR;
        return -1;
    }
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        (void)buffer;
        (void)count;
        errno = EIO;
        return -1;
    }
    return read(fd, buffer, count);
}

/**
 * @brief Stub for `close(2)`.
 *
 * When `g_test_config_force_read_fail` is set and @p fd equals `g_test_config_fake_fd`,
 * returns 0 without calling the real close (the fd is not a real kernel fd).
 * Otherwise delegates.
 *
 * @param fd  File descriptor to close.
 * @return 0 on success.
 */
static int chaos_time_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Stub for `chaos_time_atomic_cas_u64`.
 *
 * When `g_test_config_force_cas_fail` is non-zero, returns 0 to simulate a lost CAS race,
 * causing the prepare call to skip the update and return false. Otherwise delegates to the
 * real `__sync_bool_compare_and_swap`.
 *
 * @param value     Pointer to the target 64-bit word.
 * @param expected  Value required for success.
 * @param desired   Value to write on success.
 * @return 1 on success, 0 on injected failure or value mismatch.
 */
static int
chaos_time_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_time_test_config_open
#define read chaos_time_test_config_read
#define close chaos_time_test_config_close
#define chaos_time_atomic_cas_u64 chaos_time_test_atomic_cas_u64
#include "../../src/time/chaos_time_config.c"
#undef chaos_time_atomic_cas_u64
#undef close
#undef read
#undef open

/**
 * @brief Heap snapshot of a config file for backup and restore.
 */
typedef struct chaos_time_test_file_backup
{
    /** @brief Non-zero if the file existed at backup time. */
    int existed;
    /** @brief Heap-allocated copy of the file contents. */
    char *data;
    /** @brief Number of bytes in `data`. */
    size_t size;
} chaos_time_test_file_backup_t;

/**
 * @brief Read @p path into a heap snapshot stored in @p backup.
 *
 * If the file does not exist, sets `backup->existed = 0` and returns.
 *
 * @param path    Path to back up.
 * @param backup  Output struct to populate; must be zero-initialised by caller.
 */
static void backup_file(const char *path, chaos_time_test_file_backup_t *backup)
{
    FILE *file;

    backup->existed = 0;
    backup->data = NULL;
    backup->size = 0U;

    file = fopen(path, "rb");
    if (file == NULL)
    {
        return;
    }

    backup->existed = 1;
    for (;;)
    {
        char buffer[256];
        size_t rc = fread(buffer, 1U, sizeof(buffer), file);
        char *next;

        if (rc == 0U)
        {
            break;
        }

        next = (char *)realloc(backup->data, backup->size + rc);
        assert(next != NULL);
        backup->data = next;
        (void)memcpy(backup->data + backup->size, buffer, rc);
        backup->size += rc;
    }
    fclose(file);
}

/**
 * @brief Restore a file from a heap snapshot created by `backup_file`.
 *
 * Removes the file if it did not exist at backup time; otherwise rewrites it verbatim.
 *
 * @param path    Filesystem path to restore.
 * @param backup  Snapshot to write.
 */
static void restore_file(const char *path, const chaos_time_test_file_backup_t *backup)
{
    FILE *file;

    if (backup->existed == 0)
    {
        (void)unlink(path);
        return;
    }

    file = fopen(path, "wb");
    assert(file != NULL);
    assert(fwrite(backup->data, 1U, backup->size, file) == backup->size);
    assert(fclose(file) == 0);
}

/**
 * @brief Free heap memory held by a backup snapshot.
 *
 * @param backup  Snapshot to release.
 */
static void free_backup(chaos_time_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Write @p text to `CHAOS_TIME_CONFIG_PATH` with a deterministic mtime.
 *
 * Uses `futimens` on the open file descriptor before closing so that successive calls
 * with distinct @p stamp values produce distinct mtime hashes, reliably triggering a reload.
 *
 * @param text   NUL-terminated config text to write.
 * @param stamp  Seconds value used for both atime and mtime.
 */
static void write_config_text(const char *text, time_t stamp)
{
    FILE *file;
    struct timespec times[2];

    file = fopen(CHAOS_TIME_CONFIG_PATH, "w");
    assert(file != NULL);
    assert(fputs(text, file) >= 0);
    assert(fflush(file) == 0);
    times[0].tv_sec = stamp;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    assert(futimens(fileno(file), times) == 0);
    assert(fclose(file) == 0);
}

/**
 * @brief Invariant: all primitive config helpers accept valid input and reject invalid input.
 *
 * Triggering conditions: direct calls to every leaf parsing helper with valid, boundary,
 *   and invalid arguments.
 *
 * Expected observable behaviour:
 * - `is_blank_char(' '/'\\t')` → true; `is_blank_char('x')` → false.
 * - `config_reset_state(NULL, 1)` does not crash; `reset_state(&state, 0)` zeroes
 *   `rule_count` and `parse_ok` even when the struct was memset to 0xff.
 * - `trim` strips leading/trailing whitespace; NULL → NULL.
 * - `strip_comment` truncates at '#'; NULL is a no-op.
 * - `parse_errno_name`: EINVAL/EPERM/ENOSYS/EAGAIN return correct values; numeric "4" → 4;
 *   NULL → -1; "bad" → -1.
 * - `parse_probability`/`parse_latency`: NULL pointer args → error; valid strings → 0;
 *   out-of-range → error.
 * - `parse_offset("-250", ...)` → 0 return; NULL args → error; "bad" → error.
 * - `copy_text_value`/`parse_payload_probability`: NULL/empty/zero-size → error; valid → 0.
 * - `parse_clock_id`: realtime, monotonic, platform-conditional IDs, numeric "7" → true;
 *   NULL output, NULL name, "bad-clock" → false.
 * - `selector_parse`: NULL / "" / "clock_gettime/" (empty clock part) / overlong → false.
 * - `split_rule_fields("clock_gettime/monotonic:OFFSET:-250", ...)` → all three pointers set.
 * - `selector_matches(NULL, ...)` → false; `effect_allowed(NULL, ...)` → false;
 *   `effect_allowed(&selector, ERRNO/LATENCY)` → true;
 *   `effect_allowed(&selector, INVALID)` → false.
 * - `config_hash_mtime(NULL)` → MTIME_MISSING; sentinel normalization of MTIME_UNKNOWN and
 *   MTIME_RELOADING never returns those sentinel values; `hash_mtime(&zero_stat)` → non-zero.
 */
static void test_helper_functions(void)
{
    char trim_text[] = " \t value \r\n";
    char blank_text[] = " \t\r\n";
    char comment_text[] = "abc#def";
    char payload_text[] = "25@0.25";
    char split_text[] = "clock_gettime/monotonic:OFFSET:-250";
    char no_probability_text[] = "42";
    char missing_effect_text[] = "selector:value";
    char overlong_selector[sizeof("clock_gettime/") + CHAOS_TIME_MAX_TEXT];
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_TIME_MAX_VALUE];
    struct stat st;
    chaos_time_selector_t selector;
    chaos_time_config_state_t state;
    clockid_t clock_id = (clockid_t)0;

    (void)memset(overlong_selector, '7', sizeof(overlong_selector));
    (void)memcpy(overlong_selector, "clock_gettime/", sizeof("clock_gettime/") - 1U);
    overlong_selector[sizeof(overlong_selector) - 1U] = '\0';

    assert(chaos_time_is_blank_char(' '));
    assert(chaos_time_is_blank_char('\t'));
    assert(!chaos_time_is_blank_char('x'));

    chaos_time_config_reset_state(NULL, 1);
    (void)memset(&state, 0xff, sizeof(state));
    chaos_time_config_reset_state(&state, 0);
    assert(state.rule_count == 0U);
    assert(state.parse_ok == 0);

    assert(chaos_time_trim(NULL) == NULL);
    assert(strcmp(chaos_time_trim(trim_text), "value") == 0);
    assert(strcmp(chaos_time_trim(blank_text), "") == 0);
    chaos_time_strip_comment(NULL);
    chaos_time_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);

    assert(chaos_time_parse_errno_name(NULL) == -1);
    assert(chaos_time_parse_errno_name("EINVAL") == EINVAL);
    assert(chaos_time_parse_errno_name("EPERM") == EPERM);
    assert(chaos_time_parse_errno_name("ENOSYS") == ENOSYS);
    assert(chaos_time_parse_errno_name("EAGAIN") == EAGAIN);
    assert(chaos_time_parse_errno_name("4") == 4);
    assert(chaos_time_parse_errno_name("bad") == -1);
    assert(chaos_time_parse_probability(NULL, &(double){0.0}) != 0);
    assert(chaos_time_parse_probability("0.5", NULL) != 0);
    assert(chaos_time_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_time_parse_probability("2.0", &(double){0.0}) != 0);
    assert(chaos_time_parse_latency(NULL, &(unsigned int){0U}) != 0);
    assert(chaos_time_parse_latency("25", NULL) != 0);
    assert(chaos_time_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_time_parse_latency("bad", &(unsigned int){0U}) != 0);
    assert(chaos_time_parse_offset(NULL, &(int64_t){0}) != 0);
    assert(chaos_time_parse_offset("-250", NULL) != 0);
    assert(chaos_time_parse_offset("-250", &(int64_t){0}) == 0);
    assert(chaos_time_parse_offset("bad", &(int64_t){0}) != 0);
    /* Within 100 years either way; strtoll would clamp beyond int64 silently. */
    {
        int64_t offset = 0;

        assert(chaos_time_parse_offset("3155760000000", &offset) == 0);
        assert(offset == INT64_C(3155760000000));
        assert(chaos_time_parse_offset("-3155760000000", &offset) == 0);
        assert(offset == -INT64_C(3155760000000));
        assert(chaos_time_parse_offset("3155760000001", &offset) != 0);
        assert(chaos_time_parse_offset("-3155760000001", &offset) != 0);
        assert(chaos_time_parse_offset("9223372036854775808", &offset) != 0);
        assert(chaos_time_parse_offset("-9223372036854775809", &offset) != 0);
    }
    assert(chaos_time_copy_text_value(NULL, payload, sizeof(payload)) != 0);
    assert(chaos_time_copy_text_value("abc", NULL, sizeof(payload)) != 0);
    assert(chaos_time_copy_text_value("abc", payload, 0U) != 0);
    assert(chaos_time_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_time_copy_text_value("", payload, sizeof(payload)) != 0);
    assert(
        chaos_time_parse_payload_probability(NULL, payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_time_parse_payload_probability(
            no_probability_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "42") == 0);
    assert(
        chaos_time_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "25") == 0);
    assert(
        chaos_time_parse_payload_probability("@0.25", payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_time_parse_payload_probability("25@2.0", payload, sizeof(payload), &(double){0.0}) !=
        0
    );

    assert(!chaos_time_parse_clock_id(NULL, &clock_id));
    assert(!chaos_time_parse_clock_id("realtime", NULL));
    assert(chaos_time_parse_clock_id("realtime", &(clockid_t){0}));
    assert(chaos_time_parse_clock_id("monotonic", &(clockid_t){0}));
#ifdef CLOCK_MONOTONIC_RAW
    assert(chaos_time_parse_clock_id("monotonic_raw", &(clockid_t){0}));
#endif
#ifdef CLOCK_REALTIME_COARSE
    assert(chaos_time_parse_clock_id("realtime_coarse", &(clockid_t){0}));
#endif
#ifdef CLOCK_MONOTONIC_COARSE
    assert(chaos_time_parse_clock_id("monotonic_coarse", &(clockid_t){0}));
#endif
#ifdef CLOCK_BOOTTIME
    assert(chaos_time_parse_clock_id("boottime", &(clockid_t){0}));
#endif
#ifdef CLOCK_TAI
    assert(chaos_time_parse_clock_id("tai", &(clockid_t){0}));
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
    assert(chaos_time_parse_clock_id("process_cputime_id", &(clockid_t){0}));
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
    assert(chaos_time_parse_clock_id("thread_cputime_id", &(clockid_t){0}));
#endif
    assert(chaos_time_parse_clock_id("7", &(clockid_t){0}));
    assert(!chaos_time_parse_clock_id("bad-clock", &(clockid_t){0}));

    assert(!chaos_time_selector_parse(NULL, &selector));
    assert(!chaos_time_selector_parse("", &selector));
    assert(!chaos_time_selector_parse("clock_gettime/", NULL));
    assert(!chaos_time_selector_parse(overlong_selector, &selector));
    assert(chaos_time_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "clock_gettime/monotonic") == 0);
    assert(strcmp(effect_text, "OFFSET") == 0);
    assert(strcmp(value_text, "-250") == 0);
    assert(!chaos_time_split_rule_fields(NULL, &selector_text, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields(split_text, NULL, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields("bad", &selector_text, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields(
        missing_effect_text, &selector_text, &effect_text, &value_text
    ));

    assert(!chaos_time_selector_matches(NULL, CHAOS_TIME_OP_USLEEP, 0, &((unsigned int){0U})));
    assert(!chaos_time_effect_allowed(NULL, CHAOS_TIME_EFFECT_ERRNO));
    assert(chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_ERRNO));
    assert(chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_LATENCY));
    assert(!chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_INVALID));

    (void)memset(&st, 0, sizeof(st));
    assert(chaos_time_config_hash_mtime(NULL) == CHAOS_TIME_MTIME_MISSING);
    assert(
        chaos_time_config_normalize_mtime_hash(CHAOS_TIME_MTIME_UNKNOWN) != CHAOS_TIME_MTIME_UNKNOWN
    );
    assert(
        chaos_time_config_normalize_mtime_hash(CHAOS_TIME_MTIME_RELOADING) !=
        CHAOS_TIME_MTIME_RELOADING
    );
    assert(chaos_time_config_hash_mtime(&st) != 0U);
}

/**
 * @brief Invariant: selector matching respects kind hierarchy and rejects non-matching clock IDs.
 *
 * Triggering condition: `chaos_time_selector_parse()` and `chaos_time_selector_matches()`
 *   called for all four selector variants.
 *
 * Expected observable behaviour:
 * - "*" → kind=ANY, matches USLEEP with rank=1.
 * - "clock_gettime" → kind=OPERATION, matches CLOCK_GETTIME with any clock_id at rank=2.
 * - "clock_gettime/monotonic" → kind=CLOCK_ID, matches CLOCK_GETTIME+CLOCK_MONOTONIC at rank=3;
 *   rejects CLOCK_REALTIME.
 * - "nanosleep" → matches NANOSLEEP.
 * - "usleep" → matches USLEEP.
 * - "clock_gettime/" (empty clock part), "sleep" (unknown op), "clock_gettime/bad-clock"
 *   (unknown clock) all fail to parse.
 */
static void test_selector_matching(void)
{
    chaos_time_selector_t selector;
    unsigned int rank = 0U;

    assert(chaos_time_selector_parse("*", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_ANY);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_USLEEP, 0, &rank));
    assert(rank == 1U);

    assert(chaos_time_selector_parse("clock_gettime", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_OPERATION);
    assert(selector.operation == CHAOS_TIME_OP_CLOCK_GETTIME);
    assert(
        chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rank)
    );
    assert(rank == 2U);

    assert(chaos_time_selector_parse("clock_gettime/monotonic", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_CLOCK_ID);
    assert(selector.operation == CHAOS_TIME_OP_CLOCK_GETTIME);
    assert(
        chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rank)
    );
    assert(rank == 3U);
    assert(
        !chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rank)
    );

    assert(chaos_time_selector_parse("nanosleep", &selector));
    assert(selector.operation == CHAOS_TIME_OP_NANOSLEEP);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_NANOSLEEP, 0, &rank));

    assert(chaos_time_selector_parse("usleep", &selector));
    assert(selector.operation == CHAOS_TIME_OP_USLEEP);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_USLEEP, 0, &rank));

    assert(!chaos_time_selector_parse("clock_gettime/", &selector));
    assert(!chaos_time_selector_parse("sleep", &selector));
    assert(!chaos_time_selector_parse("clock_gettime/bad-clock", &selector));
}

/**
 * @brief Invariant: line and buffer parsers accept valid rules and reject invalid forms.
 *
 * Triggering condition: `chaos_time_config_parse_line()` and
 *   `chaos_time_config_parse_buffer()` with representative valid and invalid inputs.
 *
 * Expected observable behaviour:
 * - Comment line → returns 0 (skipped).
 * - `*:ERRNO:EINVAL@0.5` → selector_kind=ANY, effect=ERRNO, errnum=EINVAL, probability=0.5.
 * - `clock_gettime:LATENCY:25` → effect=LATENCY, latency_ms=25, probability=1.0 (default).
 * - `clock_gettime/monotonic:OFFSET:-250@0.75` → kind=CLOCK_ID, effect=OFFSET,
 *   offset_ms=-250, probability=0.75.
 * - 11 invalid forms: bad selector, empty selector, unknown op "sleep", bad errno name,
 *   empty errno (via "@0.5"), out-of-range latency probability, bad offset text,
 *   empty offset (via "@0.25"), OFFSET on "*" (not allowed), OFFSET on "usleep" (not allowed),
 *   unknown effect name.
 * - 4-rule buffer → rule_count=4.
 * - No-newline EOF → 1 rule parsed.
 * - Buffer with bad line → negative.
 * - Comment-only buffer with one rule → rule_count=1.
 * - NULL guards for line and buffer parsers all return negative.
 */
static void test_parse_line_and_buffer(void)
{
    chaos_time_rule_t rule;
    chaos_time_rule_t rules[8];
    size_t rule_count = 0U;
    char comment_line[] = " #: ignored";
    char buffer[] = "*:ERRNO:EINVAL@0.5\n"
                    "clock_gettime/monotonic:OFFSET:-250@0.75\n"
                    "nanosleep:LATENCY:25\n"
                    "usleep:ERRNO:EINTR\n";

    assert(chaos_time_config_parse_line(comment_line, &rule) == 0);

    {
        char line[] = "*:ERRNO:EINVAL@0.5";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_TIME_SELECTOR_ANY);
        assert(rule.effect == CHAOS_TIME_EFFECT_ERRNO);
        assert(rule.errnum == EINVAL);
        assert(rule.probability == 0.5);
    }
    {
        char line[] = "clock_gettime:LATENCY:25";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.effect == CHAOS_TIME_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
        assert(rule.probability == 1.0);
    }
    {
        char line[] = "clock_gettime/monotonic:OFFSET:-250@0.75";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_TIME_SELECTOR_CLOCK_ID);
        assert(rule.effect == CHAOS_TIME_EFFECT_OFFSET);
        assert(rule.offset_ms == -250);
        assert(rule.probability == 0.75);
    }
    {
        char invalid_line[] = "bad";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = ":ERRNO:EINTR";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "sleep:ERRNO:EINTR";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:ERRNO:nope";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:ERRNO:@0.5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:LATENCY:25@2.0";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime/monotonic:OFFSET:bad";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime/monotonic:OFFSET:@0.25";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        /* OFFSET is not allowed on the wildcard selector */
        char invalid_line[] = "*:OFFSET:5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        /* OFFSET is not allowed on usleep (no clock_id) */
        char invalid_line[] = "usleep:OFFSET:5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:BOGUS:1";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 4U);

    {
        char buffer_no_newline[] = "usleep:ERRNO:EINTR";
        rule_count = 0U;
        assert(chaos_time_config_parse_buffer(buffer_no_newline, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    {
        char invalid_buffer[] = "usleep:ERRNO:EINTR\nbad";
        assert(chaos_time_config_parse_buffer(invalid_buffer, rules, &rule_count) < 0);
    }
    {
        char comment_buffer[] = "\n# ignored\nusleep:LATENCY:5\n";
        rule_count = 0U;
        assert(chaos_time_config_parse_buffer(comment_buffer, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    assert(chaos_time_config_parse_line(NULL, &rule) < 0);
    assert(chaos_time_config_parse_line(comment_line, NULL) < 0);
    assert(chaos_time_config_parse_buffer(NULL, rules, &rule_count) < 0);
    assert(chaos_time_config_parse_buffer(buffer, NULL, &rule_count) < 0);
    assert(chaos_time_config_parse_buffer(buffer, rules, NULL) < 0);
}

/**
 * @brief Invariant: rule selection honours rank hierarchy and `selector_len` tie-break.
 *
 * Triggering condition: `chaos_time_config_select_rule()` against a 4-rule set containing
 *   one ANY rule, one OPERATION rule, one CLOCK_ID rule, and one nanosleep LATENCY rule.
 *
 * Expected observable behaviour:
 * - CLOCK_GETTIME + CLOCK_MONOTONIC with ERRNO effect → clock_gettime/monotonic wins (rank 3),
 *   returns EINTR.
 * - CLOCK_GETTIME + CLOCK_REALTIME with ERRNO effect → operation selector wins (rank 2),
 *   returns EFAULT.
 * - USLEEP with ERRNO effect → ANY wins (rank 1), returns EINVAL.
 * - NANOSLEEP with LATENCY effect → direct OPERATION match, returns latency_ms=20.
 * - NULL rules / NULL output → false.
 * - Tie-break: two rules for CLOCK_GETTIME/CLOCK_REALTIME with selector_len 10 and 12 →
 *   the rule with selector_len=12 wins, returning EPERM.
 */
static void test_rule_selection(void)
{
    chaos_time_rule_t rules[4];
    chaos_time_rule_t tie_rules[2];
    chaos_time_rule_t rule;
    char tie_line[] = "clock_gettime:ERRNO:EFAULT";
    char any_line[] = "*:ERRNO:EINVAL";
    char clock_line[] = "clock_gettime:ERRNO:EFAULT";
    char exact_line[] = "clock_gettime/monotonic:ERRNO:EINTR";
    char nanosleep_line[] = "nanosleep:LATENCY:20";

    assert(chaos_time_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_time_config_parse_line(clock_line, &rules[1]) == 1);
    assert(chaos_time_config_parse_line(exact_line, &rules[2]) == 1);
    assert(chaos_time_config_parse_line(nanosleep_line, &rules[3]) == 1);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(rule.errnum == EINTR);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EFAULT);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule
    ));
    assert(rule.errnum == EINVAL);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &rule
    ));
    assert(rule.latency_ms == 20U);
    assert(!chaos_time_config_select_rule(
        NULL, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &rule
    ));
    assert(!chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, NULL
    ));

    (void)memset(tie_rules, 0, sizeof(tie_rules));
    assert(chaos_time_config_parse_line(tie_line, &tie_rules[0]) == 1);
    tie_rules[0].selector.selector_len = 10U;
    tie_rules[0].errnum = EINVAL;
    tie_rules[1] = tie_rules[0];
    tie_rules[1].selector.selector_len = 12U;
    tie_rules[1].errnum = EPERM;
    assert(chaos_time_config_select_rule(
        tie_rules, 2U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EPERM);
}

/**
 * @brief Invariant: the prepare/match pipeline handles all file-system and state-machine paths.
 *
 * Triggering condition: `chaos_time_config_prepare()` and `chaos_time_config_match()`
 *   called under various file conditions with fault flags set and cleared between calls.
 *
 * Expected observable behaviour:
 * - No config file → `prepare` returns false; `match` returns false.
 * - Valid OFFSET rule → `prepare` true; `match` returns offset_ms=500.
 * - `match_loaded` returns same; second `prepare` with same mtime → true without reload.
 * - New mtime (nanosleep:ERRNO:EINTR) → `match` updates; errnum=EINTR.
 * - `match` for non-loaded effect → false.
 * - Bad rule → `prepare` false; `match_loaded` false.
 * - Oversized file → `read_file` returns negative; `read_file(NULL)` negative.
 * - Open failure → `prepare` false; read failure (EIO) → false; CAS failure → false.
 * - Config file restored at test end.
 */
static void test_prepare_and_match(void)
{
    chaos_time_test_file_backup_t backup;
    chaos_time_rule_t rule;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);

    g_test_config_force_open_fail = 0;
    g_test_config_force_read_fail = 0;
    g_test_config_force_cas_fail = 0;
    chaos_time_config_init();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    assert(!chaos_time_config_prepare());
    assert(!chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule));

    write_config_text("clock_gettime/monotonic:OFFSET:500\n", 11);
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_match(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(rule.offset_ms == 500);
    assert(chaos_time_config_match_loaded(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(chaos_time_config_prepare());

    write_config_text("nanosleep:ERRNO:EINTR\n", 12);
    assert(chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &rule));
    assert(rule.errnum == EINTR);
    assert(!chaos_time_config_match(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));

    write_config_text("bad-rule\n", 16);
    assert(!chaos_time_config_prepare());
    assert(!chaos_time_config_match_loaded(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule)
    );

    {
        char large_config[CHAOS_TIME_MAX_CONFIG_BYTES + 1U];
        size_t index;
        size_t size = 0U;

        for (index = 0U; index < CHAOS_TIME_MAX_CONFIG_BYTES; ++index)
        {
            large_config[index] = 'a';
        }
        large_config[CHAOS_TIME_MAX_CONFIG_BYTES] = '\0';
        write_config_text(large_config, 17);
        assert(chaos_time_config_read_file(&size, chaos_time_config_observed_mtime()) < 0);
    }
    assert(chaos_time_config_read_file(NULL, chaos_time_config_observed_mtime()) < 0);

    write_config_text("usleep:LATENCY:10\n", 13);
    g_test_config_force_open_fail = 1;
    assert(!chaos_time_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("usleep:LATENCY:20\n", 14);
    assert(!chaos_time_config_prepare());
    g_test_config_force_read_fail = 0;

    g_test_config_force_cas_fail = 1;
    write_config_text("usleep:LATENCY:30\n", 15);
    assert(!chaos_time_config_prepare());
    g_test_config_force_cas_fail = 0;

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: rule buffer parser rejects input that exceeds `CHAOS_TIME_MAX_RULES`.
 *
 * Triggering condition: a dynamically allocated buffer containing exactly
 *   `CHAOS_TIME_MAX_RULES + 1` valid rule lines.
 *
 * Expected observable behaviour: `chaos_time_config_parse_buffer()` returns a negative
 *   value before the rules array would overflow.
 */
static void test_parse_buffer_limit(void)
{
    chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES + 1U];
    size_t rule_count = 0U;
    size_t capacity = (CHAOS_TIME_MAX_RULES + 1U) * sizeof("usleep:LATENCY:1\n");
    char *buffer = (char *)malloc(capacity);
    size_t offset = 0U;
    size_t index;

    assert(buffer != NULL);
    for (index = 0U; index <= CHAOS_TIME_MAX_RULES; ++index)
    {
        offset += (size_t)snprintf(buffer + offset, capacity - offset, "usleep:LATENCY:1\n");
    }

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) < 0);
    free(buffer);
}

/**
 * @brief Invariant: a caller that observes a reload in progress uses the current
 *   snapshot and never starts a second, concurrent reload.
 *
 * Triggering condition: `g_chaos_time_cached_mtime` holds `CHAOS_TIME_MTIME_RELOADING`
 *   (another thread owns the reload) while the observed mtime differs from it.
 *
 * Expected observable behaviour: `prepare()` leaves both the reload marker and the
 *   active snapshot index untouched. A CAS from RELOADING to RELOADING would succeed,
 *   so without an explicit check the caller would reload into the same inactive
 *   snapshot -- and through the same shared read buffer -- as the owning thread.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_time_config_init();
    active_index = g_chaos_time_active_config_index;
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    assert(chaos_time_config_observed_mtime() != CHAOS_TIME_MTIME_RELOADING);

    (void)chaos_time_config_prepare();

    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    assert(g_chaos_time_active_config_index == active_index);

    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;
}

/**
 * @brief Invariant: a failed config read keeps the active rules and is retried.
 *
 * Triggering condition: the file changes while `read()` fails.
 *
 * Expected observable behaviour: the previously loaded rule set stays active, the
 * cached stamp is not advanced, and the next call loads the new content.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();

    write_config_text("nanosleep:ERRNO:EINTR\n", 40);
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 1U);

    write_config_text("nanosleep:ERRNO:EINTR\nclock_gettime/monotonic:OFFSET:500\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 1U);
    assert(g_chaos_time_cached_mtime != chaos_time_config_observed_mtime());
    assert(g_chaos_time_cached_mtime != CHAOS_TIME_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: the change stamp sees writes within one mtime tick.
 *
 * Triggering condition: stat results that differ only in size or only in inode.
 *
 * Expected observable behaviour: each difference yields a different stamp.
 */
static void test_change_stamp_beyond_mtime(void)
{
    struct stat base;
    struct stat other;

    memset(&base, 0, sizeof(base));
    base.st_mtim.tv_sec = 50;
    base.st_size = 10;
    base.st_ino = 100;
    other = base;
    assert(chaos_time_config_hash_mtime(&base) == chaos_time_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_time_config_hash_mtime(&base) != chaos_time_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_time_config_hash_mtime(&base) != chaos_time_config_hash_mtime(&other));
}

/**
 * @brief Invariant: a child forked during a reload takes the orphaned claim over.
 *
 * Triggering condition: the cached stamp is RELOADING but the claim was recorded
 * by another process id, as a forked child sees it.
 *
 * Expected observable behaviour: `prepare()` reloads and publishes the file's rules;
 * a claim recorded by this process is left alone.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 60);

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    g_chaos_time_tls_prng_state = UINT64_C(42);
    chaos_time_config_after_fork();
    assert(g_chaos_time_tls_prng_state == 0U);
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_UNKNOWN);
    assert(g_chaos_time_hits_pid == (uint64_t)getpid());
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_cached_mtime == chaos_time_config_observed_mtime());
    chaos_time_config_after_fork();
    assert(g_chaos_time_cached_mtime == chaos_time_config_observed_mtime());

    /* A competing taker-over wins the release: this caller keeps the current snapshot. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_time_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* The claim belongs to this process: another of its threads is reloading. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: refreshing the config never changes the caller's errno.
 *
 * Triggering condition: `prepare()` with no config file, so its stat(2) fails with
 * ENOENT, and with a file to read.
 *
 * Expected observable behaviour: errno holds the caller's value afterwards.
 */
static void test_prepare_preserves_errno(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_time_config_prepare();
    assert(errno == EBADF);

    write_config_text("nanosleep:ERRNO:EINTR\n", 70);
    errno = EBADF;
    assert(chaos_time_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: a config read interrupted by a signal is retried, not treated as failure.
 *
 * Triggering condition: the first `read()` fails with EINTR.
 *
 * Expected observable behaviour: the rules are loaded as if nothing had happened.
 */
static void test_interrupted_read_is_retried(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_time_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_time_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: a file that changed while it was read is not used.
 *
 * Expected observable behaviour: reading with the stamp of the file as it is now
 * succeeds; reading with any other stamp (the file changed after the stat that
 * started the reload) fails, so the reload keeps the previous rules and retries.
 */
static void test_read_file_rejects_changed_file(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# stable\n", 41);
    stamp = chaos_time_config_observed_mtime();
    assert(chaos_time_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_time_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_TIME_STATUS_PATH, "r");
    size_t length;

    if (file == NULL)
    {
        return 0;
    }
    length = fread(buffer, 1U, size - 1U, file);
    buffer[length] = '\0';
    assert(fclose(file) == 0);
    return 1;
}

/**
 * @brief Invariant: a rejected line is recorded with its number, its text as written
 *   and the reason, and a full rule set followed by comments is still accepted.
 *
 * Triggering condition: a buffer whose fourth line is invalid and carries a comment;
 *   then exactly CHAOS_TIME_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES];
    char buffer[] = "# header\n\nnanosleep:ERRNO:EINTR\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_time_config_last_error();
    const size_t line_length = strlen("nanosleep:ERRNO:EINTR\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_TIME_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_TIME_MAX_RULES; ++index)
    {
        (void)strcat(many, "nanosleep:ERRNO:EINTR\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_time_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_TIME_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_TIME_MAX_RULES; ++index)
    {
        (void)strcat(many, "nanosleep:ERRNO:EINTR\n");
    }
    assert(chaos_time_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_TIME_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "nanosleep:ERRNO:EINTR") == 0);
    free(many);
}

/**
 * @brief Invariant: every load reports its outcome in the status file.
 *
 * Triggering condition: a rule file whose second line is invalid, then a valid rule
 *   file, then no rule file.
 *
 * Expected observable behaviour: state=error naming line 2 and its text, then
 *   state=ok with the rule count, both stamped with this process id; without a rule
 *   file the status file is removed.
 */
static void test_prepare_reports_status(void)
{
    char status[CHAOS_STATUS_BUFFER_SIZE];
    char expected[CHAOS_STATUS_BUFFER_SIZE];

    chaos_time_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("nanosleep:ERRNO:EINTR\n", 52);
    assert(chaos_time_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported, not silently re-read. */
    {
        FILE *large = fopen(CHAOS_TIME_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_TIME_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_TIME_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_TIME_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_TIME_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_TIME_CONFIG_PATH, 0700) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_TIME_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_TIME_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_TIME_CONFIG_PATH, 0) == 0);
        assert(chaos_time_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_TIME_CONFIG_PATH);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(!read_status_file(status, sizeof(status)));
}

/**
 * @brief Reads this process's hits file into @p buffer; returns 0 when it does not exist.
 */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_TIME_HITS_PREFIX, g_chaos_time_hits_file);
    file = fopen(path, "r");
    if (file == NULL)
    {
        return 0;
    }
    length = fread(buffer, 1U, size - 1U, file);
    buffer[length] = '\0';
    assert(fclose(file) == 0);
    return 1;
}

/**
 * @brief Invariant: every rule of a loaded snapshot counts its hits, the process
 *   reports the counts with the rule text, and a reload keeps the count of a rule
 *   that is still in the file.
 *
 * Triggering condition: one rule loaded and hit twice; then a second rule added
 *   and hit once.
 *
 * Expected observable behaviour: the hits file lists "2<TAB>rule # a", then also
 *   "1<TAB>rule # b" with the first count unchanged.
 */
static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_time_config_state_t *state;

    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR # a\n", 61);
    assert(chaos_time_config_prepare() == 1);
    state = (chaos_time_config_state_t *)chaos_time_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "nanosleep:ERRNO:EINTR # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n") == 0);

    write_config_text("nanosleep:ERRNO:EINTR # a\nnanosleep:ERRNO:EINTR # b\n", 62);
    assert(chaos_time_config_prepare() == 1);
    state = (chaos_time_config_state_t *)chaos_time_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_time_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_time_hits_writing = 0;
    assert(g_chaos_time_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_time_hits_total = CHAOS_HITS_EAGER;
    g_chaos_time_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_time_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n3\tnanosleep:ERRNO:EINTR # b\n") == 0);
    assert(g_chaos_time_hits_pending == 0);
    chaos_time_config_report_hits(NULL);
    g_chaos_time_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_time_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_time_config_after_fork();
    assert(g_chaos_time_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\tnanosleep:ERRNO:EINTR # a\n0\tnanosleep:ERRNO:EINTR # b\n") == 0);
    g_chaos_time_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_time_hits_pending = 1;
    g_chaos_time_hits_pid = (uint64_t)getpid() + 1U;
    chaos_time_config_report_hits(NULL);
    assert(g_chaos_time_hits_pending == 1);
    g_chaos_time_hits_pending = 0;
    g_chaos_time_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_TIME_HITS_PREFIX, g_chaos_time_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
}

/**
 * @brief Invariant: once rules are loaded, the rule file is looked at no more often
 *   than the check interval, and is looked at again once the interval has passed.
 *
 * Triggering condition: rules loaded; the rule file removed; prepare called right
 *   after a look, then again with the last look one interval ago.
 *
 * Expected observable behaviour: the first call still sees the loaded rules (no
 *   look), the second sees the file is gone.
 */
static void test_rule_file_check_is_throttled(void)
{
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 81);
    assert(chaos_time_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_time_check_interval_ns = UINT64_C(10000000000);
    g_chaos_time_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    assert(chaos_time_config_prepare() == 1);

    g_chaos_time_last_check_ns = chaos_clock_now_ns() - g_chaos_time_check_interval_ns;
    assert(chaos_time_config_prepare() == 0);
    g_chaos_time_check_interval_ns = 0U;
}

/**
 * @brief Invariant: qualifiers after a rule are parsed into its policy, and a bad
 *   qualifier rejects the line.
 *
 * Expected observable behaviour: every qualifier lands in the policy and the rule
 *   itself still parses; an unknown qualifier, qualifiers without a rule and an
 *   `@until` before its `@from` are rejected as invalid rules.
 */
static void test_rule_qualifiers(void)
{
    static chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES];
    char qualified[] =
        "nanosleep:ERRNO:EINTR @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "nanosleep:ERRNO:EINTR @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "nanosleep:ERRNO:EINTR @from=2000 @until=1000\n";
    char empty_first[] = "nanosleep:ERRNO:EINTR @first=0\n";
    size_t count = 0U;

    assert(chaos_time_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_time_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_time_config_last_error()->text, "nanosleep:ERRNO:EINTR @bogus=1") == 0);
    assert(chaos_time_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_time_config_last_error()->line == 2U);
    assert(chaos_time_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_time_config_parse_buffer(empty_first, rules, &count) == -1);
}

/**
 * @brief Invariant: REGRESS needs a clock_gettime selector and a positive jump.
 */
static void test_regress_rule(void)
{
    chaos_time_rule_t rule;
    char ok[] = "clock_gettime/monotonic:REGRESS:5000";
    char gated[] = "clock_gettime/realtime:REGRESS:250@0.5";
    char every_clock[] = "clock_gettime:REGRESS:250";
    char zero[] = "clock_gettime/monotonic:REGRESS:0";
    char negative[] = "clock_gettime/monotonic:REGRESS:-5";
    char sleep_rule[] = "nanosleep:REGRESS:5000";

    assert(chaos_time_config_parse_line(ok, &rule) == 1);
    assert(rule.effect == CHAOS_TIME_EFFECT_REGRESS && rule.offset_ms == 5000);
    assert(chaos_time_config_parse_line(gated, &rule) == 1);
    assert(rule.probability == 0.5);
    assert(chaos_time_config_parse_line(every_clock, &rule) == -1);
    assert(chaos_time_config_parse_line(zero, &rule) == -1);
    assert(chaos_time_config_parse_line(negative, &rule) == -1);
    assert(chaos_time_config_parse_line(sleep_rule, &rule) == -1);
}

/**
 * @brief Invariant: a rewrite in place within one mtime tick is still seen, and a
 *        provisional load that reads the file again unchanged keeps its snapshot.
 *
 * Triggering condition: a rule file loaded right after it was written, then
 * rewritten in place with the same size and its mtime set back to the first one,
 * so that mtime, size, inode and device all stay as they were.
 *
 * Expected observable behaviour: the load is provisional; reading the unchanged
 * file again keeps the snapshot; the rewrite is loaded; an mtime older than
 * the window ends the provisional state.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "nanosleep:ERRNO:EINTR\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_time_check_interval_ns;

    g_chaos_time_check_interval_ns = 0U;
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    chaos_time_config_init();
    file = fopen(CHAOS_TIME_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_TIME_CONFIG_PATH, &first) == 0);
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    /* Read again, nothing changed: the same snapshot stays. */
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* The same bytes but the first commented out, written in place, same mtime. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_TIME_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window: the load is final and not read again. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_TIME_CONFIG_PATH, times, 0) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(g_chaos_time_config_provisional == 0);

    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    g_chaos_time_check_interval_ns = interval;
}

/**
 * @brief Invariant: hits still pending when their interval is over are written by
 *        the next look at the rule file, not only by the next hit or at exit.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_time_check_interval_ns;

    g_chaos_time_check_interval_ns = 0U;
    g_chaos_time_hits_pid = (uint64_t)getpid();
    g_chaos_time_hits_pending = 1;
    g_chaos_time_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_hits_pending == 1);
    g_chaos_time_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_hits_pending == 0);
    g_chaos_time_check_interval_ns = interval;
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_time_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_regress_rule();
    test_read_file_rejects_changed_file();
    test_helper_functions();
    test_selector_matching();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    test_parse_buffer_limit();
    test_reload_in_progress_is_not_joined();
    test_read_failure_keeps_rules_and_retries();
    test_change_stamp_beyond_mtime();
    test_fork_takes_over_orphaned_reload();
    test_prepare_preserves_errno();
    test_interrupted_read_is_retried();
    test_racy_rewrite_is_seen();
    test_pending_hits_written_after_interval();
    return 0;
}
