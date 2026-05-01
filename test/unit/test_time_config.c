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
        assert(chaos_time_config_read_file(&size) < 0);
    }
    assert(chaos_time_config_read_file(NULL) < 0);

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

int main(void)
{
    test_helper_functions();
    test_selector_matching();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    test_parse_buffer_limit();
    return 0;
}
