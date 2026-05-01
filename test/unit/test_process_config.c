/**
 * @file test_process_config.c
 * @brief Unit tests for PROCESS-domain config parsing, rule selection, and reload state machine.
 *
 * Subsystem under test: `src/process/chaos_process_config.c`
 *
 * Coverage approach:
 * - Production source is included directly after replacing `open`, `read`, `close`, and
 *   `chaos_process_atomic_cas_u64` with test-controlled stubs. This exercises the full
 *   config pipeline (file I/O, parse, CAS-protected mtime tracking) without LD_PRELOAD.
 * - A local `write_config_text()` helper uses `futimens` to set deterministic mtime stamps,
 *   ensuring each successive config write triggers a reload.
 * - The existing config file at `CHAOS_PROCESS_CONFIG_PATH` is backed up and restored so
 *   tests do not leave side effects on the host filesystem.
 *
 * Properties under test:
 * - Primitive helpers: `is_blank_char`, `config_reset_state`, `trim`, `strip_comment`,
 *   `parse_errno_name` (symbolic, numeric "42", NULL, "bad"), `parse_probability`,
 *   `parse_latency`, `parse_fail_after_count`, `copy_text_value`,
 *   `parse_payload_probability` (bare / `value@p` / missing payload / out-of-range p),
 *   `parse_fail_after_value` (ERRNO,count format, missing comma, bad errno),
 *   `selector_parse` (7 operation names + "*", NULL, "", "bogus"),
 *   `split_rule_fields` (valid / NULL / missing-effect / one-colon),
 *   `selector_matches` (* matches any, name matches exact, non-matching name),
 *   mtime hash sentinels (`MTIME_MISSING`, `MTIME_UNKNOWN`, `MTIME_RELOADING`).
 * - Line and buffer parsing: ERRNO / LATENCY / FAIL_AFTER effects; 10 invalid-line categories;
 *   buffer with blank+comment lines; no-newline EOF; NULL guards.
 * - Rule selection: operation-specific rule beats ANY wildcard; `selector_len` tie-break;
 *   FAIL_AFTER and LATENCY effects resolved by operation.
 * - Prepare-and-match state machine: no-file → prepare fails; valid file loads; same mtime
 *   → prepare returns true without reload; new mtime → reloads; bad rule → prepare fails;
 *   oversized file → read_file fails; open/read/CAS failures all return false.
 * - Buffer limit: `CHAOS_PROCESS_MAX_RULES + 1` rules → parse_buffer returns negative.
 *
 * What is NOT tested here:
 * - Action helpers (probability, latency, errno, fail_after): tested in test_process_actions.c.
 * - Wrapper call paths: tested in test_chaos_process.c.
 */

#include "../support/test_process_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

/** @brief When non-zero, the open stub returns ENOENT rather than delegating to the real open. */
static int g_test_config_force_open_fail = 0;
/**
 * @brief When non-zero, the open stub returns `g_test_config_fake_fd` for every call;
 *   subsequent reads on that fd return EIO.
 */
static int g_test_config_force_read_fail = 0;
/** @brief When non-zero, the CAS stub always returns 0 (failure), blocking config reload. */
static int g_test_config_force_cas_fail = 0;
/**
 * @brief Sentinel file descriptor returned by the open stub when `g_test_config_force_read_fail`
 *   is set. Its value is deliberately outside normal fd ranges to avoid aliasing.
 */
static const int g_test_config_fake_fd = 9312;

/**
 * @brief Stub for `open(2)` / `open(2)` with O_CREAT.
 *
 * Behaviour depends on fault-injection flags:
 * - `g_test_config_force_open_fail`: returns -1 with errno=ENOENT.
 * - `g_test_config_force_read_fail`: returns `g_test_config_fake_fd` for any flags
 *   (the subsequent read stub will inject EIO on that fd).
 * - O_CREAT: extracts mode from va_args and delegates to the real `open`.
 * - Otherwise: delegates to the real `open` without mode.
 *
 * @param path   Filesystem path.
 * @param flags  Open flags.
 * @param ...    Optional mode_t argument when flags include O_CREAT.
 * @return Opened file descriptor, `g_test_config_fake_fd`, or -1 on injected failure.
 */
static int chaos_process_test_config_open(const char *path, int flags, ...)
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
 * returns -1 with errno=EIO without consuming any bytes. Otherwise delegates to the real read.
 *
 * @param fd      File descriptor.
 * @param buffer  Destination buffer.
 * @param count   Maximum bytes to read.
 * @return Bytes read, or -1 with errno=EIO on injected failure.
 */
static ssize_t chaos_process_test_config_read(int fd, void *buffer, size_t count)
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
 * returns 0 without calling the real close (the fake fd is not a real kernel fd).
 * Otherwise delegates to the real close.
 *
 * @param fd  File descriptor to close.
 * @return 0 on success (always, for the fake fd).
 */
static int chaos_process_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Stub for `chaos_process_atomic_cas_u64`.
 *
 * When `g_test_config_force_cas_fail` is non-zero, returns 0 (CAS failure) without touching
 * @p value. This exercises the code path where a concurrent reload wins the race, causing the
 * current prepare call to skip the update and return false.
 *
 * Otherwise delegates to the real `__sync_bool_compare_and_swap`.
 *
 * @param value     Pointer to the target 64-bit word.
 * @param expected  Value required for the swap to succeed.
 * @param desired   Value to write on success.
 * @return 1 if the swap succeeded, 0 if injected or if the current value differs from expected.
 */
static int
chaos_process_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_process_test_config_open
#define read chaos_process_test_config_read
#define close chaos_process_test_config_close
#define chaos_process_atomic_cas_u64 chaos_process_test_atomic_cas_u64
#include "../../src/process/chaos_process_config.c"
#undef chaos_process_atomic_cas_u64
#undef close
#undef read
#undef open

/**
 * @brief Heap snapshot of a config file for safe backup and restore.
 *
 * Used by `test_prepare_and_match` to preserve and restore the caller's config file so the
 * test does not corrupt the host filesystem state.
 */
typedef struct chaos_process_test_file_backup
{
    /** @brief Non-zero if the file existed at backup time. */
    int existed;
    /** @brief Heap-allocated copy of the file contents; NULL when `existed == 0`. */
    char *data;
    /** @brief Number of bytes in `data`. */
    size_t size;
} chaos_process_test_file_backup_t;

/**
 * @brief Read @p path into a heap snapshot stored in @p backup.
 *
 * If the file does not exist, sets `backup->existed = 0` and returns. Uses
 * `fread` in 256-byte chunks with `realloc` growth so it handles files of any size
 * without needing an `fstat` first.
 *
 * @param path    Path to back up.
 * @param backup  Output struct to populate; must be zero-initialised by caller.
 */
static void backup_file(const char *path, chaos_process_test_file_backup_t *backup)
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
 * @brief Restore a file from a heap snapshot previously created by `backup_file`.
 *
 * If `backup->existed == 0`, the file at @p path is removed. Otherwise it is
 * rewritten verbatim from `backup->data`.
 *
 * @param path    Filesystem path to restore.
 * @param backup  Snapshot to write (must come from `backup_file`).
 */
static void restore_file(const char *path, const chaos_process_test_file_backup_t *backup)
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
 * Sets all fields back to zero/NULL so the struct is safe to discard.
 *
 * @param backup  Snapshot to release.
 */
static void free_backup(chaos_process_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Write @p text to `CHAOS_PROCESS_CONFIG_PATH` with a deterministic mtime.
 *
 * Uses `futimens` on the open file descriptor before closing so that successive calls
 * with distinct @p stamp values produce distinct mtime hashes, reliably triggering a
 * reload regardless of the wall-clock resolution on the test host.
 *
 * @param text   NUL-terminated config text to write.
 * @param stamp  Seconds value used for both atime and mtime.
 */
static void write_config_text(const char *text, time_t stamp)
{
    FILE *file;
    struct timespec times[2];

    file = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");
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
 * - `trim` strips leading and trailing whitespace including \\r\\n; NULL input → NULL.
 * - `strip_comment` truncates at '#'; NULL input is a no-op.
 * - `parse_errno_name`: all 14 symbolic names return correct values; numeric "42" → 42;
 *   NULL → -1; "bad" → -1.
 * - `parse_probability`/`parse_latency`/`parse_fail_after_count`: NULL pointer args → error;
 *   valid strings → 0 return and correct output; out-of-range value → error.
 * - `copy_text_value`: NULL/empty/zero-size → error; valid → 0 and copy.
 * - `parse_payload_probability`: NULL → error; bare value → copies as-is with probability
 *   unchanged; "value@p" → extracts each part; empty payload → error; p > 1.0 → error.
 * - `parse_fail_after_value("EAGAIN,5", ...)` → errnum=EAGAIN, count=5; NULL/no-comma/
 *   empty-errno/bad-errno → error.
 * - `selector_parse`: 7 operation names, "*", and "" / NULL / "bogus" → correct true/false.
 * - `split_rule_fields`: valid three-field text → fills all three pointers; NULL line /
 *   one-colon / missing second colon → false.
 * - `selector_matches`: NULL → false; "*" matches any operation; named selector matches
 *   exact operation and rejects others.
 * - `config_hash_mtime(NULL)` → MTIME_MISSING; sentinel normalization never returns
 *   MTIME_UNKNOWN or MTIME_RELOADING; `hash_mtime(&zero_stat)` → non-zero.
 */
static void test_helper_functions(void)
{
    char trim_text[] = " \t value \r\n";
    char blank_text[] = " \t\r\n";
    char comment_text[] = "abc#def";
    char payload_text[] = "25@0.25";
    char no_probability_text[] = "42";
    char split_text[] = "pthread_create:FAIL_AFTER:EAGAIN,3@0.5";
    char missing_effect_text[] = "selector:value";
    char fail_after_payload[] = "EAGAIN,5";
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_PROCESS_MAX_VALUE];
    struct stat st;
    chaos_process_selector_t selector;
    chaos_process_config_state_t state;
    uint64_t fail_after_count = 0U;
    int errnum = 0;

    assert(chaos_process_is_blank_char(' '));
    assert(chaos_process_is_blank_char('\t'));
    assert(!chaos_process_is_blank_char('x'));

    chaos_process_config_reset_state(NULL, 1);
    (void)memset(&state, 0xff, sizeof(state));
    chaos_process_config_reset_state(&state, 0);
    assert(state.rule_count == 0U);
    assert(state.parse_ok == 0);

    assert(chaos_process_trim(NULL) == NULL);
    assert(strcmp(chaos_process_trim(trim_text), "value") == 0);
    assert(strcmp(chaos_process_trim(blank_text), "") == 0);
    chaos_process_strip_comment(NULL);
    chaos_process_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);

    assert(chaos_process_parse_errno_name(NULL) == -1);
    assert(chaos_process_parse_errno_name("EAGAIN") == EAGAIN);
    assert(chaos_process_parse_errno_name("ENOMEM") == ENOMEM);
    assert(chaos_process_parse_errno_name("EACCES") == EACCES);
    assert(chaos_process_parse_errno_name("ENOENT") == ENOENT);
    assert(chaos_process_parse_errno_name("EINTR") == EINTR);
    assert(chaos_process_parse_errno_name("ECHILD") == ECHILD);
    assert(chaos_process_parse_errno_name("EPERM") == EPERM);
    assert(chaos_process_parse_errno_name("ESRCH") == ESRCH);
    assert(chaos_process_parse_errno_name("EBUSY") == EBUSY);
    assert(chaos_process_parse_errno_name("EINVAL") == EINVAL);
    assert(chaos_process_parse_errno_name("ENOSYS") == ENOSYS);
    assert(chaos_process_parse_errno_name("EMFILE") == EMFILE);
    assert(chaos_process_parse_errno_name("ENFILE") == ENFILE);
    assert(chaos_process_parse_errno_name("E2BIG") == E2BIG);
    assert(chaos_process_parse_errno_name("42") == 42);
    assert(chaos_process_parse_errno_name("bad") == -1);

    assert(chaos_process_parse_probability(NULL, &(double){0.0}) != 0);
    assert(chaos_process_parse_probability("0.5", NULL) != 0);
    assert(chaos_process_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_process_parse_probability("2.0", &(double){0.0}) != 0);

    assert(chaos_process_parse_latency(NULL, &(unsigned int){0U}) != 0);
    assert(chaos_process_parse_latency("25", NULL) != 0);
    assert(chaos_process_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_process_parse_latency("bad", &(unsigned int){0U}) != 0);

    assert(chaos_process_parse_fail_after_count(NULL, &fail_after_count) != 0);
    assert(chaos_process_parse_fail_after_count("12", NULL) != 0);
    assert(chaos_process_parse_fail_after_count("12", &fail_after_count) == 0);
    assert(fail_after_count == 12U);
    assert(chaos_process_parse_fail_after_count("bad", &fail_after_count) != 0);

    assert(chaos_process_copy_text_value(NULL, payload, sizeof(payload)) != 0);
    assert(chaos_process_copy_text_value("abc", NULL, sizeof(payload)) != 0);
    assert(chaos_process_copy_text_value("abc", payload, 0U) != 0);
    assert(chaos_process_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_process_copy_text_value("", payload, sizeof(payload)) != 0);

    assert(
        chaos_process_parse_payload_probability(NULL, payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_process_parse_payload_probability(
            no_probability_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "42") == 0);
    assert(
        chaos_process_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "25") == 0);
    assert(
        chaos_process_parse_payload_probability(
            "@0.25", payload, sizeof(payload), &(double){0.0}
        ) != 0
    );
    assert(
        chaos_process_parse_payload_probability(
            "25@2.0", payload, sizeof(payload), &(double){0.0}
        ) != 0
    );

    assert(
        chaos_process_parse_fail_after_value(fail_after_payload, &errnum, &fail_after_count) == 0
    );
    assert(errnum == EAGAIN);
    assert(fail_after_count == 5U);
    assert(chaos_process_parse_fail_after_value(NULL, &errnum, &fail_after_count) != 0);
    assert(chaos_process_parse_fail_after_value("missing-comma", &errnum, &fail_after_count) != 0);
    {
        char missing_errno[] = ",5";
        assert(
            chaos_process_parse_fail_after_value(missing_errno, &errnum, &fail_after_count) != 0
        );
    }
    {
        char bad_errno[] = "BAD,5";
        assert(chaos_process_parse_fail_after_value(bad_errno, &errnum, &fail_after_count) != 0);
    }

    assert(!chaos_process_selector_parse(NULL, &selector));
    assert(!chaos_process_selector_parse("", &selector));
    assert(!chaos_process_selector_parse("bogus", &selector));
    assert(chaos_process_selector_parse("*", &selector));
    assert(chaos_process_selector_parse("pthread_create", &selector));
    assert(chaos_process_selector_parse("fork", &selector));
    assert(chaos_process_selector_parse("posix_spawn", &selector));
    assert(chaos_process_selector_parse("posix_spawnp", &selector));
    assert(chaos_process_selector_parse("execve", &selector));
    assert(chaos_process_selector_parse("execveat", &selector));
    assert(chaos_process_selector_parse("waitpid", &selector));

    assert(chaos_process_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "pthread_create") == 0);
    assert(strcmp(effect_text, "FAIL_AFTER") == 0);
    assert(strcmp(value_text, "EAGAIN,3@0.5") == 0);
    assert(!chaos_process_split_rule_fields(NULL, &selector_text, &effect_text, &value_text));
    assert(!chaos_process_split_rule_fields(split_text, NULL, &effect_text, &value_text));
    assert(!chaos_process_split_rule_fields("bad", &selector_text, &effect_text, &value_text));
    assert(!chaos_process_split_rule_fields(
        missing_effect_text, &selector_text, &effect_text, &value_text
    ));

    assert(!chaos_process_selector_matches(NULL, CHAOS_PROCESS_OP_FORK, &((unsigned int){0U})));
    assert(chaos_process_selector_parse("*", &selector));
    assert(
        chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_WAITPID, &((unsigned int){0U}))
    );
    assert(chaos_process_selector_parse("fork", &selector));
    assert(chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_FORK, &((unsigned int){0U})));
    assert(
        !chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_EXECVE, &((unsigned int){0U}))
    );

    (void)memset(&st, 0, sizeof(st));
    assert(chaos_process_config_hash_mtime(NULL) == CHAOS_PROCESS_MTIME_MISSING);
    assert(
        chaos_process_config_normalize_mtime_hash(CHAOS_PROCESS_MTIME_UNKNOWN) !=
        CHAOS_PROCESS_MTIME_UNKNOWN
    );
    assert(
        chaos_process_config_normalize_mtime_hash(CHAOS_PROCESS_MTIME_RELOADING) !=
        CHAOS_PROCESS_MTIME_RELOADING
    );
    assert(chaos_process_config_hash_mtime(&st) != 0U);
}

/**
 * @brief Invariant: line and buffer parsers accept valid rules and reject invalid forms.
 *
 * Triggering condition: `chaos_process_config_parse_line()` and
 *   `chaos_process_config_parse_buffer()` with representative valid and invalid inputs.
 *
 * Expected observable behaviour:
 * - Comment line → returns 0 (skipped, no rule output).
 * - `*:ERRNO:EAGAIN@0.5` → selector_kind=ANY, effect=ERRNO, errnum=EAGAIN, probability=0.5.
 * - `fork:LATENCY:25` → operation=FORK, effect=LATENCY, latency_ms=25.
 * - `pthread_create:FAIL_AFTER:EAGAIN,2@0.5` → operation=PTHREAD_CREATE, effect=FAIL_AFTER,
 *   errnum=EAGAIN, fail_after_count=2, probability=0.5.
 * - 10 invalid-line forms all return negative: bad selector, empty selector, unknown selector,
 *   unknown effect, bad errno, out-of-range probability (ERRNO and LATENCY and FAIL_AFTER),
 *   bad latency, FAIL_AFTER without comma.
 * - 4-rule buffer with newline → rule_count=4.
 * - No-newline EOF: single rule parsed correctly.
 * - Buffer with blank line and comment: blank+comment skipped, one rule emitted.
 * - Buffer with a bad line: returns negative.
 * - NULL guards for both line and buffer parsers all return negative.
 */
static void test_parse_line_and_buffer(void)
{
    chaos_process_rule_t rule;
    chaos_process_rule_t rules[8];
    size_t rule_count = 0U;
    char comment_line[] = " #: ignored";
    char buffer[] = "*:ERRNO:EAGAIN@0.5\n"
                    "pthread_create:FAIL_AFTER:EAGAIN,1\n"
                    "fork:LATENCY:25\n"
                    "waitpid:ERRNO:EINTR\n";

    assert(chaos_process_config_parse_line(comment_line, &rule) == 0);

    {
        char line[] = "*:ERRNO:EAGAIN@0.5";
        assert(chaos_process_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_PROCESS_SELECTOR_ANY);
        assert(rule.effect == CHAOS_PROCESS_EFFECT_ERRNO);
        assert(rule.errnum == EAGAIN);
        assert(rule.probability == 0.5);
    }
    {
        char line[] = "fork:LATENCY:25";
        assert(chaos_process_config_parse_line(line, &rule) == 1);
        assert(rule.selector.operation == CHAOS_PROCESS_OP_FORK);
        assert(rule.effect == CHAOS_PROCESS_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
    }
    {
        char line[] = "pthread_create:FAIL_AFTER:EAGAIN,2@0.5";
        assert(chaos_process_config_parse_line(line, &rule) == 1);
        assert(rule.selector.operation == CHAOS_PROCESS_OP_PTHREAD_CREATE);
        assert(rule.effect == CHAOS_PROCESS_EFFECT_FAIL_AFTER);
        assert(rule.errnum == EAGAIN);
        assert(rule.fail_after_count == 2U);
        assert(rule.probability == 0.5);
    }
    {
        char invalid_line[] = "bad";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = ":ERRNO:EAGAIN";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "bogus:ERRNO:EAGAIN";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:BOGUS:1";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:ERRNO:nope";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:ERRNO:EAGAIN@2.0";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:LATENCY:bad";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:LATENCY:25@2.0";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:FAIL_AFTER:EAGAIN";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "fork:FAIL_AFTER:EAGAIN,1@2.0";
        assert(chaos_process_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_process_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 4U);

    {
        char buffer_no_newline[] = "waitpid:ERRNO:EINTR";
        rule_count = 0U;
        assert(chaos_process_config_parse_buffer(buffer_no_newline, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    {
        char buffer_with_blank[] = "\n# ignored\nwaitpid:ERRNO:EINTR\n";
        rule_count = 0U;
        assert(chaos_process_config_parse_buffer(buffer_with_blank, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    {
        char invalid_buffer[] = "waitpid:ERRNO:EINTR\nbad";
        assert(chaos_process_config_parse_buffer(invalid_buffer, rules, &rule_count) < 0);
    }

    assert(chaos_process_config_parse_line(NULL, &rule) < 0);
    assert(chaos_process_config_parse_line(comment_line, NULL) < 0);
    assert(chaos_process_config_parse_buffer(NULL, rules, &rule_count) < 0);
    assert(chaos_process_config_parse_buffer(buffer, NULL, &rule_count) < 0);
    assert(chaos_process_config_parse_buffer(buffer, rules, NULL) < 0);
}

/**
 * @brief Invariant: rule selection prefers operation-specific rules over wildcard ANY,
 *   and resolves ties by `selector_len`.
 *
 * Triggering condition: `chaos_process_config_select_rule()` against a 5-rule set
 *   containing one ANY rule and four operation-specific rules.
 *
 * Expected observable behaviour:
 * - `pthread_create` with ERRNO effect → returns ENOMEM (operation-specific wins over ANY EAGAIN).
 * - `posix_spawn` with ERRNO effect → falls back to ANY rule, returns EAGAIN.
 * - `fork` with LATENCY effect → returns latency_ms=10 (direct match).
 * - `execve` with FAIL_AFTER effect → returns fail_after_count=2.
 * - NULL rules pointer or NULL output rule → returns false.
 * - Tie-break: two rules for `waitpid` with selector_len 7 and 8 → the rule with
 *   selector_len=8 wins, returning ECHILD.
 */
static void test_rule_selection(void)
{
    chaos_process_rule_t rules[5];
    chaos_process_rule_t tie_rules[2];
    chaos_process_rule_t rule;
    char tie_line[] = "waitpid:ERRNO:EINTR";
    char any_line[] = "*:ERRNO:EAGAIN";
    char thread_line[] = "pthread_create:ERRNO:ENOMEM";
    char fork_line[] = "fork:LATENCY:10";
    char exec_line[] = "execve:FAIL_AFTER:EACCES,2";
    char wait_line[] = "waitpid:ERRNO:EINTR";

    assert(chaos_process_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_process_config_parse_line(thread_line, &rules[1]) == 1);
    assert(chaos_process_config_parse_line(fork_line, &rules[2]) == 1);
    assert(chaos_process_config_parse_line(exec_line, &rules[3]) == 1);
    assert(chaos_process_config_parse_line(wait_line, &rules[4]) == 1);

    assert(chaos_process_config_select_rule(
        rules, 5U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_PTHREAD_CREATE, &rule
    ));
    assert(rule.errnum == ENOMEM);

    assert(chaos_process_config_select_rule(
        rules, 5U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_POSIX_SPAWN, &rule
    ));
    assert(rule.errnum == EAGAIN);

    assert(chaos_process_config_select_rule(
        rules, 5U, CHAOS_PROCESS_EFFECT_LATENCY, CHAOS_PROCESS_OP_FORK, &rule
    ));
    assert(rule.latency_ms == 10U);

    assert(chaos_process_config_select_rule(
        rules, 5U, CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_EXECVE, &rule
    ));
    assert(rule.fail_after_count == 2U);

    assert(!chaos_process_config_select_rule(
        NULL, 5U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &rule
    ));
    assert(!chaos_process_config_select_rule(
        rules, 5U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, NULL
    ));

    (void)memset(tie_rules, 0, sizeof(tie_rules));
    assert(chaos_process_config_parse_line(tie_line, &tie_rules[0]) == 1);
    tie_rules[0].selector.selector_len = 7U;
    tie_rules[0].errnum = EINTR;
    tie_rules[1] = tie_rules[0];
    tie_rules[1].selector.selector_len = 8U;
    tie_rules[1].errnum = ECHILD;
    assert(chaos_process_config_select_rule(
        tie_rules, 2U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &rule
    ));
    assert(rule.errnum == ECHILD);
}

/**
 * @brief Invariant: the prepare/match pipeline handles all file-system and state-machine paths.
 *
 * Triggering condition: `chaos_process_config_prepare()` and `chaos_process_config_match()`
 *   called under various file conditions with fault flags set and cleared between calls.
 *
 * Expected observable behaviour:
 * - No config file → `prepare` returns false; `match` returns false.
 * - `match(..., NULL)` → false (NULL output guard).
 * - Valid ERRNO rule for `fork:ERRNO:EAGAIN` → `prepare` true; `match` true; errnum=EAGAIN.
 * - `match_loaded` (bypass prepare) returns same result.
 * - Second `prepare` with same mtime → returns true without reload.
 * - New mtime with FAIL_AFTER rule → `match` updates and returns fail_after_count=1.
 * - Bad rule → `prepare` returns false; `match_loaded` returns false.
 * - File exceeding `CHAOS_PROCESS_MAX_CONFIG_BYTES` → `read_file` returns negative.
 * - `read_file(NULL)` → returns negative.
 * - Open failure → `prepare` returns false.
 * - Read failure (EIO) → `prepare` returns false.
 * - CAS failure → `prepare` returns false (concurrent-reload simulation).
 * - Config file is restored to its original contents at test end.
 */
static void test_prepare_and_match(void)
{
    chaos_process_test_file_backup_t backup;
    chaos_process_rule_t rule;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);

    g_test_config_force_open_fail = 0;
    g_test_config_force_read_fail = 0;
    g_test_config_force_cas_fail = 0;
    chaos_process_config_init();
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    assert(!chaos_process_config_prepare());
    assert(!chaos_process_config_match(CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, &rule));
    assert(!chaos_process_config_match(CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, NULL));

    write_config_text("fork:ERRNO:EAGAIN\n", 11);
    assert(chaos_process_config_prepare());
    assert(chaos_process_config_match(CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, &rule));
    assert(rule.errnum == EAGAIN);
    assert(
        chaos_process_config_match_loaded(CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, &rule)
    );
    assert(chaos_process_config_prepare());

    write_config_text("pthread_create:FAIL_AFTER:EAGAIN,1\n", 12);
    assert(chaos_process_config_match(
        CHAOS_PROCESS_EFFECT_FAIL_AFTER, CHAOS_PROCESS_OP_PTHREAD_CREATE, &rule
    ));
    assert(rule.fail_after_count == 1U);

    write_config_text("bad-rule\n", 13);
    assert(!chaos_process_config_prepare());
    assert(
        !chaos_process_config_match_loaded(CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_FORK, &rule)
    );

    {
        char large_config[CHAOS_PROCESS_MAX_CONFIG_BYTES + 1U];
        size_t size = 0U;

        (void)memset(large_config, 'a', sizeof(large_config) - 1U);
        large_config[sizeof(large_config) - 1U] = '\0';
        write_config_text(large_config, 14);
        assert(chaos_process_config_read_file(&size) < 0);
    }
    assert(chaos_process_config_read_file(NULL) < 0);

    write_config_text("waitpid:ERRNO:EINTR\n", 15);
    g_test_config_force_open_fail = 1;
    assert(!chaos_process_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("waitpid:ERRNO:EINTR\n", 16);
    assert(!chaos_process_config_prepare());
    g_test_config_force_read_fail = 0;

    g_test_config_force_cas_fail = 1;
    write_config_text("waitpid:ERRNO:EINTR\n", 17);
    assert(!chaos_process_config_prepare());
    g_test_config_force_cas_fail = 0;

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: rule buffer parser rejects input that exceeds `CHAOS_PROCESS_MAX_RULES`.
 *
 * Triggering condition: a dynamically allocated buffer containing exactly
 *   `CHAOS_PROCESS_MAX_RULES + 1` valid rule lines.
 *
 * Expected observable behaviour: `chaos_process_config_parse_buffer()` returns a negative
 *   value before the rules array would overflow.
 */
static void test_parse_buffer_limit(void)
{
    chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES + 1U];
    size_t rule_count = 0U;
    size_t capacity = (CHAOS_PROCESS_MAX_RULES + 1U) * sizeof("waitpid:ERRNO:EINTR\n");
    char *buffer = (char *)malloc(capacity);
    size_t offset = 0U;
    size_t index;

    assert(buffer != NULL);
    for (index = 0U; index <= CHAOS_PROCESS_MAX_RULES; ++index)
    {
        offset += (size_t)snprintf(buffer + offset, capacity - offset, "waitpid:ERRNO:EINTR\n");
    }

    assert(chaos_process_config_parse_buffer(buffer, rules, &rule_count) < 0);
    free(buffer);
}

int main(void)
{
    test_helper_functions();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    test_parse_buffer_limit();
    return 0;
}
