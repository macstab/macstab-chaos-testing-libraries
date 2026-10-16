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

/* The rule file is read through these stubs (defined below) instead of raw system calls. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* A rule file counts as just written for 5 s, not 20 ms: the racily-clean tests
 * restore an earlier mtime and must find it still recent on a slow machine. */
#define CHAOS_RACY_WINDOW_MS 5000
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

/** Number of upcoming config reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;

/** Number of upcoming config opens that fail with EINTR, as a signal would make them. */
static int g_test_config_open_eintr = 0;

/** When non-zero, the open stub fails with this errno (EACCES, EPERM, ...). */
static int g_test_config_open_errno = 0;
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
 * - `g_test_config_open_eintr` positive: consumes one and fails with EINTR.
 * - `g_test_config_open_errno`: returns -1 with that errno.
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
    if (g_test_config_open_eintr > 0)
    {
        --g_test_config_open_eintr;
        errno = EINTR;
        return -1;
    }
    if (g_test_config_open_errno != 0)
    {
        errno = g_test_config_open_errno;
        return -1;
    }
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
    /* The count is digits: no sign (strtoull would read -1 as the largest count,
     * one that never fails), nothing past 64 bits, which would be cut to them. */
    {
        static const char *const counts[] = {
            "fork:FAIL_AFTER:EAGAIN,-1",
            "fork:FAIL_AFTER:EAGAIN,+1",
            "fork:FAIL_AFTER:EAGAIN,x",
            "fork:FAIL_AFTER:EAGAIN,18446744073709551616",
        };
        char largest[] = "fork:FAIL_AFTER:EAGAIN, 18446744073709551615";
        size_t index;

        for (index = 0U; index < sizeof(counts) / sizeof(counts[0]); ++index)
        {
            char line[64];

            (void)strcpy(line, counts[index]);
            errno = 1234;
            assert(chaos_process_config_parse_line(line, &rule) < 0);
            assert(errno == 1234);
        }
        assert(chaos_process_config_parse_line(largest, &rule) == 1);
        assert(rule.fail_after_count == UINT64_MAX);
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
    char late_any_line[] = "*:ERRNO:EAGAIN";

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

    /* Listed the other way round, the shorter selector of the same rank does not
     * replace the longer one... */
    tie_rules[1] = tie_rules[0];
    tie_rules[0].selector.selector_len = 8U;
    tie_rules[0].errnum = ECHILD;
    tie_rules[1].selector.selector_len = 7U;
    tie_rules[1].errnum = EINTR;
    assert(chaos_process_config_select_rule(
        tie_rules, 2U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &rule
    ));
    assert(rule.errnum == ECHILD);

    /* ...nor does a less specific selector listed after a more specific one. */
    assert(chaos_process_config_parse_line(late_any_line, &tie_rules[1]) == 1);
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
        assert(chaos_process_config_read_file(&size, chaos_process_config_observed_mtime()) < 0);
    }
    assert(chaos_process_config_read_file(NULL, chaos_process_config_observed_mtime()) < 0);

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

/**
 * @brief Invariant: a caller that observes a reload in progress uses the current
 *   snapshot and never starts a second, concurrent reload.
 *
 * Triggering condition: `g_chaos_process_cached_mtime` holds `CHAOS_PROCESS_MTIME_RELOADING`
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

    chaos_process_config_init();
    active_index = g_chaos_process_active_config_index;
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    assert(chaos_process_config_observed_mtime() != CHAOS_PROCESS_MTIME_RELOADING);

    (void)chaos_process_config_prepare();

    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    assert(g_chaos_process_active_config_index == active_index);

    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
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
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();

    write_config_text("fork:ERRNO:EAGAIN\n", 40);
    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 1U);

    write_config_text("fork:ERRNO:EAGAIN\npthread_create:FAIL_AFTER:EAGAIN,1\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 1U);
    assert(g_chaos_process_cached_mtime != chaos_process_config_observed_mtime());
    assert(g_chaos_process_cached_mtime != CHAOS_PROCESS_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
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
    assert(chaos_process_config_hash_mtime(&base) == chaos_process_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_process_config_hash_mtime(&base) != chaos_process_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_process_config_hash_mtime(&base) != chaos_process_config_hash_mtime(&other));
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
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 60);

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    g_chaos_process_tls_prng_state = UINT64_C(42);
    g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] = 7U;
    chaos_process_config_after_fork();
    assert(g_chaos_process_tls_prng_state == 0U);
    assert(g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] == 0U);
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_UNKNOWN);
    assert(g_chaos_process_hits_pid == (uint64_t)getpid());
    assert(chaos_process_config_prepare());
    assert(g_chaos_process_cached_mtime == chaos_process_config_observed_mtime());
    chaos_process_config_after_fork();
    assert(g_chaos_process_cached_mtime == chaos_process_config_observed_mtime());

    /* A competing taker-over wins the release: this caller keeps the current snapshot. */
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_process_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* The claim belongs to this process: another of its threads is reloading. */
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
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
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_process_config_prepare();
    assert(errno == EBADF);

    write_config_text("fork:ERRNO:EAGAIN\n", 70);
    errno = EBADF;
    assert(chaos_process_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
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
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_process_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_process_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
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
    stamp = chaos_process_config_observed_mtime();
    assert(chaos_process_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_process_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_PROCESS_STATUS_PATH, "r");
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
 *   then exactly CHAOS_PROCESS_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    char buffer[] = "# header\n\nfork:ERRNO:EAGAIN\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_process_config_last_error();
    const size_t line_length = strlen("fork:ERRNO:EAGAIN\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_process_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_PROCESS_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_PROCESS_MAX_RULES; ++index)
    {
        (void)strcat(many, "fork:ERRNO:EAGAIN\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_process_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_PROCESS_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_PROCESS_MAX_RULES; ++index)
    {
        (void)strcat(many, "fork:ERRNO:EAGAIN\n");
    }
    assert(chaos_process_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_PROCESS_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "fork:ERRNO:EAGAIN") == 0);
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

    chaos_process_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("fork:ERRNO:EAGAIN\n", 52);
    assert(chaos_process_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported, not silently re-read. */
    {
        FILE *large = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_PROCESS_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_PROCESS_CONFIG_PATH, 0700) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_PROCESS_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_PROCESS_CONFIG_PATH, 0) == 0);
        assert(chaos_process_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    }
    assert(chaos_process_config_prepare() == 0);
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

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_PROCESS_HITS_PREFIX, g_chaos_process_hits_file);
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
    chaos_process_config_state_t *state;

    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN # a\n", 61);
    assert(chaos_process_config_prepare() == 1);
    state = (chaos_process_config_state_t *)chaos_process_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "fork:ERRNO:EAGAIN # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n") == 0);

    write_config_text("fork:ERRNO:EAGAIN # a\nfork:ERRNO:EAGAIN # b\n", 62);
    assert(chaos_process_config_prepare() == 1);
    state = (chaos_process_config_state_t *)chaos_process_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_process_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_process_hits_writing = 0;
    assert(g_chaos_process_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_process_hits_total = CHAOS_HITS_EAGER;
    g_chaos_process_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_process_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n3\tfork:ERRNO:EAGAIN # b\n") == 0);
    assert(g_chaos_process_hits_pending == 0);
    chaos_process_config_report_hits(NULL);

    /* Past the eager hits, a hit once the interval is over is written at once. */
    g_chaos_process_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n4\tfork:ERRNO:EAGAIN # b\n") == 0);
    assert(g_chaos_process_hits_pending == 0);
    g_chaos_process_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_process_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_process_config_after_fork();
    assert(g_chaos_process_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\tfork:ERRNO:EAGAIN # a\n0\tfork:ERRNO:EAGAIN # b\n") == 0);
    g_chaos_process_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_process_hits_pending = 1;
    g_chaos_process_hits_pid = (uint64_t)getpid() + 1U;
    chaos_process_config_report_hits(NULL);
    assert(g_chaos_process_hits_pending == 1);
    g_chaos_process_hits_pending = 0;
    g_chaos_process_hits_pid = (uint64_t)getpid();

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_PROCESS_HITS_PREFIX, g_chaos_process_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
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
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 81);
    assert(chaos_process_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_process_check_interval_ns = UINT64_C(10000000000);
    g_chaos_process_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    assert(chaos_process_config_prepare() == 1);

    g_chaos_process_last_check_ns = chaos_clock_now_ns() - g_chaos_process_check_interval_ns;
    assert(chaos_process_config_prepare() == 0);
    g_chaos_process_check_interval_ns = 0U;
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
    static chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    char qualified[] =
        "fork:ERRNO:EAGAIN @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "fork:ERRNO:EAGAIN @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "fork:ERRNO:EAGAIN @from=2000 @until=1000\n";
    char empty_first[] = "fork:ERRNO:EAGAIN @first=0\n";
    size_t count = 0U;

    assert(chaos_process_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_process_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_process_config_last_error()->text, "fork:ERRNO:EAGAIN @bogus=1") == 0);
    assert(chaos_process_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_process_config_last_error()->line == 2U);
    assert(chaos_process_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_process_config_parse_buffer(empty_first, rules, &count) == -1);
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
 * file again keeps the snapshot and its FAIL_AFTER counters; the rewrite is loaded; an mtime older
 * than the window ends the provisional state.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "fork:ERRNO:EAGAIN\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_process_check_interval_ns;

    g_chaos_process_check_interval_ns = 0U;
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    chaos_process_config_init();
    file = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_PROCESS_CONFIG_PATH, &first) == 0);
    assert(chaos_process_config_prepare());
    assert(g_chaos_process_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);
    g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] = 3U;

    /* Read again, nothing changed: the same snapshot stays. */
    assert(chaos_process_config_prepare());
    assert(g_chaos_process_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));
    assert(g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] == 3U);

    /* The same bytes but the first commented out, written in place, same mtime. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_PROCESS_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window: the load is final and not read again. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_PROCESS_CONFIG_PATH, times, 0) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(g_chaos_process_config_provisional == 0);

    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    g_chaos_process_check_interval_ns = interval;
}

/**
 * @brief Invariant: hits still pending when their interval is over are written by
 *        the next look at the rule file, not only by the next hit or at exit.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_process_check_interval_ns;

    g_chaos_process_check_interval_ns = 0U;
    g_chaos_process_hits_pid = (uint64_t)getpid();
    g_chaos_process_hits_pending = 1;
    g_chaos_process_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_hits_pending == 1);
    g_chaos_process_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_hits_pending == 0);
    g_chaos_process_check_interval_ns = interval;
}

/**
 * @brief Invariant: the value parsers accept a value exactly at their limit and reject
 *   the first one beyond it, trailing garbage, empty halves and non-positive errno
 *   numbers.
 *
 * Expected observable behaviour:
 * - errno numbers: 2147483647 accepted; 0, -5, 2147483648 and "12x" rejected.
 * - latency: 4294967295 accepted; 4294967296 and "12x" rejected.
 * - FAIL_AFTER: "12x" as count, ",5" and "EAGAIN," rejected; a bad count or latency
 *   rejects the whole line.
 * - a value that fills its buffer exactly (no room for the terminator) is rejected,
 *   one byte shorter is accepted; the same holds for the payload before `@`.
 * - an empty effect or value field rejects the line.
 * - selector matching reports a match the same with or without a rank output.
 */
static void test_parse_boundaries(void)
{
    char payload[4];
    /* The parsers trim the text after the number in place, so it must be writable. */
    char errno_garbage[] = "12x";
    char latency_garbage[] = "12x";
    char count_garbage[] = "12x";
    char empty_errno[] = ",5";
    char empty_count[] = "EAGAIN,";
    char empty_effect_line[] = "fork::EAGAIN";
    char empty_value_line[] = "fork:ERRNO: ";
    char bad_latency_line[] = "fork:LATENCY:soon";
    char bad_count_line[] = "fork:FAIL_AFTER:EAGAIN,many";
    char split_line[] = "fork:ERRNO:EAGAIN";
    char *selector_text = NULL;
    char *effect_text = NULL;
    unsigned int latency = 0U;
    uint64_t count = 0U;
    int errnum = 0;
    double probability = 0.0;
    chaos_process_selector_t selector;
    chaos_process_rule_t rule;

    assert(chaos_process_parse_errno_name("2147483647") == 2147483647);
    assert(chaos_process_parse_errno_name("0") == -1);
    assert(chaos_process_parse_errno_name("-5") == -1);
    assert(chaos_process_parse_errno_name("2147483648") == -1);
    assert(chaos_process_parse_errno_name(errno_garbage) == -1);

    assert(chaos_process_parse_latency("4294967295", &latency) == 0);
    assert(latency == 4294967295U);
    assert(chaos_process_parse_latency("4294967296", &latency) != 0);
    assert(chaos_process_parse_latency(latency_garbage, &latency) != 0);
    assert(latency == 4294967295U);

    assert(chaos_process_parse_fail_after_count(count_garbage, &count) != 0);
    assert(chaos_process_parse_fail_after_value(empty_errno, &errnum, &count) != 0);
    assert(chaos_process_parse_fail_after_value(empty_count, &errnum, &count) != 0);
    assert(chaos_process_parse_fail_after_value(split_line, NULL, &count) != 0);
    assert(chaos_process_parse_fail_after_value(split_line, &errnum, NULL) != 0);
    assert(count == 0U);

    assert(chaos_process_copy_text_value("abcd", payload, sizeof(payload)) != 0);
    assert(chaos_process_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(strcmp(payload, "abc") == 0);
    assert(
        chaos_process_parse_payload_probability(
            "abcd@0.5", payload, sizeof(payload), &probability
        ) != 0
    );
    assert(
        chaos_process_parse_payload_probability(
            "abc@0.5", payload, sizeof(payload), &probability
        ) == 0
    );
    assert(strcmp(payload, "abc") == 0);
    assert(probability == 0.5);
    assert(
        chaos_process_parse_payload_probability("abc", NULL, sizeof(payload), &probability) != 0
    );
    assert(chaos_process_parse_payload_probability("abc", payload, sizeof(payload), NULL) != 0);

    assert(chaos_process_config_parse_line(empty_effect_line, &rule) < 0);
    assert(chaos_process_config_parse_line(empty_value_line, &rule) < 0);
    assert(chaos_process_config_parse_line(bad_latency_line, &rule) < 0);
    assert(chaos_process_config_parse_line(bad_count_line, &rule) < 0);
    assert(!chaos_process_split_rule_fields(split_line, &selector_text, &effect_text, NULL));
    assert(!chaos_process_split_rule_fields(split_line, &selector_text, NULL, NULL));
    assert(!chaos_process_selector_parse("*", NULL));

    assert(chaos_process_selector_parse("*", &selector));
    assert(chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_WAITPID, NULL));
    assert(chaos_process_selector_parse("fork", &selector));
    assert(chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_FORK, NULL));
    assert(!chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_EXECVE, NULL));
}

/**
 * @brief Invariant: opening the rule file is retried after a signal, a missing
 *   permission is reported as lasting, and other open errors as retryable.
 *
 * Triggering condition: the first open fails with EINTR; then every open fails with
 *   EACCES, EPERM, then EMFILE.
 *
 * Expected observable behaviour: the interrupted open is retried and the file read
 *   (0, its full size); EACCES and EPERM return -3; EMFILE returns -1.
 */
static void test_open_errors(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# open errors\n", 43);
    stamp = chaos_process_config_observed_mtime();
    g_test_config_open_eintr = 1;
    assert(chaos_process_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open errors\n"));

    g_test_config_open_errno = EACCES;
    assert(chaos_process_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_process_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_process_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_process_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_read_file_rejects_changed_file();
    test_helper_functions();
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
    test_parse_boundaries();
    test_open_errors();
    return 0;
}
