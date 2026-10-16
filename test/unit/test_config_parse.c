/**
 * @file test_config_parse.c
 * @brief Unit tests for IO-domain configuration parsing, buffer selection, file I/O, and
 *   hot-reload state machine.
 *
 * Subsystem under test: `src/config/chaos_io_config.c`
 *
 * Coverage approach:
 * - The production source file is included directly after three simple I/O stubs
 *   (`chaos_test_stub_open`, `chaos_test_stub_read`, `chaos_test_stub_close`) are defined.
 *   The stubs do not intercept by `#define` — instead the real-function-pointer globals
 *   (`g_chaos_io_real_open`, `g_chaos_io_real_read`, `g_chaos_io_real_close`) are reassigned
 *   at runtime, which is the same dispatch path used by the production library.
 * - Tests that require real filesystem access call `chaos_test_use_real_io()` to restore the
 *   libc function pointers, then `chaos_test_write_text_file()` to create the config file.
 * - `CHAOS_IO_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals required by
 *   the production config module.
 * - `g_config_backup` records the content of `CHAOS_IO_CONFIG_PATH` before the test suite
 *   runs; `chaos_test_restore_config_path()` is registered via `atexit()` to restore it
 *   regardless of how the process exits.
 *
 * Properties under test:
 * - Primitive helpers: `chaos_io_is_blank_char`, `chaos_io_trim` (NULL, whitespace-only,
 *   embedded whitespace), `chaos_io_strip_comment` (NULL, comment present),
 *   `chaos_io_config_reset_state` (NULL ignored; zero-initialises `rule_count` and `parse_ok`).
 * - `chaos_io_parse_operation`: all 14 valid names plus NULL and unrecognised string.
 * - `chaos_io_parse_errno_name`: 8 supported names (EIO through ENOENT), NULL → -1,
 *   unsupported name (EINVAL) → -1.
 * - `chaos_io_parse_probability`: NULL input or NULL output → -1; non-numeric suffix → -1;
 *   value > 1.0 → -1; valid string with trailing whitespace → 0, value stored.
 * - `chaos_io_parse_latency`: NULL, non-numeric, overflow (>UINT32_MAX), trailing whitespace,
 *   and NULL output pointer.
 * - `chaos_io_effect_allowed`: TORN only on write-class ops; CORRUPT only on read-class ops;
 *   INVALID → 0.
 * - Mtime sentinel normalisation: MISSING, RELOADING, UNKNOWN all map to non-sentinel values;
 *   regular hash passes through unchanged.
 * - Line parsing: 17 valid format variants (all operations × effects); comment lines → 0;
 *   empty lines → 0; and 16 invalid inputs → -1.
 * - Buffer parsing and rule selection: wildcard `*` prefix; most-specific path wins over
 *   shorter prefix; operation mismatch → no match.
 * - Buffer error paths: invalid rule resets `rule_count` to 0; rule count overflow.
 * - File read paths: NULL size_out; NULL real_open; open fails; open succeeds but read fails
 *   (verifying close is called); read returns `MAX_CONFIG_BYTES` (buffer full); real I/O
 *   with an actual file.
 * - Reload state machine: missing file → `MTIME_MISSING`; stub I/O reload → `rule_count == 0`;
 *   real file → prepare succeeds → match works; `MTIME_RELOADING` → prepare returns 1 without
 *   re-reading; invalid rule file with `MTIME_UNKNOWN` → prepare returns 0, match returns 0.
 *
 * What is NOT tested here:
 * - Wrapper call paths that invoke `chaos_io_config_match_path` at interception time.
 * - Thread-safety of the double-buffered config state (concurrent prepare/match races).
 * - Config file parsing through the full LD_PRELOAD constructor path.
 */

#include "../support/test_support.h"

#include <stdint.h>
#include <sys/stat.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

/**
 * @brief Result code returned by the open stub.
 *
 * Defaults to -1 (open fails). Set to a non-negative value to simulate a successful open
 * returning that file descriptor number.
 */
static int g_stub_open_result = -1;

/**
 * @brief errno value set by the open stub before returning.
 *
 * Defaults to EIO. Set before calling `chaos_io_config_read_file()` via stub I/O to control
 * the error code visible to the production code after a failed open.
 */
static int g_stub_open_errno = EIO;

/**
 * @brief Return value for the close stub.
 *
 * Defaults to 0 (success). Can be set to -1 to simulate a close failure, though the
 * production config reader does not inspect the close return value.
 */
static int g_stub_close_result = 0;

/**
 * @brief Number of times the close stub has been called since the last reset.
 *
 * Used to assert that the production code closes the file descriptor after a read failure
 * (i.e., the resource is not leaked on the error path).
 */
static int g_stub_close_calls = 0;

/**
 * @brief Result code returned by the read stub.
 *
 * Defaults to -1 (read fails). Set to `CHAOS_IO_MAX_CONFIG_BYTES` to simulate a completely
 * full buffer read, which should cause `chaos_io_config_read_file` to return -1.
 */
static ssize_t g_stub_read_result = -1;

/**
 * @brief errno value set by the read stub before returning.
 *
 * Defaults to EIO. Visible to the production code when `g_stub_read_result` is -1.
 */
static int g_stub_read_errno = EIO;

/**
 * @brief Number of times the read stub has been called since the last reset.
 *
 * Used to verify that `chaos_io_config_read_file` does not call read more than once
 * when the first read returns the full buffer capacity.
 */
static size_t g_stub_read_calls = 0U;

/**
 * @brief Stub open function controlled by `g_stub_open_result` and `g_stub_open_errno`.
 *
 * Always sets errno to `g_stub_open_errno` and returns `g_stub_open_result`, ignoring
 * `path` and `flags`. Used to inject open-failure scenarios without touching the filesystem.
 *
 * @param path  Ignored.
 * @param flags Ignored.
 * @return `g_stub_open_result`.
 */
static int chaos_test_stub_open(const char *path, int flags, ...)
{
    (void)path;
    (void)flags;
    errno = g_stub_open_errno;
    return g_stub_open_result;
}

/**
 * @brief Stub read function that counts calls and injects configurable errors.
 *
 * Increments `g_stub_read_calls`, sets errno to `g_stub_read_errno`, and returns
 * `g_stub_read_result` without inspecting `fd`, `buffer`, or `count`.
 *
 * @param fd      Ignored.
 * @param buffer  Ignored.
 * @param count   Ignored.
 * @return `g_stub_read_result`.
 */
static ssize_t chaos_test_stub_read(int fd, void *buffer, size_t count)
{
    (void)fd;
    (void)buffer;
    (void)count;
    ++g_stub_read_calls;
    errno = g_stub_read_errno;
    return g_stub_read_result;
}

/** Number of upcoming reads `chaos_test_eintr_read` fails with EINTR before reading for real. */
static int g_stub_read_eintr = 0;

/**
 * @brief Read that fails with EINTR `g_stub_read_eintr` times, as a signal would make it,
 * then reads for real.
 */
static ssize_t chaos_test_eintr_read(int fd, void *buffer, size_t count)
{
    if (g_stub_read_eintr > 0)
    {
        --g_stub_read_eintr;
        errno = EINTR;
        return -1;
    }
    return read(fd, buffer, count);
}

/**
 * @brief Stub close function that counts calls and returns a configurable result.
 *
 * Increments `g_stub_close_calls` and returns `g_stub_close_result` without performing
 * any actual system call. Used to verify that the production code closes the fd after
 * a read failure.
 *
 * @param fd  Ignored.
 * @return `g_stub_close_result`.
 */
static int chaos_test_stub_close(int fd)
{
    (void)fd;
    ++g_stub_close_calls;
    return g_stub_close_result;
}

/* The build hook for rules a build cannot apply (chaos-init defines it): a switch. */
static int g_test_rules_unsupported = 0;
#define CHAOS_IO_RULE_SUPPORTED(rule) ((void)(rule), !g_test_rules_unsupported)
#include "../../src/config/chaos_io_config.c"

/**
 * @brief Saved copy of `CHAOS_IO_CONFIG_PATH` as it existed before the test suite started.
 *
 * Populated in `main()` via `chaos_test_backup_file()` and restored via the atexit handler
 * `chaos_test_restore_config_path()`. Ensures that tests which write a new config file do not
 * permanently alter the developer's local config.
 */
static chaos_test_file_backup_t g_config_backup;

/**
 * @brief atexit handler that restores `CHAOS_IO_CONFIG_PATH` to its pre-test state.
 *
 * Called automatically when the process exits, whether normally or via an assertion failure.
 * Uses `chaos_test_restore_file()` to write back the original bytes (or unlink if the file
 * did not exist before the test suite ran).
 */
static void chaos_test_restore_config_path(void)
{
    chaos_test_restore_file(CHAOS_IO_CONFIG_PATH, &g_config_backup);
    chaos_test_free_backup(&g_config_backup);
}

/**
 * @brief Reset all stub control variables to their defaults.
 *
 * Resets open/read/close stub results, errno values, and call counters. Does not reset the
 * real-function-pointer globals; callers must assign those separately.
 */
static void chaos_test_reset_read_stubs(void)
{
    g_stub_open_result = -1;
    g_stub_open_errno = EIO;
    g_stub_close_result = 0;
    g_stub_close_calls = 0;
    g_stub_read_result = -1;
    g_stub_read_errno = EIO;
    g_stub_read_calls = 0U;
}

/**
 * @brief Invariant: primitive string and enum helpers produce correct results at all boundaries.
 *
 * Triggering condition: direct calls to `chaos_io_is_blank_char`, `chaos_io_trim`,
 *   `chaos_io_strip_comment`, `chaos_io_config_reset_state`, `chaos_io_parse_operation`,
 *   `chaos_io_parse_errno_name`, `chaos_io_parse_probability`, `chaos_io_parse_latency`,
 *   `chaos_io_effect_allowed`, `chaos_io_config_normalize_mtime_hash`, and
 *   `chaos_io_config_hash_mtime`.
 *
 * Expected observable behaviour:
 * - `is_blank_char(' ')` → true; `is_blank_char('x')` → false.
 * - `trim(NULL)` → NULL; `trim("  /data  \r\n")` → `"/data"`;
 *   `trim(" \t\r\n")` → `""`.
 * - `strip_comment("value # comment")` modifies the buffer to `"value "`.
 * - `config_reset_state(NULL, 1)` is a no-op; `config_reset_state(&state, 0)` zeroes
 *   `rule_count` and `parse_ok` even when the struct was memset to 0xff.
 * - All 14 valid operation names map to their corresponding enum values; NULL and "bogus"
 *   return `CHAOS_IO_OP_INVALID`.
 * - 8 valid errno names map to their numeric codes; NULL and "EINVAL" return -1.
 * - Probability parsing rejects NULL input, trailing non-numeric characters, values > 1.0,
 *   and NULL output pointer; accepts "0.25  " and stores 0.25.
 * - Latency parsing rejects NULL, non-numeric text, overflow value (4294967296), and NULL
 *   output pointer; accepts "25  " and stores 25.
 * - `effect_allowed`: TORN allowed only on WRITE/PWRITE; CORRUPT allowed only on READ/PREAD;
 *   INVALID never allowed.
 * - Mtime sentinel normalisation maps MISSING, RELOADING, and UNKNOWN to distinct
 *   non-sentinel values; a plain integer 7 passes through unchanged.
 * - `config_hash_mtime(NULL)` → `CHAOS_IO_MTIME_MISSING`; a stat with non-zero mtime
 *   produces a value != `CHAOS_IO_MTIME_MISSING`.
 */
static void test_helper_primitives(void)
{
    char text[] = "  /data  \r\n";
    char blank[] = " \t\r\n";
    char comment[] = "value # comment";
    chaos_io_config_state_t state;
    struct stat st;

    assert(chaos_io_is_blank_char(' '));
    assert(!chaos_io_is_blank_char('x'));

    assert(chaos_io_trim(NULL) == NULL);
    assert(strcmp(chaos_io_trim(text), "/data") == 0);
    assert(strcmp(chaos_io_trim(blank), "") == 0);

    chaos_io_strip_comment(comment);
    assert(strcmp(comment, "value ") == 0);
    chaos_io_strip_comment(NULL);

    (void)memset(&state, 0xff, sizeof(state));
    chaos_io_config_reset_state(NULL, 1);
    chaos_io_config_reset_state(&state, 0);
    assert(state.rule_count == 0U);
    assert(state.parse_ok == 0);

    assert(chaos_io_parse_operation(NULL) == CHAOS_IO_OP_INVALID);
    assert(chaos_io_parse_operation("read") == CHAOS_IO_OP_READ);
    assert(chaos_io_parse_operation("write") == CHAOS_IO_OP_WRITE);
    assert(chaos_io_parse_operation("open") == CHAOS_IO_OP_OPEN);
    assert(chaos_io_parse_operation("close") == CHAOS_IO_OP_CLOSE);
    assert(chaos_io_parse_operation("fsync") == CHAOS_IO_OP_FSYNC);
    assert(chaos_io_parse_operation("fdatasync") == CHAOS_IO_OP_FDATASYNC);
    assert(chaos_io_parse_operation("pread") == CHAOS_IO_OP_PREAD);
    assert(chaos_io_parse_operation("pwrite") == CHAOS_IO_OP_PWRITE);
    assert(chaos_io_parse_operation("truncate") == CHAOS_IO_OP_TRUNCATE);
    assert(chaos_io_parse_operation("allocate") == CHAOS_IO_OP_ALLOCATE);
    assert(chaos_io_parse_operation("unlink") == CHAOS_IO_OP_UNLINK);
    assert(chaos_io_parse_operation("rename_from") == CHAOS_IO_OP_RENAME_FROM);
    assert(chaos_io_parse_operation("rename_to") == CHAOS_IO_OP_RENAME_TO);
    assert(chaos_io_parse_operation("bogus") == CHAOS_IO_OP_INVALID);

    assert(chaos_io_parse_errno_name(NULL) == -1);
    assert(chaos_io_parse_errno_name("EIO") == EIO);
    assert(chaos_io_parse_errno_name("ENOSPC") == ENOSPC);
    assert(chaos_io_parse_errno_name("EDQUOT") == EDQUOT);
    assert(chaos_io_parse_errno_name("EROFS") == EROFS);
    assert(chaos_io_parse_errno_name("EACCES") == EACCES);
    assert(chaos_io_parse_errno_name("EMFILE") == EMFILE);
    assert(chaos_io_parse_errno_name("ENFILE") == ENFILE);
    assert(chaos_io_parse_errno_name("ENOENT") == ENOENT);
    assert(chaos_io_parse_errno_name("EINVAL") == -1);

    {
        double probability = -1.0;
        char invalid_suffix[] = "0.25xyz";
        char out_of_range[] = "1.5";
        char valid_probability[] = "0.25  ";
        char zero_probability[] = "0.0";

        assert(chaos_io_parse_probability(NULL, &probability) == -1);
        assert(chaos_io_parse_probability(invalid_suffix, &probability) == -1);
        assert(chaos_io_parse_probability(out_of_range, &probability) == -1);
        assert(chaos_io_parse_probability(valid_probability, &probability) == 0);
        assert(probability == 0.25);
        assert(chaos_io_parse_probability(zero_probability, NULL) == -1);
    }

    {
        unsigned int latency_ms = 0U;
        char invalid_latency[] = "10ms";
        char overflow_latency[] = "4294967296";
        char valid_latency[] = "25  ";
        char zero_latency[] = "0";

        assert(chaos_io_parse_latency(NULL, &latency_ms) == -1);
        assert(chaos_io_parse_latency(invalid_latency, &latency_ms) == -1);
        assert(chaos_io_parse_latency(overflow_latency, &latency_ms) == -1);
        assert(chaos_io_parse_latency(valid_latency, &latency_ms) == 0);
        assert(latency_ms == 25U);
        assert(chaos_io_parse_latency(zero_latency, NULL) == -1);
    }

    assert(chaos_io_effect_allowed(CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_ERRNO));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_LATENCY));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_LATENCY));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_RENAME_TO, CHAOS_IO_EFFECT_ERRNO));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_TORN));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_TORN));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_TORN));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_CORRUPT));
    assert(chaos_io_effect_allowed(CHAOS_IO_OP_PREAD, CHAOS_IO_EFFECT_CORRUPT));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_OPEN, CHAOS_IO_EFFECT_CORRUPT));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_UNLINK, CHAOS_IO_EFFECT_CORRUPT));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_INVALID));

    assert(chaos_io_config_normalize_mtime_hash(CHAOS_IO_MTIME_MISSING) != CHAOS_IO_MTIME_MISSING);
    assert(
        chaos_io_config_normalize_mtime_hash(CHAOS_IO_MTIME_RELOADING) != CHAOS_IO_MTIME_RELOADING
    );
    assert(chaos_io_config_normalize_mtime_hash(CHAOS_IO_MTIME_UNKNOWN) != CHAOS_IO_MTIME_UNKNOWN);
    assert(chaos_io_config_normalize_mtime_hash(7U) == 7U);

    (void)memset(&st, 0, sizeof(st));
    assert(chaos_io_config_hash_mtime(NULL) == CHAOS_IO_MTIME_MISSING);
#if defined(__linux__)
    st.st_mtim.tv_sec = 12;
    st.st_mtim.tv_nsec = 34;
#else
    st.st_mtimespec.tv_sec = 12;
    st.st_mtimespec.tv_nsec = 34;
#endif
    assert(chaos_io_config_hash_mtime(&st) != CHAOS_IO_MTIME_MISSING);
}

/**
 * @brief Invariant: `chaos_io_config_parse_line` accepts all 17 valid line formats and returns
 *   0 for comment and empty lines.
 *
 * Triggering condition: a compile-time table of 17 `{line, operation, effect, errnum,
 *   probability, latency_ms}` entries iterated by a loop that calls `parse_line` and checks
 *   each rule field based on the effect type.
 *
 * Expected observable behaviour:
 * - All 13 ERRNO variants (one per operation) return 1; `rule.operation`, `rule.errnum`, and
 *   `rule.probability` match the table entry.
 * - LATENCY variants for write and truncate return 1; `rule.latency_ms` matches.
 * - TORN (write) and CORRUPT (read) variants return 1; `rule.probability` matches.
 * - A pure comment line (`" # only comment"`) returns 0.
 * - An empty string returns 0.
 */
static void test_parse_line_valid_cases(void)
{
    static const struct
    {
        const char *line;
        chaos_io_operation_t operation;
        chaos_io_effect_t effect;
        int errnum;
        double probability;
        unsigned int latency_ms;
    } cases[] = {
        {"/data:read:EIO:0.1", CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_ERRNO, EIO, 0.1, 0U},
        {"/data:write:ENOSPC:0.2", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_ERRNO, ENOSPC, 0.2, 0U},
        {"/data:open:EMFILE:0.3", CHAOS_IO_OP_OPEN, CHAOS_IO_EFFECT_ERRNO, EMFILE, 0.3, 0U},
        {"/data:close:EDQUOT:0.4", CHAOS_IO_OP_CLOSE, CHAOS_IO_EFFECT_ERRNO, EDQUOT, 0.4, 0U},
        {"/data:fsync:EROFS:0.5", CHAOS_IO_OP_FSYNC, CHAOS_IO_EFFECT_ERRNO, EROFS, 0.5, 0U},
        {"/data:fdatasync:EACCES:0.6", CHAOS_IO_OP_FDATASYNC, CHAOS_IO_EFFECT_ERRNO, EACCES, 0.6, 0U
        },
        {"/data:pread:ENOENT:0.7", CHAOS_IO_OP_PREAD, CHAOS_IO_EFFECT_ERRNO, ENOENT, 0.7, 0U},
        {"/data:pwrite:ENFILE:0.8", CHAOS_IO_OP_PWRITE, CHAOS_IO_EFFECT_ERRNO, ENFILE, 0.8, 0U},
        {"/data:truncate:EIO:0.2", CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U},
        {"/data:allocate:EIO:0.2", CHAOS_IO_OP_ALLOCATE, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U},
        {"/data:unlink:EIO:0.2", CHAOS_IO_OP_UNLINK, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U},
        {"/data:rename_from:EIO:0.2", CHAOS_IO_OP_RENAME_FROM, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U},
        {"/data:rename_to:EIO:0.2", CHAOS_IO_OP_RENAME_TO, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U},
        {"/data:write:LATENCY:25", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_LATENCY, 0, 0.0, 25U},
        {"/data:truncate:LATENCY:25", CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_LATENCY, 0, 0.0, 25U},
        {"/data:write:TORN:0.9", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_TORN, 0, 0.9, 0U},
        {"/data:read:CORRUPT:1.0", CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_CORRUPT, 0, 1.0, 0U}
    };
    size_t index;

    for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index)
    {
        char line[128];
        chaos_io_rule_t rule;

        (void)snprintf(line, sizeof(line), "%s", cases[index].line);
        assert(chaos_io_config_parse_line(line, &rule) == 1);
        assert(rule.operation == cases[index].operation);
        assert(rule.effect == cases[index].effect);
        if (rule.effect == CHAOS_IO_EFFECT_ERRNO)
        {
            assert(rule.errnum == cases[index].errnum);
            assert(rule.probability == cases[index].probability);
        }
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
        {
            assert(rule.latency_ms == cases[index].latency_ms);
        }
        if (rule.effect == CHAOS_IO_EFFECT_TORN || rule.effect == CHAOS_IO_EFFECT_CORRUPT)
        {
            assert(rule.probability == cases[index].probability);
        }
    }

    {
        char comment[] = " # only comment";
        chaos_io_rule_t rule;
        assert(chaos_io_config_parse_line(comment, &rule) == 0);
    }

    {
        char empty[] = "";
        chaos_io_rule_t rule;
        assert(chaos_io_config_parse_line(empty, &rule) == 0);
    }
}

/**
 * @brief Invariant: `chaos_io_config_parse_line` rejects all malformed or semantically
 *   invalid lines.
 *
 * Triggering condition: 16 distinct invalid inputs passed to `parse_line` one at a time.
 *
 * Expected observable behaviour:
 * - NULL line or NULL rule output → -1.
 * - Too many fields (5 colon-separated tokens) → -1.
 * - Too few fields (3 tokens, missing value) → -1.
 * - Empty path prefix (line starts with `:`) → -1.
 * - Empty operation field, empty effect field, or empty value field → -1.
 * - Unrecognised operation name (`rename`) → -1.
 * - Non-numeric probability value (`not-a-number`) → -1.
 * - Unrecognised effect name (`BOOM`) → -1.
 * - TORN on a read operation → -1 (effect disallowed for this operation class).
 * - TORN on a truncate operation → -1.
 * - Non-numeric latency value → -1.
 * - Probability out of range: > 1.0 for CORRUPT → -1; < 0.0 for TORN → -1.
 * - Path component exceeding `CHAOS_IO_MAX_RULE_PATH` bytes → -1.
 */
static void test_parse_line_invalid_cases(void)
{
    char long_path_line[CHAOS_IO_MAX_RULE_PATH + 32U];
    char too_many_fields[] = "/data:read:EIO:0.1:extra";
    char missing_fields[] = "/data:read:EIO";
    char empty_prefix[] = ":read:EIO:0.1";
    char invalid_operation[] = "/data:rename:EIO:0.1";
    char invalid_errno_probability[] = "/data:read:EIO:not-a-number";
    char invalid_effect[] = "/data:read:BOOM:0.1";
    char invalid_combination[] = "/data:read:TORN:0.2";
    char invalid_truncate_combination[] = "/data:truncate:TORN:0.2";
    char invalid_latency[] = "/data:write:LATENCY:not-a-number";
    char invalid_corrupt_probability[] = "/data:read:CORRUPT:2.0";
    char invalid_torn_probability[] = "/data:pwrite:TORN:-0.1";
    char empty_operation[] = "/data::EIO:0.1";
    char empty_effect[] = "/data:read::0.1";
    char empty_value[] = "/data:read:EIO:";
    chaos_io_rule_t rule;

    assert(chaos_io_config_parse_line(NULL, &rule) == -1);
    assert(chaos_io_config_parse_line(empty_value, NULL) == -1);
    assert(chaos_io_config_parse_line(too_many_fields, &rule) == -1);
    assert(chaos_io_config_parse_line(missing_fields, &rule) == -1);
    assert(chaos_io_config_parse_line(empty_prefix, &rule) == -1);
    assert(chaos_io_config_parse_line(empty_operation, &rule) == -1);
    assert(chaos_io_config_parse_line(empty_effect, &rule) == -1);
    assert(chaos_io_config_parse_line(empty_value, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_operation, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_errno_probability, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_effect, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_combination, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_truncate_combination, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_latency, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_corrupt_probability, &rule) == -1);
    assert(chaos_io_config_parse_line(invalid_torn_probability, &rule) == -1);

    (void)memset(long_path_line, 'a', sizeof(long_path_line));
    long_path_line[0] = '/';
    long_path_line[CHAOS_IO_MAX_RULE_PATH] = ':';
    (void)snprintf(
        long_path_line + CHAOS_IO_MAX_RULE_PATH + 1U,
        sizeof(long_path_line) - (CHAOS_IO_MAX_RULE_PATH + 1U),
        "read:EIO:0.1"
    );
    assert(chaos_io_config_parse_line(long_path_line, &rule) == -1);
}

/**
 * @brief Invariant: buffer parsing loads all valid rules and rule selection returns the
 *   most-specific matching prefix for the given path and operation.
 *
 * Triggering condition: `chaos_io_config_parse_buffer` with a 4-rule buffer (wildcard,
 *   `/data`, `/data/wal.log`, `/data/wal/`), then `chaos_io_rule_prefix_matches` and
 *   `chaos_io_config_select_rule` with various path/operation combinations.
 *
 * Expected observable behaviour:
 * - NULL buffer, rules, or rule_count → -1.
 * - 4-rule buffer parses successfully with `rule_count == 4`.
 * - `prefix_matches(NULL, ...)` and `prefix_matches(..., NULL)` → 0.
 * - Wildcard `*` matches any path; `/data` matches `/data` and `/data/file` but not
 *   `/tmp/file` or `/database`.
 * - `select_rule` with NULL arguments → 0.
 * - `/data/wal.log` selects the most specific rule (errnum == ENOSPC), not the `/data` rule.
 * - `/tmp/file` for OPEN matches the wildcard rule; for WRITE no rule matches → 0.
 * - `/tmp/file` for CLOSE (no matching rule) → 0.
 */
static void test_parse_buffer_and_selection(void)
{
    char buffer[] = "# comment\n"
                    "\n"
                    "*:open:EMFILE:0.05\n"
                    "/data:write:EIO:0.30\n"
                    "/data/wal.log:write:ENOSPC:1.0\n"
                    "/data/wal/:read:CORRUPT:0.20\n";
    chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];
    chaos_io_rule_t match;
    size_t rule_count = 0U;

    assert(chaos_io_config_parse_buffer(NULL, rules, &rule_count) == -1);
    assert(chaos_io_config_parse_buffer(buffer, NULL, &rule_count) == -1);
    assert(chaos_io_config_parse_buffer(buffer, rules, NULL) == -1);

    assert(chaos_io_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 4U);

    /* A build that cannot apply a rule (chaos-init) rejects the file at it. */
    {
        char unsupported[] = "/data:write:EIO:1.0\n";
        size_t rejected_count = 9U;

        g_test_rules_unsupported = 1;
        assert(chaos_io_config_parse_buffer(unsupported, rules, &rejected_count) == -1);
        assert(rejected_count == 0U && g_chaos_io_config_error.line == 1U);
        assert(strcmp(g_chaos_io_config_error.reason, CHAOS_STATUS_REASON_UNSUPPORTED) == 0);
        g_test_rules_unsupported = 0;
    }
    assert(chaos_io_rule_prefix_matches(NULL, "/data") == 0);
    assert(chaos_io_rule_prefix_matches(&rules[0], NULL) == 0);
    assert(chaos_io_rule_prefix_matches(&rules[0], "/tmp/file"));
    /* `*` is for files: not pipes, sockets, anonymous inodes or memfds. */
    assert(!chaos_io_rule_prefix_matches(&rules[0], "pipe:[1234]"));
    assert(!chaos_io_rule_prefix_matches(&rules[0], "socket:[1234]"));
    assert(!chaos_io_rule_prefix_matches(&rules[0], "anon_inode:[eventfd]"));
    assert(!chaos_io_rule_prefix_matches(&rules[0], "/memfd:cache (deleted)"));
    assert(chaos_io_rule_prefix_matches(&rules[0], "/memfd"));
    assert(chaos_io_rule_prefix_matches(&rules[1], "/data"));
    assert(chaos_io_rule_prefix_matches(&rules[1], "/data/file"));
    assert(!chaos_io_rule_prefix_matches(&rules[1], "/tmp/file"));
    assert(!chaos_io_rule_prefix_matches(&rules[1], "/database"));
    assert(chaos_io_rule_prefix_matches(&rules[3], "/data/wal/0001"));

    assert(chaos_io_config_select_rule(NULL, rule_count, CHAOS_IO_OP_WRITE, "/data", &match) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, NULL, &match) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, "/data", NULL) == 0);
    assert(
        chaos_io_config_select_rule(
            rules, rule_count, CHAOS_IO_OP_WRITE, "/data/wal.log", &match
        ) == 1
    );
    assert(match.errnum == ENOSPC);
    assert(
        chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_OPEN, "/tmp/file", &match) == 1
    );
    assert(strcmp(match.path_prefix, "*") == 0);
    assert(
        chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, "/tmp/file", &match) == 0
    );
    assert(
        chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_CLOSE, "/tmp/file", &match) == 0
    );
}

/**
 * @brief Invariant: `chaos_io_config_parse_buffer` resets `rule_count` to 0 on parse error
 *   and fails when the number of rules exceeds `CHAOS_IO_MAX_RULES`.
 *
 * Triggering condition: a single-rule buffer with an invalid rule (TORN on read), then a
 *   dynamically allocated buffer containing `CHAOS_IO_MAX_RULES + 1` valid rules.
 *
 * Expected observable behaviour:
 * - A buffer containing an invalid rule returns -1; `rule_count` is reset to 0 even if it
 *   was non-zero before the call (17 in this test, to verify the reset is unconditional).
 * - A buffer with more than `CHAOS_IO_MAX_RULES` lines returns -1; `rule_count` is reset to 0.
 */
static void test_parse_buffer_error_paths(void)
{
    char invalid_buffer[] = "/data:read:TORN:0.1\n";
    char *overflow_buffer;
    size_t index;
    size_t rule_count = 17U;
    chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];

    assert(chaos_io_config_parse_buffer(invalid_buffer, rules, &rule_count) == -1);
    assert(rule_count == 0U);

    overflow_buffer = (char *)malloc((CHAOS_IO_MAX_RULES + 2U) * 20U);
    assert(overflow_buffer != NULL);
    overflow_buffer[0] = '\0';
    for (index = 0U; index <= CHAOS_IO_MAX_RULES; ++index)
    {
        (void)strcat(overflow_buffer, "*:open:EIO:0.0\n");
    }

    rule_count = 99U;
    assert(chaos_io_config_parse_buffer(overflow_buffer, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    free(overflow_buffer);
}

/**
 * @brief Invariant: `chaos_io_config_read_file` validates its arguments, propagates I/O
 *   errors, closes the file descriptor on read failure, and correctly reads an actual file.
 *
 * Triggering condition: `chaos_io_config_read_file` called with progressively more
 *   permissive stub configurations, culminating in real I/O against a written config file.
 *
 * Expected observable behaviour:
 * - NULL size_out → -1 (no I/O attempted).
 * - NULL `g_chaos_io_real_open` → -1.
 * - Stub open returns -1 with EIO → -1 (retried); with EACCES → -3 (lasting until the
 *   file changes).
 * - Stub open returns a valid fd, stub read returns -1 → -1 and `g_stub_close_calls == 1`
 *   (the fd is closed before returning).
 * - Stub read returns exactly `CHAOS_IO_MAX_CONFIG_BYTES` → -1 (buffer full, only one read
 *   call made: `g_stub_read_calls == 1`).
 * - Real I/O with file content `"/data:write:EIO:1.0\n"` → 0, `size_out` equals
 *   `strlen("/data:write:EIO:1.0\n")`, and `g_chaos_io_config_buffer` contains that text.
 */
static void test_read_file_paths(void)
{
    size_t size_out = 99U;

    chaos_test_reset_runtime();
    chaos_test_reset_read_stubs();

    assert(chaos_io_config_read_file(NULL, chaos_io_config_observed_mtime()) == -1);
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -1);

    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -1);

    g_chaos_io_real_close = chaos_test_stub_close;
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -1);
    g_stub_open_errno = EACCES;
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -3);
    g_stub_open_errno = EIO;

    g_stub_open_result = 7;
    g_stub_read_result = -1;
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -1);
    assert(g_stub_close_calls == 1);

    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    g_chaos_io_real_close = chaos_test_stub_close;
    g_stub_open_result = 8;
    g_stub_read_result = (ssize_t)CHAOS_IO_MAX_CONFIG_BYTES;
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == -2);
    assert(g_stub_read_calls == 1U);

    chaos_test_use_real_io();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    assert(chaos_io_config_read_file(&size_out, chaos_io_config_observed_mtime()) == 0);
    assert(size_out == strlen("/data:write:EIO:1.0\n"));
    assert(strcmp(g_chaos_io_config_buffer, "/data:write:EIO:1.0\n") == 0);
}

/**
 * @brief Invariant: the hot-reload state machine correctly responds to missing files,
 *   mtime changes, the RELOADING sentinel, and invalid config content.
 *
 * Triggering condition: `chaos_io_config_prepare()` and `chaos_io_config_match_loaded()`
 *   called in sequence as the config file is created, modified, and corrupted, with
 *   targeted mutations of `g_chaos_io_cached_mtime` to exercise sentinel branches.
 *
 * Expected observable behaviour:
 * - After removing the config file: `observed_mtime()` → `CHAOS_IO_MTIME_MISSING`;
 *   `reload(MTIME_MISSING)` keeps `cached_mtime == MTIME_MISSING`; two consecutive
 *   `prepare()` calls both return 0 (no file → no rules loaded).
 * - With failing stub I/O and `reload(1234)`: nothing is published and `cached_mtime`
 *   returns to the previous stamp (`MTIME_UNKNOWN`), so the next call retries.
 * - After writing a valid config and restoring real I/O: `observed_mtime()` !=
 *   `MTIME_MISSING`; `prepare()` returns 1; `match_loaded(WRITE, "/data/file.bin")`
 *   returns 1 with `rule.errnum == EIO`; `match_loaded(OPEN, ...)` returns 0;
 *   `match_loaded(..., NULL, ...)` returns 0; `match_path(...)` returns 1 for a matching
 *   path and 0 for a non-matching path or NULL path.
 * - With `cached_mtime == MTIME_RELOADING`: `prepare()` returns 1 immediately without
 *   re-reading the file (the RELOADING sentinel means another thread is already reloading).
 * - After writing an invalid rule file and setting `cached_mtime == MTIME_UNKNOWN`:
 *   `prepare()` returns 0 (parse failure); `match_loaded` and `match_path` return 0.
 */
static void test_reload_prepare_and_match(void)
{
    chaos_io_rule_t rule;

    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_remove_file_if_exists(CHAOS_IO_CONFIG_PATH);

    assert(chaos_io_config_observed_mtime() == CHAOS_IO_MTIME_MISSING);
    chaos_io_config_reload(CHAOS_IO_MTIME_MISSING, CHAOS_IO_MTIME_UNKNOWN);
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_MISSING);
    assert(chaos_io_config_prepare() == 0);
    assert(chaos_io_config_prepare() == 0);

    chaos_test_reset_runtime();
    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    g_chaos_io_real_close = chaos_test_stub_close;
    chaos_io_config_reload(UINT64_C(1234), CHAOS_IO_MTIME_UNKNOWN);
    /* The read failed: nothing is published and the claim is released with the
     * previous stamp, so the next call retries. */
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_UNKNOWN);
    assert(chaos_io_config_active_state()->rule_count == 0U);

    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    chaos_test_use_real_io();
    assert(chaos_io_config_observed_mtime() != CHAOS_IO_MTIME_MISSING);
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/data/file.bin", &rule) == 1);
    assert(rule.errnum == EIO);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_OPEN, "/data/file.bin", &rule) == 0);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, NULL, &rule) == 0);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/data/file.bin", NULL) == 0);
    assert(chaos_io_config_match_path(CHAOS_IO_OP_WRITE, "/data/file.bin", &rule) == 1);
    assert(chaos_io_config_match_path(CHAOS_IO_OP_WRITE, "/proc/cpuinfo", &rule) == 0);
    assert(chaos_io_config_match_path(CHAOS_IO_OP_WRITE, NULL, &rule) == 0);
    assert(chaos_io_config_match_path(CHAOS_IO_OP_WRITE, "/data/file.bin", NULL) == 0);

    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_RELOADING;
    assert(chaos_io_config_prepare() == 1);

    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:read:TORN:0.1\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 0);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/data/file.bin", &rule) == 0);
    assert(chaos_io_config_match_path(CHAOS_IO_OP_WRITE, "/data/file.bin", &rule) == 0);
}

/**
 * @brief Invariant: a failed config read keeps the active rules and is retried.
 *
 * Triggering condition: the file changes while `open()` fails.
 *
 * Expected observable behaviour: the previously loaded rule set stays active, the
 * cached stamp is not advanced, and the next call loads the new content.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_active_state()->rule_count == 1U);

    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n/logs:read:EIO:1.0\n");
    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_active_state()->rule_count == 1U);
    assert(g_chaos_io_cached_mtime != chaos_io_config_observed_mtime());
    assert(g_chaos_io_cached_mtime != CHAOS_IO_MTIME_RELOADING);

    chaos_test_use_real_io();
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_active_state()->rule_count == 2U);
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
    assert(chaos_io_config_hash_mtime(&base) == chaos_io_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_io_config_hash_mtime(&base) != chaos_io_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_io_config_hash_mtime(&base) != chaos_io_config_hash_mtime(&other));
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
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_RELOADING;
    (void)chaos_io_config_prepare();
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_RELOADING);
    g_chaos_io_tls_prng_state = UINT64_C(42);
    chaos_io_config_after_fork();
    assert(g_chaos_io_tls_prng_state == 0U);
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_UNKNOWN);
    assert(g_chaos_io_hits_pid == (uint64_t)getpid());
    assert(chaos_io_config_prepare());
    assert(g_chaos_io_cached_mtime == chaos_io_config_observed_mtime());
    chaos_io_config_after_fork();
    assert(g_chaos_io_cached_mtime == chaos_io_config_observed_mtime());

    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_RELOADING;
    (void)chaos_io_config_prepare();
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_RELOADING);
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
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
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_remove_file_if_exists(CHAOS_IO_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_io_config_prepare();
    assert(errno == EBADF);

    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    errno = EBADF;
    assert(chaos_io_config_prepare() == 1);
    assert(errno == EBADF);
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
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    g_chaos_io_real_read = chaos_test_eintr_read;
    g_stub_read_eintr = 1;
    assert(chaos_io_config_prepare() == 1);
    assert(g_stub_read_eintr == 0);
    assert(chaos_io_config_active_state()->rule_count == 1U);
    chaos_test_use_real_io();
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

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "# stable\n");
    stamp = chaos_io_config_observed_mtime();
    assert(chaos_io_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_io_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_IO_STATUS_PATH, "r");
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
 *   then exactly CHAOS_IO_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];
    char buffer[] = "# header\n\n/data:write:EIO:1.0\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_io_config_last_error();
    const size_t line_length = strlen("/data:write:EIO:1.0\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_io_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_IO_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_IO_MAX_RULES; ++index)
    {
        (void)strcat(many, "/data:write:EIO:1.0\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_io_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_IO_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_IO_MAX_RULES; ++index)
    {
        (void)strcat(many, "/data:write:EIO:1.0\n");
    }
    assert(chaos_io_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_IO_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "/data:write:EIO:1.0") == 0);
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

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "# header\nbogus-rule # typo\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported, not silently re-read. */
    {
        FILE *large = fopen(CHAOS_IO_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_IO_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_IO_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_IO_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_IO_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_IO_CONFIG_PATH, 0700) == 0);
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_IO_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_IO_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_IO_CONFIG_PATH, 0) == 0);
        assert(chaos_io_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_IO_CONFIG_PATH);
    }
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 0);
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

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_IO_HITS_PREFIX, g_chaos_io_hits_file);
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
/**
 * @brief Invariant: a rule written with a link's name also covers the files under
 *        the link's target, by which descriptors are known; rule paths are
 *        normalised like the paths they are matched against.
 */
static void test_rules_follow_links(void)
{
    chaos_io_rule_t rule;

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    (void)unlink("/tmp/chaos-link-dir");
    (void)mkdir("/tmp/chaos-real-dir", 0700);
    assert(symlink("/tmp/chaos-real-dir", "/tmp/chaos-link-dir") == 0);
    chaos_io_config_init();
    chaos_test_write_text_file(
        CHAOS_IO_CONFIG_PATH,
        "/tmp/chaos-link-dir:read:EIO:1.0\n//tmp//plain/:write:EIO:1.0\n*:fsync:EIO:1.0\n"
    );
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_READ, "/tmp/chaos-link-dir/f", &rule) == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_READ, "/tmp/chaos-real-dir/f", &rule) == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_READ, "/tmp/chaos-real-dirx", &rule) == 0);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/plain/f", &rule) == 1);
    assert(strcmp(rule.path_prefix, "/tmp/plain") == 0 && rule.resolved_prefix == NULL);
    assert(unlink("/tmp/chaos-link-dir") == 0 && rmdir("/tmp/chaos-real-dir") == 0);
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

/**
 * @brief Invariant: an image whose pid already has a hits file (the image an execve
 *        replaced) writes its own file under a number no pid reaches.
 */
static void test_hits_file_survives_exec(void)
{
    char path[64];
    FILE *file;
    long number;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_IO_HITS_PREFIX, (long)getpid());
    (void)unlink(path);
    assert(chaos_hits_file_number(CHAOS_IO_HITS_PREFIX) == (long)getpid());
    file = fopen(path, "w");
    assert(file != NULL && fclose(file) == 0);
    errno = 4242;
    number = chaos_hits_file_number(CHAOS_IO_HITS_PREFIX);
    assert(errno == 4242);
    assert(number > 4194304L && number / 1000000000L == (long)getpid());
    assert(unlink(path) == 0);
}

static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_io_config_state_t *state;

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0 # a\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    state = (chaos_io_config_state_t *)chaos_io_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "/data:write:EIO:1.0 # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\t/data:write:EIO:1.0 # a\n") == 0);

    chaos_test_write_text_file(
        CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0 # a\n/data:write:EIO:1.0 # b\n"
    );
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    state = (chaos_io_config_state_t *)chaos_io_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\t/data:write:EIO:1.0 # a\n1\t/data:write:EIO:1.0 # b\n") == 0);

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_io_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_io_hits_writing = 0;
    assert(g_chaos_io_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\t/data:write:EIO:1.0 # a\n1\t/data:write:EIO:1.0 # b\n") == 0);

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_io_hits_total = CHAOS_HITS_EAGER;
    g_chaos_io_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\t/data:write:EIO:1.0 # a\n1\t/data:write:EIO:1.0 # b\n") == 0);

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_io_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\t/data:write:EIO:1.0 # a\n3\t/data:write:EIO:1.0 # b\n") == 0);
    assert(g_chaos_io_hits_pending == 0);
    chaos_io_config_report_hits(NULL);
    g_chaos_io_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_io_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_io_config_after_fork();
    assert(g_chaos_io_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\t/data:write:EIO:1.0 # a\n0\t/data:write:EIO:1.0 # b\n") == 0);
    g_chaos_io_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_io_hits_pending = 1;
    g_chaos_io_hits_pid = (uint64_t)getpid() + 1U;
    chaos_io_config_report_hits(NULL);
    assert(g_chaos_io_hits_pending == 1);
    g_chaos_io_hits_pending = 0;
    g_chaos_io_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_IO_HITS_PREFIX, g_chaos_io_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_IO_CONFIG_PATH);
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
    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_io_check_interval_ns = UINT64_C(10000000000);
    g_chaos_io_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_IO_CONFIG_PATH);
    assert(chaos_io_config_prepare() == 1);

    g_chaos_io_last_check_ns = chaos_clock_now_ns() - g_chaos_io_check_interval_ns;
    assert(chaos_io_config_prepare() == 0);
    g_chaos_io_check_interval_ns = 0U;
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
    static chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];
    char qualified[] =
        "/data:write:EIO:1.0 @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "/data:write:EIO:1.0 @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "/data:write:EIO:1.0 @from=2000 @until=1000\n";
    char empty_first[] = "/data:write:EIO:1.0 @first=0\n";
    size_t count = 0U;

    assert(chaos_io_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_io_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_io_config_last_error()->text, "/data:write:EIO:1.0 @bogus=1") == 0);
    assert(chaos_io_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_io_config_last_error()->line == 2U);
    assert(chaos_io_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_io_config_parse_buffer(empty_first, rules, &count) == -1);
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
    static const char rule[] = "/data:write:EIO:1.0\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_io_check_interval_ns;

    g_chaos_io_check_interval_ns = 0U;
    (void)unlink(CHAOS_IO_CONFIG_PATH);
    chaos_io_config_init();
    file = fopen(CHAOS_IO_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_IO_CONFIG_PATH, &first) == 0);
    assert(chaos_io_config_prepare());
    assert(g_chaos_io_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    /* Read again, nothing changed: the same snapshot stays. */
    assert(chaos_io_config_prepare());
    assert(g_chaos_io_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* The same bytes but the first commented out, written in place, same mtime. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_IO_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window: the load is final and not read again. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_IO_CONFIG_PATH, times, 0) == 0);
    assert(chaos_io_config_prepare() == 0);
    assert(g_chaos_io_config_provisional == 0);

    (void)unlink(CHAOS_IO_CONFIG_PATH);
    g_chaos_io_check_interval_ns = interval;
}

/**
 * @brief Invariant: hits still pending when their interval is over are written by
 *        the next look at the rule file, not only by the next hit or at exit.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_io_check_interval_ns;

    g_chaos_io_check_interval_ns = 0U;
    g_chaos_io_hits_pid = (uint64_t)getpid();
    g_chaos_io_hits_pending = 1;
    g_chaos_io_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_io_config_prepare();
    assert(g_chaos_io_hits_pending == 1);
    g_chaos_io_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_io_config_prepare();
    assert(g_chaos_io_hits_pending == 0);
    g_chaos_io_check_interval_ns = interval;
}

/** Number of upcoming opens `chaos_test_eintr_open` fails with EINTR before opening. */
static int g_stub_open_eintr = 0;

/**
 * @brief Open that fails with EINTR `g_stub_open_eintr` times, as a signal would make
 * it, then opens for real.
 */
static int chaos_test_eintr_open(const char *path, int flags, ...)
{
    if (g_stub_open_eintr > 0)
    {
        --g_stub_open_eintr;
        errno = EINTR;
        return -1;
    }
    return chaos_test_real_open(path, flags);
}

/**
 * @brief Invariant: each way reading the rule file can fail is classified: lasting
 *   (-3, kept until the file changes) or retried (-1); an interrupted open is retried.
 *
 * Expected observable behaviour:
 * - No read function → -1, nothing opened.
 * - open() fails with EPERM → -3, like EACCES.
 * - read() fails with EISDIR (a directory in the file's place) → -3, descriptor closed.
 * - fstat() fails on the descriptor → -1, descriptor closed.
 * - open() fails with EINTR once → retried, and the file is read.
 */
static void test_read_file_failure_kinds(void)
{
    size_t size_out = 0U;
    uint64_t stamp;

    chaos_test_reset_runtime();
    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_close = chaos_test_stub_close;
    g_stub_open_result = 7;
    assert(chaos_io_config_read_file(&size_out, 0U) == -1);
    assert(g_stub_close_calls == 0);

    g_chaos_io_real_read = chaos_test_stub_read;
    g_stub_open_result = -1;
    g_stub_open_errno = EPERM;
    assert(chaos_io_config_read_file(&size_out, 0U) == -3);

    g_stub_open_result = 7;
    g_stub_read_errno = EISDIR;
    assert(chaos_io_config_read_file(&size_out, 0U) == -3);
    assert(g_stub_close_calls == 1);

    /* A descriptor number that is not open: fstat() fails with EBADF. */
    chaos_test_reset_read_stubs();
    g_stub_open_result = 1000;
    g_stub_read_result = 0;
    assert(chaos_io_config_read_file(&size_out, 0U) == -1);
    assert(g_stub_close_calls == 1);

    chaos_test_use_real_io();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    stamp = chaos_io_config_observed_mtime();
    g_chaos_io_real_open = chaos_test_eintr_open;
    g_stub_open_eintr = 1;
    assert(chaos_io_config_read_file(&size_out, stamp) == 0);
    assert(g_stub_open_eintr == 0);
    assert(size_out == strlen("/data:write:EIO:1.0\n"));
    chaos_test_use_real_io();
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

/**
 * @brief Invariant: matching edges: the effects each operation class allows, a last
 *   line without a newline, the more specific rule winning in either order, and a
 *   rule matching through its resolved name as well as its written one.
 */
static void test_matching_edges(void)
{
    static chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];
    char specific_first[] = "/data/wal.log:write:ENOSPC:1.0\n/data:write:EIO:1.0";
    char resolved[] = "/real";
    chaos_io_rule_t match;
    chaos_io_rule_t rule;
    size_t count = 0U;

    assert(chaos_io_effect_allowed(CHAOS_IO_OP_PWRITE, CHAOS_IO_EFFECT_TORN));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_PREAD, CHAOS_IO_EFFECT_TORN));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_CORRUPT));
    assert(!chaos_io_effect_allowed(CHAOS_IO_OP_PWRITE, CHAOS_IO_EFFECT_CORRUPT));

    assert(chaos_io_config_parse_buffer(specific_first, rules, &count) == 0);
    assert(count == 2U);
    assert(strcmp(rules[1].path_prefix, "/data") == 0);
    assert(chaos_io_config_select_rule(rules, count, CHAOS_IO_OP_WRITE, "/data/wal.log", &match));
    assert(match.errnum == ENOSPC);
    assert(chaos_io_config_select_rule(rules, count, CHAOS_IO_OP_WRITE, "/data/other", &match));
    assert(match.errnum == EIO);

    /* An empty prefix covers a path only at a boundary: a leading slash. */
    assert(chaos_io_prefix_covers("", 0U, "/x"));
    assert(!chaos_io_prefix_covers("", 0U, "x"));

    (void)memset(&rule, 0, sizeof(rule));
    (void)snprintf(rule.path_prefix, sizeof(rule.path_prefix), "%s", "/link");
    rule.path_len = strlen(rule.path_prefix);
    rule.resolved_prefix = resolved;
    rule.resolved_len = strlen(resolved);
    assert(chaos_io_rule_prefix_matches(&rule, "/link/f"));
    assert(chaos_io_rule_prefix_matches(&rule, "/real/f"));
    assert(!chaos_io_rule_prefix_matches(&rule, "/realm/f"));
    assert(!chaos_io_rule_prefix_matches(&rule, "/other/f"));
}

/**
 * @brief Invariant: past the eager hits, a hit after the interval is written at once.
 */
static void test_hit_after_interval_is_written(void)
{
    char hits[1024];
    char path[64];
    chaos_io_config_state_t *state;

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    state = (chaos_io_config_state_t *)chaos_io_config_active_state();

    g_chaos_io_hits_total = CHAOS_HITS_EAGER;
    g_chaos_io_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[0].hit);
    assert(g_chaos_io_hits_pending == 0);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\t/data:write:EIO:1.0\n") == 0);
    g_chaos_io_hits_total = 0U;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_IO_HITS_PREFIX, g_chaos_io_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

/**
 * @brief Invariant: a rule follows a link only when the link's target fits a rule
 *   path; a prefix that is no link keeps no second name.
 *
 * Triggering condition: a link to a directory whose path is longer than
 *   CHAOS_IO_MAX_RULE_PATH, and a rule for `/tmp`, a plain directory.
 *
 * Expected observable behaviour: the link rule matches by the link's name only; the
 *   `/tmp` rule has no resolved prefix.
 */
static void test_long_link_target_is_not_followed(void)
{
    char target[CHAOS_IO_MAX_RULE_PATH + 300U];
    char component[201];
    chaos_io_rule_t rule;
    char *slash;

    (void)memset(component, 'd', sizeof(component) - 1U);
    component[sizeof(component) - 1U] = '\0';
    (void)snprintf(target, sizeof(target), "%s", "/tmp/chaos-deep");
    (void)mkdir(target, 0700);
    while (strlen(target) < CHAOS_IO_MAX_RULE_PATH)
    {
        (void)strcat(target, "/");
        (void)strcat(target, component);
        assert(mkdir(target, 0700) == 0 || errno == EEXIST);
    }
    (void)unlink("/tmp/chaos-long-link");
    assert(symlink(target, "/tmp/chaos-long-link") == 0);

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(
        CHAOS_IO_CONFIG_PATH, "/tmp/chaos-long-link:read:EIO:1.0\n/tmp:write:EIO:1.0\n"
    );
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_READ, "/tmp/chaos-long-link/f", &rule) == 1);
    assert(rule.resolved_prefix == NULL);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/f", &rule) == 1);
    assert(rule.resolved_prefix == NULL);
    (void)strcat(target, "/f");
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_READ, target, &rule) == 0);

    assert(unlink("/tmp/chaos-long-link") == 0);
    *strrchr(target, '/') = '\0';
    for (;;)
    {
        assert(rmdir(target) == 0);
        slash = strrchr(target, '/');
        if (strcmp(target, "/tmp/chaos-deep") == 0 || slash == NULL)
        {
            break;
        }
        *slash = '\0';
    }
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_io_check_interval_ns = 0U;
    chaos_test_backup_file(CHAOS_IO_CONFIG_PATH, &g_config_backup);
    assert(atexit(chaos_test_restore_config_path) == 0);

    test_helper_primitives();
    test_parse_line_valid_cases();
    test_parse_line_invalid_cases();
    test_parse_buffer_and_selection();
    test_parse_buffer_error_paths();
    test_read_file_paths();
    test_reload_prepare_and_match();
    test_read_failure_keeps_rules_and_retries();
    test_change_stamp_beyond_mtime();
    test_fork_takes_over_orphaned_reload();
    test_prepare_preserves_errno();
    test_interrupted_read_is_retried();

    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_rules_follow_links();
    test_hits_file_survives_exec();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_read_file_rejects_changed_file();
    test_racy_rewrite_is_seen();
    test_pending_hits_written_after_interval();
    test_read_file_failure_kinds();
    test_matching_edges();
    test_hit_after_interval_is_written();
    test_long_link_target_is_not_followed();
    return 0;
}
