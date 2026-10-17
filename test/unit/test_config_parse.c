/**
 * @file test_config_parse.c
 * @brief Proves the libchaos-io rule file pipeline: field parsers, line and buffer
 *        parsing, rule selection, reading the rule file, the reload state machine, status
 *        and hits reporting, qualifiers, and rules that follow symlinks.
 *
 * @details Unit under test: `src/config/chaos_io_config.c`, compiled in by `#include`.
 *
 * Isolation:
 * - The module reads the rule file through the real-function pointers
 *   `g_chaos_io_real_open` / `_read` / `_close`, the same dispatch the wrappers use. Tests
 *   point them at stubs (fixed result and errno, call counters, EINTR injection) to reach
 *   every failure branch, or back at libc via `chaos_test_use_real_io()` to run against
 *   the live rule file `/tmp/.chaos-io.conf`.
 * - Build hooks defined before the include: `CHAOS_IO_RULE_SUPPORTED` switches every rule
 *   to unsupported (the chaos-init rejection path); `CHAOS_IO_LINKS_RECHECK_MS` makes a
 *   symlink-dependent load due for re-resolution at once; `CHAOS_RACY_WINDOW_MS` is
 *   widened to 5000 ms so a restored mtime still counts as recent on a slow machine.
 * - Module state (`g_chaos_io_cached_mtime`, hits counters, throttle stamps) is set
 *   directly to reach sentinel and timing branches deterministically.
 * - The live rule file is backed up before the suite and restored by an atexit handler,
 *   also after an assertion failure.
 *
 * Not covered here: the wrapper call paths (test_chaos_io.c), concurrent
 * prepare/match races on the double-buffered snapshot, and loading through the
 * LD_PRELOAD constructor.
 */

/* A rule file counts as just written for 5 s instead of 20 ms: the racily-clean test
 * restores an earlier mtime and must still find it recent on a slow machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_support.h"

#include <stdint.h>
#include <sys/stat.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

/** @brief fd the open stub returns; -1 (default) makes it fail with `g_stub_open_errno`. */
static int g_stub_open_result = -1;

/** @brief errno the open stub sets (default EIO, retried; EACCES/EPERM are lasting). */
static int g_stub_open_errno = EIO;

/** @brief Value the close stub returns; the reader ignores it. */
static int g_stub_close_result = 0;

/** @brief close stub calls; proves the fd is closed on every error path after open. */
static int g_stub_close_calls = 0;

/** @brief Value the read stub returns; CHAOS_IO_MAX_CONFIG_BYTES simulates a full buffer. */
static ssize_t g_stub_read_result = -1;

/** @brief errno the read stub sets (default EIO; EISDIR is lasting). */
static int g_stub_read_errno = EIO;

/** @brief read stub calls; a full first read must stop the loop after one call. */
static size_t g_stub_read_calls = 0U;

/** @brief open stand-in: sets `g_stub_open_errno`, returns `g_stub_open_result`. */
static int chaos_test_stub_open(const char *path, int flags, ...)
{
    (void)path;
    (void)flags;
    errno = g_stub_open_errno;
    return g_stub_open_result;
}

/** @brief read stand-in: counts, sets `g_stub_read_errno`, returns `g_stub_read_result`. */
static ssize_t chaos_test_stub_read(int fd, void *buffer, size_t count)
{
    (void)fd;
    (void)buffer;
    (void)count;
    ++g_stub_read_calls;
    errno = g_stub_read_errno;
    return g_stub_read_result;
}

/** @brief Upcoming reads `chaos_test_eintr_read` fails with EINTR before reading for real. */
static int g_stub_read_eintr = 0;

/** @brief read that fails with EINTR `g_stub_read_eintr` times, then reads for real. */
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

/** @brief close stand-in: counts and returns `g_stub_close_result` without closing. */
static int chaos_test_stub_close(int fd)
{
    (void)fd;
    ++g_stub_close_calls;
    return g_stub_close_result;
}

/* Build hook chaos-init uses to reject rules it cannot apply; here a runtime switch. */
static int g_test_rules_unsupported = 0;
#define CHAOS_IO_RULE_SUPPORTED(rule) ((void)(rule), !g_test_rules_unsupported)
/* How long a load whose rules resolve through symlinks is trusted; 0 makes it due at once. */
static unsigned g_test_links_recheck_ms = 1000U;
#define CHAOS_IO_LINKS_RECHECK_MS g_test_links_recheck_ms
#include "../../src/config/chaos_io_config.c"

/** @brief The live rule file as it was before the suite, restored at exit. */
static chaos_test_file_backup_t g_config_backup;

/** @brief atexit handler: restores (or removes) the live rule file. */
static void chaos_test_restore_config_path(void)
{
    chaos_test_restore_file(CHAOS_IO_CONFIG_PATH, &g_config_backup);
    chaos_test_free_backup(&g_config_backup);
}

/** @brief Resets stub results, errnos and counters; leaves the function pointers alone. */
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
 * @brief Field-level helpers at their boundaries.
 *
 * @details Trimming, comment stripping, state reset (from 0xff garbage), all 14 operation
 * names, the 8 accepted errno names (EINVAL is not one), probability and latency parsing
 * (NULL input or output, trailing garbage, > 1.0, > UINT32_MAX ms, trailing whitespace
 * allowed), the TORN/CORRUPT operation classes, and the change-stamp sentinels: a real
 * stat hash that collides with MISSING, RELOADING or UNKNOWN is moved off it, so a file
 * can never be mistaken for a sentinel state.
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
 * @brief Every operation with ERRNO, plus LATENCY, TORN and CORRUPT, parses into the
 *        expected fields; comment-only and empty lines return 0 (no rule).
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
 * @brief Malformed or semantically invalid lines return -1: NULL arguments, 3 or 5
 *        fields, any empty field, unknown operation or effect, non-numeric value, TORN on
 *        a non-write operation, probability outside [0, 1], and a path prefix of
 *        CHAOS_IO_MAX_RULE_PATH bytes or more.
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
 * @brief Buffer parsing and rule selection.
 *
 * @details Comments and blank lines are skipped. An unsupported rule rejects the whole
 * buffer with the line number. Prefix matching is boundary-aware (`/data` covers
 * `/data/file`, not `/database`); `*` matches files only, never pipes, sockets,
 * anonymous inodes or memfds. Selection picks the longest matching prefix for the
 * operation, and returns 0 when no rule has the operation.
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

    /* A build that cannot apply a rule (chaos-init) rejects the file and names the line. */
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
    /* `*` is for files: a TORN or CORRUPT meant for files would break the protocols of
     * pipes, sockets, anonymous inodes (eventfd) and memfds. */
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
 * @brief A buffer with an invalid rule, or with CHAOS_IO_MAX_RULES + 1 rules, returns -1
 *        and sets the rule count to 0 whatever it held before (17, 99), so a rejected file
 *        never leaves a partial rule set.
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
 * @brief Reading the rule file: argument checks and error classification.
 *
 * @details Return codes: 0 read; -1 transient (retried on the next check); -2 file fills
 * CHAOS_IO_MAX_CONFIG_BYTES (reported as too large); -3 lasting (EACCES/EPERM on open,
 * kept until the file changes). A NULL size_out or any NULL real-function pointer is -1
 * without I/O; a failed read still closes the fd; a full first read stops after one call.
 * Finally a real read of the live file returns its exact bytes.
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
 * @brief The reload state machine and matching on the active snapshot.
 *
 * @details A missing file publishes an empty snapshot under the MISSING stamp. A failed
 * read publishes nothing and restores the previous stamp so the next call retries. A
 * valid file loads and matches by operation and path (excluded paths such as /proc
 * never match). While another caller holds the RELOADING claim, prepare() serves the
 * active snapshot without reading. An invalid file publishes an empty snapshot.
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
    /* The read failed: nothing is published and the claim is released with the previous
     * stamp, so the next call retries instead of running without rules. */
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
 * @brief A transient read failure keeps the active rules and retries: with open failing
 *        the old single rule stays active and the stamp is not advanced (nor left at
 *        RELOADING); the next call with working I/O loads both new rules.
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
 * @brief The change stamp hashes size and inode as well as mtime, so a rewrite within one
 *        mtime tick that changes size, or an atomic replace (new inode), is still seen.
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
 * @brief A RELOADING claim is never taken over by prepare(); only the fork child handler
 *        releases it.
 *
 * @details The test name predates this design: a vfork child shares memory with a parent
 * whose reload may still be running, so prepare() must not steal the claim whoever made
 * it. chaos_io_config_after_fork() resets the child's PRNG state, rebinds the hits pid and
 * turns RELOADING into UNKNOWN so the next prepare() reloads; on a settled stamp it
 * changes nothing.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");

    /* A claim is never taken over, whoever made it: in a vfork child the parent's reload
     * thread is still running. A fork() child's atfork handler releases it. */
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
 * @brief prepare() never changes the caller's errno: neither the ENOENT of stat(2) on a
 *        missing file nor anything from a successful load.
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

/** @brief A read failing with EINTR is retried and the rules load normally. */
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
 * @brief A file whose stamp after reading differs from the stamp that triggered the
 *        reload is discarded (-1): the copy may be half old, half new. The matching stamp
 *        reads successfully.
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

/** @brief Reads the status file into @p buffer; returns 0 when it does not exist. */
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
 * @brief The rejected line is recorded with its 1-based number, the reason and its text
 *        as written (comment included, though the parser cuts it); exactly
 *        CHAOS_IO_MAX_RULES rules followed by a comment is accepted with no error; one
 *        rule more reports that rule as "too many rules".
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
 * @brief Every load outcome is written to the status file, stamped with this pid.
 *
 * @details An invalid line gives state=error with line, reason and text; a valid file
 * gives state=ok with the rule count; a file of CHAOS_IO_MAX_CONFIG_BYTES is "file too
 * large", one containing a NUL byte "file contains a NUL byte", a directory (EISDIR) or
 * an unreadable file (EACCES, skipped as root) "file unreadable". Without a rule file
 * the status file is removed.
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

    /* A file at the size limit is reported, not silently truncated or re-read. */
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

    /* A NUL byte rejects the file: the line parser would stop there and silently drop
     * every rule after it while reporting state=ok. */
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

    /* An unreadable rule file is reported: a directory (EISDIR on read) and, unless
     * running as root (which bypasses permissions), mode 000 (EACCES on open). */
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

/** @brief Reads this process's hits file into @p buffer; returns 0 when it does not exist. */
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
 * @brief A rule naming a symlink also covers paths under its target, the form in which
 *        /proc/self/fd reports descriptors; rule paths are normalised (`//tmp//plain/`
 *        becomes `/tmp/plain`) and a prefix that is no link gets no resolved name.
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
 * @brief Symlink resolution keeps up with links that move, without a rule file change.
 *
 * @details A rule for a file that does not exist yet resolves its directory and appends
 * the name. When the link is retargeted (as a ConfigMap update does),
 * the new target is used once the recheck is due, not before. A due recheck that finds
 * nothing moved keeps the snapshot (same active index), preserving counts and claims. A
 * prefix without links is never rechecked; a prefix that does not exist at all is
 * rechecked and stays unresolved; a resolution too long to append the rest stays
 * unresolved.
 */
static void test_rules_follow_moving_links(void)
{
    chaos_io_rule_t rule;
    unsigned int index;
    char deep[PATH_MAX];
    char long_rule[CHAOS_IO_MAX_RULE_PATH];
    char component[201];

    chaos_test_reset_runtime();
    chaos_test_use_real_io();
    (void)unlink("/tmp/chaos-cm");
    (void)mkdir("/tmp/chaos-cm-a", 0700);
    (void)mkdir("/tmp/chaos-cm-b", 0700);
    assert(symlink("/tmp/chaos-cm-a", "/tmp/chaos-cm") == 0);
    chaos_io_config_init();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/tmp/chaos-cm/db:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    /* db does not exist yet: its directory is resolved and the name appended. */
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/chaos-cm-a/db", &rule) == 1);
    assert(chaos_io_config_active_state()->links);

    /* The link moves: not re-resolved before the recheck is due, then followed. */
    assert(unlink("/tmp/chaos-cm") == 0 && symlink("/tmp/chaos-cm-b", "/tmp/chaos-cm") == 0);
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/chaos-cm-b/db", &rule) == 0);
    g_test_links_recheck_ms = 0U;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/chaos-cm-b/db", &rule) == 1);
    assert(chaos_io_config_match_loaded(CHAOS_IO_OP_WRITE, "/tmp/chaos-cm-a/db", &rule) == 0);
    /* Due again with nothing moved: no new snapshot is published. */
    index = g_chaos_io_active_config_index;
    assert(chaos_io_config_prepare() == 1);
    assert(g_chaos_io_active_config_index == index);
    g_test_links_recheck_ms = 1000U;

    /* A prefix with no link that exists: never rechecked. A prefix that does not exist:
     * rechecked, nothing resolved. A resolution too long for the remaining components to
     * be appended within PATH_MAX: none. */
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/tmp:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(!chaos_io_config_active_state()->links);
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/chaos-no-such-root/x:write:EIO:1.0\n");
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_active_state()->links);
    assert(chaos_io_config_active_state()->rules[0].resolved_prefix == NULL);
    (void)memset(component, 'e', sizeof(component) - 1U);
    component[sizeof(component) - 1U] = '\0';
    (void)snprintf(deep, sizeof(deep), "%s", "/tmp/chaos-deeper");
    (void)mkdir(deep, 0700);
    while (strlen(deep) < PATH_MAX - 400U)
    {
        (void)strcat(deep, "/");
        (void)strcat(deep, component);
        assert(mkdir(deep, 0700) == 0 || errno == EEXIST);
    }
    (void)unlink("/tmp/chaos-deeper-link");
    assert(symlink(deep, "/tmp/chaos-deeper-link") == 0);
    (void
    )snprintf(long_rule, sizeof(long_rule), "/tmp/chaos-deeper-link/%s/%s/x", component, component);
    {
        char text[CHAOS_IO_MAX_RULE_PATH + 32U];

        (void)snprintf(text, sizeof(text), "%s:write:EIO:1.0\n", long_rule);
        chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, text);
    }
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
    assert(chaos_io_config_prepare() == 1);
    assert(chaos_io_config_active_state()->rules[0].resolved_prefix == NULL);

    assert(unlink("/tmp/chaos-deeper-link") == 0);
    while (strcmp(deep, "/tmp/chaos-deeper") != 0)
    {
        assert(rmdir(deep) == 0);
        *strrchr(deep, '/') = '\0';
    }
    assert(rmdir(deep) == 0);
    assert(unlink("/tmp/chaos-cm") == 0);
    assert(rmdir("/tmp/chaos-cm-a") == 0 && rmdir("/tmp/chaos-cm-b") == 0);
    (void)unlink(CHAOS_IO_CONFIG_PATH);
}

/**
 * @brief When the pid already has a hits file (left by the image an execve replaced), the
 *        new image writes under pid * 10^9 + salt, above any pid (PID_MAX_LIMIT 2^22),
 *        instead of overwriting it; errno is preserved.
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

/**
 * @brief Hit counting and hits file reporting through reloads, contention, throttling,
 *        exit and fork.
 *
 * @details Each rule of a snapshot owns a hit slot; the hits file lists count and rule
 * text. A reload keeps the count of a rule whose text is unchanged. A hit that finds the
 * writer flag held stays pending instead of being lost; past CHAOS_HITS_EAGER hits a hit
 * within CHAOS_HITS_INTERVAL_MS is deferred to the exit report, which then has nothing
 * left. In a fork child the writer flag is released, counts restart at 0, a REGRESS
 * decision in progress (state 3) re-arms (1) and a fired one (2) stays. A process that
 * only inherited counts (other pid) writes nothing at exit.
 */
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

    /* A writer flag held when the process forked would never be released in the child
     * (the writer thread does not exist there): after_fork releases it and the child
     * counts from zero. */
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
 * @brief Once rules are loaded, the rule file is stat'ed at most once per check interval:
 *        right after a check a removed file goes unnoticed, one interval later it is seen.
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
 * @brief Qualifiers after a rule land in its policy (a trailing comment is allowed) and
 *        the rule starts with an unknown call size; an unknown qualifier, qualifiers on a
 *        line without a rule, `@until` before `@from` and `@first=0` reject the buffer.
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
 * @brief An in-place rewrite within one mtime tick is still loaded.
 *
 * @details The rewrite keeps size, inode, device and (restored via futimens) mtime, so
 * the change stamp cannot see it. A load of a file whose mtime is within
 * CHAOS_RACY_WINDOW_MS is therefore provisional and re-read on every check; an unchanged
 * re-read keeps the snapshot (content hash equal), the rewrite is loaded. Once the mtime
 * lies outside the window the load becomes final.
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

    /* Re-read with nothing changed: the same snapshot stays. */
    assert(chaos_io_config_prepare());
    assert(g_chaos_io_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* Same size, first byte commented out, written in place, mtime restored. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_IO_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_io_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window (1970): the load is final and not re-read. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_IO_CONFIG_PATH, times, 0) == 0);
    assert(chaos_io_config_prepare() == 0);
    assert(g_chaos_io_config_provisional == 0);

    (void)unlink(CHAOS_IO_CONFIG_PATH);
    g_chaos_io_check_interval_ns = interval;
}

/**
 * @brief Pending hits are flushed by the next rule file check once CHAOS_HITS_INTERVAL_MS
 *        has passed, not only by the next hit or at exit; before that they stay pending.
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

/** @brief Upcoming opens `chaos_test_eintr_open` fails with EINTR before opening for real. */
static int g_stub_open_eintr = 0;

/** @brief open that fails with EINTR `g_stub_open_eintr` times, then opens for real. */
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
 * @brief Failure classification of the rule file read: no read function is -1 with
 *        nothing opened; EPERM on open is lasting (-3) like EACCES; EISDIR on read is
 *        lasting and closes the fd; a failing fstat (EBADF on fd 1000) is transient (-1)
 *        and closes the fd; an open interrupted by EINTR is retried.
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

    /* fd 1000 is not open: read returns 0 (stub) and the stamp fstat fails with EBADF. */
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
 * @brief Matching edge cases: TORN/CORRUPT operation classes, a last line without a
 *        newline, the longest prefix winning whatever the rule order, an empty prefix
 *        covering only absolute paths, and a rule matching through both its written and
 *        its resolved prefix at a path boundary (`/real` does not cover `/realm`).
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

    /* An empty prefix covers a path only at a boundary, i.e. an absolute path. */
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
 * @brief Past CHAOS_HITS_EAGER hits, a hit arriving after CHAOS_HITS_INTERVAL_MS is written
 *        at once (nothing left pending).
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
 * @brief A link whose target is CHAOS_IO_MAX_RULE_PATH bytes or longer is not followed:
 *        the rule matches by the link's name only, never under the target; a plain
 *        directory prefix (`/tmp`) has no resolved name.
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
    /* Check the rule file on every call; the throttle has its own test. */
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
    test_rules_follow_moving_links();
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
