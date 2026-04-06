#include "../support/test_support.h"

#include <stdint.h>
#include <sys/stat.h>

CHAOS_IO_DEFINE_TEST_GLOBALS();

static int g_stub_open_result = -1;
static int g_stub_open_errno = EIO;
static int g_stub_close_result = 0;
static int g_stub_close_calls = 0;
static ssize_t g_stub_read_result = -1;
static int g_stub_read_errno = EIO;
static size_t g_stub_read_calls = 0U;

static int chaos_test_stub_open(const char *path, int flags, ...)
{
    (void)path;
    (void)flags;
    errno = g_stub_open_errno;
    return g_stub_open_result;
}

static ssize_t chaos_test_stub_read(int fd, void *buffer, size_t count)
{
    (void)fd;
    (void)buffer;
    (void)count;
    ++g_stub_read_calls;
    errno = g_stub_read_errno;
    return g_stub_read_result;
}

static int chaos_test_stub_close(int fd)
{
    (void)fd;
    ++g_stub_close_calls;
    return g_stub_close_result;
}

#include "../../src/config/chaos_io_config.c"

static chaos_test_file_backup_t g_config_backup;

static void chaos_test_restore_config_path(void)
{
    chaos_test_restore_file(CHAOS_IO_CONFIG_PATH, &g_config_backup);
    chaos_test_free_backup(&g_config_backup);
}

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
    assert(chaos_io_config_normalize_mtime_hash(CHAOS_IO_MTIME_RELOADING) != CHAOS_IO_MTIME_RELOADING);
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

static void test_parse_line_valid_cases(void)
{
    static const struct {
        const char *line;
        chaos_io_operation_t operation;
        chaos_io_effect_t effect;
        int errnum;
        double probability;
        unsigned int latency_ms;
    } cases[] = {
        { "/data:read:EIO:0.1", CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_ERRNO, EIO, 0.1, 0U },
        { "/data:write:ENOSPC:0.2", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_ERRNO, ENOSPC, 0.2, 0U },
        { "/data:open:EMFILE:0.3", CHAOS_IO_OP_OPEN, CHAOS_IO_EFFECT_ERRNO, EMFILE, 0.3, 0U },
        { "/data:close:EDQUOT:0.4", CHAOS_IO_OP_CLOSE, CHAOS_IO_EFFECT_ERRNO, EDQUOT, 0.4, 0U },
        { "/data:fsync:EROFS:0.5", CHAOS_IO_OP_FSYNC, CHAOS_IO_EFFECT_ERRNO, EROFS, 0.5, 0U },
        { "/data:fdatasync:EACCES:0.6", CHAOS_IO_OP_FDATASYNC, CHAOS_IO_EFFECT_ERRNO, EACCES, 0.6, 0U },
        { "/data:pread:ENOENT:0.7", CHAOS_IO_OP_PREAD, CHAOS_IO_EFFECT_ERRNO, ENOENT, 0.7, 0U },
        { "/data:pwrite:ENFILE:0.8", CHAOS_IO_OP_PWRITE, CHAOS_IO_EFFECT_ERRNO, ENFILE, 0.8, 0U },
        { "/data:truncate:EIO:0.2", CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U },
        { "/data:allocate:EIO:0.2", CHAOS_IO_OP_ALLOCATE, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U },
        { "/data:unlink:EIO:0.2", CHAOS_IO_OP_UNLINK, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U },
        { "/data:rename_from:EIO:0.2", CHAOS_IO_OP_RENAME_FROM, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U },
        { "/data:rename_to:EIO:0.2", CHAOS_IO_OP_RENAME_TO, CHAOS_IO_EFFECT_ERRNO, EIO, 0.2, 0U },
        { "/data:write:LATENCY:25", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_LATENCY, 0, 0.0, 25U },
        { "/data:truncate:LATENCY:25", CHAOS_IO_OP_TRUNCATE, CHAOS_IO_EFFECT_LATENCY, 0, 0.0, 25U },
        { "/data:write:TORN:0.9", CHAOS_IO_OP_WRITE, CHAOS_IO_EFFECT_TORN, 0, 0.9, 0U },
        { "/data:read:CORRUPT:1.0", CHAOS_IO_OP_READ, CHAOS_IO_EFFECT_CORRUPT, 0, 1.0, 0U }
    };
    size_t index;

    for (index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        char line[128];
        chaos_io_rule_t rule;

        (void)snprintf(line, sizeof(line), "%s", cases[index].line);
        assert(chaos_io_config_parse_line(line, &rule) == 1);
        assert(rule.operation == cases[index].operation);
        assert(rule.effect == cases[index].effect);
        if (rule.effect == CHAOS_IO_EFFECT_ERRNO) {
            assert(rule.errnum == cases[index].errnum);
            assert(rule.probability == cases[index].probability);
        }
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
            assert(rule.latency_ms == cases[index].latency_ms);
        }
        if (rule.effect == CHAOS_IO_EFFECT_TORN || rule.effect == CHAOS_IO_EFFECT_CORRUPT) {
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
        "read:EIO:0.1");
    assert(chaos_io_config_parse_line(long_path_line, &rule) == -1);
}

static void test_parse_buffer_and_selection(void)
{
    char buffer[] =
        "# comment\n"
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
    assert(chaos_io_rule_prefix_matches(NULL, "/data") == 0);
    assert(chaos_io_rule_prefix_matches(&rules[0], NULL) == 0);
    assert(chaos_io_rule_prefix_matches(&rules[0], "/tmp/file"));
    assert(chaos_io_rule_prefix_matches(&rules[1], "/data"));
    assert(chaos_io_rule_prefix_matches(&rules[1], "/data/file"));
    assert(!chaos_io_rule_prefix_matches(&rules[1], "/tmp/file"));
    assert(!chaos_io_rule_prefix_matches(&rules[1], "/database"));
    assert(chaos_io_rule_prefix_matches(&rules[3], "/data/wal/0001"));

    assert(chaos_io_config_select_rule(NULL, rule_count, CHAOS_IO_OP_WRITE, "/data", &match) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, NULL, &match) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, "/data", NULL) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, "/data/wal.log", &match) == 1);
    assert(match.errnum == ENOSPC);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_OPEN, "/tmp/file", &match) == 1);
    assert(strcmp(match.path_prefix, "*") == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_WRITE, "/tmp/file", &match) == 0);
    assert(chaos_io_config_select_rule(rules, rule_count, CHAOS_IO_OP_CLOSE, "/tmp/file", &match) == 0);
}

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
    for (index = 0U; index <= CHAOS_IO_MAX_RULES; ++index) {
        (void)strcat(overflow_buffer, "*:open:EIO:0.0\n");
    }

    rule_count = 99U;
    assert(chaos_io_config_parse_buffer(overflow_buffer, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    free(overflow_buffer);
}

static void test_read_file_paths(void)
{
    size_t size_out = 99U;

    chaos_test_reset_runtime();
    chaos_test_reset_read_stubs();

    assert(chaos_io_config_read_file(NULL) == -1);
    assert(chaos_io_config_read_file(&size_out) == -1);

    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    assert(chaos_io_config_read_file(&size_out) == -1);

    g_chaos_io_real_close = chaos_test_stub_close;
    assert(chaos_io_config_read_file(&size_out) == -1);

    g_stub_open_result = 7;
    g_stub_read_result = -1;
    assert(chaos_io_config_read_file(&size_out) == -1);
    assert(g_stub_close_calls == 1);

    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    g_chaos_io_real_close = chaos_test_stub_close;
    g_stub_open_result = 8;
    g_stub_read_result = (ssize_t)CHAOS_IO_MAX_CONFIG_BYTES;
    assert(chaos_io_config_read_file(&size_out) == -1);
    assert(g_stub_read_calls == 1U);

    chaos_test_use_real_io();
    chaos_test_write_text_file(CHAOS_IO_CONFIG_PATH, "/data:write:EIO:1.0\n");
    assert(chaos_io_config_read_file(&size_out) == 0);
    assert(size_out == strlen("/data:write:EIO:1.0\n"));
    assert(strcmp(g_chaos_io_config_buffer, "/data:write:EIO:1.0\n") == 0);
}

static void test_reload_prepare_and_match(void)
{
    chaos_io_rule_t rule;

    chaos_test_use_real_io();
    chaos_io_config_init();
    chaos_test_remove_file_if_exists(CHAOS_IO_CONFIG_PATH);

    assert(chaos_io_config_observed_mtime() == CHAOS_IO_MTIME_MISSING);
    chaos_io_config_reload(CHAOS_IO_MTIME_MISSING);
    assert(g_chaos_io_cached_mtime == CHAOS_IO_MTIME_MISSING);
    assert(chaos_io_config_prepare() == 0);
    assert(chaos_io_config_prepare() == 0);

    chaos_test_reset_runtime();
    chaos_test_reset_read_stubs();
    g_chaos_io_real_open = chaos_test_stub_open;
    g_chaos_io_real_read = chaos_test_stub_read;
    g_chaos_io_real_close = chaos_test_stub_close;
    chaos_io_config_reload(UINT64_C(1234));
    assert(g_chaos_io_cached_mtime == UINT64_C(1234));
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

int main(void)
{
    chaos_test_backup_file(CHAOS_IO_CONFIG_PATH, &g_config_backup);
    assert(atexit(chaos_test_restore_config_path) == 0);

    test_helper_primitives();
    test_parse_line_valid_cases();
    test_parse_line_invalid_cases();
    test_parse_buffer_and_selection();
    test_parse_buffer_error_paths();
    test_read_file_paths();
    test_reload_prepare_and_match();

    return 0;
}
