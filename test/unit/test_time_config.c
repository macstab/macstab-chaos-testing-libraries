#include "../support/test_time_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_TIME_DEFINE_TEST_GLOBALS();

static int g_test_config_force_open_fail = 0;
static int g_test_config_force_read_fail = 0;
static int g_test_config_force_cas_fail = 0;
static const int g_test_config_fake_fd = 8124;

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

static int chaos_time_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

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

typedef struct chaos_time_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_time_test_file_backup_t;

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

static void free_backup(chaos_time_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

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
        char invalid_line[] = "*:OFFSET:5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
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
