#include "../support/test_process_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

static int g_test_config_force_open_fail = 0;
static int g_test_config_force_read_fail = 0;
static int g_test_config_force_cas_fail = 0;
static const int g_test_config_fake_fd = 9312;

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

static int chaos_process_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

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

typedef struct chaos_process_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_process_test_file_backup_t;

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

static void free_backup(chaos_process_test_file_backup_t *backup)
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
