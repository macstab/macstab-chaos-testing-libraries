#include "../support/test_net_support.h"

#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_NET_DEFINE_TEST_GLOBALS();

#include "../../src/net/chaos_net_endpoint.c"

static int g_test_config_force_open_fail = 0;
static int g_test_config_force_read_fail = 0;
static int g_test_config_force_cas_fail = 0;
static const int g_test_config_fake_fd = 9123;

static int chaos_net_test_config_open(const char *path, int flags, ...)
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

static ssize_t chaos_net_test_config_read(int fd, void *buffer, size_t count)
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

static int chaos_net_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

static int
chaos_net_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_net_test_config_open
#define read chaos_net_test_config_read
#define close chaos_net_test_config_close
#define chaos_net_atomic_cas_u64 chaos_net_test_atomic_cas_u64
#include "../../src/net/chaos_net_config.c"
#undef chaos_net_atomic_cas_u64
#undef close
#undef read
#undef open

typedef struct chaos_net_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_net_test_file_backup_t;

static void backup_file(const char *path, chaos_net_test_file_backup_t *backup)
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

static void restore_file(const char *path, const chaos_net_test_file_backup_t *backup)
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

static void free_backup(chaos_net_test_file_backup_t *backup)
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

    file = fopen(CHAOS_NET_CONFIG_PATH, "w");
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
    char comment_text[] = "abc#def";
    char split_text[] = "tcp4://127.0.0.1:5432:connect:LATENCY:5";
    char missing_value_sep[] = "selector-only";
    char missing_effect_sep[] = "selector:op";
    char missing_operation_sep[] = "selector:op:effect";
    char *selector_text = NULL;
    char *operation_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    chaos_net_endpoint_t selector;
    struct stat st;
    size_t index;
    static const struct
    {
        const char *name;
        chaos_net_operation_t operation;
    } operations[] = {
        {"bind", CHAOS_NET_OP_BIND},
        {"listen", CHAOS_NET_OP_LISTEN},
        {"connect", CHAOS_NET_OP_CONNECT},
        {"accept", CHAOS_NET_OP_ACCEPT},
        {"socket", CHAOS_NET_OP_SOCKET},
        {"shutdown", CHAOS_NET_OP_SHUTDOWN},
        {"poll", CHAOS_NET_OP_POLL},
        {"send", CHAOS_NET_OP_SEND},
        {"recv", CHAOS_NET_OP_RECV}
    };
    static const struct
    {
        const char *name;
        int errnum;
    } errnos[] = {
        {"ECONNREFUSED", ECONNREFUSED},
        {"ETIMEDOUT", ETIMEDOUT},
        {"ECONNRESET", ECONNRESET},
        {"EHOSTUNREACH", EHOSTUNREACH},
        {"ENETUNREACH", ENETUNREACH},
        {"EADDRINUSE", EADDRINUSE},
        {"EADDRNOTAVAIL", EADDRNOTAVAIL},
        {"EAFNOSUPPORT", EAFNOSUPPORT},
        {"EPROTONOSUPPORT", EPROTONOSUPPORT},
        {"EPIPE", EPIPE},
        {"ENOTCONN", ENOTCONN},
        {"EOPNOTSUPP", EOPNOTSUPP},
        {"EINVAL", EINVAL},
        {"EINTR", EINTR},
        {"ENOMEM", ENOMEM},
        {"ENOBUFS", ENOBUFS},
        {"EMFILE", EMFILE},
        {"ENFILE", ENFILE},
        {"EAGAIN", EAGAIN}
    };
    assert(chaos_net_is_blank_char(' '));
    assert(chaos_net_is_blank_char('\t'));
    assert(!chaos_net_is_blank_char('x'));
    assert(chaos_net_trim(NULL) == NULL);
    assert(strcmp(chaos_net_trim(trim_text), "value") == 0);
    chaos_net_strip_comment(NULL);
    chaos_net_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);

    for (index = 0U; index < sizeof(operations) / sizeof(operations[0]); ++index)
    {
        assert(chaos_net_parse_operation(operations[index].name) == operations[index].operation);
    }
    assert(chaos_net_parse_operation(NULL) == CHAOS_NET_OP_INVALID);
    assert(chaos_net_parse_operation("bogus") == CHAOS_NET_OP_INVALID);

    for (index = 0U; index < sizeof(errnos) / sizeof(errnos[0]); ++index)
    {
        assert(chaos_net_parse_errno_name(errnos[index].name) == errnos[index].errnum);
    }
    assert(chaos_net_parse_errno_name(NULL) == -1);
    assert(chaos_net_parse_errno_name("ENOPE") == -1);

    {
        double probability = 0.0;
        unsigned int latency_ms = 0U;

        assert(chaos_net_parse_probability("0.25", &probability) == 0);
        assert(probability == 0.25);
        assert(chaos_net_parse_probability(NULL, &probability) == -1);
        assert(chaos_net_parse_probability("2.0", &probability) == -1);
        assert(chaos_net_parse_probability("x", &probability) == -1);

        assert(chaos_net_parse_latency("25", &latency_ms) == 0);
        assert(latency_ms == 25U);
        assert(chaos_net_parse_latency(NULL, &latency_ms) == -1);
        assert(chaos_net_parse_latency("42949672960", &latency_ms) == -1);
        assert(chaos_net_parse_latency("x", &latency_ms) == -1);
    }

    assert(chaos_net_effect_allowed(CHAOS_NET_OP_CONNECT, CHAOS_NET_EFFECT_LATENCY));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_BIND, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_ACCEPT, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_SOCKET, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_SHUTDOWN, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_POLL, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_SEND, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_RECV, CHAOS_NET_EFFECT_ERRNO));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_RECV, CHAOS_NET_EFFECT_CORRUPT));
    assert(chaos_net_effect_allowed(CHAOS_NET_OP_POLL, CHAOS_NET_EFFECT_TIMEOUT));
    assert(!chaos_net_effect_allowed(CHAOS_NET_OP_INVALID, CHAOS_NET_EFFECT_LATENCY));
    assert(!chaos_net_effect_allowed(CHAOS_NET_OP_CONNECT, (chaos_net_effect_t)9999));

    assert(!chaos_net_selector_allowed(CHAOS_NET_OP_CONNECT, NULL));
    assert(chaos_net_endpoint_parse_selector("*", &selector));
    assert(chaos_net_selector_allowed(CHAOS_NET_OP_CONNECT, &selector));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:80", &selector));
    assert(chaos_net_selector_allowed(CHAOS_NET_OP_SEND, &selector));
    assert(chaos_net_endpoint_parse_selector("tcp4://*:0", &selector));
    assert(chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));
    assert(selector.wildcard_host == 1);
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:1", &selector));
    assert(!chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));
    assert(chaos_net_endpoint_parse_selector("unix://*", &selector));
    assert(chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));
    assert(chaos_net_endpoint_parse_selector("unix:///tmp/app.sock", &selector));
    assert(!chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));

    assert(
        chaos_net_config_normalize_mtime_hash(CHAOS_NET_MTIME_MISSING) != CHAOS_NET_MTIME_MISSING
    );
    assert(
        chaos_net_config_normalize_mtime_hash(CHAOS_NET_MTIME_RELOADING) !=
        CHAOS_NET_MTIME_RELOADING
    );
    assert(
        chaos_net_config_normalize_mtime_hash(CHAOS_NET_MTIME_UNKNOWN) != CHAOS_NET_MTIME_UNKNOWN
    );
    assert(chaos_net_config_hash_mtime(NULL) == CHAOS_NET_MTIME_MISSING);
    (void)memset(&st, 0, sizeof(st));
#if defined(__linux__)
    st.st_mtim.tv_sec = 11;
    st.st_mtim.tv_nsec = 12;
#else
    st.st_mtimespec.tv_sec = 11;
    st.st_mtimespec.tv_nsec = 12;
#endif
    assert(chaos_net_config_hash_mtime(&st) != CHAOS_NET_MTIME_MISSING);

    assert(chaos_net_config_read_file(NULL) == -1);
    assert(!chaos_net_split_rule_fields(
        NULL, &selector_text, &operation_text, &effect_text, &value_text
    ));
    assert(!chaos_net_split_rule_fields(
        missing_value_sep, &selector_text, &operation_text, &effect_text, &value_text
    ));
    assert(!chaos_net_split_rule_fields(
        missing_effect_sep, &selector_text, &operation_text, &effect_text, &value_text
    ));
    assert(!chaos_net_split_rule_fields(
        missing_operation_sep, &selector_text, &operation_text, &effect_text, &value_text
    ));
    assert(chaos_net_split_rule_fields(
        split_text, &selector_text, &operation_text, &effect_text, &value_text
    ));
    assert(strcmp(selector_text, "tcp4://127.0.0.1:5432") == 0);
    assert(strcmp(operation_text, "connect") == 0);
    assert(strcmp(effect_text, "LATENCY") == 0);
    assert(strcmp(value_text, "5") == 0);
}

static void test_parse_and_select_rules(void)
{
    chaos_net_rule_t rules[7];
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint;
    size_t rule_count = 0U;
    char buffer[] = "tcp4://*:5432:connect:ECONNREFUSED:0.5\n"
                    "tcp4://127.0.0.1:5432:connect:LATENCY:10\n"
                    "tcp4://*:0:socket:EAFNOSUPPORT:1.0\n"
                    "unix://*:socket:LATENCY:5\n"
                    "tcp4://127.0.0.1:5432:shutdown:ENOTCONN:1.0\n"
                    "tcp4://127.0.0.1:5432:poll:TIMEOUT:0.4\n"
                    "unix:///tmp/app.sock:recv:CORRUPT:1.0\n";

    assert(chaos_net_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 7U);
    assert(rules[0].operation == CHAOS_NET_OP_CONNECT);
    assert(rules[0].effect == CHAOS_NET_EFFECT_ERRNO);
    assert(rules[2].operation == CHAOS_NET_OP_SOCKET);
    assert(rules[2].errnum == EAFNOSUPPORT);
    assert(rules[4].operation == CHAOS_NET_OP_SHUTDOWN);
    assert(rules[5].effect == CHAOS_NET_EFFECT_TIMEOUT);
    assert(rules[6].effect == CHAOS_NET_EFFECT_CORRUPT);

    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5432", &endpoint));
    assert(chaos_net_config_select_endpoint_rule(
        rules, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, &rule
    ));
    assert(rule.effect == CHAOS_NET_EFFECT_LATENCY);

    assert(chaos_net_endpoint_parse_selector("tcp4://*:0", &endpoint));
    assert(chaos_net_config_select_endpoint_rule(
        rules, rule_count, CHAOS_NET_OP_SOCKET, &endpoint, &rule
    ));
    assert(rule.effect == CHAOS_NET_EFFECT_ERRNO);

    assert(
        chaos_net_config_select_endpoint_rule(
            rules, rule_count, CHAOS_NET_OP_POLL, &endpoint, &rule
        ) == 0
    );
}

static void test_selection_and_buffer_edges(void)
{
    static const char overflow_line[] = "tcp4://127.0.0.1:80:connect:ECONNREFUSED:1.0\n";
    chaos_net_rule_t rules[CHAOS_NET_MAX_RULES];
    chaos_net_rule_t tie_rules[2];
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint;
    size_t rule_count = 0U;
    size_t index;
    char overflow_buffer[(CHAOS_NET_MAX_RULES + 1U) * sizeof(overflow_line)];
    size_t offset = 0U;
    char buffer[] = "# comment\n"
                    " \n"
                    "tcp4://*:80:connect:ECONNREFUSED:1.0\n"
                    "tcp4://127.0.0.1:80:connect:EHOSTUNREACH:1.0\n"
                    "*:poll:TIMEOUT:1.0\n"
                    "unix:///tmp/app.sock:recv:CORRUPT:1.0\n";

    assert(chaos_net_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 4U);

    assert(!chaos_net_config_select_endpoint_rule(
        NULL, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, &rule
    ));
    assert(
        !chaos_net_config_select_endpoint_rule(rules, rule_count, CHAOS_NET_OP_CONNECT, NULL, &rule)
    );
    assert(!chaos_net_config_select_endpoint_rule(
        rules, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, NULL
    ));

    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:80", &endpoint));
    assert(chaos_net_config_select_endpoint_rule(
        rules, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, &rule
    ));
    assert(rule.errnum == EHOSTUNREACH);
    assert(!chaos_net_config_select_endpoint_rule(
        rules, rule_count, CHAOS_NET_OP_RECV, &endpoint, &rule
    ));

    assert(chaos_net_config_parse_buffer(NULL, rules, &rule_count) == -1);
    assert(chaos_net_config_parse_buffer(buffer, NULL, &rule_count) == -1);
    assert(chaos_net_config_parse_buffer(buffer, rules, NULL) == -1);

    for (index = 0U; index <= CHAOS_NET_MAX_RULES; ++index)
    {
        int written = snprintf(
            overflow_buffer + offset, sizeof(overflow_buffer) - offset, "%s", overflow_line
        );

        assert(written > 0);
        assert((size_t)written < sizeof(overflow_buffer) - offset);
        offset += (size_t)written;
    }
    assert(chaos_net_config_parse_buffer(overflow_buffer, rules, &rule_count) == -1);

    (void)memset(tie_rules, 0, sizeof(tie_rules));
    assert(chaos_net_endpoint_parse_selector("tcp4://*:80", &tie_rules[0].selector));
    tie_rules[0].operation = CHAOS_NET_OP_CONNECT;
    tie_rules[0].effect = CHAOS_NET_EFFECT_LATENCY;
    tie_rules[0].latency_ms = 5U;
    tie_rules[0].selector.selector_len = 10U;
    tie_rules[1] = tie_rules[0];
    tie_rules[1].latency_ms = 7U;
    tie_rules[1].selector.selector_len = 12U;
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:80", &endpoint));
    assert(
        chaos_net_config_select_endpoint_rule(tie_rules, 2U, CHAOS_NET_OP_CONNECT, &endpoint, &rule)
    );
    assert(rule.latency_ms == 7U);
}

static void test_invalid_lines(void)
{
    char blank_line[] = "  # ignored";
    char invalid_effect[] = "tcp4://127.0.0.1:5432:connect:BOOM:0.1";
    char invalid_combo[] = "tcp4://127.0.0.1:5432:connect:CORRUPT:0.1";
    char invalid_selector[] = "tcp4://127.0.0.1:connect:EIO:0.1";
    char invalid_timeout_combo[] = "tcp4://127.0.0.1:5432:connect:TIMEOUT:0.1";
    char invalid_socket_combo[] = "unix:///tmp/app.sock:socket:EAFNOSUPPORT:0.1";
    char missing_fields[] = "tcp4://127.0.0.1:5432";
    char empty_selector[] = ":connect:LATENCY:1";
    char empty_operation[] = "tcp4://127.0.0.1:5432::LATENCY:1";
    char empty_effect[] = "tcp4://127.0.0.1:5432:connect::1";
    char empty_value[] = "tcp4://127.0.0.1:5432:connect:LATENCY:";
    char invalid_operation[] = "tcp4://127.0.0.1:5432:nope:LATENCY:1";
    char invalid_errno_value[] = "tcp4://127.0.0.1:5432:connect:ECONNREFUSED:x";
    char invalid_latency_value[] = "tcp4://127.0.0.1:5432:connect:LATENCY:x";
    char invalid_corrupt_value[] = "tcp4://127.0.0.1:5432:recv:CORRUPT:x";
    char invalid_timeout_value[] = "tcp4://127.0.0.1:5432:poll:TIMEOUT:x";
    chaos_net_rule_t rule;

    assert(chaos_net_config_parse_line(blank_line, &rule) == 0);
    assert(chaos_net_config_parse_line(NULL, &rule) == -1);
    assert(chaos_net_config_parse_line(blank_line, NULL) == -1);
    assert(chaos_net_config_parse_line(missing_fields, &rule) == -1);
    assert(chaos_net_config_parse_line(empty_selector, &rule) == -1);
    assert(chaos_net_config_parse_line(empty_operation, &rule) == -1);
    assert(chaos_net_config_parse_line(empty_effect, &rule) == -1);
    assert(chaos_net_config_parse_line(empty_value, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_operation, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_effect, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_combo, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_selector, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_timeout_combo, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_socket_combo, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_errno_value, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_latency_value, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_corrupt_value, &rule) == -1);
    assert(chaos_net_config_parse_line(invalid_timeout_value, &rule) == -1);
}

static void test_file_and_state_edges(void)
{
    chaos_net_test_file_backup_t backup;
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint;
    FILE *file;
    size_t index;

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    g_test_config_force_open_fail = 0;
    g_test_config_force_read_fail = 0;
    g_test_config_force_cas_fail = 0;

    chaos_net_config_init();
    chaos_net_config_reset_state(NULL, 1);
    assert(chaos_net_config_observed_mtime() == CHAOS_NET_MTIME_MISSING);

    (void)unlink(CHAOS_NET_CONFIG_PATH);
    g_test_config_force_open_fail = 1;
    assert(chaos_net_config_read_file(&index) == -1);
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    assert(chaos_net_config_read_file(&index) == -1);
    g_test_config_force_read_fail = 0;

    file = fopen(CHAOS_NET_CONFIG_PATH, "w");
    assert(file != NULL);
    for (index = 0U; index < CHAOS_NET_MAX_CONFIG_BYTES; ++index)
    {
        assert(fputc('a', file) != EOF);
    }
    assert(fclose(file) == 0);
    assert(chaos_net_config_read_file(&index) == -1);

    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 30);
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9010", &endpoint));
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
    assert(chaos_net_config_prepare());
    assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
    assert(rule.errnum == ECONNREFUSED);

    g_chaos_net_cached_mtime = chaos_net_config_observed_mtime();
    assert(chaos_net_config_prepare());

    chaos_net_config_reset_state(&g_chaos_net_config_states[g_chaos_net_active_config_index], 1);
    g_chaos_net_config_states[g_chaos_net_active_config_index].rule_count = 1U;
    g_test_config_force_cas_fail = 1;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
    assert(chaos_net_config_prepare());
    g_test_config_force_cas_fail = 0;

    write_config_text("tcp4://127.0.0.1:9010:connect:CORRUPT:1.0\n", 31);
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
    assert(!chaos_net_config_prepare());
    assert(!chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));

    chaos_net_config_reset_state(&g_chaos_net_config_states[g_chaos_net_active_config_index], 0);
    assert(!chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

static void test_prepare_and_match(void)
{
    chaos_net_test_file_backup_t backup;
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint;

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);

    chaos_net_config_init();
    (void)unlink(CHAOS_NET_CONFIG_PATH);
    assert(!chaos_net_config_prepare());

    write_config_text("tcp4://127.0.0.1:9000:connect:ECONNREFUSED:1.0\n", 10);
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9000", &endpoint));
    assert(!chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, NULL, &rule));
    assert(!chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, &endpoint, NULL));
    assert(chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
    assert(rule.effect == CHAOS_NET_EFFECT_ERRNO);
    assert(rule.errnum == ECONNREFUSED);

    write_config_text("tcp4://127.0.0.1:9000:connect:CORRUPT:1.0\n", 11);
    assert(!chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, &endpoint, &rule));

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

int main(void)
{
    test_helper_functions();
    test_parse_and_select_rules();
    test_selection_and_buffer_edges();
    test_invalid_lines();
    test_file_and_state_edges();
    test_prepare_and_match();
    return 0;
}
