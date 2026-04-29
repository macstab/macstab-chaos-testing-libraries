#include "../support/test_dns_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_DNS_DEFINE_TEST_GLOBALS();

static int g_test_config_force_open_fail = 0;
static int g_test_config_force_read_fail = 0;
static int g_test_config_force_cas_fail = 0;
static const int g_test_config_fake_fd = 9124;

static int chaos_dns_test_config_open(const char *path, int flags, ...)
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

static ssize_t chaos_dns_test_config_read(int fd, void *buffer, size_t count)
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

static int chaos_dns_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

static int
chaos_dns_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_dns_test_config_open
#define read chaos_dns_test_config_read
#define close chaos_dns_test_config_close
#define chaos_dns_atomic_cas_u64 chaos_dns_test_atomic_cas_u64
#include "../../src/dns/chaos_dns_config.c"
#undef chaos_dns_atomic_cas_u64
#undef close
#undef read
#undef open

typedef struct chaos_dns_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_dns_test_file_backup_t;

static void backup_file(const char *path, chaos_dns_test_file_backup_t *backup)
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

static void restore_file(const char *path, const chaos_dns_test_file_backup_t *backup)
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

static void free_backup(chaos_dns_test_file_backup_t *backup)
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

    file = fopen(CHAOS_DNS_CONFIG_PATH, "w");
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
    char payload_text[] = "value@0.25";
    char split_text[] = "dns://api.example.com:REWRITE:alt.example.com";
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_DNS_MAX_VALUE];
    struct stat st;

    assert(chaos_dns_is_blank_char(' '));
    assert(chaos_dns_is_blank_char('\t'));
    assert(!chaos_dns_is_blank_char('x'));

    assert(strcmp(chaos_dns_trim(trim_text), "value") == 0);
    chaos_dns_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);
    assert(chaos_dns_ascii_case_equal("Example", "example"));
    assert(!chaos_dns_ascii_case_equal("Example", "sample"));
    assert(chaos_dns_ascii_case_ends_with("api.example.com", "example.com"));
    assert(!chaos_dns_ascii_case_ends_with("api.example.com", "other.com"));

    assert(chaos_dns_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_dns_parse_probability("2.0", &(double){0.0}) != 0);
    assert(chaos_dns_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_dns_parse_latency("bad", &(unsigned int){0U}) != 0);
    assert(chaos_dns_parse_limit("2", &(unsigned int){0U}) == 0);
    assert(chaos_dns_parse_limit("0", &(unsigned int){0U}) != 0);
    assert(chaos_dns_parse_family_filter("inet4") == CHAOS_DNS_FAMILY_INET4);
    assert(chaos_dns_parse_family_filter("inet6") == CHAOS_DNS_FAMILY_INET6);
    assert(chaos_dns_parse_family_filter("weird") == CHAOS_DNS_FAMILY_INVALID);
    assert(chaos_dns_parse_gai_name("EAI_AGAIN") == EAI_AGAIN);
    assert(chaos_dns_parse_gai_name("NOPE") == 0x7fffffff);
    assert(chaos_dns_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_dns_copy_text_value("", payload, sizeof(payload)) != 0);
    assert(
        chaos_dns_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "value") == 0);
    assert(chaos_dns_validate_override_value("127.0.0.1,[::1]"));
    assert(!chaos_dns_validate_override_value("bad-host"));
    assert(chaos_dns_override_token_valid("127.0.0.1"));
    assert(chaos_dns_override_token_valid("[::1]"));
    assert(!chaos_dns_override_token_valid("not-an-ip"));

    assert(chaos_dns_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "dns://api.example.com") == 0);
    assert(strcmp(effect_text, "REWRITE") == 0);
    assert(strcmp(value_text, "alt.example.com") == 0);
    assert(!chaos_dns_split_rule_fields("bad", &selector_text, &effect_text, &value_text));

    (void)memset(&st, 0, sizeof(st));
    st.st_size = 0;
    assert(chaos_dns_config_hash_mtime(NULL) == CHAOS_DNS_MTIME_MISSING);
    assert(
        chaos_dns_config_normalize_mtime_hash(CHAOS_DNS_MTIME_UNKNOWN) != CHAOS_DNS_MTIME_UNKNOWN
    );
    assert(chaos_dns_config_hash_mtime(&st) != 0U);
}

static void test_selector_matching(void)
{
    chaos_dns_selector_t selector;
    unsigned int rank = 0U;

    assert(chaos_dns_selector_parse("*", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", &rank
    ));
    assert(rank == 1U);

    assert(chaos_dns_selector_parse("dns://api.example.com", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "API.EXAMPLE.COM", &rank
    ));
    assert(rank == 3U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "other.example.com", &rank
    ));

    assert(chaos_dns_selector_parse("dns://*.example.com", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", &rank
    ));
    assert(rank == 2U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "example.com", &rank
    ));
    assert(chaos_dns_selector_parse("rdns://127.0.0.1", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(strcmp(selector.text, "127.0.0.1") == 0);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "127.0.0.1", &rank
    ));
    assert(rank == 3U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "127.0.0.1", &rank
    ));
    assert(chaos_dns_selector_parse("rdns://[::1]", &selector));
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(strcmp(selector.text, "::1") == 0);
    assert(chaos_dns_selector_parse("rdns://*", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "127.0.0.1", &rank
    ));
    assert(!chaos_dns_selector_parse("dns://", &selector));
    assert(!chaos_dns_selector_parse("dns://*bad", &selector));
    assert(!chaos_dns_selector_parse("rdns://bad-host", &selector));
    assert(!chaos_dns_selector_parse("rdns://*.example.com", &selector));
}

static void test_parse_line_and_buffer(void)
{
    chaos_dns_rule_t rule;
    chaos_dns_rule_t rules[10];
    size_t rule_count = 0U;
    char buffer[] = "dns://api.example.com:EAI_AGAIN:0.5\n"
                    "dns://api.example.com:LATENCY:25@0.4\n"
                    "dns://api.example.com:REWRITE:alt.example.com@0.3\n"
                    "*:SERVICE:https@1.0\n"
                    "*:OVERRIDE:127.0.0.1,[::1]@0.2\n"
                    "*:FILTER_FAMILY:inet6@0.5\n"
                    "*:LIMIT:2@0.7\n"
                    "*:SHUFFLE:0.8\n"
                    "rdns://127.0.0.1:EAI_FAIL:0.6\n"
                    "rdns://[::1]:SERVICE:redis@0.9\n";

    {
        char blank_line[] = " \n";

        assert(chaos_dns_config_parse_line(blank_line, &rule) == 0);
    }

    {
        char gai_line[] = "dns://api.example.com:EAI_AGAIN:0.5";
        assert(chaos_dns_config_parse_line(gai_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_GAI);
        assert(rule.gai_error == EAI_AGAIN);
    }
    {
        char latency_line[] = "dns://api.example.com:LATENCY:25@0.4";
        assert(chaos_dns_config_parse_line(latency_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
        assert(rule.probability == 0.4);
    }
    {
        char rewrite_line[] = "dns://api.example.com:REWRITE:alt.example.com@0.3";
        assert(chaos_dns_config_parse_line(rewrite_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_REWRITE);
        assert(strcmp(rule.text, "alt.example.com") == 0);
    }
    {
        char service_line[] = "*:SERVICE:https@1.0";
        assert(chaos_dns_config_parse_line(service_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_SERVICE);
        assert(strcmp(rule.text, "https") == 0);
    }
    {
        char override_line[] = "*:OVERRIDE:127.0.0.1,[::1]@0.2";
        assert(chaos_dns_config_parse_line(override_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_OVERRIDE);
    }
    {
        char family_line[] = "*:FILTER_FAMILY:inet6@0.5";
        assert(chaos_dns_config_parse_line(family_line, &rule) == 1);
        assert(rule.family == CHAOS_DNS_FAMILY_INET6);
    }
    {
        char limit_line[] = "*:LIMIT:2@0.7";
        assert(chaos_dns_config_parse_line(limit_line, &rule) == 1);
        assert(rule.limit == 2U);
    }
    {
        char shuffle_line[] = "*:SHUFFLE:0.8";
        assert(chaos_dns_config_parse_line(shuffle_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_SHUFFLE);
    }
    {
        char reverse_gai_line[] = "rdns://127.0.0.1:EAI_FAIL:0.6";
        assert(chaos_dns_config_parse_line(reverse_gai_line, &rule) == 1);
        assert(rule.selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
        assert(rule.effect == CHAOS_DNS_EFFECT_GAI);
        assert(rule.gai_error == EAI_FAIL);
    }
    {
        char reverse_service_line[] = "rdns://[::1]:SERVICE:redis@0.9";
        assert(chaos_dns_config_parse_line(reverse_service_line, &rule) == 1);
        assert(rule.selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
        assert(rule.effect == CHAOS_DNS_EFFECT_SERVICE);
        assert(strcmp(rule.text, "redis") == 0);
    }
    {
        char invalid_line[] = "dns://api.example.com:OVERRIDE:not-a-host@1.0";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "dns://api.example.com:FILTER_FAMILY:bad";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "rdns://127.0.0.1:OVERRIDE:127.0.0.1";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "rdns://127.0.0.1:LIMIT:1";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_dns_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 10U);
}

static void test_rule_selection(void)
{
    chaos_dns_rule_t rules[5];
    chaos_dns_rule_t selected;
    char exact_line[] = "dns://api.example.com:SHUFFLE:1.0";
    char suffix_line[] = "dns://*.example.com:SHUFFLE:1.0";
    char any_line[] = "*:SHUFFLE:1.0";
    char reverse_any_line[] = "rdns://*:SERVICE:svc";
    char reverse_exact_line[] = "rdns://127.0.0.1:SERVICE:redis";

    assert(chaos_dns_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_dns_config_parse_line(suffix_line, &rules[1]) == 1);
    assert(chaos_dns_config_parse_line(exact_line, &rules[2]) == 1);
    assert(chaos_dns_config_parse_line(reverse_any_line, &rules[3]) == 1);
    assert(chaos_dns_config_parse_line(reverse_exact_line, &rules[4]) == 1);

    assert(chaos_dns_config_select_rule(
        rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "api.example.com", &selected
    ));
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(chaos_dns_config_select_rule(
        rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.example.com", &selected
    ));
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(chaos_dns_config_select_rule(rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "other.net", &selected)
    );
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(chaos_dns_config_select_reverse_rule(
        rules, 5U, CHAOS_DNS_EFFECT_SERVICE, "127.0.0.1", &selected
    ));
    assert(strcmp(selected.text, "redis") == 0);
    assert(
        chaos_dns_config_select_reverse_rule(rules, 5U, CHAOS_DNS_EFFECT_SERVICE, "::1", &selected)
    );
    assert(strcmp(selected.text, "svc") == 0);
}

static void test_prepare_and_match(void)
{
    chaos_dns_rule_t rule;
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();

    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    assert(!chaos_dns_config_prepare());

    write_config_text("dns://api.example.com:REWRITE:alt.example.com\n", 10);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, "api.example.com", &rule));
    assert(strcmp(rule.text, "alt.example.com") == 0);
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_LIMIT, "api.example.com", &rule));
    assert(chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_REWRITE, "api.example.com", &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));

    write_config_text("rdns://127.0.0.1:REWRITE:ptr.example\n", 11);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));
    assert(strcmp(rule.text, "ptr.example") == 0);
    assert(chaos_dns_config_match_reverse_loaded(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));

    g_test_config_force_cas_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 12);
    assert(chaos_dns_config_prepare());
    g_test_config_force_cas_fail = 0;

    g_test_config_force_open_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 13);
    assert(!chaos_dns_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 14);
    assert(!chaos_dns_config_prepare());
    g_test_config_force_read_fail = 0;

    write_config_text("dns://api.example.com:OVERRIDE:not-a-host\n", 15);
    assert(!chaos_dns_config_prepare());
    assert(!chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_OVERRIDE, "api.example.com", &rule));
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, NULL, &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, NULL, &rule));

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

int main(void)
{
    test_helper_functions();
    test_selector_matching();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    return 0;
}
