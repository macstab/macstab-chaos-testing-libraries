#include "chaos_dns_config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__linux__)
#define CHAOS_DNS_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_DNS_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_DNS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

typedef struct chaos_dns_config_state
{
    chaos_dns_rule_t rules[CHAOS_DNS_MAX_RULES];
    size_t rule_count;
    int parse_ok;
} chaos_dns_config_state_t;

static chaos_dns_config_state_t g_chaos_dns_config_states[2];
static volatile unsigned int g_chaos_dns_active_config_index = 0U;
static volatile uint64_t g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;
static __thread char g_chaos_dns_config_buffer[CHAOS_DNS_MAX_CONFIG_BYTES + 1U];

static void chaos_dns_config_reset_state(chaos_dns_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

static const chaos_dns_config_state_t *chaos_dns_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_dns_active_config_index;
    return &g_chaos_dns_config_states[index];
}

static void chaos_dns_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_dns_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_dns_cached_mtime = observed_mtime;
}

static int chaos_dns_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static char *chaos_dns_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_dns_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_dns_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

static void chaos_dns_strip_comment(char *line)
{
    char *comment;

    if (line == NULL)
    {
        return;
    }

    comment = strchr(line, '#');
    if (comment != NULL)
    {
        *comment = '\0';
    }
}

static int chaos_dns_ascii_case_equal(const char *left, const char *right)
{
    unsigned char left_ch;
    unsigned char right_ch;

    if (left == NULL || right == NULL)
    {
        return 0;
    }

    while (*left != '\0' && *right != '\0')
    {
        left_ch = (unsigned char)*left++;
        right_ch = (unsigned char)*right++;
        if (tolower(left_ch) != tolower(right_ch))
        {
            return 0;
        }
    }

    return *left == '\0' && *right == '\0';
}

static int chaos_dns_ascii_case_ends_with(const char *text, const char *suffix)
{
    size_t text_len;
    size_t suffix_len;

    if (text == NULL || suffix == NULL)
    {
        return 0;
    }

    text_len = strlen(text);
    suffix_len = strlen(suffix);
    if (text_len < suffix_len)
    {
        return 0;
    }

    return chaos_dns_ascii_case_equal(text + (text_len - suffix_len), suffix);
}

static int chaos_dns_parse_reverse_selector_body(const char *body, chaos_dns_selector_t *selector)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    const char *source = body;
    size_t body_len;

    if (body == NULL || selector == NULL || *body == '\0')
    {
        return 0;
    }
    if (strcmp(body, "*") == 0)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind = CHAOS_DNS_SELECTOR_ANY;
        return 1;
    }

    body_len = strlen(body);
    if (body[0] == '[')
    {
        if (body_len <= 2U || body[body_len - 1U] != ']')
        {
            return 0;
        }
        if (body_len - 2U >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, body + 1, body_len - 2U);
        host[body_len - 2U] = '\0';
        source = host;
    }
    else if (body_len >= sizeof(host))
    {
        return 0;
    }

    if (inet_pton(AF_INET, source, &ipv4) == 1)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        return inet_ntop(AF_INET, &ipv4, selector->text, sizeof(selector->text)) != NULL;
    }
    if (inet_pton(AF_INET6, source, &ipv6) == 1)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_REVERSE;
        selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        return inet_ntop(AF_INET6, &ipv6, selector->text, sizeof(selector->text)) != NULL;
    }

    return 0;
}

static int chaos_dns_selector_parse(const char *text, chaos_dns_selector_t *selector)
{
    const char *body;
    size_t body_len;

    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP;
        selector->kind = CHAOS_DNS_SELECTOR_ANY;
        return 1;
    }
    if (strncmp(text, "dns://", 6) == 0)
    {
        body = text + 6;
        if (*body == '\0')
        {
            return 0;
        }
        selector->domain = CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP;
        if (strcmp(body, "*") == 0)
        {
            selector->kind = CHAOS_DNS_SELECTOR_ANY;
            return 1;
        }
        if (strncmp(body, "*.", 2) == 0)
        {
            body += 2;
            selector->kind = CHAOS_DNS_SELECTOR_SUFFIX;
        }
        else
        {
            selector->kind = CHAOS_DNS_SELECTOR_EXACT;
        }

        body_len = strlen(body);
        if (body_len == 0U || body_len >= sizeof(selector->text) || strchr(body, '*') != NULL)
        {
            return 0;
        }

        (void)memcpy(selector->text, body, body_len + 1U);
        return 1;
    }
    if (strncmp(text, "rdns://", 7) == 0)
    {
        return chaos_dns_parse_reverse_selector_body(text + 7, selector);
    }

    return 0;
}

static int chaos_dns_selector_matches_domain(
    const chaos_dns_selector_t *selector,
    chaos_dns_selector_domain_t domain,
    const char *name,
    unsigned int *rank_out
)
{
    size_t name_len;
    size_t suffix_len;

    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL || name == NULL || *name == '\0' || selector->domain != domain)
    {
        return 0;
    }
    if (selector->kind == CHAOS_DNS_SELECTOR_ANY)
    {
        if (rank_out != NULL)
        {
            *rank_out = 1U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_DNS_SELECTOR_EXACT)
    {
        if (!chaos_dns_ascii_case_equal(selector->text, name))
        {
            return 0;
        }
        if (rank_out != NULL)
        {
            *rank_out = 3U;
        }
        return 1;
    }
    if (domain != CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP || selector->kind != CHAOS_DNS_SELECTOR_SUFFIX)
    {
        return 0;
    }

    name_len = strlen(name);
    suffix_len = strlen(selector->text);
    if (name_len <= suffix_len)
    {
        return 0;
    }
    if (!chaos_dns_ascii_case_ends_with(name, selector->text))
    {
        return 0;
    }
    if (name[name_len - suffix_len - 1U] != '.')
    {
        return 0;
    }
    if (rank_out != NULL)
    {
        *rank_out = 2U;
    }
    return 1;
}

static int chaos_dns_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_dns_trim(end) != '\0')
    {
        return -1;
    }
    if (value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

static int chaos_dns_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_dns_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

static int chaos_dns_parse_limit(const char *text, unsigned int *limit)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || limit == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_dns_trim(end) != '\0' || value == 0UL || value > 0xffffffffUL)
    {
        return -1;
    }

    *limit = (unsigned int)value;
    return 0;
}

static int chaos_dns_effect_allowed(const chaos_dns_selector_t *selector, chaos_dns_effect_t effect)
{
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP)
    {
        return 1;
    }
    if (selector->domain != CHAOS_DNS_SELECTOR_DOMAIN_REVERSE)
    {
        return 0;
    }

    return effect == CHAOS_DNS_EFFECT_GAI || effect == CHAOS_DNS_EFFECT_LATENCY ||
           effect == CHAOS_DNS_EFFECT_REWRITE || effect == CHAOS_DNS_EFFECT_SERVICE;
}

static chaos_dns_family_filter_t chaos_dns_parse_family_filter(const char *text)
{
    if (text == NULL)
    {
        return CHAOS_DNS_FAMILY_INVALID;
    }
    if (strcmp(text, "inet4") == 0 || strcmp(text, "ipv4") == 0)
    {
        return CHAOS_DNS_FAMILY_INET4;
    }
    if (strcmp(text, "inet6") == 0 || strcmp(text, "ipv6") == 0)
    {
        return CHAOS_DNS_FAMILY_INET6;
    }
    if (strcmp(text, "any") == 0)
    {
        return CHAOS_DNS_FAMILY_ANY;
    }
    return CHAOS_DNS_FAMILY_INVALID;
}

static int chaos_dns_parse_gai_name(const char *text)
{
    if (text == NULL)
    {
        return 0x7fffffff;
    }
    if (strcmp(text, "EAI_AGAIN") == 0)
    {
        return EAI_AGAIN;
    }
    if (strcmp(text, "EAI_FAIL") == 0)
    {
        return EAI_FAIL;
    }
    if (strcmp(text, "EAI_NONAME") == 0)
    {
        return EAI_NONAME;
    }
    if (strcmp(text, "EAI_MEMORY") == 0)
    {
        return EAI_MEMORY;
    }
    if (strcmp(text, "EAI_SYSTEM") == 0)
    {
        return EAI_SYSTEM;
    }
    return 0x7fffffff;
}

static int chaos_dns_copy_text_value(const char *text, char *target, size_t target_size)
{
    size_t len;

    if (text == NULL || target == NULL || target_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len == 0U || len >= target_size)
    {
        return -1;
    }
    (void)memcpy(target, text, len + 1U);
    return 0;
}

static int chaos_dns_parse_payload_probability(
    const char *text, char *payload, size_t payload_size, double *probability
)
{
    const char *separator;
    size_t payload_len;
    char probability_text[64];
    char payload_text[CHAOS_DNS_MAX_VALUE];

    if (text == NULL || payload == NULL || probability == NULL)
    {
        return -1;
    }

    separator = strrchr(text, '@');
    if (separator == NULL)
    {
        *probability = 1.0;
        return chaos_dns_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(separator - text);
    if (payload_len == 0U || payload_len >= sizeof(payload_text))
    {
        return -1;
    }
    (void)memcpy(payload_text, text, payload_len);
    payload_text[payload_len] = '\0';
    if (chaos_dns_copy_text_value(chaos_dns_trim(payload_text), payload, payload_size) != 0)
    {
        return -1;
    }
    if (chaos_dns_copy_text_value(separator + 1, probability_text, sizeof(probability_text)) != 0)
    {
        return -1;
    }

    return chaos_dns_parse_probability(probability_text, probability);
}

static int chaos_dns_override_token_valid(const char *token)
{
    char host[INET6_ADDRSTRLEN];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t len;

    if (token == NULL || *token == '\0')
    {
        return 0;
    }

    len = strlen(token);
    if (len >= sizeof(host))
    {
        return 0;
    }
    if (token[0] == '[' && len > 2U && token[len - 1U] == ']')
    {
        if (len - 2U >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, token + 1, len - 2U);
        host[len - 2U] = '\0';
    }
    else
    {
        (void)memcpy(host, token, len + 1U);
    }

    (void)memset(&ipv4, 0, sizeof(ipv4));
    (void)memset(&ipv6, 0, sizeof(ipv6));

    return inet_pton(AF_INET, host, &ipv4) == 1 || inet_pton(AF_INET6, host, &ipv6) == 1;
}

static int chaos_dns_validate_override_value(const char *text)
{
    char buffer[CHAOS_DNS_MAX_VALUE];
    char *cursor;
    int found = 0;

    if (chaos_dns_copy_text_value(text, buffer, sizeof(buffer)) != 0)
    {
        return 0;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *token = cursor;
        char *separator = strchr(cursor, ',');

        if (separator != NULL)
        {
            *separator++ = '\0';
            cursor = separator;
        }
        else
        {
            cursor += strlen(cursor);
        }

        token = chaos_dns_trim(token);
        if (*token == '\0' || !chaos_dns_override_token_valid(token))
        {
            return 0;
        }
        found = 1;
    }

    return found;
}

static uint64_t chaos_dns_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_DNS_MTIME_MISSING || value == CHAOS_DNS_MTIME_RELOADING ||
        value == CHAOS_DNS_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

static uint64_t chaos_dns_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_DNS_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_DNS_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_dns_config_normalize_mtime_hash(value);
}

static uint64_t chaos_dns_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_dns_enter_internal();
    rc = stat(CHAOS_DNS_CONFIG_PATH, &st);
    chaos_dns_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_DNS_MTIME_MISSING;
    }

    return chaos_dns_config_hash_mtime(&st);
}

static int chaos_dns_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_dns_enter_internal();
    fd = open(CHAOS_DNS_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_dns_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_dns_config_buffer + total, CHAOS_DNS_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_dns_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_DNS_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_dns_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_dns_leave_internal(previous);
    g_chaos_dns_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

static int
chaos_dns_split_rule_fields(char *line, char **selector_text, char **effect_text, char **value_text)
{
    char *selector_end;
    char *effect_end;

    if (line == NULL || selector_text == NULL || effect_text == NULL || value_text == NULL)
    {
        return 0;
    }

    if (line[0] == '*' && line[1] == ':')
    {
        selector_end = line + 1;
    }
    else if (strncmp(line, "dns://", 6) == 0)
    {
        selector_end = strchr(line + 6, ':');
    }
    else if (strncmp(line, "rdns://[", 8) == 0)
    {
        char *close = strchr(line + 8, ']');

        if (close == NULL || close[1] != ':')
        {
            return 0;
        }
        selector_end = close + 1;
    }
    else if (strncmp(line, "rdns://", 7) == 0)
    {
        selector_end = strchr(line + 7, ':');
    }
    else
    {
        return 0;
    }
    if (selector_end == NULL)
    {
        return 0;
    }

    *selector_end++ = '\0';
    effect_end = strchr(selector_end, ':');
    if (effect_end == NULL)
    {
        return 0;
    }
    *effect_end++ = '\0';

    *selector_text = chaos_dns_trim(line);
    *effect_text = chaos_dns_trim(selector_end);
    *value_text = chaos_dns_trim(effect_end);
    return 1;
}

void chaos_dns_config_init(void)
{
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[0], 1);
    chaos_dns_config_reset_state(&g_chaos_dns_config_states[1], 1);
    g_chaos_dns_active_config_index = 0U;
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;
}

int chaos_dns_config_parse_line(char *line, chaos_dns_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_DNS_MAX_VALUE];
    int gai_error;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_dns_strip_comment(line);
    line = chaos_dns_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_dns_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_dns_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    gai_error = chaos_dns_parse_gai_name(effect_text);
    if (gai_error != 0x7fffffff)
    {
        rule->effect = CHAOS_DNS_EFFECT_GAI;
        rule->gai_error = gai_error;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        return chaos_dns_parse_probability(value_text, &rule->probability) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_LATENCY;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "REWRITE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_REWRITE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "SERVICE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_SERVICE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "OVERRIDE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_OVERRIDE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        if (!chaos_dns_validate_override_value(payload))
        {
            return -1;
        }
        return chaos_dns_copy_text_value(payload, rule->text, sizeof(rule->text)) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "FILTER_FAMILY") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_FILTER_FAMILY;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        rule->family = chaos_dns_parse_family_filter(payload);
        return rule->family != CHAOS_DNS_FAMILY_INVALID ? 1 : -1;
    }
    if (strcmp(effect_text, "LIMIT") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_LIMIT;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        if (chaos_dns_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_dns_parse_limit(payload, &rule->limit) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "SHUFFLE") == 0)
    {
        rule->effect = CHAOS_DNS_EFFECT_SHUFFLE;
        if (!chaos_dns_effect_allowed(&rule->selector, rule->effect))
        {
            return -1;
        }
        return chaos_dns_parse_probability(value_text, &rule->probability) == 0 ? 1 : -1;
    }

    return -1;
}

int chaos_dns_config_parse_buffer(char *buffer, chaos_dns_rule_t *rules, size_t *rule_count)
{
    char *cursor;
    size_t count = 0U;

    if (buffer == NULL || rules == NULL || rule_count == NULL)
    {
        return -1;
    }

    cursor = buffer;
    while (*cursor != '\0')
    {
        char *line = cursor;
        int rc;

        if (count >= CHAOS_DNS_MAX_RULES)
        {
            return -1;
        }
        while (*cursor != '\0' && *cursor != '\n')
        {
            ++cursor;
        }
        if (*cursor == '\n')
        {
            *cursor++ = '\0';
        }

        rc = chaos_dns_config_parse_line(line, &rules[count]);
        if (rc < 0)
        {
            return -1;
        }
        if (rc == 0)
        {
            continue;
        }

        ++count;
    }

    *rule_count = count;
    return 0;
}

static int chaos_dns_config_select_rule_domain(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    chaos_dns_selector_domain_t domain,
    const char *name,
    chaos_dns_rule_t *rule
)
{
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

    if (rules == NULL || name == NULL || rule == NULL)
    {
        return 0;
    }

    for (index = 0U; index < rule_count; ++index)
    {
        unsigned int rank = 0U;

        if (rules[index].effect != effect)
        {
            continue;
        }
        if (!chaos_dns_selector_matches_domain(&rules[index].selector, domain, name, &rank))
        {
            continue;
        }
        if (!found || rank > best_rank ||
            (rank == best_rank && rules[index].selector.selector_len > best_len))
        {
            *rule = rules[index];
            best_rank = rank;
            best_len = rules[index].selector.selector_len;
            found = 1;
        }
    }

    return found;
}

int chaos_dns_config_select_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *name,
    chaos_dns_rule_t *rule
)
{
    return chaos_dns_config_select_rule_domain(
        rules, rule_count, effect, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, name, rule
    );
}

int chaos_dns_config_select_reverse_rule(
    const chaos_dns_rule_t *rules,
    size_t rule_count,
    chaos_dns_effect_t effect,
    const char *address,
    chaos_dns_rule_t *rule
)
{
    return chaos_dns_config_select_rule_domain(
        rules, rule_count, effect, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, address, rule
    );
}

int chaos_dns_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_dns_config_state_t *next_state;

    observed_mtime = chaos_dns_config_observed_mtime();
    cached_mtime = chaos_dns_atomic_load_u64(&g_chaos_dns_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }
    if (!chaos_dns_atomic_cas_u64(
            &g_chaos_dns_cached_mtime, cached_mtime, CHAOS_DNS_MTIME_RELOADING
        ))
    {
        return chaos_dns_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_dns_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_dns_config_states[next_index];
    chaos_dns_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_DNS_MTIME_MISSING &&
        chaos_dns_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_dns_config_parse_buffer(
            g_chaos_dns_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_dns_config_reset_state(next_state, 0);
    }

    chaos_dns_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

int chaos_dns_config_match_loaded(
    chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_rule(state->rules, state->rule_count, effect, name, rule);
}

int chaos_dns_config_match_reverse_loaded(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    const chaos_dns_config_state_t *state = chaos_dns_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_dns_config_select_reverse_rule(
        state->rules, state->rule_count, effect, address, rule
    );
}

int chaos_dns_config_match(chaos_dns_effect_t effect, const char *name, chaos_dns_rule_t *rule)
{
    if (name == NULL || *name == '\0' || rule == NULL || !chaos_dns_config_prepare())
    {
        return 0;
    }

    return chaos_dns_config_match_loaded(effect, name, rule);
}

int chaos_dns_config_match_reverse(
    chaos_dns_effect_t effect, const char *address, chaos_dns_rule_t *rule
)
{
    if (address == NULL || *address == '\0' || rule == NULL || !chaos_dns_config_prepare())
    {
        return 0;
    }

    return chaos_dns_config_match_reverse_loaded(effect, address, rule);
}
