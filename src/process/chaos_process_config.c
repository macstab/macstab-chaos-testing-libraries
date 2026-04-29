#include "chaos_process_config.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__linux__)
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_PROCESS_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_PROCESS_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

typedef struct chaos_process_config_state
{
    chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    size_t rule_count;
    int parse_ok;
} chaos_process_config_state_t;

static chaos_process_config_state_t g_chaos_process_config_states[2];
static volatile unsigned int g_chaos_process_active_config_index = 0U;
static volatile uint64_t g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
static __thread char g_chaos_process_config_buffer[CHAOS_PROCESS_MAX_CONFIG_BYTES + 1U];

static void chaos_process_reset_fail_after_counters(void)
{
    size_t index;

    for (index = 0U; index < (size_t)CHAOS_PROCESS_OP_COUNT; ++index)
    {
        g_chaos_process_fail_after_counters[index] = 0U;
    }
}

static void chaos_process_config_reset_state(chaos_process_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

static const chaos_process_config_state_t *chaos_process_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_process_active_config_index;
    return &g_chaos_process_config_states[index];
}

static void chaos_process_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    chaos_process_reset_fail_after_counters();
    __sync_synchronize();
    g_chaos_process_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_process_cached_mtime = observed_mtime;
}

static int chaos_process_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static char *chaos_process_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_process_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_process_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

static void chaos_process_strip_comment(char *line)
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

static int chaos_process_selector_parse(const char *text, chaos_process_selector_t *selector)
{
    if (text == NULL || selector == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(selector, 0, sizeof(*selector));
    selector->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_ANY;
        selector->operation = CHAOS_PROCESS_OP_INVALID;
        return 1;
    }
    if (strcmp(text, "pthread_create") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_PTHREAD_CREATE;
        return 1;
    }
    if (strcmp(text, "fork") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_FORK;
        return 1;
    }
    if (strcmp(text, "posix_spawn") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_POSIX_SPAWN;
        return 1;
    }
    if (strcmp(text, "posix_spawnp") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_POSIX_SPAWNP;
        return 1;
    }
    if (strcmp(text, "execve") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_EXECVE;
        return 1;
    }
    if (strcmp(text, "execveat") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_EXECVEAT;
        return 1;
    }
    if (strcmp(text, "waitpid") == 0)
    {
        selector->kind = CHAOS_PROCESS_SELECTOR_OPERATION;
        selector->operation = CHAOS_PROCESS_OP_WAITPID;
        return 1;
    }

    return 0;
}

static int chaos_process_selector_matches(
    const chaos_process_selector_t *selector,
    chaos_process_operation_t operation,
    unsigned int *rank_out
)
{
    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_PROCESS_SELECTOR_ANY)
    {
        if (rank_out != NULL)
        {
            *rank_out = 1U;
        }
        return 1;
    }
    if (selector->kind == CHAOS_PROCESS_SELECTOR_OPERATION && selector->operation == operation)
    {
        if (rank_out != NULL)
        {
            *rank_out = 2U;
        }
        return 1;
    }
    return 0;
}

static int chaos_process_parse_errno_name(const char *text)
{
    char *end = NULL;
    long value;

    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }
    if (strcmp(text, "ENOMEM") == 0)
    {
        return ENOMEM;
    }
    if (strcmp(text, "EACCES") == 0)
    {
        return EACCES;
    }
    if (strcmp(text, "ENOENT") == 0)
    {
        return ENOENT;
    }
    if (strcmp(text, "EINTR") == 0)
    {
        return EINTR;
    }
    if (strcmp(text, "ECHILD") == 0)
    {
        return ECHILD;
    }
    if (strcmp(text, "EPERM") == 0)
    {
        return EPERM;
    }
    if (strcmp(text, "ESRCH") == 0)
    {
        return ESRCH;
    }
    if (strcmp(text, "EBUSY") == 0)
    {
        return EBUSY;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "ENOSYS") == 0)
    {
        return ENOSYS;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "E2BIG") == 0)
    {
        return E2BIG;
    }

    value = strtol(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0' || value <= 0L || value > 0x7fffffffL)
    {
        return -1;
    }
    return (int)value;
}

static int chaos_process_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_process_trim(end) != '\0' || value < 0.0 || value > 1.0)
    {
        return -1;
    }

    *probability = value;
    return 0;
}

static int chaos_process_copy_text_value(const char *text, char *buffer, size_t buffer_size)
{
    size_t len;

    if (text == NULL || buffer == NULL || buffer_size == 0U)
    {
        return -1;
    }

    len = strlen(text);
    if (len == 0U || len >= buffer_size)
    {
        return -1;
    }

    (void)memcpy(buffer, text, len + 1U);
    return 0;
}

static int chaos_process_parse_payload_probability(
    const char *text, char *payload, size_t payload_size, double *probability
)
{
    const char *at_sign;
    size_t payload_len;

    if (text == NULL || payload == NULL || probability == NULL)
    {
        return -1;
    }

    *probability = 1.0;
    at_sign = strrchr(text, '@');
    if (at_sign == NULL)
    {
        return chaos_process_copy_text_value(text, payload, payload_size);
    }

    payload_len = (size_t)(at_sign - text);
    if (payload_len == 0U || payload_len >= payload_size)
    {
        return -1;
    }

    (void)memcpy(payload, text, payload_len);
    payload[payload_len] = '\0';
    if (chaos_process_parse_probability(at_sign + 1, probability) != 0)
    {
        return -1;
    }
    return 0;
}

static int chaos_process_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0' || value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

static int chaos_process_parse_fail_after_count(const char *text, uint64_t *count)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || count == NULL)
    {
        return -1;
    }

    value = strtoull(text, &end, 10);
    if (end == text || *chaos_process_trim(end) != '\0')
    {
        return -1;
    }

    *count = (uint64_t)value;
    return 0;
}

static int chaos_process_parse_fail_after_value(char *payload, int *errnum, uint64_t *count)
{
    char *comma;

    if (payload == NULL || errnum == NULL || count == NULL)
    {
        return -1;
    }

    comma = strchr(payload, ',');
    if (comma == NULL)
    {
        return -1;
    }
    *comma++ = '\0';
    payload = chaos_process_trim(payload);
    comma = chaos_process_trim(comma);
    if (*payload == '\0' || *comma == '\0')
    {
        return -1;
    }

    *errnum = chaos_process_parse_errno_name(payload);
    if (*errnum < 0)
    {
        return -1;
    }
    return chaos_process_parse_fail_after_count(comma, count);
}

static uint64_t chaos_process_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_PROCESS_MTIME_UNKNOWN || value == CHAOS_PROCESS_MTIME_RELOADING)
    {
        return value - 1U;
    }
    return value;
}

static uint64_t chaos_process_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_PROCESS_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_PROCESS_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_PROCESS_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_process_config_normalize_mtime_hash(value);
}

static uint64_t chaos_process_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_process_enter_internal();
    rc = stat(CHAOS_PROCESS_CONFIG_PATH, &st);
    chaos_process_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_PROCESS_MTIME_MISSING;
    }

    return chaos_process_config_hash_mtime(&st);
}

static int chaos_process_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_process_enter_internal();
    fd = open(CHAOS_PROCESS_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_process_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_process_config_buffer + total, CHAOS_PROCESS_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_process_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_PROCESS_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_process_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_process_leave_internal(previous);
    g_chaos_process_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

static int chaos_process_split_rule_fields(
    char *line, char **selector_text, char **effect_text, char **value_text
)
{
    char *selector_end;
    char *effect_end;

    if (line == NULL || selector_text == NULL || effect_text == NULL || value_text == NULL)
    {
        return 0;
    }

    selector_end = strchr(line, ':');
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

    *selector_text = chaos_process_trim(line);
    *effect_text = chaos_process_trim(selector_end);
    *value_text = chaos_process_trim(effect_end);
    return 1;
}

void chaos_process_config_init(void)
{
    chaos_process_config_reset_state(&g_chaos_process_config_states[0], 1);
    chaos_process_config_reset_state(&g_chaos_process_config_states[1], 1);
    g_chaos_process_active_config_index = 0U;
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
    chaos_process_reset_fail_after_counters();
}

int chaos_process_config_parse_line(char *line, chaos_process_rule_t *rule)
{
    char *selector_text;
    char *effect_text;
    char *value_text;
    char payload[CHAOS_PROCESS_MAX_VALUE];
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_process_strip_comment(line);
    line = chaos_process_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_process_split_rule_fields(line, &selector_text, &effect_text, &value_text))
    {
        return -1;
    }
    if (*selector_text == '\0' || *effect_text == '\0' || *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_process_selector_parse(selector_text, &rule->selector))
    {
        return -1;
    }

    if (strcmp(effect_text, "ERRNO") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_ERRNO;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        errnum = chaos_process_parse_errno_name(payload);
        if (errnum < 0)
        {
            return -1;
        }
        rule->errnum = errnum;
        return 1;
    }
    if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_LATENCY;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_process_parse_latency(payload, &rule->latency_ms) == 0 ? 1 : -1;
    }
    if (strcmp(effect_text, "FAIL_AFTER") == 0)
    {
        rule->effect = CHAOS_PROCESS_EFFECT_FAIL_AFTER;
        if (chaos_process_parse_payload_probability(
                value_text, payload, sizeof(payload), &rule->probability
            ) != 0)
        {
            return -1;
        }
        return chaos_process_parse_fail_after_value(
                   payload, &rule->errnum, &rule->fail_after_count
               ) == 0
                   ? 1
                   : -1;
    }

    return -1;
}

int chaos_process_config_parse_buffer(char *buffer, chaos_process_rule_t *rules, size_t *rule_count)
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
        int parsed;

        cursor = strchr(cursor, '\n');
        if (cursor != NULL)
        {
            *cursor++ = '\0';
        }
        else
        {
            cursor = line + strlen(line);
        }

        parsed = chaos_process_config_parse_line(line, &rules[count]);
        if (parsed < 0)
        {
            return -1;
        }
        if (parsed == 0)
        {
            continue;
        }
        ++count;
        if (count > CHAOS_PROCESS_MAX_RULES)
        {
            return -1;
        }
    }

    *rule_count = count;
    return 0;
}

int chaos_process_config_select_rule(
    const chaos_process_rule_t *rules,
    size_t rule_count,
    chaos_process_effect_t effect,
    chaos_process_operation_t operation,
    chaos_process_rule_t *rule
)
{
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

    if (rules == NULL || rule == NULL)
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
        if (!chaos_process_selector_matches(&rules[index].selector, operation, &rank))
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

int chaos_process_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_process_config_state_t *next_state;

    observed_mtime = chaos_process_config_observed_mtime();
    cached_mtime = chaos_process_atomic_load_u64(&g_chaos_process_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }
    if (!chaos_process_atomic_cas_u64(
            &g_chaos_process_cached_mtime, cached_mtime, CHAOS_PROCESS_MTIME_RELOADING
        ))
    {
        return chaos_process_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_process_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_process_config_states[next_index];
    chaos_process_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_PROCESS_MTIME_MISSING &&
        chaos_process_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_process_config_parse_buffer(
            g_chaos_process_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_process_config_reset_state(next_state, 0);
    }

    chaos_process_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

int chaos_process_config_match_loaded(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
)
{
    const chaos_process_config_state_t *state = chaos_process_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_process_config_select_rule(
        state->rules, state->rule_count, effect, operation, rule
    );
}

int chaos_process_config_match(
    chaos_process_effect_t effect, chaos_process_operation_t operation, chaos_process_rule_t *rule
)
{
    if (rule == NULL || !chaos_process_config_prepare())
    {
        return 0;
    }

    return chaos_process_config_match_loaded(effect, operation, rule);
}
