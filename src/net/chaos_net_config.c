#include "chaos_net_config.h"

#include "chaos_net_endpoint.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__linux__)
#define CHAOS_NET_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_NET_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_NET_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_NET_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

typedef struct chaos_net_config_state
{
    chaos_net_rule_t rules[CHAOS_NET_MAX_RULES];
    size_t rule_count;
    int parse_ok;
} chaos_net_config_state_t;

static chaos_net_config_state_t g_chaos_net_config_states[2];
static volatile unsigned int g_chaos_net_active_config_index = 0U;
static volatile uint64_t g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
static __thread char g_chaos_net_config_buffer[CHAOS_NET_MAX_CONFIG_BYTES + 1U];

static void chaos_net_config_reset_state(chaos_net_config_state_t *state, int parse_ok)
{
    if (state == NULL)
    {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

static const chaos_net_config_state_t *chaos_net_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_net_active_config_index;
    return &g_chaos_net_config_states[index];
}

static void chaos_net_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_net_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_net_cached_mtime = observed_mtime;
}

static int chaos_net_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static char *chaos_net_trim(char *text)
{
    char *end;

    if (text == NULL)
    {
        return NULL;
    }

    while (*text != '\0' && chaos_net_is_blank_char(*text))
    {
        ++text;
    }
    if (*text == '\0')
    {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_net_is_blank_char(end[-1]))
    {
        --end;
    }
    *end = '\0';
    return text;
}

static void chaos_net_strip_comment(char *line)
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

static chaos_net_operation_t chaos_net_parse_operation(const char *text)
{
    if (text == NULL)
    {
        return CHAOS_NET_OP_INVALID;
    }
    if (strcmp(text, "bind") == 0)
    {
        return CHAOS_NET_OP_BIND;
    }
    if (strcmp(text, "listen") == 0)
    {
        return CHAOS_NET_OP_LISTEN;
    }
    if (strcmp(text, "connect") == 0)
    {
        return CHAOS_NET_OP_CONNECT;
    }
    if (strcmp(text, "accept") == 0)
    {
        return CHAOS_NET_OP_ACCEPT;
    }
    if (strcmp(text, "socket") == 0)
    {
        return CHAOS_NET_OP_SOCKET;
    }
    if (strcmp(text, "shutdown") == 0)
    {
        return CHAOS_NET_OP_SHUTDOWN;
    }
    if (strcmp(text, "poll") == 0)
    {
        return CHAOS_NET_OP_POLL;
    }
    if (strcmp(text, "send") == 0)
    {
        return CHAOS_NET_OP_SEND;
    }
    if (strcmp(text, "recv") == 0)
    {
        return CHAOS_NET_OP_RECV;
    }
    return CHAOS_NET_OP_INVALID;
}

static int chaos_net_parse_errno_name(const char *text)
{
    if (text == NULL)
    {
        return -1;
    }
    if (strcmp(text, "ECONNREFUSED") == 0)
    {
        return ECONNREFUSED;
    }
    if (strcmp(text, "ETIMEDOUT") == 0)
    {
        return ETIMEDOUT;
    }
    if (strcmp(text, "ECONNRESET") == 0)
    {
        return ECONNRESET;
    }
    if (strcmp(text, "EHOSTUNREACH") == 0)
    {
        return EHOSTUNREACH;
    }
    if (strcmp(text, "ENETUNREACH") == 0)
    {
        return ENETUNREACH;
    }
    if (strcmp(text, "EADDRINUSE") == 0)
    {
        return EADDRINUSE;
    }
    if (strcmp(text, "EADDRNOTAVAIL") == 0)
    {
        return EADDRNOTAVAIL;
    }
    if (strcmp(text, "EAFNOSUPPORT") == 0)
    {
        return EAFNOSUPPORT;
    }
    if (strcmp(text, "EPROTONOSUPPORT") == 0)
    {
        return EPROTONOSUPPORT;
    }
    if (strcmp(text, "EPIPE") == 0)
    {
        return EPIPE;
    }
    if (strcmp(text, "ENOTCONN") == 0)
    {
        return ENOTCONN;
    }
    if (strcmp(text, "EOPNOTSUPP") == 0)
    {
        return EOPNOTSUPP;
    }
    if (strcmp(text, "EINVAL") == 0)
    {
        return EINVAL;
    }
    if (strcmp(text, "EINTR") == 0)
    {
        return EINTR;
    }
    if (strcmp(text, "ENOMEM") == 0)
    {
        return ENOMEM;
    }
    if (strcmp(text, "ENOBUFS") == 0)
    {
        return ENOBUFS;
    }
    if (strcmp(text, "EMFILE") == 0)
    {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0)
    {
        return ENFILE;
    }
    if (strcmp(text, "EAGAIN") == 0)
    {
        return EAGAIN;
    }
    return -1;
}

static int chaos_net_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL)
    {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_net_trim(end) != '\0')
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

static int chaos_net_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL)
    {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_net_trim(end) != '\0')
    {
        return -1;
    }
    if (value > 0xffffffffUL)
    {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

static int chaos_net_effect_allowed(chaos_net_operation_t operation, chaos_net_effect_t effect)
{
    if (effect == CHAOS_NET_EFFECT_LATENCY)
    {
        return operation != CHAOS_NET_OP_INVALID;
    }
    if (effect == CHAOS_NET_EFFECT_ERRNO)
    {
        return operation == CHAOS_NET_OP_BIND || operation == CHAOS_NET_OP_LISTEN ||
               operation == CHAOS_NET_OP_CONNECT || operation == CHAOS_NET_OP_ACCEPT ||
               operation == CHAOS_NET_OP_SOCKET || operation == CHAOS_NET_OP_SHUTDOWN ||
               operation == CHAOS_NET_OP_POLL || operation == CHAOS_NET_OP_SEND ||
               operation == CHAOS_NET_OP_RECV;
    }
    if (effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        return operation == CHAOS_NET_OP_RECV;
    }
    if (effect == CHAOS_NET_EFFECT_TIMEOUT)
    {
        return operation == CHAOS_NET_OP_POLL;
    }
    return 0;
}

static int
chaos_net_selector_allowed(chaos_net_operation_t operation, const chaos_net_endpoint_t *selector)
{
    if (selector == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_ANY)
    {
        return 1;
    }
    if (operation == CHAOS_NET_OP_SOCKET)
    {
        if ((selector->kind == CHAOS_NET_ENDPOINT_TCP4 ||
             selector->kind == CHAOS_NET_ENDPOINT_TCP6 ||
             selector->kind == CHAOS_NET_ENDPOINT_UDP4 ||
             selector->kind == CHAOS_NET_ENDPOINT_UDP6) &&
            selector->wildcard_host != 0 && selector->port == 0U)
        {
            return 1;
        }
        return selector->kind == CHAOS_NET_ENDPOINT_UNIX && strcmp(selector->value.text, "*") == 0;
    }
    return selector->kind == CHAOS_NET_ENDPOINT_TCP4 || selector->kind == CHAOS_NET_ENDPOINT_TCP6 ||
           selector->kind == CHAOS_NET_ENDPOINT_UDP4 || selector->kind == CHAOS_NET_ENDPOINT_UDP6 ||
           selector->kind == CHAOS_NET_ENDPOINT_UNIX;
}

static uint64_t chaos_net_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_NET_MTIME_MISSING || value == CHAOS_NET_MTIME_RELOADING ||
        value == CHAOS_NET_MTIME_UNKNOWN)
    {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

static uint64_t chaos_net_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL)
    {
        return CHAOS_NET_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_NET_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_NET_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);
    return chaos_net_config_normalize_mtime_hash(value);
}

static uint64_t chaos_net_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = stat(CHAOS_NET_CONFIG_PATH, &st);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return CHAOS_NET_MTIME_MISSING;
    }

    return chaos_net_config_hash_mtime(&st);
}

static int chaos_net_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL)
    {
        return -1;
    }

    previous = chaos_net_enter_internal();
    fd = open(CHAOS_NET_CONFIG_PATH, O_RDONLY);
    if (fd < 0)
    {
        chaos_net_leave_internal(previous);
        return -1;
    }

    for (;;)
    {
        ssize_t rc =
            read(fd, g_chaos_net_config_buffer + total, CHAOS_NET_MAX_CONFIG_BYTES - total);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_net_leave_internal(previous);
            return -1;
        }
        if (rc == 0)
        {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_NET_MAX_CONFIG_BYTES)
        {
            (void)close(fd);
            chaos_net_leave_internal(previous);
            return -1;
        }
    }

    (void)close(fd);
    chaos_net_leave_internal(previous);
    g_chaos_net_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

static int chaos_net_split_rule_fields(
    char *line, char **selector_text, char **operation_text, char **effect_text, char **value_text
)
{
    char *value_sep;
    char *effect_sep;
    char *operation_sep;

    if (line == NULL || selector_text == NULL || operation_text == NULL || effect_text == NULL ||
        value_text == NULL)
    {
        return 0;
    }

    value_sep = strrchr(line, ':');
    if (value_sep == NULL)
    {
        return 0;
    }
    *value_sep++ = '\0';

    effect_sep = strrchr(line, ':');
    if (effect_sep == NULL)
    {
        return 0;
    }
    *effect_sep++ = '\0';

    operation_sep = strrchr(line, ':');
    if (operation_sep == NULL)
    {
        return 0;
    }
    *operation_sep++ = '\0';

    *selector_text = chaos_net_trim(line);
    *operation_text = chaos_net_trim(operation_sep);
    *effect_text = chaos_net_trim(effect_sep);
    *value_text = chaos_net_trim(value_sep);
    return 1;
}

void chaos_net_config_init(void)
{
    chaos_net_config_reset_state(&g_chaos_net_config_states[0], 1);
    chaos_net_config_reset_state(&g_chaos_net_config_states[1], 1);
    g_chaos_net_active_config_index = 0U;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
}

int chaos_net_config_parse_line(char *line, chaos_net_rule_t *rule)
{
    char *selector_text;
    char *operation_text;
    char *effect_text;
    char *value_text;
    int errnum;

    if (line == NULL || rule == NULL)
    {
        return -1;
    }

    chaos_net_strip_comment(line);
    line = chaos_net_trim(line);
    if (*line == '\0')
    {
        return 0;
    }
    if (!chaos_net_split_rule_fields(
            line, &selector_text, &operation_text, &effect_text, &value_text
        ))
    {
        return -1;
    }
    if (*selector_text == '\0' || *operation_text == '\0' || *effect_text == '\0' ||
        *value_text == '\0')
    {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    if (!chaos_net_endpoint_parse_selector(selector_text, &rule->selector))
    {
        return -1;
    }

    rule->operation = chaos_net_parse_operation(operation_text);
    if (rule->operation == CHAOS_NET_OP_INVALID)
    {
        return -1;
    }
    if (!chaos_net_selector_allowed(rule->operation, &rule->selector))
    {
        return -1;
    }

    errnum = chaos_net_parse_errno_name(effect_text);
    if (errnum >= 0)
    {
        rule->effect = CHAOS_NET_EFFECT_ERRNO;
        rule->errnum = errnum;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "LATENCY") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_LATENCY;
        if (chaos_net_parse_latency(value_text, &rule->latency_ms) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "CORRUPT") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_CORRUPT;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else if (strcmp(effect_text, "TIMEOUT") == 0)
    {
        rule->effect = CHAOS_NET_EFFECT_TIMEOUT;
        if (chaos_net_parse_probability(value_text, &rule->probability) != 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    return chaos_net_effect_allowed(rule->operation, rule->effect) ? 1 : -1;
}

int chaos_net_config_parse_buffer(char *buffer, chaos_net_rule_t *rules, size_t *rule_count)
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

        if (count >= CHAOS_NET_MAX_RULES)
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

        rc = chaos_net_config_parse_line(line, &rules[count]);
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

int chaos_net_config_select_endpoint_rule(
    const chaos_net_rule_t *rules,
    size_t rule_count,
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *endpoint,
    chaos_net_rule_t *rule
)
{
    size_t index;
    unsigned int best_rank = 0U;
    size_t best_len = 0U;
    int found = 0;

    if (rules == NULL || endpoint == NULL || rule == NULL)
    {
        return 0;
    }

    for (index = 0U; index < rule_count; ++index)
    {
        unsigned int rank = 0U;

        if (rules[index].operation != operation)
        {
            continue;
        }
        if (!chaos_net_endpoint_matches(&rules[index].selector, endpoint, &rank))
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

int chaos_net_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;
    unsigned int active_index;
    unsigned int next_index;
    size_t config_size;
    chaos_net_config_state_t *next_state;

    observed_mtime = chaos_net_config_observed_mtime();
    cached_mtime = chaos_net_atomic_load_u64(&g_chaos_net_cached_mtime);

    if (observed_mtime == cached_mtime)
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }
    if (!chaos_net_atomic_cas_u64(
            &g_chaos_net_cached_mtime, cached_mtime, CHAOS_NET_MTIME_RELOADING
        ))
    {
        return chaos_net_config_active_state()->rule_count != 0U;
    }

    active_index = g_chaos_net_active_config_index;
    next_index = active_index == 0U ? 1U : 0U;
    next_state = &g_chaos_net_config_states[next_index];
    chaos_net_config_reset_state(next_state, 1);

    if (observed_mtime != CHAOS_NET_MTIME_MISSING &&
        chaos_net_config_read_file(&config_size) == 0 && config_size > 0U &&
        chaos_net_config_parse_buffer(
            g_chaos_net_config_buffer, next_state->rules, &next_state->rule_count
        ) != 0)
    {
        chaos_net_config_reset_state(next_state, 0);
    }

    chaos_net_config_publish(next_index, observed_mtime);
    return next_state->parse_ok != 0 && next_state->rule_count != 0U;
}

int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    const chaos_net_config_state_t *state = chaos_net_config_active_state();

    if (state->parse_ok == 0)
    {
        return 0;
    }

    return chaos_net_config_select_endpoint_rule(
        state->rules, state->rule_count, operation, endpoint, rule
    );
}

int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    if (endpoint == NULL || rule == NULL || !chaos_net_config_prepare())
    {
        return 0;
    }

    return chaos_net_config_match_endpoint_loaded(operation, endpoint, rule);
}
