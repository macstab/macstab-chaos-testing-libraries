/*
 * Config parsing, validation, snapshot management, and rule selection.
 *
 * The wrapper layer depends on this module for current rule state, but the
 * implementation stays intentionally small: two snapshots, in-place parsing, and
 * deterministic longest-prefix matching.
 */

#include "chaos_io_config.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__linux__)
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtim.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtim.tv_nsec)
#else
#define CHAOS_IO_STAT_SEC(st) ((st)->st_mtimespec.tv_sec)
#define CHAOS_IO_STAT_NSEC(st) ((st)->st_mtimespec.tv_nsec)
#endif

typedef struct chaos_io_config_state {
    chaos_io_rule_t rules[CHAOS_IO_MAX_RULES];
    size_t rule_count;
    int parse_ok;
} chaos_io_config_state_t;

static chaos_io_config_state_t g_chaos_io_config_states[2];
static volatile unsigned int g_chaos_io_active_config_index = 0U;
static volatile uint64_t g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
static __thread char g_chaos_io_config_buffer[CHAOS_IO_MAX_CONFIG_BYTES + 1U];

/* Resets a config state to an empty passthrough configuration. */
static void chaos_io_config_reset_state(chaos_io_config_state_t *state, int parse_ok)
{
    if (state == NULL) {
        return;
    }

    (void)memset(state, 0, sizeof(*state));
    state->parse_ok = parse_ok;
}

/* Returns the current active config state with an acquire barrier. */
static const chaos_io_config_state_t *chaos_io_config_active_state(void)
{
    unsigned int index;

    __sync_synchronize();
    index = g_chaos_io_active_config_index;
    return &g_chaos_io_config_states[index];
}

/* Publishes a freshly loaded config state. */
static void chaos_io_config_publish(unsigned int next_index, uint64_t observed_mtime)
{
    __sync_synchronize();
    g_chaos_io_active_config_index = next_index;
    __sync_synchronize();
    g_chaos_io_cached_mtime = observed_mtime;
}

/* Returns non-zero when the character is insignificant config whitespace. */
static int chaos_io_is_blank_char(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

/* Trims leading and trailing config whitespace in place. */
static char *chaos_io_trim(char *text)
{
    char *end;

    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && chaos_io_is_blank_char(*text)) {
        ++text;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text);
    while (end > text && chaos_io_is_blank_char(end[-1])) {
        --end;
    }
    *end = '\0';

    return text;
}

/* Removes an inline comment from a config line. */
static void chaos_io_strip_comment(char *line)
{
    char *comment;

    if (line == NULL) {
        return;
    }

    comment = strchr(line, '#');
    if (comment != NULL) {
        *comment = '\0';
    }
}

/* Parses the string name of an operation. */
static chaos_io_operation_t chaos_io_parse_operation(const char *text)
{
    if (text == NULL) {
        return CHAOS_IO_OP_INVALID;
    }
    if (strcmp(text, "read") == 0) {
        return CHAOS_IO_OP_READ;
    }
    if (strcmp(text, "write") == 0) {
        return CHAOS_IO_OP_WRITE;
    }
    if (strcmp(text, "open") == 0) {
        return CHAOS_IO_OP_OPEN;
    }
    if (strcmp(text, "close") == 0) {
        return CHAOS_IO_OP_CLOSE;
    }
    if (strcmp(text, "fsync") == 0) {
        return CHAOS_IO_OP_FSYNC;
    }
    if (strcmp(text, "fdatasync") == 0) {
        return CHAOS_IO_OP_FDATASYNC;
    }
    if (strcmp(text, "pread") == 0) {
        return CHAOS_IO_OP_PREAD;
    }
    if (strcmp(text, "pwrite") == 0) {
        return CHAOS_IO_OP_PWRITE;
    }
    return CHAOS_IO_OP_INVALID;
}

/* Parses an errno name supported by the config format. */
static int chaos_io_parse_errno_name(const char *text)
{
    if (text == NULL) {
        return -1;
    }
    if (strcmp(text, "EIO") == 0) {
        return EIO;
    }
    if (strcmp(text, "ENOSPC") == 0) {
        return ENOSPC;
    }
    if (strcmp(text, "EDQUOT") == 0) {
        return EDQUOT;
    }
    if (strcmp(text, "EROFS") == 0) {
        return EROFS;
    }
    if (strcmp(text, "EACCES") == 0) {
        return EACCES;
    }
    if (strcmp(text, "EMFILE") == 0) {
        return EMFILE;
    }
    if (strcmp(text, "ENFILE") == 0) {
        return ENFILE;
    }
    if (strcmp(text, "ENOENT") == 0) {
        return ENOENT;
    }
    return -1;
}

/* Parses a floating-point probability from the config. */
static int chaos_io_parse_probability(const char *text, double *probability)
{
    char *end = NULL;
    double value;

    if (text == NULL || probability == NULL) {
        return -1;
    }

    value = strtod(text, &end);
    if (end == text || *chaos_io_trim(end) != '\0') {
        return -1;
    }
    if (value < 0.0 || value > 1.0) {
        return -1;
    }

    *probability = value;
    return 0;
}

/* Parses a millisecond latency value from the config. */
static int chaos_io_parse_latency(const char *text, unsigned int *latency_ms)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || latency_ms == NULL) {
        return -1;
    }

    value = strtoul(text, &end, 10);
    if (end == text || *chaos_io_trim(end) != '\0') {
        return -1;
    }
    if (value > 0xffffffffUL) {
        return -1;
    }

    *latency_ms = (unsigned int)value;
    return 0;
}

/* Returns non-zero when the effect is valid for the selected operation. */
static int chaos_io_effect_allowed(chaos_io_operation_t operation, chaos_io_effect_t effect)
{
    if (effect == CHAOS_IO_EFFECT_ERRNO || effect == CHAOS_IO_EFFECT_LATENCY) {
        return 1;
    }
    if (effect == CHAOS_IO_EFFECT_TORN) {
        return operation == CHAOS_IO_OP_WRITE || operation == CHAOS_IO_OP_PWRITE;
    }
    if (effect == CHAOS_IO_EFFECT_CORRUPT) {
        return operation == CHAOS_IO_OP_READ || operation == CHAOS_IO_OP_PREAD;
    }
    return 0;
}

/* Normalizes hashed mtimes so they never overlap with sentinel values. */
static uint64_t chaos_io_config_normalize_mtime_hash(uint64_t value)
{
    if (value == CHAOS_IO_MTIME_MISSING
        || value == CHAOS_IO_MTIME_RELOADING
        || value == CHAOS_IO_MTIME_UNKNOWN) {
        return value ^ UINT64_C(0x9e3779b97f4a7c15);
    }

    return value;
}

/* Hashes the current stat mtime into an atomic cache key. */
static uint64_t chaos_io_config_hash_mtime(const struct stat *st)
{
    uint64_t value;

    if (st == NULL) {
        return CHAOS_IO_MTIME_MISSING;
    }

    value = UINT64_C(1469598103934665603);
    value ^= (uint64_t)CHAOS_IO_STAT_SEC(st);
    value *= UINT64_C(1099511628211);
    value ^= (uint64_t)CHAOS_IO_STAT_NSEC(st);
    value *= UINT64_C(1099511628211);

    return chaos_io_config_normalize_mtime_hash(value);
}

/* Stats the config file and returns the mtime cache key. */
static uint64_t chaos_io_config_observed_mtime(void)
{
    struct stat st;
    int previous;
    int rc;

    previous = chaos_io_enter_internal();
    rc = stat(CHAOS_IO_CONFIG_PATH, &st);
    chaos_io_leave_internal(previous);

    if (rc != 0) {
        return CHAOS_IO_MTIME_MISSING;
    }

    return chaos_io_config_hash_mtime(&st);
}

/* Reads the config file into the thread-local buffer. */
static int chaos_io_config_read_file(size_t *size_out)
{
    size_t total = 0U;
    int previous;
    int fd;

    if (size_out == NULL
        || g_chaos_io_real_open == NULL
        || g_chaos_io_real_read == NULL
        || g_chaos_io_real_close == NULL) {
        return -1;
    }

    previous = chaos_io_enter_internal();
    fd = g_chaos_io_real_open(CHAOS_IO_CONFIG_PATH, O_RDONLY);
    if (fd < 0) {
        chaos_io_leave_internal(previous);
        return -1;
    }

    for (;;) {
        ssize_t rc = g_chaos_io_real_read(fd, g_chaos_io_config_buffer + total, CHAOS_IO_MAX_CONFIG_BYTES - total);
        if (rc < 0) {
            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return -1;
        }
        if (rc == 0) {
            break;
        }
        total += (size_t)rc;
        if (total == CHAOS_IO_MAX_CONFIG_BYTES) {
            (void)g_chaos_io_real_close(fd);
            chaos_io_leave_internal(previous);
            return -1;
        }
    }

    (void)g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);

    g_chaos_io_config_buffer[total] = '\0';
    *size_out = total;
    return 0;
}

/* Returns non-zero when a rule prefix matches the supplied path. */
static int chaos_io_rule_prefix_matches(const chaos_io_rule_t *rule, const char *path)
{
    if (rule == NULL || path == NULL) {
        return 0;
    }
    if (strcmp(rule->path_prefix, "*") == 0) {
        return 1;
    }
    if (strncmp(path, rule->path_prefix, rule->path_len) != 0) {
        return 0;
    }
    if (path[rule->path_len] == '\0') {
        return 1;
    }
    if (rule->path_len > 0U && rule->path_prefix[rule->path_len - 1U] == '/') {
        return 1;
    }
    return path[rule->path_len] == '/';
}

/* Reloads the inactive config state from disk or clears it on passthrough conditions. */
static void chaos_io_config_reload(uint64_t observed_mtime)
{
    unsigned int next_index = 1U - g_chaos_io_active_config_index;
    chaos_io_config_state_t *next_state = &g_chaos_io_config_states[next_index];
    size_t file_size = 0U;

    chaos_io_config_reset_state(next_state, 1);

    if (observed_mtime == CHAOS_IO_MTIME_MISSING) {
        chaos_io_config_publish(next_index, CHAOS_IO_MTIME_MISSING);
        return;
    }

    if (chaos_io_config_read_file(&file_size) != 0) {
        chaos_io_config_reset_state(next_state, 0);
        chaos_io_config_publish(next_index, observed_mtime);
        return;
    }

    if (chaos_io_config_parse_buffer(g_chaos_io_config_buffer, next_state->rules, &next_state->rule_count) != 0) {
        chaos_io_config_reset_state(next_state, 0);
    }

    (void)file_size;
    chaos_io_config_publish(next_index, observed_mtime);
}

/* Initializes the global config cache. */
void chaos_io_config_init(void)
{
    chaos_io_config_reset_state(&g_chaos_io_config_states[0], 1);
    chaos_io_config_reset_state(&g_chaos_io_config_states[1], 1);
    g_chaos_io_active_config_index = 0U;
    g_chaos_io_cached_mtime = CHAOS_IO_MTIME_UNKNOWN;
}

/* Refreshes the cached config if the config file mtime changed. */
int chaos_io_config_prepare(void)
{
    uint64_t observed_mtime;
    uint64_t cached_mtime;

    observed_mtime = chaos_io_config_observed_mtime();
    cached_mtime = chaos_io_atomic_load_u64(&g_chaos_io_cached_mtime);

    if (cached_mtime == observed_mtime) {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    if (cached_mtime == CHAOS_IO_MTIME_RELOADING) {
        return chaos_io_config_active_state()->rule_count != 0U;
    }
    if (chaos_io_atomic_cas_u64(&g_chaos_io_cached_mtime, cached_mtime, CHAOS_IO_MTIME_RELOADING)) {
        chaos_io_config_reload(observed_mtime);
    }
    return chaos_io_config_active_state()->rule_count != 0U;
}

/* Parses a single config line into a rule. */
int chaos_io_config_parse_line(char *line, chaos_io_rule_t *rule)
{
    char *fields[4];
    char *cursor;
    size_t field_index = 0U;
    int parsed_errno;
    double probability;
    unsigned int latency_ms;

    if (line == NULL || rule == NULL) {
        return -1;
    }

    chaos_io_strip_comment(line);
    cursor = chaos_io_trim(line);
    if (*cursor == '\0') {
        return 0;
    }

    fields[field_index++] = cursor;
    while (*cursor != '\0' && field_index < 4U) {
        if (*cursor == ':') {
            *cursor = '\0';
            fields[field_index++] = cursor + 1;
        }
        ++cursor;
    }

    if (field_index != 4U) {
        return -1;
    }

    fields[0] = chaos_io_trim(fields[0]);
    fields[1] = chaos_io_trim(fields[1]);
    fields[2] = chaos_io_trim(fields[2]);
    fields[3] = chaos_io_trim(fields[3]);

    if (*fields[0] == '\0' || *fields[1] == '\0' || *fields[2] == '\0' || *fields[3] == '\0') {
        return -1;
    }
    if (strlen(fields[0]) >= CHAOS_IO_MAX_RULE_PATH) {
        return -1;
    }

    (void)memset(rule, 0, sizeof(*rule));
    (void)memcpy(rule->path_prefix, fields[0], strlen(fields[0]) + 1U);
    rule->path_len = strlen(rule->path_prefix);
    rule->operation = chaos_io_parse_operation(fields[1]);
    if (rule->operation == CHAOS_IO_OP_INVALID) {
        return -1;
    }

    parsed_errno = chaos_io_parse_errno_name(fields[2]);
    if (parsed_errno >= 0) {
        rule->effect = CHAOS_IO_EFFECT_ERRNO;
        rule->errnum = parsed_errno;
        if (chaos_io_parse_probability(fields[3], &probability) != 0) {
            return -1;
        }
        rule->probability = probability;
    } else if (strcmp(fields[2], "LATENCY") == 0) {
        rule->effect = CHAOS_IO_EFFECT_LATENCY;
        if (chaos_io_parse_latency(fields[3], &latency_ms) != 0) {
            return -1;
        }
        rule->latency_ms = latency_ms;
    } else if (strcmp(fields[2], "TORN") == 0) {
        rule->effect = CHAOS_IO_EFFECT_TORN;
        if (chaos_io_parse_probability(fields[3], &probability) != 0) {
            return -1;
        }
        rule->probability = probability;
    } else if (strcmp(fields[2], "CORRUPT") == 0) {
        rule->effect = CHAOS_IO_EFFECT_CORRUPT;
        if (chaos_io_parse_probability(fields[3], &probability) != 0) {
            return -1;
        }
        rule->probability = probability;
    } else {
        return -1;
    }

    if (!chaos_io_effect_allowed(rule->operation, rule->effect)) {
        return -1;
    }

    return 1;
}

/* Parses an entire config buffer in place. */
int chaos_io_config_parse_buffer(char *buffer, chaos_io_rule_t *rules, size_t *rule_count)
{
    char *line;
    size_t count = 0U;

    if (buffer == NULL || rules == NULL || rule_count == NULL) {
        return -1;
    }

    line = buffer;
    for (;;) {
        char *next = strchr(line, '\n');
        chaos_io_rule_t parsed_rule;
        int parse_result;

        if (next != NULL) {
            *next = '\0';
        }

        parse_result = chaos_io_config_parse_line(line, &parsed_rule);
        if (parse_result < 0) {
            *rule_count = 0U;
            return -1;
        }
        if (parse_result > 0) {
            if (count >= CHAOS_IO_MAX_RULES) {
                *rule_count = 0U;
                return -1;
            }
            rules[count++] = parsed_rule;
        }

        if (next == NULL) {
            break;
        }
        line = next + 1;
    }

    *rule_count = count;
    return 0;
}

/* Selects the longest-prefix matching rule from a caller-supplied rule set. */
int chaos_io_config_select_rule(
    const chaos_io_rule_t *rules,
    size_t rule_count,
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    const chaos_io_rule_t *best = NULL;
    size_t index;

    if (rules == NULL || path == NULL || rule == NULL) {
        return 0;
    }

    for (index = 0U; index < rule_count; ++index) {
        const chaos_io_rule_t *candidate = &rules[index];
        if (candidate->operation != operation) {
            continue;
        }
        if (!chaos_io_rule_prefix_matches(candidate, path)) {
            continue;
        }
        if (best == NULL || candidate->path_len > best->path_len) {
            best = candidate;
        }
    }

    if (best == NULL) {
        return 0;
    }

    *rule = *best;
    return 1;
}

/* Matches a path against the current loaded config without forcing a refresh. */
int chaos_io_config_match_loaded(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    const chaos_io_config_state_t *state;

    if (path == NULL || rule == NULL) {
        return 0;
    }

    state = chaos_io_config_active_state();
    if (state->rule_count == 0U) {
        return 0;
    }

    return chaos_io_config_select_rule(state->rules, state->rule_count, operation, path, rule);
}

/* Refreshes the config if needed and then matches a path against it. */
int chaos_io_config_match_path(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    if (path == NULL || rule == NULL || chaos_io_is_excluded_path(path)) {
        return 0;
    }
    if (!chaos_io_config_prepare()) {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}
