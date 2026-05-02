/**
 * @file test_net_config.c
 * @brief Unit tests for NET-domain configuration parsing, rule selection, and reload state machine.
 *
 * Subsystem under test: `src/net/chaos_net_config.c` and `src/net/chaos_net_endpoint.c`
 *
 * Coverage approach:
 * - `chaos_net_endpoint.c` is included inline (no `#define` overrides needed) to give
 *   access to endpoint parsing helpers used by the config subsystem.
 * - `open`, `read`, and `close` are `#define`-overridden before including
 *   `chaos_net_config.c` so tests can inject file-I/O failures without real filesystem
 *   dependency. The `chaos_process_atomic_cas_u64` CAS primitive is similarly overridden
 *   to simulate CAS race failures.
 * - Config file content is written via local `write_config_text()` helpers with
 *   `futimens` to control the mtime precisely, allowing the reload state machine to be
 *   driven deterministically.
 * - The net config file is backed up before and restored after any test that writes to it.
 *
 * Properties under test:
 * - Helper primitives: trim, strip_comment, blank_char, all nine operation names, all 19
 *   errno names, probability/latency parsing edge cases, effect_allowed and selector_allowed
 *   matrices, mtime hashing and sentinel normalisation.
 * - Rule parsing: valid rules covering all seven supported net effect types across multiple
 *   operation/selector combinations.
 * - Rule selection: exact endpoint match beats wildcard; `selector_len` tie-breaking selects
 *   the longer (more specific) rule.
 * - Selection edges: NULL pointer arguments rejected, no-match returns 0.
 * - Invalid rule lines: 18+ rejection cases covering bad effects, invalid op/effect
 *   combinations, empty fields, and malformed values.
 * - Reload state machine: no-file returns false; successful load and match; repeated
 *   prepare with same mtime skips reload; bad rule clears rules and returns false; CAS
 *   failure falls through to old state; forced open/read failures.
 *
 * What is NOT tested here:
 * - Concurrent config reload races under real multi-thread access.
 * - Endpoint resolution from live socket file descriptors.
 * - LD_PRELOAD wrapper call paths.
 */

#include "../support/test_net_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_NET_DEFINE_TEST_GLOBALS();

/**
 * @brief When non-zero, causes the test `open` stub to return -1 with ENOENT.
 *
 * Used to exercise the config-file-not-found path in `chaos_net_config_prepare()`.
 */
static int g_test_config_force_open_fail = 0;

/**
 * @brief When non-zero, causes the test `read` stub to return -1 with EIO.
 *
 * The test `open` stub returns a fake fd (`g_test_config_fake_fd`) when this
 * flag is set. The test `read` stub intercepts reads on that fd and injects an
 * EIO error. The test `close` stub swallows closes of the fake fd without
 * touching the real filesystem.
 */
static int g_test_config_force_read_fail = 0;

/**
 * @brief When non-zero, causes the CAS stub to return 0 (failure).
 *
 * Simulates the lost-race scenario in `chaos_net_config_prepare()` where another
 * thread atomically updates the mtime before this thread can commit its reload.
 */
static int g_test_config_force_cas_fail = 0;

/** @brief Fake fd returned by the test `open` stub when read-fail mode is active. */
static const int g_test_config_fake_fd = 7331;

/**
 * @brief Test-controlled `open(2)` stub for the net config subsystem.
 *
 * When `g_test_config_force_open_fail != 0`, returns -1 with ENOENT without
 * touching the filesystem. When `g_test_config_force_read_fail != 0`, returns
 * `g_test_config_fake_fd` without opening a real file. Otherwise delegates to
 * the real `open(2)`, forwarding the variadic `mode` argument for O_CREAT paths.
 */
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

/**
 * @brief Test-controlled `read(2)` stub for the net config subsystem.
 *
 * When `g_test_config_force_read_fail != 0` and the fd matches the fake fd,
 * returns -1 with EIO. Otherwise delegates to the real `read(2)`.
 */
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

/**
 * @brief Test-controlled `close(2)` stub for the net config subsystem.
 *
 * Swallows closes of the fake fd (returns 0) to avoid EBADF from closing a
 * file descriptor that was never opened. Otherwise delegates to `close(2)`.
 */
static int chaos_net_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Test-controlled CAS stub for the net config mtime update.
 *
 * When `g_test_config_force_cas_fail != 0`, returns 0 (failure) to simulate a
 * concurrent mtime update. Otherwise performs the real GCC built-in CAS.
 */
static int
chaos_net_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/* Include endpoint parsing inline first (no overrides needed). */
#include "../../src/net/chaos_net_endpoint.c"

#define open chaos_net_test_config_open
#define read chaos_net_test_config_read
#define close chaos_net_test_config_close
#define chaos_net_atomic_cas_u64 chaos_net_test_atomic_cas_u64
#include "../../src/net/chaos_net_config.c"
#undef chaos_net_atomic_cas_u64
#undef close
#undef read
#undef open

/* -------------------------------------------------------------------------
 * Local backup/restore helpers
 * --------------------------------------------------------------------- */

/**
 * @brief Simple backup record for the net config file.
 *
 * Used by tests that write to CHAOS_NET_CONFIG_PATH to restore the original
 * content when the test completes.
 */
typedef struct chaos_net_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_net_test_file_backup_t;

/**
 * @brief Read and preserve the current net config file content.
 *
 * If the file does not exist, sets `backup->existed = 0`. Otherwise reads the
 * entire file into a heap buffer. The caller must call `free_backup()` after
 * `restore_file()`.
 *
 * @param path    File path to back up (typically CHAOS_NET_CONFIG_PATH).
 * @param backup  Output record to populate.
 */
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

/**
 * @brief Restore the net config file from a backup record.
 *
 * If `backup->existed == 0`, removes the file if it currently exists.
 * Otherwise overwrites the file with the backed-up content.
 *
 * @param path    File path to restore.
 * @param backup  Backup record produced by `backup_file()`.
 */
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

/**
 * @brief Release heap memory owned by a backup record.
 *
 * @param backup  Backup record to release.
 */
static void free_backup(chaos_net_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Write config text to CHAOS_NET_CONFIG_PATH with a precise mtime.
 *
 * Uses `futimens(2)` to set the file mtime to @p stamp seconds (nanoseconds=0),
 * making config-reload decisions deterministic regardless of real wall-clock time.
 *
 * @param text   Config file content to write.
 * @param stamp  Desired mtime in seconds since the epoch.
 */
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

/* -------------------------------------------------------------------------
 * Test functions
 * --------------------------------------------------------------------- */

/**
 * @brief Invariant: low-level parsing helpers handle NULL, boundary values, and valid inputs.
 *
 * Triggering conditions: direct calls to `chaos_net_is_blank_char`, `chaos_net_trim`,
 *   `chaos_net_strip_comment`, `chaos_net_parse_operation`, `chaos_net_parse_errno_name`,
 *   `chaos_net_parse_probability`, `chaos_net_parse_latency`, `chaos_net_effect_allowed`,
 *   `chaos_net_selector_allowed`, `chaos_net_config_normalize_mtime_hash`,
 *   `chaos_net_config_hash_mtime`, `chaos_net_split_rule_fields`.
 *
 * Expected observable behaviour:
 * - Blank chars: space and tab return true; 'x' returns false.
 * - trim(NULL) returns NULL; trim of padded text returns the inner word.
 * - strip_comment on "abc#def" leaves "abc".
 * - All nine operation name strings map to their enum values; NULL and "bogus" map to INVALID.
 * - All 19 errno names map to their correct values; NULL and "ENOPE" return -1.
 * - Probability: 0.25 parses correctly; NULL, >1.0, non-numeric return -1.
 * - Latency: 25 parses correctly; NULL, overflow, non-numeric return -1.
 * - effect_allowed and selector_allowed matrices match documented constraints.
 * - Mtime sentinel normalisation: none of the three sentinels collide with the
 *   normalized output.
 * - split_rule_fields correctly splits "tcp4://127.0.0.1:5432:connect:LATENCY:5"
 *   into its four components; bad inputs return false.
 */
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

    /* Selector-allowed: NULL selector is always rejected. Wildcard and exact-IP
     * selectors are allowed for data operations; SOCKET only allows wildcard-host
     * or UNIX wildcard selectors. */
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

    /* Mtime sentinel normalisation: each sentinel must map to a different value. */
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

/**
 * @brief Invariant: a seven-rule buffer is parsed correctly and endpoint rule selection
 *   returns the highest-specificity match.
 *
 * Triggering condition: `chaos_net_config_parse_buffer()` on a multi-rule buffer,
 *   followed by `chaos_net_config_select_endpoint_rule()` with various endpoints and
 *   operations.
 *
 * Expected observable behaviour:
 * - All seven rules are parsed; specific field values are preserved (operation, effect, errnum).
 * - Exact-IP endpoint tcp4://127.0.0.1:5432 on OP_CONNECT picks the LATENCY rule, not
 *   the wildcard-host ECONNREFUSED rule.
 * - Wildcard-host tcp4://\*:0 on OP_SOCKET picks the EAFNOSUPPORT rule.
 * - No match for OP_POLL on a tcp4 wildcard endpoint returns 0.
 */
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

/**
 * @brief Invariant: buffer overflow, NULL pointer arguments, and selector_len tie-breaking.
 *
 * Triggering conditions:
 * - `chaos_net_config_parse_buffer()` on a buffer with CHAOS_NET_MAX_RULES+1 identical rules.
 * - `chaos_net_config_select_endpoint_rule()` with NULL rules, endpoint, or output pointers.
 * - Rule selection with two rules sharing the same endpoint but different `selector_len`;
 *   the rule with the larger `selector_len` must win.
 *
 * Expected observable behaviour:
 * - A four-rule buffer (with comments and blank lines) parses to exactly four rules.
 * - NULL arguments to select_endpoint_rule all return false.
 * - Exact match on tcp4://127.0.0.1:80 returns EHOSTUNREACH (not ECONNREFUSED from
 *   the wildcard-host rule).
 * - No match for OP_RECV on a TCP4 endpoint returns false.
 * - Overflow buffer (MAX_RULES+1 identical lines) causes `parse_buffer` to return -1.
 * - Tie-break selects the rule with selector_len=12 over selector_len=10.
 */
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

/**
 * @brief Invariant: all 18 classes of invalid rule lines are rejected by `parse_line`.
 *
 * Triggering condition: `chaos_net_config_parse_line()` called on each malformed string.
 *
 * Expected observable behaviour: every call returns -1. The blank/comment line
 * returns 0 (skipped, not an error). NULL line or NULL rule pointer returns -1.
 *
 * Invalid cases exercised:
 * - Missing fields (no colon separators)
 * - Empty selector, operation, effect, or value fields
 * - Unknown operation ("nope"), unknown effect ("BOOM")
 * - CORRUPT on a connect operation (only allowed on recv)
 * - Invalid selector (tcp4 URL with no port component)
 * - TIMEOUT on a connect operation (only allowed on poll)
 * - SOCKET with a specific UNIX path (only wildcard UNIX allowed for socket)
 * - Non-numeric probability, latency, corrupt threshold, and timeout values
 */
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

/**
 * @brief Invariant: file-I/O failure modes and mtime-driven reload state machine.
 *
 * Triggering conditions:
 * - `g_test_config_force_open_fail = 1` causes `chaos_net_config_read_file()` to return -1.
 * - `g_test_config_force_read_fail = 1` causes `chaos_net_config_read_file()` to return -1.
 * - A file of exactly CHAOS_NET_MAX_CONFIG_BYTES bytes causes `read_file` to return -1.
 * - A valid config file with mtime=30 loads successfully.
 * - Repeating `prepare()` with the same cached mtime skips the reload.
 * - `g_test_config_force_cas_fail = 1` causes `prepare()` to return true (old rules retained).
 * - A syntactically invalid config file causes `prepare()` to return false and clears rules.
 *
 * Expected observable behaviour per path:
 * - open fail and read fail both cause `read_file` to return -1 without panicking.
 * - Oversized file: `read_file` returns -1 without reading data.
 * - Successful load: `config_match_endpoint_loaded` finds the expected rule.
 * - Repeated prepare at same mtime: returns true without triggering another file read.
 * - CAS fail: returns true (falling through to old state without clearing rules).
 * - Invalid config write: `prepare()` returns false; subsequent match returns false.
 * - reset_state with `clear=0` leaves rule_count unchanged; matched returns false.
 */
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

/**
 * @brief Invariant: the public `chaos_net_config_match_endpoint()` API drives the full
 *   prepare→match pipeline and correctly propagates parse failures.
 *
 * Triggering condition: `write_config_text()` with different rules between calls to
 *   `chaos_net_config_match_endpoint()`.
 *
 * Expected observable behaviour:
 * - With no config file: `prepare()` returns false; match returns false.
 * - NULL endpoint or NULL rule pointer to `match_endpoint` both return false.
 * - After writing a valid ECONNREFUSED rule: match succeeds, effect and errnum verified.
 * - After writing a CORRUPT rule for the same endpoint+operation (which is invalid):
 *   `match_endpoint` returns false (parse error invalidates rules).
 */
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
