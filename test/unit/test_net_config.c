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

/* The rule file is read through these stubs (defined below) instead of raw system calls. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

#include "../support/test_net_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/wait.h>

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

/** Number of upcoming config reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;

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
    if (g_test_config_read_eintr > 0)
    {
        --g_test_config_read_eintr;
        errno = EINTR;
        return -1;
    }
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
/* The build hook for rules a build cannot apply (chaos-init defines it): a switch. */
static int g_test_rules_unsupported = 0;
#define CHAOS_NET_RULE_SUPPORTED(rule) ((void)(rule), !g_test_rules_unsupported)
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
        /* The grammar, whatever the locale: strtod accepted nan (which passes
         * every range check), inf, hex and exponents, and failed on "0.5"
         * under a locale with a decimal comma. */
        {
            static const struct
            {
                const char *text;
                double value;
            } valid[] = {
                {"0", 0.0},
                {"1", 1.0},
                {"0.5", 0.5},
                {"0.3", 0.3},
                {"1.0", 1.0},
                {"1.0000", 1.0},
                {"0.0001", 0.0001},
                {"0.25 \t", 0.25},
                {"0.12345678901234567", 0.123456789012345},
            };
            static const char *const invalid[] = {
                "",      "nan",  "NAN",  "inf", "-0",    "+0.5", "0x0.8", "1e-3",
                "0.5e0", "0,5",  ".5",   "0.",  "1.",    "1.5",  "1.01",  "2",
                "01",    "0.5x", " 0.5", "00",  "0.5 1", "10",   "-0.5",  "1.0 x",
            };
            size_t item;

            for (item = 0U; item < sizeof(valid) / sizeof(valid[0]); ++item)
            {
                probability = -1.0;
                assert(chaos_policy_parse_probability(valid[item].text, &probability) == 0);
                assert(probability == valid[item].value);
            }
            for (item = 0U; item < sizeof(invalid) / sizeof(invalid[0]); ++item)
            {
                assert(chaos_policy_parse_probability(invalid[item], &probability) == -1);
            }
            assert(chaos_policy_parse_probability("0.5", NULL) == -1);
        }

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

    assert(chaos_net_config_read_file(NULL, chaos_net_config_observed_mtime()) == -1);
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
    chaos_net_endpoint_t endpoint = {0};
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

    /* A build that cannot apply a rule (chaos-init) rejects the file at it. */
    {
        char unsupported[] = "tcp4://*:80:connect:ECONNREFUSED:1.0\n";
        size_t rejected_count = 9U;

        g_test_rules_unsupported = 1;
        assert(chaos_net_config_parse_buffer(unsupported, rules, &rejected_count) == -1);
        assert(rejected_count == 0U && g_chaos_net_config_error.line == 1U);
        assert(strcmp(g_chaos_net_config_error.reason, CHAOS_STATUS_REASON_UNSUPPORTED) == 0);
        g_test_rules_unsupported = 0;
    }
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
    chaos_net_endpoint_t endpoint = {0};
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
 * - A file of exactly CHAOS_NET_MAX_CONFIG_BYTES bytes causes `read_file` to return -2.
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
    chaos_net_endpoint_t endpoint = {0};
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
    assert(chaos_net_config_read_file(&index, chaos_net_config_observed_mtime()) == -1);
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    assert(chaos_net_config_read_file(&index, chaos_net_config_observed_mtime()) == -1);
    g_test_config_force_read_fail = 0;

    file = fopen(CHAOS_NET_CONFIG_PATH, "w");
    assert(file != NULL);
    for (index = 0U; index < CHAOS_NET_MAX_CONFIG_BYTES; ++index)
    {
        assert(fputc('a', file) != EOF);
    }
    assert(fclose(file) == 0);
    assert(chaos_net_config_read_file(&index, chaos_net_config_observed_mtime()) == -2);

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
    chaos_net_endpoint_t endpoint = {0};

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

/**
 * @brief Invariant: a caller that observes a reload in progress uses the current
 *   snapshot and never starts a second, concurrent reload.
 *
 * Triggering condition: `g_chaos_net_cached_mtime` holds `CHAOS_NET_MTIME_RELOADING`
 *   (another thread owns the reload) while the observed mtime differs from it.
 *
 * Expected observable behaviour: `prepare()` leaves both the reload marker and the
 *   active snapshot index untouched. A CAS from RELOADING to RELOADING would succeed,
 *   so without an explicit check the caller would reload into the same inactive
 *   snapshot -- and through the same shared read buffer -- as the owning thread.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_net_config_init();
    active_index = g_chaos_net_active_config_index;
    /* The claim belongs to this process: another of its threads is reloading. */
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_RELOADING;
    assert(chaos_net_config_observed_mtime() != CHAOS_NET_MTIME_RELOADING);

    (void)chaos_net_config_prepare();

    assert(g_chaos_net_cached_mtime == CHAOS_NET_MTIME_RELOADING);
    assert(g_chaos_net_active_config_index == active_index);

    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
}

/**
 * @brief Invariant: a failed config read keeps the active rules and is retried.
 *
 * Triggering condition: the file changes while `read()` fails.
 *
 * Expected observable behaviour:
 * - `prepare()` still reports the previously loaded rule as active.
 * - The cached stamp is not advanced, so the next call retries the read.
 * - Once reading works again, the new content is loaded.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_net_test_file_backup_t backup;
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint = {0};

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    chaos_net_config_init();
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9010", &endpoint));

    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 40);
    assert(chaos_net_config_prepare());

    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNRESET:1.0\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_net_config_prepare());
    assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
    assert(rule.errnum == ECONNREFUSED);
    assert(g_chaos_net_cached_mtime != chaos_net_config_observed_mtime());
    assert(g_chaos_net_cached_mtime != CHAOS_NET_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_net_config_prepare());
    assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
    assert(rule.errnum == ECONNRESET);

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: the change stamp sees writes within one mtime tick.
 *
 * Triggering condition: stat results that differ only in size or only in inode.
 *
 * Expected observable behaviour: each difference yields a different stamp.
 */
static void test_change_stamp_beyond_mtime(void)
{
    struct stat base;
    struct stat other;

    memset(&base, 0, sizeof(base));
    base.st_mtim.tv_sec = 50;
    base.st_size = 10;
    base.st_ino = 100;
    other = base;
    assert(chaos_net_config_hash_mtime(&base) == chaos_net_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_net_config_hash_mtime(&base) != chaos_net_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_net_config_hash_mtime(&base) != chaos_net_config_hash_mtime(&other));
}

/**
 * @brief Invariant: a child forked during a reload takes the orphaned claim over.
 *
 * Triggering condition: the cached stamp is RELOADING but the claim was recorded
 * by another process id, as a forked child sees it.
 *
 * Expected observable behaviour: `prepare()` reloads and publishes the file's rules
 * instead of serving the stale snapshot forever.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_net_test_file_backup_t backup;
    chaos_net_rule_t rule;
    chaos_net_endpoint_t endpoint = {0};

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    chaos_net_config_init();
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9010", &endpoint));
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 60);

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_RELOADING;
    (void)chaos_net_config_prepare();
    assert(g_chaos_net_cached_mtime == CHAOS_NET_MTIME_RELOADING);
    g_chaos_net_tls_prng_state = UINT64_C(42);
    chaos_net_config_after_fork();
    assert(g_chaos_net_tls_prng_state == 0U);
    assert(g_chaos_net_cached_mtime == CHAOS_NET_MTIME_UNKNOWN);
    assert(g_chaos_net_hits_pid == (uint64_t)getpid());
    assert(chaos_net_config_prepare());
    assert(g_chaos_net_cached_mtime == chaos_net_config_observed_mtime());
    chaos_net_config_after_fork();
    assert(g_chaos_net_cached_mtime == chaos_net_config_observed_mtime());
    assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));

    /* A competing taker-over wins the release: this caller keeps the current snapshot. */
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_net_config_prepare());
    g_test_config_force_cas_fail = 0;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: refreshing the config never changes the caller's errno.
 *
 * Triggering condition: `prepare()` with no config file, so its stat(2) fails with
 * ENOENT, and with a file to read.
 *
 * Expected observable behaviour: errno holds the caller's value afterwards.
 */
static void test_prepare_preserves_errno(void)
{
    chaos_net_test_file_backup_t backup;

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    chaos_net_config_init();
    (void)unlink(CHAOS_NET_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_net_config_prepare();
    assert(errno == EBADF);

    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 70);
    errno = EBADF;
    assert(chaos_net_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: a config read interrupted by a signal is retried, not treated as failure.
 *
 * Triggering condition: the first `read()` fails with EINTR.
 *
 * Expected observable behaviour: the rules are loaded as if nothing had happened.
 */
static void test_interrupted_read_is_retried(void)
{
    chaos_net_test_file_backup_t backup;

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_net_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_net_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: socket close rules parse, and RESET exists only for close.
 *
 * Triggering condition: `close` rules with RESET, an errno and LATENCY; RESET on
 * another operation; RESET with an invalid probability.
 *
 * Expected observable behaviour: the close rules parse with operation CLOSE and the
 * named effect; the other two lines are rejected.
 */
static void test_close_rules(void)
{
    char reset_line[] = "tcp4://127.0.0.1:9010:close:RESET:1.0";
    char errno_line[] = "tcp4://127.0.0.1:9010:close:EINTR:0.5";
    char latency_line[] = "tcp4://127.0.0.1:9010:close:LATENCY:25";
    char reset_on_recv[] = "tcp4://127.0.0.1:9010:recv:RESET:1.0";
    char reset_bad_probability[] = "tcp4://127.0.0.1:9010:close:RESET:2.0";
    chaos_net_rule_t rule;

    assert(chaos_net_config_parse_line(reset_line, &rule) == 1);
    assert(rule.operation == CHAOS_NET_OP_CLOSE);
    assert(rule.effect == CHAOS_NET_EFFECT_RESET);
    assert(chaos_net_config_parse_line(errno_line, &rule) == 1);
    assert(rule.operation == CHAOS_NET_OP_CLOSE);
    assert(rule.effect == CHAOS_NET_EFFECT_ERRNO);
    assert(rule.errnum == EINTR);
    assert(chaos_net_config_parse_line(latency_line, &rule) == 1);
    assert(rule.effect == CHAOS_NET_EFFECT_LATENCY);
    assert(chaos_net_config_parse_line(reset_on_recv, &rule) == -1);
    assert(chaos_net_config_parse_line(reset_bad_probability, &rule) == -1);
}

/**
 * @brief Invariant: a file that changed while it was read is not used.
 *
 * Expected observable behaviour: reading with the stamp of the file as it is now
 * succeeds; reading with any other stamp (the file changed after the stat that
 * started the reload) fails, so the reload keeps the previous rules and retries.
 */
static void test_read_file_rejects_changed_file(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# stable\n", 41);
    stamp = chaos_net_config_observed_mtime();
    assert(chaos_net_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_net_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_NET_STATUS_PATH, "r");
    size_t length;

    if (file == NULL)
    {
        return 0;
    }
    length = fread(buffer, 1U, size - 1U, file);
    buffer[length] = '\0';
    assert(fclose(file) == 0);
    return 1;
}

/**
 * @brief Invariant: a rejected line is recorded with its number, its text as written
 *   and the reason, and a full rule set followed by comments is still accepted.
 *
 * Triggering condition: a buffer whose fourth line is invalid and carries a comment;
 *   then exactly CHAOS_NET_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_net_rule_t rules[CHAOS_NET_MAX_RULES];
    char buffer[] =
        "# header\n\ntcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_net_config_last_error();
    const size_t line_length = strlen("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_net_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_NET_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_NET_MAX_RULES; ++index)
    {
        (void)strcat(many, "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_net_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_NET_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_NET_MAX_RULES; ++index)
    {
        (void)strcat(many, "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n");
    }
    assert(chaos_net_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_NET_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0") == 0);
    free(many);
}

/**
 * @brief Invariant: every load reports its outcome in the status file.
 *
 * Triggering condition: a rule file whose second line is invalid, then a valid rule
 *   file, then no rule file.
 *
 * Expected observable behaviour: state=error naming line 2 and its text, then
 *   state=ok with the rule count, both stamped with this process id; without a rule
 *   file the status file is removed.
 */
static void test_prepare_reports_status(void)
{
    char status[CHAOS_STATUS_BUFFER_SIZE];
    char expected[CHAOS_STATUS_BUFFER_SIZE];

    chaos_net_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_net_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    /* The status is staged under a name of its own; a leftover of an earlier
     * process with this pid is replaced, not left behind. */
    {
        char staging[128];
        FILE *leftover;

        (void)snprintf(
            staging, sizeof(staging), "/tmp/.chaos-staging-%ld-chaos-net.status", (long)getpid()
        );
        leftover = fopen(staging, "w");
        assert(leftover != NULL);
        assert(fclose(leftover) == 0);
        write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 52);
        assert(chaos_net_config_prepare() == 1);
        assert(access(staging, F_OK) != 0);
    }
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported, not silently re-read. */
    {
        FILE *large = fopen(CHAOS_NET_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_NET_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_net_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_NET_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_NET_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_net_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_NET_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_NET_CONFIG_PATH, 0700) == 0);
    assert(chaos_net_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_NET_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_NET_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_NET_CONFIG_PATH, 0) == 0);
        assert(chaos_net_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_NET_CONFIG_PATH);
    }
    assert(chaos_net_config_prepare() == 0);
    assert(!read_status_file(status, sizeof(status)));
}

/**
 * @brief Reads this process's hits file into @p buffer; returns 0 when it does not exist.
 */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, (long)getpid());
    file = fopen(path, "r");
    if (file == NULL)
    {
        return 0;
    }
    length = fread(buffer, 1U, size - 1U, file);
    buffer[length] = '\0';
    assert(fclose(file) == 0);
    return 1;
}

/**
 * @brief Invariant: every rule of a loaded snapshot counts its hits, the process
 *   reports the counts with the rule text, and a reload keeps the count of a rule
 *   that is still in the file.
 *
 * Triggering condition: one rule loaded and hit twice; then a second rule added
 *   and hit once.
 *
 * Expected observable behaviour: the hits file lists "2<TAB>rule # a", then also
 *   "1<TAB>rule # b" with the first count unchanged.
 */
static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_net_config_state_t *state;

    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # a\n", 61);
    assert(chaos_net_config_prepare() == 1);
    state = (chaos_net_config_state_t *)chaos_net_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == &state->hits[0]);
    assert(strcmp(state->text[0], "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # a\n") == 0);

    write_config_text(
        "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
        "a\ntcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n",
        62
    );
    assert(chaos_net_config_prepare() == 1);
    state = (chaos_net_config_state_t *)chaos_net_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0].count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_net_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_net_hits_writing = 0;
    assert(g_chaos_net_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_net_hits_total = CHAOS_HITS_EAGER;
    g_chaos_net_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1].count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_net_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n3\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );
    assert(g_chaos_net_hits_pending == 0);
    chaos_net_config_report_hits(NULL);
    g_chaos_net_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_net_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_net_config_after_fork();
    assert(g_chaos_net_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n0\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );
    g_chaos_net_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_net_hits_pending = 1;
    g_chaos_net_hits_pid = (uint64_t)getpid() + 1U;
    chaos_net_config_report_hits(NULL);
    assert(g_chaos_net_hits_pending == 1);
    g_chaos_net_hits_pending = 0;
    g_chaos_net_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, (long)getpid());
    (void)unlink(path);
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Invariant: a forked child reports only its own hits.
 *
 * Triggering condition: the parent hits a rule three times, forks, and the child
 *   hits it once.
 *
 * Expected observable behaviour: the child's hits file reports 1, not 4; the
 *   parent's file still reports 3.
 */
static void test_forked_child_reports_own_hits(void)
{
    char hits[1024];
    char path[64];
    chaos_net_config_state_t *state;
    pid_t child;
    int status = 0;

    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # f\n", 71);
    assert(chaos_net_config_prepare() == 1);
    state = (chaos_net_config_state_t *)chaos_net_config_active_state();
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);

    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        chaos_hit_record(state->rules[0].hit);
        _exit(
            read_hits_file(hits, sizeof(hits)) &&
                    strcmp(hits, "1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # f\n") == 0
                ? 0
                : 1
        );
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "3\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # f\n") == 0);

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, (long)child);
    (void)unlink(path);
    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, (long)getpid());
    (void)unlink(path);
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Invariant: once rules are loaded, the rule file is looked at no more often
 *   than the check interval, and is looked at again once the interval has passed.
 *
 * Triggering condition: rules loaded; the rule file removed; prepare called right
 *   after a look, then again with the last look one interval ago.
 *
 * Expected observable behaviour: the first call still sees the loaded rules (no
 *   look), the second sees the file is gone.
 */
static void test_rule_file_check_is_throttled(void)
{
    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 81);
    assert(chaos_net_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_net_check_interval_ns = UINT64_C(10000000000);
    g_chaos_net_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_NET_CONFIG_PATH);
    assert(chaos_net_config_prepare() == 1);

    g_chaos_net_last_check_ns = chaos_clock_now_ns() - g_chaos_net_check_interval_ns;
    assert(chaos_net_config_prepare() == 0);
    g_chaos_net_check_interval_ns = 0U;
}

/**
 * @brief Invariant: the vDSO lookup fails safely on anything but a real vDSO.
 *
 * Expected observable behaviour: a NULL base, memory without an ELF header and an
 *   unknown symbol name all give NULL; the real clock advances.
 */
static void test_vdso_lookup_rejects_bad_input(void)
{
    static const char not_elf[64] = "not an ELF image";
    const uint64_t first = chaos_clock_now_ns();

    assert(chaos_clock_vdso_lookup(0U, CHAOS_CLOCK_VDSO_SYMBOL) == NULL);
    assert(chaos_clock_vdso_lookup((uintptr_t)not_elf, CHAOS_CLOCK_VDSO_SYMBOL) == NULL);
    assert(
        chaos_clock_vdso_lookup((uintptr_t)getauxval(AT_SYSINFO_EHDR), "no_such_symbol") == NULL
    );
    assert(chaos_clock_vdso_lookup((uintptr_t)getauxval(AT_SYSINFO_EHDR), NULL) == NULL);
    assert(first != 0U && chaos_clock_now_ns() >= first);
    assert(chaos_clock_checked_recently(&g_chaos_net_last_check_ns, 0U) == 0);
}

/**
 * @brief Invariant: qualifiers after a rule are parsed into its policy, and a bad
 *   qualifier rejects the line.
 *
 * Expected observable behaviour: every qualifier lands in the policy and the rule
 *   itself still parses; an unknown qualifier, qualifiers without a rule and an
 *   `@until` before its `@from` are rejected as invalid rules.
 */
static void test_rule_qualifiers(void)
{
    static chaos_net_rule_t rules[CHAOS_NET_MAX_RULES];
    char qualified[] = "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @first=3 @from=1000 "
                       "@until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @from=2000 @until=1000\n";
    char empty_first[] = "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @first=0\n";
    size_t count = 0U;

    assert(chaos_net_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_net_config_parse_buffer(unknown, rules, &count) == -1);
    assert(
        strcmp(
            chaos_net_config_last_error()->text,
            "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @bogus=1"
        ) == 0
    );
    assert(chaos_net_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_net_config_last_error()->line == 2U);
    assert(chaos_net_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_net_config_parse_buffer(empty_first, rules, &count) == -1);
}

/**
 * @brief Invariant: TRICKLE parses on recv with a positive chunk size only.
 */
static void test_trickle_rule(void)
{
    chaos_net_rule_t rule;
    char ok[] = "tcp4://127.0.0.1:9000:recv:TRICKLE:1";
    char zero[] = "tcp4://127.0.0.1:9000:recv:TRICKLE:0";
    char send_rule[] = "tcp4://127.0.0.1:9000:send:TRICKLE:4";
    char text[] = "tcp4://127.0.0.1:9000:recv:TRICKLE:lots";

    assert(chaos_net_config_parse_line(ok, &rule) == 1);
    assert(rule.effect == CHAOS_NET_EFFECT_TRICKLE);
    assert(rule.chunk_bytes == 1U);
    assert(rule.probability == 1.0);
    assert(chaos_net_config_parse_line(zero, &rule) == -1);
    assert(chaos_net_config_parse_line(send_rule, &rule) == -1);
    assert(chaos_net_config_parse_line(text, &rule) == -1);

    {
        char dup[] = "tcp4://127.0.0.1:9000:recv:DUP:0.5";
        char dup_send[] = "tcp4://127.0.0.1:9000:send:DUP:0.5";
        char dup_bad[] = "tcp4://127.0.0.1:9000:recv:DUP:often";

        assert(chaos_net_config_parse_line(dup, &rule) == 1);
        assert(rule.effect == CHAOS_NET_EFFECT_DUP && rule.probability == 0.5);
        assert(chaos_net_config_parse_line(dup_send, &rule) == -1);
        assert(chaos_net_config_parse_line(dup_bad, &rule) == -1);
    }
}

/**
 * @brief Invariant: an @first budget is per process: a forked child starts its own,
 *   while the parent's stays used up.
 */
static void test_first_budget_is_per_process(void)
{
    chaos_net_config_state_t *state;
    pid_t child;
    int status = 0;

    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @first=1\n", 91);
    assert(chaos_net_config_prepare() == 1);
    state = (chaos_net_config_state_t *)chaos_net_config_active_state();
    assert(chaos_policy_fire(&state->rules[0].policy, state->rules[0].hit) == 1);
    assert(chaos_policy_fire(&state->rules[0].policy, state->rules[0].hit) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        _exit(
            chaos_policy_fire(&state->rules[0].policy, state->rules[0].hit) == 1 &&
                    chaos_policy_fire(&state->rules[0].policy, state->rules[0].hit) == 0
                ? 0
                : 1
        );
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(chaos_policy_fire(&state->rules[0].policy, state->rules[0].hit) == 0);
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_net_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_forked_child_reports_own_hits();
    test_first_budget_is_per_process();
    test_rule_file_check_is_throttled();
    test_vdso_lookup_rejects_bad_input();
    test_rule_qualifiers();
    test_trickle_rule();
    test_read_file_rejects_changed_file();
    test_helper_functions();
    test_parse_and_select_rules();
    test_selection_and_buffer_edges();
    test_invalid_lines();
    test_file_and_state_edges();
    test_prepare_and_match();
    test_reload_in_progress_is_not_joined();
    test_read_failure_keeps_rules_and_retries();
    test_change_stamp_beyond_mtime();
    test_fork_takes_over_orphaned_reload();
    test_prepare_preserves_errno();
    test_close_rules();
    test_interrupted_read_is_retried();
    return 0;
}
