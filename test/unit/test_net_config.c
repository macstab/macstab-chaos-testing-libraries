/**
 * @file test_net_config.c
 * @brief Unit tests for the libchaos-net rule file: parsing, operation/effect/selector
 *   checks, rule selection, reload, status file and hits file.
 *
 * @details
 * Unit under test: `src/net/chaos_net_config.c` (with `chaos_net_endpoint.c` for selectors).
 * The suite proves:
 * - grammar: `selector:operation:effect:value`; an errno name in the effect field means
 *   ERRNO; values are probabilities (ERRNO, CORRUPT, TIMEOUT, DUP, RESET), milliseconds
 *   (LATENCY, up to UINT32_MAX, no unit suffix) or a chunk size >= 1 (TRICKLE); probabilities
 *   follow the locale-independent grammar of `chaos_policy_parse_probability()`; qualifiers
 *   land in the rule's policy; a rejected line fails the whole file with its line number;
 * - checks: ERRNO is valid for every operation; CORRUPT, TRICKLE and DUP only for recv,
 *   TIMEOUT only for poll, RESET only for close; `socket` rules take only `*`, a wildcard
 *   host with port 0, or `unix://\*` (no address exists at socket() time); a build hook
 *   (`CHAOS_NET_RULE_SUPPORTED`, defined by `chaos-init`) can reject rules as UNSUPPORTED;
 * - selection: highest rank wins, then the longer selector, then the earlier rule; the two
 *   ends of a connection are searched together and the first end wins a tie;
 * - reload: as for every libchaos library (change stamp over mtime, size and inode; one
 *   reloader; failed I/O keeps the rules and retries; a file changed during the read is
 *   discarded; provisional loads of just-written files; EINTR retried; EACCES/EPERM/EISDIR
 *   lasting; errno preserved; throttled stat); a rule copy held across reloads (a blocking
 *   recv()) counts on the slot its rule keeps and goes inert once its rule leaves; a copy made
 *   while a snapshot is rewritten is rejected by its sequence counter;
 * - reporting: the status file in its exact format, staged under a per-writer name that
 *   never overwrites another writer's file; per-rule hits with eager and throttled writes;
 *   a fork child counts its own hits and has its own `@first` budget;
 * - the vDSO clock lookup rejects anything but a real vDSO and takes over a lookup orphaned
 *   by fork.
 *
 * Seams:
 * - `CHAOS_CONFIG_FILE_OPEN/READ/CLOSE` route the rule file through libc names, which are
 *   macro-redirected to stubs injecting EINTR, a chosen open errno, ENOENT, EIO, or an
 *   immediate EOF on the fake fd 7331 (whose fstat() then fails); otherwise they pass through.
 * - `chaos_net_atomic_cas_u64` is redirected so a lost reload race is deterministic.
 * - `CHAOS_STATUS_NONCE` is fixed through `g_test_status_nonce`, so staging names are known.
 * - `CHAOS_RACY_WINDOW_MS` is raised from 20 ms to 5000 ms.
 * - Tests use the real rule file `/tmp/.chaos-net.conf` with explicit mtimes, back up and
 *   restore it where they rewrite it, and fork for the per-process tests. `main()` sets the
 *   check interval to 0 so every call looks at the file.
 *
 * Out of scope: concurrent reloads on real threads, endpoints of live descriptors
 * (`test_net_endpoint.c`) and the wrappers (`test_chaos_net.c`).
 */

/* A rule file counts as just written for 5000 ms, not 20 ms: the racy-rewrite test restores
 * an earlier mtime and must still find it recent on a slow or loaded machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include <stdint.h>

/** @brief Nonce in the status writer's staging name (chaos_status.h); fixed so tests can
 *   predict and pre-create that name. */
static uint64_t g_test_status_nonce = 0U;
#define CHAOS_STATUS_NONCE(staging) ((void)(staging), g_test_status_nonce)

/* Production reads the rule file with raw syscalls on Linux; route it through the libc names
 * so the open/read/close stubs below can intercept it. */
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

/** @brief Non-zero fails every open with ENOENT: the file vanished between stat and open. */
static int g_test_config_force_open_fail = 0;

/**
 * @brief Non-zero makes open return `g_test_config_fake_fd`, read on it fail with EIO and close
 *   on it succeed, so a read failure after a successful open needs no real file.
 */
static int g_test_config_force_read_fail = 0;

/** @brief Number of upcoming reads that fail with EINTR, as a signal handler would cause. */
static int g_test_config_read_eintr = 0;

/** @brief Number of upcoming opens that fail with EINTR, as a signal handler would cause. */
static int g_test_config_open_eintr = 0;

/** @brief Non-zero fails every open with this errno (EACCES, EPERM, EMFILE). */
static int g_test_config_open_errno = 0;

/**
 * @brief Non-zero makes open return the fake fd and its first read report EOF; the fstat()
 *   that validates the read then fails with EBADF, as the fd was never really open.
 */
static int g_test_config_fake_eof = 0;

/** @brief Non-zero makes every CAS on the reload stamp fail, as when another thread won. */
static int g_test_config_force_cas_fail = 0;

/** @brief Fake fd for the read-failure and EOF paths; far above any fd this binary opens. */
static const int g_test_config_fake_fd = 7331;

/**
 * @brief open() replacement for the config source.
 *
 * Fault flags are checked in order: pending EINTR, `g_test_config_open_errno`, ENOENT, then
 * the fake fd. Otherwise it calls the real open(), forwarding the mode only with O_CREAT
 * (off Linux the status writer creates its file through open(), redirected here too).
 */
static int chaos_net_test_config_open(const char *path, int flags, ...)
{
    if (g_test_config_open_eintr > 0)
    {
        --g_test_config_open_eintr;
        errno = EINTR;
        return -1;
    }
    if (g_test_config_open_errno != 0)
    {
        errno = g_test_config_open_errno;
        return -1;
    }
    if (g_test_config_force_open_fail != 0)
    {
        errno = ENOENT;
        return -1;
    }
    if (g_test_config_force_read_fail != 0 || g_test_config_fake_eof != 0)
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
 * @brief read() replacement: pending EINTR first, then EIO or EOF on the fake fd, else the
 *   real read().
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
    if (g_test_config_fake_eof != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return read(fd, buffer, count);
}

/** @brief close() replacement: succeeds on the fake fd without a syscall, else real close(). */
static int chaos_net_test_config_close(int fd)
{
    if ((g_test_config_force_read_fail != 0 || g_test_config_fake_eof != 0) &&
        fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/** @brief CAS replacement: fails while `g_test_config_force_cas_fail` is set, else a real CAS. */
static int
chaos_net_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/* Selector parsing, compiled before the redirects: it does no file I/O. */
#include "../../src/net/chaos_net_endpoint.c"

#define open chaos_net_test_config_open
#define read chaos_net_test_config_read
#define close chaos_net_test_config_close
#define chaos_net_atomic_cas_u64 chaos_net_test_atomic_cas_u64
/* chaos-init defines this hook to reject rules it cannot apply from outside the tracee;
 * here it is a switch. */
static int g_test_rules_unsupported = 0;
#define CHAOS_NET_RULE_SUPPORTED(rule) ((void)(rule), !g_test_rules_unsupported)
#include "../../src/net/chaos_net_config.c"
#undef chaos_net_atomic_cas_u64
#undef close
#undef read
#undef open

/* -------------------------------------------------------------------------
 * Rule file backup, so tests leave the developer's file as they found it
 * --------------------------------------------------------------------- */

/** @brief Saved content of a rule file, or the fact that there was none. */
typedef struct chaos_net_test_file_backup
{
    int existed;
    char *data;
    size_t size;
} chaos_net_test_file_backup_t;

/** @brief Saves the whole of @p path into @p backup, or records that it does not exist. */
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

/** @brief Rewrites @p path from @p backup, or removes it when it did not exist. */
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

/** @brief Frees the saved content; the file itself is not touched. */
static void free_backup(chaos_net_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Replaces the rule file with @p text and sets its atime and mtime to @p stamp seconds.
 *
 * A distinct stamp per write makes every rewrite a change even within one filesystem tick,
 * and a stamp far in the past keeps the load out of the provisional (just-written) window.
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
 * @brief Proves the lexical and value helpers, the operation and errno name tables, the
 *   effect and selector checks, the change stamp, and the four-field split.
 *
 * @details
 * - All ten operation names but `close` (covered by test_close_rules) and all 19 errno names
 *   map to their values; NULL and unknown names fail.
 * - Probability uses the locale-independent rule grammar: "0", "1", "0." + digits, "1." +
 *   zeros, trailing blanks allowed, at most 15 significant decimals. nan, inf, hex, exponents,
 *   signs, a decimal comma, ".5", "0.", "1.5", leading zeros and trailing text are rejected:
 *   strtod accepted nan (which passes every range check) and stopped at the '.' under a
 *   locale with a decimal comma.
 * - Latency accepts 25 and rejects NULL, 42949672960 (over UINT32_MAX) and text.
 * - `socket` accepts `*`, `tcp4://\*:0` and `unix://\*`, but no address and no UNIX path.
 * - No sentinel stamp survives normalisation; a missing file is `CHAOS_NET_MTIME_MISSING`.
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
 * @brief Proves a seven-rule file parses field by field and selection picks the most
 *   specific rule for the operation.
 *
 * @details An exact endpoint picks the exact LATENCY rule over the earlier wildcard-host
 * ECONNREFUSED rule; `tcp4://\*:0` on socket picks the EAFNOSUPPORT rule; poll on that
 * endpoint matches nothing (the poll rule names another endpoint). With the build hook
 * rejecting rules, the file fails at line 1 with reason UNSUPPORTED and a rule count of 0.
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
 * @brief Proves comment and blank lines are skipped, NULL arguments are rejected, the rule
 *   limit applies, and the longer selector breaks a rank tie.
 *
 * @details Four rules among comments parse to four. The exact rule beats the wildcard-host
 * rule; recv matches nothing. `CHAOS_NET_MAX_RULES` + 1 (257) rules fail the buffer. Of two
 * rules with equal rank, `selector_len` 12 beats 10 regardless of order in the array.
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
 * @brief Proves every malformed line is rejected with -1 and a comment-only line returns 0.
 *
 * @details Rejected: missing fields; an empty selector, operation, effect or value; an
 * unknown operation or effect; CORRUPT on connect (recv only); a selector without a port;
 * TIMEOUT on connect (poll only); a UNIX path on socket; and a non-numeric value for ERRNO,
 * LATENCY, CORRUPT and TIMEOUT. A NULL line or rule pointer is -1.
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
 * @brief Proves the read errors, the size limit, both-ends matching, a lost reload race and
 *   an invalid file.
 *
 * @details
 * - With no file the observed stamp is MISSING. A failed open (ENOENT) or read (EIO) returns
 *   -1; a file of exactly `CHAOS_NET_MAX_CONFIG_BYTES` (256 KiB) returns -2, as a read that
 *   fills the buffer cannot tell a complete file from a truncated one.
 * - Both ends of a connection are searched together: a wildcard rule matching the end tried
 *   first does not shadow a more specific rule for the other end; between equally specific
 *   rules the first end's wins; either end may be NULL; both NULL match nothing.
 * - Unchanged stamp: no reload. A lost CAS keeps the active snapshot and still reports rules.
 * - An invalid file (CORRUPT on connect) is fail-open: no rule matches, and none matches
 *   from a snapshot reset without clearing (`parse_ok` 0).
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

    {
        chaos_net_endpoint_t local;
        chaos_net_endpoint_t peer;

        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5433", &local));
        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5432", &peer));
        write_config_text("*:recv:LATENCY:10\ntcp4://127.0.0.1:5432:recv:ECONNRESET:1.0\n", 32);
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
        assert(chaos_net_config_prepare());
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, &local, &peer, &rule));
        assert(rule.effect == CHAOS_NET_EFFECT_ERRNO && rule.errnum == ECONNRESET);
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, &peer, &local, &rule));
        assert(rule.errnum == ECONNRESET);
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, &local, NULL, &rule));
        assert(rule.effect == CHAOS_NET_EFFECT_LATENCY);
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, NULL, &peer, &rule));
        assert(rule.errnum == ECONNRESET);
        assert(!chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, NULL, NULL, &rule));
        assert(!chaos_net_config_match_either_loaded(CHAOS_NET_OP_SEND, &local, &peer, &rule));
        /* Only recv rules are loaded: recv is a target, send is not (no lookup needed). */
        assert(chaos_net_config_targets_loaded(CHAOS_NET_OP_RECV));
        assert(!chaos_net_config_targets_loaded(CHAOS_NET_OP_SEND));
        /* Final: the peer's exact match (rank 3) has no higher rule; the local end's `*`
         * match (rank 1) is outranked by the exact rule, and SEND matches nothing. */
        assert(chaos_net_config_match_final_loaded(CHAOS_NET_OP_RECV, &peer, &rule));
        assert(rule.errnum == ECONNRESET);
        assert(!chaos_net_config_match_final_loaded(CHAOS_NET_OP_RECV, &local, &rule));
        assert(!chaos_net_config_match_final_loaded(CHAOS_NET_OP_SEND, &local, &rule));

        write_config_text(
            "tcp4://127.0.0.1:5433:recv:ECONNRESET:1.0\n"
            "tcp4://127.0.0.1:5432:recv:ETIMEDOUT:1.0\n",
            33
        );
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
        assert(chaos_net_config_prepare());
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, &local, &peer, &rule));
        assert(rule.errnum == ECONNRESET);
        assert(chaos_net_config_match_either_loaded(CHAOS_NET_OP_RECV, &peer, &local, &rule));
        assert(rule.errnum == ETIMEDOUT);
        /* Equal rank and selector length on the other rule: a tie, which this end wins. */
        assert(chaos_net_config_match_final_loaded(CHAOS_NET_OP_RECV, &local, &rule));
        assert(rule.errnum == ECONNRESET);

        /* Equal rank, longer selector: the other end could still win. */
        write_config_text(
            "tcp4://*:5433:recv:ECONNRESET:1.0\ntcp4://*:15432:recv:ETIMEDOUT:1.0\n", 34
        );
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
        assert(chaos_net_config_prepare());
        assert(!chaos_net_config_match_final_loaded(CHAOS_NET_OP_RECV, &local, &rule));

        /* Wildcard rules only: any match is final. */
        write_config_text("*:recv:LATENCY:10\n", 35);
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
        assert(chaos_net_config_prepare());
        assert(chaos_net_config_match_final_loaded(CHAOS_NET_OP_RECV, &local, &rule));
        assert(rule.effect == CHAOS_NET_EFFECT_LATENCY);

        write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 30);
        g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
        assert(chaos_net_config_prepare());
    }

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
    assert(!chaos_net_config_match_either_loaded(CHAOS_NET_OP_CONNECT, &endpoint, NULL, &rule));
    assert(!chaos_net_config_targets_loaded(CHAOS_NET_OP_CONNECT)); /* rejected file: no target */
    assert(!chaos_net_config_match_final_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves `chaos_net_config_match_endpoint()` refreshes before matching.
 *
 * @details Each rule file write is picked up by the next match without an explicit
 * prepare(): no file matches nothing, an ECONNREFUSED rule then matches, and replacing it
 * with an invalid line makes the same query match nothing. NULL endpoint or rule fails.
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
 * @brief Proves a caller that sees a reload in progress uses the current snapshot and does not
 *   start a second reload.
 *
 * @details A CAS from RELOADING to RELOADING would succeed, so without the explicit check two
 * threads would parse into the same inactive snapshot through the same shared read buffer.
 * The marker and the active index must stay untouched.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_net_config_init();
    active_index = g_chaos_net_active_config_index;
    /* Another thread of this process holds the claim. */
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_RELOADING;
    assert(chaos_net_config_observed_mtime() != CHAOS_NET_MTIME_RELOADING);

    (void)chaos_net_config_prepare();

    assert(g_chaos_net_cached_mtime == CHAOS_NET_MTIME_RELOADING);
    assert(g_chaos_net_active_config_index == active_index);

    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;
}

/**
 * @brief Proves a failed read keeps the active rules and releases the claim with the previous
 *   stamp, so the next call retries.
 *
 * @details Advancing the stamp would make the failure permanent: the file would not change
 * again and the new rule would never load. Leaving `RELOADING` would block every future
 * reload. The second prepare() must load ECONNRESET.
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
 * @brief Proves the change stamp differs when only the size or only the inode differs.
 *
 * @details Filesystems with 1 s (or coarser) mtime granularity give an append or an atomic
 * rename-over within the same second the same mtime; size and inode catch those.
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
 * @brief Proves a reload claim is never taken over by prepare(), and that the fork child
 *   handler releases an inherited one and resets per-process state.
 *
 * @details A vfork child shares the parent's memory while the parent's reloading thread is
 * still running, so prepare() must leave a `RELOADING` claim alone whoever made it. Only
 * `chaos_net_config_after_fork()` (pthread_atfork child handler; the reloading thread does not
 * exist in a fork child) resets it to `UNKNOWN`. It also zeroes the TLS PRNG state so pre-fork
 * workers do not all draw the parent's sequence, and records the child's pid as owner of the
 * hits. The next prepare() loads the file and its rule matches; a second handler call with no
 * claim leaves the published stamp alone. With a claim set, prepare() returns the current
 * snapshot before the CAS, so a forced CAS failure makes no difference.
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

    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_net_config_prepare());
    g_test_config_force_cas_fail = 0;
    g_chaos_net_cached_mtime = CHAOS_NET_MTIME_UNKNOWN;

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves prepare() preserves errno, both when stat() fails with ENOENT and when the
 *   file is opened and read.
 *
 * @details prepare() runs inside interposed calls; a wrapped connect() that succeeds must not
 * leave the library's own ENOENT for a caller that inspects errno.
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
 * @brief Proves a read interrupted by a signal (EINTR) is retried and the rules load, instead
 *   of being treated as a read failure that defers the load.
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
 * @brief Proves `close` rules parse with RESET, an errno and LATENCY, and that RESET is
 *   rejected on any other operation and with a probability above 1.
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
 * @brief Proves a file whose stamp after the read differs from the stamp that started the
 *   reload is rejected (-1), so a half-old, half-new copy is never parsed.
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

/** @brief Reads the status file into @p buffer (NUL-terminated); 0 when it does not exist. */
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
 * @brief Proves a rejected line is recorded by number, reason and original text, and that the
 *   rule limit counts rules, not lines.
 *
 * @details Line 4 (comments and blank lines count) is reported as "invalid rule" with its
 * comment still attached, so the status file shows the line as the user wrote it.
 * `CHAOS_NET_MAX_RULES` (256) rules followed by a comment parse cleanly and clear the last
 * error; one rule more is rejected as "too many rules" at line 257 with a rule count of 0.
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
 * @brief Proves every load writes its outcome to the status file in the exact documented
 *   format, that staging never clobbers another writer's file, and that a missing rule file
 *   removes the status file.
 *
 * @details Checked outcomes, each stamped with this pid: an invalid line 2; a valid file
 * (`state=ok`, `rules=1`); a file of exactly `CHAOS_NET_MAX_CONFIG_BYTES` ("file too large");
 * a NUL byte ("file contains a NUL byte", since the parser would stop there and report a
 * truncated rule set as ok); a directory (EISDIR on read) and, unless running as root, a
 * mode-0 file (EACCES on open), both "file unreadable". A pre-existing staging file with this
 * pid and nonce belongs to another writer (a container sharing /tmp with the same pid): it is
 * left in place and the next nonce is used, and that staging file is gone after the rename.
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

    {
        char staging[128];
        FILE *other;

        g_test_status_nonce = UINT64_C(0x10);
        (void)snprintf(
            staging, sizeof(staging), "/tmp/.chaos-staging-%ld-10-chaos-net.status", (long)getpid()
        );
        other = fopen(staging, "w");
        assert(other != NULL);
        assert(fclose(other) == 0);
        write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n", 52);
        assert(chaos_net_config_prepare() == 1);
        assert(access(staging, F_OK) == 0);
        assert(unlink(staging) == 0);
        (void)snprintf(
            staging, sizeof(staging), "/tmp/.chaos-staging-%ld-11-chaos-net.status", (long)getpid()
        );
        assert(access(staging, F_OK) != 0);
        g_test_status_nonce = 0U;
    }
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

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

/** @brief Reads this process's hits file into @p buffer (NUL-terminated); 0 when absent. */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, g_chaos_net_hits_file);
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
 * @brief Proves the hits file lifecycle: per-rule counts with the rule text, counts kept
 *   across a reload, write throttling, the exit flush, and the fork reset.
 *
 * @details
 * - Each line is `count<TAB>rule text` with the comment kept; a rule still in the file after
 *   a reload keeps its count (2), a new rule starts at 0.
 * - A hit that finds another thread writing (`g_chaos_net_hits_writing`) is left pending, not
 *   lost and not written concurrently.
 * - After `CHAOS_HITS_EAGER` (64) hits, a hit within `CHAOS_HITS_INTERVAL_MS` (100 ms) of the
 *   last write is only counted; the exit report writes it, and a second exit report with
 *   nothing pending writes nothing. Once the interval has passed a hit is written at once.
 * - The fork child handler releases a writer flag held by a parent thread, zeroes the counts,
 *   and turns a slot that was deciding a once-only effect (state 3) back to armed (1) while a
 *   fired one (2) stays fired.
 * - A process whose pid is not the recorded owner (a vfork child sharing the parent's
 *   memory) writes nothing at exit.
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
    assert(state->rules[0].hit == state->hits[0]);
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
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );

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

    g_chaos_net_hits_total = CHAOS_HITS_EAGER;
    g_chaos_net_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n1\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );

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

    g_chaos_net_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(g_chaos_net_hits_pending == 0);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # "
            "a\n4\ttcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 # b\n"
        ) == 0
    );
    g_chaos_net_hits_total = 0U;

    g_chaos_net_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* deciding: owner thread is gone */
    state->rules[1].hit->state = 2U; /* fired: must stay fired */
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

    g_chaos_net_hits_pending = 1;
    g_chaos_net_hits_pid = (uint64_t)getpid() + 1U;
    chaos_net_config_report_hits(NULL);
    assert(g_chaos_net_hits_pending == 1);
    g_chaos_net_hits_pending = 0;
    g_chaos_net_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, g_chaos_net_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Proves a fork child writes only its own hits, to its own hits file.
 *
 * @details The parent hits the rule 3 times and forks (a real fork(), so the pthread_atfork
 * handler runs); the child's single hit is reported as 1, not 4, and the parent's file still
 * reads 3. The child reports through its exit status, as asserts there would not fail the
 * parent.
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
    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_NET_HITS_PREFIX, g_chaos_net_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Proves that with rules loaded the rule file is stat()ed at most once per check
 *   interval, and again once the interval has passed.
 *
 * @details The interval is raised to 10 s and the rule file removed. Right after a look,
 * prepare() still reports the loaded rules (no stat); with the last look one interval ago it
 * sees the file is gone. A zero `chaos_clock_now_ns()` would make the throttle meaningless,
 * hence the first assertion.
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
 * @brief Proves the vDSO clock lookup rejects anything but a real vDSO, and that a lookup
 *   orphaned by fork is taken over while one of this process's own is not waited for.
 *
 * @details A NULL base, memory without an ELF header, an unknown symbol and a NULL name give
 * NULL; the clock is non-zero and monotonic; a zero interval never counts as checked
 * recently. A lookup state of 1 (in progress) owned by another pid (the parent, forked
 * mid-lookup) is reset and redone, ending as 2 owned by this pid. In progress and owned by
 * this process (another thread), the caller gets NULL (no vDSO clock for this call) instead
 * of spinning.
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

    g_chaos_clock_state = 1;
    g_chaos_clock_owner = (long)getpid() + 1L;
    (void)chaos_clock_now_ns();
    assert(g_chaos_clock_state == 2 && g_chaos_clock_owner == (long)getpid());
    g_chaos_clock_state = 1;
    assert(chaos_clock_vdso() == NULL);
    g_chaos_clock_state = 2;
}

/**
 * @brief Proves qualifiers are stripped from the rule and parsed into its policy, and that a
 *   bad qualifier rejects the line.
 *
 * @details All four qualifier kinds before a comment land in the policy; a parsed rule carries
 * no byte count until a wrapper sets one (`CHAOS_POLICY_NO_SIZE`). Rejected: an unknown
 * qualifier (reported with its full text), a qualifier with no rule before it (line 2),
 * `@until` not after `@from`, and `@first=0`.
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
 * @brief Proves TRICKLE and DUP are recv-only and validate their values.
 *
 * @details TRICKLE takes a chunk size >= 1 in bytes and always fires (probability 1.0); 0 and
 * text are rejected. DUP takes a probability. Both are rejected on send.
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
 * @brief Proves a `@first=N` budget is per process: a fork child gets a fresh budget of 1
 *   while the parent's stays used up.
 *
 * @details The atfork child handler resets the claims of every slot, so pre-fork workers
 * each see a start-up fault once. The child reports through its exit status.
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
    assert(
        chaos_policy_fire(
            &state->rules[0].policy, state->rules[0].hit, state->rules[0].hit_generation
        ) == 1
    );
    assert(
        chaos_policy_fire(
            &state->rules[0].policy, state->rules[0].hit, state->rules[0].hit_generation
        ) == 0
    );
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        _exit(
            chaos_policy_fire(
                &state->rules[0].policy, state->rules[0].hit, state->rules[0].hit_generation
            ) == 1 &&
                    chaos_policy_fire(
                        &state->rules[0].policy, state->rules[0].hit, state->rules[0].hit_generation
                    ) == 0
                ? 0
                : 1
        );
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(
        chaos_policy_fire(
            &state->rules[0].policy, state->rules[0].hit, state->rules[0].hit_generation
        ) == 0
    );
    (void)unlink(CHAOS_NET_CONFIG_PATH);
}

/**
 * @brief Proves an in-place rewrite that leaves mtime, size, inode and device unchanged is
 *   still loaded, and that re-reading an unchanged provisional file keeps its snapshot.
 *
 * @details A load whose mtime is within `CHAOS_RACY_WINDOW_MS` of now is provisional: a write
 * in the same mtime tick would be invisible to the stamp, so the file is read again on the
 * next check. Re-reading identical bytes (same content hash) keeps the snapshot with its hits
 * and `@first` claims. Commenting out the rule in place and restoring the original atime and
 * mtime is loaded (0 rules). Setting the mtime far outside the window makes the load final.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_net_check_interval_ns;

    g_chaos_net_check_interval_ns = 0U;
    (void)unlink(CHAOS_NET_CONFIG_PATH);
    chaos_net_config_init();
    file = fopen(CHAOS_NET_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_NET_CONFIG_PATH, &first) == 0);
    assert(chaos_net_config_prepare());
    assert(g_chaos_net_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    assert(chaos_net_config_prepare());
    assert(g_chaos_net_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_NET_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_net_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_NET_CONFIG_PATH, times, 0) == 0);
    assert(chaos_net_config_prepare() == 0);
    assert(g_chaos_net_config_provisional == 0);

    (void)unlink(CHAOS_NET_CONFIG_PATH);
    g_chaos_net_check_interval_ns = interval;
}

/**
 * @brief Proves pending hits are written by the next look at the rule file once their
 *   interval is over, so a long-running process that stopped hitting still reports them.
 *
 * @details Inside the interval the pending flag stays set; one interval later prepare()
 * writes and clears it.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_net_check_interval_ns;

    g_chaos_net_check_interval_ns = 0U;
    g_chaos_net_hits_pid = (uint64_t)getpid();
    g_chaos_net_hits_pending = 1;
    g_chaos_net_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_net_config_prepare();
    assert(g_chaos_net_hits_pending == 1);
    g_chaos_net_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_net_config_prepare();
    assert(g_chaos_net_hits_pending == 0);
    g_chaos_net_check_interval_ns = interval;
}

/**
 * @brief Proves a rule copy held across reloads stays bound to its own rule: it counts on the
 *   slot that rule keeps, and once the rule leaves it neither fires nor charges the rule that
 *   inherits the slot.
 *
 * @details A blocking recv() holds a copy of its rule for as long as it blocks. Rule a
 * (`@first=5`) is copied; a reload that keeps a gives it the same slot, and the copy's firing
 * counts there. Two reloads drop a and give the slot to c (`@first=1`): the slot's generation
 * moved on, so the stale copy fails, and c keeps a count of 0, no claims, and its own single
 * firing. Finally a match during a snapshot rewrite (odd sequence) is rejected, and a read
 * begun before a write stays invalid after it ends.
 */
static void test_rule_copies_across_reloads(void)
{
    const chaos_net_config_state_t *state;
    const uint64_t interval = g_chaos_net_check_interval_ns;
    chaos_net_rule_t copy;

    g_chaos_net_check_interval_ns = 0U;
    chaos_net_config_init();
    write_config_text("tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @first=5 # a\n", 70);
    assert(chaos_net_config_prepare());
    copy = chaos_net_config_active_state()->rules[0];

    write_config_text(
        "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0 @first=5 # a\n"
        "tcp4://127.0.0.1:9011:connect:ECONNREFUSED:1.0 # b\n",
        71
    );
    assert(chaos_net_config_prepare());
    state = chaos_net_config_active_state();
    assert(state->hits[0] == copy.hit);
    assert(chaos_policy_fire(&copy.policy, copy.hit, copy.hit_generation) == 1);
    assert(state->hits[0]->count == 1U);

    write_config_text("tcp4://127.0.0.1:9011:connect:ECONNREFUSED:1.0 # b\n", 72);
    assert(chaos_net_config_prepare());
    write_config_text(
        "tcp4://127.0.0.1:9011:connect:ECONNREFUSED:1.0 # b\n"
        "tcp4://127.0.0.1:9012:connect:ECONNREFUSED:1.0 @first=1 # c\n",
        73
    );
    assert(chaos_net_config_prepare());
    state = chaos_net_config_active_state();
    assert(state->hits[1] == copy.hit); /* c reuses a's slot */
    assert(chaos_policy_fire(&copy.policy, copy.hit, copy.hit_generation) == 0);
    assert(state->hits[1]->count == 0U && chaos_hit_claims(state->hits[1]->claimed) == 0U);
    assert(
        chaos_policy_fire(
            &state->rules[1].policy, state->rules[1].hit, state->rules[1].hit_generation
        ) == 1
    );

    {
        chaos_net_config_state_t *active = (chaos_net_config_state_t *)state;
        chaos_net_endpoint_t endpoint = {0};
        chaos_net_rule_t rule;
        uint64_t begin;

        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9011", &endpoint));
        assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
        begin = chaos_snapshot_read_begin(&active->sequence);
        chaos_snapshot_write_begin(&active->sequence);
        assert(!chaos_snapshot_read_valid(&active->sequence, begin));
        assert(!chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
        chaos_snapshot_write_end(&active->sequence);
        assert(!chaos_snapshot_read_valid(&active->sequence, begin));
        assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
    }

    (void)unlink(CHAOS_NET_CONFIG_PATH);
    g_chaos_net_check_interval_ns = interval;
}

/**
 * @brief Proves the remaining value, effect and selector checks, an unterminated last line,
 *   and that a later rule never displaces an earlier match of equal or higher rank.
 *
 * @details
 * - Latency rejects a unit suffix ("10ms") and leaves the output unchanged; trailing blanks
 *   are accepted; the input text is never modified.
 * - ERRNO is valid for all ten operations, RESET only for close, nothing for INVALID.
 * - `socket` accepts a wildcard host with port 0 for tcp6, udp4 and udp6, and rejects a port
 *   or a concrete host; send accepts every selector kind except INVALID.
 * - A final line without a newline still yields its rule.
 * - An exact rule listed before a wildcard stays selected, and of two identical-rank,
 *   identical-length rules the first stays.
 */
static void test_rule_checks_and_selection_order(void)
{
    static const chaos_net_operation_t every_operation[] = {
        CHAOS_NET_OP_BIND,
        CHAOS_NET_OP_LISTEN,
        CHAOS_NET_OP_CONNECT,
        CHAOS_NET_OP_ACCEPT,
        CHAOS_NET_OP_SOCKET,
        CHAOS_NET_OP_SHUTDOWN,
        CHAOS_NET_OP_POLL,
        CHAOS_NET_OP_SEND,
        CHAOS_NET_OP_RECV,
        CHAOS_NET_OP_CLOSE,
    };
    static const char *const socket_selectors_allowed[] = {
        "tcp6://*:0",
        "udp4://*:0",
        "udp6://*:0",
    };
    static const char *const socket_selectors_rejected[] = {
        "tcp4://*:80",
        "udp6://*:53",
        "udp4://127.0.0.1:0",
        "tcp6://[::1]:0",
    };
    static const char *const kinds_for_send[] = {
        "tcp6://[::1]:443",
        "udp4://127.0.0.1:53",
        "udp6://[::1]:53",
        "unix:///tmp/app.sock",
    };
    chaos_net_endpoint_t selector;
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rules[2];
    chaos_net_rule_t rule;
    /* String literals: a parser that wrote to its input would crash here. */
    const char *unit_suffix = "10ms";
    const char *trailing_blanks = "10 \t";
    char kept[] = "10 x";
    unsigned int latency_ms = 7U;
    size_t rule_count = 0U;
    size_t index;

    assert(chaos_net_parse_latency(unit_suffix, &latency_ms) == -1);
    assert(latency_ms == 7U);
    assert(chaos_net_parse_latency(trailing_blanks, &latency_ms) == 0);
    assert(latency_ms == 10U);
    assert(chaos_net_parse_latency(kept, &latency_ms) == -1 && strcmp(kept, "10 x") == 0);
    assert(chaos_net_parse_latency("10", NULL) == -1);

    for (index = 0U; index < sizeof(every_operation) / sizeof(every_operation[0]); ++index)
    {
        assert(chaos_net_effect_allowed(every_operation[index], CHAOS_NET_EFFECT_ERRNO));
        assert(
            chaos_net_effect_allowed(every_operation[index], CHAOS_NET_EFFECT_RESET) ==
            (every_operation[index] == CHAOS_NET_OP_CLOSE)
        );
    }
    assert(!chaos_net_effect_allowed(CHAOS_NET_OP_INVALID, CHAOS_NET_EFFECT_ERRNO));

    for (index = 0U; index < sizeof(socket_selectors_allowed) / sizeof(socket_selectors_allowed[0]);
         ++index)
    {
        assert(chaos_net_endpoint_parse_selector(socket_selectors_allowed[index], &selector));
        assert(chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));
    }
    for (index = 0U;
         index < sizeof(socket_selectors_rejected) / sizeof(socket_selectors_rejected[0]);
         ++index)
    {
        assert(chaos_net_endpoint_parse_selector(socket_selectors_rejected[index], &selector));
        assert(!chaos_net_selector_allowed(CHAOS_NET_OP_SOCKET, &selector));
    }
    for (index = 0U; index < sizeof(kinds_for_send) / sizeof(kinds_for_send[0]); ++index)
    {
        assert(chaos_net_endpoint_parse_selector(kinds_for_send[index], &selector));
        assert(chaos_net_selector_allowed(CHAOS_NET_OP_SEND, &selector));
    }
    selector.kind = CHAOS_NET_ENDPOINT_INVALID;
    assert(!chaos_net_selector_allowed(CHAOS_NET_OP_SEND, &selector));

    {
        char unterminated[] = "# rules\ntcp4://127.0.0.1:80:connect:ECONNREFUSED:1.0";

        assert(chaos_net_config_parse_buffer(unterminated, rules, &rule_count) == 0);
        assert(rule_count == 1U);
        assert(rules[0].errnum == ECONNREFUSED);
    }

    {
        char exact_first[] = "tcp4://127.0.0.1:80:connect:EHOSTUNREACH:1.0\n"
                             "tcp4://*:80:connect:ECONNREFUSED:1.0\n";

        assert(chaos_net_config_parse_buffer(exact_first, rules, &rule_count) == 0);
        assert(rule_count == 2U);
        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:80", &endpoint));
        assert(chaos_net_config_select_endpoint_rule(
            rules, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, &rule
        ));
        assert(rule.errnum == EHOSTUNREACH);
    }

    {
        char same_rank[] = "tcp4://*:80:connect:EHOSTUNREACH:1.0\n"
                           "tcp4://*:80:connect:ECONNREFUSED:1.0\n";

        assert(chaos_net_config_parse_buffer(same_rank, rules, &rule_count) == 0);
        assert(chaos_net_config_select_endpoint_rule(
            rules, rule_count, CHAOS_NET_OP_CONNECT, &endpoint, &rule
        ));
        assert(rule.errnum == EHOSTUNREACH);
    }
}

/**
 * @brief Proves how open errors are classified, that a read whose fstat() fails is rejected,
 *   and that no failure path leaves the reentrancy guard set.
 *
 * @details Two EINTRs are retried and the file read. EACCES/EPERM return -3 (lasting, until
 * the file changes); EMFILE returns -1 (retried); none touches the size output. EOF followed
 * by a failing fstat() returns -1: an unverifiable read is not used. A guard left set would
 * disable every wrapper on this thread. With a rule loaded, an endpoint no rule names matches
 * nothing.
 */
static void test_read_file_open_errors(void)
{
    chaos_net_test_file_backup_t backup;
    size_t size = 0U;
    uint64_t stamp;

    backup_file(CHAOS_NET_CONFIG_PATH, &backup);
    write_config_text("# open\n", 43);
    stamp = chaos_net_config_observed_mtime();

    g_test_config_open_eintr = 2;
    assert(chaos_net_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open\n"));

    size = 0U;
    g_test_config_open_errno = EACCES;
    assert(chaos_net_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_net_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_net_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;
    assert(size == 0U);
    assert(!chaos_net_in_internal());

    g_test_config_fake_eof = 1;
    assert(chaos_net_config_read_file(&size, stamp) == -1);
    g_test_config_fake_eof = 0;
    assert(size == 0U);
    assert(!chaos_net_in_internal());

    {
        chaos_net_endpoint_t endpoint;
        chaos_net_rule_t rule;

        chaos_net_config_init();
        write_config_text("tcp4://127.0.0.1:9012:connect:ECONNREFUSED:1.0\n", 44);
        assert(chaos_net_config_prepare());
        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9013", &endpoint));
        assert(!chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
        assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9012", &endpoint));
        assert(chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_CONNECT, &endpoint, &rule));
        assert(rule.errnum == ECONNREFUSED);
        (void)unlink(CHAOS_NET_CONFIG_PATH);
    }

    restore_file(CHAOS_NET_CONFIG_PATH, &backup);
    free_backup(&backup);
}

int main(void)
{
    /* Stat the rule file on every call so each write is seen at once; the throttle has its
     * own test. */
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
    test_racy_rewrite_is_seen();
    test_pending_hits_written_after_interval();
    test_rule_copies_across_reloads();
    test_rule_checks_and_selection_order();
    test_read_file_open_errors();
    return 0;
}
