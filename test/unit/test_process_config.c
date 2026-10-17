/**
 * @file test_process_config.c
 * @brief Proves the libchaos-process rule file pipeline: parse, select, reload, report.
 *
 * @details
 * Unit under test: `src/process/chaos_process_config.c`. The suite proves:
 * - the rule grammar `selector:effect:value[@probability] [qualifiers] [# comment]` for the
 *   ERRNO, LATENCY and FAIL_AFTER effects, including every numeric limit and each rejection
 *   reason recorded for the status file;
 * - rule selection: a named operation beats `*`, then the longer selector wins, regardless of
 *   rule order;
 * - the reload protocol: the change stamp (mtime, size, inode, device), the single reload
 *   claim, the two-snapshot publish, keeping the active rules on a failed read, rejecting a
 *   file that changed while it was read, re-reading a racily-clean (just written) file, and
 *   the 1 ms check throttle;
 * - the status file and hits file contents, and the fork() child reset;
 * - errno preservation across a reload.
 *
 * Isolation:
 * - `CHAOS_CONFIG_FILE_OPEN/READ/CLOSE` are predefined to libc `open`/`read`/`close`, which are
 *   then renamed by macro to stubs, so open and read failures (EINTR, EACCES, EPERM, EMFILE,
 *   EIO) are injected without touching the file system. `stat`/`fstat` stay real.
 * - `chaos_process_atomic_cas_u64` is renamed to a stub that can lose every CAS.
 * - Everything else is real: the tests write the real rule file
 *   (`/tmp/.chaos-process.conf`) and read the real status and hits files. Tests that write it
 *   back up and restore any existing rule file.
 * - `write_config_text()` sets the mtime to a fixed second near the epoch: each write gets a
 *   distinct stamp even within one clock tick, and the stamp is far outside the racily-clean
 *   window, so the load is final unless a test wants otherwise.
 * - `main()` sets the check interval to 0 so every `prepare()` looks at the file; only the
 *   throttle test restores a non-zero interval.
 *
 * The tests share the library's static state; each one that depends on it starts with
 * `chaos_process_config_init()`.
 */
/* Production reads the rule file with raw system calls; routing it through libc names lets the
 * macros below swap in the fault-injecting stubs. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* Widens the racily-clean window from 20 ms to 5 s: test_racy_rewrite_is_seen() restores the
 * mtime of a write made earlier and needs it still "recent" on a slow or loaded machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_process_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_PROCESS_DEFINE_TEST_GLOBALS();

/** @brief Non-zero makes every open fail with ENOENT (file gone since the stat). */
static int g_test_config_force_open_fail = 0;
/** @brief Non-zero makes open return `g_test_config_fake_fd`, whose reads fail with EIO. */
static int g_test_config_force_read_fail = 0;

/** @brief Upcoming reads that fail with EINTR, as an interrupting signal would make them. */
static int g_test_config_read_eintr = 0;

/** @brief Upcoming opens that fail with EINTR, as an interrupting signal would make them. */
static int g_test_config_open_eintr = 0;

/** @brief Non-zero makes every open fail with this errno (EACCES, EPERM, EMFILE). */
static int g_test_config_open_errno = 0;
/** @brief Non-zero makes every CAS fail, as if another thread claimed the reload first. */
static int g_test_config_force_cas_fail = 0;
/**
 * @brief Fake descriptor for the read-failure path; high enough not to alias a real open fd.
 */
static const int g_test_config_fake_fd = 9312;

/**
 * @brief Replaces `open(2)` for the production source; injects failures, else calls real open.
 *
 * Checks in order: pending EINTR, `g_test_config_open_errno`, forced ENOENT, then the fake fd
 * for the read-failure path. The variadic mode is forwarded for O_CREAT so the stub keeps
 * open's full signature.
 *
 * @return A real fd, `g_test_config_fake_fd`, or -1 with errno set.
 */
static int chaos_process_test_config_open(const char *path, int flags, ...)
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
 * @brief Replaces `read(2)`: pending EINTR first, EIO on the fake fd, else the real read.
 */
static ssize_t chaos_process_test_config_read(int fd, void *buffer, size_t count)
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
 * @brief Replaces `close(2)`: the fake fd is not a kernel fd, so it is not passed to close.
 */
static int chaos_process_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Replaces the reload-claim CAS; under `g_test_config_force_cas_fail` it always loses.
 *
 * A lost CAS means another thread claimed the reload, so the caller must use the active
 * snapshot unchanged. Otherwise it performs the real `__sync_bool_compare_and_swap`.
 */
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

/**
 * @brief Copy of a rule file taken before a test overwrites it, restored afterwards.
 *
 * The rule file path is fixed and shared with any libchaos-process run on the host, so tests
 * that write it put back what was there.
 */
typedef struct chaos_process_test_file_backup
{
    /** @brief Non-zero if the file existed; zero makes the restore delete it. */
    int existed;
    /** @brief Heap copy of the contents; NULL when the file did not exist or was empty. */
    char *data;
    /** @brief Bytes in `data`. */
    size_t size;
} chaos_process_test_file_backup_t;

/**
 * @brief Copies @p path into @p backup, or records that it does not exist.
 *
 * Reads in 256-byte chunks, so files of any size are copied without an `fstat` first.
 * @p backup is fully overwritten; it need not be initialised.
 */
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

/** @brief Rewrites @p path from @p backup verbatim, or deletes it if it did not exist. */
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

/** @brief Frees the copy held by @p backup and zeroes it. */
static void free_backup(chaos_process_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Writes @p text as the rule file and sets its atime and mtime to @p stamp seconds.
 *
 * Distinct stamps give distinct change stamps even when two writes fall into one file system
 * clock tick and keep the same size. Small stamps (1970) lie outside the racily-clean window,
 * so the next load is final, not provisional.
 */
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

/**
 * @brief Proves each leaf parser accepts its valid forms and rejects NULL, empty and bad input.
 *
 * Covers trimming (blanks include CR/LF), `#` comment stripping, all 14 errno names plus a
 * decimal errno, probability in [0, 1], latency and FAIL_AFTER count digits, bounded value
 * copies, `value[@p]` splitting (bare value leaves the probability as is), `ERRNO,count`,
 * the 7 selector names plus `*`, three-field splitting, and selector matching.
 *
 * The change-stamp checks matter for reload: a missing file hashes to MTIME_MISSING, and the
 * normaliser moves a hash off the MTIME_UNKNOWN and MTIME_RELOADING sentinels, so a real file
 * can never be mistaken for "not loaded yet" or "reload in progress".
 */
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

/**
 * @brief Proves the line parser fills a rule per effect and the buffer parser is all-or-nothing.
 *
 * Valid lines for each effect set selector, effect, payload and probability; a comment line
 * yields no rule (0). Ten malformed lines (structure, selector, effect, errno, latency,
 * missing count, probability > 1 for each effect) are rejected. A FAIL_AFTER count must be
 * plain digits that fit 64 bits: `-1` and `+1` are rejected because strtoull would turn -1
 * into UINT64_MAX (a rule that never fires), and 2^64 because it would wrap; UINT64_MAX itself
 * is accepted. Rejection must not change errno.
 *
 * Buffers: 4 rules parse; a last line without newline counts; blank and comment lines are
 * skipped; one bad line fails the whole buffer, so a half-applied rule file cannot happen.
 */
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
    {
        static const char *const counts[] = {
            "fork:FAIL_AFTER:EAGAIN,-1",
            "fork:FAIL_AFTER:EAGAIN,+1",
            "fork:FAIL_AFTER:EAGAIN,x",
            "fork:FAIL_AFTER:EAGAIN,18446744073709551616",
        };
        char largest[] = "fork:FAIL_AFTER:EAGAIN, 18446744073709551615";
        size_t index;

        for (index = 0U; index < sizeof(counts) / sizeof(counts[0]); ++index)
        {
            char line[64];

            (void)strcpy(line, counts[index]);
            errno = 1234;
            assert(chaos_process_config_parse_line(line, &rule) < 0);
            assert(errno == 1234);
        }
        assert(chaos_process_config_parse_line(largest, &rule) == 1);
        assert(rule.fail_after_count == UINT64_MAX);
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

/**
 * @brief Proves rule selection picks the most specific matching rule, independent of order.
 *
 * Selection is per (effect, operation). A named operation (pthread_create → ENOMEM) beats `*`
 * (EAGAIN); an operation with no named rule falls back to `*` (posix_spawn → EAGAIN). Among
 * equal ranks the longer `selector_len` wins whether listed first or second, and a later `*`
 * does not displace an earlier named rule. Order independence lets users append rules without
 * re-sorting the file.
 */
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
    char late_any_line[] = "*:ERRNO:EAGAIN";

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

    tie_rules[1] = tie_rules[0];
    tie_rules[0].selector.selector_len = 8U;
    tie_rules[0].errnum = ECHILD;
    tie_rules[1].selector.selector_len = 7U;
    tie_rules[1].errnum = EINTR;
    assert(chaos_process_config_select_rule(
        tie_rules, 2U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &rule
    ));
    assert(rule.errnum == ECHILD);

    assert(chaos_process_config_parse_line(late_any_line, &tie_rules[1]) == 1);
    assert(chaos_process_config_select_rule(
        tie_rules, 2U, CHAOS_PROCESS_EFFECT_ERRNO, CHAOS_PROCESS_OP_WAITPID, &rule
    ));
    assert(rule.errnum == ECHILD);
}

/**
 * @brief Proves the load/match lifecycle from no file through valid, changed and broken files.
 *
 * - No rule file: prepare and match report no rules.
 * - A valid file loads; match and match_loaded find the rule; an unchanged file keeps it.
 * - A new stamp is picked up by match itself (it calls prepare), with the new rule.
 * - A bad rule replaces the rule set with an empty one (fail closed to "no faults").
 * - A file of CHAOS_PROCESS_MAX_CONFIG_BYTES or more is refused by read_file.
 * - Open failure, EIO on read and a lost reload CAS each leave the active rule set in place;
 *   that set is the empty one from the bad rule, hence false.
 */
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
        assert(chaos_process_config_read_file(&size, chaos_process_config_observed_mtime()) < 0);
    }
    assert(chaos_process_config_read_file(NULL, chaos_process_config_observed_mtime()) < 0);

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

/**
 * @brief Proves CHAOS_PROCESS_MAX_RULES + 1 (257) valid rules fail the buffer, not overflow.
 *
 * The output array has room for one extra rule, so an off-by-one in the limit check would
 * write it instead of failing.
 */
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

/**
 * @brief Proves a caller that finds a reload in progress uses the active snapshot.
 *
 * The cached stamp is set to RELOADING, as while another thread owns the reload. A CAS from
 * RELOADING to RELOADING would succeed, so without an explicit check this caller would reload
 * into the same inactive snapshot through the same shared read buffer as the owner. The
 * claim and the active index must be untouched afterwards.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_process_config_init();
    active_index = g_chaos_process_active_config_index;
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    assert(chaos_process_config_observed_mtime() != CHAOS_PROCESS_MTIME_RELOADING);

    (void)chaos_process_config_prepare();

    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    assert(g_chaos_process_active_config_index == active_index);

    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;
}

/**
 * @brief Proves a failed read keeps the active rules and is retried on the next call.
 *
 * A read error (EIO here) says nothing about the rules, so dropping them would silently stop
 * fault injection until the file changed again. The claim is released with the old stamp
 * (not RELOADING, not the new one), so the next call reloads and finds both rules.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();

    write_config_text("fork:ERRNO:EAGAIN\n", 40);
    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 1U);

    write_config_text("fork:ERRNO:EAGAIN\npthread_create:FAIL_AFTER:EAGAIN,1\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 1U);
    assert(g_chaos_process_cached_mtime != chaos_process_config_observed_mtime());
    assert(g_chaos_process_cached_mtime != CHAOS_PROCESS_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_process_config_prepare());
    assert(chaos_process_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves the change stamp sees writes that leave the mtime unchanged.
 *
 * File systems stamp mtime from a coarse clock, so two writes in one tick keep it. The size
 * catches an append; the inode catches a rewrite via temporary file and rename(2) (`sed -i`).
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
    assert(chaos_process_config_hash_mtime(&base) == chaos_process_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_process_config_hash_mtime(&base) != chaos_process_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_process_config_hash_mtime(&base) != chaos_process_config_hash_mtime(&other));
}

/**
 * @brief Proves prepare never takes over a reload claim; only the fork() child handler drops it.
 *
 * A vfork child shares the parent's memory while the parent's reloading thread still runs, so
 * prepare must leave any RELOADING claim alone. A fork() child's atfork handler releases the
 * inherited claim (to UNKNOWN) and starts the child afresh: PRNG state 0 (reseeded on next
 * draw, so pre-forked workers do not decide alike), FAIL_AFTER counters 0, hits owned by the
 * child's pid. The next prepare then loads. The handler leaves a published stamp alone.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 60);

    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    g_chaos_process_tls_prng_state = UINT64_C(42);
    g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] = 7U;
    chaos_process_config_after_fork();
    assert(g_chaos_process_tls_prng_state == 0U);
    assert(g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] == 0U);
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_UNKNOWN);
    assert(g_chaos_process_hits_pid == (uint64_t)getpid());
    assert(chaos_process_config_prepare());
    assert(g_chaos_process_cached_mtime == chaos_process_config_observed_mtime());
    chaos_process_config_after_fork();
    assert(g_chaos_process_cached_mtime == chaos_process_config_observed_mtime());

    /* With rules loaded, a caller that finds a claim keeps the current snapshot (true); the
     * claim check returns before the forced CAS failure is reached. */
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_process_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* Same claim seen again: still untouched. */
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_RELOADING;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_cached_mtime == CHAOS_PROCESS_MTIME_RELOADING);
    g_chaos_process_cached_mtime = CHAOS_PROCESS_MTIME_UNKNOWN;

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves prepare preserves the caller's errno, with and without a rule file.
 *
 * Wrappers call prepare before the real function; a stat ENOENT leaking out would make a
 * successful call appear to fail with ENOENT. EBADF is a value prepare never sets itself.
 */
static void test_prepare_preserves_errno(void)
{
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_process_config_prepare();
    assert(errno == EBADF);

    write_config_text("fork:ERRNO:EAGAIN\n", 70);
    errno = EBADF;
    assert(chaos_process_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves a read interrupted by a signal (EINTR) is retried, not treated as failure.
 */
static void test_interrupted_read_is_retried(void)
{
    chaos_process_test_file_backup_t backup;

    backup_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_process_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_process_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_PROCESS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves read_file rejects a file whose stamp differs from the one that started reload.
 *
 * A writer that rewrote or appended during the read leaves a different stamp and possibly a
 * half-old, half-new copy. read_file compares the fstat stamp with the expected one: a
 * mismatch returns -1 (retryable), the matching stamp returns the full content.
 */
static void test_read_file_rejects_changed_file(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# stable\n", 41);
    stamp = chaos_process_config_observed_mtime();
    assert(chaos_process_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_process_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
}

/** @brief Reads the status file into @p buffer (NUL-terminated); 0 when it does not exist. */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_PROCESS_STATUS_PATH, "r");
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
 * @brief Proves a rejected buffer records line number, reason and the line as written.
 *
 * The status file shows these to the user, so the text keeps the comment the parser strips
 * and the line number counts blank and comment lines. Exactly CHAOS_PROCESS_MAX_RULES rules
 * plus a trailing comment is accepted and clears the error; one rule more reports line 257
 * as "too many rules" and leaves rule_count 0.
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    char buffer[] = "# header\n\nfork:ERRNO:EAGAIN\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_process_config_last_error();
    const size_t line_length = strlen("fork:ERRNO:EAGAIN\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_process_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_PROCESS_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_PROCESS_MAX_RULES; ++index)
    {
        (void)strcat(many, "fork:ERRNO:EAGAIN\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_process_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_PROCESS_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_PROCESS_MAX_RULES; ++index)
    {
        (void)strcat(many, "fork:ERRNO:EAGAIN\n");
    }
    assert(chaos_process_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_PROCESS_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "fork:ERRNO:EAGAIN") == 0);
    free(many);
}

/**
 * @brief Proves every load writes its outcome to the status file, byte for byte.
 *
 * Outcomes: an invalid line (state=error, line 2, text as written); a valid file (state=ok,
 * rules=1); a file of CHAOS_PROCESS_MAX_CONFIG_BYTES ("file too large"); a NUL byte ("file
 * contains a NUL byte"); a directory (EISDIR) and, when not root, a mode-0 file (EACCES), both
 * "file unreadable"; no rule file removes the status file. Every report carries this pid.
 */
static void test_prepare_reports_status(void)
{
    char status[CHAOS_STATUS_BUFFER_SIZE];
    char expected[CHAOS_STATUS_BUFFER_SIZE];

    chaos_process_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("fork:ERRNO:EAGAIN\n", 52);
    assert(chaos_process_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported and not re-read until it changes. */
    {
        FILE *large = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_PROCESS_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every later rule while
     * reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);

    /* Root bypasses file permissions, so the EACCES case runs only for other users. */
    assert(mkdir(CHAOS_PROCESS_CONFIG_PATH, 0700) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_PROCESS_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_PROCESS_CONFIG_PATH, 0) == 0);
        assert(chaos_process_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    }
    assert(chaos_process_config_prepare() == 0);
    assert(!read_status_file(status, sizeof(status)));
}

/** @brief Reads this process's hits file into @p buffer; 0 when it does not exist. */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_PROCESS_HITS_PREFIX, g_chaos_process_hits_file);
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
 * @brief Proves hit counting, the hits file format and its write schedule.
 *
 * - Each line is `count<TAB>rule text as written`; a reload keeps the count of a rule whose
 *   text is unchanged (`# a` stays 2 when `# b` is added).
 * - A hit that finds the writer busy stays pending and is not lost.
 * - The first CHAOS_HITS_EAGER (64) hits are written at once; after that a hit inside the
 *   100 ms interval only counts, a hit after it writes; the exit report flushes the rest.
 * - The fork() child handler releases the writer flag, resets a once-only decision still in
 *   progress (state 3 to 1) but keeps one that fired (2), and restarts counts at 0.
 * - Only the process that owns the counts writes them; a vfork child, which shares memory but
 *   has another pid, writes nothing.
 */
static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_process_config_state_t *state;

    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN # a\n", 61);
    assert(chaos_process_config_prepare() == 1);
    state = (chaos_process_config_state_t *)chaos_process_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "fork:ERRNO:EAGAIN # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n") == 0);

    write_config_text("fork:ERRNO:EAGAIN # a\nfork:ERRNO:EAGAIN # b\n", 62);
    assert(chaos_process_config_prepare() == 1);
    state = (chaos_process_config_state_t *)chaos_process_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    g_chaos_process_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_process_hits_writing = 0;
    assert(g_chaos_process_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    g_chaos_process_hits_total = CHAOS_HITS_EAGER;
    g_chaos_process_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n1\tfork:ERRNO:EAGAIN # b\n") == 0);

    chaos_process_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n3\tfork:ERRNO:EAGAIN # b\n") == 0);
    assert(g_chaos_process_hits_pending == 0);
    chaos_process_config_report_hits(NULL);

    g_chaos_process_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tfork:ERRNO:EAGAIN # a\n4\tfork:ERRNO:EAGAIN # b\n") == 0);
    assert(g_chaos_process_hits_pending == 0);
    g_chaos_process_hits_total = 0U;

    g_chaos_process_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_process_config_after_fork();
    assert(g_chaos_process_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\tfork:ERRNO:EAGAIN # a\n0\tfork:ERRNO:EAGAIN # b\n") == 0);
    g_chaos_process_hits_total = 0U;

    g_chaos_process_hits_pending = 1;
    g_chaos_process_hits_pid = (uint64_t)getpid() + 1U;
    chaos_process_config_report_hits(NULL);
    assert(g_chaos_process_hits_pending == 1);
    g_chaos_process_hits_pending = 0;
    g_chaos_process_hits_pid = (uint64_t)getpid();

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_PROCESS_HITS_PREFIX, g_chaos_process_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
}

/**
 * @brief Proves the rule file is stat()ed at most once per check interval once rules load.
 *
 * The stat is the largest part of a wrapper's cost. The interval is widened to 10 s so the
 * test cannot race the clock: right after a look, deleting the file goes unseen; with the
 * last look one interval back, the deletion is seen and the rules are gone.
 */
static void test_rule_file_check_is_throttled(void)
{
    chaos_process_config_init();
    write_config_text("fork:ERRNO:EAGAIN\n", 81);
    assert(chaos_process_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_process_check_interval_ns = UINT64_C(10000000000);
    g_chaos_process_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    assert(chaos_process_config_prepare() == 1);

    g_chaos_process_last_check_ns = chaos_clock_now_ns() - g_chaos_process_check_interval_ns;
    assert(chaos_process_config_prepare() == 0);
    g_chaos_process_check_interval_ns = 0U;
}

/**
 * @brief Proves qualifiers parse into the rule's policy and bad ones reject the line.
 *
 * `@first`, `@from`, `@until` and both `@size` bounds land in the policy; libchaos-process
 * calls carry no byte count, so `call_size` is CHAOS_POLICY_NO_SIZE. Rejected: an unknown
 * qualifier, a qualifier line with no rule (line 2), `@until` before `@from`, and
 * `@first=0`.
 */
static void test_rule_qualifiers(void)
{
    static chaos_process_rule_t rules[CHAOS_PROCESS_MAX_RULES];
    char qualified[] =
        "fork:ERRNO:EAGAIN @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "fork:ERRNO:EAGAIN @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "fork:ERRNO:EAGAIN @from=2000 @until=1000\n";
    char empty_first[] = "fork:ERRNO:EAGAIN @first=0\n";
    size_t count = 0U;

    assert(chaos_process_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_process_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_process_config_last_error()->text, "fork:ERRNO:EAGAIN @bogus=1") == 0);
    assert(chaos_process_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_process_config_last_error()->line == 2U);
    assert(chaos_process_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_process_config_parse_buffer(empty_first, rules, &count) == -1);
}

/**
 * @brief Proves a same-size in-place rewrite within one mtime tick is still loaded.
 *
 * Such a rewrite leaves mtime, size, inode and device unchanged, so the change stamp cannot
 * see it. A load of a file written within the racily-clean window is therefore provisional
 * and re-read on each check: an unchanged re-read (same content hash) keeps the snapshot and
 * its FAIL_AFTER counters; the rewrite (rule commented out) loads 0 rules; an mtime outside
 * the window makes the load final.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "fork:ERRNO:EAGAIN\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_process_check_interval_ns;

    g_chaos_process_check_interval_ns = 0U;
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    chaos_process_config_init();
    file = fopen(CHAOS_PROCESS_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_PROCESS_CONFIG_PATH, &first) == 0);
    assert(chaos_process_config_prepare());
    assert(g_chaos_process_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);
    g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] = 3U;

    assert(chaos_process_config_prepare());
    assert(g_chaos_process_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));
    assert(g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_FORK] == 3U);

    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_PROCESS_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_PROCESS_CONFIG_PATH, times, 0) == 0);
    assert(chaos_process_config_prepare() == 0);
    assert(g_chaos_process_config_provisional == 0);

    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
    g_chaos_process_check_interval_ns = interval;
}

/**
 * @brief Proves the next rule-file check writes hits pending for a whole interval (100 ms).
 *
 * Without this a long-running process that stopped hitting would report its last counts only
 * at exit. Inside the interval the hits stay pending.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_process_check_interval_ns;

    g_chaos_process_check_interval_ns = 0U;
    g_chaos_process_hits_pid = (uint64_t)getpid();
    g_chaos_process_hits_pending = 1;
    g_chaos_process_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_hits_pending == 1);
    g_chaos_process_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_process_config_prepare();
    assert(g_chaos_process_hits_pending == 0);
    g_chaos_process_check_interval_ns = interval;
}

/**
 * @brief Proves each value parser accepts its exact limit and rejects the next value.
 *
 * - errno: 2147483647 (INT_MAX) accepted; 0, -5, 2147483648 and "12x" rejected.
 * - latency (ms): 4294967295 accepted; 4294967296 and "12x" rejected, output untouched.
 * - FAIL_AFTER: "12x", ",5", "EAGAIN," and NULL outputs rejected, count untouched.
 * - A value that fills its buffer with no room for the NUL is rejected, one byte shorter is
 *   accepted; likewise the payload before `@`.
 * - An empty effect or value field, a bad latency or a bad count rejects the line.
 * - Selector matching gives the same answer with a NULL rank output.
 */
static void test_parse_boundaries(void)
{
    char payload[4];
    /* Writable arrays: the parsers trim the text after the number in place. */
    char errno_garbage[] = "12x";
    char latency_garbage[] = "12x";
    char count_garbage[] = "12x";
    char empty_errno[] = ",5";
    char empty_count[] = "EAGAIN,";
    char empty_effect_line[] = "fork::EAGAIN";
    char empty_value_line[] = "fork:ERRNO: ";
    char bad_latency_line[] = "fork:LATENCY:soon";
    char bad_count_line[] = "fork:FAIL_AFTER:EAGAIN,many";
    char split_line[] = "fork:ERRNO:EAGAIN";
    char *selector_text = NULL;
    char *effect_text = NULL;
    unsigned int latency = 0U;
    uint64_t count = 0U;
    int errnum = 0;
    double probability = 0.0;
    chaos_process_selector_t selector;
    chaos_process_rule_t rule;

    assert(chaos_process_parse_errno_name("2147483647") == 2147483647);
    assert(chaos_process_parse_errno_name("0") == -1);
    assert(chaos_process_parse_errno_name("-5") == -1);
    assert(chaos_process_parse_errno_name("2147483648") == -1);
    assert(chaos_process_parse_errno_name(errno_garbage) == -1);

    assert(chaos_process_parse_latency("4294967295", &latency) == 0);
    assert(latency == 4294967295U);
    assert(chaos_process_parse_latency("4294967296", &latency) != 0);
    assert(chaos_process_parse_latency(latency_garbage, &latency) != 0);
    assert(latency == 4294967295U);

    assert(chaos_process_parse_fail_after_count(count_garbage, &count) != 0);
    assert(chaos_process_parse_fail_after_value(empty_errno, &errnum, &count) != 0);
    assert(chaos_process_parse_fail_after_value(empty_count, &errnum, &count) != 0);
    assert(chaos_process_parse_fail_after_value(split_line, NULL, &count) != 0);
    assert(chaos_process_parse_fail_after_value(split_line, &errnum, NULL) != 0);
    assert(count == 0U);

    assert(chaos_process_copy_text_value("abcd", payload, sizeof(payload)) != 0);
    assert(chaos_process_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(strcmp(payload, "abc") == 0);
    assert(
        chaos_process_parse_payload_probability(
            "abcd@0.5", payload, sizeof(payload), &probability
        ) != 0
    );
    assert(
        chaos_process_parse_payload_probability(
            "abc@0.5", payload, sizeof(payload), &probability
        ) == 0
    );
    assert(strcmp(payload, "abc") == 0);
    assert(probability == 0.5);
    assert(
        chaos_process_parse_payload_probability("abc", NULL, sizeof(payload), &probability) != 0
    );
    assert(chaos_process_parse_payload_probability("abc", payload, sizeof(payload), NULL) != 0);

    assert(chaos_process_config_parse_line(empty_effect_line, &rule) < 0);
    assert(chaos_process_config_parse_line(empty_value_line, &rule) < 0);
    assert(chaos_process_config_parse_line(bad_latency_line, &rule) < 0);
    assert(chaos_process_config_parse_line(bad_count_line, &rule) < 0);
    assert(!chaos_process_split_rule_fields(split_line, &selector_text, &effect_text, NULL));
    assert(!chaos_process_split_rule_fields(split_line, &selector_text, NULL, NULL));
    assert(!chaos_process_selector_parse("*", NULL));

    assert(chaos_process_selector_parse("*", &selector));
    assert(chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_WAITPID, NULL));
    assert(chaos_process_selector_parse("fork", &selector));
    assert(chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_FORK, NULL));
    assert(!chaos_process_selector_matches(&selector, CHAOS_PROCESS_OP_EXECVE, NULL));
}

/**
 * @brief Proves open errors are classified: EINTR retried, EACCES/EPERM lasting, rest retryable.
 *
 * -3 (lasting) makes the reload reject the file until it changes, so an unreadable file is
 * reported once instead of re-opened on every check; -1 (EMFILE, out of descriptors) is
 * retried on the next check because it says nothing about the file.
 */
static void test_open_errors(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# open errors\n", 43);
    stamp = chaos_process_config_observed_mtime();
    g_test_config_open_eintr = 1;
    assert(chaos_process_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open errors\n"));

    g_test_config_open_errno = EACCES;
    assert(chaos_process_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_process_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_process_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;
    (void)unlink(CHAOS_PROCESS_CONFIG_PATH);
}

int main(void)
{
    /* Interval 0 makes every prepare stat the file, so tests see each write at once; the
     * throttle has its own test. */
    g_chaos_process_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_read_file_rejects_changed_file();
    test_helper_functions();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    test_parse_buffer_limit();
    test_reload_in_progress_is_not_joined();
    test_read_failure_keeps_rules_and_retries();
    test_change_stamp_beyond_mtime();
    test_fork_takes_over_orphaned_reload();
    test_prepare_preserves_errno();
    test_interrupted_read_is_retried();
    test_racy_rewrite_is_seen();
    test_pending_hits_written_after_interval();
    test_parse_boundaries();
    test_open_errors();
    return 0;
}
