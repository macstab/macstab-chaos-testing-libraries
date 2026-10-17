/**
 * @file test_time_config.c
 * @brief Proves the libchaos-time rule file pipeline: value and selector parsing, rule
 *   selection by specificity, the reload state machine with its failure paths, the status
 *   file, the hits file, qualifiers and the atfork reset.
 *
 * @details Unit under test: `src/time/chaos_time_config.c`, included directly so its
 * `static` functions and globals are reachable.
 *
 * Isolation seams:
 * - `CHAOS_CONFIG_FILE_OPEN/READ/CLOSE` are predefined to libc calls, which the `open`,
 *   `read` and `close` macros then route to stubs. Production uses raw system calls here,
 *   which no stub could intercept. The stubs inject EINTR, a chosen open errno, ENOENT, or
 *   a fake fd (8124) whose reads fail with EIO; otherwise they pass through.
 * - `chaos_time_atomic_cas_u64` is routed to a stub that can lose every CAS, modelling
 *   another thread winning the reload claim.
 * - `CHAOS_RACY_WINDOW_MS` is raised to 5000 so a file stays "just written" long enough on
 *   a slow machine.
 * - `g_chaos_time_check_interval_ns` is 0 for the whole run, so every call looks at the rule
 *   file; only the throttle test sets an interval.
 *
 * Side effects: the suite writes and deletes the real rule file, status file and hits file
 * under `/tmp` (`/tmp/.chaos-time.conf`, `.status`, `.hits.<n>`), so it must not run beside
 * a process using libchaos-time. Tests that start from a user's rule file back it up and
 * restore it. `write_config_text()` stamps mtimes of a few seconds after the epoch: every
 * write gets a distinct stamp regardless of filesystem timestamp resolution, and the stamp
 * is outside the racy window, so loads are final unless a test wants otherwise.
 *
 * Out of scope: the effect actions (test_time_actions.c) and the wrappers
 * (test_chaos_time.c).
 */

/* Read the rule file through libc names, which the macros below route to the stubs;
 * production uses raw system calls that no stub can intercept. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* A rule file counts as just written for 5 s instead of 20 ms: the racy-rewrite test
 * restores the first mtime and must still find it recent on a slow machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_time_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_TIME_DEFINE_TEST_GLOBALS();

/** @brief Non-zero makes the open stub fail with ENOENT (file removed after the stat). */
static int g_test_config_force_open_fail = 0;
/** @brief Non-zero makes the open stub return the fake fd, whose reads fail with EIO. */
static int g_test_config_force_read_fail = 0;

/** @brief Upcoming reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;

/** @brief Upcoming opens that fail with EINTR, as a signal would make them. */
static int g_test_config_open_eintr = 0;

/** @brief Non-zero makes every open fail with this errno (EACCES, EPERM, EMFILE). */
static int g_test_config_open_errno = 0;
/** @brief Non-zero makes every CAS fail, as if another thread had won the reload claim. */
static int g_test_config_force_cas_fail = 0;
/** @brief Fake fd for the read-failure path; high enough not to alias a descriptor in use. */
static const int g_test_config_fake_fd = 8124;

/**
 * @brief open seam. Checked in order: a pending EINTR, a forced errno, a forced ENOENT, then
 *   the fake fd for the read-failure path; otherwise the real open, forwarding the mode
 *   argument when O_CREAT is set.
 */
static int chaos_time_test_config_open(const char *path, int flags, ...)
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
 * @brief read seam: a pending EINTR first, then EIO on the fake fd, otherwise the real read.
 */
static ssize_t chaos_time_test_config_read(int fd, void *buffer, size_t count)
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

/** @brief close seam: the fake fd is not a kernel descriptor, so it is not really closed. */
static int chaos_time_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief CAS seam for the reload claim: fails while `g_test_config_force_cas_fail` is set,
 *   otherwise a real `__sync_bool_compare_and_swap`.
 *
 * @details A lost claim makes prepare keep the active snapshot and report whether it holds
 * rules, so the result depends on what an earlier load left active.
 */
static int
chaos_time_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_time_test_config_open
#define read chaos_time_test_config_read
#define close chaos_time_test_config_close
#define chaos_time_atomic_cas_u64 chaos_time_test_atomic_cas_u64
#include "../../src/time/chaos_time_config.c"
#undef chaos_time_atomic_cas_u64
#undef close
#undef read
#undef open

/** @brief Saved copy of a user's rule file, restored after a test that overwrites it. */
typedef struct chaos_time_test_file_backup
{
    /** @brief Non-zero if the file existed; zero makes restore delete it instead. */
    int existed;
    /** @brief File contents (heap; NULL for an empty or missing file). */
    char *data;
    /** @brief Bytes in `data`. */
    size_t size;
} chaos_time_test_file_backup_t;

/** @brief Copies @p path into @p backup, or records that it does not exist. */
static void backup_file(const char *path, chaos_time_test_file_backup_t *backup)
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

/** @brief Rewrites @p path from @p backup, or deletes it if it did not exist before. */
static void restore_file(const char *path, const chaos_time_test_file_backup_t *backup)
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

/** @brief Frees the saved contents and clears @p backup. */
static void free_backup(chaos_time_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Writes @p text to the rule file and sets its atime and mtime to @p stamp seconds.
 *
 * @details A distinct @p stamp per write guarantees a new change stamp, so the next prepare
 * reloads even if two writes fall into one filesystem timestamp tick. Stamps near the epoch
 * lie outside the racy window, so the load is final, not provisional.
 */
static void write_config_text(const char *text, time_t stamp)
{
    FILE *file;
    struct timespec times[2];

    file = fopen(CHAOS_TIME_CONFIG_PATH, "w");
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
 * @brief Proves each leaf parser accepts its valid forms and rejects NULL arguments and
 *   malformed text, so a bad rule fails at parse time instead of injecting a wrong fault.
 *
 * @details Highlights:
 * - `config_reset_state(&state, 0)` clears `rule_count` and `parse_ok` over 0xff garbage.
 * - `parse_errno_name`: EINVAL, EPERM, ENOSYS, EAGAIN and the number "4"; not "bad".
 * - `parse_offset` accepts exactly +-3155760000000 ms (100 years of 365.25 days) and
 *   rejects 1 ms more and values beyond int64, which `strtoll` would clamp silently.
 * - `parse_payload_probability`: "42" (probability defaults), "25@0.25"; not "@0.25" or a
 *   probability above 1.0.
 * - `parse_clock_id`: every clock name this platform defines, the number "7"; not
 *   "bad-clock".
 * - `selector_parse` rejects "", "clock_gettime/" (empty clock) and a selector longer than
 *   `CHAOS_TIME_MAX_TEXT` (128).
 * - `split_rule_fields` needs two colons and all output pointers.
 * - `effect_allowed` permits ERRNO and LATENCY on any selector, never INVALID.
 * - `hash_mtime(NULL)` is MTIME_MISSING; normalisation moves each reserved sentinel off its
 *   own value. It maps MTIME_UNKNOWN to MTIME_RELOADING, so "never returns a sentinel"
 *   would be false; the test checks only that the input value is not returned.
 */
static void test_helper_functions(void)
{
    char trim_text[] = " \t value \r\n";
    char blank_text[] = " \t\r\n";
    char comment_text[] = "abc#def";
    char payload_text[] = "25@0.25";
    char split_text[] = "clock_gettime/monotonic:OFFSET:-250";
    char no_probability_text[] = "42";
    char missing_effect_text[] = "selector:value";
    char overlong_selector[sizeof("clock_gettime/") + CHAOS_TIME_MAX_TEXT];
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_TIME_MAX_VALUE];
    struct stat st;
    chaos_time_selector_t selector;
    chaos_time_config_state_t state;
    clockid_t clock_id = (clockid_t)0;

    (void)memset(overlong_selector, '7', sizeof(overlong_selector));
    (void)memcpy(overlong_selector, "clock_gettime/", sizeof("clock_gettime/") - 1U);
    overlong_selector[sizeof(overlong_selector) - 1U] = '\0';

    assert(chaos_time_is_blank_char(' '));
    assert(chaos_time_is_blank_char('\t'));
    assert(!chaos_time_is_blank_char('x'));

    chaos_time_config_reset_state(NULL, 1);
    (void)memset(&state, 0xff, sizeof(state));
    chaos_time_config_reset_state(&state, 0);
    assert(state.rule_count == 0U);
    assert(state.parse_ok == 0);

    assert(chaos_time_trim(NULL) == NULL);
    assert(strcmp(chaos_time_trim(trim_text), "value") == 0);
    assert(strcmp(chaos_time_trim(blank_text), "") == 0);
    chaos_time_strip_comment(NULL);
    chaos_time_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);

    assert(chaos_time_parse_errno_name(NULL) == -1);
    assert(chaos_time_parse_errno_name("EINVAL") == EINVAL);
    assert(chaos_time_parse_errno_name("EPERM") == EPERM);
    assert(chaos_time_parse_errno_name("ENOSYS") == ENOSYS);
    assert(chaos_time_parse_errno_name("EAGAIN") == EAGAIN);
    assert(chaos_time_parse_errno_name("4") == 4);
    assert(chaos_time_parse_errno_name("bad") == -1);
    assert(chaos_time_parse_probability(NULL, &(double){0.0}) != 0);
    assert(chaos_time_parse_probability("0.5", NULL) != 0);
    assert(chaos_time_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_time_parse_probability("2.0", &(double){0.0}) != 0);
    assert(chaos_time_parse_latency(NULL, &(unsigned int){0U}) != 0);
    assert(chaos_time_parse_latency("25", NULL) != 0);
    assert(chaos_time_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_time_parse_latency("bad", &(unsigned int){0U}) != 0);
    assert(chaos_time_parse_offset(NULL, &(int64_t){0}) != 0);
    assert(chaos_time_parse_offset("-250", NULL) != 0);
    assert(chaos_time_parse_offset("-250", &(int64_t){0}) == 0);
    assert(chaos_time_parse_offset("bad", &(int64_t){0}) != 0);
    /* Offsets are bounded to 100 years either way; strtoll would clamp beyond int64
     * silently, so overflow must be detected, not inherited. */
    {
        int64_t offset = 0;

        assert(chaos_time_parse_offset("3155760000000", &offset) == 0);
        assert(offset == INT64_C(3155760000000));
        assert(chaos_time_parse_offset("-3155760000000", &offset) == 0);
        assert(offset == -INT64_C(3155760000000));
        assert(chaos_time_parse_offset("3155760000001", &offset) != 0);
        assert(chaos_time_parse_offset("-3155760000001", &offset) != 0);
        assert(chaos_time_parse_offset("9223372036854775808", &offset) != 0);
        assert(chaos_time_parse_offset("-9223372036854775809", &offset) != 0);
    }
    assert(chaos_time_copy_text_value(NULL, payload, sizeof(payload)) != 0);
    assert(chaos_time_copy_text_value("abc", NULL, sizeof(payload)) != 0);
    assert(chaos_time_copy_text_value("abc", payload, 0U) != 0);
    assert(chaos_time_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_time_copy_text_value("", payload, sizeof(payload)) != 0);
    assert(
        chaos_time_parse_payload_probability(NULL, payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_time_parse_payload_probability(
            no_probability_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "42") == 0);
    assert(
        chaos_time_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "25") == 0);
    assert(
        chaos_time_parse_payload_probability("@0.25", payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_time_parse_payload_probability("25@2.0", payload, sizeof(payload), &(double){0.0}) !=
        0
    );

    assert(!chaos_time_parse_clock_id(NULL, &clock_id));
    assert(!chaos_time_parse_clock_id("realtime", NULL));
    assert(chaos_time_parse_clock_id("realtime", &(clockid_t){0}));
    assert(chaos_time_parse_clock_id("monotonic", &(clockid_t){0}));
#ifdef CLOCK_MONOTONIC_RAW
    assert(chaos_time_parse_clock_id("monotonic_raw", &(clockid_t){0}));
#endif
#ifdef CLOCK_REALTIME_COARSE
    assert(chaos_time_parse_clock_id("realtime_coarse", &(clockid_t){0}));
#endif
#ifdef CLOCK_MONOTONIC_COARSE
    assert(chaos_time_parse_clock_id("monotonic_coarse", &(clockid_t){0}));
#endif
#ifdef CLOCK_BOOTTIME
    assert(chaos_time_parse_clock_id("boottime", &(clockid_t){0}));
#endif
#ifdef CLOCK_TAI
    assert(chaos_time_parse_clock_id("tai", &(clockid_t){0}));
#endif
#ifdef CLOCK_PROCESS_CPUTIME_ID
    assert(chaos_time_parse_clock_id("process_cputime_id", &(clockid_t){0}));
#endif
#ifdef CLOCK_THREAD_CPUTIME_ID
    assert(chaos_time_parse_clock_id("thread_cputime_id", &(clockid_t){0}));
#endif
    assert(chaos_time_parse_clock_id("7", &(clockid_t){0}));
    assert(!chaos_time_parse_clock_id("bad-clock", &(clockid_t){0}));

    assert(!chaos_time_selector_parse(NULL, &selector));
    assert(!chaos_time_selector_parse("", &selector));
    assert(!chaos_time_selector_parse("clock_gettime/", NULL));
    assert(!chaos_time_selector_parse(overlong_selector, &selector));
    assert(chaos_time_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "clock_gettime/monotonic") == 0);
    assert(strcmp(effect_text, "OFFSET") == 0);
    assert(strcmp(value_text, "-250") == 0);
    assert(!chaos_time_split_rule_fields(NULL, &selector_text, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields(split_text, NULL, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields("bad", &selector_text, &effect_text, &value_text));
    assert(!chaos_time_split_rule_fields(
        missing_effect_text, &selector_text, &effect_text, &value_text
    ));

    assert(!chaos_time_selector_matches(NULL, CHAOS_TIME_OP_USLEEP, 0, &((unsigned int){0U})));
    assert(!chaos_time_effect_allowed(NULL, CHAOS_TIME_EFFECT_ERRNO));
    assert(chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_ERRNO));
    assert(chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_LATENCY));
    assert(!chaos_time_effect_allowed(&selector, CHAOS_TIME_EFFECT_INVALID));

    (void)memset(&st, 0, sizeof(st));
    assert(chaos_time_config_hash_mtime(NULL) == CHAOS_TIME_MTIME_MISSING);
    assert(
        chaos_time_config_normalize_mtime_hash(CHAOS_TIME_MTIME_UNKNOWN) != CHAOS_TIME_MTIME_UNKNOWN
    );
    assert(
        chaos_time_config_normalize_mtime_hash(CHAOS_TIME_MTIME_RELOADING) !=
        CHAOS_TIME_MTIME_RELOADING
    );
    assert(chaos_time_config_hash_mtime(&st) != 0U);
}

/**
 * @brief Proves the three selector kinds and their ranks, which drive rule selection:
 *   `*` matches any operation at rank 1, `clock_gettime` any clock at rank 2, and
 *   `clock_gettime/monotonic` only CLOCK_MONOTONIC at rank 3.
 *
 * @details Also: `nanosleep` and `usleep` parse to their operations. `sleep` is not an
 * operation name (the sleep() wrapper uses `nanosleep` rules). An empty or unknown clock is
 * rejected.
 */
static void test_selector_matching(void)
{
    chaos_time_selector_t selector;
    unsigned int rank = 0U;

    assert(chaos_time_selector_parse("*", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_ANY);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_USLEEP, 0, &rank));
    assert(rank == 1U);

    assert(chaos_time_selector_parse("clock_gettime", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_OPERATION);
    assert(selector.operation == CHAOS_TIME_OP_CLOCK_GETTIME);
    assert(
        chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rank)
    );
    assert(rank == 2U);

    assert(chaos_time_selector_parse("clock_gettime/monotonic", &selector));
    assert(selector.kind == CHAOS_TIME_SELECTOR_CLOCK_ID);
    assert(selector.operation == CHAOS_TIME_OP_CLOCK_GETTIME);
    assert(
        chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rank)
    );
    assert(rank == 3U);
    assert(
        !chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rank)
    );

    assert(chaos_time_selector_parse("nanosleep", &selector));
    assert(selector.operation == CHAOS_TIME_OP_NANOSLEEP);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_NANOSLEEP, 0, &rank));

    assert(chaos_time_selector_parse("usleep", &selector));
    assert(selector.operation == CHAOS_TIME_OP_USLEEP);
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_USLEEP, 0, &rank));

    assert(!chaos_time_selector_parse("clock_gettime/", &selector));
    assert(!chaos_time_selector_parse("sleep", &selector));
    assert(!chaos_time_selector_parse("clock_gettime/bad-clock", &selector));
}

/**
 * @brief Proves the rule grammar `selector:EFFECT:value[@probability]` for ERRNO, LATENCY
 *   and OFFSET, and that one bad line rejects the whole buffer.
 *
 * @details parse_line returns 1 for a rule, 0 for a blank or comment line and a negative
 * value for an error. Probability defaults to 1.0. The 11 rejected lines cover: no colons,
 * empty selector, unknown operation `sleep`, unknown errno name, empty value before `@`
 * (ERRNO and OFFSET), probability above 1.0, non-numeric offset, OFFSET on `*` and on
 * `usleep` (OFFSET applies only to clock reads), and an unknown effect. Buffers: four mixed
 * rules, a last line without a newline, and blank and comment lines all parse; a bad second
 * line fails the buffer. All NULL arguments fail.
 */
static void test_parse_line_and_buffer(void)
{
    chaos_time_rule_t rule;
    chaos_time_rule_t rules[8];
    size_t rule_count = 0U;
    char comment_line[] = " #: ignored";
    char buffer[] = "*:ERRNO:EINVAL@0.5\n"
                    "clock_gettime/monotonic:OFFSET:-250@0.75\n"
                    "nanosleep:LATENCY:25\n"
                    "usleep:ERRNO:EINTR\n";

    assert(chaos_time_config_parse_line(comment_line, &rule) == 0);

    {
        char line[] = "*:ERRNO:EINVAL@0.5";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_TIME_SELECTOR_ANY);
        assert(rule.effect == CHAOS_TIME_EFFECT_ERRNO);
        assert(rule.errnum == EINVAL);
        assert(rule.probability == 0.5);
    }
    {
        char line[] = "clock_gettime:LATENCY:25";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.effect == CHAOS_TIME_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
        assert(rule.probability == 1.0);
    }
    {
        char line[] = "clock_gettime/monotonic:OFFSET:-250@0.75";
        assert(chaos_time_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_TIME_SELECTOR_CLOCK_ID);
        assert(rule.effect == CHAOS_TIME_EFFECT_OFFSET);
        assert(rule.offset_ms == -250);
        assert(rule.probability == 0.75);
    }
    {
        char invalid_line[] = "bad";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = ":ERRNO:EINTR";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "sleep:ERRNO:EINTR";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:ERRNO:nope";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:ERRNO:@0.5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:LATENCY:25@2.0";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime/monotonic:OFFSET:bad";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime/monotonic:OFFSET:@0.25";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        /* OFFSET needs a clock_gettime selector; `*` also covers the sleep operations. */
        char invalid_line[] = "*:OFFSET:5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        /* usleep reads no clock, so there is nothing to shift. */
        char invalid_line[] = "usleep:OFFSET:5";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "clock_gettime:BOGUS:1";
        assert(chaos_time_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 4U);

    {
        char buffer_no_newline[] = "usleep:ERRNO:EINTR";
        rule_count = 0U;
        assert(chaos_time_config_parse_buffer(buffer_no_newline, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    {
        char invalid_buffer[] = "usleep:ERRNO:EINTR\nbad";
        assert(chaos_time_config_parse_buffer(invalid_buffer, rules, &rule_count) < 0);
    }
    {
        char comment_buffer[] = "\n# ignored\nusleep:LATENCY:5\n";
        rule_count = 0U;
        assert(chaos_time_config_parse_buffer(comment_buffer, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    assert(chaos_time_config_parse_line(NULL, &rule) < 0);
    assert(chaos_time_config_parse_line(comment_line, NULL) < 0);
    assert(chaos_time_config_parse_buffer(NULL, rules, &rule_count) < 0);
    assert(chaos_time_config_parse_buffer(buffer, NULL, &rule_count) < 0);
    assert(chaos_time_config_parse_buffer(buffer, rules, NULL) < 0);
}

/**
 * @brief Proves the most specific matching rule of the requested effect wins, independent
 *   of file order.
 *
 * @details With `*`, `clock_gettime` and `clock_gettime/monotonic` ERRNO rules, a monotonic
 * read selects the clock rule (EINTR), a realtime read the operation rule (EFAULT) and
 * usleep the wildcard (EINVAL); a nanosleep LATENCY query finds the LATENCY rule. Equal
 * rank falls back to the longer selector text (`selector_len`, forced to 10 and 12 here),
 * whichever is listed first, and a later wildcard never replaces a more specific rule. File
 * order is not a tie-breaker, so reordering lines does not change behaviour.
 */
static void test_rule_selection(void)
{
    chaos_time_rule_t rules[4];
    chaos_time_rule_t tie_rules[2];
    chaos_time_rule_t rule;
    char tie_line[] = "clock_gettime:ERRNO:EFAULT";
    char any_line[] = "*:ERRNO:EINVAL";
    char clock_line[] = "clock_gettime:ERRNO:EFAULT";
    char exact_line[] = "clock_gettime/monotonic:ERRNO:EINTR";
    char nanosleep_line[] = "nanosleep:LATENCY:20";
    char late_any_line[] = "*:ERRNO:EINVAL";

    assert(chaos_time_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_time_config_parse_line(clock_line, &rules[1]) == 1);
    assert(chaos_time_config_parse_line(exact_line, &rules[2]) == 1);
    assert(chaos_time_config_parse_line(nanosleep_line, &rules[3]) == 1);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(rule.errnum == EINTR);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EFAULT);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule
    ));
    assert(rule.errnum == EINVAL);

    assert(chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &rule
    ));
    assert(rule.latency_ms == 20U);
    assert(!chaos_time_config_select_rule(
        NULL, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, &rule
    ));
    assert(!chaos_time_config_select_rule(
        rules, 4U, CHAOS_TIME_EFFECT_LATENCY, CHAOS_TIME_OP_NANOSLEEP, 0, NULL
    ));

    (void)memset(tie_rules, 0, sizeof(tie_rules));
    assert(chaos_time_config_parse_line(tie_line, &tie_rules[0]) == 1);
    tie_rules[0].selector.selector_len = 10U;
    tie_rules[0].errnum = EINVAL;
    tie_rules[1] = tie_rules[0];
    tie_rules[1].selector.selector_len = 12U;
    tie_rules[1].errnum = EPERM;
    assert(chaos_time_config_select_rule(
        tie_rules, 2U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EPERM);

    /* Reversed order: a later, shorter selector of the same rank does not win... */
    tie_rules[0] = tie_rules[1];
    tie_rules[1].selector.selector_len = 10U;
    tie_rules[1].errnum = EINVAL;
    assert(chaos_time_config_select_rule(
        tie_rules, 2U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EPERM);

    /* ...nor does a later selector of lower rank. */
    assert(chaos_time_config_parse_line(late_any_line, &tie_rules[1]) == 1);
    assert(chaos_time_config_select_rule(
        tie_rules, 2U, CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, &rule
    ));
    assert(rule.errnum == EPERM);
}

/**
 * @brief Proves the load cycle end to end: no rule file means no rules, a changed file is
 *   reloaded by `match` itself, a rejected file disables every rule, and open, read and
 *   claim failures never yield rules.
 *
 * @details Sequence:
 * - No file: prepare and match report nothing.
 * - An OFFSET rule loads; `match` and `match_loaded` find it; an unchanged stamp keeps it.
 * - A rewrite with a new stamp is picked up by the next `match`, and the old rule is gone.
 * - A bad rule leaves no usable snapshot, so even `match_loaded` finds nothing.
 * - A file of exactly `CHAOS_TIME_MAX_CONFIG_BYTES` is rejected by `read_file` (it might be
 *   truncated), as is a NULL size output.
 * - ENOENT on open, EIO on read and a lost reload claim each return false: the active
 *   snapshot, still the rejected one, holds no rules.
 */
static void test_prepare_and_match(void)
{
    chaos_time_test_file_backup_t backup;
    chaos_time_rule_t rule;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);

    g_test_config_force_open_fail = 0;
    g_test_config_force_read_fail = 0;
    g_test_config_force_cas_fail = 0;
    chaos_time_config_init();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    assert(!chaos_time_config_prepare());
    assert(!chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule));

    write_config_text("clock_gettime/monotonic:OFFSET:500\n", 11);
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_match(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(rule.offset_ms == 500);
    assert(chaos_time_config_match_loaded(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));
    assert(chaos_time_config_prepare());

    write_config_text("nanosleep:ERRNO:EINTR\n", 12);
    assert(chaos_time_config_match(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, 0, &rule));
    assert(rule.errnum == EINTR);
    assert(!chaos_time_config_match(
        CHAOS_TIME_EFFECT_OFFSET, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, &rule
    ));

    write_config_text("bad-rule\n", 16);
    assert(!chaos_time_config_prepare());
    assert(!chaos_time_config_match_loaded(CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_USLEEP, 0, &rule)
    );

    {
        char large_config[CHAOS_TIME_MAX_CONFIG_BYTES + 1U];
        size_t index;
        size_t size = 0U;

        for (index = 0U; index < CHAOS_TIME_MAX_CONFIG_BYTES; ++index)
        {
            large_config[index] = 'a';
        }
        large_config[CHAOS_TIME_MAX_CONFIG_BYTES] = '\0';
        write_config_text(large_config, 17);
        assert(chaos_time_config_read_file(&size, chaos_time_config_observed_mtime()) < 0);
    }
    assert(chaos_time_config_read_file(NULL, chaos_time_config_observed_mtime()) < 0);

    write_config_text("usleep:LATENCY:10\n", 13);
    g_test_config_force_open_fail = 1;
    assert(!chaos_time_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("usleep:LATENCY:20\n", 14);
    assert(!chaos_time_config_prepare());
    g_test_config_force_read_fail = 0;

    g_test_config_force_cas_fail = 1;
    write_config_text("usleep:LATENCY:30\n", 15);
    assert(!chaos_time_config_prepare());
    g_test_config_force_cas_fail = 0;

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves `CHAOS_TIME_MAX_RULES` + 1 (257) valid rules reject the buffer instead of
 *   dropping rules silently or overflowing the rule array.
 */
static void test_parse_buffer_limit(void)
{
    chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES + 1U];
    size_t rule_count = 0U;
    size_t capacity = (CHAOS_TIME_MAX_RULES + 1U) * sizeof("usleep:LATENCY:1\n");
    char *buffer = (char *)malloc(capacity);
    size_t offset = 0U;
    size_t index;

    assert(buffer != NULL);
    for (index = 0U; index <= CHAOS_TIME_MAX_RULES; ++index)
    {
        offset += (size_t)snprintf(buffer + offset, capacity - offset, "usleep:LATENCY:1\n");
    }

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) < 0);
    free(buffer);
}

/**
 * @brief Proves a caller that finds a reload in progress uses the current snapshot and does
 *   not start a second, concurrent reload.
 *
 * @details The cached stamp is set to MTIME_RELOADING, as while another thread owns the
 * claim. prepare must leave the marker and the active index untouched. The check is
 * explicit because a CAS from RELOADING to RELOADING succeeds: without it the caller would
 * reload into the same inactive snapshot, through the same shared read buffer, as the owner.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_time_config_init();
    active_index = g_chaos_time_active_config_index;
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    assert(chaos_time_config_observed_mtime() != CHAOS_TIME_MTIME_RELOADING);

    (void)chaos_time_config_prepare();

    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    assert(g_chaos_time_active_config_index == active_index);

    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;
}

/**
 * @brief Proves a transient read failure (EIO) keeps the active rules and is retried on the
 *   next call.
 *
 * @details A failed read says nothing about the new rules, so the one loaded rule stays
 * active and prepare still reports rules. The claim is released with the previous stamp,
 * neither advanced nor left at RELOADING, so the next call reloads and finds both rules
 * instead of running on stale rules until the file changes again.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();

    write_config_text("nanosleep:ERRNO:EINTR\n", 40);
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 1U);

    write_config_text("nanosleep:ERRNO:EINTR\nclock_gettime/monotonic:OFFSET:500\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 1U);
    assert(g_chaos_time_cached_mtime != chaos_time_config_observed_mtime());
    assert(g_chaos_time_cached_mtime != CHAOS_TIME_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_time_config_prepare());
    assert(chaos_time_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves the change stamp covers size and inode as well as mtime, so an append or an
 *   atomic rename within one mtime tick is still detected.
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
    assert(chaos_time_config_hash_mtime(&base) == chaos_time_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_time_config_hash_mtime(&base) != chaos_time_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_time_config_hash_mtime(&base) != chaos_time_config_hash_mtime(&other));
}

/**
 * @brief Proves a reload claim inherited through fork() is released by the atfork handler,
 *   after which the child reloads; prepare itself never takes over a claim.
 *
 * @details The handler is called directly. A reload thread of the parent does not exist in
 * the child, so the handler turns RELOADING into MTIME_UNKNOWN. It also clears the PRNG
 * state, so a child does not repeat its parent's random decisions, and records the child's
 * pid as the owner of its hits. A second call with no claim leaves the published stamp
 * alone. A lost CAS keeps the current snapshot (which holds a rule, so prepare reports
 * true). With RELOADING set and no fork, prepare leaves the claim to its owner.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 60);

    /* prepare never takes over a claim: in a vfork child the parent's reload thread is
     * still running. Only the fork() atfork handler releases it. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    g_chaos_time_tls_prng_state = UINT64_C(42);
    chaos_time_config_after_fork();
    assert(g_chaos_time_tls_prng_state == 0U);
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_UNKNOWN);
    assert(g_chaos_time_hits_pid == (uint64_t)getpid());
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_cached_mtime == chaos_time_config_observed_mtime());
    chaos_time_config_after_fork();
    assert(g_chaos_time_cached_mtime == chaos_time_config_observed_mtime());

    /* Another thread wins the claim: this caller keeps the current snapshot. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_time_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* RELOADING without a fork: another thread of this process owns the reload. */
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_RELOADING;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_cached_mtime == CHAOS_TIME_MTIME_RELOADING);
    g_chaos_time_cached_mtime = CHAOS_TIME_MTIME_UNKNOWN;

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves prepare preserves the caller's errno, whether its stat fails with ENOENT or
 *   it reads a file.
 *
 * @details prepare runs inside wrappers whose real call may succeed; leaking the library's
 * own ENOENT into errno would corrupt the caller's error handling.
 */
static void test_prepare_preserves_errno(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_time_config_prepare();
    assert(errno == EBADF);

    write_config_text("nanosleep:ERRNO:EINTR\n", 70);
    errno = EBADF;
    assert(chaos_time_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves a read interrupted by a signal (EINTR) is retried in place and the rules load
 *   as if nothing had happened.
 */
static void test_interrupted_read_is_retried(void)
{
    chaos_time_test_file_backup_t backup;

    backup_file(CHAOS_TIME_CONFIG_PATH, &backup);
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_time_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_time_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_TIME_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves `read_file` rejects a file whose stamp after the read differs from the one
 *   that triggered the reload.
 *
 * @details A writer that rewrote or appended to the file mid-read can leave a copy that is
 * half old and half new. Passing a stamp that differs by one bit simulates that; the current
 * stamp succeeds with the full size.
 */
static void test_read_file_rejects_changed_file(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# stable\n", 41);
    stamp = chaos_time_config_observed_mtime();
    assert(chaos_time_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_time_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
}

/** @brief Reads the status file into @p buffer (NUL-terminated); 0 when it does not exist. */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_TIME_STATUS_PATH, "r");
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
 * @brief Proves a rejected line is reported with its 1-based number (blank and comment lines
 *   counted), its text as written and the reason, and that the rule limit counts rules, not
 *   lines.
 *
 * @details "bogus-rule # typo" on line 4 is reported with its comment, since the parser cuts
 * the comment off in place only after the line was saved. Exactly 256 rules plus a trailing
 * comment parse with no error. 257 rules fail with "too many rules" on line 257, and the
 * rule count drops to 0, so no partial rule set is used.
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES];
    char buffer[] = "# header\n\nnanosleep:ERRNO:EINTR\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_time_config_last_error();
    const size_t line_length = strlen("nanosleep:ERRNO:EINTR\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_time_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_TIME_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_TIME_MAX_RULES; ++index)
    {
        (void)strcat(many, "nanosleep:ERRNO:EINTR\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_time_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_TIME_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_TIME_MAX_RULES; ++index)
    {
        (void)strcat(many, "nanosleep:ERRNO:EINTR\n");
    }
    assert(chaos_time_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_TIME_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "nanosleep:ERRNO:EINTR") == 0);
    free(many);
}

/**
 * @brief Proves every load writes its outcome to the status file in the exact documented
 *   format, and that without a rule file the status file is removed.
 *
 * @details Outcomes: a bad line 2 gives `state=error` with line, reason and text; a valid
 * file gives `state=ok` and the rule count; both end with this pid. Whole-file rejections
 * report line 0 and an empty text: a file of exactly `CHAOS_TIME_MAX_CONFIG_BYTES` ("file
 * too large"), a NUL byte ("file contains a NUL byte"), a directory (EISDIR on read) and,
 * unless running as root, a mode-0 file (EACCES on open), both "file unreadable".
 */
static void test_prepare_reports_status(void)
{
    char status[CHAOS_STATUS_BUFFER_SIZE];
    char expected[CHAOS_STATUS_BUFFER_SIZE];

    chaos_time_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("nanosleep:ERRNO:EINTR\n", 52);
    assert(chaos_time_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* At the size limit the file may be truncated, so it is rejected and reported. */
    {
        FILE *large = fopen(CHAOS_TIME_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_TIME_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_TIME_CONFIG_PATH);

    /* The parser would stop at a NUL byte and drop every later rule while reporting
     * state=ok, so the whole file is rejected. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_TIME_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_TIME_CONFIG_PATH);

    /* Unreadable: a directory fails read with EISDIR; a mode-0 file fails open with
     * EACCES, except for root, which bypasses permission checks. */
    assert(mkdir(CHAOS_TIME_CONFIG_PATH, 0700) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_TIME_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_TIME_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_TIME_CONFIG_PATH, 0) == 0);
        assert(chaos_time_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_TIME_CONFIG_PATH);
    }
    assert(chaos_time_config_prepare() == 0);
    assert(!read_status_file(status, sizeof(status)));
}

/** @brief Reads this process's hits file into @p buffer; 0 when it does not exist. */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_TIME_HITS_PREFIX, g_chaos_time_hits_file);
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
 * @brief Proves hit counting and reporting: each rule has its own slot, the hits file lists
 *   `count<TAB>rule text`, and a reload keeps the count of a rule whose text is unchanged.
 *
 * @details Write scheduling (`CHAOS_HITS_EAGER` = 64 hits written at once, then at most every
 * `CHAOS_HITS_INTERVAL_MS` = 100 ms) is driven through the globals:
 * - A hit that finds the writer busy stays pending; it is not lost.
 * - Past 64 hits and inside the interval a hit is counted but not written; the exit report
 *   writes it, and a second exit report has nothing left.
 * - Past 64 hits with the interval over, a hit is written at once.
 * - The atfork handler releases a held writer flag, resets a REGRESS decision in progress
 *   (state 3) to 1, keeps a completed jump (state 2) and restarts the counts at zero.
 * - An exit report from a pid other than the owner (a vfork child) writes nothing.
 */
static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_time_config_state_t *state;

    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR # a\n", 61);
    assert(chaos_time_config_prepare() == 1);
    state = (chaos_time_config_state_t *)chaos_time_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "nanosleep:ERRNO:EINTR # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n") == 0);

    write_config_text("nanosleep:ERRNO:EINTR # a\nnanosleep:ERRNO:EINTR # b\n", 62);
    assert(chaos_time_config_prepare() == 1);
    state = (chaos_time_config_state_t *)chaos_time_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* Writer busy: the hit stays pending for the writer to pick up. */
    g_chaos_time_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_time_hits_writing = 0;
    assert(g_chaos_time_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* Past the eager hits and inside the interval: counted, not yet written... */
    g_chaos_time_hits_total = CHAOS_HITS_EAGER;
    g_chaos_time_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n1\tnanosleep:ERRNO:EINTR # b\n") == 0);

    /* ...the exit report writes it; a second one finds nothing pending. */
    chaos_time_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n3\tnanosleep:ERRNO:EINTR # b\n") == 0);
    assert(g_chaos_time_hits_pending == 0);
    chaos_time_config_report_hits(NULL);

    /* Past the eager hits with the interval over: written at once. */
    g_chaos_time_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tnanosleep:ERRNO:EINTR # a\n4\tnanosleep:ERRNO:EINTR # b\n") == 0);
    assert(g_chaos_time_hits_pending == 0);
    g_chaos_time_hits_total = 0U;

    /* In a fork child the writer thread does not exist: the flag is released and the
     * child counts its own hits from zero. */
    g_chaos_time_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_time_config_after_fork();
    assert(g_chaos_time_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\tnanosleep:ERRNO:EINTR # a\n0\tnanosleep:ERRNO:EINTR # b\n") == 0);
    g_chaos_time_hits_total = 0U;

    /* Another pid (a vfork child sharing this memory) must not write the owner's counts. */
    g_chaos_time_hits_pending = 1;
    g_chaos_time_hits_pid = (uint64_t)getpid() + 1U;
    chaos_time_config_report_hits(NULL);
    assert(g_chaos_time_hits_pending == 1);
    g_chaos_time_hits_pending = 0;
    g_chaos_time_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_TIME_HITS_PREFIX, g_chaos_time_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
}

/**
 * @brief Proves that once rules are loaded the rule file is stat'ed at most once per check
 *   interval (10 s here), and again once the interval has passed.
 *
 * @details Each look is a stat system call, the largest part of a wrapper's cost. With the
 * file removed right after a look, prepare still reports the loaded rules; with the last
 * look one interval ago, it notices the file is gone.
 */
static void test_rule_file_check_is_throttled(void)
{
    chaos_time_config_init();
    write_config_text("nanosleep:ERRNO:EINTR\n", 81);
    assert(chaos_time_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_time_check_interval_ns = UINT64_C(10000000000);
    g_chaos_time_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    assert(chaos_time_config_prepare() == 1);

    g_chaos_time_last_check_ns = chaos_clock_now_ns() - g_chaos_time_check_interval_ns;
    assert(chaos_time_config_prepare() == 0);
    g_chaos_time_check_interval_ns = 0U;
}

/**
 * @brief Proves the qualifiers `@first`, `@from`, `@until`, `@size>` and `@size<` after a rule
 *   land in its policy, and that a bad qualifier rejects the line.
 *
 * @details A parsed rule starts with `call_size` = `CHAOS_POLICY_NO_SIZE`. Rejected: an
 * unknown qualifier (reported with the full line), qualifiers on a line without a rule
 * (line 2), `@until` not after `@from`, and `@first=0`.
 */
static void test_rule_qualifiers(void)
{
    static chaos_time_rule_t rules[CHAOS_TIME_MAX_RULES];
    char qualified[] =
        "nanosleep:ERRNO:EINTR @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "nanosleep:ERRNO:EINTR @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "nanosleep:ERRNO:EINTR @from=2000 @until=1000\n";
    char empty_first[] = "nanosleep:ERRNO:EINTR @first=0\n";
    size_t count = 0U;

    assert(chaos_time_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_time_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_time_config_last_error()->text, "nanosleep:ERRNO:EINTR @bogus=1") == 0);
    assert(chaos_time_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_time_config_last_error()->line == 2U);
    assert(chaos_time_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_time_config_parse_buffer(empty_first, rules, &count) == -1);
}

/**
 * @brief Proves REGRESS requires a `clock_gettime/<clock>` selector and a positive jump in
 *   ms, and accepts a probability.
 *
 * @details A bare `clock_gettime` selector is rejected: the jump state is per rule, so a rule
 * across all clocks would arm on one clock and jump on another. Zero, negative and sleep
 * selectors are rejected.
 */
static void test_regress_rule(void)
{
    chaos_time_rule_t rule;
    char ok[] = "clock_gettime/monotonic:REGRESS:5000";
    char gated[] = "clock_gettime/realtime:REGRESS:250@0.5";
    char every_clock[] = "clock_gettime:REGRESS:250";
    char zero[] = "clock_gettime/monotonic:REGRESS:0";
    char negative[] = "clock_gettime/monotonic:REGRESS:-5";
    char sleep_rule[] = "nanosleep:REGRESS:5000";

    assert(chaos_time_config_parse_line(ok, &rule) == 1);
    assert(rule.effect == CHAOS_TIME_EFFECT_REGRESS && rule.offset_ms == 5000);
    assert(chaos_time_config_parse_line(gated, &rule) == 1);
    assert(rule.probability == 0.5);
    assert(chaos_time_config_parse_line(every_clock, &rule) == -1);
    assert(chaos_time_config_parse_line(zero, &rule) == -1);
    assert(chaos_time_config_parse_line(negative, &rule) == -1);
    assert(chaos_time_config_parse_line(sleep_rule, &rule) == -1);
}

/**
 * @brief Proves a same-size rewrite in place within one mtime tick is still loaded, and that
 *   re-reading an unchanged provisional file keeps its snapshot.
 *
 * @details A file loaded within the racy window of its mtime is provisional: a later write
 * could keep mtime, size, inode and device identical, so the stamp alone cannot prove the
 * file unchanged. Each prepare therefore re-reads it and compares a content hash. Sequence:
 * - Load right after writing: provisional, `rules=1`.
 * - Re-read with identical bytes: same content hash, snapshot kept, so counts and claims
 *   survive.
 * - Same bytes with the first commented out and the mtime restored: loaded, `rules=0`.
 * - mtime moved to 60 s after the epoch, outside the window: the load is final.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "nanosleep:ERRNO:EINTR\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_time_check_interval_ns;

    g_chaos_time_check_interval_ns = 0U;
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    chaos_time_config_init();
    file = fopen(CHAOS_TIME_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_TIME_CONFIG_PATH, &first) == 0);
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    /* Provisional re-read with identical bytes: the snapshot stays. */
    assert(chaos_time_config_prepare());
    assert(g_chaos_time_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* Same size, first byte now '#', written in place, mtime restored: identical stamp. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_TIME_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the racy window: the load is final and is not re-read. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_TIME_CONFIG_PATH, times, 0) == 0);
    assert(chaos_time_config_prepare() == 0);
    assert(g_chaos_time_config_provisional == 0);

    (void)unlink(CHAOS_TIME_CONFIG_PATH);
    g_chaos_time_check_interval_ns = interval;
}

/**
 * @brief Proves pending hits are written by the next look at the rule file once their
 *   100 ms interval is over, so a long-running process that stopped hitting still reports.
 *
 * @details Inside the interval the look leaves them pending.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_time_check_interval_ns;

    g_chaos_time_check_interval_ns = 0U;
    g_chaos_time_hits_pid = (uint64_t)getpid();
    g_chaos_time_hits_pending = 1;
    g_chaos_time_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_hits_pending == 1);
    g_chaos_time_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_time_config_prepare();
    assert(g_chaos_time_hits_pending == 0);
    g_chaos_time_check_interval_ns = interval;
}

/**
 * @brief Proves the value parsers accept a value exactly at their limit and reject the first
 *   value beyond it, trailing garbage and non-positive errno numbers, leaving the output
 *   unchanged on failure.
 *
 * @details Limits:
 * - errno numbers: 1 to 2147483647 (INT_MAX); 0, -5, 2147483648 and "12x" are rejected.
 * - latency: up to 4294967295 ms (UINT_MAX); 4294967296 and "12x" are rejected.
 * - A 4-byte value buffer takes 3 characters plus NUL; 4 characters are rejected, alone
 *   or before `@`.
 *
 * Also: a clock id or offset with trailing garbage, an empty effect or value field, a bad
 * latency and a REGRESS probability above 1 reject the input. `split_rule_fields` needs every
 * output pointer. Selector matching gives the same result without a rank output, and
 * `match` without an output rule finds nothing.
 */
static void test_parse_boundaries(void)
{
    char payload[4];
    /* The parsers trim trailing text in place, so these inputs must be writable arrays. */
    char errno_garbage[] = "12x";
    char latency_garbage[] = "12x";
    char clock_garbage[] = "7x";
    char offset_garbage[] = "5x";
    char empty_effect_line[] = "nanosleep::EINTR";
    char empty_value_line[] = "nanosleep:ERRNO: ";
    char bad_latency_line[] = "nanosleep:LATENCY:soon";
    char bad_regress_line[] = "clock_gettime/monotonic:REGRESS:5000@2";
    char split_line[] = "nanosleep:ERRNO:EINTR";
    char *selector_text = NULL;
    char *effect_text = NULL;
    unsigned int latency = 0U;
    int64_t offset = 0;
    clockid_t clock_id = CLOCK_REALTIME;
    double probability = 0.0;
    chaos_time_selector_t selector;
    chaos_time_rule_t rule;

    assert(chaos_time_parse_errno_name("2147483647") == 2147483647);
    assert(chaos_time_parse_errno_name("0") == -1);
    assert(chaos_time_parse_errno_name("-5") == -1);
    assert(chaos_time_parse_errno_name("2147483648") == -1);
    assert(chaos_time_parse_errno_name(errno_garbage) == -1);

    assert(chaos_time_parse_latency("4294967295", &latency) == 0);
    assert(latency == 4294967295U);
    assert(chaos_time_parse_latency("4294967296", &latency) != 0);
    assert(chaos_time_parse_latency(latency_garbage, &latency) != 0);
    assert(latency == 4294967295U);

    assert(!chaos_time_parse_clock_id(clock_garbage, &clock_id));
    assert(clock_id == CLOCK_REALTIME);
    assert(chaos_time_parse_offset(offset_garbage, &offset) != 0);
    assert(offset == 0);

    assert(chaos_time_copy_text_value("abcd", payload, sizeof(payload)) != 0);
    assert(chaos_time_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(strcmp(payload, "abc") == 0);
    assert(
        chaos_time_parse_payload_probability("abcd@0.5", payload, sizeof(payload), &probability) !=
        0
    );
    assert(
        chaos_time_parse_payload_probability("abc@0.5", payload, sizeof(payload), &probability) == 0
    );
    assert(strcmp(payload, "abc") == 0);
    assert(probability == 0.5);
    assert(chaos_time_parse_payload_probability("abc", NULL, sizeof(payload), &probability) != 0);
    assert(chaos_time_parse_payload_probability("abc", payload, sizeof(payload), NULL) != 0);

    assert(chaos_time_config_parse_line(empty_effect_line, &rule) < 0);
    assert(chaos_time_config_parse_line(empty_value_line, &rule) < 0);
    assert(chaos_time_config_parse_line(bad_latency_line, &rule) < 0);
    assert(chaos_time_config_parse_line(bad_regress_line, &rule) < 0);
    assert(!chaos_time_split_rule_fields(split_line, &selector_text, &effect_text, NULL));
    assert(!chaos_time_split_rule_fields(split_line, &selector_text, NULL, NULL));

    assert(chaos_time_selector_parse("*", &selector));
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_USLEEP, CLOCK_REALTIME, NULL));
    assert(chaos_time_selector_parse("nanosleep", &selector));
    assert(chaos_time_selector_matches(&selector, CHAOS_TIME_OP_NANOSLEEP, CLOCK_REALTIME, NULL));
    assert(chaos_time_selector_parse("clock_gettime/monotonic", &selector));
    assert(
        chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_MONOTONIC, NULL)
    );
    assert(
        !chaos_time_selector_matches(&selector, CHAOS_TIME_OP_CLOCK_GETTIME, CLOCK_REALTIME, NULL)
    );

    assert(!chaos_time_config_match(
        CHAOS_TIME_EFFECT_ERRNO, CHAOS_TIME_OP_NANOSLEEP, CLOCK_REALTIME, NULL
    ));
}

/**
 * @brief Proves the open-error classification of `read_file`: EINTR is retried, EACCES and
 *   EPERM return -3 (lasting until the file changes, reported "file unreadable"), and any
 *   other error such as EMFILE returns -1 (retried on the next check).
 */
static void test_open_errors(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# open errors\n", 43);
    stamp = chaos_time_config_observed_mtime();
    g_test_config_open_eintr = 1;
    assert(chaos_time_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open errors\n"));

    g_test_config_open_errno = EACCES;
    assert(chaos_time_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_time_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_time_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;
    (void)unlink(CHAOS_TIME_CONFIG_PATH);
}

int main(void)
{
    /* Stat the rule file on every call so each write is seen at once; the throttle has its
     * own test. */
    g_chaos_time_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_regress_rule();
    test_read_file_rejects_changed_file();
    test_helper_functions();
    test_selector_matching();
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
