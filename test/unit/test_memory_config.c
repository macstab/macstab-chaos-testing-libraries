/**
 * @file test_memory_config.c
 * @brief Proves libchaos-memory rule parsing, selector ranking, reload, status file and hits
 *        file reporting.
 *
 * @details
 * Unit under test: `src/memory/chaos_memory_config.c`, compiled into this binary by `#include`.
 *
 * Seams:
 * - `CHAOS_CONFIG_FILE_OPEN/READ/CLOSE` are redefined from raw system calls to `open`, `read` and
 *   `close`, which are in turn redefined to local stubs for the included unit only. The stubs
 *   pass through to the real calls unless told to fail the open (EINTR once, ENOENT, or any
 *   errno), fail the read (EINTR once, or EIO on the fake fd 8124), so every read_file()
 *   outcome is reachable without a crafted filesystem.
 * - `chaos_memory_atomic_cas_u64` is redefined to a stub that can lose every compare-and-swap,
 *   modelling another thread winning the reload claim.
 * - `CHAOS_RACY_WINDOW_MS` is widened from 20 ms to 5000 ms, so a file the test just wrote still
 *   counts as racily clean on a slow machine.
 * - main() sets `g_chaos_memory_check_interval_ns` to 0 so every prepare() looks at the rule
 *   file; only test_rule_file_check_is_throttled() restores a throttle.
 *
 * The reload tests use the real rule file (`/tmp/.chaos-memory.conf`), status file and hits file
 * of this process. write_config_text() sets an explicit mtime on every write so each write
 * changes the change stamp regardless of filesystem timestamp granularity. Some tests back up
 * and restore a pre-existing rule file; the others remove the file when they finish.
 */

/* Route the rule file read through libc names so the stubs below can intercept it. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* A rule file counts as just written for 5 s, not 20 ms: the racily-clean tests
 * restore an earlier mtime and must find it still recent on a slow machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_memory_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

/** @brief Non-zero: every open fails with ENOENT, as for a file removed after its stat. */
static int g_test_config_force_open_fail = 0;

/** @brief Non-zero: open returns the fake fd, whose read fails with EIO and close succeeds. */
static int g_test_config_force_read_fail = 0;

/** @brief Upcoming reads that fail with EINTR, as a signal delivered mid-read makes them. */
static int g_test_config_read_eintr = 0;

/** @brief Upcoming opens that fail with EINTR, as a signal delivered mid-open makes them. */
static int g_test_config_open_eintr = 0;

/** @brief Non-zero: every open fails with this errno; checked before the other switches. */
static int g_test_config_open_errno = 0;

/** @brief Non-zero: every compare-and-swap fails, as when another thread claims the reload. */
static int g_test_config_force_cas_fail = 0;

/** @brief Fd handed out under `g_test_config_force_read_fail`; far above any fd the test opens. */
static const int g_test_config_fake_fd = 8124;

/**
 * @brief `open` seam. Failure switches apply in this order: EINTR countdown, explicit errno,
 *        ENOENT, fake fd; otherwise the real open, forwarding the mode for O_CREAT.
 */
static int chaos_memory_test_config_open(const char *path, int flags, ...)
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
 * @brief `read` seam: the EINTR countdown first, then EIO for the fake fd; else the real read.
 */
static ssize_t chaos_memory_test_config_read(int fd, void *buffer, size_t count)
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

/** @brief `close` seam: the fake fd is never really closed, so no unrelated fd 8124 is hit. */
static int chaos_memory_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/** @brief Reload-claim seam: fails under `g_test_config_force_cas_fail`, else a real CAS. */
static int
chaos_memory_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_memory_test_config_open
#define read chaos_memory_test_config_read
#define close chaos_memory_test_config_close
#define chaos_memory_atomic_cas_u64 chaos_memory_test_atomic_cas_u64
#include "../../src/memory/chaos_memory_config.c"
#undef chaos_memory_atomic_cas_u64
#undef close
#undef read
#undef open

/** @brief A file's content, or its absence, saved so a test can put it back. */
typedef struct chaos_memory_test_file_backup
{
    int existed; /**< Non-zero if the file existed when the backup was taken. */
    char *data;  /**< Heap-allocated content copy; NULL if file did not exist. */
    size_t size; /**< Byte length of `data`. */
} chaos_memory_test_file_backup_t;

/** @brief Saves @p path into @p backup; a missing file is recorded as `existed == 0`. */
static void backup_file(const char *path, chaos_memory_test_file_backup_t *backup)
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

/** @brief Puts @p path back as saved: rewritten, or removed if it did not exist. */
static void restore_file(const char *path, const chaos_memory_test_file_backup_t *backup)
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

/** @brief Frees the saved content. */
static void free_backup(chaos_memory_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Writes @p text as the rule file with atime and mtime set to @p stamp seconds.
 *
 * @details Distinct stamps make each write change the change stamp even when two writes land in
 * the same filesystem timestamp tick. Stamps near the epoch are also far outside the racy
 * window, so such a load is final, not provisional.
 */
static void write_config_text(const char *text, time_t stamp)
{
    FILE *file;
    struct timespec times[2];

    file = fopen(CHAOS_MEMORY_CONFIG_PATH, "w");
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
 * @brief Proves the parser's building blocks accept what the grammar allows and reject the rest.
 *
 * @details
 * - Trimming, comment stripping and reset_state(); reset_state(NULL) is a no-op and a
 *   0xff-filled state comes back with no rules and parse_ok 0.
 * - All 11 errno names (ENOMEM, EINVAL, EACCES, EPERM, EBADF, ENODEV, EAGAIN, EFAULT, ENOSYS,
 *   ENFILE, EMFILE) map to their values; a decimal number is accepted; NULL and "bad" give -1.
 * - Probability, latency, text copy and `payload@probability` reject NULL, empty and
 *   out-of-range input; a value without `@` keeps the whole text as payload.
 * - Every selector (`*`, `mmap`, `mmap/anon`, `mmap/file`, `mprotect`, `madvise`, `munmap`)
 *   parses; NULL and "" do not.
 * - A rule line splits on its first two colons, so `@0.5` stays in the value field.
 * - `mmap/anon` matches only flags with MAP_ANONYMOUS; `mmap/file` matches any mmap without it
 *   (MAP_SHARED here) and never another operation.
 * - The change stamp of NULL is MISSING, and normalisation moves a hash off the UNKNOWN and
 *   RELOADING sentinels by subtracting 1. Only "differs from its input" is asserted: UNKNOWN
 *   normalises to UNKNOWN - 1, which is RELOADING itself.
 */
static void test_helper_functions(void)
{
    char trim_text[] = " \t value \r\n";
    char blank_text[] = " \t\r\n";
    char comment_text[] = "abc#def";
    char payload_text[] = "25@0.25";
    char no_probability_text[] = "42";
    char split_text[] = "mmap/anon:ERRNO:ENOMEM@0.5";
    char missing_effect_text[] = "selector:value";
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_MEMORY_MAX_VALUE];
    struct stat st;
    chaos_memory_selector_t selector;
    chaos_memory_config_state_t state;

    assert(chaos_memory_is_blank_char(' '));
    assert(chaos_memory_is_blank_char('\t'));
    assert(!chaos_memory_is_blank_char('x'));

    chaos_memory_config_reset_state(NULL, 1);
    (void)memset(&state, 0xff, sizeof(state));
    chaos_memory_config_reset_state(&state, 0);
    assert(state.rule_count == 0U);
    assert(state.parse_ok == 0);

    assert(chaos_memory_trim(NULL) == NULL);
    assert(strcmp(chaos_memory_trim(trim_text), "value") == 0);
    assert(strcmp(chaos_memory_trim(blank_text), "") == 0);
    chaos_memory_strip_comment(NULL);
    chaos_memory_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);

    assert(chaos_memory_parse_errno_name(NULL) == -1);
    assert(chaos_memory_parse_errno_name("ENOMEM") == ENOMEM);
    assert(chaos_memory_parse_errno_name("EINVAL") == EINVAL);
    assert(chaos_memory_parse_errno_name("EACCES") == EACCES);
    assert(chaos_memory_parse_errno_name("EPERM") == EPERM);
    assert(chaos_memory_parse_errno_name("EBADF") == EBADF);
    assert(chaos_memory_parse_errno_name("ENODEV") == ENODEV);
    assert(chaos_memory_parse_errno_name("EAGAIN") == EAGAIN);
    assert(chaos_memory_parse_errno_name("EFAULT") == EFAULT);
    assert(chaos_memory_parse_errno_name("ENOSYS") == ENOSYS);
    assert(chaos_memory_parse_errno_name("ENFILE") == ENFILE);
    assert(chaos_memory_parse_errno_name("EMFILE") == EMFILE);
    assert(chaos_memory_parse_errno_name("42") == 42);
    assert(chaos_memory_parse_errno_name("bad") == -1);

    assert(chaos_memory_parse_probability(NULL, &(double){0.0}) != 0);
    assert(chaos_memory_parse_probability("0.5", NULL) != 0);
    assert(chaos_memory_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_memory_parse_probability("2.0", &(double){0.0}) != 0);

    assert(chaos_memory_parse_latency(NULL, &(unsigned int){0U}) != 0);
    assert(chaos_memory_parse_latency("25", NULL) != 0);
    assert(chaos_memory_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_memory_parse_latency("bad", &(unsigned int){0U}) != 0);

    assert(chaos_memory_copy_text_value(NULL, payload, sizeof(payload)) != 0);
    assert(chaos_memory_copy_text_value("abc", NULL, sizeof(payload)) != 0);
    assert(chaos_memory_copy_text_value("abc", payload, 0U) != 0);
    assert(chaos_memory_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_memory_copy_text_value("", payload, sizeof(payload)) != 0);

    assert(
        chaos_memory_parse_payload_probability(NULL, payload, sizeof(payload), &(double){0.0}) != 0
    );
    assert(
        chaos_memory_parse_payload_probability(
            no_probability_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "42") == 0);
    assert(
        chaos_memory_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "25") == 0);
    assert(
        chaos_memory_parse_payload_probability("@0.25", payload, sizeof(payload), &(double){0.0}) !=
        0
    );
    assert(
        chaos_memory_parse_payload_probability(
            "25@2.0", payload, sizeof(payload), &(double){0.0}
        ) != 0
    );

    assert(!chaos_memory_selector_parse(NULL, &selector));
    assert(!chaos_memory_selector_parse("", &selector));
    assert(chaos_memory_selector_parse("munmap", &selector));
    assert(chaos_memory_selector_parse("*", &selector));
    assert(chaos_memory_selector_parse("mmap", &selector));
    assert(chaos_memory_selector_parse("mmap/anon", &selector));
    assert(chaos_memory_selector_parse("mmap/file", &selector));
    assert(chaos_memory_selector_parse("mprotect", &selector));
    assert(chaos_memory_selector_parse("madvise", &selector));
    assert(chaos_memory_selector_parse("munmap", &selector));

    assert(chaos_memory_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "mmap/anon") == 0);
    assert(strcmp(effect_text, "ERRNO") == 0);
    assert(strcmp(value_text, "ENOMEM@0.5") == 0);
    assert(!chaos_memory_split_rule_fields(NULL, &selector_text, &effect_text, &value_text));
    assert(!chaos_memory_split_rule_fields(split_text, NULL, &effect_text, &value_text));
    assert(!chaos_memory_split_rule_fields("bad", &selector_text, &effect_text, &value_text));
    assert(!chaos_memory_split_rule_fields(
        missing_effect_text, &selector_text, &effect_text, &value_text
    ));

    assert(!chaos_memory_selector_matches(
        NULL, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &((unsigned int){0U})
    ));
    assert(chaos_memory_selector_parse("*", &selector));
    assert(
        chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MPROTECT, 0, &((unsigned int){0U}))
    );
    assert(chaos_memory_selector_parse("mmap", &selector));
    assert(chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &((unsigned int){0U})
    ));
    assert(chaos_memory_selector_parse("mmap/anon", &selector));
    assert(chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &((unsigned int){0U})
    ));
    assert(!chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MMAP, MAP_SHARED, &((unsigned int){0U})
    ));
    assert(chaos_memory_selector_parse("mmap/file", &selector));
    assert(chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MMAP, MAP_SHARED, &((unsigned int){0U})
    ));
    assert(!chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MPROTECT, 0, &((unsigned int){0U})
    ));
    assert(chaos_memory_selector_parse("munmap", &selector));
    assert(
        chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MUNMAP, 0, &((unsigned int){0U}))
    );
    assert(
        !chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MADVISE, 0, &((unsigned int){0U}))
    );

    (void)memset(&st, 0, sizeof(st));
    assert(chaos_memory_config_hash_mtime(NULL) == CHAOS_MEMORY_MTIME_MISSING);
    assert(
        chaos_memory_config_normalize_mtime_hash(CHAOS_MEMORY_MTIME_UNKNOWN) !=
        CHAOS_MEMORY_MTIME_UNKNOWN
    );
    assert(
        chaos_memory_config_normalize_mtime_hash(CHAOS_MEMORY_MTIME_RELOADING) !=
        CHAOS_MEMORY_MTIME_RELOADING
    );
    assert(chaos_memory_config_hash_mtime(&st) != 0U);
}

/**
 * @brief Proves line parsing fills every rule field and buffer parsing is all-or-nothing.
 *
 * @details parse_line() returns 0 for a comment, 1 with selector, effect, errnum or latency and
 * probability filled for a rule, and a negative value for a missing field, an empty or unknown
 * selector, an unknown effect, an unknown or empty errno, a non-numeric latency and a
 * probability above 1. parse_buffer() counts rules across lines (the last line needs no
 * newline), skips blank and comment lines, and fails the whole buffer on one bad line, so a
 * typo can never load half a rule file. NULL arguments are rejected, not dereferenced.
 */
static void test_parse_line_and_buffer(void)
{
    chaos_memory_rule_t rule;
    chaos_memory_rule_t rules[8];
    size_t rule_count = 0U;
    char comment_line[] = " #: ignored";
    char buffer[] = "*:ERRNO:ENOMEM@0.5\n"
                    "mmap/anon:LATENCY:25\n"
                    "mprotect:ERRNO:EACCES\n"
                    "madvise:LATENCY:5\n"
                    "munmap:ERRNO:EINVAL\n";

    assert(chaos_memory_config_parse_line(comment_line, &rule) == 0);

    {
        char line[] = "*:ERRNO:ENOMEM@0.5";
        assert(chaos_memory_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_MEMORY_SELECTOR_ANY);
        assert(rule.effect == CHAOS_MEMORY_EFFECT_ERRNO);
        assert(rule.errnum == ENOMEM);
        assert(rule.probability == 0.5);
    }
    {
        char line[] = "mmap/file:LATENCY:25";
        assert(chaos_memory_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_MEMORY_SELECTOR_MMAP_KIND);
        assert(rule.selector.mmap_kind == CHAOS_MEMORY_MMAP_KIND_FILE);
        assert(rule.effect == CHAOS_MEMORY_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
    }
    {
        char invalid_line[] = "bad";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = ":ERRNO:ENOMEM";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "bogus:ERRNO:ENOMEM";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char line[] = "munmap:ERRNO:ENOMEM";
        assert(chaos_memory_config_parse_line(line, &rule) == 1);
        assert(rule.selector.kind == CHAOS_MEMORY_SELECTOR_OPERATION);
        assert(rule.selector.operation == CHAOS_MEMORY_OP_MUNMAP);
        assert(rule.effect == CHAOS_MEMORY_EFFECT_ERRNO);
        assert(rule.errnum == ENOMEM);
    }
    {
        char invalid_line[] = "mmap:BOGUS:1";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "mmap:ERRNO:nope";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "mmap:ERRNO:@0.5";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "mmap:LATENCY:bad";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "mmap:LATENCY:25@2.0";
        assert(chaos_memory_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_memory_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 5U);

    {
        char buffer_no_newline[] = "mprotect:ERRNO:EACCES";
        rule_count = 0U;
        assert(chaos_memory_config_parse_buffer(buffer_no_newline, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }
    {
        char invalid_buffer[] = "mprotect:ERRNO:EACCES\nbad";
        assert(chaos_memory_config_parse_buffer(invalid_buffer, rules, &rule_count) < 0);
    }
    {
        char comment_buffer[] = "\n# ignored\nmadvise:LATENCY:5\n";
        rule_count = 0U;
        assert(chaos_memory_config_parse_buffer(comment_buffer, rules, &rule_count) == 0);
        assert(rule_count == 1U);
    }

    assert(chaos_memory_config_parse_line(NULL, &rule) < 0);
    assert(chaos_memory_config_parse_line(comment_line, NULL) < 0);
    assert(chaos_memory_config_parse_buffer(NULL, rules, &rule_count) < 0);
    assert(chaos_memory_config_parse_buffer(buffer, NULL, &rule_count) < 0);
    assert(chaos_memory_config_parse_buffer(buffer, rules, NULL) < 0);
}

/**
 * @brief Proves the most specific selector wins, independent of the order rules are listed in.
 *
 * @details Rank is `*` (1) < operation (2) < `mmap/anon` or `mmap/file` (3); within a rank the
 * longer selector text wins; at equal rank and length the earlier rule wins. Each distinct
 * errnum identifies which rule was chosen. The tie cases force `selector_len` to 8 and 9 on two
 * otherwise identical `mprotect` rules, because no two real selectors of one operation share a
 * rank with different lengths.
 */
static void test_rule_selection(void)
{
    chaos_memory_rule_t rules[6];
    chaos_memory_rule_t tie_rules[2];
    chaos_memory_rule_t rule;
    char tie_line[] = "mprotect:ERRNO:EINVAL";
    char any_line[] = "*:ERRNO:ENOMEM";
    char late_any_line[] = "*:ERRNO:ENOMEM";
    char mmap_line[] = "mmap:ERRNO:EINVAL";
    char anon_line[] = "mmap/anon:ERRNO:EAGAIN";
    char file_line[] = "mmap/file:ERRNO:EACCES";
    char madvise_line[] = "madvise:LATENCY:20";
    char munmap_line[] = "munmap:ERRNO:EINVAL";

    assert(chaos_memory_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_memory_config_parse_line(mmap_line, &rules[1]) == 1);
    assert(chaos_memory_config_parse_line(anon_line, &rules[2]) == 1);
    assert(chaos_memory_config_parse_line(file_line, &rules[3]) == 1);
    assert(chaos_memory_config_parse_line(madvise_line, &rules[4]) == 1);
    assert(chaos_memory_config_parse_line(munmap_line, &rules[5]) == 1);

    assert(chaos_memory_config_select_rule(
        rules,
        6U,
        CHAOS_MEMORY_EFFECT_ERRNO,
        CHAOS_MEMORY_OP_MMAP,
        MAP_PRIVATE | MAP_ANONYMOUS,
        &rule
    ));
    assert(rule.errnum == EAGAIN);

    assert(chaos_memory_config_select_rule(
        rules, 6U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_SHARED, &rule
    ));
    assert(rule.errnum == EACCES);

    assert(chaos_memory_config_select_rule(
        rules, 6U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &rule
    ));
    assert(rule.errnum == ENOMEM);

    assert(chaos_memory_config_select_rule(
        rules, 6U, CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, &rule
    ));
    assert(rule.latency_ms == 20U);

    assert(chaos_memory_config_select_rule(
        rules, 6U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MUNMAP, 0, &rule
    ));
    assert(rule.errnum == EINVAL);

    assert(!chaos_memory_config_select_rule(
        NULL, 6U, CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, &rule
    ));
    assert(!chaos_memory_config_select_rule(
        rules, 6U, CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MADVISE, 0, NULL
    ));

    (void)memset(tie_rules, 0, sizeof(tie_rules));
    assert(chaos_memory_config_parse_line(tie_line, &tie_rules[0]) == 1);
    tie_rules[0].selector.selector_len = 8U;
    tie_rules[0].errnum = EINVAL;
    tie_rules[1] = tie_rules[0];
    tie_rules[1].selector.selector_len = 9U;
    tie_rules[1].errnum = EPERM;
    assert(chaos_memory_config_select_rule(
        tie_rules, 2U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &rule
    ));
    assert(rule.errnum == EPERM);

    /* Listed the other way round, the shorter selector of the same rank does not
     * replace the longer one... */
    tie_rules[1] = tie_rules[0];
    tie_rules[0].selector.selector_len = 9U;
    tie_rules[0].errnum = EPERM;
    assert(chaos_memory_config_select_rule(
        tie_rules, 2U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &rule
    ));
    assert(rule.errnum == EPERM);

    /* ...nor does a less specific selector listed after a more specific one. */
    assert(chaos_memory_config_parse_line(late_any_line, &tie_rules[1]) == 1);
    assert(chaos_memory_config_select_rule(
        tie_rules, 2U, CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MPROTECT, 0, &rule
    ));
    assert(rule.errnum == EPERM);
}

/**
 * @brief Proves reload follows the rule file through creation, edits, a bad rule and I/O faults.
 *
 * @details
 * - No rule file: prepare() and match() report no rules; match() with a NULL out-rule is 0.
 * - Each rewrite with a new mtime (11, 12, 13) replaces the rule set on the next match(),
 *   which calls prepare() itself; the replaced rule no longer matches. An unchanged file
 *   keeps its snapshot.
 * - A bad rule (14) loads an invalid snapshot: no rule matches, even from match_loaded().
 * - read_file() refuses a file that fills its 262144-byte buffer (it may be longer) and a NULL
 *   size pointer.
 * - With the active snapshot empty after the bad rule, prepare() stays 0 when the open fails
 *   (16), the read fails (17) or the reload claim is lost (18): none of these may publish the
 *   new file's rule.
 */
static void test_prepare_and_match(void)
{
    chaos_memory_test_file_backup_t backup;
    chaos_memory_rule_t rule;

    backup_file(CHAOS_MEMORY_CONFIG_PATH, &backup);

    g_test_config_force_open_fail = 0;
    g_test_config_force_read_fail = 0;
    g_test_config_force_cas_fail = 0;
    chaos_memory_config_init();
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    assert(!chaos_memory_config_prepare());
    assert(!chaos_memory_config_match(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &rule
    ));
    assert(!chaos_memory_config_match(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, NULL
    ));

    write_config_text("mmap/anon:ERRNO:ENOMEM\n", 11);
    assert(chaos_memory_config_prepare());
    assert(chaos_memory_config_match(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &rule
    ));
    assert(rule.errnum == ENOMEM);
    assert(chaos_memory_config_match_loaded(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &rule
    ));
    assert(chaos_memory_config_prepare());

    write_config_text("mprotect:LATENCY:25\n", 12);
    assert(
        chaos_memory_config_match(CHAOS_MEMORY_EFFECT_LATENCY, CHAOS_MEMORY_OP_MPROTECT, 0, &rule)
    );
    assert(rule.latency_ms == 25U);
    assert(!chaos_memory_config_match(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &rule
    ));

    write_config_text("munmap:ERRNO:EINVAL\n", 13);
    assert(chaos_memory_config_match(CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MUNMAP, 0, &rule));
    assert(rule.errnum == EINVAL);

    write_config_text("bad-rule\n", 14);
    assert(!chaos_memory_config_prepare());
    assert(!chaos_memory_config_match_loaded(
        CHAOS_MEMORY_EFFECT_ERRNO, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, &rule
    ));

    {
        char large_config[CHAOS_MEMORY_MAX_CONFIG_BYTES + 1U];
        size_t size = 0U;

        (void)memset(large_config, 'a', sizeof(large_config) - 1U);
        large_config[sizeof(large_config) - 1U] = '\0';
        write_config_text(large_config, 15);
        assert(chaos_memory_config_read_file(&size, chaos_memory_config_observed_mtime()) < 0);
    }
    assert(chaos_memory_config_read_file(NULL, chaos_memory_config_observed_mtime()) < 0);

    write_config_text("madvise:LATENCY:10\n", 16);
    g_test_config_force_open_fail = 1;
    assert(!chaos_memory_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("madvise:LATENCY:20\n", 17);
    assert(!chaos_memory_config_prepare());
    g_test_config_force_read_fail = 0;

    g_test_config_force_cas_fail = 1;
    write_config_text("madvise:LATENCY:30\n", 18);
    assert(!chaos_memory_config_prepare());
    g_test_config_force_cas_fail = 0;

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves one rule beyond `CHAOS_MEMORY_MAX_RULES` (256) rejects the buffer instead of
 *        dropping the excess silently.
 */
static void test_parse_buffer_limit(void)
{
    chaos_memory_rule_t rules[CHAOS_MEMORY_MAX_RULES + 1U];
    size_t rule_count = 0U;
    size_t capacity = (CHAOS_MEMORY_MAX_RULES + 1U) * sizeof("madvise:LATENCY:1\n");
    char *buffer = (char *)malloc(capacity);
    size_t offset = 0U;
    size_t index;

    assert(buffer != NULL);
    for (index = 0U; index <= CHAOS_MEMORY_MAX_RULES; ++index)
    {
        offset += (size_t)snprintf(buffer + offset, capacity - offset, "madvise:LATENCY:1\n");
    }

    assert(chaos_memory_config_parse_buffer(buffer, rules, &rule_count) < 0);
    free(buffer);
}

/**
 * @brief Proves a caller that finds a reload claimed serves the current snapshot and does not
 *        join the reload.
 *
 * @details The cached stamp is set to RELOADING, as another thread's claim leaves it. A CAS
 * from RELOADING to RELOADING would succeed, so without the explicit check this caller would
 * reload into the same inactive snapshot and shared read buffer as the owner. The claim and
 * the active index must both be unchanged afterwards.
 */
static void test_reload_in_progress_is_not_joined(void)
{
    unsigned int active_index;

    chaos_memory_config_init();
    active_index = g_chaos_memory_active_config_index;
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    assert(chaos_memory_config_observed_mtime() != CHAOS_MEMORY_MTIME_RELOADING);

    (void)chaos_memory_config_prepare();

    assert(g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_RELOADING);
    assert(g_chaos_memory_active_config_index == active_index);

    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;
}

/**
 * @brief Proves a failed read keeps the active rules and is retried on the next call.
 *
 * @details A transient read error says nothing about the new rules. The reload releases its
 * claim with the previous stamp (neither the new stamp nor RELOADING), so the next prepare()
 * sees a change and loads the two-rule file instead of waiting for another edit.
 */
static void test_read_failure_keeps_rules_and_retries(void)
{
    chaos_memory_test_file_backup_t backup;

    backup_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    chaos_memory_config_init();

    write_config_text("mmap/anon:ERRNO:ENOMEM\n", 40);
    assert(chaos_memory_config_prepare());
    assert(chaos_memory_config_active_state()->rule_count == 1U);

    write_config_text("mmap/anon:ERRNO:ENOMEM\nmunmap:ERRNO:EINVAL\n", 41);
    g_test_config_force_read_fail = 1;
    assert(chaos_memory_config_prepare());
    assert(chaos_memory_config_active_state()->rule_count == 1U);
    assert(g_chaos_memory_cached_mtime != chaos_memory_config_observed_mtime());
    assert(g_chaos_memory_cached_mtime != CHAOS_MEMORY_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_memory_config_prepare());
    assert(chaos_memory_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves the change stamp covers size and inode, not only mtime.
 *
 * @details An append within one timestamp tick changes only the size; an atomic rename
 * replacement can keep the mtime but changes the inode. Either must trigger a reload.
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
    assert(chaos_memory_config_hash_mtime(&base) == chaos_memory_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_memory_config_hash_mtime(&base) != chaos_memory_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_memory_config_hash_mtime(&base) != chaos_memory_config_hash_mtime(&other));
}

/**
 * @brief Proves a reload claim is released only by the fork() child handler, never taken over
 *        by prepare().
 *
 * @details
 * - prepare() leaves a RELOADING claim in place whoever made it: in a vfork child the parent's
 *   reloading thread is still running in the shared memory.
 * - chaos_memory_config_after_fork() turns the claim back into UNKNOWN, zeroes the PRNG state so
 *   the child does not repeat the parent's draws, and adopts the child's pid for hits; the next
 *   prepare() then loads the file. With no claim held, the handler leaves the stamp alone.
 * - While a claim is held, prepare() returns the current snapshot (1 rule) before reaching the
 *   compare-and-swap, so a forced CAS failure does not change the result.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_memory_test_file_backup_t backup;

    backup_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    chaos_memory_config_init();
    write_config_text("mmap/anon:ERRNO:ENOMEM\n", 60);

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    (void)chaos_memory_config_prepare();
    assert(g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_RELOADING);
    g_chaos_memory_tls_prng_state = UINT64_C(42);
    chaos_memory_config_after_fork();
    assert(g_chaos_memory_tls_prng_state == 0U);
    assert(g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_UNKNOWN);
    assert(g_chaos_memory_hits_pid == (uint64_t)getpid());
    assert(chaos_memory_config_prepare());
    assert(g_chaos_memory_cached_mtime == chaos_memory_config_observed_mtime());
    chaos_memory_config_after_fork();
    assert(g_chaos_memory_cached_mtime == chaos_memory_config_observed_mtime());

    /* With a claim held the CAS is never reached: the current snapshot is served. */
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_memory_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* Another thread of this process holding the claim: left alone as well. */
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    (void)chaos_memory_config_prepare();
    assert(g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_RELOADING);
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves prepare() preserves the caller's errno across a failed stat and a full load.
 *
 * @details prepare() runs inside wrappers whose real call may succeed; a leaked ENOENT from the
 * missing rule file would then be reported by the application as its own error. EBADF is a
 * sentinel neither path produces.
 */
static void test_prepare_preserves_errno(void)
{
    chaos_memory_test_file_backup_t backup;

    backup_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    chaos_memory_config_init();
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_memory_config_prepare();
    assert(errno == EBADF);

    write_config_text("mmap/anon:ERRNO:ENOMEM\n", 70);
    errno = EBADF;
    assert(chaos_memory_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves a read interrupted by a signal is retried in place and the load completes.
 */
static void test_interrupted_read_is_retried(void)
{
    chaos_memory_test_file_backup_t backup;

    backup_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    chaos_memory_config_init();
    write_config_text("mmap/anon:ERRNO:ENOMEM\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_memory_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_memory_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves read_file() discards content whose fstat stamp differs from the expected one.
 *
 * @details A writer that changed the file between the stat that started the reload and the
 * read can leave a half-old, half-new copy. Passing the current stamp with one bit flipped
 * models that; read_file() returns -1 so the caller keeps the old rules and retries.
 */
static void test_read_file_rejects_changed_file(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# stable\n", 41);
    stamp = chaos_memory_config_observed_mtime();
    assert(chaos_memory_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_memory_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
}

/** @brief Reads the status file into @p buffer; returns 0 when it does not exist. */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_MEMORY_STATUS_PATH, "r");
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
 * @brief Proves a rejected line is reported by number, verbatim text and reason.
 *
 * @details
 * - Line 4 of a buffer with a header, a blank line and a valid rule is reported as
 *   "invalid rule" with its text before the parser cut the `# typo` comment off.
 * - Exactly 256 rules followed by a comment parse cleanly: comments do not count against the
 *   limit, and success clears the recorded error.
 * - A 257th rule is reported as "too many rules" on line 257, and the rule count is reset to 0
 *   so no caller uses the partial set.
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_memory_rule_t rules[CHAOS_MEMORY_MAX_RULES];
    char buffer[] = "# header\n\nmprotect:LATENCY:25\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_memory_config_last_error();
    const size_t line_length = strlen("mprotect:LATENCY:25\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_memory_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_MEMORY_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_MEMORY_MAX_RULES; ++index)
    {
        (void)strcat(many, "mprotect:LATENCY:25\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_memory_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_MEMORY_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_MEMORY_MAX_RULES; ++index)
    {
        (void)strcat(many, "mprotect:LATENCY:25\n");
    }
    assert(chaos_memory_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_MEMORY_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "mprotect:LATENCY:25") == 0);
    free(many);
}

/**
 * @brief Proves every load writes its outcome to the status file in the exact documented format.
 *
 * @details In order: a rejected line (state=error, line 2, its text); a valid file (state=ok,
 * rules=1); a file of exactly 262144 bytes ("file too large"); a NUL byte ("file contains a NUL
 * byte"); a directory, EISDIR on read ("file unreadable"); and, unless running as root, which
 * bypasses mode 0, a file without read permission, EACCES on open (same reason). Every record
 * carries this pid. With no rule file the status file is removed rather than left stale.
 */
static void test_prepare_reports_status(void)
{
    char status[CHAOS_STATUS_BUFFER_SIZE];
    char expected[CHAOS_STATUS_BUFFER_SIZE];

    chaos_memory_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_memory_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("mprotect:LATENCY:25\n", 52);
    assert(chaos_memory_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* At the size limit the file may be longer than the buffer: rejected, not truncated. */
    {
        FILE *large = fopen(CHAOS_MEMORY_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_MEMORY_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_memory_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_MEMORY_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_memory_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_MEMORY_CONFIG_PATH, 0700) == 0);
    assert(chaos_memory_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_MEMORY_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_MEMORY_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_MEMORY_CONFIG_PATH, 0) == 0);
        assert(chaos_memory_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    }
    assert(chaos_memory_config_prepare() == 0);
    assert(!read_status_file(status, sizeof(status)));
}

/** @brief Reads this process's hits file into @p buffer; returns 0 when it does not exist. */
static int read_hits_file(char *buffer, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_MEMORY_HITS_PREFIX, g_chaos_memory_hits_file);
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
 * @brief Proves hit counting and the hits file's write schedule, across reload and fork.
 *
 * @details
 * - Each rule's slot counts its hits; the hits file lists `<count>TAB<rule text>` per rule,
 *   comment included. A reload that keeps a rule's text keeps its count.
 * - A hit that finds the writer flag held leaves `pending` set instead of blocking or writing.
 * - After the first `CHAOS_HITS_EAGER` (64) hits, a hit within `CHAOS_HITS_INTERVAL_MS` (100 ms)
 *   of the last write is only counted; the exit report writes it, and a second exit report has
 *   nothing to write. A hit after the interval writes at once.
 * - The fork() child handler releases the writer flag, zeroes counts, turns a REGRESS decision
 *   in progress (state 3) back into armed (state 1) and keeps a completed one (state 2).
 * - A process whose pid is not the recorded owner of the counts, as in a vfork child, writes
 *   nothing at exit.
 */
static void test_hits_are_counted_and_reported(void)
{
    char hits[1024];
    char path[64];
    chaos_memory_config_state_t *state;

    chaos_memory_config_init();
    write_config_text("mprotect:LATENCY:25 # a\n", 61);
    assert(chaos_memory_config_prepare() == 1);
    state = (chaos_memory_config_state_t *)chaos_memory_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "mprotect:LATENCY:25 # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n") == 0);

    write_config_text("mprotect:LATENCY:25 # a\nmprotect:LATENCY:25 # b\n", 62);
    assert(chaos_memory_config_prepare() == 1);
    state = (chaos_memory_config_state_t *)chaos_memory_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n1\tmprotect:LATENCY:25 # b\n") == 0);

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_memory_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_memory_hits_writing = 0;
    assert(g_chaos_memory_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n1\tmprotect:LATENCY:25 # b\n") == 0);

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_memory_hits_total = CHAOS_HITS_EAGER;
    g_chaos_memory_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n1\tmprotect:LATENCY:25 # b\n") == 0);

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_memory_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n3\tmprotect:LATENCY:25 # b\n") == 0);
    assert(g_chaos_memory_hits_pending == 0);
    chaos_memory_config_report_hits(NULL);

    /* Past the eager hits, a hit once the interval is over is written at once. */
    g_chaos_memory_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tmprotect:LATENCY:25 # a\n4\tmprotect:LATENCY:25 # b\n") == 0);
    assert(g_chaos_memory_hits_pending == 0);
    g_chaos_memory_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_memory_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_memory_config_after_fork();
    assert(g_chaos_memory_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "1\tmprotect:LATENCY:25 # a\n0\tmprotect:LATENCY:25 # b\n") == 0);
    g_chaos_memory_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_memory_hits_pending = 1;
    g_chaos_memory_hits_pid = (uint64_t)getpid() + 1U;
    chaos_memory_config_report_hits(NULL);
    assert(g_chaos_memory_hits_pending == 1);
    g_chaos_memory_hits_pending = 0;
    g_chaos_memory_hits_pid = (uint64_t)getpid();

    (void
    )snprintf(path, sizeof(path), "%s.%ld", CHAOS_MEMORY_HITS_PREFIX, g_chaos_memory_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
}

/**
 * @brief Proves the stat of the rule file is throttled once rules are loaded.
 *
 * @details The stat is the largest part of a wrapper's cost, so production looks at most every
 * `CHAOS_CHECK_INTERVAL_NS` (1 ms). The test widens the interval to 10 s so the first call is
 * certain to fall inside it: the removed file goes unnoticed. Moving the last look one interval
 * back makes the next call look and find no rules.
 */
static void test_rule_file_check_is_throttled(void)
{
    chaos_memory_config_init();
    write_config_text("mprotect:LATENCY:25\n", 81);
    assert(chaos_memory_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_memory_check_interval_ns = UINT64_C(10000000000);
    g_chaos_memory_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    assert(chaos_memory_config_prepare() == 1);

    g_chaos_memory_last_check_ns = chaos_clock_now_ns() - g_chaos_memory_check_interval_ns;
    assert(chaos_memory_config_prepare() == 0);
    g_chaos_memory_check_interval_ns = 0U;
}

/**
 * @brief Proves qualifiers are parsed into the rule's policy and a bad qualifier rejects the line.
 *
 * @details `@first`, `@from`, `@until` and both `@size` bounds land in the policy, and the rule
 * starts with no call size. Rejected: an unknown qualifier (reported with the full line),
 * qualifiers on a line without a rule (reported as line 2), `@until` before `@from`, and
 * `@first=0`.
 */
static void test_rule_qualifiers(void)
{
    static chaos_memory_rule_t rules[CHAOS_MEMORY_MAX_RULES];
    char qualified[] =
        "mprotect:LATENCY:25 @first=3 @from=1000 @until=2000 @size>10 @size<99 # owner\n";
    char unknown[] = "mprotect:LATENCY:25 @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "mprotect:LATENCY:25 @from=2000 @until=1000\n";
    char empty_first[] = "mprotect:LATENCY:25 @first=0\n";
    size_t count = 0U;

    assert(chaos_memory_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_memory_config_parse_buffer(unknown, rules, &count) == -1);
    assert(strcmp(chaos_memory_config_last_error()->text, "mprotect:LATENCY:25 @bogus=1") == 0);
    assert(chaos_memory_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_memory_config_last_error()->line == 2U);
    assert(chaos_memory_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_memory_config_parse_buffer(empty_first, rules, &count) == -1);
}

/**
 * @brief Proves a same-size in-place rewrite within the racy window is still loaded.
 *
 * @details A file whose mtime is within `CHAOS_RACY_WINDOW_MS` of now may still change without
 * changing its stamp, so its load is provisional and the file is re-read on later checks. An
 * unchanged re-read (same content hash) keeps the snapshot and its counts. Rewriting the first
 * byte to `#` with the original mtime restored leaves mtime, size, inode and device identical;
 * only the provisional re-read sees rules drop to 0. Setting the mtime to 60 s after the epoch
 * makes the next load final.
 */
static void test_racy_rewrite_is_seen(void)
{
    static const char rule[] = "mprotect:LATENCY:25\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_memory_check_interval_ns;

    g_chaos_memory_check_interval_ns = 0U;
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    chaos_memory_config_init();
    file = fopen(CHAOS_MEMORY_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_MEMORY_CONFIG_PATH, &first) == 0);
    assert(chaos_memory_config_prepare());
    assert(g_chaos_memory_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    /* Read again, nothing changed: the same snapshot stays. */
    assert(chaos_memory_config_prepare());
    assert(g_chaos_memory_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* The same bytes but the first commented out, written in place, same mtime. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_MEMORY_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_memory_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window: the load is final and not read again. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_MEMORY_CONFIG_PATH, times, 0) == 0);
    assert(chaos_memory_config_prepare() == 0);
    assert(g_chaos_memory_config_provisional == 0);

    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
    g_chaos_memory_check_interval_ns = interval;
}

/**
 * @brief Proves pending hits are flushed by the next look at the rule file once their interval
 *        is over, so a process that stopped hitting still reports them before exit.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_memory_check_interval_ns;

    g_chaos_memory_check_interval_ns = 0U;
    g_chaos_memory_hits_pid = (uint64_t)getpid();
    g_chaos_memory_hits_pending = 1;
    g_chaos_memory_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_memory_config_prepare();
    assert(g_chaos_memory_hits_pending == 1);
    g_chaos_memory_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_memory_config_prepare();
    assert(g_chaos_memory_hits_pending == 0);
    g_chaos_memory_check_interval_ns = interval;
}

/**
 * @brief Proves the value parsers accept exactly their limit and reject the first value beyond.
 *
 * @details
 * - errno numbers: 2147483647 accepted; 0, -5, 2147483648 and "12x" rejected.
 * - latency (ms): 4294967295 accepted; 4294967296 and "12x" rejected, the output unchanged.
 * - A 4-byte buffer takes "abc" but not "abcd" (no room for the terminator), both as a plain
 *   value and as the payload before `@`.
 * - An empty effect or value field rejects the line; NULL outputs are rejected.
 * - selector_matches() gives the same answer with a NULL rank output.
 */
static void test_parse_boundaries(void)
{
    char payload[4];
    /* The parsers trim the text after the number in place, so it must be writable. */
    char errno_garbage[] = "12x";
    char latency_garbage[] = "12x";
    char empty_effect_line[] = "mmap::ENOMEM";
    char empty_value_line[] = "mmap:ERRNO: ";
    char split_line[] = "mmap:ERRNO:ENOMEM";
    char *selector_text = NULL;
    char *effect_text = NULL;
    unsigned int latency = 0U;
    double probability = 0.0;
    chaos_memory_selector_t selector;
    chaos_memory_rule_t rule;

    assert(chaos_memory_parse_errno_name("2147483647") == 2147483647);
    assert(chaos_memory_parse_errno_name("0") == -1);
    assert(chaos_memory_parse_errno_name("-5") == -1);
    assert(chaos_memory_parse_errno_name("2147483648") == -1);
    assert(chaos_memory_parse_errno_name(errno_garbage) == -1);

    assert(chaos_memory_parse_latency("4294967295", &latency) == 0);
    assert(latency == 4294967295U);
    assert(chaos_memory_parse_latency("4294967296", &latency) != 0);
    assert(chaos_memory_parse_latency(latency_garbage, &latency) != 0);
    assert(latency == 4294967295U);

    assert(chaos_memory_copy_text_value("abcd", payload, sizeof(payload)) != 0);
    assert(chaos_memory_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(strcmp(payload, "abc") == 0);
    assert(
        chaos_memory_parse_payload_probability(
            "abcd@0.5", payload, sizeof(payload), &probability
        ) != 0
    );
    assert(
        chaos_memory_parse_payload_probability("abc@0.5", payload, sizeof(payload), &probability) ==
        0
    );
    assert(strcmp(payload, "abc") == 0);
    assert(probability == 0.5);
    assert(chaos_memory_parse_payload_probability("abc", NULL, sizeof(payload), &probability) != 0);
    assert(chaos_memory_parse_payload_probability("abc", payload, sizeof(payload), NULL) != 0);

    assert(chaos_memory_config_parse_line(empty_effect_line, &rule) < 0);
    assert(chaos_memory_config_parse_line(empty_value_line, &rule) < 0);
    assert(!chaos_memory_split_rule_fields(split_line, &selector_text, &effect_text, NULL));
    assert(!chaos_memory_split_rule_fields(split_line, &selector_text, NULL, NULL));
    assert(!chaos_memory_selector_parse("*", NULL));

    assert(chaos_memory_selector_parse("*", &selector));
    assert(chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MUNMAP, 0, NULL));
    assert(chaos_memory_selector_parse("mprotect", &selector));
    assert(chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MPROTECT, 0, NULL));
    assert(chaos_memory_selector_parse("mmap/anon", &selector));
    assert(chaos_memory_selector_matches(
        &selector, CHAOS_MEMORY_OP_MMAP, MAP_PRIVATE | MAP_ANONYMOUS, NULL
    ));
    assert(!chaos_memory_selector_matches(&selector, CHAOS_MEMORY_OP_MMAP, MAP_SHARED, NULL));
}

/**
 * @brief Proves the open of the rule file classifies its errors.
 *
 * @details EINTR is retried and the file is read in full (0). EACCES and EPERM return -3: the
 * condition lasts until the file changes, so the reload reports "file unreadable" and stops
 * re-reading. EMFILE returns -1: retryable, so the active rules are kept and the next check
 * tries again.
 */
static void test_open_errors(void)
{
    size_t size = 0U;
    uint64_t stamp;

    write_config_text("# open errors\n", 43);
    stamp = chaos_memory_config_observed_mtime();
    g_test_config_open_eintr = 1;
    assert(chaos_memory_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open errors\n"));

    g_test_config_open_errno = EACCES;
    assert(chaos_memory_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_memory_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_memory_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_memory_check_interval_ns = 0U;
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
