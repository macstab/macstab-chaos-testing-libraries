/**
 * @file test_memory_config.c
 * @brief Unit tests for memory-domain configuration parsing, selector matching, rule
 *   selection, and hot-reload state machine.
 *
 * Subsystem under test: `src/memory/chaos_memory_config.c`
 *
 * Coverage approach:
 * - The production source file is included after four stubs are wired via `#define`:
 *   `open`, `read`, `close`, and `chaos_memory_atomic_cas_u64`. This provides deterministic
 *   control over file I/O failure modes and atomic CAS races.
 * - `g_test_config_fake_fd` (8124) is a sentinel file descriptor used exclusively by the
 *   read-failure and close stubs.
 * - `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` instantiates all required globals.
 * - Tests that require real filesystem access use the OS-level `open`/`read`/`close`
 *   available after the `#undef` block.
 * - `write_config_text(text, stamp)` writes the file and sets its mtime via `futimens` to a
 *   controlled timestamp, ensuring each successive write triggers a fresh reload.
 * - `backup_file` / `restore_file` / `free_backup` preserve the original
 *   `CHAOS_MEMORY_CONFIG_PATH` content around `test_prepare_and_match`.
 *
 * Properties under test:
 * - Primitive helpers: `chaos_memory_is_blank_char`, `chaos_memory_config_reset_state`
 *   (NULL no-op; zeroes rule_count and parse_ok), `chaos_memory_trim`, `chaos_memory_strip_comment`.
 * - Parse helpers: `chaos_memory_parse_errno_name` (12 valid names plus numeric fallback,
 *   NULL → -1, unrecognised string → -1), `chaos_memory_parse_probability`,
 *   `chaos_memory_parse_latency`, `chaos_memory_copy_text_value`,
 *   `chaos_memory_parse_payload_probability` (with and without `@probability` suffix).
 * - Selector parsing: all valid selector tokens (*, mmap, mmap/anon, mmap/file, mprotect,
 *   madvise, munmap); NULL and empty strings rejected.
 * - Field splitting: valid 3-colon line parsed to selector/effect/value; NULL, missing
 *   fields, and only 2 colons rejected.
 * - Selector matching: NULL selector → false; `*` matches any op; `mmap` matches both
 *   mmap/anon and mmap/file; `mmap/anon` matches MAP_ANONYMOUS only; `mmap/file` matches
 *   shared mappings only; `munmap` matches MUNMAP but not MADVISE.
 * - Mtime hashing: NULL → MISSING; sentinels UNKNOWN and RELOADING normalise to different
 *   values; a zero-stat produces non-zero hash.
 * - Line parsing: comment line → 0; each valid effect/selector combination → 1 with correct
 *   fields; 9 invalid inputs → < 0; NULL arguments → < 0.
 * - Buffer parsing: 5-rule buffer → rule_count=5; no-newline buffer → rule_count=1; invalid
 *   line in buffer → < 0; comment+blank+rule buffer → rule_count=1; NULL arguments → < 0.
 * - Rule selection: most-specific selector wins (mmap/anon over mmap over *); NULL rules or
 *   NULL output → false; tie-breaking by `selector_len` (longer text wins).
 * - Hot-reload: missing file → prepare false; valid file → prepare true, match true; same
 *   mtime on second prepare → true (no-op); invalid content → prepare false, match false;
 *   buffer-full (oversized content) → read fails; NULL size_out → read fails; open/read/CAS
 *   injection failures.
 * - `test_parse_buffer_limit`: `CHAOS_MEMORY_MAX_RULES + 1` lines → parse returns < 0.
 *
 * What is NOT tested here:
 * - Memory wrapper call paths that invoke action helpers at interception time.
 * - Action helpers (tested in `test_memory_actions.c`).
 */

#include "../support/test_memory_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

/**
 * @brief When non-zero, the open stub returns ENOENT / -1 unconditionally.
 *
 * Set before `chaos_memory_config_prepare()` to simulate a file that exists at mtime-check
 * time but cannot be opened.
 */
static int g_test_config_force_open_fail = 0;

/**
 * @brief When non-zero, the open stub returns `g_test_config_fake_fd` and the read stub
 *   injects EIO for that fd.
 */
static int g_test_config_force_read_fail = 0;

/**
 * @brief When non-zero, the CAS stub always returns 0 (compare-and-swap fails).
 *
 * Simulates a lost reload race to verify graceful fallback.
 */
static int g_test_config_force_cas_fail = 0;

/**
 * @brief Sentinel file descriptor returned by the open stub when `g_test_config_force_read_fail`
 *   is set.
 *
 * Value 8124 is chosen to be outside the range of normally-open test fds.
 */
static const int g_test_config_fake_fd = 8124;

/**
 * @brief Stub open with configurable failure modes and real-fd passthrough.
 *
 * When `g_test_config_force_open_fail` is set: returns -1 with errno ENOENT.
 * When `g_test_config_force_read_fail` is set: returns `g_test_config_fake_fd`.
 * For O_CREAT opens: delegates to the real `open(path, flags, mode)`.
 * Otherwise: delegates to `open(path, flags)`.
 */
static int chaos_memory_test_config_open(const char *path, int flags, ...)
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
 * @brief Stub read that injects EIO for the fake fd.
 *
 * Returns -1 with EIO when `g_test_config_force_read_fail` is set and `fd == g_test_config_fake_fd`.
 * All other fds pass through to the real `read`.
 */
static ssize_t chaos_memory_test_config_read(int fd, void *buffer, size_t count)
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
 * @brief Stub close that silently succeeds for the fake fd.
 *
 * Returns 0 without a syscall for the fake fd when `g_test_config_force_read_fail` is set.
 * Delegates to the real `close` for all other fds.
 */
static int chaos_memory_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Stub compare-and-swap controlled by `g_test_config_force_cas_fail`.
 *
 * Returns 0 when forced to fail; otherwise delegates to `__sync_bool_compare_and_swap`.
 */
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

/**
 * @brief In-memory backup of a file's content and existence state.
 */
typedef struct chaos_memory_test_file_backup
{
    int existed;   /**< Non-zero if the file existed when the backup was taken. */
    char *data;    /**< Heap-allocated content copy; NULL if file did not exist. */
    size_t size;   /**< Byte length of `data`. */
} chaos_memory_test_file_backup_t;

/**
 * @brief Save the full content of `path` into `backup`.
 *
 * Reads in 256-byte chunks, growing the buffer via `realloc`. If the file does not exist,
 * records `existed == 0` and stores no data.
 */
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

/**
 * @brief Restore a previously backed-up file.
 *
 * If `backup->existed == 0`, unlinks the file. Otherwise writes back the saved content.
 */
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

/**
 * @brief Release heap memory held by a backup structure.
 */
static void free_backup(chaos_memory_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Write `text` to `CHAOS_MEMORY_CONFIG_PATH` and set mtime to `stamp` via `futimens`.
 *
 * Sets both access time and modification time to `{stamp, 0}` using the file's open fd,
 * ensuring each write produces a unique mtime that triggers a reload.
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
 * @brief Invariant: all primitive string, parse, selector, and hash helpers produce
 *   correct results at boundary values and reject invalid inputs.
 *
 * Triggering condition: direct calls to each low-level helper with valid, invalid, NULL,
 *   and edge-case inputs.
 *
 * Expected observable behaviour:
 * - `is_blank_char` returns true for space and tab; false for 'x'.
 * - `config_reset_state(NULL, 1)` is a no-op; with a 0xff-filled state → rule_count=0,
 *   parse_ok=0.
 * - `trim` and `strip_comment` operate correctly on typical config-file text.
 * - `parse_errno_name`: 12 valid named errors (ENOMEM through EMFILE) map to their values;
 *   numeric string "42" → 42; NULL → -1; unrecognised string "bad" → -1.
 * - `parse_probability`, `parse_latency`: NULL input or NULL output → non-zero; valid
 *   strings → 0; out-of-range probability → non-zero.
 * - `copy_text_value`: NULL input, NULL output, zero size, or empty string → non-zero;
 *   non-empty string → 0.
 * - `parse_payload_probability` without `@` separator: payload set to full input value.
 *   With `@0.25` suffix: payload set to text before `@`; empty payload before `@` → non-zero;
 *   probability > 1.0 → non-zero.
 * - `selector_parse`: NULL and empty → false; all eight valid tokens succeed; `*` produces
 *   ANY kind; `mmap/anon` produces MMAP_KIND with ANON kind; `mmap/file` produces FILE kind.
 * - `split_rule_fields`: valid 3-field line produces correct selector/effect/value tokens;
 *   NULL, missing effect, or too few colons → false.
 * - `selector_matches`: NULL selector → false; `*` matches MPROTECT; `mmap` matches
 *   MAP_ANONYMOUS and MAP_SHARED; `mmap/anon` matches MAP_ANONYMOUS but not MAP_SHARED;
 *   `mmap/file` matches MAP_SHARED but not MPROTECT; `munmap` matches MUNMAP not MADVISE.
 * - Mtime hashing: NULL → MISSING; UNKNOWN/RELOADING sentinels normalise; zero-stat → non-zero.
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
 * @brief Invariant: `chaos_memory_config_parse_line` accepts all valid effect/selector
 *   combinations and rejects malformed or semantically invalid lines; buffer parsing
 *   aggregates rules correctly.
 *
 * Triggering condition: a comment line, individual valid and invalid line strings, several
 *   multi-rule buffers, and NULL argument checks.
 *
 * Expected observable behaviour:
 * - Comment line → 0.
 * - `"*:ERRNO:ENOMEM@0.5"` → 1; selector.kind=ANY, effect=ERRNO, errnum=ENOMEM,
 *   probability=0.5.
 * - `"mmap/file:LATENCY:25"` → 1; selector.kind=MMAP_KIND (FILE), effect=LATENCY,
 *   latency_ms=25.
 * - `"munmap:ERRNO:ENOMEM"` → 1; selector.kind=OPERATION (MUNMAP), errnum=ENOMEM.
 * - Invalid lines (too few fields, empty selector, unknown selector, unknown effect,
 *   unknown errno name, empty errno value, invalid LATENCY string, LATENCY probability > 1)
 *   all return < 0.
 * - 5-rule buffer → rule_count=5.
 * - No-newline single-rule buffer → rule_count=1.
 * - Buffer with an invalid rule → < 0.
 * - Comment + blank + rule buffer → rule_count=1.
 * - NULL line, NULL rule, NULL buffer, NULL rules array, NULL rule_count → all < 0.
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
 * @brief Invariant: rule selection returns the most specific matching selector and handles
 *   NULL guards and tie-breaking by `selector_len`.
 *
 * Triggering condition: a 6-rule array (*, mmap, mmap/anon, mmap/file, madvise, munmap)
 *   and a 2-element tie-break array.
 *
 * Expected observable behaviour:
 * - mmap OP_MMAP MAP_ANONYMOUS → mmap/anon wins (errnum=EAGAIN).
 * - mmap OP_MMAP MAP_SHARED → mmap/file wins (errnum=EACCES).
 * - mprotect → wildcard `*` wins (errnum=ENOMEM).
 * - madvise LATENCY → madvise rule wins (latency_ms=20).
 * - munmap → munmap rule wins (errnum=EINVAL).
 * - NULL rules or NULL output → false.
 * - Tie-break: two rules with the same selector text and operation but different
 *   `selector_len` (8 vs 9); the one with the higher `selector_len` wins (errnum=EPERM).
 */
static void test_rule_selection(void)
{
    chaos_memory_rule_t rules[6];
    chaos_memory_rule_t tie_rules[2];
    chaos_memory_rule_t rule;
    char tie_line[] = "mprotect:ERRNO:EINVAL";
    char any_line[] = "*:ERRNO:ENOMEM";
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
}

/**
 * @brief Invariant: the hot-reload state machine responds correctly to missing files,
 *   mtime changes, parse failures, oversized content, and all injected I/O failures.
 *
 * Triggering condition: `chaos_memory_config_prepare()` and related match functions called
 *   in sequence as the config file is created, modified with distinct mtime values,
 *   intentionally corrupted, and made inaccessible via stub flags.
 *
 * Expected observable behaviour:
 * - Missing file: `prepare()` → false; `match(ERRNO, ...)` → false; NULL rule → false.
 * - `"mmap/anon:ERRNO:ENOMEM\n"` (mtime 11): prepare → true; match for MMAP+MAP_ANONYMOUS
 *   → true, errnum=ENOMEM; `match_loaded` → true; second prepare (same mtime) → true.
 * - `"mprotect:LATENCY:25\n"` (mtime 12): mprotect LATENCY match → true, latency_ms=25;
 *   previous mmap ERRNO match → false (rule replaced).
 * - `"munmap:ERRNO:EINVAL\n"` (mtime 13): munmap ERRNO → true, errnum=EINVAL.
 * - `"bad-rule\n"` (mtime 14): prepare → false; `match_loaded` → false.
 * - Oversized content (> CHAOS_MEMORY_MAX_CONFIG_BYTES): `read_file` → < 0.
 * - NULL size_out: `read_file(NULL)` → < 0.
 * - Open failure (mtime 16): prepare → false.
 * - Read failure (mtime 17): prepare → false.
 * - CAS failure (mtime 18): prepare → false (CAS lost, reload not committed).
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
        assert(chaos_memory_config_read_file(&size) < 0);
    }
    assert(chaos_memory_config_read_file(NULL) < 0);

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
 * @brief Invariant: `chaos_memory_config_parse_buffer` returns an error when the rule
 *   count exceeds `CHAOS_MEMORY_MAX_RULES`.
 *
 * Triggering condition: a dynamically allocated buffer containing
 *   `CHAOS_MEMORY_MAX_RULES + 1` valid `"madvise:LATENCY:1\n"` lines.
 *
 * Expected observable behaviour:
 * - `parse_buffer` returns < 0.
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

int main(void)
{
    test_helper_functions();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    test_parse_buffer_limit();
    return 0;
}
