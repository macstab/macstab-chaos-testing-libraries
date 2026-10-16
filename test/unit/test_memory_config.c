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
 *   (NULL no-op; zeroes rule_count and parse_ok), `chaos_memory_trim`,
 * `chaos_memory_strip_comment`.
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

/* The rule file is read through these stubs (defined below) instead of raw system calls. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

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

/** Number of upcoming config reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;

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
 * Returns -1 with EIO when `g_test_config_force_read_fail` is set and `fd ==
 * g_test_config_fake_fd`. All other fds pass through to the real `read`.
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
    int existed; /**< Non-zero if the file existed when the backup was taken. */
    char *data;  /**< Heap-allocated content copy; NULL if file did not exist. */
    size_t size; /**< Byte length of `data`. */
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

/**
 * @brief Invariant: a caller that observes a reload in progress uses the current
 *   snapshot and never starts a second, concurrent reload.
 *
 * Triggering condition: `g_chaos_memory_cached_mtime` holds `CHAOS_MEMORY_MTIME_RELOADING`
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
 * @brief Invariant: a failed config read keeps the active rules and is retried.
 *
 * Triggering condition: the file changes while `read()` fails.
 *
 * Expected observable behaviour: the previously loaded rule set stays active, the
 * cached stamp is not advanced, and the next call loads the new content.
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
    assert(chaos_memory_config_hash_mtime(&base) == chaos_memory_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_memory_config_hash_mtime(&base) != chaos_memory_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_memory_config_hash_mtime(&base) != chaos_memory_config_hash_mtime(&other));
}

/**
 * @brief Invariant: a child forked during a reload takes the orphaned claim over.
 *
 * Triggering condition: the cached stamp is RELOADING but the claim was recorded
 * by another process id, as a forked child sees it.
 *
 * Expected observable behaviour: `prepare()` reloads and publishes the file's rules;
 * a claim recorded by this process is left alone.
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

    /* A competing taker-over wins the release: this caller keeps the current snapshot. */
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_memory_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* The claim belongs to this process: another of its threads is reloading. */
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_RELOADING;
    (void)chaos_memory_config_prepare();
    assert(g_chaos_memory_cached_mtime == CHAOS_MEMORY_MTIME_RELOADING);
    g_chaos_memory_cached_mtime = CHAOS_MEMORY_MTIME_UNKNOWN;

    restore_file(CHAOS_MEMORY_CONFIG_PATH, &backup);
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
 * @brief Invariant: a config read interrupted by a signal is retried, not treated as failure.
 *
 * Triggering condition: the first `read()` fails with EINTR.
 *
 * Expected observable behaviour: the rules are loaded as if nothing had happened.
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
    stamp = chaos_memory_config_observed_mtime();
    assert(chaos_memory_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_memory_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_MEMORY_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
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
 * @brief Invariant: a rejected line is recorded with its number, its text as written
 *   and the reason, and a full rule set followed by comments is still accepted.
 *
 * Triggering condition: a buffer whose fourth line is invalid and carries a comment;
 *   then exactly CHAOS_MEMORY_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
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

    /* A file at the size limit is reported, not silently re-read. */
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

/**
 * @brief Reads this process's hits file into @p buffer; returns 0 when it does not exist.
 */
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
 * @brief Invariant: qualifiers after a rule are parsed into its policy, and a bad
 *   qualifier rejects the line.
 *
 * Expected observable behaviour: every qualifier lands in the policy and the rule
 *   itself still parses; an unknown qualifier, qualifiers without a rule and an
 *   `@until` before its `@from` are rejected as invalid rules.
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
 * @brief Invariant: a rewrite in place within one mtime tick is still seen, and a
 *        provisional load that reads the file again unchanged keeps its snapshot.
 *
 * Triggering condition: a rule file loaded right after it was written, then
 * rewritten in place with the same size and its mtime set back to the first one,
 * so that mtime, size, inode and device all stay as they were.
 *
 * Expected observable behaviour: the load is provisional; reading the unchanged
 * file again keeps the snapshot; the rewrite is loaded; an mtime older than
 * the window ends the provisional state.
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
 * @brief Invariant: hits still pending when their interval is over are written by
 *        the next look at the rule file, not only by the next hit or at exit.
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
    return 0;
}
