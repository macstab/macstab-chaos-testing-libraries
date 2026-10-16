/**
 * @file test_dns_config.c
 * @brief Unit tests for DNS-domain configuration parsing, selector matching, rule selection,
 *   and hot-reload state machine.
 *
 * Subsystem under test: `src/dns/chaos_dns_config.c`
 *
 * Coverage approach:
 * - The production source file is included after four stubs are wired via `#define`:
 *   `open`, `read`, `close`, and `chaos_dns_atomic_cas_u64`. This allows precise control
 *   over file-open/read failures and atomic compare-and-swap races, which are otherwise
 *   non-deterministic.
 * - `g_test_config_fake_fd` (9124) is a sentinel file descriptor used exclusively by the
 *   read-failure and close stubs; any real-path opens delegated to the OS use a distinct fd.
 * - `CHAOS_DNS_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals.
 * - Filesystem operations required by `test_prepare_and_match` use the real `open`/`read`/
 *   `close` after the `#undef` block, along with `backup_file`/`restore_file`/
 *   `write_config_text` helpers defined locally.
 * - `write_config_text(text, stamp)` writes the file and sets its mtime via `futimens` so
 *   that each successive write has a unique timestamp, ensuring the mtime-change detection
 *   logic triggers a reload on the next `prepare` call.
 *
 * Properties under test:
 * - Primitive helpers: `chaos_dns_is_blank_char`, `chaos_dns_trim`, `chaos_dns_strip_comment`,
 *   `chaos_dns_ascii_case_equal`, `chaos_dns_ascii_case_ends_with`.
 * - Parse helpers: `chaos_dns_parse_probability`, `chaos_dns_parse_latency`,
 *   `chaos_dns_parse_limit`, `chaos_dns_parse_family_filter`, `chaos_dns_parse_gai_name`,
 *   `chaos_dns_copy_text_value`, `chaos_dns_parse_payload_probability`,
 *   `chaos_dns_validate_override_value`, `chaos_dns_override_token_valid`,
 *   `chaos_dns_split_rule_fields`.
 * - Mtime hashing: NULL → `CHAOS_DNS_MTIME_MISSING`; sentinel normalisation remaps
 *   `CHAOS_DNS_MTIME_UNKNOWN` to a different value.
 * - Selector parsing: `*` → ANY/LOOKUP; `dns://exact` → EXACT/LOOKUP (case-insensitive);
 *   `dns://\*.suffix` → SUFFIX/LOOKUP; `rdns://ip` → EXACT/REVERSE; `rdns://[::1]` strips
 *   brackets; `rdns://\*` → ANY/REVERSE; invalid selectors rejected.
 * - Selector matching: rank 1 for ANY, 2 for SUFFIX, 3 for EXACT; domain mismatch → no match.
 * - Line parsing: blank → 0; each of 10 valid effect types returns 1 with correct fields;
 *   invalid OVERRIDE value, invalid FILTER_FAMILY, rdns with OVERRIDE, rdns with LIMIT → -1;
 *   10-rule buffer parses to `rule_count == 10`.
 * - Rule selection: `select_rule` returns the most specific selector (exact > suffix > any);
 *   `select_reverse_rule` prefers exact reverse match over wildcard reverse match.
 * - Hot-reload: missing file → prepare returns false; valid file → prepare returns true,
 *   match works; subsequent same-mtime prepare → no-op but returns true; invalid-content
 *   prepare → false and match returns false; NULL path arguments → match returns false;
 *   CAS-fail path; open-fail path; read-fail path.
 *
 * What is NOT tested here:
 * - DNS wrapper call paths (tested in `test_chaos_dns.c`).
 * - Action helpers — filter, shuffle, limit, GAI injection (tested in `test_dns_actions.c`).
 * - Constructor initialisation and symbol resolution (tested in `test_dns_runtime.c`).
 */

/* The rule file is read through these stubs (defined below) instead of raw system calls. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* A rule file counts as just written for 5 s, not 20 ms: the racily-clean tests
 * restore an earlier mtime and must find it still recent on a slow machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_dns_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_DNS_DEFINE_TEST_GLOBALS();

/**
 * @brief When non-zero, the open stub returns ENOENT / -1 unconditionally.
 *
 * Set before calling `chaos_dns_config_prepare()` to exercise the path where the config
 * file cannot be opened (e.g., permissions removed after mtime detection).
 */
static int g_test_config_force_open_fail = 0;

/**
 * @brief When non-zero, the open stub returns `g_test_config_fake_fd` and the read/close
 *   stubs inject EIO / no-op for that fd.
 *
 * Set before calling `chaos_dns_config_prepare()` to simulate a read failure after a
 * successful open without touching the filesystem.
 */
static int g_test_config_force_read_fail = 0;

/** Number of upcoming config reads that fail with EINTR, as a signal would make them. */
static int g_test_config_read_eintr = 0;

/** Number of upcoming config opens that fail with EINTR, as a signal would make them. */
static int g_test_config_open_eintr = 0;

/** When non-zero, the open stub fails with this errno (EACCES, EPERM, ...). */
static int g_test_config_open_errno = 0;

/**
 * @brief When non-zero, the CAS stub always returns 0 (CAS fails).
 *
 * Used to verify that a lost compare-and-swap race during config reload does not corrupt
 * state or prevent a future successful prepare.
 */
static int g_test_config_force_cas_fail = 0;

/**
 * @brief Sentinel file descriptor returned by the open stub when `g_test_config_force_read_fail`
 *   is set.
 *
 * The value 9124 is chosen to be outside the range of typical low-numbered fds opened by
 * the test binary, ensuring the read/close stubs can identify it unambiguously.
 */
static const int g_test_config_fake_fd = 9124;

/**
 * @brief Stub open function with configurable failure modes and real-fd passthrough.
 *
 * When `g_test_config_open_eintr` is positive: consumes one and fails with EINTR.
 * When `g_test_config_open_errno` is set: returns -1 with that errno.
 * When `g_test_config_force_open_fail` is set: returns -1 with errno ENOENT.
 * When `g_test_config_force_read_fail` is set: returns `g_test_config_fake_fd` without
 *   touching the filesystem.
 * For O_CREAT opens: delegates to the real `open(path, flags, mode)` (variadic).
 * Otherwise: delegates to `open(path, flags)`.
 *
 * @param path   Config file path.
 * @param flags  Open flags; O_CREAT triggers variadic mode extraction.
 * @return File descriptor or -1.
 */
static int chaos_dns_test_config_open(const char *path, int flags, ...)
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
 * @brief Stub read function that injects EIO when the fake fd is active.
 *
 * Returns -1 with errno EIO only when `g_test_config_force_read_fail` is non-zero and
 * `fd == g_test_config_fake_fd`. All other fds are passed through to the real `read`.
 *
 * @param fd      File descriptor.
 * @param buffer  Read buffer.
 * @param count   Maximum bytes to read.
 * @return Bytes read, or -1 on injected error.
 */
static ssize_t chaos_dns_test_config_read(int fd, void *buffer, size_t count)
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
 * @brief Stub close function that silently succeeds for the fake fd.
 *
 * Returns 0 without a syscall when `g_test_config_force_read_fail` is non-zero and
 * `fd == g_test_config_fake_fd`. Delegates to the real `close` for all other fds.
 *
 * @param fd  File descriptor to close.
 * @return 0 on success.
 */
static int chaos_dns_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/**
 * @brief Stub compare-and-swap function controlled by `g_test_config_force_cas_fail`.
 *
 * Returns 0 (CAS failed) when `g_test_config_force_cas_fail` is non-zero, simulating a lost
 * reload race. Otherwise delegates to `__sync_bool_compare_and_swap`.
 *
 * @param value     Pointer to the volatile counter to swap.
 * @param expected  Expected current value.
 * @param desired   Desired new value.
 * @return 1 if swapped, 0 if the CAS was forced to fail or the current value differed.
 */
static int
chaos_dns_test_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    if (g_test_config_force_cas_fail != 0)
    {
        return 0;
    }
    return __sync_bool_compare_and_swap(value, expected, desired);
}

#define open chaos_dns_test_config_open
#define read chaos_dns_test_config_read
#define close chaos_dns_test_config_close
#define chaos_dns_atomic_cas_u64 chaos_dns_test_atomic_cas_u64
#include "../../src/dns/chaos_dns_config.c"
#undef chaos_dns_atomic_cas_u64
#undef close
#undef read
#undef open

/**
 * @brief In-memory backup of a file's content and existence state.
 *
 * Used by `backup_file` and `restore_file` to save and restore `CHAOS_DNS_CONFIG_PATH`
 * around tests that modify it.
 */
typedef struct chaos_dns_test_file_backup
{
    int existed; /**< Non-zero if the file existed when the backup was taken. */
    char *data;  /**< Heap-allocated copy of the file content; NULL if none. */
    size_t size; /**< Byte length of `data`. */
} chaos_dns_test_file_backup_t;

/**
 * @brief Save the full content of `path` into `backup`.
 *
 * If the file does not exist, records `existed == 0` and stores no data. Reads the file in
 * 256-byte chunks, growing the backup buffer via `realloc`.
 *
 * @param path    File to back up.
 * @param backup  Destination; zeroed on entry.
 */
static void backup_file(const char *path, chaos_dns_test_file_backup_t *backup)
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
 * If `backup->existed` is 0, unlinks `path`. Otherwise opens `path` for writing and writes
 * back the saved content.
 *
 * @param path    File to restore.
 * @param backup  Source backup data.
 */
static void restore_file(const char *path, const chaos_dns_test_file_backup_t *backup)
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
 *
 * Frees `backup->data` and resets all fields to zero/NULL. Does not touch the filesystem.
 *
 * @param backup  Backup to free.
 */
static void free_backup(chaos_dns_test_file_backup_t *backup)
{
    free(backup->data);
    backup->data = NULL;
    backup->size = 0U;
    backup->existed = 0;
}

/**
 * @brief Write `text` to `CHAOS_DNS_CONFIG_PATH` and set its mtime to `stamp`.
 *
 * Opens the file with `fopen`, writes the text, flushes, and then calls `futimens` with both
 * access time and modification time set to `{stamp, 0}`. This ensures each successive write
 * in `test_prepare_and_match` has a unique, increasing mtime that triggers a config reload.
 *
 * @param text   Null-terminated config text to write.
 * @param stamp  Unix timestamp to assign as the file's mtime.
 */
static void write_config_text(const char *text, time_t stamp)
{
    FILE *file;
    struct timespec times[2];

    file = fopen(CHAOS_DNS_CONFIG_PATH, "w");
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
 * @brief Invariant: all primitive string, parse, and hash helpers behave correctly at
 *   boundary values.
 *
 * Triggering condition: direct calls to each low-level helper with valid, invalid, NULL,
 *   and boundary inputs.
 *
 * Expected observable behaviour:
 * - `is_blank_char(' ')` and `is_blank_char('\t')` → true; `is_blank_char('x')` → false.
 * - `trim` strips leading/trailing whitespace including CR and LF.
 * - `strip_comment` removes everything from `#` onwards; leaves `abc` from `"abc#def"`.
 * - `ascii_case_equal("Example", "example")` → true; different strings → false.
 * - `ascii_case_ends_with("api.example.com", "example.com")` → true; mismatched suffix → false.
 * - `parse_probability("0.5", ...)` → 0; `("2.0", ...)` → non-zero (out of range).
 * - `parse_latency("25", ...)` → 0; `("bad", ...)` → non-zero.
 * - `parse_limit("2", ...)` → 0; `("0", ...)` → non-zero (zero limit is invalid).
 * - `parse_family_filter("inet4")` → INET4; `("inet6")` → INET6; unknown → INVALID.
 * - `parse_gai_name("EAI_AGAIN")` → EAI_AGAIN; unknown → 0x7fffffff (sentinel).
 * - `copy_text_value("abc", ...)` → 0; `("", ...)` → non-zero (empty not allowed).
 * - `parse_payload_probability("value@0.25", ...)` → 0; payload set to "value".
 * - `validate_override_value("127.0.0.1,[::1]")` → true; `("bad-host")` → false.
 * - `override_token_valid("127.0.0.1")` and `("[::1]")` → true; `("not-an-ip")` → false.
 * - `split_rule_fields("dns://api.example.com:REWRITE:alt.example.com", ...)` → true;
 *   selector="dns://api.example.com", effect="REWRITE", value="alt.example.com".
 * - `split_rule_fields("bad", ...)` → false (too few colons).
 * - `config_hash_mtime(NULL)` → `CHAOS_DNS_MTIME_MISSING`.
 * - `config_normalize_mtime_hash(CHAOS_DNS_MTIME_UNKNOWN)` → value != UNKNOWN.
 * - `config_hash_mtime` of a zero-stat produces a non-zero value.
 */
static void test_helper_functions(void)
{
    char trim_text[] = " \t value \r\n";
    char comment_text[] = "abc#def";
    char payload_text[] = "value@0.25";
    char split_text[] = "dns://api.example.com:REWRITE:alt.example.com";
    char *selector_text = NULL;
    char *effect_text = NULL;
    char *value_text = NULL;
    char payload[CHAOS_DNS_MAX_VALUE];
    struct stat st;

    assert(chaos_dns_is_blank_char(' '));
    assert(chaos_dns_is_blank_char('\t'));
    assert(!chaos_dns_is_blank_char('x'));

    assert(strcmp(chaos_dns_trim(trim_text), "value") == 0);
    chaos_dns_strip_comment(comment_text);
    assert(strcmp(comment_text, "abc") == 0);
    assert(chaos_dns_ascii_case_equal("Example", "example"));
    assert(!chaos_dns_ascii_case_equal("Example", "sample"));
    assert(chaos_dns_ascii_case_ends_with("api.example.com", "example.com"));
    assert(!chaos_dns_ascii_case_ends_with("api.example.com", "other.com"));

    assert(chaos_dns_parse_probability("0.5", &(double){0.0}) == 0);
    assert(chaos_dns_parse_probability("2.0", &(double){0.0}) != 0);
    assert(chaos_dns_parse_latency("25", &(unsigned int){0U}) == 0);
    assert(chaos_dns_parse_latency("bad", &(unsigned int){0U}) != 0);
    assert(chaos_dns_parse_limit("2", &(unsigned int){0U}) == 0);
    assert(chaos_dns_parse_limit("0", &(unsigned int){0U}) != 0);
    assert(chaos_dns_parse_family_filter("inet4") == CHAOS_DNS_FAMILY_INET4);
    assert(chaos_dns_parse_family_filter("inet6") == CHAOS_DNS_FAMILY_INET6);
    assert(chaos_dns_parse_family_filter("weird") == CHAOS_DNS_FAMILY_INVALID);
    assert(chaos_dns_parse_gai_name("EAI_AGAIN") == EAI_AGAIN);
    assert(chaos_dns_parse_gai_name("NOPE") == 0x7fffffff);
    assert(chaos_dns_copy_text_value("abc", payload, sizeof(payload)) == 0);
    assert(chaos_dns_copy_text_value("", payload, sizeof(payload)) != 0);
    assert(
        chaos_dns_parse_payload_probability(
            payload_text, payload, sizeof(payload), &(double){0.0}
        ) == 0
    );
    assert(strcmp(payload, "value") == 0);
    assert(chaos_dns_validate_override_value("127.0.0.1,[::1]"));
    assert(!chaos_dns_validate_override_value("bad-host"));
    assert(chaos_dns_override_token_valid("127.0.0.1"));
    assert(chaos_dns_override_token_valid("[::1]"));
    assert(!chaos_dns_override_token_valid("not-an-ip"));

    assert(chaos_dns_split_rule_fields(split_text, &selector_text, &effect_text, &value_text));
    assert(strcmp(selector_text, "dns://api.example.com") == 0);
    assert(strcmp(effect_text, "REWRITE") == 0);
    assert(strcmp(value_text, "alt.example.com") == 0);
    assert(!chaos_dns_split_rule_fields("bad", &selector_text, &effect_text, &value_text));

    (void)memset(&st, 0, sizeof(st));
    st.st_size = 0;
    assert(chaos_dns_config_hash_mtime(NULL) == CHAOS_DNS_MTIME_MISSING);
    assert(
        chaos_dns_config_normalize_mtime_hash(CHAOS_DNS_MTIME_UNKNOWN) != CHAOS_DNS_MTIME_UNKNOWN
    );
    assert(chaos_dns_config_hash_mtime(&st) != 0U);
}

/**
 * @brief Invariant: selector parsing produces correct kind, domain, and text fields; matching
 *   assigns the correct rank and respects domain boundaries.
 *
 * Triggering condition: `chaos_dns_selector_parse` and `chaos_dns_selector_matches_domain`
 *   with all valid selector forms and several invalid ones.
 *
 * Expected observable behaviour:
 * - `*` → ANY, LOOKUP domain; matches any hostname in LOOKUP domain with rank 1.
 * - `dns://api.example.com` → EXACT, LOOKUP; case-insensitive match rank 3; non-matching
 *   hostname → false.
 * - `dns://\*.example.com` → SUFFIX, LOOKUP; suffix match rank 2; bare `example.com` (no
 *   subdomain) → false.
 * - `rdns://127.0.0.1` → EXACT, REVERSE; rank 3 for exact IP match; LOOKUP domain → false.
 * - `rdns://[::1]` → EXACT, REVERSE; brackets stripped, text field is `"::1"`.
 * - `rdns://\*` → ANY, REVERSE; matches any IP in REVERSE domain.
 * - Invalid selectors: empty host (`dns://`), bad wildcard (`dns://\*bad`), non-IP rdns
 *   hostname, rdns wildcard-suffix (`rdns://\*.example.com`) → all return false.
 */
static void test_selector_matching(void)
{
    chaos_dns_selector_t selector;
    unsigned int rank = 0U;

    assert(chaos_dns_selector_parse("*", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", &rank
    ));
    assert(rank == 1U);

    assert(chaos_dns_selector_parse("dns://api.example.com", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "API.EXAMPLE.COM", &rank
    ));
    assert(rank == 3U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "other.example.com", &rank
    ));

    assert(chaos_dns_selector_parse("dns://*.example.com", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", &rank
    ));
    assert(rank == 2U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "example.com", &rank
    ));
    assert(chaos_dns_selector_parse("rdns://127.0.0.1", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(strcmp(selector.text, "127.0.0.1") == 0);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "127.0.0.1", &rank
    ));
    assert(rank == 3U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "127.0.0.1", &rank
    ));
    assert(chaos_dns_selector_parse("rdns://[::1]", &selector));
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(strcmp(selector.text, "::1") == 0);
    assert(chaos_dns_selector_parse("rdns://*", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "127.0.0.1", &rank
    ));
    assert(!chaos_dns_selector_parse("dns://", &selector));
    assert(!chaos_dns_selector_parse("dns://*bad", &selector));
    assert(!chaos_dns_selector_parse("rdns://bad-host", &selector));
    assert(!chaos_dns_selector_parse("rdns://*.example.com", &selector));
}

/**
 * @brief Invariant: individual line parsing handles all effect types and rejects invalid
 *   combinations; buffer parsing aggregates all valid rules.
 *
 * Triggering condition: `chaos_dns_config_parse_line` with a blank line, then with one line
 *   per effect type (GAI, LATENCY, REWRITE, SERVICE, OVERRIDE, FILTER_FAMILY, LIMIT,
 *   SHUFFLE, rdns GAI, rdns SERVICE), then with four invalid lines; finally
 *   `chaos_dns_config_parse_buffer` with a 10-rule buffer.
 *
 * Expected observable behaviour:
 * - Blank line → 0.
 * - GAI line: effect=GAI, gai_error=EAI_AGAIN.
 * - LATENCY line: effect=LATENCY, latency_ms=25, probability=0.4.
 * - REWRITE line: effect=REWRITE, text="alt.example.com".
 * - SERVICE line: effect=SERVICE, text="https".
 * - OVERRIDE line: effect=OVERRIDE.
 * - FILTER_FAMILY line: family=INET6.
 * - LIMIT line: limit=2.
 * - SHUFFLE line: effect=SHUFFLE.
 * - rdns GAI: selector domain=REVERSE, effect=GAI, gai_error=EAI_FAIL.
 * - rdns SERVICE: selector domain=REVERSE, effect=SERVICE, text="redis".
 * - Invalid OVERRIDE (non-IP host), invalid FILTER_FAMILY (unknown token),
 *   rdns with OVERRIDE, rdns with LIMIT → all return < 0.
 * - `parse_buffer` with the 10-line buffer → 0, rule_count=10.
 */
static void test_parse_line_and_buffer(void)
{
    chaos_dns_rule_t rule;
    chaos_dns_rule_t rules[10];
    size_t rule_count = 0U;
    char buffer[] = "dns://api.example.com:EAI_AGAIN:0.5\n"
                    "dns://api.example.com:LATENCY:25@0.4\n"
                    "dns://api.example.com:REWRITE:alt.example.com@0.3\n"
                    "*:SERVICE:https@1.0\n"
                    "*:OVERRIDE:127.0.0.1,[::1]@0.2\n"
                    "*:FILTER_FAMILY:inet6@0.5\n"
                    "*:LIMIT:2@0.7\n"
                    "*:SHUFFLE:0.8\n"
                    "rdns://127.0.0.1:EAI_FAIL:0.6\n"
                    "rdns://[::1]:SERVICE:redis@0.9\n";

    {
        char blank_line[] = " \n";

        assert(chaos_dns_config_parse_line(blank_line, &rule) == 0);
    }

    {
        char gai_line[] = "dns://api.example.com:EAI_AGAIN:0.5";
        assert(chaos_dns_config_parse_line(gai_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_GAI);
        assert(rule.gai_error == EAI_AGAIN);
    }
    {
        char latency_line[] = "dns://api.example.com:LATENCY:25@0.4";
        assert(chaos_dns_config_parse_line(latency_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_LATENCY);
        assert(rule.latency_ms == 25U);
        assert(rule.probability == 0.4);
    }
    {
        char rewrite_line[] = "dns://api.example.com:REWRITE:alt.example.com@0.3";
        assert(chaos_dns_config_parse_line(rewrite_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_REWRITE);
        assert(strcmp(rule.text, "alt.example.com") == 0);
    }
    {
        char service_line[] = "*:SERVICE:https@1.0";
        assert(chaos_dns_config_parse_line(service_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_SERVICE);
        assert(strcmp(rule.text, "https") == 0);
    }
    {
        char override_line[] = "*:OVERRIDE:127.0.0.1,[::1]@0.2";
        assert(chaos_dns_config_parse_line(override_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_OVERRIDE);
    }
    {
        char family_line[] = "*:FILTER_FAMILY:inet6@0.5";
        assert(chaos_dns_config_parse_line(family_line, &rule) == 1);
        assert(rule.family == CHAOS_DNS_FAMILY_INET6);
    }
    {
        char limit_line[] = "*:LIMIT:2@0.7";
        assert(chaos_dns_config_parse_line(limit_line, &rule) == 1);
        assert(rule.limit == 2U);
    }
    {
        char shuffle_line[] = "*:SHUFFLE:0.8";
        assert(chaos_dns_config_parse_line(shuffle_line, &rule) == 1);
        assert(rule.effect == CHAOS_DNS_EFFECT_SHUFFLE);
    }
    {
        char reverse_gai_line[] = "rdns://127.0.0.1:EAI_FAIL:0.6";
        assert(chaos_dns_config_parse_line(reverse_gai_line, &rule) == 1);
        assert(rule.selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
        assert(rule.effect == CHAOS_DNS_EFFECT_GAI);
        assert(rule.gai_error == EAI_FAIL);
    }
    {
        char reverse_service_line[] = "rdns://[::1]:SERVICE:redis@0.9";
        assert(chaos_dns_config_parse_line(reverse_service_line, &rule) == 1);
        assert(rule.selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_REVERSE);
        assert(rule.effect == CHAOS_DNS_EFFECT_SERVICE);
        assert(strcmp(rule.text, "redis") == 0);
    }
    {
        char invalid_line[] = "dns://api.example.com:OVERRIDE:not-a-host@1.0";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "dns://api.example.com:FILTER_FAMILY:bad";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "rdns://127.0.0.1:OVERRIDE:127.0.0.1";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }
    {
        char invalid_line[] = "rdns://127.0.0.1:LIMIT:1";
        assert(chaos_dns_config_parse_line(invalid_line, &rule) < 0);
    }

    assert(chaos_dns_config_parse_buffer(buffer, rules, &rule_count) == 0);
    assert(rule_count == 10U);
}

/**
 * @brief Invariant: rule selection returns the most specific matching rule for both
 *   forward (LOOKUP) and reverse (REVERSE) domain queries.
 *
 * Triggering condition: a 5-rule array (any, suffix, exact, reverse-any, reverse-exact)
 *   tested with `chaos_dns_config_select_rule` and `chaos_dns_config_select_reverse_rule`
 *   for various hostname and IP inputs.
 *
 * Expected observable behaviour:
 * - Exact hostname `"api.example.com"` → EXACT selector wins over SUFFIX and ANY.
 * - Suffix match `"edge.example.com"` → SUFFIX selector wins over ANY.
 * - No-match hostname `"other.net"` → ANY selector used.
 * - Reverse lookup for `"127.0.0.1"` → exact reverse rule (text="redis") wins over any.
 * - Reverse lookup for `"::1"` → any reverse rule (text="svc").
 */
static void test_rule_selection(void)
{
    chaos_dns_rule_t rules[5];
    chaos_dns_rule_t selected;
    char exact_line[] = "dns://api.example.com:SHUFFLE:1.0";
    char suffix_line[] = "dns://*.example.com:SHUFFLE:1.0";
    char any_line[] = "*:SHUFFLE:1.0";
    char reverse_any_line[] = "rdns://*:SERVICE:svc";
    char reverse_exact_line[] = "rdns://127.0.0.1:SERVICE:redis";

    assert(chaos_dns_config_parse_line(any_line, &rules[0]) == 1);
    assert(chaos_dns_config_parse_line(suffix_line, &rules[1]) == 1);
    assert(chaos_dns_config_parse_line(exact_line, &rules[2]) == 1);
    assert(chaos_dns_config_parse_line(reverse_any_line, &rules[3]) == 1);
    assert(chaos_dns_config_parse_line(reverse_exact_line, &rules[4]) == 1);

    assert(chaos_dns_config_select_rule(
        rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "api.example.com", &selected
    ));
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_EXACT);
    assert(chaos_dns_config_select_rule(
        rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.example.com", &selected
    ));
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(chaos_dns_config_select_rule(rules, 3U, CHAOS_DNS_EFFECT_SHUFFLE, "other.net", &selected)
    );
    assert(selected.selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(chaos_dns_config_select_reverse_rule(
        rules, 5U, CHAOS_DNS_EFFECT_SERVICE, "127.0.0.1", &selected
    ));
    assert(strcmp(selected.text, "redis") == 0);
    assert(
        chaos_dns_config_select_reverse_rule(rules, 5U, CHAOS_DNS_EFFECT_SERVICE, "::1", &selected)
    );
    assert(strcmp(selected.text, "svc") == 0);
}

/**
 * @brief Invariant: the hot-reload state machine responds correctly to file absence,
 *   content validity, mtime changes, CAS races, and I/O failures.
 *
 * Triggering condition: `chaos_dns_config_prepare()` and the match family of functions
 *   called in sequence as the config file is created, modified with distinct mtime values,
 *   and corrupted, with targeted fault injection via the stub flags.
 *
 * Expected observable behaviour:
 * - Missing file: `prepare()` → false.
 * - REWRITE rule for `api.example.com`: `prepare()` → true; `match(REWRITE, host)` → true,
 *   text="alt.example.com"; `match(LIMIT, host)` → false; `match_loaded` → true;
 *   `match_reverse(REWRITE, ip)` → false.
 * - Reverse REWRITE rule: `prepare()` → true; `match_reverse(REWRITE, "127.0.0.1")` → true,
 *   text="ptr.example"; `match_reverse_loaded` → true.
 * - CAS failure (`g_test_config_force_cas_fail = 1`): `prepare()` → true (CAS failure is a
 *   benign lost race; the loaded state from a prior successful load is still usable).
 * - Open or read failure: `prepare()` keeps the active rules → true; the next call retries.
 * - Invalid content (non-IP OVERRIDE value): `prepare()` → false; `match_loaded` → false.
 * - NULL hostname to `match` and `match_reverse` → false.
 */
static void test_prepare_and_match(void)
{
    chaos_dns_rule_t rule;
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();

    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    assert(!chaos_dns_config_prepare());

    write_config_text("dns://api.example.com:REWRITE:alt.example.com\n", 10);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match(CHAOS_DNS_EFFECT_REWRITE, "api.example.com", &rule));
    assert(strcmp(rule.text, "alt.example.com") == 0);
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_LIMIT, "api.example.com", &rule));
    assert(chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_REWRITE, "api.example.com", &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));

    write_config_text("rdns://127.0.0.1:REWRITE:ptr.example\n", 11);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));
    assert(strcmp(rule.text, "ptr.example") == 0);
    assert(chaos_dns_config_match_reverse_loaded(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));

    g_test_config_force_cas_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 12);
    assert(chaos_dns_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* A failed open or read keeps the active rules and is retried on the next call. */
    g_test_config_force_open_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 13);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match_reverse_loaded(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 14);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match_reverse_loaded(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));
    g_test_config_force_read_fail = 0;

    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_LATENCY, "api.example.com", &rule));

    write_config_text("dns://api.example.com:OVERRIDE:not-a-host\n", 15);
    assert(!chaos_dns_config_prepare());
    assert(!chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_OVERRIDE, "api.example.com", &rule));
    assert(!chaos_dns_config_match_reverse_loaded(CHAOS_DNS_EFFECT_REWRITE, "127.0.0.1", &rule));
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, NULL, &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, NULL, &rule));

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Invariant: a caller that observes a reload in progress uses the current
 *   snapshot and never starts a second, concurrent reload.
 *
 * Triggering condition: `g_chaos_dns_cached_mtime` holds `CHAOS_DNS_MTIME_RELOADING`
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

    chaos_dns_config_init();
    active_index = g_chaos_dns_active_config_index;
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    assert(chaos_dns_config_observed_mtime() != CHAOS_DNS_MTIME_RELOADING);

    (void)chaos_dns_config_prepare();

    assert(g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_RELOADING);
    assert(g_chaos_dns_active_config_index == active_index);

    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;
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
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();

    write_config_text("dns://api.example.com:LATENCY:20\n", 40);
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_active_state()->rule_count == 1U);

    write_config_text(
        "dns://api.example.com:LATENCY:20\nrdns://127.0.0.1:REWRITE:ptr.example\n", 41
    );
    g_test_config_force_read_fail = 1;
    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_active_state()->rule_count == 1U);
    assert(g_chaos_dns_cached_mtime != chaos_dns_config_observed_mtime());
    assert(g_chaos_dns_cached_mtime != CHAOS_DNS_MTIME_RELOADING);
    g_test_config_force_read_fail = 0;

    assert(chaos_dns_config_prepare());
    assert(chaos_dns_config_active_state()->rule_count == 2U);

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
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
    assert(chaos_dns_config_hash_mtime(&base) == chaos_dns_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_dns_config_hash_mtime(&base) != chaos_dns_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_dns_config_hash_mtime(&base) != chaos_dns_config_hash_mtime(&other));
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
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();
    write_config_text("dns://api.example.com:LATENCY:20\n", 60);

    /* A claim is never taken over, whoever made it: in a vfork child the parent's
     * reload thread is still running. A fork() child's atfork handler releases it. */
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    (void)chaos_dns_config_prepare();
    assert(g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_RELOADING);
    g_chaos_dns_tls_prng_state = UINT64_C(42);
    chaos_dns_config_after_fork();
    assert(g_chaos_dns_tls_prng_state == 0U);
    assert(g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_UNKNOWN);
    assert(g_chaos_dns_hits_pid == (uint64_t)getpid());
    assert(chaos_dns_config_prepare());
    assert(g_chaos_dns_cached_mtime == chaos_dns_config_observed_mtime());
    chaos_dns_config_after_fork();
    assert(g_chaos_dns_cached_mtime == chaos_dns_config_observed_mtime());

    /* A competing taker-over wins the release: this caller keeps the current snapshot. */
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_dns_config_prepare());
    g_test_config_force_cas_fail = 0;

    /* The claim belongs to this process: another of its threads is reloading. */
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    (void)chaos_dns_config_prepare();
    assert(g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_RELOADING);
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
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
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();
    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    errno = EBADF;
    (void)chaos_dns_config_prepare();
    assert(errno == EBADF);

    write_config_text("dns://api.example.com:LATENCY:20\n", 70);
    errno = EBADF;
    assert(chaos_dns_config_prepare());
    assert(errno == EBADF);

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
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
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();
    write_config_text("dns://api.example.com:LATENCY:20\n", 80);
    g_test_config_read_eintr = 1;
    assert(chaos_dns_config_prepare());
    assert(g_test_config_read_eintr == 0);
    assert(chaos_dns_config_active_state()->rule_count == 1U);

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
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
    stamp = chaos_dns_config_observed_mtime();
    assert(chaos_dns_config_read_file(&size, stamp ^ UINT64_C(1)) == -1);
    assert(chaos_dns_config_read_file(&size, stamp) == 0);
    assert(size == strlen("# stable\n"));
    (void)unlink(CHAOS_DNS_CONFIG_PATH);
}

/**
 * @brief Reads the status file into @p buffer; returns 0 when it does not exist.
 */
static int read_status_file(char *buffer, size_t size)
{
    FILE *file = fopen(CHAOS_DNS_STATUS_PATH, "r");
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
 *   then exactly CHAOS_DNS_MAX_RULES valid rules followed by a comment; then one rule more.
 *
 * Expected observable behaviour: the invalid buffer reports line 4, "invalid rule" and
 *   the line before the parser cut the comment off; the full set parses with no error;
 *   the oversized set reports the first rule beyond the limit as "too many rules".
 */
static void test_parse_buffer_reports_rejected_line(void)
{
    static chaos_dns_rule_t rules[CHAOS_DNS_MAX_RULES];
    char buffer[] = "# header\n\ndns://api.example.com:LATENCY:20\nbogus-rule # typo\n";
    const chaos_status_error_t *error = chaos_dns_config_last_error();
    const size_t line_length = strlen("dns://api.example.com:LATENCY:20\n");
    size_t rule_count = 7U;
    size_t index;
    char *many;

    assert(chaos_dns_config_parse_buffer(buffer, rules, &rule_count) == -1);
    assert(error->line == 4U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_INVALID) == 0);
    assert(strcmp(error->text, "bogus-rule # typo") == 0);

    many = (char *)malloc((CHAOS_DNS_MAX_RULES + 1U) * line_length + 32U);
    assert(many != NULL);
    many[0] = '\0';
    for (index = 0U; index < CHAOS_DNS_MAX_RULES; ++index)
    {
        (void)strcat(many, "dns://api.example.com:LATENCY:20\n");
    }
    (void)strcat(many, "# trailing comment\n");
    assert(chaos_dns_config_parse_buffer(many, rules, &rule_count) == 0);
    assert(rule_count == CHAOS_DNS_MAX_RULES);
    assert(error->reason == NULL);

    many[0] = '\0';
    for (index = 0U; index <= CHAOS_DNS_MAX_RULES; ++index)
    {
        (void)strcat(many, "dns://api.example.com:LATENCY:20\n");
    }
    assert(chaos_dns_config_parse_buffer(many, rules, &rule_count) == -1);
    assert(rule_count == 0U);
    assert(error->line == CHAOS_DNS_MAX_RULES + 1U);
    assert(strcmp(error->reason, CHAOS_STATUS_REASON_TOO_MANY) == 0);
    assert(strcmp(error->text, "dns://api.example.com:LATENCY:20") == 0);
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

    chaos_dns_config_init();
    write_config_text("# header\nbogus-rule # typo\n", 51);
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=2\nreason=invalid rule\ntext=bogus-rule # typo\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    write_config_text("dns://api.example.com:LATENCY:20\n", 52);
    assert(chaos_dns_config_prepare() == 1);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(expected, sizeof(expected), "state=ok\nrules=1\npid=%ld\n", (long)getpid());
    assert(strcmp(status, expected) == 0);

    /* A file at the size limit is reported, not silently re-read. */
    {
        FILE *large = fopen(CHAOS_DNS_CONFIG_PATH, "w");
        size_t index;

        assert(large != NULL);
        for (index = 0U; index < CHAOS_DNS_MAX_CONFIG_BYTES; ++index)
        {
            assert(fputc('#', large) != EOF);
        }
        assert(fclose(large) == 0);
    }
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file too large\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);

    (void)unlink(CHAOS_DNS_CONFIG_PATH);

    /* A NUL byte rejects the file: the parser would stop there and drop every rule
     * after it, reporting state=ok. */
    {
        static const char text[] = "# rules\n\0\n";
        FILE *nul = fopen(CHAOS_DNS_CONFIG_PATH, "w");

        assert(nul != NULL);
        assert(fwrite(text, 1U, sizeof(text) - 1U, nul) == sizeof(text) - 1U);
        assert(fclose(nul) == 0);
    }
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file contains a NUL byte\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    (void)unlink(CHAOS_DNS_CONFIG_PATH);

    /* A rule file that cannot be read is reported too: a directory (EISDIR on read),
     * and, unless running as root, a file without read permission (EACCES on open). */
    assert(mkdir(CHAOS_DNS_CONFIG_PATH, 0700) == 0);
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)));
    (void)snprintf(
        expected,
        sizeof(expected),
        "state=error\nrules=0\nline=0\nreason=file unreadable\ntext=\npid=%ld\n",
        (long)getpid()
    );
    assert(strcmp(status, expected) == 0);
    assert(rmdir(CHAOS_DNS_CONFIG_PATH) == 0);
    if (geteuid() != 0)
    {
        FILE *locked = fopen(CHAOS_DNS_CONFIG_PATH, "w");

        assert(locked != NULL);
        assert(fclose(locked) == 0);
        assert(chmod(CHAOS_DNS_CONFIG_PATH, 0) == 0);
        assert(chaos_dns_config_prepare() == 0);
        assert(read_status_file(status, sizeof(status)));
        assert(strcmp(status, expected) == 0);
        (void)unlink(CHAOS_DNS_CONFIG_PATH);
    }
    assert(chaos_dns_config_prepare() == 0);
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

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_DNS_HITS_PREFIX, g_chaos_dns_hits_file);
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
    chaos_dns_config_state_t *state;

    chaos_dns_config_init();
    write_config_text("dns://api.example.com:LATENCY:20 # a\n", 61);
    assert(chaos_dns_config_prepare() == 1);
    state = (chaos_dns_config_state_t *)chaos_dns_config_active_state();
    assert(state->rule_count == 1U);
    assert(state->rules[0].hit == state->hits[0]);
    assert(strcmp(state->text[0], "dns://api.example.com:LATENCY:20 # a") == 0);
    chaos_hit_record(state->rules[0].hit);
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(strcmp(hits, "2\tdns://api.example.com:LATENCY:20 # a\n") == 0);

    write_config_text(
        "dns://api.example.com:LATENCY:20 # a\ndns://api.example.com:LATENCY:20 # b\n", 62
    );
    assert(chaos_dns_config_prepare() == 1);
    state = (chaos_dns_config_state_t *)chaos_dns_config_active_state();
    assert(state->rule_count == 2U);
    assert(state->hits[0]->count == 2U);
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\tdns://api.example.com:LATENCY:20 # a\n1\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );

    /* A hit that finds another thread writing is left pending, not lost. */
    g_chaos_dns_hits_writing = 1;
    chaos_hit_record(state->rules[1].hit);
    g_chaos_dns_hits_writing = 0;
    assert(g_chaos_dns_hits_pending == 1);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\tdns://api.example.com:LATENCY:20 # a\n1\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );

    /* Past the eager hits, a hit inside the interval is not written at once... */
    g_chaos_dns_hits_total = CHAOS_HITS_EAGER;
    g_chaos_dns_hits_last_ms = chaos_hits_now_ms();
    chaos_hit_record(state->rules[1].hit);
    assert(state->hits[1]->count == 3U);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\tdns://api.example.com:LATENCY:20 # a\n1\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );

    /* ...the exit report writes it, and a second one has nothing left to write. */
    chaos_dns_config_report_hits(NULL);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\tdns://api.example.com:LATENCY:20 # a\n3\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );
    assert(g_chaos_dns_hits_pending == 0);
    chaos_dns_config_report_hits(NULL);

    /* Past the eager hits, a hit once the interval is over is written at once. */
    g_chaos_dns_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    chaos_hit_record(state->rules[1].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "2\tdns://api.example.com:LATENCY:20 # a\n4\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );
    assert(g_chaos_dns_hits_pending == 0);
    g_chaos_dns_hits_total = 0U;

    /* A writer flag held when the process forked is released in the child, which
     * starts counting from zero. */
    g_chaos_dns_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* a once-only effect deciding in the parent */
    state->rules[1].hit->state = 2U; /* one that already fired */
    chaos_dns_config_after_fork();
    assert(g_chaos_dns_hits_writing == 0);
    assert(state->rules[0].hit->state == 1U);
    assert(state->rules[1].hit->state == 2U);
    state->rules[0].hit->state = 0U;
    state->rules[1].hit->state = 0U;
    chaos_hit_record(state->rules[0].hit);
    assert(read_hits_file(hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "1\tdns://api.example.com:LATENCY:20 # a\n0\tdns://api.example.com:LATENCY:20 # b\n"
        ) == 0
    );
    g_chaos_dns_hits_total = 0U;

    /* The exit report of a process that only inherited these counts writes nothing. */
    g_chaos_dns_hits_pending = 1;
    g_chaos_dns_hits_pid = (uint64_t)getpid() + 1U;
    chaos_dns_config_report_hits(NULL);
    assert(g_chaos_dns_hits_pending == 1);
    g_chaos_dns_hits_pending = 0;
    g_chaos_dns_hits_pid = (uint64_t)getpid();

    (void)snprintf(path, sizeof(path), "%s.%ld", CHAOS_DNS_HITS_PREFIX, g_chaos_dns_hits_file);
    (void)unlink(path);
    (void)unlink(CHAOS_DNS_CONFIG_PATH);
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
    chaos_dns_config_init();
    write_config_text("dns://api.example.com:LATENCY:20\n", 81);
    assert(chaos_dns_config_prepare() == 1);

    assert(chaos_clock_now_ns() != 0U);
    g_chaos_dns_check_interval_ns = UINT64_C(10000000000);
    g_chaos_dns_last_check_ns = chaos_clock_now_ns();
    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    assert(chaos_dns_config_prepare() == 1);

    g_chaos_dns_last_check_ns = chaos_clock_now_ns() - g_chaos_dns_check_interval_ns;
    assert(chaos_dns_config_prepare() == 0);
    g_chaos_dns_check_interval_ns = 0U;
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
    static chaos_dns_rule_t rules[CHAOS_DNS_MAX_RULES];
    char qualified[] = "dns://api.example.com:LATENCY:20 @first=3 @from=1000 @until=2000 @size>10 "
                       "@size<99 # owner\n";
    char unknown[] = "dns://api.example.com:LATENCY:20 @bogus=1\n";
    char lonely[] = "# header\n  @first=3\n";
    char backwards[] = "dns://api.example.com:LATENCY:20 @from=2000 @until=1000\n";
    char empty_first[] = "dns://api.example.com:LATENCY:20 @first=0\n";
    size_t count = 0U;

    assert(chaos_dns_config_parse_buffer(qualified, rules, &count) == 0);
    assert(count == 1U);
    assert(rules[0].policy.first == 3U);
    assert(rules[0].policy.from_ms == 1000);
    assert(rules[0].policy.until_ms == 2000);
    assert(rules[0].policy.has_size_above && rules[0].policy.size_above == 10U);
    assert(rules[0].policy.has_size_below && rules[0].policy.size_below == 99U);
    assert(rules[0].call_size == CHAOS_POLICY_NO_SIZE);

    assert(chaos_dns_config_parse_buffer(unknown, rules, &count) == -1);
    assert(
        strcmp(chaos_dns_config_last_error()->text, "dns://api.example.com:LATENCY:20 @bogus=1") ==
        0
    );
    assert(chaos_dns_config_parse_buffer(lonely, rules, &count) == -1);
    assert(chaos_dns_config_last_error()->line == 2U);
    assert(chaos_dns_config_parse_buffer(backwards, rules, &count) == -1);
    assert(chaos_dns_config_parse_buffer(empty_first, rules, &count) == -1);
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
    static const char rule[] = "dns://api.example.com:LATENCY:20\n";
    char rewritten[sizeof(rule)];
    char status[512];
    struct timespec times[2];
    struct stat first;
    FILE *file;
    const uint64_t interval = g_chaos_dns_check_interval_ns;

    g_chaos_dns_check_interval_ns = 0U;
    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    chaos_dns_config_init();
    file = fopen(CHAOS_DNS_CONFIG_PATH, "w");
    assert(file != NULL && fputs(rule, file) >= 0 && fclose(file) == 0);
    assert(stat(CHAOS_DNS_CONFIG_PATH, &first) == 0);
    assert(chaos_dns_config_prepare());
    assert(g_chaos_dns_config_provisional == 1);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=1\n") != NULL);

    /* Read again, nothing changed: the same snapshot stays. */
    assert(chaos_dns_config_prepare());
    assert(g_chaos_dns_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    /* The same bytes but the first commented out, written in place, same mtime. */
    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_DNS_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    /* An mtime outside the window: the load is final and not read again. */
    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_DNS_CONFIG_PATH, times, 0) == 0);
    assert(chaos_dns_config_prepare() == 0);
    assert(g_chaos_dns_config_provisional == 0);

    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    g_chaos_dns_check_interval_ns = interval;
}

/**
 * @brief Invariant: hits still pending when their interval is over are written by
 *        the next look at the rule file, not only by the next hit or at exit.
 */
static void test_pending_hits_written_after_interval(void)
{
    const uint64_t interval = g_chaos_dns_check_interval_ns;

    g_chaos_dns_check_interval_ns = 0U;
    g_chaos_dns_hits_pid = (uint64_t)getpid();
    g_chaos_dns_hits_pending = 1;
    g_chaos_dns_hits_last_ms = chaos_hits_now_ms();
    (void)chaos_dns_config_prepare();
    assert(g_chaos_dns_hits_pending == 1);
    g_chaos_dns_hits_last_ms = chaos_hits_now_ms() - CHAOS_HITS_INTERVAL_MS;
    (void)chaos_dns_config_prepare();
    assert(g_chaos_dns_hits_pending == 0);
    g_chaos_dns_check_interval_ns = interval;
}

/**
 * @brief Invariant: every parser and matcher refuses what it cannot handle instead of
 *   reading past it: missing arguments, over-long or malformed selectors and values,
 *   rule lines whose fields are missing, and effects a selector domain does not allow.
 *
 * Triggering condition: the helpers called directly with NULL and boundary inputs, and
 *   `chaos_dns_config_parse_line` with one malformed line per rejection.
 *
 * Expected observable behaviour: each call reports failure (0, -1, NULL, INVALID or
 *   0x7fffffff) and leaves its output alone; the accepted forms (`dns://\*`, the
 *   remaining EAI names, `any`) parse to their values.
 */
static void test_rejections(void)
{
    chaos_dns_selector_t selector;
    chaos_dns_rule_t rule;
    chaos_dns_rule_t rules[2];
    char payload[CHAOS_DNS_MAX_VALUE];
    char long_text[CHAOS_DNS_MAX_VALUE + 8U];
    char line[CHAOS_DNS_MAX_VALUE + 64U];
    size_t count = 7U;
    double probability = 0.0;
    unsigned int value = 0U;
    unsigned int rank = 9U;

    /* Helpers given nothing to work on. */
    chaos_dns_config_reset_state(NULL, 1);
    assert(chaos_dns_trim(NULL) == NULL);
    chaos_dns_strip_comment(NULL);
    assert(!chaos_dns_ascii_case_equal(NULL, "a") && !chaos_dns_ascii_case_equal("a", NULL));
    assert(
        !chaos_dns_ascii_case_ends_with(NULL, "a") && !chaos_dns_ascii_case_ends_with("a", NULL)
    );
    assert(!chaos_dns_ascii_case_ends_with("com", "example.com"));
    assert(chaos_dns_parse_latency(NULL, &value) == -1 && chaos_dns_parse_latency("1", NULL) == -1);
    assert(chaos_dns_parse_limit(NULL, &value) == -1 && chaos_dns_parse_limit("1", NULL) == -1);
    assert(chaos_dns_parse_family_filter(NULL) == CHAOS_DNS_FAMILY_INVALID);
    assert(chaos_dns_parse_family_filter("any") == CHAOS_DNS_FAMILY_ANY);
    assert(chaos_dns_parse_gai_name(NULL) == 0x7fffffff);
    assert(chaos_dns_parse_gai_name("EAI_NONAME") == EAI_NONAME);
    assert(chaos_dns_parse_gai_name("EAI_MEMORY") == EAI_MEMORY);
    assert(chaos_dns_parse_gai_name("EAI_SYSTEM") == EAI_SYSTEM);
    assert(chaos_dns_copy_text_value(NULL, payload, sizeof(payload)) == -1);
    assert(chaos_dns_copy_text_value("a", NULL, sizeof(payload)) == -1);
    assert(chaos_dns_copy_text_value("a", payload, 0U) == -1);
    assert(chaos_dns_parse_payload_probability(NULL, payload, sizeof(payload), &probability) == -1);
    assert(chaos_dns_parse_payload_probability("a", NULL, sizeof(payload), &probability) == -1);
    assert(chaos_dns_parse_payload_probability("a", payload, sizeof(payload), NULL) == -1);
    assert(!chaos_dns_override_token_valid(NULL) && !chaos_dns_override_token_valid(""));
    assert(!chaos_dns_validate_override_value(NULL));
    assert(chaos_dns_config_read_file(NULL, 0U) == -1);
    assert(!chaos_dns_split_rule_fields(NULL, NULL, NULL, NULL));
    assert(chaos_dns_config_parse_buffer(NULL, rules, &count) == -1);
    assert(chaos_dns_config_parse_line(NULL, &rule) == -1);
    assert(chaos_dns_config_select_rule(NULL, 0U, CHAOS_DNS_EFFECT_GAI, "a", &rule) == 0);

    /* A payload with nothing before the '@', and values too long for their buffers. */
    assert(
        chaos_dns_parse_payload_probability("@0.5", payload, sizeof(payload), &probability) == -1
    );
    assert(
        chaos_dns_parse_payload_probability(" @0.5", payload, sizeof(payload), &probability) == -1
    );
    assert(chaos_dns_parse_payload_probability("a@", payload, sizeof(payload), &probability) == -1);
    memset(long_text, 'x', sizeof(long_text) - 1U);
    long_text[sizeof(long_text) - 1U] = '\0';
    long_text[sizeof(long_text) - 3U] = '@';
    assert(
        chaos_dns_parse_payload_probability(long_text, payload, sizeof(payload), &probability) == -1
    );
    long_text[sizeof(long_text) - 3U] = 'x';
    long_text[60] = '\0';
    assert(!chaos_dns_override_token_valid(long_text));
    long_text[60] = 'x';

    /* Selectors: none, unknown scheme, the lookup wildcard, malformed reverse bodies. */
    assert(!chaos_dns_selector_parse(NULL, &selector) && !chaos_dns_selector_parse("", &selector));
    assert(!chaos_dns_selector_parse("*", NULL));
    assert(!chaos_dns_selector_parse("http://example.com", &selector));
    assert(chaos_dns_selector_parse("dns://*", &selector));
    assert(selector.kind == CHAOS_DNS_SELECTOR_ANY);
    assert(selector.domain == CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP);
    assert(!chaos_dns_parse_reverse_selector_body(NULL, &selector));
    assert(!chaos_dns_parse_reverse_selector_body("1.2.3.4", NULL));
    assert(!chaos_dns_selector_parse("rdns://", &selector));
    assert(!chaos_dns_selector_parse("rdns://[]", &selector));
    assert(!chaos_dns_selector_parse("rdns://[::1", &selector));
    (void)snprintf(line, sizeof(line), "rdns://[%.60s]", long_text);
    assert(!chaos_dns_selector_parse(line, &selector));
    (void)snprintf(line, sizeof(line), "rdns://%.60s", long_text);
    assert(!chaos_dns_selector_parse(line, &selector));

    /* Matching: nothing to match, a kind no domain produces, a suffix without its dot. */
    assert(!chaos_dns_selector_matches_domain(NULL, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "a", &rank));
    assert(rank == 0U);
    assert(chaos_dns_selector_parse("rdns://*", &selector));
    selector.kind = CHAOS_DNS_SELECTOR_SUFFIX;
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "127.0.0.1", NULL
    ));
    assert(chaos_dns_selector_parse("dns://*.example.com", &selector));
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.net", NULL
    ));
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "fooexample.com", NULL
    ));

    /* Effects: no selector, a domain no parser produces. */
    assert(!chaos_dns_effect_allowed(NULL, CHAOS_DNS_EFFECT_GAI));
    selector.domain = (chaos_dns_selector_domain_t)99;
    assert(!chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_GAI));

    /* Rule lines missing a field, or with a value their effect cannot take. */
    {
        static const char *const bad[] = {
            "nope:EAI_AGAIN:1.0",
            "dns://api.example.com",
            "dns://api.example.com:EAI_AGAIN",
            "rdns://[::1:EAI_AGAIN:1.0",
            "dns://api.example.com::1.0",
            "dns://*bad:EAI_AGAIN:1.0",
            "dns://api.example.com:LATENCY:@0.5",
            "dns://api.example.com:REWRITE:@0.5",
            "dns://api.example.com:SERVICE:@0.5",
            "dns://api.example.com:OVERRIDE:@0.5",
            "dns://api.example.com:FILTER_FAMILY:@0.5",
            "rdns://127.0.0.1:FILTER_FAMILY:inet4",
            "dns://api.example.com:LIMIT:@0.5",
            "rdns://127.0.0.1:SHUFFLE:1.0",
            "dns://api.example.com:BOGUS:1.0",
        };
        size_t index;

        for (index = 0U; index < sizeof(bad) / sizeof(bad[0]); ++index)
        {
            (void)snprintf(line, sizeof(line), "%s", bad[index]);
            assert(chaos_dns_config_parse_line(line, &rule) == -1);
        }
    }

    /* Two rules of one rank: the longer selector wins, whichever comes first. */
    (void)snprintf(line, sizeof(line), "dns://*.example.com:SHUFFLE:1.0");
    assert(chaos_dns_config_parse_line(line, &rules[0]) == 1);
    (void)snprintf(line, sizeof(line), "dns://*.api.example.com:SHUFFLE:1.0");
    assert(chaos_dns_config_parse_line(line, &rules[1]) == 1);
    assert(chaos_dns_config_select_rule(
        rules, 2U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.api.example.com", &rule
    ));
    assert(strcmp(rule.selector.text, "api.example.com") == 0);
    rules[0] = rules[1];
    (void)snprintf(line, sizeof(line), "dns://*.example.com:SHUFFLE:1.0");
    assert(chaos_dns_config_parse_line(line, &rules[1]) == 1);
    assert(chaos_dns_config_select_rule(
        rules, 2U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.api.example.com", &rule
    ));
    assert(strcmp(rule.selector.text, "api.example.com") == 0);
    /* A less specific rank listed later does not replace a more specific one. */
    (void)snprintf(line, sizeof(line), "*:SHUFFLE:1.0");
    assert(chaos_dns_config_parse_line(line, &rules[1]) == 1);
    assert(chaos_dns_config_select_rule(
        rules, 2U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.api.example.com", &rule
    ));
    assert(rule.selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(count == 7U);
}

/**
 * @brief Invariant: the value parsers and selector checks accept exactly what fits and
 *   reject the first value beyond a limit, trailing garbage, empty parts and malformed
 *   address tokens; every effect rejects a value it cannot parse.
 *
 * Expected observable behaviour:
 * - latency 4294967295 and limit 4294967295 accepted; 4294967296, "12x" and limit 0
 *   rejected.
 * - "ipv4"/"ipv6" are the INET4/INET6 families.
 * - names compare equal only at equal length, either way round.
 * - a suffix selector with nothing after its `*.`, and a name longer than the
 *   selector buffer, are not selectors.
 * - an empty name or a lookup selector asked about a reverse query does not match;
 *   matching works the same with or without a rank output.
 * - "[" alone, "[::1" and an empty list element are not override addresses.
 * - the mtime sentinels never come out of normalisation unchanged.
 * - "*x...", a bracketed reverse address without ':' after ']', an empty value and
 *   each effect with an unparseable value reject the line.
 * - a buffer whose last line has no newline still yields that rule.
 * - reverse lookups allow only GAI, LATENCY, REWRITE and SERVICE.
 * - match and match_reverse with an empty name or no output rule match nothing.
 */
static void test_parse_boundaries(void)
{
    static chaos_dns_rule_t rules[2];
    char payload[4];
    /* The parsers trim the text after the number in place, so it must be writable. */
    char latency_garbage[] = "12x";
    char limit_garbage[] = "12x";
    char long_name[CHAOS_DNS_MAX_TEXT + 16U];
    char line[CHAOS_DNS_MAX_TEXT + 64U];
    char buffer[] = "# rules\ndns://api.example.com:EAI_AGAIN:1.0";
    char *selector_text = NULL;
    char *effect_text = NULL;
    unsigned int value = 0U;
    unsigned int rank = 9U;
    size_t count = 0U;
    chaos_dns_selector_t selector;
    chaos_dns_rule_t rule;

    assert(chaos_dns_parse_latency("4294967295", &value) == 0 && value == 4294967295U);
    assert(chaos_dns_parse_latency("4294967296", &value) == -1);
    assert(chaos_dns_parse_latency(latency_garbage, &value) == -1);
    assert(chaos_dns_parse_limit("4294967295", &value) == 0 && value == 4294967295U);
    assert(chaos_dns_parse_limit("4294967296", &value) == -1);
    assert(chaos_dns_parse_limit(limit_garbage, &value) == -1);
    assert(chaos_dns_parse_limit("0", &value) == -1);
    assert(chaos_dns_parse_limit("x", &value) == -1);
    assert(value == 4294967295U);

    assert(chaos_dns_parse_family_filter("ipv4") == CHAOS_DNS_FAMILY_INET4);
    assert(chaos_dns_parse_family_filter("ipv6") == CHAOS_DNS_FAMILY_INET6);
    assert(chaos_dns_copy_text_value("abcd", payload, sizeof(payload)) == -1);
    assert(chaos_dns_copy_text_value("abc", payload, sizeof(payload)) == 0);

    assert(chaos_dns_ascii_case_equal("Example.COM", "example.com"));
    assert(!chaos_dns_ascii_case_equal("example.com", "example.co"));
    assert(!chaos_dns_ascii_case_equal("example.co", "example.com"));

    assert(!chaos_dns_selector_parse("dns://*.", &selector));
    memset(long_name, 'a', sizeof(long_name) - 1U);
    long_name[sizeof(long_name) - 1U] = '\0';
    (void)snprintf(line, sizeof(line), "dns://%s", long_name);
    assert(!chaos_dns_selector_parse(line, &selector));

    assert(chaos_dns_selector_parse("dns://api.example.com", &selector));
    assert(
        !chaos_dns_selector_matches_domain(&selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "", &rank)
    );
    assert(
        !chaos_dns_selector_matches_domain(&selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, NULL, &rank)
    );
    assert(rank == 0U);
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_REVERSE, "api.example.com", NULL
    ));
    assert(!chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.co", NULL
    ));
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "API.example.com", NULL
    ));
    assert(chaos_dns_selector_parse("dns://*.example.com", &selector));
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", NULL
    ));
    assert(chaos_dns_selector_parse("*", &selector));
    assert(chaos_dns_selector_matches_domain(
        &selector, CHAOS_DNS_SELECTOR_DOMAIN_LOOKUP, "api.example.com", NULL
    ));

    assert(!chaos_dns_override_token_valid("["));
    assert(!chaos_dns_override_token_valid("[]"));
    assert(!chaos_dns_override_token_valid("[::1"));
    assert(chaos_dns_override_token_valid("[::1]"));
    assert(!chaos_dns_validate_override_value("192.0.2.1,,192.0.2.2"));
    assert(chaos_dns_validate_override_value("192.0.2.1, 192.0.2.2"));

    assert(
        chaos_dns_config_normalize_mtime_hash(CHAOS_DNS_MTIME_MISSING) != CHAOS_DNS_MTIME_MISSING
    );
    assert(
        chaos_dns_config_normalize_mtime_hash(CHAOS_DNS_MTIME_RELOADING) !=
        CHAOS_DNS_MTIME_RELOADING
    );

    {
        static const char *const bad[] = {
            "*x:EAI_AGAIN:1.0",
            "rdns://[::1]x:EAI_AGAIN:1.0",
            "dns://api.example.com:LATENCY: ",
            "dns://api.example.com:EAI_AGAIN:2",
            "dns://api.example.com:LATENCY:soon",
            "dns://api.example.com:LIMIT:0",
            "dns://api.example.com:SHUFFLE:2",
        };
        size_t index;

        for (index = 0U; index < sizeof(bad) / sizeof(bad[0]); ++index)
        {
            (void)snprintf(line, sizeof(line), "%s", bad[index]);
            assert(chaos_dns_config_parse_line(line, &rule) == -1);
        }
    }
    (void)snprintf(line, sizeof(line), "dns://api.example.com:EAI_AGAIN:1.0");
    assert(!chaos_dns_split_rule_fields(line, &selector_text, &effect_text, NULL));
    assert(!chaos_dns_split_rule_fields(line, &selector_text, NULL, NULL));
    assert(!chaos_dns_split_rule_fields(line, NULL, NULL, NULL));
    assert(chaos_dns_config_parse_line(line, NULL) == -1);

    assert(chaos_dns_config_parse_buffer(buffer, rules, &count) == 0);
    assert(count == 1U && rules[0].effect == CHAOS_DNS_EFFECT_GAI);
    assert(chaos_dns_config_parse_buffer(buffer, NULL, &count) == -1);
    assert(chaos_dns_config_parse_buffer(buffer, rules, NULL) == -1);
    assert(!chaos_dns_config_select_rule(rules, 1U, CHAOS_DNS_EFFECT_GAI, NULL, &rule));
    assert(!chaos_dns_config_select_rule(rules, 1U, CHAOS_DNS_EFFECT_GAI, "api.example.com", NULL));

    assert(chaos_dns_selector_parse("rdns://127.0.0.1", &selector));
    assert(chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_GAI));
    assert(chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_LATENCY));
    assert(chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_REWRITE));
    assert(chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_SERVICE));
    assert(!chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_OVERRIDE));

    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, "", &rule));
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, "api.example.com", NULL));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, "", &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, "127.0.0.1", NULL));
}

/**
 * @brief Invariant: opening the rule file is retried after a signal, a missing
 *   permission is reported as lasting, and other open errors as retryable; with
 *   no rule file, nothing matches.
 *
 * Triggering condition: the first open fails with EINTR; then every open fails with
 *   EACCES, EPERM, then EMFILE; finally the file is removed and a lookup matched.
 *
 * Expected observable behaviour: the interrupted open is retried and the file read
 *   (0, its full size); EACCES and EPERM return -3; EMFILE returns -1; without a
 *   rule file match and match_reverse return 0.
 */
static void test_open_errors(void)
{
    size_t size = 0U;
    uint64_t stamp;
    chaos_dns_rule_t rule;

    write_config_text("# open errors\n", 43);
    stamp = chaos_dns_config_observed_mtime();
    g_test_config_open_eintr = 1;
    assert(chaos_dns_config_read_file(&size, stamp) == 0);
    assert(g_test_config_open_eintr == 0);
    assert(size == strlen("# open errors\n"));

    g_test_config_open_errno = EACCES;
    assert(chaos_dns_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EPERM;
    assert(chaos_dns_config_read_file(&size, stamp) == -3);
    g_test_config_open_errno = EMFILE;
    assert(chaos_dns_config_read_file(&size, stamp) == -1);
    g_test_config_open_errno = 0;

    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_GAI, "api.example.com", &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_GAI, "127.0.0.1", &rule));
}

int main(void)
{
    /* Look at the rule file on every call; the throttle has its own test. */
    g_chaos_dns_check_interval_ns = 0U;
    test_parse_buffer_reports_rejected_line();
    test_prepare_reports_status();
    test_hits_are_counted_and_reported();
    test_rule_file_check_is_throttled();
    test_rule_qualifiers();
    test_read_file_rejects_changed_file();
    test_helper_functions();
    test_selector_matching();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_rejections();
    test_prepare_and_match();
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
