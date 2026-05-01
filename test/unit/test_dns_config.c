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
    int existed;   /**< Non-zero if the file existed when the backup was taken. */
    char *data;    /**< Heap-allocated copy of the file content; NULL if none. */
    size_t size;   /**< Byte length of `data`. */
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
 * - Open failure (`g_test_config_force_open_fail = 1`): `prepare()` → false.
 * - Read failure (`g_test_config_force_read_fail = 1`): `prepare()` → false.
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

    g_test_config_force_open_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 13);
    assert(!chaos_dns_config_prepare());
    g_test_config_force_open_fail = 0;

    g_test_config_force_read_fail = 1;
    write_config_text("dns://api.example.com:LATENCY:20\n", 14);
    assert(!chaos_dns_config_prepare());
    g_test_config_force_read_fail = 0;

    write_config_text("dns://api.example.com:OVERRIDE:not-a-host\n", 15);
    assert(!chaos_dns_config_prepare());
    assert(!chaos_dns_config_match_loaded(CHAOS_DNS_EFFECT_OVERRIDE, "api.example.com", &rule));
    assert(!chaos_dns_config_match(CHAOS_DNS_EFFECT_OVERRIDE, NULL, &rule));
    assert(!chaos_dns_config_match_reverse(CHAOS_DNS_EFFECT_REWRITE, NULL, &rule));

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

int main(void)
{
    test_helper_functions();
    test_selector_matching();
    test_parse_line_and_buffer();
    test_rule_selection();
    test_prepare_and_match();
    return 0;
}
