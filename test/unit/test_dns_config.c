/**
 * @file test_dns_config.c
 * @brief Unit tests for the libchaos-dns rule file: parsing, selector matching, rule
 *   selection, reload, status file and hits file.
 *
 * @details
 * Unit under test: `src/dns/chaos_dns_config.c`. The suite proves:
 * - grammar: `selector:effect:value[@probability]` with `*`, `dns://host`, `dns://\*.suffix`,
 *   `rdns://ip` and `rdns://[v6]` selectors; every effect parses its value; numeric limits
 *   (latency and LIMIT up to 4294967295, LIMIT >= 1) and buffer limits reject the first value
 *   past them; reverse selectors accept only GAI, LATENCY, REWRITE and SERVICE; qualifiers
 *   (`@first`, `@from`, `@until`, `@size`) land in the rule's policy and a bad one rejects
 *   the line; a rejected line fails the whole file;
 * - selection: the most specific selector wins (exact rank 3 > suffix 2 > any 1), the longer
 *   suffix wins a tie whatever the order, and lookup and reverse rules never cross;
 * - reload: the change stamp covers mtime, size and inode; one reloader at a time (a
 *   `RELOADING` claim is never joined, and only the atfork handler releases one inherited by a
 *   fork child); a failed open or read keeps the active rules and retries; a file changed
 *   while being read is discarded; a load of a just-written file is provisional and re-read
 *   so an in-place rewrite within one mtime tick is seen; EINTR on open and read is retried;
 *   EACCES/EPERM on open and EISDIR on read are lasting failures; errno is preserved; the
 *   file is looked at no more often than the check interval once rules are loaded;
 * - reporting: every load writes the status file (`state=ok` with the rule count, or
 *   `state=error` with line, reason and text) and a missing rule file removes it; hits are
 *   counted per rule, survive a reload for rules still present, are written eagerly for the
 *   first `CHAOS_HITS_EAGER` (64) hits and then at most every `CHAOS_HITS_INTERVAL_MS`
 *   (100 ms), are flushed at exit, and restart from zero in a fork child.
 *
 * Seams:
 * - `CHAOS_CONFIG_FILE_OPEN/READ/CLOSE` are defined before the include so the rule file is
 *   read through libc names instead of raw syscalls; `open`, `read` and `close` are then
 *   macro-redirected to stubs that inject EINTR, a chosen open errno, ENOENT, or EIO on the
 *   fake fd 9124 (an fd number the test binary never reaches), and otherwise pass through.
 * - `chaos_dns_atomic_cas_u64` is redirected so a lost reload race is deterministic.
 * - `CHAOS_RACY_WINDOW_MS` is raised from 20 ms to 5000 ms (see below).
 * - Tests use the real rule file path `CHAOS_DNS_CONFIG_PATH` (`/tmp/.chaos-dns.conf`), set
 *   explicit mtimes with futimens() so every rewrite is a distinct change, and back up and
 *   restore any file that was there. `main()` sets the check interval to 0 so every call
 *   looks at the file; the throttle has its own test.
 *
 * Out of scope: the interposed entry points (`test_chaos_dns.c`), the effect helpers
 * (`test_dns_actions.c`) and the constructor (`test_dns_runtime.c`).
 */

/* Production reads the rule file with raw syscalls on Linux; route it through the libc names
 * so the open/read/close stubs below can intercept it. */
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)

/* A rule file counts as just written for 5000 ms, not 20 ms: the racy-rewrite test restores
 * an earlier mtime and must still find it recent on a slow or loaded machine. */
#define CHAOS_RACY_WINDOW_MS 5000
#include "../support/test_dns_support.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>

CHAOS_DNS_DEFINE_TEST_GLOBALS();

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

/** @brief Non-zero makes every CAS on the reload stamp fail, as when another thread won. */
static int g_test_config_force_cas_fail = 0;

/** @brief Fake fd for the read-failure path; far above any fd this test binary opens. */
static const int g_test_config_fake_fd = 9124;

/**
 * @brief open() replacement for the config source.
 *
 * Fault flags are checked in order: pending EINTR, `g_test_config_open_errno`, ENOENT, then
 * the fake fd. Otherwise it calls the real open(), forwarding the mode only with O_CREAT
 * (off Linux the status writer creates its file through open(), redirected here too).
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

/** @brief read() replacement: pending EINTR first, EIO on the fake fd, else the real read(). */
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

/** @brief close() replacement: succeeds on the fake fd without a syscall, else real close(). */
static int chaos_dns_test_config_close(int fd)
{
    if (g_test_config_force_read_fail != 0 && fd == g_test_config_fake_fd)
    {
        return 0;
    }
    return close(fd);
}

/** @brief CAS replacement: fails while `g_test_config_force_cas_fail` is set, else a real CAS. */
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

/** @brief Saved content of a rule file, so tests leave the developer's file as they found it. */
typedef struct chaos_dns_test_file_backup
{
    int existed; /**< Non-zero if the file existed when the backup was taken. */
    char *data;  /**< Heap-allocated copy of the file content; NULL if none. */
    size_t size; /**< Byte length of `data`. */
} chaos_dns_test_file_backup_t;

/** @brief Saves the whole of @p path into @p backup, or records that it does not exist. */
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

/** @brief Rewrites @p path from @p backup, or removes it when it did not exist. */
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

/** @brief Frees the saved content; the file itself is not touched. */
static void free_backup(chaos_dns_test_file_backup_t *backup)
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
 * @brief Proves the lexical and value helpers on one valid and one invalid input each.
 *
 * @details Covers blank detection, trimming (CR and LF included), comment stripping,
 * ASCII case-insensitive equality and suffix tests, probability (2.0 rejected), latency,
 * LIMIT (0 rejected), family names, GAI names (unknown yields the 0x7fffffff sentinel), text
 * values (empty rejected), `value@probability` payloads, OVERRIDE address lists (v4 and
 * bracketed v6), and the three-field split. The change stamp of a missing file is
 * `CHAOS_DNS_MTIME_MISSING`, the `UNKNOWN` sentinel never survives normalisation, and an
 * all-zero stat still hashes to a non-zero stamp.
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
 * @brief Proves each selector form parses to its kind and domain and matches with its rank.
 *
 * @details `*` is ANY (rank 1); `dns://host` is EXACT (rank 3) and case-insensitive;
 * `dns://\*.suffix` is SUFFIX (rank 2) and requires a label before the suffix, so the bare
 * domain does not match. `rdns://ip` is EXACT in the reverse domain and never matches a
 * lookup; `rdns://[::1]` stores the address without brackets; `rdns://\*` is reverse ANY.
 * An empty host, a `*` not followed by `.`, a non-IP reverse body and a reverse suffix are
 * rejected.
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
 * @brief Proves one line per effect parses into the right rule fields, and a file of all of
 *   them yields every rule.
 *
 * @details A blank line returns 0 (no rule). GAI takes an `EAI_*` name as the effect field
 * and the probability as the value; LATENCY, REWRITE, SERVICE, OVERRIDE, FILTER_FAMILY and
 * LIMIT take `value[@probability]`; SHUFFLE takes only a probability. Reverse selectors parse
 * GAI and SERVICE. Rejected with -1: OVERRIDE with a host name instead of an IP literal, an
 * unknown family, and OVERRIDE or LIMIT on a reverse selector (getnameinfo returns no list to
 * replace or truncate).
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
 * @brief Proves selection picks the most specific matching selector regardless of file order.
 *
 * @details The rules are listed least specific first, so a first-match implementation would
 * fail. Lookups: exact beats suffix beats any. Reverse lookups: the exact address beats
 * `rdns://\*`, which catches any other address.
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
 * @brief Proves the reload sequence end to end: absent file, forward and reverse rules, a
 *   lost reload race, failed I/O, and an invalid file.
 *
 * @details
 * - No rule file: prepare() returns 0.
 * - A forward REWRITE rule matches its effect and name only, never a reverse query.
 * - A changed file (new mtime) replaces it with a reverse rule.
 * - A lost CAS keeps the active snapshot and still reports rules loaded.
 * - A failed open (ENOENT) or read (EIO) after the stat keeps the active rules; the next
 *   call retries and loads the new file.
 * - An invalid file is fail-open: no rule of the new file or of the previous one matches.
 * - A NULL name matches nothing.
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
 * @brief Proves a caller that sees a reload in progress uses the current snapshot and does not
 *   start a second reload.
 *
 * @details The cached stamp is set to `CHAOS_DNS_MTIME_RELOADING` (another thread holds the
 * claim). A CAS from RELOADING to RELOADING would succeed, so without the explicit check two
 * threads would parse into the same inactive snapshot through the same shared read buffer.
 * The marker and the active index must stay untouched.
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
 * @brief Proves a failed read keeps the active rules and releases the claim with the previous
 *   stamp, so the next call retries.
 *
 * @details Advancing the stamp would make the failure permanent: the file would not change
 * again and the new rules would never load. Leaving `RELOADING` would block every future
 * reload. The second prepare() must load both rules.
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
    assert(chaos_dns_config_hash_mtime(&base) == chaos_dns_config_hash_mtime(&other));

    other.st_size = 20;
    assert(chaos_dns_config_hash_mtime(&base) != chaos_dns_config_hash_mtime(&other));

    other = base;
    other.st_ino = 101;
    assert(chaos_dns_config_hash_mtime(&base) != chaos_dns_config_hash_mtime(&other));
}

/**
 * @brief Proves a reload claim is never taken over by prepare(), and that the fork child
 *   handler releases an inherited one and resets per-process state.
 *
 * @details A vfork child shares the parent's memory while the parent's reloading thread is
 * still running, so prepare() must leave a `RELOADING` claim alone whoever made it. Only
 * `chaos_dns_config_after_fork()` (pthread_atfork child handler; the reloading thread does not
 * exist in a fork child) resets it to `UNKNOWN`. It also zeroes the TLS PRNG state so pre-fork
 * workers do not all draw the parent's sequence, and records the child's pid as owner of the
 * hits. The next prepare() then loads the file; a second handler call with no claim leaves the
 * published stamp alone. With a claim set, prepare() returns the current snapshot before the
 * CAS, so a forced CAS failure makes no difference.
 */
static void test_fork_takes_over_orphaned_reload(void)
{
    chaos_dns_test_file_backup_t backup;

    backup_file(CHAOS_DNS_CONFIG_PATH, &backup);
    chaos_dns_config_init();
    write_config_text("dns://api.example.com:LATENCY:20\n", 60);

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

    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    g_test_config_force_cas_fail = 1;
    assert(chaos_dns_config_prepare());
    g_test_config_force_cas_fail = 0;

    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_RELOADING;
    (void)chaos_dns_config_prepare();
    assert(g_chaos_dns_cached_mtime == CHAOS_DNS_MTIME_RELOADING);
    g_chaos_dns_cached_mtime = CHAOS_DNS_MTIME_UNKNOWN;

    restore_file(CHAOS_DNS_CONFIG_PATH, &backup);
    free_backup(&backup);
}

/**
 * @brief Proves prepare() preserves errno, both when stat() fails with ENOENT and when the
 *   file is opened and read.
 *
 * @details prepare() runs inside interposed calls; a wrapped getaddrinfo that succeeds must
 * not leave the library's own ENOENT for a caller that inspects errno.
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
 * @brief Proves a read interrupted by a signal (EINTR) is retried and the rules load, instead
 *   of being treated as a read failure that defers the load.
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
 * @brief Proves a file whose stamp after the read differs from the stamp that started the
 *   reload is rejected (-1), so a half-old, half-new copy is never parsed.
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

/** @brief Reads the status file into @p buffer (NUL-terminated); 0 when it does not exist. */
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
 * @brief Proves a rejected line is recorded by number, reason and original text, and that the
 *   rule limit counts rules, not lines.
 *
 * @details Line 4 (comments and blank lines count) is reported as "invalid rule" with its
 * comment still attached, so the status file shows the line as the user wrote it.
 * `CHAOS_DNS_MAX_RULES` (256) rules followed by a comment parse cleanly and clear the last
 * error; one rule more is rejected as "too many rules" at line 257 with a rule count of 0.
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
 * @brief Proves every load writes its outcome to the status file in the exact documented
 *   format, and that a missing rule file removes it.
 *
 * @details Checked outcomes, each stamped with this pid: an invalid line 2 (`state=error`
 * with line, reason and text); a valid file (`state=ok`, `rules=1`); a file of exactly
 * `CHAOS_DNS_MAX_CONFIG_BYTES` (256 KiB), rejected as "file too large" because a read that
 * fills the buffer cannot tell a complete file from a truncated one; a NUL byte ("file
 * contains a NUL byte"), since the parser would stop there and report `state=ok` for a
 * truncated rule set; a directory (EISDIR on read) and, unless running as root, a mode-0
 * file (EACCES on open), both "file unreadable".
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

/** @brief Reads this process's hits file into @p buffer (NUL-terminated); 0 when absent. */
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
 * @brief Proves the hits file lifecycle: per-rule counts with the rule text, counts kept
 *   across a reload, write throttling, the exit flush, and the fork reset.
 *
 * @details
 * - Each line is `count<TAB>rule text` with the comment kept; a rule still in the file after
 *   a reload keeps its count (2), a new rule starts at 0.
 * - A hit that finds another thread writing (`g_chaos_dns_hits_writing`) is left pending, not
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

    g_chaos_dns_hits_writing = 1;
    state->rules[0].hit->state = 3U; /* deciding: owner thread is gone */
    state->rules[1].hit->state = 2U; /* fired: must stay fired */
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
 * @brief Proves qualifiers are stripped from the rule and parsed into its policy, and that a
 *   bad qualifier rejects the line.
 *
 * @details All four qualifier kinds before a comment land in the policy, and a DNS rule
 * carries no byte count (`CHAOS_POLICY_NO_SIZE`), so a `@size` gate never passes for it.
 * Rejected: an unknown qualifier (reported with its full text), a qualifier with no rule
 * before it, `@until` not after `@from`, and `@first=0`.
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

    assert(chaos_dns_config_prepare());
    assert(g_chaos_dns_config_content == chaos_config_content_hash(rule, sizeof(rule) - 1U));

    (void)memcpy(rewritten, rule, sizeof(rule));
    rewritten[0] = '#';
    file = fopen(CHAOS_DNS_CONFIG_PATH, "r+");
    assert(file != NULL && fputs(rewritten, file) >= 0 && fflush(file) == 0);
    times[0] = first.st_atim;
    times[1] = first.st_mtim;
    assert(futimens(fileno(file), times) == 0 && fclose(file) == 0);
    assert(chaos_dns_config_prepare() == 0);
    assert(read_status_file(status, sizeof(status)) && strstr(status, "rules=0\n") != NULL);

    times[1].tv_sec = 60;
    times[1].tv_nsec = 0L;
    assert(utimensat(AT_FDCWD, CHAOS_DNS_CONFIG_PATH, times, 0) == 0);
    assert(chaos_dns_config_prepare() == 0);
    assert(g_chaos_dns_config_provisional == 0);

    (void)unlink(CHAOS_DNS_CONFIG_PATH);
    g_chaos_dns_check_interval_ns = interval;
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
 * @brief Proves every parser and matcher rejects NULL, over-long and malformed input instead
 *   of reading past a buffer, and that ties in selection go to the longer suffix.
 *
 * @details
 * - NULL arguments to every helper fail (0, -1, NULL, `CHAOS_DNS_FAMILY_INVALID` or
 *   0x7fffffff); `any`, `dns://\*` and the remaining `EAI_*` names are accepted.
 * - A payload with nothing before or after `@`, and values longer than their buffers, fail.
 * - Selectors: empty, unknown scheme, empty or unterminated brackets, and over-long reverse
 *   bodies fail. A suffix must match at a label boundary (`fooexample.com` does not match
 *   `\*.example.com`) and a reverse selector forced to SUFFIX kind matches nothing.
 * - A rule line missing a field, with an empty or unparseable value, an unknown effect, or an
 *   effect the reverse domain does not allow (FILTER_FAMILY, SHUFFLE) returns -1.
 * - Of two suffix rules the longer wins in either order, and a later ANY rule does not
 *   displace a SUFFIX match.
 * - `count` stays 7: a rejected buffer never wrote it.
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

    assert(!chaos_dns_effect_allowed(NULL, CHAOS_DNS_EFFECT_GAI));
    selector.domain = (chaos_dns_selector_domain_t)99;
    assert(!chaos_dns_effect_allowed(&selector, CHAOS_DNS_EFFECT_GAI));

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
    (void)snprintf(line, sizeof(line), "*:SHUFFLE:1.0");
    assert(chaos_dns_config_parse_line(line, &rules[1]) == 1);
    assert(chaos_dns_config_select_rule(
        rules, 2U, CHAOS_DNS_EFFECT_SHUFFLE, "edge.api.example.com", &rule
    ));
    assert(rule.selector.kind == CHAOS_DNS_SELECTOR_SUFFIX);
    assert(count == 7U);
}

/**
 * @brief Proves the parsers accept exactly up to each limit and reject the first value past
 *   it, trailing garbage and empty parts.
 *
 * @details
 * - Latency and LIMIT accept 4294967295 and reject 4294967296, "12x" and (LIMIT) 0; a
 *   rejected value leaves the output unchanged.
 * - `ipv4`/`ipv6` alias INET4/INET6; a 4-byte buffer takes "abc" but not "abcd".
 * - Names compare equal only at equal length, in either argument order.
 * - `dns://\*.` and a name longer than `CHAOS_DNS_MAX_TEXT` (256) are not selectors.
 * - An empty or NULL name, or a lookup selector asked about a reverse query, does not match;
 *   matching works without a rank output.
 * - `[`, `[]`, `[::1` and an empty list element are not OVERRIDE addresses; blanks after a
 *   comma are.
 * - Neither the MISSING nor the RELOADING sentinel survives normalisation.
 * - A final line without a newline still yields its rule.
 * - Reverse selectors allow GAI, LATENCY, REWRITE and SERVICE and refuse OVERRIDE.
 */
static void test_parse_boundaries(void)
{
    static chaos_dns_rule_t rules[2];
    char payload[4];
    /* Writable: the parsers trim the text after the number in place. */
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
 * @brief Proves how open errors are classified: EINTR is retried, EACCES/EPERM are lasting
 *   (-3, reported as "file unreadable" until the file changes), anything else such as EMFILE
 *   is transient (-1, retried on the next check). Without a rule file nothing matches.
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
    /* Stat the rule file on every call so each write is seen at once; the throttle has its
     * own test. */
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
