/**
 * @file test_common.c
 * @brief Unit tests for the headers every library shares (src/common).
 *
 * Subsystem under test: `chaos_policy.h`, `chaos_clock.h`, `chaos_status.h`,
 * `chaos_hits.h`, `chaos_once.h` and `chaos_sleep.h`, through the paths the
 * libraries' own tests cannot reach: failing system calls, a missing or broken
 * vDSO, full buffers, a full slot pool, and a second thread waiting for an
 * initialiser; and the qualifier grammar and checks every library shares.
 *
 * Coverage approach: the status files' system calls, the raw clock and the sleep
 * system call are replaced with stubs that fail on request; the vDSO lookup is
 * fed hand-made ELF images; the vDSO clock is replaced with one that fails.
 *
 * Properties under test:
 * - numbers in qualifiers are 1 to 18 digits;
 * - without a working vDSO, clocks fall back to the raw system call, and to 0
 *   when that fails too; the rule-file throttle then never skips a look;
 * - a vDSO image without a load segment, dynamic section or symbol tables has
 *   no clock;
 * - a write interrupted by a signal goes on; a write that makes no progress fails;
 * - a status file whose staging name does not fit, or whose staging file cannot
 *   be created, is left as it was; a refused rename rewrites the file in place;
 * - a hits file whose name or contents do not fit is not written; a rule left
 *   without a slot in a full pool counts nothing;
 * - a thread that finds an initialiser running on another thread waits for it;
 * - qualifiers are trailing `@` words before any comment; a bad one rejects the
 *   line and leaves it as it was; `@until` must follow `@from`;
 * - `@first=N` fires N times per slot generation; `@size` gates are strict and
 *   never match a call without a byte count;
 * - an interrupted sleep goes on with the remaining time; errno is kept.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Raw clock: real, or failing. */
static int g_clock_fails = 0;
static long test_raw_gettime(clockid_t clock, struct timespec *now);
#define CHAOS_CLOCK_RAW_GETTIME(clock, now) test_raw_gettime((clock), (now))

/* Status file system calls: real, with failures on request. */
static int g_open_fails = 0;     /* errno for the staging open, 0 = real */
static int g_rename_fails = 0;   /* errno for the rename, 0 = real */
static int g_existing_fails = 0; /* the in-place open fails */
static int g_write_interrupts = 0;
static int g_write_stalls = 0;
static int g_write_fails = 0; /* errno for every write, 0 = real */
static int g_open_exists = 0; /* staging opens that find the name taken */
static unsigned g_opens = 0U;
static int test_open(const char *path);
static int test_open_existing(const char *path);
static long test_write(int fd, const void *data, size_t length);
static int test_rename(const char *from, const char *to);
#define CHAOS_STATUS_OPEN(path) test_open(path)
#define CHAOS_STATUS_OPEN_EXISTING(path) test_open_existing(path)
#define CHAOS_STATUS_SHARE(fd) fchmod((fd), 0666)
#define CHAOS_STATUS_WRITE(fd, data, length) test_write((fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) close(fd)
#define CHAOS_STATUS_UNLINK(path) unlink(path)
#define CHAOS_STATUS_EXISTS(path) (access((path), F_OK) == 0)
#define CHAOS_STATUS_RENAME(from, to) test_rename((from), (to))

/* Sleep system call: records the requests, interrupted or failing on request. */
static int g_sleep_interrupts = 0;
static int g_sleep_fails = 0; /* errno, 0 = succeeds */
static unsigned g_sleeps = 0U;
static struct timespec g_sleep_request;
static long test_sleep(struct timespec *request, struct timespec *remaining);
#define CHAOS_SLEEP_SYSCALL(request, remaining) test_sleep((request), (remaining))

#include "../../src/common/chaos_hits.h"
#include "../../src/common/chaos_once.h"
#include "../../src/common/chaos_policy.h"
#include "../../src/common/chaos_sleep.h"

#include <assert.h>
#include <pthread.h>

static long test_raw_gettime(clockid_t clock, struct timespec *now)
{
    if (g_clock_fails)
    {
        errno = EINVAL;
        return -1;
    }
    return clock_gettime(clock, now);
}

static int test_open(const char *path)
{
    ++g_opens;
    if (g_open_exists > 0)
    {
        --g_open_exists;
        errno = EEXIST;
        return -1;
    }
    if (g_open_fails != 0)
    {
        errno = g_open_fails;
        return -1;
    }
    return open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
}

static int test_open_existing(const char *path)
{
    if (g_existing_fails)
    {
        errno = EACCES;
        return -1;
    }
    return open(path, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
}

static long test_write(int fd, const void *data, size_t length)
{
    if (g_write_interrupts > 0)
    {
        --g_write_interrupts;
        errno = EINTR;
        return -1;
    }
    if (g_write_stalls)
    {
        return 0;
    }
    if (g_write_fails != 0)
    {
        errno = g_write_fails;
        return -1;
    }
    return (long)write(fd, data, length);
}

static int test_rename(const char *from, const char *to)
{
    if (g_rename_fails != 0)
    {
        errno = g_rename_fails;
        return -1;
    }
    return rename(from, to);
}

static long test_sleep(struct timespec *request, struct timespec *remaining)
{
    if (g_sleeps++ == 0U)
    {
        g_sleep_request = *request;
    }
    if (g_sleep_interrupts > 0)
    {
        --g_sleep_interrupts;
        remaining->tv_nsec /= 2;
        errno = EINTR;
        return -1;
    }
    if (g_sleep_fails != 0)
    {
        errno = g_sleep_fails;
        return -1;
    }
    return 0;
}

/** @brief The contents of @p path into @p out; -1 when it cannot be read. */
static long read_file(const char *path, char *out, size_t size)
{
    const int fd = open(path, O_RDONLY);
    long length;

    if (fd < 0)
    {
        return -1;
    }
    length = (long)read(fd, out, size - 1U);
    (void)close(fd);
    out[length > 0 ? length : 0] = '\0';
    return length;
}

/** @brief Whether the test directory holds a staging file left behind. */
static int staging_left(void)
{
    char command[128];
    FILE *list;
    int found;

    (void)snprintf(command, sizeof(command), "ls -a /tmp/chaos-common-test | grep -c staging");
    list = popen(command, "r");
    assert(list != NULL);
    found = fgetc(list) != '0';
    (void)pclose(list);
    return found;
}

static int failing_vdso(clockid_t clock, struct timespec *now)
{
    (void)clock;
    (void)now;
    return -1;
}

static void test_policy_numbers(void)
{
    chaos_rule_policy_t policy;
    char empty[] = "/a:open:EIO:1.0 @size>";
    char long_number[] = "/a:open:EIO:1.0 @size>1234567890123456789";
    char longest[] = "/a:open:EIO:1.0 @size>123456789012345678";

    assert(chaos_policy_extract(empty, &policy) != 0);
    assert(chaos_policy_extract(long_number, &policy) != 0);
    assert(chaos_policy_extract(longest, &policy) == 0);
}

static void test_vdso_lookup(void)
{
    struct fake_image
    {
        ElfW(Ehdr) header;
        ElfW(Phdr) program[2];
        ElfW(Dyn) dynamic[1];
    } image;

    /* Nothing mapped, or not an ELF image. */
    assert(chaos_clock_vdso_lookup(0U, "x") == NULL);
    memset(&image, 0, sizeof(image));
    assert(chaos_clock_vdso_lookup((uintptr_t)&image, "x") == NULL);

    /* An image with a load segment and a dynamic section, but no symbol tables. */
    memcpy(image.header.e_ident, ELFMAG, SELFMAG);
    image.header.e_phoff = offsetof(struct fake_image, program);
    image.header.e_phnum = 2;
    image.program[0].p_type = PT_LOAD;
    image.program[1].p_type = PT_DYNAMIC;
    image.program[1].p_offset = offsetof(struct fake_image, dynamic);
    image.dynamic[0].d_tag = DT_NULL;
    assert(chaos_clock_vdso_lookup((uintptr_t)&image, "x") == NULL);
    /* ...and one with no dynamic section at all. */
    image.header.e_phnum = 1;
    assert(chaos_clock_vdso_lookup((uintptr_t)&image, "x") == NULL);
}

static void test_clocks_without_vdso(void)
{
    const chaos_clock_vdso_fn real = chaos_clock_vdso();
    volatile uint64_t last = 0U;

    /* A vDSO clock that fails: the raw clock stands in, and 0 when it fails too. */
    assert(real != NULL);
    g_chaos_clock_vdso = failing_vdso;
    assert(chaos_clock_now_ns() == 0U);
    assert(chaos_clock_checked_recently(&last, UINT64_C(1000000000)) == 0);
    assert(chaos_clock_realtime_ms() > INT64_C(1600000000000));
    assert(chaos_hits_now_ms() > 0U);
    g_clock_fails = 1;
    assert(chaos_clock_realtime_ms() == 0);
    assert(chaos_hits_now_ms() == 0U);
    assert(!chaos_clock_stamp_is_recent(0, 0L));
    g_clock_fails = 0;
    g_chaos_clock_vdso = real;
    assert(chaos_clock_now_ns() > 0U);
}

static void test_status_files(void)
{
    char long_path[256];
    char contents[64];

    assert(chaos_status_format(contents, 0U, CHAOS_STATUS_OK, 1U, NULL, 1L) == 0U);

    (void)mkdir("/tmp/chaos-common-test", 0700);
    (void)unlink("/tmp/chaos-common-test/.status");

    /* A write a signal interrupts goes on. */
    g_write_interrupts = 2;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "first\n", 6U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "first\n") == 0);

    /* A write that makes no progress: the file stays as it was. */
    g_write_stalls = 1;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "second\n", 7U);
    g_write_stalls = 0;
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(!staging_left());

    /* A staging name that does not fit, and a staging file that cannot be made. */
    memset(long_path, 'd', sizeof(long_path));
    long_path[0] = '/';
    (void)strcpy(long_path + 180, "/.status");
    errno = 1234;
    chaos_status_replace_file(long_path, "x\n", 2U);
    assert(errno == 1234);
    g_open_fails = EACCES;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "third\n", 6U);
    g_open_fails = 0;
    assert(errno == 1234);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "first\n") == 0);

    /* A refused rename (another user's file in a sticky /tmp) rewrites in place. */
    g_rename_fails = EPERM;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "fourth\n", 7U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 7L);
    assert(strcmp(contents, "fourth\n") == 0);
    assert(!staging_left());
    /* ...unless that is refused too; any other failure leaves it alone. */
    g_existing_fails = 1;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "fifth\n", 6U);
    g_existing_fails = 0;
    g_rename_fails = EXDEV;
    errno = 1234;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "sixth\n", 6U);
    assert(errno == 1234);
    g_rename_fails = 0;
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 7L);
    assert(strcmp(contents, "fourth\n") == 0);
    assert(!staging_left());

    (void)unlink("/tmp/chaos-common-test/.status");
}

static void test_hits(void)
{
    static const char texts[2][CHAOS_STATUS_TEXT_MAX + 1U] = {"/a:open:EIO:1.0", "/b:open:EIO:1.0"};
    chaos_hit_slot_t pool[1];
    chaos_hit_slot_t *next[2];
    char prefix[200];
    char buffer[16];
    char contents[64];

    /* A full pool: the second rule has no slot and counts nothing. */
    chaos_hits_pool_reset(pool, 1U);
    chaos_hits_assign(pool, 1U, NULL, NULL, 0U, next, texts, 2U, NULL);
    assert(next[0] == &pool[0] && next[1] == NULL);

    /* A file name that does not fit, or contents that do not: nothing is written. */
    pool[0].count = 3U;
    memset(prefix, 'p', sizeof(prefix) - 1U);
    prefix[0] = '/';
    prefix[sizeof(prefix) - 1U] = '\0';
    g_opens = 0U;
    chaos_hits_write_for(prefix, 1L, next, texts, 2U, buffer, sizeof(buffer));
    chaos_hits_write_for(
        "/tmp/chaos-common-test/hits", 1L, next, texts, 2U, buffer, sizeof(buffer)
    );
    assert(g_opens == 0U);
    assert(access("/tmp/chaos-common-test/hits.1", F_OK) != 0);

    /* With room, a rule without a slot is written with 0. */
    {
        char room[2U * CHAOS_HITS_LINE_MAX + 1U];

        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits", 1L, next, texts, 2U, room, sizeof(room)
        );
        assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
        assert(strcmp(contents, "3\t/a:open:EIO:1.0\n0\t/b:open:EIO:1.0\n") == 0);
        (void)unlink("/tmp/chaos-common-test/hits.1");
    }
}

/** @brief chaos_policy_extract() on a copy of @p text; the cut line goes to @p rule. */
static int extract(const char *text, chaos_rule_policy_t *policy, char *rule)
{
    (void)strcpy(rule, text);
    return chaos_policy_extract(rule, policy);
}

static void test_policy_grammar(void)
{
    static const char *const rejected[] = {
        "/a:open:EIO:1.0 @first=0",
        "/a:open:EIO:1.0 @first=x",
        "/a:open:EIO:1.0 @from=x",
        "/a:open:EIO:1.0 @until=",
        "/a:open:EIO:1.0 @size<1/",
        "/a:open:EIO:1.0 @size>1:",
        "/a:open:EIO:1.0 @size=1",
        "/a:open:EIO:1.0 @from=20 @until=20",
        "/a:open:EIO:1.0 @from=20 @until=10",
    };
    chaos_rule_policy_t policy;
    char rule[128];
    size_t index;

    /* Qualifiers separated by tabs, blanks and a CR before a comment: all cut. */
    assert(extract("/a:open:EIO:1.0\t@first=3 @from=10\t@until=20 \t\r# note", &policy, rule) == 0);
    assert(strcmp(rule, "/a:open:EIO:1.0\t") == 0);
    assert(policy.first == 3U && policy.from_ms == 10 && policy.until_ms == 20);
    assert(extract("/a:open:EIO:1.0 @size>10 @size<20", &policy, rule) == 0);
    assert(policy.has_size_above && policy.size_above == 10U);
    assert(policy.has_size_below && policy.size_below == 20U);

    /* Not qualifiers: a line that is only one, a word with `@` inside, no words. */
    assert(extract("@first=3", &policy, rule) == 0);
    assert(strcmp(rule, "@first=3") == 0 && chaos_policy_is_empty(&policy));
    assert(extract("/a:open:EIO:1.0 x@first=3", &policy, rule) == 0);
    assert(strcmp(rule, "/a:open:EIO:1.0 x@first=3") == 0 && chaos_policy_is_empty(&policy));
    assert(extract(" \t", &policy, rule) == 0 && chaos_policy_is_empty(&policy));

    /* A window open on one side only is valid. */
    assert(extract("/a:open:EIO:1.0 @until=10", &policy, rule) == 0 && policy.until_ms == 10);
    assert(extract("/a:open:EIO:1.0 @from=10", &policy, rule) == 0 && policy.from_ms == 10);

    /* A bad qualifier rejects the line and leaves it whole. */
    for (index = 0U; index < sizeof(rejected) / sizeof(rejected[0]); ++index)
    {
        assert(extract(rejected[index], &policy, rule) != 0);
        assert(index >= 7U || strcmp(rule, rejected[index]) == 0);
    }
}

static void test_policy_probability(void)
{
    double probability = -1.0;

    assert(chaos_policy_parse_probability("1.00\t \r\n", &probability) == 0);
    assert(probability == 1.0);
    assert(chaos_policy_parse_probability("0.25", &probability) == 0);
    assert(probability == 0.25);
    /* Decimals beyond the 15th are checked but do not change the value. */
    assert(chaos_policy_parse_probability("0.1234567890123459999", &probability) == 0);
    assert(probability >= 0.123456789012345 && probability < 0.123456789012346);
    assert(chaos_policy_parse_probability("0.123456789012345x", &probability) != 0);
    assert(chaos_policy_parse_probability("1.5", &probability) != 0);
    assert(chaos_policy_parse_probability("0.", &probability) != 0);
    assert(chaos_policy_parse_probability("0.:", &probability) != 0);
    assert(chaos_policy_parse_probability("2", &probability) != 0);
    assert(chaos_policy_parse_probability(NULL, &probability) != 0);
}

static void test_policy_checks(void)
{
    const int64_t now = chaos_clock_realtime_ms();
    chaos_rule_policy_t policy;

    /* Any one qualifier makes a policy non-empty. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_is_empty(&policy));
    policy.first = 1U;
    assert(!chaos_policy_is_empty(&policy));
    memset(&policy, 0, sizeof(policy));
    policy.from_ms = 1;
    assert(!chaos_policy_is_empty(&policy));
    memset(&policy, 0, sizeof(policy));
    policy.until_ms = 1;
    assert(!chaos_policy_is_empty(&policy));
    memset(&policy, 0, sizeof(policy));
    policy.has_size_above = 1U;
    assert(!chaos_policy_is_empty(&policy));
    memset(&policy, 0, sizeof(policy));
    policy.has_size_below = 1U;
    assert(!chaos_policy_is_empty(&policy));

    /* The window is [from, until) on the wall clock. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_window_open(&policy));
    policy.from_ms = now - 60000;
    assert(chaos_policy_window_open(&policy));
    policy.until_ms = now + 60000;
    assert(chaos_policy_window_open(&policy));
    policy.from_ms = now + 30000;
    assert(!chaos_policy_window_open(&policy));
    policy.from_ms = 0;
    policy.until_ms = now - 30000;
    assert(!chaos_policy_window_open(&policy));

    /* Size gates are strict; a call without a byte count never passes one. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_size_ok(&policy, CHAOS_POLICY_NO_SIZE));
    policy.has_size_above = 1U;
    policy.size_above = 10U;
    assert(!chaos_policy_size_ok(&policy, CHAOS_POLICY_NO_SIZE));
    assert(!chaos_policy_size_ok(&policy, 10U));
    assert(chaos_policy_size_ok(&policy, 11U));
    policy.has_size_below = 1U;
    policy.size_below = 20U;
    assert(chaos_policy_size_ok(&policy, 19U));
    assert(!chaos_policy_size_ok(&policy, 20U));
    policy.has_size_above = 0U;
    assert(chaos_policy_size_ok(&policy, 5U));
    assert(!chaos_policy_size_ok(&policy, 25U));
}

static unsigned g_reports = 0U;

static void count_report(chaos_hit_slot_t *slot)
{
    (void)slot;
    ++g_reports;
}

static void test_policy_fire(void)
{
    chaos_rule_policy_t policy;
    chaos_hit_slot_t slot;

    /* A rule outside a snapshot fires every time, @first or not. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);
    policy.first = 1U;
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);

    /* @first=2 on a slot: two firings, each counted and reported, then inert. */
    memset(&slot, 0, sizeof(slot));
    slot.generation = 5U;
    slot.claimed = chaos_hit_claims_none(5U);
    slot.report = count_report;
    policy.first = 2U;
    g_reports = 0U;
    assert(chaos_policy_fire(&policy, &slot, 5U) == 1);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 1);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 0);
    assert(slot.count == 2U && g_reports == 2U);

    /* A copy of an earlier generation: its rule has left the file. */
    assert(chaos_policy_fire(&policy, &slot, 4U) == 0);
    /* Claims tagged with another generation are not this copy's to take. */
    slot.claimed = chaos_hit_claims_none(4U);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 0);
    /* The claim counter never wraps, whatever @first allows. */
    policy.first = UINT64_C(1) << 40;
    slot.claimed = chaos_hit_claims_none(5U) | UINT64_C(0xffffffff);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 0);
    assert(slot.count == 2U);

    /* Without @first a slot just counts; without a report hook nothing is called. */
    policy.first = 0U;
    slot.report = NULL;
    assert(chaos_policy_fire(&policy, &slot, 5U) == 1);
    assert(slot.count == 3U && g_reports == 2U);
}

static void test_sleep_ms(void)
{
    /* Zero sleeps not at all. */
    g_sleeps = 0U;
    chaos_sleep_ms(0U);
    assert(g_sleeps == 0U);

    /* Interrupted twice: goes on until done, and errno is kept. */
    g_sleep_interrupts = 2;
    errno = 1234;
    chaos_sleep_ms(1500U);
    assert(g_sleeps == 3U);
    assert(g_sleep_request.tv_sec == 1 && g_sleep_request.tv_nsec == 500000000L);
    assert(errno == 1234);

    /* Any other failure ends the sleep. */
    g_sleeps = 0U;
    g_sleep_fails = EINVAL;
    chaos_sleep_ms(7U);
    g_sleep_fails = 0;
    assert(g_sleeps == 1U && g_sleep_request.tv_nsec == 7000000L);
    assert(errno == 1234);
}

static void test_vdso_symbols(void)
{
    struct fake_vdso
    {
        ElfW(Ehdr) header;
        ElfW(Phdr) program[3];
        ElfW(Dyn) dynamic[5];
        uint32_t hash[2];
        ElfW(Sym) symbols[4];
        char strings[16];
    } image;
    const uintptr_t base = (uintptr_t)&image;

    memset(&image, 0, sizeof(image));
    memcpy(image.header.e_ident, ELFMAG, SELFMAG);
    image.header.e_phoff = offsetof(struct fake_vdso, program);

    /* A dynamic section but no load segment: no bias, no clock. */
    image.header.e_phnum = 1;
    image.program[0].p_type = PT_DYNAMIC;
    image.program[0].p_offset = offsetof(struct fake_vdso, dynamic);
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);

    /* Two load segments (only the first sets the bias), then the dynamic section. */
    image.header.e_phnum = 3;
    image.program[0].p_type = PT_LOAD;
    image.program[0].p_offset = 0U;
    image.program[1].p_type = PT_LOAD;
    image.program[1].p_offset = 0x10000U;
    image.program[2].p_type = PT_DYNAMIC;
    image.program[2].p_offset = offsetof(struct fake_vdso, dynamic);

    /* A symbol table without strings, then without a hash table: no clock. */
    image.dynamic[0].d_tag = DT_SYMTAB;
    image.dynamic[0].d_un.d_ptr = offsetof(struct fake_vdso, symbols);
    image.dynamic[1].d_tag = DT_NULL;
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);
    image.dynamic[1].d_tag = DT_STRTAB;
    image.dynamic[1].d_un.d_ptr = offsetof(struct fake_vdso, strings);
    image.dynamic[2].d_tag = DT_NULL;
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);

    /* Full tables, with an entry the lookup ignores. Symbols: an object, an
     * undefined function, another function, and the wanted one. */
    image.dynamic[2].d_tag = DT_DEBUG;
    image.dynamic[3].d_tag = DT_HASH;
    image.dynamic[3].d_un.d_ptr = offsetof(struct fake_vdso, hash);
    image.dynamic[4].d_tag = DT_NULL;
    image.hash[1] = 4U;
    memcpy(image.strings, "\0clock\0other", 13U);
    image.symbols[0].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
    image.symbols[0].st_shndx = 1U;
    image.symbols[0].st_name = 1U;
    image.symbols[1].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    image.symbols[1].st_shndx = SHN_UNDEF;
    image.symbols[1].st_name = 1U;
    image.symbols[2].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    image.symbols[2].st_shndx = 1U;
    image.symbols[2].st_name = 7U;
    image.symbols[3].st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    image.symbols[3].st_shndx = 1U;
    image.symbols[3].st_name = 1U;
    image.symbols[3].st_value = 0x40U;
    assert(chaos_clock_vdso_lookup(base, "clock") == (void *)(base + 0x40U));
    assert(chaos_clock_vdso_lookup(base, "missing") == NULL);
    assert(chaos_clock_vdso_lookup(base, NULL) == NULL);
}

static void test_clock_lookup_state(void)
{
    const chaos_clock_vdso_fn real = chaos_clock_vdso();
    const int64_t now = chaos_clock_realtime_ms();
    volatile uint64_t last = 0U;

    /* A lookup in progress in this process: callers do not wait, they fall back. */
    g_chaos_clock_state = 1;
    g_chaos_clock_owner = (long)getpid();
    assert(chaos_clock_vdso() == NULL);
    assert(chaos_clock_now_ns() == 0U);
    assert(chaos_clock_realtime_ms() >= now);
    /* ...claimed by another process (forked mid-lookup): taken over and finished. */
    g_chaos_clock_owner = (long)getpid() + 1L;
    assert(chaos_clock_vdso() == real);
    assert(g_chaos_clock_state == 2 && g_chaos_clock_owner == (long)getpid());

    /* Only a stamp within the racy window of now is recent, in either direction. */
    assert(chaos_clock_stamp_is_recent(now / 1000, (long)(now % 1000) * 1000000L));
    assert(!chaos_clock_stamp_is_recent(now / 1000 - 1, (long)(now % 1000) * 1000000L));
    assert(!chaos_clock_stamp_is_recent(now / 1000 + 1, (long)(now % 1000) * 1000000L));

    /* The throttle: off at 0, otherwise one look per interval. */
    assert(chaos_clock_checked_recently(&last, 0U) == 0 && last == 0U);
    assert(chaos_clock_checked_recently(&last, 1U) == 0 && last != 0U);
    assert(chaos_clock_checked_recently(&last, UINT64_C(1000000000000)) == 1);
}

static void test_status_report(void)
{
    chaos_status_error_t error;
    char line[260];
    char report[CHAOS_STATUS_BUFFER_SIZE];

    /* Control characters become blanks; the line ends at a newline. */
    chaos_status_keep_line(&error, 3U, "a\tb\177c\nd");
    assert(strcmp(error.text, "a b c") == 0 && error.line == 3U && error.reason == NULL);
    /* A long line is kept to its first CHAOS_STATUS_TEXT_MAX bytes. */
    memset(line, 'x', sizeof(line) - 1U);
    line[sizeof(line) - 1U] = '\0';
    chaos_status_keep_line(&error, 4U, line);
    assert(strlen(error.text) == CHAOS_STATUS_TEXT_MAX);

    /* An error without a rejected line reports like a plain state. */
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_ERROR, 2U, NULL, 9L) > 0U);
    assert(strcmp(report, "state=error\nrules=2\npid=9\n") == 0);
    chaos_status_keep_line(&error, 4U, "bad");
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_ERROR, 2U, &error, 9L) > 0U);
    assert(strcmp(report, "state=error\nrules=2\npid=9\n") == 0);
    chaos_status_reject(&error, CHAOS_STATUS_REASON_INVALID);
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_ERROR, 2U, &error, 9L) > 0U);
    assert(
        strcmp(report, "state=error\nrules=0\nline=4\nreason=invalid rule\ntext=bad\npid=9\n") == 0
    );
    chaos_status_clear(&error);
    assert(error.line == 0U && error.reason == NULL && error.text[0] == '\0');

    /* A buffer too small: the report is cut, and its length is what fits. */
    assert(chaos_status_format(report, 8U, CHAOS_STATUS_OK, 1U, NULL, 1L) == 7U);
    assert(strcmp(report, "state=o") == 0);
}

static void test_status_staging(void)
{
    char contents[64];
    int cwd;

    (void)unlink("/tmp/chaos-common-test/.status");

    /* A staging name another writer holds: the next one is tried. */
    g_opens = 0U;
    g_open_exists = 2;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "first\n", 6U);
    assert(g_opens == 3U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    /* ...but not forever: four taken names leave the file as it was. */
    g_opens = 0U;
    g_open_exists = 4;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "second\n", 7U);
    assert(g_opens == 4U && g_open_exists == 0);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);

    /* A write that fails outright: the file stays as it was, errno untouched. */
    g_write_fails = EIO;
    errno = 1234;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "third\n", 6U);
    g_write_fails = 0;
    assert(errno == 1234);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "first\n") == 0);
    assert(!staging_left());

    /* EACCES on the rename is a refused rename too: rewritten in place. */
    g_rename_fails = EACCES;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "fourth\n", 7U);
    g_rename_fails = 0;
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 7L);
    assert(strcmp(contents, "fourth\n") == 0);
    assert(!staging_left());

    /* A name without a directory is staged and replaced in the working directory. */
    cwd = open(".", O_RDONLY);
    assert(cwd >= 0 && chdir("/tmp/chaos-common-test") == 0);
    chaos_status_replace_file("plain", "fifth\n", 6U);
    assert(fchdir(cwd) == 0);
    (void)close(cwd);
    assert(read_file("/tmp/chaos-common-test/plain", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "fifth\n") == 0);
    assert(!staging_left());

    /* The report itself, and its removal. */
    chaos_status_write("/tmp/chaos-common-test/.status", CHAOS_STATUS_OK, 4U, NULL);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) > 0L);
    assert(strncmp(contents, "state=ok\nrules=4\npid=", 21U) == 0);
    errno = 1234;
    chaos_status_remove("/tmp/chaos-common-test/.status");
    chaos_status_remove("/tmp/chaos-common-test/.status");
    assert(errno == 1234);
    assert(access("/tmp/chaos-common-test/.status", F_OK) != 0);
    (void)unlink("/tmp/chaos-common-test/plain");
}

static void test_snapshot_sequence(void)
{
    volatile uint64_t sequence = 0U;
    uint64_t begin;

    /* Begin and end are idempotent; a copy made while odd, or across a write, is torn. */
    chaos_snapshot_write_begin(&sequence);
    chaos_snapshot_write_begin(&sequence);
    assert(sequence == 1U);
    begin = chaos_snapshot_read_begin(&sequence);
    assert(!chaos_snapshot_read_valid(&sequence, begin));
    chaos_snapshot_write_end(&sequence);
    chaos_snapshot_write_end(&sequence);
    assert(sequence == 2U);
    assert(!chaos_snapshot_read_valid(&sequence, 0U));
    begin = chaos_snapshot_read_begin(&sequence);
    assert(chaos_snapshot_read_valid(&sequence, begin));
}

static void test_hits_reload(void)
{
    static const char first[2][CHAOS_STATUS_TEXT_MAX + 1U] = {"A", "B"};
    static const char active_texts[3][CHAOS_STATUS_TEXT_MAX + 1U] = {"A", "C", "B"};
    static const char next_texts[2][CHAOS_STATUS_TEXT_MAX + 1U] = {"B", "C"};
    chaos_hit_slot_t pool[3];
    chaos_hit_slot_t *slots[2];
    chaos_hit_slot_t *active[3];
    chaos_hit_slot_t *next[2];
    uint64_t generation;

    memset(pool, 0, sizeof(pool));
    chaos_hits_pool_reset(pool, 3U);
    chaos_hits_assign(pool, 3U, NULL, NULL, 0U, slots, first, 2U, NULL);
    assert(slots[0] == &pool[0] && slots[1] == &pool[1]);
    pool[1].count = 7U;

    /* A rule still in the file keeps its slot and count; an entry without a slot is
     * not matched by its text; a new rule takes the next free slot. */
    active[0] = slots[0];
    active[1] = NULL;
    active[2] = slots[1];
    chaos_hits_assign(pool, 3U, active, active_texts, 3U, next, next_texts, 2U, count_report);
    assert(next[0] == &pool[1] && pool[1].count == 7U && pool[1].report == count_report);
    assert(next[1] == &pool[2] && pool[2].count == 0U && pool[2].used);

    /* The rule that left frees its slot and outdates its copies. */
    generation = pool[0].generation;
    chaos_hits_release(pool, 3U, next, 2U);
    assert(!pool[0].used && pool[0].generation == generation + 1U);
    assert(pool[1].used && pool[2].used);
    assert(!chaos_hit_slot_current(&pool[0], generation));
    assert(chaos_hit_slot_current(&pool[0], generation + 1U));
    assert(chaos_hit_slot_current(NULL, generation));

    /* A forked child starts its counts and claims afresh; a jumped REGRESS re-arms.
     * A reload the fork cut short (its snapshot assigned, never published) leaves
     * a slot no snapshot of the child holds: it is released. */
    {
        static const char cut_short[1][CHAOS_STATUS_TEXT_MAX + 1U] = {"D"};
        chaos_hit_slot_t *building[1];

        chaos_hits_assign(pool, 3U, next, next_texts, 2U, building, cut_short, 1U, NULL);
        assert(building[0] == &pool[0] && pool[0].used);
        generation = pool[0].generation;
    }
    pool[1].state = 3U;
    pool[2].state = 2U;
    chaos_hits_pool_after_fork(pool, 3U, next, 2U);
    assert(pool[1].count == 0U && pool[1].state == 1U && pool[2].state == 2U);
    assert(!pool[0].used && pool[0].generation == generation + 1U);
    assert(pool[1].used && pool[2].used);
    chaos_hit_record(NULL);
}

static void test_hits_file_number(void)
{
    static const long taken[] = {
        1L,
        1000000000L,
        1000000001L,
        1000000002L,
        1000000003L,
        1000000004L,
        1000000005L,
        1000000006L
    };
    const chaos_clock_vdso_fn real = chaos_clock_vdso();
    char long_prefix[200];
    char path[64];
    size_t index;

    /* Without a vDSO clock the salt is 0, so the numbers tried are known. */
    g_chaos_clock_vdso = failing_vdso;
    assert(chaos_hits_file_number_for("/tmp/chaos-common-test/n", 1L) == 1L);
    (void)close(open("/tmp/chaos-common-test/n.1", O_WRONLY | O_CREAT, 0600));
    assert(chaos_hits_file_number_for("/tmp/chaos-common-test/n", 1L) == 1000000000L);
    /* Eight names taken: the last number tried is used. */
    for (index = 0U; index < sizeof(taken) / sizeof(taken[0]); ++index)
    {
        (void)snprintf(path, sizeof(path), "/tmp/chaos-common-test/n.%ld", taken[index]);
        (void)close(open(path, O_WRONLY | O_CREAT, 0600));
    }
    errno = 1234;
    assert(chaos_hits_file_number_for("/tmp/chaos-common-test/n", 1L) == 1000000007L);
    assert(errno == 1234);
    for (index = 0U; index < sizeof(taken) / sizeof(taken[0]); ++index)
    {
        (void)snprintf(path, sizeof(path), "/tmp/chaos-common-test/n.%ld", taken[index]);
        (void)unlink(path);
    }
    g_chaos_clock_vdso = real;

    /* A prefix too long for a name: the pid is used as it is. */
    memset(long_prefix, 'p', sizeof(long_prefix) - 1U);
    long_prefix[sizeof(long_prefix) - 1U] = '\0';
    assert(chaos_hits_file_number_for(long_prefix, 42L) == 42L);
    assert(chaos_hits_file_number(long_prefix) == (long)getpid());
}

/* A once-control whose initialiser runs until the main thread lets it finish. */
static volatile chaos_once_t g_once = CHAOS_ONCE_INIT;
static volatile int g_initialising = 0;
static volatile int g_release = 0;
static volatile int g_initialised = 0;

static void slow_initialise(void)
{
    g_initialising = 1;
    while (!g_release)
    {
        (void)sched_yield();
    }
    g_initialised = 1;
}

static void *run_once(void *argument)
{
    (void)argument;
    (void)chaos_once(&g_once, slow_initialise);
    return NULL;
}

static void *release_later(void *argument)
{
    struct timespec pause = {0, 20000000L};

    (void)argument;
    (void)nanosleep(&pause, NULL);
    g_release = 1;
    return NULL;
}

static void test_once_waits(void)
{
    pthread_t initialiser;
    pthread_t releaser;

    assert(pthread_create(&initialiser, NULL, run_once, NULL) == 0);
    while (!g_initialising)
    {
        (void)sched_yield();
    }
    /* Another thread's initialiser is running: this call waits for it. */
    assert(pthread_create(&releaser, NULL, release_later, NULL) == 0);
    assert(chaos_once(&g_once, slow_initialise) == 1);
    assert(g_initialised);
    assert(pthread_join(initialiser, NULL) == 0);
    assert(pthread_join(releaser, NULL) == 0);
}

int main(void)
{
    test_policy_numbers();
    test_vdso_lookup();
    test_clocks_without_vdso();
    test_status_files();
    test_hits();
    test_policy_grammar();
    test_policy_probability();
    test_policy_checks();
    test_policy_fire();
    test_sleep_ms();
    test_vdso_symbols();
    test_clock_lookup_state();
    test_status_report();
    test_status_staging();
    test_snapshot_sequence();
    test_hits_reload();
    test_hits_file_number();
    test_once_waits();
    (void)rmdir("/tmp/chaos-common-test");
    return 0;
}
