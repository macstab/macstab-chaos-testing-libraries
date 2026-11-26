/**
 * @file test_common.c
 * @brief Proves the shared headers in `src/common` on the paths the per-library suites
 *        cannot reach: failing system calls, a missing or malformed vDSO, full buffers and
 *        slot pools, concurrent initialisers, and the qualifier grammar all libraries use.
 *
 * @details Units under test: `chaos_policy.h`, `chaos_clock.h`, `chaos_status.h`,
 * `chaos_hits.h`, `chaos_bucket.h`, `chaos_once.h`, `chaos_sleep.h`, included
 * header-only.
 *
 * Isolation: every system call the headers make goes through an overridable macro, which
 * this file defines before the includes:
 * - `CHAOS_CLOCK_RAW_GETTIME`: `g_clock_fails` makes the raw clock fail (EINVAL);
 * - `CHAOS_STATUS_OPEN` / `_OPEN_EXISTING` / `_WRITE` / `_RENAME` / `_LINK`: inject EEXIST
 *   on staging names, open/rename/link errnos, EINTR, zero-progress and failing writes;
 *   the rest map to the real calls;
 * - `CHAOS_SLEEP_SYSCALL`: records the first request, simulates EINTR (halving the
 *   remaining time) or another failure.
 * The vDSO lookup is fed hand-built ELF images, and `g_chaos_clock_vdso` is swapped for a
 * failing clock. Files are written under `/tmp/chaos-common-test`.
 *
 * Properties proven:
 * - qualifier numbers have 1 to 18 digits; qualifiers are trailing `@` words before any
 *   comment; a malformed one rejects the line; `@until` must be later than `@from`;
 * - `@first=N` fires N times per slot generation and the claim counter never wraps;
 *   `@size` bounds are exclusive and an unknown size never passes a gate;
 * - without a working vDSO the clocks fall back to the raw system call, and to 0 when
 *   that fails; the rule-file throttle then never skips a check;
 * - a vDSO image without a load segment, dynamic section, symbol, string or hash table
 *   yields no clock;
 * - status files are replaced atomically via a staging file; EINTR is retried, no
 *   progress or any failure leaves the old file and no staging file; a rename refused
 *   with EPERM/EACCES rewrites in place; errno is never changed;
 * - hits files are created exclusively (link, or rename where hard links fail), never
 *   overwrite another process's file of the same pid, and are skipped when the name or
 *   contents do not fit; slots follow rule texts across reloads and forks;
 * - a token bucket starts full, refills at its rate, holds at most one second's worth,
 *   and hands out bytes it does not have only against a wait that no second caller is
 *   given again;
 * - a second thread entering an initialiser that is running waits for it;
 * - an interrupted sleep resumes with the remaining time; errno is preserved.
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

/* Seam: raw clock_gettime, failing with EINVAL while `g_clock_fails`. */
static int g_clock_fails = 0;
static long test_raw_gettime(clockid_t clock, struct timespec *now);
#define CHAOS_CLOCK_RAW_GETTIME(clock, now) test_raw_gettime((clock), (now))

/* Seam: status/hits file system calls; each knob injects one failure mode, 0 = real. */
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
static int g_link_fails = 0; /* errno for the link, 0 = real */
static int test_link(const char *from, const char *to);
#define CHAOS_STATUS_OPEN(path) test_open(path)
#define CHAOS_STATUS_OPEN_EXISTING(path) test_open_existing(path)
#define CHAOS_STATUS_SHARE(fd) fchmod((fd), 0666)
#define CHAOS_STATUS_WRITE(fd, data, length) test_write((fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) close(fd)
#define CHAOS_STATUS_UNLINK(path) unlink(path)
#define CHAOS_STATUS_EXISTS(path) (access((path), F_OK) == 0)
#define CHAOS_STATUS_RENAME(from, to) test_rename((from), (to))
#define CHAOS_STATUS_LINK(from, to) test_link((from), (to))

/* Seam: the sleep system call. Records the first request; `g_sleep_interrupts` EINTRs halve
 * the remaining time each; `g_sleep_fails` fails with that errno. */
static int g_sleep_interrupts = 0;
static int g_sleep_fails = 0; /* errno, 0 = succeeds */
static unsigned g_sleeps = 0U;
static struct timespec g_sleep_request;
static long test_sleep(struct timespec *request, struct timespec *remaining);
#define CHAOS_SLEEP_SYSCALL(request, remaining) test_sleep((request), (remaining))

/* Bucket seam: `g_bucket_cas_fails` makes that many compare-and-swap attempts fail, which
 * is what a thread losing the race to another one sees. */
static unsigned g_bucket_cas_fails = 0U;
static int test_bucket_cas(volatile uint64_t *state, uint64_t seen, uint64_t next)
{
    if (g_bucket_cas_fails > 0U)
    {
        --g_bucket_cas_fails;
        return 0;
    }
    return __sync_bool_compare_and_swap(state, seen, next);
}
#define CHAOS_BUCKET_CAS(state, seen, next) test_bucket_cas((state), (seen), (next))

#include "../../src/common/chaos_bucket.h"
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

static int test_link(const char *from, const char *to)
{
    if (g_link_fails != 0)
    {
        errno = g_link_fails;
        return -1;
    }
    return link(from, to);
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

/** @brief Whether a staging file was left in the test directory (a leak on failure). */
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

/** @brief A vDSO clock_gettime that always fails, to force the fallback paths. */
static int failing_vdso(clockid_t clock, struct timespec *now)
{
    (void)clock;
    (void)now;
    return -1;
}

/** @brief A qualifier number needs 1 to 18 digits: none and 19 are rejected, 18 accepted. */
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

/** @brief vDSO lookup rejects a NULL base, non-ELF memory, and images lacking tables. */
static void test_vdso_lookup(void)
{
    struct fake_image
    {
        ElfW(Ehdr) header;
        ElfW(Phdr) program[2];
        ElfW(Dyn) dynamic[1];
    } image;

    /* No vDSO (AT_SYSINFO_EHDR 0), or memory without the ELF magic. */
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

/**
 * @brief Clock fallbacks: a failing vDSO makes the monotonic clock read 0 and disables the
 *        throttle; the realtime clock falls back to the raw system call, and reads 0 when
 *        that fails too, which also makes no mtime stamp count as recent.
 */
static void test_clocks_without_vdso(void)
{
    const chaos_clock_vdso_fn real = chaos_clock_vdso();
    volatile uint64_t last = 0U;

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

/**
 * @brief Status file replacement under failures; errno is preserved throughout and no
 *        staging file is left behind.
 */
static void test_status_files(void)
{
    char long_path[256];
    char contents[64];

    assert(chaos_status_format(contents, 0U, CHAOS_STATUS_OK, 1U, NULL, 1L) == 0U);

    (void)mkdir("/tmp/chaos-common-test", 0700);
    (void)unlink("/tmp/chaos-common-test/.status");

    /* A zero-size buffer formats nothing. Two EINTRs during the write are retried. */
    g_write_interrupts = 2;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "first\n", 6U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "first\n") == 0);

    /* A write returning 0 would loop forever; it aborts and the old file stays. */
    g_write_stalls = 1;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "second\n", 7U);
    g_write_stalls = 0;
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(!staging_left());

    /* A staging name that overflows its buffer, and a staging open failing with EACCES. */
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

    /* A rename refused with EPERM (another user's file in sticky /tmp) falls back to
     * rewriting the existing file in place. */
    g_rename_fails = EPERM;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "fourth\n", 7U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 7L);
    assert(strcmp(contents, "fourth\n") == 0);
    assert(!staging_left());
    /* ...unless the in-place open is refused too; a rename failing with any other errno
     * (EXDEV) leaves the file alone. */
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

/**
 * @brief Hits slots and hits file creation: pool exhaustion, oversize names and contents,
 *        exclusive creation, pid collisions between containers, and filesystems without
 *        hard links.
 */
static void test_hits(void)
{
    static const char texts[2][CHAOS_STATUS_TEXT_MAX + 1U] = {"/a:open:EIO:1.0", "/b:open:EIO:1.0"};
    chaos_hit_slot_t pool[1];
    chaos_hit_slot_t *next[2];
    char prefix[200];
    char buffer[16];
    char contents[64];

    /* A pool of 1: the second rule gets no slot (NULL) and counts nothing. */
    chaos_hits_pool_reset(pool, 1U);
    chaos_hits_assign(pool, 1U, NULL, NULL, 0U, next, texts, 2U, NULL);
    assert(next[0] == &pool[0] && next[1] == NULL);

    /* A name that overflows the path buffer, or contents larger than the 16-byte buffer:
     * nothing is opened, the number stays, nothing is owned. */
    pool[0].count = 3U;
    memset(prefix, 'p', sizeof(prefix) - 1U);
    prefix[0] = '/';
    prefix[sizeof(prefix) - 1U] = '\0';
    g_opens = 0U;
    {
        char room[2U * CHAOS_HITS_LINE_MAX + 1U];
        long number = 1L;
        int owned = 0;

        chaos_hits_write_for(
            prefix, 1L, &number, &owned, next, texts, 2U, NULL, room, sizeof(room)
        );
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            NULL,
            buffer,
            sizeof(buffer)
        );
        assert(g_opens == 0U && number == 1L && !owned);
        assert(access("/tmp/chaos-common-test/hits.1", F_OK) != 0);

        /* The first write creates the file (a slotless rule reads 0); later writes replace
         * it. A stale EEXIST in errno must not be mistaken for a taken name. */
        errno = EEXIST;
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            NULL,
            room,
            sizeof(room)
        );
        assert(number == 1L && owned && errno == EEXIST);
        assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
        assert(strcmp(contents, "3\t/a:open:EIO:1.0\n0\t/b:open:EIO:1.0\n") == 0);
        pool[0].count = 4U;
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            NULL,
            room,
            sizeof(room)
        );
        assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
        assert(strncmp(contents, "4\t", 2U) == 0);

        /* Another process with the same pid (containers sharing /tmp each run pid 1) chose
         * the same name before either wrote: its exclusive create fails, it moves to
         * pid * 10^9 + salt, and this process's file is untouched. */
        {
            long other = 1L;
            int other_owned = 0;
            char path[64];

            pool[0].count = 9U;
            chaos_hits_write_for(
                "/tmp/chaos-common-test/hits",
                1L,
                &other,
                &other_owned,
                next,
                texts,
                2U,
                NULL,
                room,
                sizeof(room)
            );
            assert(other_owned && other > 1000000000L && other < 2000000000L);
            (void)snprintf(path, sizeof(path), "/tmp/chaos-common-test/hits.%ld", other);
            assert(read_file(path, contents, sizeof(contents)) > 0L);
            assert(strncmp(contents, "9\t", 2U) == 0);
            assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
            assert(strncmp(contents, "4\t", 2U) == 0);
            (void)unlink(path);
        }

        /* Every name taken: nothing is written, nothing owned, no staging file leaks. */
        {
            long other = 1L;
            int other_owned = 0;

            g_link_fails = EEXIST;
            chaos_hits_write_for(
                "/tmp/chaos-common-test/hits",
                1L,
                &other,
                &other_owned,
                next,
                texts,
                2U,
                NULL,
                room,
                sizeof(room)
            );
            g_link_fails = 0;
            assert(!other_owned);
            assert(!staging_left());
        }
        (void)unlink("/tmp/chaos-common-test/hits.1");

        /* link(2) refused (EPERM, no hard links on this file system): created by rename. */
        number = 1L;
        owned = 0;
        g_link_fails = EPERM;
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            NULL,
            room,
            sizeof(room)
        );
        g_link_fails = 0;
        assert(owned && number == 1L);
        assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
        assert(!staging_left());
        (void)unlink("/tmp/chaos-common-test/hits.1");

        /* Header lines (counts that belong to no rule) go in front of the rule lines, and
         * carry no tab: that is what lets a reader which splits on the first tab skip what
         * it does not know. Proven here on the bytes, not on the intent. */
        number = 1L;
        owned = 0;
        pool[0].count = 7U;
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            "suppressed.shared=2\nsuppressed.unknown=0\n",
            room,
            sizeof(room)
        );
        {
            char whole[128];

            assert(read_file("/tmp/chaos-common-test/hits.1", whole, sizeof(whole)) > 0L);
            assert(
                strcmp(
                    whole,
                    "suppressed.shared=2\nsuppressed.unknown=0\n"
                    "7\t/a:open:EIO:1.0\n0\t/b:open:EIO:1.0\n"
                ) == 0
            );
            /* The header is in front of every tab, which is what makes it skippable. */
            assert(strchr(whole, '\t') > strstr(whole, "suppressed.unknown=0"));
        }
        (void)unlink("/tmp/chaos-common-test/hits.1");

        /* Negative: no header writes the rule lines alone, byte for byte as before. */
        chaos_hits_write_for(
            "/tmp/chaos-common-test/hits",
            1L,
            &number,
            &owned,
            next,
            texts,
            2U,
            NULL,
            room,
            sizeof(room)
        );
        assert(read_file("/tmp/chaos-common-test/hits.1", contents, sizeof(contents)) > 0L);
        assert(strcmp(contents, "7\t/a:open:EIO:1.0\n0\t/b:open:EIO:1.0\n") == 0);
        (void)unlink("/tmp/chaos-common-test/hits.1");

        /* The shared generation line: the header a library writes always starts with it,
         * so a reader can tell which rule file the counts below belong to. */
        {
            char header[CHAOS_HITS_HEADER_MAX];

            assert(chaos_hits_header_generation(header, sizeof(header), 7U) == 13U);
            assert(strcmp(header, "generation=7\n") == 0);
            assert(chaos_hits_header_generation(header, sizeof(header), 0U) == 13U);
            assert(strcmp(header, "generation=0\n") == 0);
            /* No tab, which is what makes it skippable by a reader that splits on one. */
            assert(strchr(header, '\t') == NULL);
            /* Too small: nothing is claimed, so the caller writes no header at all. */
            assert(chaos_hits_header_generation(header, 4U, 7U) == 0U);
        }

        /* Negative: a header that does not fit the scratch writes nothing at all -- a
         * truncated header would be a line a reader cannot classify. */
        {
            char tiny[8];

            chaos_hits_write_for(
                "/tmp/chaos-common-test/hits",
                1L,
                &number,
                &owned,
                next,
                texts,
                2U,
                "suppressed.shared=2\n",
                tiny,
                sizeof(tiny)
            );
            assert(access("/tmp/chaos-common-test/hits.1", F_OK) != 0);
        }
    }
}

/** @brief chaos_policy_extract() on a copy of @p text, left in @p rule (cut on success). */
static int extract(const char *text, chaos_rule_policy_t *policy, char *rule)
{
    (void)strcpy(rule, text);
    return chaos_policy_extract(rule, policy);
}

/** @brief Qualifier extraction: which words are qualifiers and which lines are rejected. */
static void test_policy_grammar(void)
{
    static const char *const rejected[] = {
        "/a:open:EIO:1.0 @first=0",
        "/a:open:EIO:1.0 @first=x",
        /* `@every=0` would divide by zero, and `@every=` has no count at all. */
        "/a:open:EIO:1.0 @every=0",
        "/a:open:EIO:1.0 @every=",
        "/a:open:EIO:1.0 @every=x",
        /* `@at` is written with the sign that says "from now on"; without it the number
         * would read as a Unix time, which is `@from`. A delay of zero is no delay. */
        "/a:open:EIO:1.0 @at=500",
        "/a:open:EIO:1.0 @at=+0",
        "/a:open:EIO:1.0 @at=+",
        "/a:open:EIO:1.0 @at=+x",
        "/a:open:EIO:1.0 @at=",
        "/a:open:EIO:1.0 @from=x",
        "/a:open:EIO:1.0 @until=",
        /* `@until=0` is how "no upper bound" is stored, so taking it as written would turn
         * a window that can never be open into one that is always open. */
        "/a:open:EIO:1.0 @until=0",
        "/a:open:EIO:1.0 @from=0 @until=0",
        "/a:open:EIO:1.0 @size<1/",
        "/a:open:EIO:1.0 @size>1:",
        "/a:open:EIO:1.0 @size=1",
        "/a:open:EIO:1.0 @from=20 @until=20",
        "/a:open:EIO:1.0 @from=20 @until=10",
        /* A '#' with no blank before it would cut the value short instead of starting
         * a comment: dns://x:REWRITE:a#b would quietly redirect to `a`. */
        "/a:open:EIO:1.0#note",
        "/a:open:EIO:1.0 @first=3#note",
        "/a:open:EIO:1.0\t@first=3#note",
    };
    chaos_rule_policy_t policy;
    char rule[128];
    size_t index;

    /* Qualifiers separated by tabs and blanks, followed by a CR and a comment, are all
     * extracted and cut from the line. */
    assert(extract("/a:open:EIO:1.0\t@first=3 @from=10\t@until=20 \t\r# note", &policy, rule) == 0);
    assert(strcmp(rule, "/a:open:EIO:1.0\t") == 0);
    assert(policy.first == 3U && policy.from_ms == 10 && policy.until_ms == 20);
    assert(extract("/a:open:EIO:1.0 @size>10 @size<20", &policy, rule) == 0);
    assert(policy.has_size_above && policy.size_above == 10U);
    assert(policy.has_size_below && policy.size_below == 20U);

    /* Not qualifiers: a line that is nothing but one (it is the rule text), a word with
     * `@` inside, and a blank line. */
    assert(extract("@first=3", &policy, rule) == 0);
    assert(strcmp(rule, "@first=3") == 0 && chaos_policy_is_empty(&policy));
    assert(extract("/a:open:EIO:1.0 x@first=3", &policy, rule) == 0);
    assert(strcmp(rule, "/a:open:EIO:1.0 x@first=3") == 0 && chaos_policy_is_empty(&policy));
    assert(extract(" \t", &policy, rule) == 0 && chaos_policy_is_empty(&policy));

    /* A comment still starts wherever a blank, tab or CR precedes the '#', and a line
     * that opens with one is still a comment. */
    assert(extract("#note", &policy, rule) == 0 && chaos_policy_is_empty(&policy));
    assert(extract("/a:open:EIO:1.0 #note", &policy, rule) == 0);
    assert(extract("/a:open:EIO:1.0\t#note", &policy, rule) == 0);
    assert(extract("/a:open:EIO:1.0\r#note", &policy, rule) == 0);

    /* `@every=N` counts evaluations, not hits: N >= 1, and 1 is allowed though it gates
     * nothing. */
    assert(extract("/a:open:EIO:1.0 @every=3", &policy, rule) == 0 && policy.every == 3U);
    assert(extract("/a:open:EIO:1.0 @every=1", &policy, rule) == 0 && policy.every == 1U);
    assert(!chaos_policy_is_empty(&policy));

    /* `@at=+N` is a delay from the moment the rule became active, in ms. */
    assert(extract("/a:open:EIO:1.0 @at=+500", &policy, rule) == 0 && policy.at_ms == 500U);
    assert(!chaos_policy_is_empty(&policy));
    {
        chaos_hit_slot_t slot;

        (void)memset(&slot, 0, sizeof(slot));
        /* The delay is measured from the slot's activation moment: a second ago it has
         * passed, now it has not, and without a moment at all (no slot, or no readable
         * clock) the rule stays closed rather than firing at once. */
        slot.armed_ms = chaos_hits_now_ms() - 1000U;
        assert(chaos_policy_at_ok(&policy, &slot) != 0);
        slot.armed_ms = chaos_hits_now_ms();
        assert(chaos_policy_at_ok(&policy, &slot) == 0);
        slot.armed_ms = chaos_hits_now_ms() + 100000U;
        assert(chaos_policy_at_ok(&policy, &slot) == 0);
        slot.armed_ms = 0U;
        assert(chaos_policy_at_ok(&policy, &slot) == 0);
        assert(chaos_policy_at_ok(&policy, NULL) == 0);
        /* Without the qualifier there is nothing to wait for. */
        assert(extract("/a:open:EIO:1.0", &policy, rule) == 0 && policy.at_ms == 0U);
        assert(chaos_policy_at_ok(&policy, NULL) != 0);
    }

    /* A window open on one side only is valid. */
    assert(extract("/a:open:EIO:1.0 @until=10", &policy, rule) == 0 && policy.until_ms == 10);
    assert(extract("/a:open:EIO:1.0 @from=10", &policy, rule) == 0 && policy.from_ms == 10);

    /* A malformed qualifier rejects the line and leaves it unmodified; the window errors
     * (`@until` <= `@from`) are the exception, because they are found after the words were
     * cut -- which is what naming them by content rather than by position says. */
    for (index = 0U; index < sizeof(rejected) / sizeof(rejected[0]); ++index)
    {
        const int window_error =
            strstr(rejected[index], "@from=") != NULL && strstr(rejected[index], "@until=") != NULL;

        assert(extract(rejected[index], &policy, rule) != 0);
        assert(window_error || strcmp(rule, rejected[index]) == 0);
    }
}

/**
 * @brief Probability parsing: trailing whitespace allowed, [0, 1] only, digits after the
 *        decimal point required, and no trailing garbage.
 */
static void test_policy_probability(void)
{
    double probability = -1.0;

    assert(chaos_policy_parse_probability("1.00\t \r\n", &probability) == 0);
    assert(probability == 1.0);
    assert(chaos_policy_parse_probability("0.25", &probability) == 0);
    assert(probability == 0.25);
    /* Digits beyond the 15th decimal are validated but ignored for the value. */
    assert(chaos_policy_parse_probability("0.1234567890123459999", &probability) == 0);
    assert(probability >= 0.123456789012345 && probability < 0.123456789012346);
    assert(chaos_policy_parse_probability("0.123456789012345x", &probability) != 0);
    assert(chaos_policy_parse_probability("1.5", &probability) != 0);
    assert(chaos_policy_parse_probability("0.", &probability) != 0);
    assert(chaos_policy_parse_probability("0.:", &probability) != 0);
    assert(chaos_policy_parse_probability("2", &probability) != 0);
    assert(chaos_policy_parse_probability(NULL, &probability) != 0);
}

/** @brief Emptiness, the [from, until) wall-clock window, and exclusive size gates. */
static void test_policy_checks(void)
{
    const int64_t now = chaos_clock_realtime_ms();
    chaos_rule_policy_t policy;

    /* Any one qualifier makes a policy non-empty (an empty one is a rule-less line). */
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
    memset(&policy, 0, sizeof(policy));
    policy.every = 2U;
    assert(!chaos_policy_is_empty(&policy));

    /* `@every=N`: the Nth evaluation of the rule passes, the others do not. The counter
     * the gate reads is the one chaos_hits.h keeps per rule, so the first evaluation is
     * number 1. Without the qualifier every evaluation passes. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_every_ok(&policy, 1U) && chaos_policy_every_ok(&policy, 7U));
    policy.every = 3U;
    assert(!chaos_policy_every_ok(&policy, 1U));
    assert(!chaos_policy_every_ok(&policy, 2U));
    assert(chaos_policy_every_ok(&policy, 3U));
    assert(!chaos_policy_every_ok(&policy, 4U));
    assert(chaos_policy_every_ok(&policy, 6U));
    /* `@every=1` gates nothing, which is why it is allowed rather than rejected. */
    policy.every = 1U;
    assert(chaos_policy_every_ok(&policy, 1U) && chaos_policy_every_ok(&policy, 2U));

    /* The window is [from, until) in Unix ms on the wall clock. */
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

    /* Both size bounds are exclusive; CHAOS_POLICY_NO_SIZE passes only when ungated. */
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

/* Report hook calls, to prove each firing is reported exactly once. */
static unsigned g_reports = 0U;

static void count_report(chaos_hit_slot_t *slot)
{
    (void)slot;
    ++g_reports;
}

/** @brief The final hit gate: `@first` claims, generation tagging, counting, reporting. */
static void test_policy_fire(void)
{
    chaos_rule_policy_t policy;
    chaos_hit_slot_t slot;

    /* A rule without a slot (outside a snapshot) fires every time, `@first` or not. */
    memset(&policy, 0, sizeof(policy));
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);
    policy.first = 1U;
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);
    assert(chaos_policy_fire(&policy, NULL, 0U) == 1);

    /* `@first=2` on a slot: two firings, each counted and reported, then none. */
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

    /* A rule copy of an earlier generation (its rule left the file) never fires. */
    assert(chaos_policy_fire(&policy, &slot, 4U) == 0);
    /* A claim word tagged with another generation cannot be claimed by this copy. */
    slot.claimed = chaos_hit_claims_none(4U);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 0);
    /* The 32-bit claim counter never wraps, even when `@first` exceeds 2^32. */
    policy.first = UINT64_C(1) << 40;
    slot.claimed = chaos_hit_claims_none(5U) | UINT64_C(0xffffffff);
    assert(chaos_policy_fire(&policy, &slot, 5U) == 0);
    assert(slot.count == 2U);

    /* Without `@first` a slot only counts; a NULL report hook is not called. */
    policy.first = 0U;
    slot.report = NULL;
    assert(chaos_policy_fire(&policy, &slot, 5U) == 1);
    assert(slot.count == 3U && g_reports == 2U);
}

/** @brief chaos_sleep_ms(): 0 is a no-op, EINTR resumes, other errors stop; errno kept. */
static void test_sleep_ms(void)
{
    /* 0 ms issues no system call. */
    g_sleeps = 0U;
    chaos_sleep_ms(0U);
    assert(g_sleeps == 0U);

    /* 1500 ms is one {1 s, 500000000 ns} request; two EINTRs give three calls. */
    g_sleep_interrupts = 2;
    errno = 1234;
    chaos_sleep_ms(1500U);
    assert(g_sleeps == 3U);
    assert(g_sleep_request.tv_sec == 1 && g_sleep_request.tv_nsec == 500000000L);
    assert(errno == 1234);

    /* Any other failure ends the sleep after one call. */
    g_sleeps = 0U;
    g_sleep_fails = EINVAL;
    chaos_sleep_ms(7U);
    g_sleep_fails = 0;
    assert(g_sleeps == 1U && g_sleep_request.tv_nsec == 7000000L);
    assert(errno == 1234);
}

/**
 * @brief vDSO symbol resolution on a hand-built image: the load bias comes from the first
 *        PT_LOAD only, and the symbol must be a defined STT_FUNC with the exact name.
 */
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

    /* A dynamic section without a load segment: no load bias, so no clock. */
    image.header.e_phnum = 1;
    image.program[0].p_type = PT_DYNAMIC;
    image.program[0].p_offset = offsetof(struct fake_vdso, dynamic);
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);

    /* Two load segments (the second must not move the bias), then the dynamic section. */
    image.header.e_phnum = 3;
    image.program[0].p_type = PT_LOAD;
    image.program[0].p_offset = 0U;
    image.program[1].p_type = PT_LOAD;
    image.program[1].p_offset = 0x10000U;
    image.program[2].p_type = PT_DYNAMIC;
    image.program[2].p_offset = offsetof(struct fake_vdso, dynamic);

    /* DT_SYMTAB without DT_STRTAB, then without DT_HASH (symbol count): no clock. */
    image.dynamic[0].d_tag = DT_SYMTAB;
    image.dynamic[0].d_un.d_ptr = offsetof(struct fake_vdso, symbols);
    image.dynamic[1].d_tag = DT_NULL;
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);
    image.dynamic[1].d_tag = DT_STRTAB;
    image.dynamic[1].d_un.d_ptr = offsetof(struct fake_vdso, strings);
    image.dynamic[2].d_tag = DT_NULL;
    assert(chaos_clock_vdso_lookup(base, "clock") == NULL);

    /* Complete tables plus an ignored DT_DEBUG. Symbols: an object named "clock", an
     * undefined function "clock", a function "other", and the defined "clock" at 0x40. */
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

/**
 * @brief vDSO lookup state machine, the racy-mtime window, and the rule-file throttle.
 */
static void test_clock_lookup_state(void)
{
    const chaos_clock_vdso_fn real = chaos_clock_vdso();
    const int64_t now = chaos_clock_realtime_ms();
    volatile uint64_t last = 0U;

    /* A lookup in progress in this process (state 1, own pid): callers do not spin (a
     * signal handler may have interrupted the owner); they use the fallback. */
    g_chaos_clock_state = 1;
    g_chaos_clock_owner = (long)getpid();
    assert(chaos_clock_vdso() == NULL);
    assert(chaos_clock_now_ns() == 0U);
    assert(chaos_clock_realtime_ms() >= now);
    /* ...claimed by another pid (this child was forked mid-lookup): the claim is taken
     * over and the lookup completes (state 2, own pid). */
    g_chaos_clock_owner = (long)getpid() + 1L;
    assert(chaos_clock_vdso() == real);
    assert(g_chaos_clock_state == 2 && g_chaos_clock_owner == (long)getpid());

    /* Only a stamp within CHAOS_RACY_WINDOW_MS of now, in either direction, is recent. */
    assert(chaos_clock_stamp_is_recent(now / 1000, (long)(now % 1000) * 1000000L));
    assert(!chaos_clock_stamp_is_recent(now / 1000 - 1, (long)(now % 1000) * 1000000L));
    assert(!chaos_clock_stamp_is_recent(now / 1000 + 1, (long)(now % 1000) * 1000000L));

    /* The throttle: interval 0 disables it; otherwise one check per interval. */
    assert(chaos_clock_checked_recently(&last, 0U) == 0 && last == 0U);
    assert(chaos_clock_checked_recently(&last, 1U) == 0 && last != 0U);
    assert(chaos_clock_checked_recently(&last, UINT64_C(1000000000000)) == 1);
}

/** @brief Status report text: line sanitising, truncation, and the rejected-line fields. */
static void test_status_report(void)
{
    chaos_status_error_t error;
    char line[260];
    char report[CHAOS_STATUS_BUFFER_SIZE];

    chaos_status_clear(&error);

    /* Control characters (TAB, DEL) become blanks; the kept text ends at a newline. */
    chaos_status_keep_line(&error, 3U, "a\tb\177c\nd");
    assert(strcmp(error.text, "a b c") == 0 && error.line == 3U && error.reason == NULL);
    /* A long line is kept to its first CHAOS_STATUS_TEXT_MAX bytes. */
    memset(line, 'x', sizeof(line) - 1U);
    line[sizeof(line) - 1U] = '\0';
    chaos_status_keep_line(&error, 4U, line);
    assert(strlen(error.text) == CHAOS_STATUS_TEXT_MAX);

    /* An error without a rejected line, or with a kept line but no reason yet, reports
     * like a plain state; after chaos_status_reject() it reports rules=0 and the line. */
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
    assert(error.warning_count == 0U);

    /* No warning raised: the report carries no `warnings` key at all, so a reader that
     * does not know the key sees exactly what it saw before. */
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_OK, 2U, &error, 9L) > 0U);
    assert(strcmp(report, "state=ok\nrules=2\npid=9\n") == 0);

    /* Warnings are listed in order, numbered from 1, between the state and the pid. The
     * rule file stays in force, so the state is still ok and no error key appears. */
    chaos_status_warn(&error, 4U, CHAOS_STATUS_WARN_SHADOWED);
    chaos_status_warn(&error, 7U, CHAOS_STATUS_WARN_SHADOWED);
    assert(error.warning_count == 2U);
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_OK, 2U, &error, 9L) > 0U);
    assert(
        strcmp(
            report,
            "state=ok\nrules=2\nwarnings=2\n"
            "warn.1=line:4 reason:shadowed by an earlier rule\n"
            "warn.2=line:7 reason:shadowed by an earlier rule\n"
            "pid=9\n"
        ) == 0
    );

    /* A rejected file reports both: the rejection and the warnings raised before it. */
    chaos_status_keep_line(&error, 9U, "bad");
    chaos_status_reject(&error, CHAOS_STATUS_REASON_INVALID);
    assert(error.warning_count == 2U); /* keep_line leaves warnings alone */
    assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_ERROR, 2U, &error, 9L) > 0U);
    assert(
        strcmp(
            report,
            "state=error\nrules=0\nline=9\nreason=invalid rule\ntext=bad\nwarnings=2\n"
            "warn.1=line:4 reason:shadowed by an earlier rule\n"
            "warn.2=line:7 reason:shadowed by an earlier rule\n"
            "pid=9\n"
        ) == 0
    );

    /* Past the cap only the first CHAOS_STATUS_WARN_MAX are listed, while the count keeps
     * rising: a flood is visible without flooding the report. */
    {
        size_t index;
        size_t listed = 0U;
        const char *scan = report;

        chaos_status_clear(&error);
        for (index = 0U; index < CHAOS_STATUS_WARN_MAX + 3U; ++index)
        {
            chaos_status_warn(&error, index + 1U, CHAOS_STATUS_WARN_SHADOWED);
        }
        assert(error.warning_count == CHAOS_STATUS_WARN_MAX + 3U);
        assert(chaos_status_format(report, sizeof(report), CHAOS_STATUS_OK, 1U, &error, 9L) > 0U);
        assert(strstr(report, "warnings=11\n") != NULL);
        while ((scan = strstr(scan, "warn.")) != NULL)
        {
            ++listed;
            ++scan;
        }
        assert(listed == CHAOS_STATUS_WARN_MAX);
        assert(strstr(report, "warn.8=line:8 ") != NULL);
        assert(strstr(report, "warn.9=") == NULL);
    }

    /* A buffer too small truncates between keys and stays a valid string. */
    {
        char tiny[12];

        chaos_status_clear(&error);
        chaos_status_warn(&error, 1U, CHAOS_STATUS_WARN_SHADOWED);
        assert(
            chaos_status_format(tiny, sizeof(tiny), CHAOS_STATUS_OK, 1U, &error, 9L) < sizeof(tiny)
        );
        assert(strlen(tiny) < sizeof(tiny));
        assert(chaos_status_format(tiny, 1U, CHAOS_STATUS_OK, 1U, &error, 9L) == 0U);
        assert(tiny[0] == '\0');
        assert(chaos_status_format(tiny, 0U, CHAOS_STATUS_OK, 1U, &error, 9L) == 0U);
    }
    chaos_status_clear(&error);

    /* A buffer too small: the report is truncated and the return is the length kept. */
    assert(chaos_status_format(report, 8U, CHAOS_STATUS_OK, 1U, NULL, 1L) == 7U);
    assert(strcmp(report, "state=o") == 0);
}

/** @brief Staging-name collisions, write and rename failures, relative names, removal. */
static void test_status_staging(void)
{
    char contents[64];
    int cwd;

    (void)unlink("/tmp/chaos-common-test/.status");

    /* A staging name another writer holds (EEXIST): the next nonce is tried. */
    g_opens = 0U;
    g_open_exists = 2;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "first\n", 6U);
    assert(g_opens == 3U);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    /* ...at most 4 attempts: four taken names leave the file as it was. */
    g_opens = 0U;
    g_open_exists = 4;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "second\n", 7U);
    assert(g_opens == 4U && g_open_exists == 0);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);

    /* A write failing with EIO: the old file stays, errno untouched, staging removed. */
    g_write_fails = EIO;
    errno = 1234;
    chaos_status_replace_file("/tmp/chaos-common-test/.status", "third\n", 6U);
    g_write_fails = 0;
    assert(errno == 1234);
    assert(read_file("/tmp/chaos-common-test/.status", contents, sizeof(contents)) == 6L);
    assert(strcmp(contents, "first\n") == 0);
    assert(!staging_left());

    /* EACCES on the rename is treated like EPERM: rewritten in place. */
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

    /* chaos_status_write() writes the report; removing twice is harmless and keeps errno. */
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

/** @brief Snapshot seqlock: idempotent begin/end, and torn-read detection. */
static void test_snapshot_sequence(void)
{
    volatile uint64_t sequence = 0U;
    uint64_t begin;

    /* Begin and end are idempotent; a read begun while odd, or whose begin value differs
     * from the current sequence (a write intervened), is reported torn. */
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

/** @brief Slot assignment across reloads, release on removal, and reset after fork. */
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
    uint64_t armed;

    memset(pool, 0, sizeof(pool));
    chaos_hits_pool_reset(pool, 3U);
    chaos_hits_assign(pool, 3U, NULL, NULL, 0U, slots, first, 2U, NULL);
    assert(slots[0] == &pool[0] && slots[1] == &pool[1]);
    pool[1].count = 7U;
    /* The evaluation ordinal of whoever held a slot before must not be inherited: it is
     * what the draw key is mixed with, so a rule starting at somebody else's ordinal
     * makes different decisions for the same seed, and `@every=N` fires on the wrong
     * calls. Slot 2 below is handed to a rule that is new to this process. */
    pool[2].evaluations = 11U;
    /* As if this rule had been active for five seconds already, which the reload below
     * must not forget: within one millisecond a re-armed slot would be indistinguishable
     * from one that kept its moment. */
    assert(pool[1].armed_ms != 0U);
    armed = pool[1].armed_ms - 5000U;
    pool[1].armed_ms = armed;

    /* A rule whose text survives the reload keeps its slot and count (B moves from index 1
     * to 0); an active entry without a slot is not matched by text (C is new); a new rule
     * takes the next free slot. */
    active[0] = slots[0];
    active[1] = NULL;
    active[2] = slots[1];
    chaos_hits_assign(pool, 3U, active, active_texts, 3U, next, next_texts, 2U, count_report);
    assert(next[0] == &pool[1] && pool[1].count == 7U && pool[1].report == count_report);
    assert(next[1] == &pool[2] && pool[2].count == 0U && pool[2].used);
    assert(pool[2].evaluations == 0U);
    /* The moment a rule became active, which `@at=+N` counts from: the slot carried over
     * keeps the moment it got at the first assignment, so a reload that leaves a rule
     * alone does not restart its delay; the slot that is new to this process gets one
     * now. */
    assert(armed != 0U && pool[1].armed_ms == armed);
    assert(pool[2].armed_ms != 0U);

    /* The rule that left (A) frees its slot and bumps its generation, so stale copies of
     * it stop matching; a NULL slot is always current. */
    generation = pool[0].generation;
    chaos_hits_release(pool, 3U, next, 2U);
    assert(!pool[0].used && pool[0].generation == generation + 1U);
    assert(pool[1].used && pool[2].used);
    assert(!chaos_hit_slot_current(&pool[0], generation));
    assert(chaos_hit_slot_current(&pool[0], generation + 1U));
    assert(chaos_hit_slot_current(NULL, generation));

    /* After fork the child zeroes its counts and claims; REGRESS state 3 (decision in
     * progress in a parent thread that does not exist in the child) returns to 1 (armed),
     * state 2 (already jumped) is kept. A reload the fork interrupted (snapshot assigned,
     * never published) leaves slot 0 held by no published snapshot: it is released. */
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

/** @brief Hits file numbering: the pid, then pid * 10^9 + salt + attempt; 8 names checked. */
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

    /* Without a vDSO clock the salt is 0, so the candidate numbers are predictable. */
    g_chaos_clock_vdso = failing_vdso;
    assert(chaos_hits_file_number_for("/tmp/chaos-common-test/n", 1L) == 1L);
    (void)close(open("/tmp/chaos-common-test/n.1", O_WRONLY | O_CREAT, 0600));
    assert(chaos_hits_file_number_for("/tmp/chaos-common-test/n", 1L) == 1000000000L);
    /* All 8 candidates taken: the 9th number is returned unchecked; errno is preserved. */
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

    /* A prefix too long to form a name: the pid is returned as is. */
    memset(long_prefix, 'p', sizeof(long_prefix) - 1U);
    long_prefix[sizeof(long_prefix) - 1U] = '\0';
    assert(chaos_hits_file_number_for(long_prefix, 42L) == 42L);
    assert(chaos_hits_file_number(long_prefix) == (long)getpid());
}

/* A once-control whose initialiser spins until a helper thread releases it.
 *
 * The three flags are handed between threads with the same acquire/release builtins
 * chaos_once.h uses, not with `volatile`: volatile keeps the compiler from caching the
 * value but orders nothing, so a handshake built on it is a data race that happens to
 * work on the two architectures this is built for. It also hides the ordering from
 * ThreadSanitizer, which then reports the test rather than the code under test. */
static volatile chaos_once_t g_once = CHAOS_ONCE_INIT;
static int g_initialising = 0;
static int g_release = 0;
static int g_initialised = 0;

static void slow_initialise(void)
{
    __atomic_store_n(&g_initialising, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&g_release, __ATOMIC_ACQUIRE) == 0)
    {
        (void)sched_yield();
    }
    __atomic_store_n(&g_initialised, 1, __ATOMIC_RELEASE);
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
    __atomic_store_n(&g_release, 1, __ATOMIC_RELEASE);
    return NULL;
}

/**
 * @brief A thread that enters chaos_once() while another thread's initialiser runs waits
 *        until it completes, and returns only once the initialisation is visible.
 *
 * @details The releaser sleeps 20 ms before letting the initialiser finish, so the main
 * thread's chaos_once() call is reliably made while initialisation is in progress.
 */
static void test_once_waits(void)
{
    pthread_t initialiser;
    pthread_t releaser;

    assert(pthread_create(&initialiser, NULL, run_once, NULL) == 0);
    while (__atomic_load_n(&g_initialising, __ATOMIC_ACQUIRE) == 0)
    {
        (void)sched_yield();
    }

    assert(pthread_create(&releaser, NULL, release_later, NULL) == 0);
    assert(chaos_once(&g_once, slow_initialise) == 1);
    /* Plain read: chaos_once() returning 1 is what makes the initialiser's write visible,
     * and that is the property under test. */
    assert(__atomic_load_n(&g_initialised, __ATOMIC_RELAXED) == 1);
    assert(pthread_join(initialiser, NULL) == 0);
    assert(pthread_join(releaser, NULL) == 0);
}

/**
 * @brief The token bucket: what it hands out, what it refills, and what it reserves.
 *
 * @details The bucket is a pure function of its state word and the millisecond it is
 * asked at, so every property is checked by asking at chosen times rather than by
 * sleeping. The rate is 1000 bytes per second throughout, which makes a millisecond worth
 * exactly one byte and the arithmetic readable.
 */
static void test_bucket(void)
{
    chaos_bucket_t bucket;

    /* No rate, nothing wanted, or no clock: the call is not held back at all. A bucket
     * that throttled when the clock is unreadable would block a process for ever. */
    bucket.state = 0U;
    assert(chaos_bucket_take(&bucket, 0U, 500U, 1000U) == 500U);
    assert(chaos_bucket_take(&bucket, 1000U, 0U, 1000U) == 0U);
    assert(chaos_bucket_take(&bucket, 1000U, 500U, 0U) == 500U);
    assert(chaos_bucket_reserve(&bucket, 0U, 500U, 1000U) == 0U);
    assert(chaos_bucket_reserve(&bucket, 1000U, 0U, 1000U) == 0U);
    assert(chaos_bucket_reserve(&bucket, 1000U, 500U, 0U) == 0U);
    assert(bucket.state == 0U);

    /* A bucket nobody has used is full: the first second's worth passes at once, and only
     * a caller that keeps going is slowed down. */
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, 10000U) == 1000U);
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, 10000U) == 0U);
    /* Refill is the elapsed milliseconds, one byte each, and what is asked for bounds it. */
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, 10400U) == 400U);
    assert(chaos_bucket_take(&bucket, 1000U, 100U, 10900U) == 100U);
    /* Never more than one second's worth, however long the bucket stood idle. */
    assert(chaos_bucket_take(&bucket, 1000U, 5000U, 20000U) == 1000U);

    /* A tenth of a second's worth is what a caller that has to wait asks for, and it
     * never rounds down to nothing: below ten bytes per second the chunk is one byte. */
    assert(chaos_bucket_chunk(1000U) == 100U);
    assert(chaos_bucket_chunk(10U) == 1U);
    assert(chaos_bucket_chunk(9U) == 1U);
    assert(chaos_bucket_chunk(1U) == 1U);

    /* The wait for what is not there yet, rounded up so it is never short of a token. */
    assert(chaos_bucket_wait_ms(1000U, 100U) == 100U);
    assert(chaos_bucket_wait_ms(1000U, 1U) == 1U);
    assert(chaos_bucket_wait_ms(1000000U, 1U) == 1U);
    assert(chaos_bucket_wait_ms(0U, 100U) == 0U);
    assert(chaos_bucket_wait_ms(1000U, 0U) == 0U);

    /* A reservation hands out bytes that have not arrived and returns the wait for them.
     * The empty bucket of the line above is at 20000 with nothing left. */
    assert(chaos_bucket_reserve(&bucket, 1000U, 100U, 20000U) == 100U);
    /* The bytes are charged, so a call at the moment the wait is over gets nothing more
     * than what arrived meanwhile: without the charge the rate would double. */
    assert(chaos_bucket_take(&bucket, 1000U, 100U, 20100U) == 0U);
    /* And a second reservation made while the first one waits is told to wait for both,
     * which is what holds the rate when several threads share a descriptor. */
    assert(chaos_bucket_reserve(&bucket, 1000U, 100U, 20000U) == 200U);
    assert(chaos_bucket_reserve(&bucket, 1000U, 100U, 20000U) == 300U);
    /* A reservation covered by what is in the bucket waits not at all and empties it. */
    bucket.state = 0U;
    assert(chaos_bucket_reserve(&bucket, 1000U, 400U, 30000U) == 0U);
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, 30000U) == 600U);

    /* A lost race: the attempt fails, the loop looks again and hands out the same bytes,
     * because nothing but the bucket's own word is involved. */
    bucket.state = 0U;
    g_bucket_cas_fails = 1U;
    assert(chaos_bucket_take(&bucket, 1000U, 400U, 40000U) == 400U);
    assert(g_bucket_cas_fails == 0U);
    g_bucket_cas_fails = 1U;
    assert(chaos_bucket_reserve(&bucket, 1000U, 1000U, 40000U) == 400U);
    assert(g_bucket_cas_fails == 0U);

    /* The millisecond is truncated to 32 bits and every comparison is a signed
     * difference, so the wrap after 49 days is not a special case: a stamp just below it
     * and a reading just above it are 2 ms apart, not 4294967294. */
    assert(chaos_bucket_later(UINT64_C(0x100000001), UINT64_C(0xffffffff)));
    assert(!chaos_bucket_later(UINT64_C(0xffffffff), UINT64_C(0x100000001)));
    bucket.state = 0U;
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, UINT64_C(0xffffffff)) == 1000U);
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, UINT64_C(0x100000001)) == 2U);
    /* And what is stored is the truncated millisecond: a whole reading would spill into
     * the token half of the word and hand out tokens nobody refilled. A monotonic clock
     * passes 2^32 ms after 49 days of uptime, so this is the ordinary case, not an edge. */
    bucket.state = 0U;
    assert(chaos_bucket_take(&bucket, 1000U, 1000U, UINT64_C(0x1000003e8)) == 1000U);
    assert((bucket.state >> 32) == 0U);
    bucket.state = 0U;
    assert(chaos_bucket_reserve(&bucket, 1000U, 2000U, UINT64_C(0x1000003e8)) == 1000U);
    assert((bucket.state >> 32) == 0U);

    /* A rate whose millisecond is worth less than a byte. Asked once per millisecond, the
     * elapsed time must not be thrown away: at 500 bytes a second a byte is due every
     * other millisecond, so a hundred milliseconds of polling must hand out fifty. The
     * whole second's worth the bucket starts with is drained first, so what follows is
     * refill alone. Rates below a thousand are the common ones -- a slow log shipper, a
     * trickling metrics push -- and a bucket that loses the remainder hands out nothing
     * for them, for ever. */
    {
        uint64_t moved = 0U;
        uint64_t at;

        bucket.state = 0U;
        assert(chaos_bucket_take(&bucket, 500U, 500U, 30000U) == 500U);
        for (at = 30001U; at <= 30100U; ++at)
        {
            moved += chaos_bucket_take(&bucket, 500U, 1U, at);
        }
        assert(moved == 50U);
    }

    /* Giving back what could not be used. A caller that takes its allowance and then has
     * to answer EAGAIN moved nothing, so the bytes come back or its next attempt meets a
     * bucket it drained itself -- and a datagram larger than one second's worth, which the
     * take can never cover because the bucket is capped there, would never be sent at all.
     * The ceiling still holds, and the stamp is untouched. */
    {
        const uint64_t at = 40000U;

        bucket.state = 0U;
        assert(chaos_bucket_take(&bucket, 1000U, 1000U, at) == 1000U);
        assert(chaos_bucket_take(&bucket, 1000U, 10U, at) == 0U);
        chaos_bucket_return(&bucket, 1000U, 400U, at);
        assert(chaos_bucket_take(&bucket, 1000U, 1000U, at) == 400U);
        /* More back than the bucket holds is capped, not wrapped. */
        chaos_bucket_return(&bucket, 1000U, 99999U, at);
        assert(chaos_bucket_take(&bucket, 1000U, 5000U, at) == 1000U);
        /* No rate, nothing given, no clock: nothing happens, as everywhere else here. */
        chaos_bucket_return(&bucket, 0U, 10U, at);
        chaos_bucket_return(&bucket, 1000U, 0U, at);
        chaos_bucket_return(&bucket, 1000U, 10U, 0U);
        assert(chaos_bucket_take(&bucket, 1000U, 10U, at) == 0U);
        /* And a lost race: the state moved under the caller, so it reads it again and
         * gives the bytes back on top of what it finds. */
        g_bucket_cas_fails = 1U;
        chaos_bucket_return(&bucket, 1000U, 250U, at);
        assert(g_bucket_cas_fails == 0U);
        assert(chaos_bucket_take(&bucket, 1000U, 1000U, at) == 250U);
    }
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
    test_bucket();
    (void)rmdir("/tmp/chaos-common-test");
    return 0;
}
