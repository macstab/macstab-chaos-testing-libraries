/**
 * @file test_common.c
 * @brief Unit tests for the headers every library shares (src/common).
 *
 * Subsystem under test: `chaos_policy.h`, `chaos_clock.h`, `chaos_status.h`,
 * `chaos_hits.h` and `chaos_once.h`, through the paths the libraries' own tests
 * cannot reach: failing system calls, a missing or broken vDSO, full buffers, a
 * full slot pool, and a second thread waiting for an initialiser.
 *
 * Coverage approach: the status files' system calls and the raw clock are
 * replaced with stubs that fail on request; the vDSO lookup is fed hand-made ELF
 * images; the vDSO clock is replaced with one that fails.
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
 * - a thread that finds an initialiser running on another thread waits for it.
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

#include "../../src/common/chaos_hits.h"
#include "../../src/common/chaos_once.h"
#include "../../src/common/chaos_policy.h"

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
    test_once_waits();
    (void)rmdir("/tmp/chaos-common-test");
    return 0;
}
