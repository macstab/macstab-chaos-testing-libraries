/**
 * @file test_chaos_init_io.c
 * @brief Proves chaos-init resolves io system calls to the same path strings and
 *        operations the libchaos-io wrappers use, and applies ERRNO and LATENCY to them.
 *
 * @details Unit under test: `chaos_init_io_decide()` in `src/init/chaos_init_io.c`,
 * compiled in by `#include` with the libchaos-io rule core, `chaos_init_proc.c` and
 * `chaos_init_tracee.c`.
 *
 * Isolation: no supervisor and no seccomp filter. Each call is a `chaos_init_call_t`
 * filled as a notification fills it, with this process as the caller, so the real
 * resolution paths run against real state: process_vm_readv(2) reads paths and iovec
 * arrays from this process, `/proc/<pid>/fd/<n>` and `/proc/<pid>/cwd` resolve its own
 * descriptors and working directory. A forked child parked in pause(2) is the second
 * process for per-process counting. Fixtures live under `/tmp/initio`.
 *
 * Seams, both defined before the include and delegating to the real function otherwise:
 * - `CHAOS_INIT_IO_PROC_LINK`: `g_fail_cwd` makes the `cwd` link unreadable;
 * - `CHAOS_INIT_PROCESS_OF`: `g_fail_process` makes the caller unresolvable (vanished).
 *
 * Properties proven:
 * - a file is named absolutely, relative to the cwd, relative to a directory fd, or by
 *   fd; what cannot be named passes: fds 0-2, a pipe, an unopened fd, unreadable memory,
 *   an unreadable cwd, a relative path that overflows CHAOS_IO_MAX_PATH once joined;
 * - ERRNO gives FAIL, LATENCY gives DELAY, probability 0 never fires;
 * - `@size` sees the byte count, for iovec arrays the sum of iov_len (more than 1024
 *   entries or an unreadable array is unknown size and does not match);
 * - sendfile and copy_file_range are writes to their output fd only;
 * - renames follow the wrapper: the destination's rule wins when its prefix is at least
 *   as long as the source's; an unreadable side leaves the other to decide;
 * - `@first` and hit counts are per process and land in that process's hits file;
 *   counts follow rule texts across reloads, also when a reload reuses a snapshot buffer;
 * - TORN, CORRUPT and ERRNO on close reject the whole rule file in SECCOMP mode, with
 *   the status file naming the line;
 * - /proc is never faulted, also as a rename source a rule names explicitly.
 */

#include <stdint.h>
#include <sys/types.h>

/* Seams: an unreadable `cwd` link (any link name starting with 'c'; the code under test
 * only reads `cwd` and `fd/<n>`), and a caller that vanished after its call matched. */
static int g_fail_cwd = 0;
static int g_fail_process = 0;
long chaos_init_proc_link(pid_t pid, const char *name, char *out, size_t size);
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
static long test_proc_link(pid_t pid, const char *name, char *out, size_t size)
{
    return g_fail_cwd && name[0] == 'c' ? -1 : chaos_init_proc_link(pid, name, out, size);
}
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    return g_fail_process ? -1 : chaos_init_process_of(tid, tgid, start);
}
#define CHAOS_INIT_IO_PROC_LINK test_proc_link
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

#include "../../src/init/chaos_init_io.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-io.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-io.conf.new", "/tmp/.chaos-io.conf") == 0);
}

/**
 * @brief Decides system call @p nr made by @p tid with arguments a0..a4; asserts io
 *        owns it. The verdict is pre-set to FAIL/-1 so a PASS proves it was written.
 */
static chaos_init_verdict_t
decide_for(pid_t tid, int nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    call.tid = tid;
    call.nr = nr;
    call.args[0] = a0;
    call.args[1] = a1;
    call.args[2] = a2;
    call.args[3] = a3;
    call.args[4] = a4;
    verdict.action = CHAOS_INIT_FAIL;
    verdict.error = -1;
    assert(chaos_init_io_decide(&call, &verdict) == 1);
    return verdict;
}

static chaos_init_verdict_t
decide(int nr, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    return decide_for(getpid(), nr, a0, a1, a2, a3, a4);
}

#define P(text) ((uint64_t)(uintptr_t)(text))

/* Functions, not macros: a macro would evaluate the decide() argument twice and spend
 * an `@first` hit on the first evaluation. */
static int FAILS(chaos_init_verdict_t verdict, int error)
{
    return verdict.action == CHAOS_INIT_FAIL && verdict.error == error;
}

static int PASSES(chaos_init_verdict_t verdict)
{
    return verdict.action == CHAOS_INIT_PASS;
}

/** @brief Opens (creating) @p path read-write; stays open so /proc/<pid>/fd resolves it. */
static int open_file(const char *path)
{
    const int fd = open(path, O_CREAT | O_RDWR, 0644);

    assert(fd > 2);
    return fd;
}

int main(void)
{
    chaos_init_call_t other;
    chaos_init_verdict_t verdict;
    struct iovec vector[3];
    char buffer[400];
    char hits[2048];
    int pipe_fds[2];
    int dir;
    int big;
    int torn;
    int full;
    int closing;
    int syncing;
    pid_t child;
    FILE *file;

    (void)unlink("/tmp/.chaos-io.conf");
    assert(
        system("rm -rf /tmp/initio && mkdir -p /tmp/initio/data /tmp/initio/big "
               "/tmp/initio/torn /tmp/initio/w /tmp/initio/c /tmp/initio/s /tmp/initio/ren/to "
               "/tmp/initio/ren/from /tmp/initio/t") == 0
    );
    chaos_init_io_start();
    g_chaos_io_check_interval_ns = 0U;

    /* A non-io system call is not io's: decide returns 0 so another library may own it. */
    memset(&other, 0, sizeof(other));
    other.tid = getpid();
    other.nr = __NR_getpid;
    assert(chaos_init_io_decide(&other, &verdict) == 0);

    /* No rule file: every call passes, renames included. */
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    assert(PASSES(decide(
        __NR_renameat2,
        (uint64_t)AT_FDCWD,
        P("/tmp/initio/ren/from/a"),
        (uint64_t)AT_FDCWD,
        P("/tmp/initio/x"),
        0
    )));

    write_rules("/tmp/initio/data:open:EIO:1.0\n"
                "/tmp/initio/slow:open:LATENCY:25\n"
                "/tmp/initio/never:open:EIO:0.0\n"
                "/tmp/initio/once:open:EACCES:1.0 @first=1\n"
                "/tmp/initio/big:read:EIO:1.0 @size>100\n"
                "/tmp/initio/w:write:ENOSPC:1.0\n"
                "/tmp/initio/s:fsync:EIO:1.0\n"
                "/tmp/initio/t:truncate:EROFS:1.0\n"
                "/tmp/initio/data:unlink:EACCES:1.0\n"
                "/tmp/initio/ren:rename_from:EMFILE:1.0\n"
                "/tmp/initio/ren/from:rename_from:EACCES:1.0\n"
                "/tmp/initio/ren/to:rename_to:ENFILE:1.0\n");

    /* The same file named three ways resolves to the same string and matches each time
     * (the hits check below expects exactly 3 hits on this rule). */
    verdict = decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0);
    assert(FAILS(verdict, EIO));
    assert(chdir("/tmp/initio") == 0);
    assert(FAILS(decide(__NR_openat, (uint64_t)AT_FDCWD, P("data/y"), 0, 0, 0), EIO));
    dir = open("/tmp/initio", O_RDONLY | O_DIRECTORY);
    assert(dir > 2);
    assert(FAILS(decide(__NR_openat, (uint64_t)dir, P("data/z"), 0, 0, 0), EIO));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("elsewhere"), 0, 0, 0)));

    /* Fail-open when the path cannot be named: a pipe or fd 0-2 as directory fd, a NULL
     * path, an excluded /proc path, and an unreadable cwd link. */
    assert(pipe(pipe_fds) == 0);
    assert(PASSES(decide(__NR_openat, (uint64_t)pipe_fds[0], P("data/z"), 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, 1U, P("data/z"), 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, 0U, 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/proc/self/status"), 0, 0, 0)));
    g_fail_cwd = 1;
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("data/y"), 0, 0, 0)));
    g_fail_cwd = 0;
    /* A relative path that fits CHAOS_IO_MAX_PATH alone but overflows it once joined to
     * the cwd `/tmp/initio`: the join fails and the call passes rather than matching a
     * truncated path. */
    {
        static char long_path[CHAOS_IO_MAX_PATH];

        memcpy(long_path, "data/", 5U);
        memset(long_path + 5, 'a', CHAOS_IO_MAX_PATH - 11U);
        long_path[CHAOS_IO_MAX_PATH - 6U] = '\0';
        assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P(long_path), 0, 0, 0)));
    }
    assert(chdir("/") == 0);

    /* Fail-open for a vanished caller: the path matches but no hit slot exists, so the
     * call passes and is not counted (the hits check below still expects 3). */
    g_fail_process = 1;
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    g_fail_process = 0;

    /* LATENCY gives a 25 ms DELAY; probability 0.0 never fires. */
    verdict = decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/slow/a"), 0, 0, 0);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 25U);
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/never/a"), 0, 0, 0)));

    /* `@first=1` is per process: this process spends its one hit, then the parked child
     * still gets its own first hit. */
    assert(FAILS(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/once/a"), 0, 0, 0), EACCES)
    );
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/once/a"), 0, 0, 0)));
    child = fork();
    if (child == 0)
    {
        pause();
        _exit(0);
    }
    assert(child > 0);
    assert(FAILS(
        decide_for(child, __NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/once/a"), 0, 0, 0), EACCES
    ));
    assert(kill(child, SIGKILL) == 0 && waitpid(child, NULL, 0) == child);

    /* By descriptor, with `@size>100`: read uses args[2]; readv sums iov_len (3 x 100
     * matches, 1 x 100 does not); 2000 entries exceeds the 1024 cap and a NULL array is
     * unreadable, both unknown size. fd 1, a pipe and an unopened fd have no path. */
    big = open_file("/tmp/initio/big/f");
    assert(PASSES(decide(__NR_read, (uint64_t)big, P(buffer), 50U, 0, 0)));
    assert(FAILS(decide(__NR_read, (uint64_t)big, P(buffer), 500U, 0, 0), EIO));
    vector[0].iov_base = buffer;
    vector[0].iov_len = 100U;
    vector[1].iov_base = buffer + 100;
    vector[1].iov_len = 100U;
    vector[2].iov_base = buffer + 200;
    vector[2].iov_len = 100U;
    assert(FAILS(decide(__NR_readv, (uint64_t)big, P(vector), 3U, 0, 0), EIO));
    assert(PASSES(decide(__NR_readv, (uint64_t)big, P(vector), 1U, 0, 0)));
    assert(PASSES(decide(__NR_readv, (uint64_t)big, P(vector), 2000U, 0, 0)));
    assert(PASSES(decide(__NR_readv, (uint64_t)big, 0U, 3U, 0, 0)));
    assert(PASSES(decide(__NR_read, 1U, P(buffer), 500U, 0, 0)));
    assert(PASSES(decide(__NR_read, (uint64_t)pipe_fds[0], P(buffer), 500U, 0, 0)));
    assert(PASSES(decide(__NR_read, 999U, P(buffer), 500U, 0, 0))); /* not open */

    /* sendfile and copy_file_range are writes to their output fd: they fail when the
     * output is under the write rule, and pass when only the input is. */
    full = open_file("/tmp/initio/w/f");
    assert(FAILS(decide(__NR_write, (uint64_t)full, P(buffer), 10U, 0, 0), ENOSPC));
    assert(FAILS(decide(__NR_sendfile, (uint64_t)full, (uint64_t)big, 0, 10U, 0), ENOSPC));
    assert(FAILS(decide(__NR_copy_file_range, (uint64_t)big, 0, (uint64_t)full, 0, 10U), ENOSPC));
    assert(PASSES(decide(__NR_copy_file_range, (uint64_t)full, 0, (uint64_t)big, 0, 10U)));

    /* fsync and fdatasync are distinct operations; truncate matches by path, ftruncate
     * by fd (here an fd outside the truncate rule); unlinkat by dirfd + path. */
    syncing = open_file("/tmp/initio/s/f");
    assert(FAILS(decide(__NR_fsync, (uint64_t)syncing, 0, 0, 0, 0), EIO));
    assert(PASSES(decide(__NR_fdatasync, (uint64_t)syncing, 0, 0, 0, 0)));
    assert(FAILS(decide(__NR_truncate, P("/tmp/initio/t/f"), 0, 0, 0, 0), EROFS));
    assert(PASSES(decide(__NR_truncate, P("/tmp/initio/data/f"), 0, 0, 0, 0))); /* no rule */
    assert(PASSES(decide(__NR_truncate, 0U, 0, 0, 0, 0)));                      /* unreadable */
    (void)close(open_file("/tmp/initio/t/f"));
    assert(PASSES(decide(__NR_ftruncate, (uint64_t)full, 0, 0, 0, 0)));
    assert(
        FAILS(decide(__NR_unlinkat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/f"), 0, 0, 0), EACCES)
    );

    /* Renames match rename_from on the source and rename_to on the destination; the
     * destination's rule wins when its prefix is at least as long. Third case: source
     * `ren` (EMFILE) loses to destination `ren/to` (ENFILE). */
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/from/a"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/x"),
            0
        ),
        EACCES
    ));
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/x"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/to/b"),
            0
        ),
        ENFILE
    ));
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/a"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/to/b"),
            0
        ),
        ENFILE
    ));
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/from/a"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/x"),
            0
        ),
        EACCES
    ));
    assert(PASSES(decide(
        __NR_renameat2,
        (uint64_t)AT_FDCWD,
        P("/tmp/initio/x"),
        (uint64_t)AT_FDCWD,
        P("/tmp/initio/y"),
        0
    )));
    assert(PASSES(decide(__NR_renameat2, (uint64_t)AT_FDCWD, 0U, (uint64_t)AT_FDCWD, 0U, 0)));
    /* Both sides match and `ren/from` is longer than `ren/to`: the source's rule wins. */
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/from/a"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/to/b"),
            0
        ),
        EACCES
    ));
    /* An unreadable destination leaves the source to decide; below, x86_64 rename(2)
     * takes the same path, and an unreadable source leaves the destination to decide. */
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/ren/from/a"),
            (uint64_t)AT_FDCWD,
            0U,
            0
        ),
        EACCES
    ));
#ifdef __NR_rename
    assert(
        FAILS(decide(__NR_rename, P("/tmp/initio/ren/from/a"), P("/tmp/initio/x"), 0, 0, 0), EACCES)
    );
#endif
    assert(FAILS(
        decide(
            __NR_renameat2, (uint64_t)AT_FDCWD, 0U, (uint64_t)AT_FDCWD, P("/tmp/initio/ren/to/b"), 0
        ),
        ENFILE
    ));

    /* The hits file is rewritten on each of a process's first CHAOS_HITS_EAGER hits, so
     * it is current without a flush: 3 hits on the data rule, 1 on `@first`, and the
     * never-firing rule listed at 0. */
    (void)snprintf(buffer, sizeof(buffer), "/tmp/.chaos-io.hits.%ld", (long)getpid());
    file = fopen(buffer, "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(
        strncmp(
            hits, "3\t/tmp/initio/data:open:EIO:1.0\n", strlen("3\t/tmp/initio/data:open:EIO:1.0\n")
        ) == 0
    );
    assert(strstr(hits, "1\t/tmp/initio/once:open:EACCES:1.0 @first=1\n") != NULL);
    assert(strstr(hits, "0\t/tmp/initio/never:open:EIO:0.0\n") != NULL);

    /* The child's hits file holds only its own counts: its `@first` hit, and 0 on the
     * data rule this process hit 3 times. */
    (void)unlink(buffer);
    (void)snprintf(buffer, sizeof(buffer), "/tmp/.chaos-io.hits.%ld", (long)child);
    file = fopen(buffer, "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(strstr(hits, "1\t/tmp/initio/once:open:EACCES:1.0 @first=1\n") != NULL);
    assert(
        strncmp(
            hits, "0\t/tmp/initio/data:open:EIO:1.0\n", strlen("0\t/tmp/initio/data:open:EIO:1.0\n")
        ) == 0
    );
    (void)unlink(buffer);

    /* Effects SECCOMP mode cannot apply reject the whole rule file: TORN and CORRUPT
     * rewrite data the kernel moves, and ERRNO on close would need the descriptor closed
     * and the call failed at once. No rule of a rejected file applies (the valid open
     * rule on line 1 passes too) and the status file names the offending line. */
    torn = open_file("/tmp/initio/torn/f");
    closing = open_file("/tmp/initio/c/f");
    write_rules("/tmp/initio/data:open:EIO:1.0\n/tmp/initio/torn:write:TORN:1.0\n");
    assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    file = fopen("/tmp/.chaos-io.status", "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(
        strncmp(
            hits,
            "state=error\nrules=0\nline=2\nreason=unsupported in seccomp mode\n",
            strlen("state=error\nrules=0\nline=2\nreason=unsupported in seccomp mode\n")
        ) == 0
    );
    write_rules("/tmp/initio/c:close:EIO:1.0\n");
    assert(PASSES(decide(__NR_close, (uint64_t)closing, 0, 0, 0, 0)));
    write_rules("/tmp/initio/c:close:LATENCY:5\n/tmp/initio/data:read:CORRUPT:1.0\n");
    assert(PASSES(decide(__NR_close, (uint64_t)closing, 0, 0, 0, 0)));
    write_rules("/tmp/initio/c:close:LATENCY:5\n");
    assert(decide(__NR_close, (uint64_t)closing, 0, 0, 0, 0).action == CHAOS_INIT_DELAY);

    /* The /proc exclusion beats an explicit rule: a rename from /proc passes, while the
     * same rename shape under /tmp/initio fails. */
    write_rules("/proc:rename_from:EROFS:1.0\n/tmp/initio:rename_from:EROFS:1.0\n");
    assert(PASSES(decide(
        __NR_renameat2,
        (uint64_t)AT_FDCWD,
        P("/proc/self/x"),
        (uint64_t)AT_FDCWD,
        P("/tmp/initio/x"),
        0
    )));
    assert(FAILS(
        decide(
            __NR_renameat2,
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/x"),
            (uint64_t)AT_FDCWD,
            P("/tmp/initio/y"),
            0
        ),
        EROFS
    ));

    /* Two reloads between calls: the second reload reuses the snapshot buffer of the
     * first, so state pointer equality alone would miss it. The new `@first=1` text must
     * start from zero hits, not inherit the exhausted count of the text it replaced. */
    write_rules("/tmp/initio/data:open:EIO:1.0 @first=1\n");
    assert(FAILS(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0), EIO));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    write_rules("/tmp/initio/other:open:EIO:1.0\n");
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    write_rules("/tmp/initio/data:open:EACCES:1.0 @first=1\n");
    assert(FAILS(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0), EACCES)
    );
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));

    (void)snprintf(buffer, sizeof(buffer), "/tmp/.chaos-io.hits.%ld", (long)getpid());
    (void)unlink(buffer);
    (void)unlink("/tmp/.chaos-io.conf");
    return 0;
}
