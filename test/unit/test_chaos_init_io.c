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
 * - CORRUPT and ERRNO on close reject the whole rule file in SECCOMP mode, with
 *   the status file naming the line;
 * - /proc is never faulted, also as a rename source a rule names explicitly.
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
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
/* Seams for what a dropped write needs to know about a descriptor: its fdinfo, which can
 * be unreadable or hold no flags line, and its type. Neither failure is reachable through
 * a real descriptor -- a closed one has no /proc/<pid>/fd link either, so the decision
 * stops before this. */
static int g_fail_fdinfo = 0;
static const char *g_fdinfo_instead = NULL;
static int g_fail_fd_stat = 0;
static FILE *test_fdinfo_open(const char *path, const char *mode)
{
    if (g_fail_fdinfo)
    {
        return NULL;
    }
    return fopen(g_fdinfo_instead != NULL ? g_fdinfo_instead : path, mode);
}
static int test_fd_stat(const char *path, struct stat *out)
{
    return g_fail_fd_stat ? -1 : stat(path, out);
}
#define CHAOS_INIT_IO_PROC_LINK test_proc_link
#define CHAOS_INIT_IO_FDINFO_OPEN test_fdinfo_open
#define CHAOS_INIT_IO_FD_STAT test_fd_stat
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

#include "../../src/init/chaos_init_io.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

/* The seed source lives in chaos_init_core.c, which this test does not include; the
 * declaration comes from chaos_init_core.h, so the definition may follow the include. A
 * fixed value keeps the rules' draw keys the same in every run. */
uint64_t chaos_init_seed(void)
{
    return UINT64_C(0x5eed5eed5eed5eed);
}

/* The installed TRACE set lives in chaos_init_core.c, which this test does not include.
 * `g_traced_all` is the seam: with it set every call counts as traced, which is the state
 * a container starts in when its rule file already asked for those effects; cleared, it
 * is a filter that traces nothing, which is what a reload adding such an effect meets. */
static int g_traced_all = 1;
void chaos_init_traced_set(const long *calls, size_t count)
{
    (void)calls;
    (void)count;
}
int chaos_init_traced(long nr)
{
    (void)nr;
    return g_traced_all;
}

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
    /* Zeroed as chaos_init_decide() zeroes it, then pre-set to FAIL/-1 so a PASS proves
     * the decider wrote it. */
    memset(&verdict, 0, sizeof(verdict));
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

static int RETURNS(chaos_init_verdict_t verdict, long value)
{
    return verdict.action == CHAOS_INIT_RETURN && verdict.value == value;
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
               "/tmp/initio/ren/from /tmp/initio/t && mkfifo /tmp/initio/torn/pipe") == 0
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
                "/tmp/initio/big:truncate:ENOSPC:1.0 @size>100\n"
                "/tmp/initio/big:allocate:EDQUOT:1.0 @size>100\n"
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
    /* A total above SSIZE_MAX is no byte count either: the call returns ssize_t and the
     * kernel rejects it, and a wrapping sum would have handed `@size>100` a small number
     * for a request larger than the address space. */
    vector[0].iov_len = (size_t)SSIZE_MAX;
    vector[1].iov_len = (size_t)SSIZE_MAX;
    assert(PASSES(decide(__NR_readv, (uint64_t)big, P(vector), 2U, 0, 0)));
    vector[0].iov_len = 100U;
    vector[1].iov_len = 100U;
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
    /* truncate reports its length (args[1] for both forms), so `@size` decides on it as it
     * does under LD_PRELOAD. */
    assert(FAILS(decide(__NR_truncate, P("/tmp/initio/big/f"), 200U, 0, 0, 0), ENOSPC));
    assert(PASSES(decide(__NR_truncate, P("/tmp/initio/big/f"), 50U, 0, 0, 0)));
    /* fallocate reports its length too, from args[3]: the wrappers always passed it while
     * this table said the call had none, so `@size` worked under LD_PRELOAD and silently
     * never fired here. */
    assert(FAILS(decide(__NR_fallocate, (uint64_t)big, 0, 0, 200U, 0), EDQUOT));
    assert(PASSES(decide(__NR_fallocate, (uint64_t)big, 0, 0, 50U, 0)));
    /* A negative length is not a byte count. Both of these carry a signed off_t, the
     * kernel rejects them with EINVAL, and the wrapper maps them to "no size" for exactly
     * that reason -- read out of the register as unsigned, -4096 is a count above any
     * `@size>N` gate, so the supervisor failed a call the kernel would have refused while
     * LD_PRELOAD let it through. -1 happened to agree, being the value that means "no
     * size"; -2 and below did not. */
    assert(PASSES(decide(__NR_truncate, P("/tmp/initio/big/f"), (uint64_t)(int64_t)-4096, 0, 0, 0))
    );
    assert(PASSES(decide(__NR_ftruncate, (uint64_t)big, (uint64_t)(int64_t)-2, 0, 0, 0)));
    assert(PASSES(decide(__NR_fallocate, (uint64_t)big, 0, 0, (uint64_t)(int64_t)-4096, 0)));
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
    /* The file leads with the tab-free header lines the library writes there -- the
     * reload generation -- so the count lines are looked up rather than compared against
     * the start of the file. A reader correlates the counts with that generation, and it
     * must be there whichever mode produced them. */
    assert(strncmp(hits, "generation=", strlen("generation=")) == 0);
    assert(strstr(hits, "\n3\t/tmp/initio/data:open:EIO:1.0\n") != NULL);
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
    assert(strstr(hits, "\n0\t/tmp/initio/data:open:EIO:1.0\n") != NULL);
    (void)unlink(buffer);

    /* TORN is applied here now: the byte count sits in a register, so the filter answers
     * the call with TRACE and the stop shortens it. The verdict names the argument to
     * replace and the count to put there, which must be a real tear -- at least one byte
     * and less than the request. */
    torn = open_file("/tmp/initio/torn/f");
    closing = open_file("/tmp/initio/c/f");
    write_rules("/tmp/initio/torn:write:TORN:1.0\n");
    {
        const chaos_init_verdict_t shortened =
            decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0);

        assert(shortened.action == CHAOS_INIT_SHORTEN);
        assert(shortened.arg_index == 2U);
        assert(shortened.value >= 1 && shortened.value < 10);
    }
    /* The vectored forms keep their count in memory, so one argument cannot shorten them:
     * they stay on the notification path and are written whole, as in the library. */
    {
        struct iovec whole[2];

        whole[0].iov_base = buffer;
        whole[0].iov_len = 6U;
        whole[1].iov_base = buffer;
        whole[1].iov_len = 6U;
        assert(PASSES(decide(__NR_writev, (uint64_t)torn, P(whole), 2U, 0, 0)));
    }
    /* The traced set names exactly the register-count calls of the operations that carry a
     * traced effect, each once. Three rules on purpose: a second `write` rule must not
     * name the same calls twice, and the `open` rule must not contribute at all. */
    write_rules("/tmp/initio/torn:write:TORN:1.0\n"
                "/tmp/initio/other:write:TORN:0.5\n"
                "/tmp/initio/data:open:EIO:1.0\n");
    {
        long traced[8];
        const size_t count = chaos_init_io_traced_calls(traced, sizeof(traced) / sizeof(traced[0]));
        size_t index;
        int saw_write = 0;
        int saw_sendfile = 0;
        int saw_copy = 0;
        int saw_writev = 0;
        int saw_openat = 0;

        for (index = 0U; index < count; ++index)
        {
            saw_write = saw_write || traced[index] == __NR_write;
            saw_sendfile = saw_sendfile || traced[index] == __NR_sendfile;
            saw_copy = saw_copy || traced[index] == __NR_copy_file_range;
            saw_writev = saw_writev || traced[index] == __NR_writev;
            saw_openat = saw_openat || traced[index] == __NR_openat;
        }
        /* write, sendfile and copy_file_range are the `write` operation's register-count
         * calls; the vectored forms and the untraced operation are absent, and the two
         * rules of the same operation do not double the set. */
        assert(saw_write && saw_sendfile && saw_copy);
        assert(!saw_writev && !saw_openat);
        assert(count == 3U);
        /* Truncated to the capacity rather than overrunning it, and a NULL destination is
         * no request at all. */
        assert(chaos_init_io_traced_calls(traced, 2U) == 2U);
        assert(chaos_init_io_traced_calls(traced, 0U) == 0U);
        assert(chaos_init_io_traced_calls(NULL, 4U) == 0U);
    }

    /* CORRUPT is applied here now, but only at the exit stop: the entry stop cannot know
     * how many bytes there will be to corrupt, so it asks to be called again and draws
     * nothing. A read that returns nothing is left alone and counts no hit, and a vectored
     * read is left alone too -- its bytes are spread over segments. */
    write_rules("/tmp/initio/torn:read:CORRUPT:1.0\n");
    assert(decide(__NR_read, (uint64_t)torn, P(buffer), 10U, 0, 0).action == CHAOS_INIT_AFTER);
    assert(PASSES(decide(__NR_readv, (uint64_t)torn, P(buffer), 2U, 0, 0)));
    {
        chaos_init_call_t after;
        char buffer2[64];
        /* Larger than any read reported below, so the bytes past the result can be
         * checked: an effect that corrupts outside what the call delivered would be
         * writing memory the call never touched. */
        unsigned char read_area[128];

        memset(&after, 0, sizeof(after));
        after.tid = getpid();
        after.nr = __NR_read;
        after.args[0] = (uint64_t)torn;
        after.args[1] = P(read_area);
        after.args[2] = sizeof(read_area);
        /* Nothing returned: nothing to corrupt, and -- the point of the guard -- no draw,
         * so no hit. The hits file is what shows it: a count above zero here would mean a
         * read that delivered nothing was charged for an effect it never got. */
        (void)memset(read_area, 'A', sizeof(read_area));
        assert(chaos_init_io_decide_result(&after, 0) == 1);
        assert(chaos_init_io_decide_result(&after, -1) == 1);
        assert(read_area[0] == 'A');
        /* Eight bytes returned: exactly one bit inside those eight flips, and nothing
         * beyond them is touched -- the call wrote eight bytes, so neither may the effect.
         * Twelve rounds, because one would not show that the byte is drawn rather than
         * fixed: each round must change exactly one byte below eight, and over the twelve
         * at least two different bytes and two different bits must be hit. The draws are
         * seeded from getrandom(),
         * so twelve identical ones have a chance of about 2e-10 -- below the rate at which
         * the hardware running this would be the likelier explanation. */
        {
            size_t round;
            size_t first_offset = sizeof(read_area);
            unsigned char first_mask = 0U;
            int saw_another = 0;
            int saw_another_bit = 0;

            for (round = 0U; round < 12U; ++round)
            {
                size_t index;
                size_t offset = sizeof(read_area);
                unsigned char mask = 0U;
                int differences = 0;

                (void)memset(read_area, 'A', sizeof(read_area));
                assert(chaos_init_io_decide_result(&after, 8) == 1);
                for (index = 0U; index < sizeof(read_area); ++index)
                {
                    const unsigned char changed = (unsigned char)(read_area[index] ^ 'A');

                    if (changed != 0U)
                    {
                        ++differences;
                        offset = index;
                        mask = changed;
                        assert(index < 8U);
                        /* One bit, not a byte rewritten. */
                        assert((changed & (unsigned char)(changed - 1U)) == 0U);
                    }
                }
                assert(differences == 1);
                if (round == 0U)
                {
                    first_offset = offset;
                    first_mask = mask;
                }
                saw_another = saw_another || offset != first_offset;
                saw_another_bit = saw_another_bit || mask != first_mask;
            }
            /* Both the byte and the bit within it are drawn, so over twelve rounds each
             * must have taken more than one value. */
            assert(saw_another);
            assert(saw_another_bit);
        }
        /* Twelve hits, not fourteen: the two calls that returned nothing drew nothing. The
         * hits file is rewritten by each hit, so this reads the count they left. */
        (void)snprintf(buffer2, sizeof(buffer2), "/tmp/.chaos-io.hits.%ld", (long)getpid());
        file = fopen(buffer2, "r");
        assert(file != NULL);
        hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
        (void)fclose(file);
        assert(strstr(hits, "\n12\t/tmp/initio/torn:read:CORRUPT:1.0\n") != NULL);

        /* An effect that is not CORRUPT can only reach the exit stop if the rule file
         * changed between the two stops. It must do nothing there: the call has already
         * run, and drawing again would charge a hit for an effect nobody can apply. */
        write_rules("/tmp/initio/torn:read:EIO:1.0\n");
        (void)memset(read_area, 'A', sizeof(read_area));
        assert(chaos_init_io_decide_result(&after, 8) == 1);
        assert(chaos_init_io_decide_result(&after, 8) == 1);
        assert(read_area[0] == 'A' && read_area[7] == 'A');
        /* One real hit through the entry stop, and the two exit-stop calls above added
         * none: a count of three here would mean the guard let them draw. */
        assert(FAILS(decide(__NR_read, (uint64_t)torn, P(buffer), 10U, 0, 0), EIO));
        file = fopen(buffer2, "r");
        assert(file != NULL);
        hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
        (void)fclose(file);
        assert(strstr(hits, "\n1\t/tmp/initio/torn:read:EIO:1.0\n") != NULL);
        /* A call of another kind is not io's at the exit stop either. */
        after.nr = __NR_getpid;
        assert(chaos_init_io_decide_result(&after, 8) == 0);
    }

    /* FREE still rejects the whole rule file: it rewrites the structure the kernel
     * returned, which is neither a register nor the bytes a call wrote. No rule of a
     * rejected file applies, and the status names the offending line. */
    write_rules("/tmp/initio/data:open:EIO:1.0\n/tmp/initio/torn:statfs:FULL:1.0\n");
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
    /* With nothing traced the set is empty, so the filter stays the one it always was. */
    {
        long traced[8];

        assert(chaos_init_io_traced_calls(traced, sizeof(traced) / sizeof(traced[0])) == 0U);
    }
    /* DROP on pwrite is a reply with the byte count and no call, which a notification can
     * answer: 10 bytes reported written, nothing written. A positioned write does not use
     * the descriptor's offset, so there is nothing to correct. */
    write_rules("/tmp/initio/torn:pwrite:DROP:1.0\n");
    assert(RETURNS(decide(__NR_pwrite64, (uint64_t)torn, P(buffer), 10U, 0, 0), 10L));
    {
        struct iovec vector[2];

        vector[0].iov_base = buffer;
        vector[0].iov_len = 4U;
        vector[1].iov_base = buffer;
        vector[1].iov_len = 3U;
        assert(RETURNS(decide(__NR_pwritev, (uint64_t)torn, P(vector), 2U, 0, 0), 7L));
        /* A vector that cannot be read has no count to report, so nothing is dropped. */
        assert(PASSES(decide(__NR_pwritev, (uint64_t)torn, 8U, 2U, 0, 0)));
        /* Nor one whose total is no value the call could have returned: the supervisor
         * sums the tracee's vector without bounding it, so a reply built from that total
         * would be a negative return. The kernel rejects such a call with EINVAL. */
        vector[0].iov_len = (size_t)SSIZE_MAX;
        vector[1].iov_len = (size_t)SSIZE_MAX;
        assert(PASSES(decide(__NR_pwritev, (uint64_t)torn, P(vector), 2U, 0, 0)));
    }
    /* DROP on a plain write has to move the descriptor's offset on by the count it
     * reports, which is a call of its own: the write is replaced by that `lseek` and the
     * tracee is told the count once it has run. The vectored form takes it too -- the
     * correction needs no register of the call, only its total. */
    write_rules("/tmp/initio/torn:write:DROP:1.0\n");
    {
        chaos_init_verdict_t dropped = decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0);

        assert(dropped.action == CHAOS_INIT_INSTEAD && dropped.value == 10L);
        assert(dropped.instead_nr == __NR_lseek);
        assert(dropped.instead_args[0] == (uint64_t)torn && dropped.instead_args[1] == 10U);
        assert(dropped.instead_args[2] == (uint64_t)SEEK_CUR);

        vector[0].iov_base = buffer;
        vector[0].iov_len = 4U;
        vector[1].iov_base = buffer;
        vector[1].iov_len = 3U;
        dropped = decide(__NR_writev, (uint64_t)torn, P(vector), 2U, 0, 0);
        assert(dropped.action == CHAOS_INIT_INSTEAD && dropped.value == 7L);
        assert(dropped.instead_args[1] == 7U);
        /* Both forms are traced for it, and nothing else of the operation: `sendfile` and
         * `copy_file_range` move bytes between two descriptors, so dropping one would have
         * to correct two offsets. They are left alone and count no hit. */
        {
            long traced[8];
            const size_t count =
                chaos_init_io_traced_calls(traced, sizeof(traced) / sizeof(traced[0]));

            assert(count == 2U);
            assert(
                (traced[0] == __NR_write && traced[1] == __NR_writev) ||
                (traced[0] == __NR_writev && traced[1] == __NR_write)
            );
        }
        assert(PASSES(decide(__NR_sendfile, (uint64_t)torn, (uint64_t)big, 0, 10U, 0)));
        /* A zero-byte write has no offset to move, so it needs no second call. */
        assert(RETURNS(decide(__NR_write, (uint64_t)torn, P(buffer), 0U, 0, 0), 0L));
        /* A descriptor with no offset is left alone: the bytes would simply be gone, and
         * that is net's DROP on a datagram, not this one. A FIFO has a path, so the rule
         * does match it -- what stops the drop is the missing offset. */
        {
            const int fifo = open("/tmp/initio/torn/pipe", O_RDWR);

            assert(fifo > 2);
            assert(PASSES(decide(__NR_write, (uint64_t)fifo, P(buffer), 10U, 0, 0)));
            (void)close(fifo);
        }
        /* What the descriptor cannot be asked about is left alone too: unreadable fdinfo,
         * fdinfo without a flags line, and an unreadable type. */
        g_fail_fdinfo = 1;
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
        g_fail_fdinfo = 0;
        g_fdinfo_instead = "/tmp/initio/torn/f";
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
        g_fdinfo_instead = NULL;
        g_fail_fd_stat = 1;
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
        g_fail_fd_stat = 0;
        /* None of those counted a hit: the drop was decided before the draw. */
        {
            char path[64];

            (void)snprintf(path, sizeof(path), "/tmp/.chaos-io.hits.%ld", (long)getpid());
            file = fopen(path, "r");
            assert(file != NULL);
            hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
            (void)fclose(file);
            assert(strstr(hits, "\n3\t/tmp/initio/torn:write:DROP:1.0\n") != NULL);
        }
    }
    /* O_APPEND writes at the end whatever the offset says, so a dropped one corrects
     * nothing and is answered by the reply alone. */
    {
        const int appending = open("/tmp/initio/torn/a", O_CREAT | O_WRONLY | O_APPEND, 0644);

        assert(appending > 2);
        write_rules("/tmp/initio/torn:write:DROP:1.0\n");
        assert(RETURNS(decide(__NR_write, (uint64_t)appending, P(buffer), 10U, 0, 0), 10L));
        (void)close(appending);
    }

    /* THROTTLE: the same bucket arithmetic as the library's, applied through the
     * registers. The rate is 10 bytes per second, so a byte takes 100 ms to arrive and
     * the bucket holds 10 -- small enough that the test does not depend on how fast this
     * machine is. */
    write_rules("/tmp/initio/torn:write:THROTTLE:10\n");
    {
        chaos_init_verdict_t held;

        /* A full bucket covers the whole call: it passes, and the rule is not even asked,
         * so an allowance that changes nothing spends no hit. */
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 7U, 0, 0)));
        /* Three bytes left of the ten: the call is shortened to exactly those. */
        held = decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0);
        assert(held.action == CHAOS_INIT_SHORTEN);
        assert(held.arg_index == 2U && held.value == 3L);
        /* Nothing left: the call is parked rather than slept in, which is the one
         * difference from the library -- the tracee's other threads keep being served.
         * A tenth of a second's worth is one byte at this rate, 100 ms away -- less
         * whatever these calls themselves took, because the bucket keeps the part of a
         * millisecond it could not turn into a token. Pinning 100 pins that loss, and
         * passed only while the calls fell inside one millisecond. */
        held = decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY);
        assert(held.delay_ms > 50U && held.delay_ms <= 100U);
        assert(held.shortens && held.value == 1L);
        assert(held.arg_index == 2U);
        /* What that delay turns into when it is due -- a shortened call, not a whole one
         * -- is chaos_init_delay_answer()'s own test in test_chaos_init.c. */
        /* The byte is charged when the call is parked, so the next caller waits for the
         * one after it: a second wait on top of what is left of the first. Without the
         * charge both would be told 100 ms and the rate would come out double. */
        held = decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY);
        assert(held.delay_ms > 100U && held.delay_ms <= 200U);
        /* A call the rate lets through whole spends neither a hit nor a `@first` claim --
         * the allowance changed nothing, so there was no effect to charge for. The budget
         * is the sharpest way to say it: with `@first=1` the untouched call must leave the
         * claim for the call that is actually shortened. */
        /* A filter that does not trace this call cannot carry a shortened write, and a
         * filter cannot be changed once installed -- so a rule file replaced at run time
         * can ask for an effect this container will never deliver. It must then not fire
         * and not count a hit: a hit reported for a fault nobody injected is worse than a
         * rule that visibly does nothing. */
        g_traced_all = 0;
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 13U, 0, 0)));
        {
            char hits[256] = {0};
            char path[64];
            FILE *file;

            (void)snprintf(path, sizeof(path), "/tmp/.chaos-io.hits.%ld", (long)getpid());
            file = fopen(path, "r");
            if (file != NULL)
            {
                hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
                (void)fclose(file);
            }
            assert(strstr(hits, "THROTTLE:13") == NULL);
        }
        g_traced_all = 1;

        write_rules("/tmp/initio/torn:write:THROTTLE:13 @first=1\n");
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 13U, 0, 0)));
        held = decide(__NR_write, (uint64_t)torn, P(buffer), 13U, 0, 0);
        assert(held.action == CHAOS_INIT_DELAY && held.shortens);
        write_rules("/tmp/initio/torn:write:THROTTLE:10\n");

        /* A non-blocking descriptor is told EAGAIN instead of being parked, as in the
         * library: its event loop is written for that answer. Its own bucket, because a
         * slot is keyed by the descriptor. */
        {
            const int impatient = open("/tmp/initio/torn/n", O_CREAT | O_WRONLY | O_NONBLOCK, 0644);

            assert(impatient > 2);
            assert(PASSES(decide(__NR_write, (uint64_t)impatient, P(buffer), 10U, 0, 0)));
            assert(FAILS(decide(__NR_write, (uint64_t)impatient, P(buffer), 10U, 0, 0), EAGAIN));
            (void)close(impatient);
        }
        /* The vectored form keeps its count in memory, so no register can shorten it: it
         * stays notified and is written whole, as in the library. */
        vector[0].iov_base = buffer;
        vector[0].iov_len = 6U;
        vector[1].iov_base = buffer;
        vector[1].iov_len = 6U;
        assert(PASSES(decide(__NR_writev, (uint64_t)torn, P(vector), 2U, 0, 0)));
        /* A process the supervisor cannot identify has no bucket to charge, so the call
         * goes through rather than being held back by a rate nobody is keeping. */
        g_fail_process = 1;
        assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
        g_fail_process = 0;
    }

    /* statfs and fstatfs are notified, so ERRNO and LATENCY reach them here as in the
     * library; FREE and FULL rewrite the structure the kernel returned, which a reply
     * cannot reach, so they reject the whole file with the other data effects. */
    write_rules("/tmp/initio/torn:statfs:EIO:1.0\n");
    assert(FAILS(decide(__NR_fstatfs, (uint64_t)torn, P(buffer), 0, 0, 0), EIO));
    assert(FAILS(decide(__NR_statfs, P("/tmp/initio/torn/f"), P(buffer), 0, 0, 0), EIO));
    write_rules("/tmp/initio/torn:statfs:FULL:1.0\n");
    assert(PASSES(decide(__NR_fstatfs, (uint64_t)torn, P(buffer), 0, 0, 0)));
    file = fopen("/tmp/.chaos-io.status", "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(strstr(hits, "reason=unsupported in seccomp mode\n") != NULL);
    write_rules("/tmp/initio/torn:statfs:FREE:4096\n");
    assert(PASSES(decide(__NR_statfs, P("/tmp/initio/torn/f"), P(buffer), 0, 0, 0)));

    write_rules("/tmp/initio/c:close:EIO:1.0\n");
    assert(PASSES(decide(__NR_close, (uint64_t)closing, 0, 0, 0, 0)));
    /* One unsupported effect disables every rule of the file, the valid LATENCY included.
     * FULL is the unsupported one here; CORRUPT is applied now. */
    write_rules("/tmp/initio/c:close:LATENCY:5\n/tmp/initio/data:statfs:FULL:1.0\n");
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
    /* A reload without a call: what the inotify watch of chaos_init.c asks for when a
     * rule file is put in place, so that the status file reports the rules before anything
     * has called into them. Two rules, because every file loaded above has one or none: a
     * status that said anything else would mean the reload did nothing. */
    write_rules("/tmp/initio/data:open:EIO:1.0\n/tmp/initio/other:open:EIO:1.0\n");
    chaos_init_io_reload();
    {
        FILE *reloaded = fopen("/tmp/.chaos-io.status", "r");
        char text[256] = {0};

        assert(reloaded != NULL);
        text[fread(text, 1U, sizeof(text) - 1U, reloaded)] = '\0';
        (void)fclose(reloaded);
        assert(strncmp(text, "state=ok\nrules=2\n", strlen("state=ok\nrules=2\n")) == 0);
    }

    return 0;
}
