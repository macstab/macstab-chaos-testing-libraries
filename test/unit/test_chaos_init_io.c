/**
 * @file test_chaos_init_io.c
 * @brief Unit tests for chaos-init's io decisions.
 *
 * Subsystem under test: `src/init/chaos_init_io.c` (with the io rule core it
 * includes, `chaos_init_proc.c` and `chaos_init_tracee.c`).
 *
 * Coverage approach:
 * - Calls are built as a notification would carry them, with this test process
 *   as the caller: paths and iovec arrays are its own memory, descriptors its own
 *   open files, and /proc/<pid> its own entries. Nothing is faked.
 * - A forked child that only sleeps stands in for a second process.
 *
 * Properties under test:
 * - Every way an io call names its file: absolute, relative to the working
 *   directory or to a directory descriptor, by descriptor; fds 0-2, pipes,
 *   unreadable memory and /proc pass.
 * - ERRNO fails the call, LATENCY delays it, TORN and CORRUPT are not applied.
 * - `@size` sees the byte count, also of iovec arrays; sendfile and
 *   copy_file_range are writes to their output.
 * - Renames are decided like renameat(): the destination wins on a longer or equal
 *   prefix.
 * - `@first` and hits are per process.
 */

#include <stdint.h>
#include <sys/types.h>

/* Seams: a /proc link that cannot be read, and a process that ended after its
 * call matched. Both delegate to the real functions otherwise. */
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

static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-io.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-io.conf.new", "/tmp/.chaos-io.conf") == 0);
}

/** @brief Decides system call @p nr of this process with arguments a0..a4. */
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

/* Functions, not macros: each decision is made exactly once (it may use up @first). */
static int FAILS(chaos_init_verdict_t verdict, int error)
{
    return verdict.action == CHAOS_INIT_FAIL && verdict.error == error;
}

static int PASSES(chaos_init_verdict_t verdict)
{
    return verdict.action == CHAOS_INIT_PASS;
}

/** @brief Opens (creating) @p path for writing; the descriptor stays open. */
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

    /* Not an io system call. */
    memset(&other, 0, sizeof(other));
    other.tid = getpid();
    other.nr = __NR_getpid;
    assert(chaos_init_io_decide(&other, &verdict) == 0);

    /* Without a rule file every call runs. */
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));

    write_rules("/tmp/initio/data:open:EIO:1.0\n"
                "/tmp/initio/slow:open:LATENCY:25\n"
                "/tmp/initio/never:open:EIO:0.0\n"
                "/tmp/initio/once:open:EACCES:1.0 @first=1\n"
                "/tmp/initio/big:read:EIO:1.0 @size>100\n"
                "/tmp/initio/torn:write:TORN:1.0\n"
                "/tmp/initio/w:write:ENOSPC:1.0\n"
                "/tmp/initio/c:close:EIO:1.0\n"
                "/tmp/initio/s:fsync:EIO:1.0\n"
                "/tmp/initio/t:truncate:EROFS:1.0\n"
                "/tmp/initio/data:unlink:EACCES:1.0\n"
                "/tmp/initio/ren:rename_from:EMFILE:1.0\n"
                "/tmp/initio/ren/from:rename_from:EACCES:1.0\n"
                "/tmp/initio/ren/to:rename_to:ENFILE:1.0\n");

    /* Absolute, relative to the cwd, relative to a directory descriptor. */
    verdict = decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0);
    assert(FAILS(verdict, EIO));
    assert(chdir("/tmp/initio") == 0);
    assert(FAILS(decide(__NR_openat, (uint64_t)AT_FDCWD, P("data/y"), 0, 0, 0), EIO));
    dir = open("/tmp/initio", O_RDONLY | O_DIRECTORY);
    assert(dir > 2);
    assert(FAILS(decide(__NR_openat, (uint64_t)dir, P("data/z"), 0, 0, 0), EIO));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("elsewhere"), 0, 0, 0)));

    /* What cannot be named passes: a pipe or fd 0-2 as directory, unreadable memory,
     * /proc. */
    assert(pipe(pipe_fds) == 0);
    assert(PASSES(decide(__NR_openat, (uint64_t)pipe_fds[0], P("data/z"), 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, 1U, P("data/z"), 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, 0U, 0, 0, 0)));
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/proc/self/status"), 0, 0, 0)));
    g_fail_cwd = 1;
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("data/y"), 0, 0, 0)));
    g_fail_cwd = 0;
    assert(chdir("/") == 0);

    /* A process that ended after its call matched is not counted, and its call runs. */
    g_fail_process = 1;
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/x"), 0, 0, 0)));
    g_fail_process = 0;

    /* LATENCY delays; a rule whose probability is 0 never fires. */
    verdict = decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/slow/a"), 0, 0, 0);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 25U);
    assert(PASSES(decide(__NR_openat, (uint64_t)AT_FDCWD, P("/tmp/initio/never/a"), 0, 0, 0)));

    /* @first is per process: this one, then a second one. */
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

    /* By descriptor, with the byte count for @size. */
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

    /* TORN is not applied; ENOSPC on writes, also through sendfile and
     * copy_file_range to the file. */
    torn = open_file("/tmp/initio/torn/f");
    assert(PASSES(decide(__NR_write, (uint64_t)torn, P(buffer), 10U, 0, 0)));
    full = open_file("/tmp/initio/w/f");
    assert(FAILS(decide(__NR_write, (uint64_t)full, P(buffer), 10U, 0, 0), ENOSPC));
    assert(FAILS(decide(__NR_sendfile, (uint64_t)full, (uint64_t)big, 0, 10U, 0), ENOSPC));
    assert(FAILS(decide(__NR_copy_file_range, (uint64_t)big, 0, (uint64_t)full, 0, 10U), ENOSPC));
    assert(PASSES(decide(__NR_copy_file_range, (uint64_t)full, 0, (uint64_t)big, 0, 10U)));

    /* close, fsync, truncate by path and by descriptor, unlinkat. */
    closing = open_file("/tmp/initio/c/f");
    assert(FAILS(decide(__NR_close, (uint64_t)closing, 0, 0, 0, 0), EIO));
    syncing = open_file("/tmp/initio/s/f");
    assert(FAILS(decide(__NR_fsync, (uint64_t)syncing, 0, 0, 0, 0), EIO));
    assert(PASSES(decide(__NR_fdatasync, (uint64_t)syncing, 0, 0, 0, 0)));
    assert(FAILS(decide(__NR_truncate, P("/tmp/initio/t/f"), 0, 0, 0, 0), EROFS));
    (void)close(open_file("/tmp/initio/t/f"));
    assert(PASSES(decide(__NR_ftruncate, (uint64_t)full, 0, 0, 0, 0)));
    assert(
        FAILS(decide(__NR_unlinkat, (uint64_t)AT_FDCWD, P("/tmp/initio/data/f"), 0, 0, 0), EACCES)
    );

    /* Renames: either side, the destination winning on a longer or equal prefix. */
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

    /* The hits of this process were written as they happened. */
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

    /* The second process counted its own @first hit in its own file. */
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
    (void)unlink("/tmp/.chaos-io.conf");
    return 0;
}
