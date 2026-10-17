/**
 * @file test_chaos_init.c
 * @brief Proves the supervisor-side building blocks of chaos-init that need no seccomp
 *        notification: argument parsing, the BPF filter, status and exit reporting, the
 *        delay queue, tracee memory and /proc access, and the per-process tracee table.
 *
 * @details Units under test, compiled in by `#include`: `src/init/chaos_init_core.c`,
 * `chaos_init_delay.c`, `chaos_init_proc.c`, `chaos_init_tracee.c`.
 *
 * Isolation:
 * - Memory and /proc access run for real against this test process, which plays the
 *   tracee (process_vm_readv(2)/process_vm_writev(2) on its own pid).
 * - Seam `CHAOS_INIT_PROC_READ`: `g_fake_status` / `g_fake_stat` substitute canned
 *   `/proc/<pid>/status` and `/proc/<pid>/stat` text to drive the parsers through
 *   malformed and edge-case input; NULL delegates to the real reader.
 * - Seam `CHAOS_INIT_PROCESS_OF`: the tracee table resolves tids through the
 *   `g_fake_tgid` / `g_fake_start` tables (tids 1..199), so pid reuse, threads of one
 *   process and ended processes are set up without forking.
 * - The filter is verified by behaviour, not by instruction listing: `run_filter()`
 *   interprets the subset of classic BPF the builder emits (LD|W|ABS, JEQ, JGE, RET)
 *   over a `seccomp_data` built per case. A wrong jump offset therefore fails exactly
 *   like a missing system call. The interpreter asserts on any other opcode, on an
 *   out-of-bounds load and on running off the end of the program.
 *
 * Properties proven:
 * - arguments: exactly `--libs <name>[,<name>...] -- <command...>`, known names only;
 * - filter: each library's system calls are notified and no others; calls shared by
 *   libraries appear once; foreign architectures and (x86_64) the x32 ABI pass; of all
 *   sendmsg calls only the handover (fd and flags both exact) passes; too small an
 *   output buffer is refused rather than overrun;
 * - exit code (shell convention, 128 + signal), kernel >= 5.5 check, unsupported
 *   reasons by errno, status file text, GODEBUG multipathtcp handling, PATH search;
 * - delay queue: next() reports the earliest due time; pop() releases only due calls,
 *   one per call; a full queue refuses; a parked call re-notified after a signal keeps
 *   its due time and answer under its new id;
 * - tracee memory: strings stop at a NUL before an unmapped page, partial reads and
 *   writes fail with EFAULT; /proc link and stat/status parsing, including the
 *   start-time + image fingerprint that tells an execve'd image from the old one;
 * - tracee table: one entry per process, pid reuse starts over, a full table reclaims
 *   ended processes before evicting the least recently used live one; counts follow
 *   rule texts across reloads; hits files are written eagerly, then on flush.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Seam for the /proc parsers: NULL reads the real file, non-NULL returns the canned text
 * for `status` or (any other name) `stat`. */
static const char *g_fake_status = NULL;
static const char *g_fake_stat = NULL;
static long test_proc_read(pid_t pid, const char *name, char *out, size_t size);
#define CHAOS_INIT_PROC_READ test_proc_read

/* Seam for the tracee table: tid -> (tgid, start fingerprint); tgid 0 means no such
 * process. Lets the test model threads, pid reuse and process exit without forking. */
#define TEST_PIDS 200
static pid_t g_fake_tgid[TEST_PIDS];
static unsigned long long g_fake_start[TEST_PIDS];
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

#include "../../src/init/chaos_init_core.c"
#include "../../src/init/chaos_init_delay.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static long test_proc_read(pid_t pid, const char *name, char *out, size_t size)
{
    const char *fake = strcmp(name, "status") == 0 ? g_fake_status : g_fake_stat;

    if (fake == NULL)
    {
        return chaos_init_proc_read(pid, name, out, size);
    }
    (void)snprintf(out, size, "%s", fake);
    return (long)strlen(out);
}

static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    if (tid <= 0 || tid >= TEST_PIDS || g_fake_tgid[tid] == 0)
    {
        return -1;
    }
    *tgid = g_fake_tgid[tid];
    *start = g_fake_start[tid];
    return 0;
}

#include <assert.h>
#include <linux/audit.h>
#include <stdint.h>

/**
 * @brief Interprets @p filter (as built by chaos_init_build_filter()) over @p data and
 *        returns the SECCOMP_RET_* value it reaches.
 *
 * @details Supports only the opcodes the builder emits; anything else, a load outside
 * `struct seccomp_data`, or falling off the end aborts the test, so a builder change
 * that the interpreter does not model cannot pass silently.
 */
static uint32_t
run_filter(const struct sock_filter *filter, size_t length, const struct seccomp_data *data)
{
    const unsigned char *bytes = (const unsigned char *)data;
    uint32_t accumulator = 0U;
    size_t pc = 0U;

    while (pc < length)
    {
        const struct sock_filter *op = &filter[pc];

        switch (op->code)
        {
        case BPF_LD | BPF_W | BPF_ABS:
            assert(op->k + 4U <= sizeof(*data));
            memcpy(&accumulator, bytes + op->k, sizeof(accumulator));
            ++pc;
            break;
        case BPF_JMP | BPF_JEQ | BPF_K:
            pc += 1U + (accumulator == op->k ? op->jt : op->jf);
            break;
        case BPF_JMP | BPF_JGE | BPF_K:
            pc += 1U + (accumulator >= op->k ? op->jt : op->jf);
            break;
        case BPF_RET | BPF_K:
            return op->k;
        default:
            assert(!"unexpected BPF instruction");
        }
    }
    assert(!"the filter ran off its end");
    return 0U;
}

/* Handover descriptor compiled into every filter decide() builds; the one sendmsg the
 * filter allows unnotified is on this fd with CHAOS_INIT_HANDOVER_FLAGS. */
static int g_test_handover = 1000;

/**
 * @brief Builds the filter for @p libs and returns its verdict for system call @p nr on
 *        architecture @p arch, with @p fd as args[0] and @p flags as args[2] (sendmsg).
 */
static uint32_t decide(unsigned libs, long nr, uint64_t fd, uint64_t flags, uint32_t arch)
{
    struct sock_filter filter[CHAOS_INIT_MAX_FILTER];
    struct seccomp_data data;
    const size_t length =
        chaos_init_build_filter(libs, g_test_handover, filter, CHAOS_INIT_MAX_FILTER);

    assert(length > 0U);
    memset(&data, 0, sizeof(data));
    data.nr = (int)nr;
    data.arch = arch;
    data.args[0] = fd;
    data.args[2] = flags;
    return run_filter(filter, length, &data);
}

#define NOTIFY SECCOMP_RET_USER_NOTIF
#define ALLOW SECCOMP_RET_ALLOW
#define ARCH CHAOS_INIT_AUDIT_ARCH

/** @brief Only `--libs <known,...> -- <command>` parses; command index is argv[4]. */
static void test_parse_args(void)
{
    char *good[] = {"chaos-init", "--libs", "io,net,process", "--", "/app", "-x", NULL};
    char *all[] = {"chaos-init", "--libs", "io,net,dns,time,memory,process", "--", "app", NULL};
    char *unknown[] = {"chaos-init", "--libs", "io,disk", "--", "app", NULL};
    char *empty[] = {"chaos-init", "--libs", "io,", "--", "app", NULL};
    char *no_libs[] = {"chaos-init", "--lib", "io", "--", "app", NULL};
    char *no_dashes[] = {"chaos-init", "--libs", "io", "app", "x", NULL};
    char *no_command[] = {"chaos-init", "--libs", "io", "--", NULL};
    chaos_init_options_t options;

    assert(chaos_init_parse_args(6, good, &options) == 0);
    assert(options.libs == (CHAOS_INIT_LIB_IO | CHAOS_INIT_LIB_NET | CHAOS_INIT_LIB_PROCESS));
    assert(options.command == 4);
    assert(chaos_init_parse_args(5, all, &options) == 0 && options.libs == 0x3fU);
    assert(chaos_init_parse_args(5, unknown, &options) == -1);
    assert(chaos_init_parse_args(5, empty, &options) == -1);
    assert(chaos_init_parse_args(5, no_libs, &options) == -1);
    assert(chaos_init_parse_args(5, no_dashes, &options) == -1);
    assert(chaos_init_parse_args(4, no_command, &options) == -1);
}

static void test_filter_decisions(void)
{
    struct sock_filter small[8];

    /* Each library's calls, and only those, are notified to the supervisor; sendmsg
     * is not an io call, so io alone lets it through. */
    assert(decide(CHAOS_INIT_LIB_IO, __NR_openat, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_IO, __NR_fsync, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_IO, __NR_connect, 0U, 0U, ARCH) == ALLOW);
    assert(decide(CHAOS_INIT_LIB_IO, __NR_sendmsg, 3U, 0U, ARCH) == ALLOW);
    assert(decide(CHAOS_INIT_LIB_NET, __NR_connect, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_NET, __NR_epoll_pwait, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_NET, __NR_openat, 0U, 0U, ARCH) == ALLOW);
    assert(decide(CHAOS_INIT_LIB_MEMORY, __NR_mmap, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_MEMORY, __NR_read, 0U, 0U, ARCH) == ALLOW);
    assert(decide(CHAOS_INIT_LIB_PROCESS, __NR_clone, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_PROCESS, __NR_execve, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_PROCESS, __NR_getpid, 0U, 0U, ARCH) == ALLOW);

    /* read is in both io and net yet notified once (deduplicated, so jump offsets
     * stay right); with all six libraries every listed call is still reached. */
    assert(decide(CHAOS_INIT_LIB_IO | CHAOS_INIT_LIB_NET, __NR_read, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_munmap, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_waitid, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_getpid, 0U, 0U, ARCH) == ALLOW);

    /* dns and time contribute no system calls: SECCOMP mode does not intercept them. */
    assert(decide(CHAOS_INIT_LIB_DNS | CHAOS_INIT_LIB_TIME, __NR_connect, 0U, 0U, ARCH) == ALLOW);

    /* Only the handover sendmsg passes unnotified: right fd and exact flags. Any other
     * flags or fd is notified, so the application cannot use the bypass by accident. */
    assert(
        decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 1000U, CHAOS_INIT_HANDOVER_FLAGS, ARCH) == ALLOW
    );
    assert(decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 1000U, MSG_NOSIGNAL, ARCH) == NOTIFY);
    assert(decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 7U, CHAOS_INIT_HANDOVER_FLAGS, ARCH) == NOTIFY);
    /* The handover fd is a build parameter, not a constant: a low fd (4) works, and the
     * previous fd 1000 is then notified. */
    g_test_handover = 4;
    assert(decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 4U, CHAOS_INIT_HANDOVER_FLAGS, ARCH) == ALLOW);
    assert(
        decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 1000U, CHAOS_INIT_HANDOVER_FLAGS, ARCH) == NOTIFY
    );
    g_test_handover = 1000;

    /* chaos-init decodes only its native ABI: a foreign AUDIT_ARCH and, on x86_64, an
     * x32 system call number (bit 30 set) pass unnotified. */
    assert(decide(CHAOS_INIT_LIB_NET, __NR_connect, 0U, 0U, 0x12345678U) == ALLOW);
#ifdef __x86_64__
    assert(decide(CHAOS_INIT_LIB_NET, 0x40000000L | __NR_connect, 0U, 0U, ARCH) == ALLOW);
#endif

    /* An output buffer too small for the program returns 0 rather than overrunning. */
    assert(chaos_init_build_filter(0x3fU, 4, small, sizeof(small) / sizeof(small[0])) == 0U);
}

/** @brief Wait status maps to the shell convention: exit status, or 128 + signal. */
static void test_exit_code(void)
{
    assert(chaos_init_exit_code(0) == 0);
    assert(chaos_init_exit_code(3 << 8) == 3);
    assert(chaos_init_exit_code(9) == 137);
    assert(chaos_init_exit_code(15) == 143);
}

/**
 * @brief Caller-gone detection, the kernel >= 5.5 gate (seccomp user notification with
 *        SECCOMP_USER_NOTIF_FLAG_CONTINUE), and the reason text for each install errno.
 */
static void test_kernel_and_reasons(void)
{
    /* Only ENOENT from SECCOMP_IOCTL_NOTIF_ID_VALID means the caller is gone; any other
     * error must still get the call answered, or the tracee would hang. */
    assert(chaos_init_caller_gone(ENOENT));
    assert(!chaos_init_caller_gone(EINVAL));
    assert(!chaos_init_caller_gone(ENOTTY));

    assert(!chaos_init_kernel_supported(NULL));
    assert(!chaos_init_kernel_supported("garbage"));
    assert(!chaos_init_kernel_supported("5"));
    assert(!chaos_init_kernel_supported("4.19.0"));
    assert(!chaos_init_kernel_supported("5.4.0-1-amd64"));
    assert(chaos_init_kernel_supported("5.5.0"));
    assert(chaos_init_kernel_supported("6.10.14-linuxkit"));

    assert(strstr(chaos_init_unsupported_reason(EINVAL), "emulated") != NULL);
    assert(strstr(chaos_init_unsupported_reason(ENOSYS), "kernel") != NULL);
    assert(strstr(chaos_init_unsupported_reason(EACCES), "refused") != NULL);
    assert(strstr(chaos_init_unsupported_reason(EPERM), "refused") != NULL);
    assert(strstr(chaos_init_unsupported_reason(ENOTSUP), "5.5") != NULL);
    assert(strcmp(chaos_init_unsupported_reason(EIO), "seccomp could not be installed") == 0);
}

/** @brief Status file text for active and unsupported states, and GODEBUG merging. */
static void test_status_text(void)
{
    char text[256];
    char tiny[8];

    assert(
        chaos_init_format_status(
            text, sizeof(text), CHAOS_INIT_LIB_PROCESS | CHAOS_INIT_LIB_IO, NULL, 1L, 0
        ) > 0U
    );
    assert(strcmp(text, "state=active\nlibs=io,process\npid=1\n") == 0);
    assert(
        chaos_init_format_status(
            text, sizeof(text), CHAOS_INIT_LIB_NET, "kernel older than 5.5", 7L, 1
        ) > 0U
    );
    assert(strcmp(text, "state=unsupported\nreason=kernel older than 5.5\nlibs=net\npid=7\n") == 0);
    assert(chaos_init_format_status(tiny, sizeof(tiny), CHAOS_INIT_LIB_NET, NULL, 1L, 0) == 0U);
    /* A too-small buffer returns 0 (above). When MPTCP was turned off for the
     * application, the active status says so with `mptcp=off`. */
    assert(chaos_init_format_status(text, sizeof(text), CHAOS_INIT_LIB_NET, NULL, 1L, 1) > 0U);
    assert(strcmp(text, "state=active\nlibs=net\npid=1\nmptcp=off\n") == 0);

    /* GODEBUG gets `multipathtcp=0` appended to existing settings; a user's own
     * `multipathtcp=` setting (first, or after a comma) is left alone (returns 0), a
     * key that merely ends in `multipathtcp` is not one, and an overflow returns 0. */
    {
        char value[32];

        assert(chaos_init_godebug_mptcp_off(NULL, value, sizeof(value)) == 1);
        assert(strcmp(value, "multipathtcp=0") == 0);
        assert(chaos_init_godebug_mptcp_off("", value, sizeof(value)) == 1);
        assert(strcmp(value, "multipathtcp=0") == 0);
        assert(chaos_init_godebug_mptcp_off("http2debug=1", value, sizeof(value)) == 1);
        assert(strcmp(value, "http2debug=1,multipathtcp=0") == 0);
        assert(chaos_init_godebug_mptcp_off("multipathtcp=1", value, sizeof(value)) == 0);
        assert(chaos_init_godebug_mptcp_off("a=1,multipathtcp=2", value, sizeof(value)) == 0);
        assert(chaos_init_godebug_mptcp_off("xmultipathtcp=1", value, sizeof(value)) == 1);
        assert(strcmp(value, "xmultipathtcp=1,multipathtcp=0") == 0);
        assert(chaos_init_godebug_mptcp_off("a-setting-far-too-long-for-it", value, 8U) == 0);
    }
}

/** @brief PATH search for the command, with execvp(3) semantics where they matter. */
static void test_find_command(void)
{
    char path[256];
    char tiny[4];

    assert(chaos_init_find_command("sh", "/nonexistent:/bin:/usr/bin", path, sizeof(path)));
    assert(strcmp(path, "/bin/sh") == 0);
    /* An empty PATH entry is the current directory, and the result is the bare name. */
    {
        char here[256];
        FILE *file;

        assert(getcwd(here, sizeof(here)) != NULL && chdir("/tmp") == 0);
        file = fopen("/tmp/chaos-init-find-me", "w");
        assert(file != NULL && fclose(file) == 0 && chmod("/tmp/chaos-init-find-me", 0755) == 0);
        assert(chaos_init_find_command("chaos-init-find-me", "/nonexistent:", path, sizeof(path)));
        assert(strcmp(path, "chaos-init-find-me") == 0);
        assert(unlink("/tmp/chaos-init-find-me") == 0 && chdir(here) == 0);
    }
    assert(!chaos_init_find_command("no-such-command", "/bin:/usr/bin", path, sizeof(path)));
    assert(!chaos_init_find_command("tmp", "/", path, sizeof(path))); /* a directory */
    assert(chaos_init_find_command("./x/y", "/bin", path, sizeof(path)));
    assert(strcmp(path, "./x/y") == 0);
    assert(!chaos_init_find_command("/bin/sh", NULL, tiny, sizeof(tiny)));
    assert(!chaos_init_find_command("", NULL, path, sizeof(path)));
    assert(!chaos_init_find_command(NULL, NULL, path, sizeof(path)));
    assert(chaos_init_find_command("sh", NULL, path, sizeof(path)));
    /* A name with '/' is used as is; an empty or NULL name, a too-small output, a NULL
     * PATH (default search path) are covered above. No output buffer is refused. */
    assert(!chaos_init_find_command("sh", NULL, NULL, sizeof(path)));
    assert(!chaos_init_find_command("sh", NULL, path, 0U));
    /* A PATH entry whose joined path does not fit is skipped, never truncated into a
     * different path; the next entry that fits is found. */
    {
        char small[12];

        assert(chaos_init_find_command(
            "sh", "/a-directory-name-longer-than-the-buffer:/bin", small, sizeof(small)
        ));
        assert(strcmp(small, "/bin/sh") == 0);
    }
    /* A regular file without execute permission is skipped, as execvp(3) skips it;
     * when nothing else is found the result is -1 (refused, EACCES), not 0 (missing). */
    {
        FILE *file = fopen("/tmp/chaos-init-not-executable", "w");

        assert(file != NULL && fclose(file) == 0);
        assert(chmod("/tmp/chaos-init-not-executable", 0644) == 0);
        assert(
            chaos_init_find_command("chaos-init-not-executable", "/tmp", path, sizeof(path)) == -1
        );
        assert(unlink("/tmp/chaos-init-not-executable") == 0);
    }
}

/** @brief The queue of calls held back by LATENCY until their due time. */
static void test_delays(void)
{
    chaos_init_call_t call;
    chaos_init_call_t other;
    uint64_t due = 0U;
    uint64_t id = 0U;
    chaos_init_verdict_t answer;
    chaos_init_verdict_t eio;
    chaos_init_verdict_t run;
    size_t index;

    memset(&run, 0, sizeof(run));
    run.action = CHAOS_INIT_PASS;
    eio = run;
    eio.action = CHAOS_INIT_FAIL;
    eio.error = EIO;
    memset(&call, 0, sizeof(call));
    call.tid = 41;
    call.nr = 63;
    call.args[0] = 5U;
    call.args[2] = 4096U;

    /* next() reports the earliest due time; pop() releases due calls only, one per
     * call and in no guaranteed order (8 and 9 are both due by 250); a full queue of
     * CHAOS_INIT_MAX_DELAYED refuses the next add. */
    assert(chaos_init_delay_next(&due) == 0);
    assert(chaos_init_delay_pop(1000U, &id, &answer) == 0);
    assert(chaos_init_delay_add(7U, &call, 300U, &run) == 0);
    assert(chaos_init_delay_add(8U, &call, 100U, &eio) == 0);
    assert(chaos_init_delay_add(9U, &call, 200U, &run) == 0);
    assert(chaos_init_delay_next(&due) == 1 && due == 100U);
    assert(chaos_init_delay_pop(50U, &id, &answer) == 0);
    assert(
        chaos_init_delay_pop(250U, &id, &answer) == 1 &&
        (id == 8U ? answer.error == EIO : id == 9U && answer.action == CHAOS_INIT_PASS)
    );
    assert(
        chaos_init_delay_pop(250U, &id, &answer) == 1 &&
        (id == 8U ? answer.error == EIO : id == 9U && answer.action == CHAOS_INIT_PASS)
    );
    assert(chaos_init_delay_pop(250U, &id, &answer) == 0);
    assert(chaos_init_delay_pop(300U, &id, &answer) == 1 && id == 7U);
    for (index = 0U; index < CHAOS_INIT_MAX_DELAYED; ++index)
    {
        assert(chaos_init_delay_add(index, &call, 1U, &run) == 0);
    }
    assert(chaos_init_delay_add(1U, &call, 1U, &run) == -1);
    while (chaos_init_delay_pop(1U, &id, &answer))
    {
    }

    /* A parked call interrupted by a signal is re-notified under a new id; resume()
     * matches it by tid, number and all six arguments and rebinds the id, keeping the
     * due time and answer. A different tid, number or argument is a new call. */
    assert(chaos_init_delay_resume(&call, 20U) == 0);
    assert(chaos_init_delay_add(10U, &call, 500U, &eio) == 0);
    other = call;
    other.tid = 42;
    assert(chaos_init_delay_resume(&other, 21U) == 0);
    other = call;
    other.nr = 64;
    assert(chaos_init_delay_resume(&other, 21U) == 0);
    other = call;
    other.args[5] = 1U;
    assert(chaos_init_delay_resume(&other, 21U) == 0);
    assert(chaos_init_delay_resume(&call, 22U) == 1);
    assert(chaos_init_delay_next(&due) == 1 && due == 500U);
    assert(chaos_init_delay_pop(499U, &id, &answer) == 0);
    assert(chaos_init_delay_pop(500U, &id, &answer) == 1 && id == 22U && answer.error == EIO);
    assert(chaos_init_delay_next(&due) == 0);

    /* The answer sent when a delay expires, delay cleared: FAIL if an errno is set,
     * else RETURN if the verdict carries a value, else PASS (the call runs). */
    {
        chaos_init_verdict_t verdict;

        memset(&verdict, 0, sizeof(verdict));
        verdict.action = CHAOS_INIT_DELAY;
        verdict.delay_ms = 5U;
        assert(chaos_init_delay_answer(&verdict).action == CHAOS_INIT_PASS);
        verdict.returns = 1;
        assert(chaos_init_delay_answer(&verdict).action == CHAOS_INIT_RETURN);
        assert(chaos_init_delay_answer(&verdict).delay_ms == 0U);
        verdict.error = EIO;
        assert(chaos_init_delay_answer(&verdict).action == CHAOS_INIT_FAIL);
    }
}

/** @brief Tracee memory access and /proc parsing, with this process as the tracee. */
static void test_memory_and_proc(void)
{
    const long page = sysconf(_SC_PAGESIZE);
    char *pages =
        mmap(NULL, (size_t)page * 2U, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const char *text = "chaos-init reads this";
    char out[64];
    char cwd[512];
    char link[512];
    pid_t tgid = 0;
    uint64_t start = 0U;

    /* Reads of this process: a fixed-size read, a string, a string longer than the
     * buffer (ENAMETOOLONG), and a NULL address. */
    assert(
        chaos_init_read_memory(getpid(), (uintptr_t)text, out, 6U) == 0 &&
        memcmp(out, "chaos-", 6U) == 0
    );
    assert(
        chaos_init_read_string(getpid(), (uintptr_t)text, out, sizeof(out)) == (long)strlen(text)
    );
    assert(strcmp(out, text) == 0);
    assert(
        chaos_init_read_string(getpid(), (uintptr_t)text, out, 5U) == -1 && errno == ENAMETOOLONG
    );
    assert(chaos_init_read_string(getpid(), 0U, out, sizeof(out)) == -1);

    /* Page-boundary handling: string reads never cross into the next page unless the
     * NUL was not found, so "end" just before a PROT_NONE page is read, while "endX"
     * runs into it and fails. A fixed read straddling the page fails with EFAULT, even
     * though process_vm_readv(2) returns a short count without setting errno. */
    assert(pages != MAP_FAILED && mprotect(pages + page, (size_t)page, PROT_NONE) == 0);
    memcpy(pages + page - 4, "end", 4U);
    assert(chaos_init_read_string(getpid(), (uintptr_t)(pages + page - 4), out, sizeof(out)) == 3);
    memcpy(pages + page - 4, "endX", 4U);
    assert(chaos_init_read_string(getpid(), (uintptr_t)(pages + page - 4), out, sizeof(out)) == -1);
    errno = 0;
    assert(
        chaos_init_read_memory(getpid(), (uintptr_t)(pages + page - 4), out, 8U) == -1 &&
        errno == EFAULT
    );
    /* Writes into this process; a write cut short by the PROT_NONE page, or to an
     * unmapped address, fails with EFAULT. */
    assert(chaos_init_write_memory(getpid(), (uintptr_t)(pages + page - 8), "12345678", 8U) == 0);
    assert(memcmp(pages + page - 8, "12345678", 8U) == 0);
    errno = 0;
    assert(
        chaos_init_write_memory(getpid(), (uintptr_t)(pages + page - 4), "12345678", 8U) == -1 &&
        errno == EFAULT
    );
    errno = 0;
    assert(chaos_init_write_memory(getpid(), 8U, "1", 1U) == -1 && errno == EFAULT);
    (void)munmap(pages, (size_t)page * 2U);

    /* /proc links: `cwd` resolves; a missing entry, a zero-size buffer and a name that
     * overflows the 64-byte path buffer fail; reading a directory fails. */
    assert(getcwd(cwd, sizeof(cwd)) != NULL);
    assert(
        chaos_init_proc_link(getpid(), "cwd", link, sizeof(link)) == (long)strlen(cwd) &&
        strcmp(link, cwd) == 0
    );
    assert(chaos_init_proc_link(getpid(), "no-such-entry", link, sizeof(link)) == -1);
    assert(chaos_init_proc_link(getpid(), "cwd", link, 0U) == -1);
    assert(
        chaos_init_proc_link(
            getpid(),
            "a-name-far-too-long-for-the-proc-path-buffer-of-sixty-four-bytes",
            link,
            sizeof(link)
        ) == -1
    );
    assert(chaos_init_proc_read(getpid(), "fd", link, sizeof(link)) == -1); /* a directory */

    /* Thread -> (tgid, start time from stat field 22). A gone pid, a status without
     * Tgid, a truncated stat, a non-numeric field 22 fail. The comm field may contain
     * ')' ("a) b"), so parsing starts at the last ')'. */
    assert(chaos_init_process_of(getpid(), &tgid, &start) == 0 && tgid == getpid() && start > 0U);
    assert(chaos_init_process_of(999999999, &tgid, &start) == -1);
    g_fake_status = "Name:\tx\n";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_status = "Name:\tx\nTgid:\t12\n";
    g_fake_stat = "12 (x)";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_stat = "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 x";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_stat = "12 (a) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 99";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == 0 && tgid == 12 && start == 4242U);
    /* execve keeps pid and start time, so stat fields 26 (start of code) and 28 (start
     * of stack) are mixed into the fingerprint: changing either changes it, changing
     * another field (29) does not, and zeros (hidden by the kernel) leave the bare
     * start time. */
    {
        uint64_t image;

        g_fake_stat =
            "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 1 2 3 4096 5 8192 7";
        assert(chaos_init_process_of(getpid(), &tgid, &image) == 0 && image != 4242U);
        g_fake_stat =
            "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 1 2 3 4097 5 8192 7";
        assert(
            chaos_init_process_of(getpid(), &tgid, &start) == 0 && start != image && start != 4242U
        );
        g_fake_stat =
            "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 1 2 3 4096 5 8193 7";
        assert(
            chaos_init_process_of(getpid(), &tgid, &start) == 0 && start != image && start != 4242U
        );
        g_fake_stat =
            "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 1 2 3 4096 5 8192 9";
        assert(chaos_init_process_of(getpid(), &tgid, &start) == 0 && start == image);
        g_fake_stat = "12 (x) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 1 2 3 0 5 0 7";
        assert(chaos_init_process_of(getpid(), &tgid, &start) == 0 && start == 4242U);
    }
    /* PPid parsing: -1 for a gone process, a status without PPid, or a non-numeric
     * PPid. Also a stat without any ')' fails process lookup. */
    assert(chaos_init_parent_of(999999999) == -1);
    g_fake_status = "Name:\tx\nTgid:\t12\nPPid:\t7\n";
    assert(chaos_init_parent_of(12) == 7);
    g_fake_status = "Name:\tx\nTgid:\t12\n";
    assert(chaos_init_parent_of(12) == -1);
    g_fake_status = "Name:\tx\nTgid:\t12\nPPid:\tx\n";
    assert(chaos_init_parent_of(12) == -1);
    g_fake_status = "Name:\tx\nTgid:\t12\n";
    g_fake_stat = "12 no-paren";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    /* A non-numeric Tgid, and a Tgid whose stat vanished between the two reads. */
    g_fake_status = "Name:\tx\nTgid:\tx\n";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_status = "Name:\tx\nTgid:\t999999999\n";
    g_fake_stat = NULL;
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_status = NULL;
    /* Against the real /proc: this process's parent, and a gone pid. */
    assert(chaos_init_parent_of(getpid()) == getppid());
    assert(chaos_init_parent_of(999999999) == -1);
}

/* A stand-in library for the tracee table, with room for 4 rules per process. The test
 * edits `g_test_texts` and bumps `g_test_generation` to simulate a reload. */
CHAOS_INIT_RULES_STORAGE(g_test_rules, 4U);
static chaos_init_text_t g_test_texts[5];
static size_t g_test_text_count = 0U;
static uint64_t g_test_generation = 1U;

static size_t test_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    *texts = (const chaos_init_text_t *)g_test_texts;
    *generation = g_test_generation;
    return g_test_text_count;
}

static chaos_init_rules_t g_test_lib = {
    "/tmp/.chaos-inittest.hits",
    4U,
    test_snapshot,
    g_test_rules_slots,
    g_test_rules_hashes,
    g_test_rules_generation,
    g_test_rules_count,
    g_test_rules_total,
    g_test_rules_pending,
    g_test_rules_buffer,
    g_test_rules_file,
};

/**
 * @brief Reads and deletes the hits file `/tmp/.chaos-inittest.hits.<tgid>`; returns 0
 *        when it does not exist. Deleting makes the next call prove a fresh write.
 */
static int read_hits(pid_t tgid, char *out, size_t size)
{
    char path[64];
    FILE *file;
    size_t length;

    (void)snprintf(path, sizeof(path), "/tmp/.chaos-inittest.hits.%ld", (long)tgid);
    file = fopen(path, "r");
    if (file == NULL)
    {
        return 0;
    }
    length = fread(out, 1U, size - 1U, file);
    out[length] = '\0';
    (void)fclose(file);
    (void)unlink(path);
    return 1;
}

/** @brief Per-process entries, hit slots and hits files of the tracee table. */
static void test_tracee_table(void)
{
    chaos_init_rules_t too_many = g_test_lib;
    chaos_hit_slot_t foreign;
    chaos_hit_slot_t *slot;
    char hits[512];
    int first;
    int index;

    /* Registration refuses a library wider than CHAOS_INIT_MAX_RULES and more than
     * CHAOS_INIT_MAX_LIBS libraries. Registering g_test_lib in all six slots is harmless:
     * hit reports find the first. */
    too_many.max_rules = CHAOS_INIT_MAX_RULES + 1U;
    assert(chaos_init_tracee_register(&too_many) == -1);
    assert(chaos_init_tracee_register(&g_test_lib) == 0);
    for (index = 1; index < (int)CHAOS_INIT_MAX_LIBS; ++index)
    {
        assert(chaos_init_tracee_register(&g_test_lib) == 0);
    }
    assert(chaos_init_tracee_register(&g_test_lib) == -1);

    strcpy(g_test_texts[0], "/a:open:EIO:1.0");
    strcpy(g_test_texts[1], "/b:open:EIO:1.0");
    g_test_text_count = 2U;

    /* One entry per process: two threads of process 10 share it; an unresolvable tid
     * gets none. */
    assert(chaos_init_tracee_of(0) == -1);
    g_fake_tgid[10] = 10;
    g_fake_start[10] = 5U;
    g_fake_tgid[11] = 10; /* a second thread of process 10 */
    g_fake_start[11] = 5U;
    first = chaos_init_tracee_of(10);
    assert(first >= 0 && chaos_init_tracee_of(11) == first);
    /* find() looks up by tgid without allocating; tgid 0 never matches a free entry. */
    assert(chaos_init_tracee_find(10) == first && chaos_init_tracee_tgid(first) == 10);
    assert(chaos_init_tracee_find(12) == -1 && chaos_init_tracee_find(0) == -1);

    /* A hit is counted in the process's slot and the hits file is written at once;
     * slots exist only for the snapshot's 2 rules. */
    slot = chaos_init_tracee_slot(&g_test_lib, first, 1U);
    assert(slot != NULL && chaos_init_tracee_slot(&g_test_lib, first, 2U) == NULL);
    chaos_hit_record(slot);
    assert(read_hits(10, hits, sizeof(hits)));
    assert(strcmp(hits, "0\t/a:open:EIO:1.0\n1\t/b:open:EIO:1.0\n") == 0);

    /* On reload a count follows its rule text (matched by hash), here from index 1 to
     * index 0; a new text starts at 0. */
    strcpy(g_test_texts[0], "/b:open:EIO:1.0");
    strcpy(g_test_texts[1], "/c:open:EIO:1.0");
    ++g_test_generation;
    slot = chaos_init_tracee_slot(&g_test_lib, first, 0U);
    assert(slot->count == 1U && chaos_init_tracee_slot(&g_test_lib, first, 1U)->count == 0U);

    /* The first CHAOS_HITS_EAGER hits are written immediately; the next one only marks
     * the entry pending until a flush. flush(1) also rewrites entries with any hits. */
    for (index = 1; index < (int)CHAOS_HITS_EAGER; ++index)
    {
        chaos_hit_record(slot);
    }
    assert(read_hits(10, hits, sizeof(hits)) && !chaos_init_tracee_pending());
    chaos_hit_record(slot);
    assert(!read_hits(10, hits, sizeof(hits)) && chaos_init_tracee_pending());
    chaos_init_tracee_flush(0);
    assert(read_hits(10, hits, sizeof(hits)) && !chaos_init_tracee_pending());
    assert(strcmp(hits, "65\t/b:open:EIO:1.0\n0\t/c:open:EIO:1.0\n") == 0);
    chaos_init_tracee_flush(1);
    assert(read_hits(10, hits, sizeof(hits)));

    /* tracee_hit() maps a matched rule copy's snapshot slot to the caller's slot by
     * index; a slot outside the snapshot, a NULL slot or an unresolvable tid gives NULL. */
    {
        chaos_hit_slot_t pool[2];
        chaos_hit_slot_t *snapshot[2] = {&pool[0], &pool[1]};

        assert(
            chaos_init_tracee_hit(&g_test_lib, 10, snapshot, 2U, &pool[1]) ==
            chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 1U)
        );
        assert(chaos_init_tracee_hit(&g_test_lib, 10, snapshot, 1U, &pool[1]) == NULL);
        assert(chaos_init_tracee_hit(&g_test_lib, 10, snapshot, 2U, NULL) == NULL);
        assert(chaos_init_tracee_hit(&g_test_lib, 0, snapshot, 2U, &pool[0]) == NULL);
    }

    /* A report from a slot outside every registered library's storage is ignored
     * rather than indexing out of bounds. */
    memset(&foreign, 0, sizeof(foreign));
    foreign.report = chaos_init_tracee_report;
    chaos_hit_record(&foreign);

    /* Pid reuse: process 10 gets a new start time. The old entry is dropped (its
     * pending hits written first) and the new process starts from 0 under a new serial. */
    chaos_hit_record(slot);
    chaos_hit_record(slot); /* pending: written when the entry is dropped */
    {
        const uint64_t ended = chaos_init_tracee_serial(first);

        g_fake_start[10] = 6U;
        g_fake_start[11] = 6U;
        assert(chaos_init_tracee_of(10) >= 0);
        /* The serial distinguishes holders of the same entry and pid. */
        assert(chaos_init_tracee_serial(chaos_init_tracee_find(10)) != ended);
    }
    assert(chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 0U)->count == 0U);
    /* The new process does not overwrite the old process's hits file: since
     * `.hits.10` exists, it gets a file numbered pid * 10^9 + salt. The old file holds
     * the old process's final 67 hits (1 + 63 + 1 + 2 pending at drop). */
    chaos_hit_record(chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 0U));
    {
        const long number = g_test_rules_file[chaos_init_tracee_of(10)];
        char path[64];

        assert(number > 10L * 1000000000L);
        (void)snprintf(path, sizeof(path), "/tmp/.chaos-inittest.hits.%ld", number);
        assert(unlink(path) == 0);
    }
    assert(read_hits(10, hits, sizeof(hits)) && strncmp(hits, "67\t", 3U) == 0);

    /* A full table (CHAOS_INIT_MAX_TRACEES = 128: process 10, 20..139, 140..146) first
     * reclaims ended processes: process 30 ends and 150 takes its entry... */
    for (index = 0; index < (int)CHAOS_INIT_MAX_TRACEES - 1; ++index)
    {
        g_fake_tgid[20 + index % 100] = 0;
    }
    for (index = 0; index < 120; ++index)
    {
        g_fake_tgid[20 + index] = 20 + index;
        g_fake_start[20 + index] = 1U;
        assert(chaos_init_tracee_of(20 + index) >= 0);
    }
    for (index = 140; index < 147; ++index)
    {
        g_fake_tgid[index] = index;
        g_fake_start[index] = 1U;
        assert(chaos_init_tracee_of(index) >= 0);
    }
    /* 10 and 20..139 and 140..146 fill the table; 30 ends. */
    g_fake_tgid[30] = 0;
    g_fake_tgid[150] = 150;
    g_fake_start[150] = 1U;
    assert(chaos_init_tracee_of(150) >= 0);
    /* ...and when none ended, the least recently used entry is evicted: process 20,
     * not process 10, which was allocated first but has just been used again (its
     * count survives at 2). */
    slot = chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 0U);
    chaos_hit_record(slot);
    g_fake_tgid[151] = 151;
    g_fake_start[151] = 1U;
    assert(chaos_init_tracee_of(151) >= 0);
    assert(chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 0U)->count == 2U);
    {
        char path[64];

        (void)snprintf(
            path,
            sizeof(path),
            "/tmp/.chaos-inittest.hits.%ld",
            g_test_rules_file[chaos_init_tracee_of(10)]
        );
        assert(unlink(path) == 0);
    }
    for (index = 0; index < (int)CHAOS_INIT_MAX_TRACEES; ++index)
    {
        assert(g_chaos_init_tracees[index].tgid != 20);
    }

    /* Reclaim frees every ended entry in one pass: 40 (pid reused, new start time)
     * and 42 (pid now a thread of process 43). The next two processes take those
     * entries in index order and no live process is evicted. */
    {
        const int reused = chaos_init_tracee_find(40);
        const int threaded = chaos_init_tracee_find(42);

        assert(reused >= 0 && threaded >= 0 && reused < threaded);
        g_fake_start[40] = 2U;
        g_fake_tgid[42] = 43;
        g_fake_tgid[152] = 152;
        g_fake_start[152] = 1U;
        assert(chaos_init_tracee_of(152) == reused);
        assert(chaos_init_tracee_find(40) == -1 && chaos_init_tracee_find(42) == -1);
        g_fake_tgid[153] = 153;
        g_fake_start[153] = 1U;
        assert(chaos_init_tracee_of(153) == threaded);
        assert(chaos_init_tracee_find(10) >= 0 && chaos_init_tracee_find(21) >= 0);
    }

    /* flush(1) skips processes without hits: process 21 gets no hits file. */
    chaos_init_tracee_flush(1);
    assert(!read_hits(21, hits, sizeof(hits)));

    /* A snapshot with more rules (5) than the library's max_rules (4): the first 4 get
     * slots and appear in the hits file, the fifth has no slot. */
    strcpy(g_test_texts[0], "/d0:open:EIO:1.0");
    strcpy(g_test_texts[1], "/d1:open:EIO:1.0");
    strcpy(g_test_texts[2], "/d2:open:EIO:1.0");
    strcpy(g_test_texts[3], "/d3:open:EIO:1.0");
    strcpy(g_test_texts[4], "/d4:open:EIO:1.0");
    g_test_text_count = 5U;
    ++g_test_generation;
    g_fake_tgid[154] = 154;
    g_fake_start[154] = 1U;
    first = chaos_init_tracee_of(154);
    assert(first >= 0 && chaos_init_tracee_slot(&g_test_lib, first, 4U) == NULL);
    slot = chaos_init_tracee_slot(&g_test_lib, first, 3U);
    assert(slot != NULL);
    chaos_hit_record(slot);
    assert(read_hits(154, hits, sizeof(hits)));
    assert(
        strcmp(
            hits,
            "0\t/d0:open:EIO:1.0\n0\t/d1:open:EIO:1.0\n0\t/d2:open:EIO:1.0\n1\t/d3:open:EIO:1.0\n"
        ) == 0
    );
    {
        char path[64];

        (void)snprintf(
            path,
            sizeof(path),
            "/tmp/.chaos-inittest.hits.%ld",
            g_test_rules_file[chaos_init_tracee_find(10)]
        );
        (void)unlink(path);
    }
}

int main(void)
{
    test_parse_args();
    test_filter_decisions();
    test_exit_code();
    test_kernel_and_reasons();
    test_status_text();
    test_delays();
    test_find_command();
    test_memory_and_proc();
    test_tracee_table();
    return 0;
}
