/**
 * @file test_chaos_init.c
 * @brief Unit tests for the system-call-free part of chaos-init.
 *
 * Subsystems under test: `src/init/chaos_init_core.c`, `chaos_init_delay.c`,
 * `chaos_init_proc.c`, `chaos_init_tracee.c`
 *
 * Coverage approach:
 * - The production sources are included directly.
 * - Memory and /proc are read for real, from this test process itself; only the
 *   /proc reader of chaos_init_process_of() is replaced, to feed it malformed
 *   files, and the process lookup of the tracee table, to control pids.
 * - The filter is not checked instruction by instruction: a small interpreter for
 *   the classic BPF the filter uses (load word, jump if equal / greater or equal,
 *   return) runs it on seccomp_data built per case, and the test asserts the
 *   decision, so a wrong jump offset fails like a wrong system call list.
 *
 * Properties under test:
 * - Arguments: `--libs <names> -- <command>` with known names only.
 * - Filter: each library's calls are notified, other calls and other architectures
 *   pass, and of all sendmsg calls only the handover passes.
 * - Exit code, kernel version check, unsupported reasons, status text.
 * - Delays: the earliest first, one at a time, a full queue refuses.
 * - Memory: strings up to an unmapped page, partial reads, /proc links, the
 *   process and start time of a thread.
 * - Tracee table: one entry per process, a reused pid starts over, a full table
 *   frees ended processes first and the oldest last; counts follow rule texts
 *   across reloads; hits files are written eagerly, then on flush.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* /proc reader of chaos_init_process_of(): real, or a canned malformed file. */
static const char *g_fake_status = NULL;
static const char *g_fake_stat = NULL;
static long test_proc_read(pid_t pid, const char *name, char *out, size_t size);
#define CHAOS_INIT_PROC_READ test_proc_read

/* Process lookup of the tracee table: tid -> (tgid, start) set by the test. */
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

/** @brief Runs @p filter (as built by chaos_init_build_filter) on @p data. */
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

/** @brief The decision for system call @p nr with arguments @p fd and @p flags. */
static uint32_t decide(unsigned libs, long nr, uint64_t fd, uint64_t flags, uint32_t arch)
{
    struct sock_filter filter[CHAOS_INIT_MAX_FILTER];
    struct seccomp_data data;
    const size_t length = chaos_init_build_filter(libs, filter, CHAOS_INIT_MAX_FILTER);

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

    /* Each library's calls, and only those, go to the supervisor. */
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

    /* Shared calls appear once, and every call of every library is notified. */
    assert(decide(CHAOS_INIT_LIB_IO | CHAOS_INIT_LIB_NET, __NR_read, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_munmap, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_waitid, 0U, 0U, ARCH) == NOTIFY);
    assert(decide(0x3fU, __NR_getpid, 0U, 0U, ARCH) == ALLOW);

    /* dns and time have no system calls of their own here. */
    assert(decide(CHAOS_INIT_LIB_DNS | CHAOS_INIT_LIB_TIME, __NR_connect, 0U, 0U, ARCH) == ALLOW);

    /* Of all sendmsg calls only the handover passes. */
    assert(
        decide(
            CHAOS_INIT_LIB_NET,
            __NR_sendmsg,
            CHAOS_INIT_HANDOVER_FD,
            CHAOS_INIT_HANDOVER_FLAGS,
            ARCH
        ) == ALLOW
    );
    assert(
        decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, CHAOS_INIT_HANDOVER_FD, MSG_NOSIGNAL, ARCH) ==
        NOTIFY
    );
    assert(decide(CHAOS_INIT_LIB_NET, __NR_sendmsg, 7U, CHAOS_INIT_HANDOVER_FLAGS, ARCH) == NOTIFY);

    /* Another architecture passes, and so does the x32 ABI. */
    assert(decide(CHAOS_INIT_LIB_NET, __NR_connect, 0U, 0U, 0x12345678U) == ALLOW);
#ifdef __x86_64__
    assert(decide(CHAOS_INIT_LIB_NET, 0x40000000L | __NR_connect, 0U, 0U, ARCH) == ALLOW);
#endif

    /* Too little room is refused, not overrun. */
    assert(chaos_init_build_filter(0x3fU, small, sizeof(small) / sizeof(small[0])) == 0U);
}

static void test_exit_code(void)
{
    assert(chaos_init_exit_code(0) == 0);
    assert(chaos_init_exit_code(3 << 8) == 3);
    assert(chaos_init_exit_code(9) == 137);
    assert(chaos_init_exit_code(15) == 143);
}

static void test_kernel_and_reasons(void)
{
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

static void test_status_text(void)
{
    char text[256];
    char tiny[8];

    assert(
        chaos_init_format_status(
            text, sizeof(text), CHAOS_INIT_LIB_PROCESS | CHAOS_INIT_LIB_IO, NULL, 1L
        ) > 0U
    );
    assert(strcmp(text, "state=active\nlibs=io,process\npid=1\n") == 0);
    assert(
        chaos_init_format_status(
            text, sizeof(text), CHAOS_INIT_LIB_NET, "kernel older than 5.5", 7L
        ) > 0U
    );
    assert(strcmp(text, "state=unsupported\nreason=kernel older than 5.5\nlibs=net\npid=7\n") == 0);
    assert(chaos_init_format_status(tiny, sizeof(tiny), CHAOS_INIT_LIB_NET, NULL, 1L) == 0U);
}

static void test_delays(void)
{
    uint64_t due = 0U;
    uint64_t id = 0U;
    size_t index;

    assert(chaos_init_delay_next(&due) == 0);
    assert(chaos_init_delay_pop(1000U, &id) == 0);
    assert(chaos_init_delay_add(7U, 300U) == 0);
    assert(chaos_init_delay_add(8U, 100U) == 0);
    assert(chaos_init_delay_add(9U, 200U) == 0);
    assert(chaos_init_delay_next(&due) == 1 && due == 100U);
    assert(chaos_init_delay_pop(50U, &id) == 0);
    assert(chaos_init_delay_pop(250U, &id) == 1 && (id == 8U || id == 9U));
    assert(chaos_init_delay_pop(250U, &id) == 1 && (id == 8U || id == 9U));
    assert(chaos_init_delay_pop(250U, &id) == 0);
    assert(chaos_init_delay_pop(300U, &id) == 1 && id == 7U);
    for (index = 0U; index < CHAOS_INIT_MAX_DELAYED; ++index)
    {
        assert(chaos_init_delay_add(index, 1U) == 0);
    }
    assert(chaos_init_delay_add(1U, 1U) == -1);
    while (chaos_init_delay_pop(1U, &id))
    {
    }
}

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

    /* Plain reads of this very process. */
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

    /* A string that ends right before an unmapped page is read; one that runs
     * into it is not, and a partial read is an error. */
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
    (void)munmap(pages, (size_t)page * 2U);

    /* /proc links. */
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

    /* The process of a thread and its start time; ended or malformed ones fail. */
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
    g_fake_stat = "12 no-paren";
    assert(chaos_init_process_of(getpid(), &tgid, &start) == -1);
    g_fake_status = NULL;
    g_fake_stat = NULL;
}

/* A library for the tracee table: two snapshots of rule texts. */
CHAOS_INIT_RULES_STORAGE(g_test_rules, 4U);
static chaos_init_text_t g_test_texts[4];
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
};

/** @brief The hits file of process @p tgid into @p out; 0 when there is none. */
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

static void test_tracee_table(void)
{
    chaos_init_rules_t too_many = g_test_lib;
    chaos_hit_slot_t foreign;
    chaos_hit_slot_t *slot;
    char hits[512];
    int first;
    int index;

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

    /* One entry per process; an unknown thread has none. */
    assert(chaos_init_tracee_of(0) == -1);
    g_fake_tgid[10] = 10;
    g_fake_start[10] = 5U;
    g_fake_tgid[11] = 10; /* a second thread of process 10 */
    g_fake_start[11] = 5U;
    first = chaos_init_tracee_of(10);
    assert(first >= 0 && chaos_init_tracee_of(11) == first);

    /* A hit is counted in the process's slot and written at once. */
    slot = chaos_init_tracee_slot(&g_test_lib, first, 1U);
    assert(slot != NULL && chaos_init_tracee_slot(&g_test_lib, first, 2U) == NULL);
    chaos_hit_record(slot);
    assert(read_hits(10, hits, sizeof(hits)));
    assert(strcmp(hits, "0\t/a:open:EIO:1.0\n1\t/b:open:EIO:1.0\n") == 0);

    /* A reload keeps the count of a rule whose text stayed, wherever it moved. */
    strcpy(g_test_texts[0], "/b:open:EIO:1.0");
    strcpy(g_test_texts[1], "/c:open:EIO:1.0");
    ++g_test_generation;
    slot = chaos_init_tracee_slot(&g_test_lib, first, 0U);
    assert(slot->count == 1U && chaos_init_tracee_slot(&g_test_lib, first, 1U)->count == 0U);

    /* After CHAOS_HITS_EAGER hits, writes wait for a flush. */
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

    /* A slot of no registered library is ignored. */
    memset(&foreign, 0, sizeof(foreign));
    foreign.report = chaos_init_tracee_report;
    chaos_hit_record(&foreign);

    /* The pid of an ended process, now another one's: its counts start over. */
    chaos_hit_record(slot);
    chaos_hit_record(slot); /* pending: written when the entry is dropped */
    g_fake_start[10] = 6U;
    g_fake_start[11] = 6U;
    assert(chaos_init_tracee_of(10) >= 0);
    assert(read_hits(10, hits, sizeof(hits)));
    assert(chaos_init_tracee_slot(&g_test_lib, chaos_init_tracee_of(10), 0U)->count == 0U);

    /* A full table frees ended processes first... */
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
    /* ...and when none ended, the oldest (process 10) gives way. */
    g_fake_tgid[151] = 151;
    g_fake_start[151] = 1U;
    assert(chaos_init_tracee_of(151) >= 0);
    g_fake_start[10] = 6U;
    assert(chaos_init_tracee_of(10) >= 0); /* back, as a new entry */
}

int main(void)
{
    test_parse_args();
    test_filter_decisions();
    test_exit_code();
    test_kernel_and_reasons();
    test_status_text();
    test_delays();
    test_memory_and_proc();
    test_tracee_table();
    return 0;
}
