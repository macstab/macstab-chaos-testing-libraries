/**
 * @file test_chaos_init.c
 * @brief Unit tests for the system-call-free part of chaos-init.
 *
 * Subsystem under test: `src/init/chaos_init_core.c`
 *
 * Coverage approach:
 * - The production source is included directly.
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
 */

#include "../../src/init/chaos_init_core.c"

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

int main(void)
{
    test_parse_args();
    test_filter_decisions();
    test_exit_code();
    test_kernel_and_reasons();
    test_status_text();
    return 0;
}
