/**
 * @file test_chaos_init_trace.c
 * @brief Unit tests for the register access of src/init/chaos_init_trace.c.
 *
 * @details These do not stub ptrace. Each test forks a child that puts itself under its
 * parent with `PTRACE_TRACEME`, installs a `SECCOMP_RET_TRACE` filter for one system call
 * and makes it; the parent reads the registers at the stop, changes them, and checks what
 * the child observed. A stubbed register file would prove the arithmetic and nothing about
 * the architecture, which is the only thing this module has to get right.
 *
 * Covered:
 * - the number and the arguments of a stopped call are the ones the child passed;
 * - shortening an argument shortens the call: a 10-byte write becomes a 3-byte write, and
 *   the reader receives exactly the first three bytes (this is TORN's whole mechanism);
 * - skipping a call makes the tracee see a return value no call produced, with nothing
 *   written, and a negative value arrives as -1 with that errno (DROP and an injected
 *   failure);
 * - a register block that was never read reports no number and no arguments, and writing
 *   it back fails instead of handing the kernel a zeroed register file;
 * - a skip on a thread that died between the read and the write reports the failure rather
 *   than claiming an effect it never applied.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../../src/init/chaos_init_trace.c"

#include <assert.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/** @brief Installs a filter answering @p nr with TRACE and everything else with ALLOW. */
static void install_trace_filter(long nr)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {(unsigned short)(sizeof(code) / sizeof(code[0])), code};

    code[1].k = (unsigned)nr;
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    assert(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0U, &program) == 0);
}

/**
 * @brief Waits for @p child's seccomp trace stop and reads its registers.
 *
 * @details The child stops itself with SIGSTOP first, which is where the parent turns on
 * PTRACE_O_TRACESECCOMP; without that option a RET_TRACE never becomes a stop.
 */
static void await_trace_stop(pid_t child, chaos_init_trace_regs_t *regs)
{
    int status = 0;

    assert(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
    assert(ptrace(PTRACE_SETOPTIONS, child, 0, (void *)(long)PTRACE_O_TRACESECCOMP) == 0);
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    assert(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
    assert((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)));
    assert(chaos_init_trace_read(child, regs) == 0);
}

/** @brief Proves a stopped write reports its own number and arguments. */
static void test_reads_the_stopped_call(void)
{
    chaos_init_trace_regs_t regs;
    int pipe_fds[2];
    pid_t child;
    int status = 0;

    assert(pipe(pipe_fds) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        (void)close(pipe_fds[0]);
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        install_trace_filter(__NR_write);
        (void)raise(SIGSTOP);
        _exit(syscall(SYS_write, pipe_fds[1], "0123456789", (size_t)10) == 10 ? 0 : 1);
    }
    (void)close(pipe_fds[1]);
    await_trace_stop(child, &regs);
    assert(chaos_init_trace_number(&regs) == __NR_write);
    assert(chaos_init_trace_arg(&regs, 0U) == (uint64_t)pipe_fds[1]);
    assert(chaos_init_trace_arg(&regs, 2U) == 10U);
    /* Out of range yields 0 rather than a neighbouring register. */
    assert(chaos_init_trace_arg(&regs, CHAOS_INIT_TRACE_ARGS) == 0U);
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    {
        char buffer[16] = {0};

        assert(read(pipe_fds[0], buffer, sizeof(buffer)) == 10);
    }
    while (waitpid(child, &status, 0) == child && !WIFEXITED(status))
    {
        if (WIFSTOPPED(status))
        {
            assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
        }
    }
    assert(WEXITSTATUS(status) == 0);
    (void)close(pipe_fds[0]);
}

/** @brief Proves shortening the count shortens the write: TORN, through the real kernel. */
static void test_shortening_an_argument_shortens_the_call(void)
{
    chaos_init_trace_regs_t regs;
    char buffer[16] = {0};
    int pipe_fds[2];
    pid_t child;
    int status = 0;

    assert(pipe(pipe_fds) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        (void)close(pipe_fds[0]);
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        install_trace_filter(__NR_write);
        (void)raise(SIGSTOP);
        /* 3, not 10: the parent shortened it. */
        _exit(syscall(SYS_write, pipe_fds[1], "0123456789", (size_t)10) == 3 ? 0 : 1);
    }
    (void)close(pipe_fds[1]);
    await_trace_stop(child, &regs);
    chaos_init_trace_set_arg(&regs, 2U, 3U);
    assert(chaos_init_trace_write(child, &regs) == 0);
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    assert(read(pipe_fds[0], buffer, sizeof(buffer)) == 3);
    assert(memcmp(buffer, "012", 3U) == 0);
    while (waitpid(child, &status, 0) == child && !WIFEXITED(status))
    {
        if (WIFSTOPPED(status))
        {
            assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
        }
    }
    assert(WEXITSTATUS(status) == 0);
    (void)close(pipe_fds[0]);
}

/**
 * @brief Proves a skipped call returns what the supervisor says and writes nothing.
 *
 * @details Twice: a count the tracee takes for success (DROP) and a negative value, which
 * arrives as -1 with that errno (an injected failure). The pipe stays empty either way,
 * which is what "the call did not run" has to mean.
 */
static void test_skipping_a_call(void)
{
    chaos_init_trace_regs_t regs;
    int pipe_fds[2];
    pid_t child;
    int status = 0;

    assert(pipe(pipe_fds) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        (void)close(pipe_fds[0]);
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        install_trace_filter(__NR_write);
        (void)raise(SIGSTOP);
        if (syscall(SYS_write, pipe_fds[1], "0123456789", (size_t)10) != 10)
        {
            _exit(1);
        }
        errno = 0;
        if (syscall(SYS_write, pipe_fds[1], "x", (size_t)1) != -1 || errno != ENOSPC)
        {
            _exit(2);
        }
        _exit(0);
    }
    (void)close(pipe_fds[1]);
    await_trace_stop(child, &regs);
    assert(chaos_init_trace_skip(child, &regs, 10) == 0);
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    /* The second write, failed with ENOSPC from the supervisor. */
    assert(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
    assert((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)));
    assert(chaos_init_trace_read(child, &regs) == 0);
    assert(chaos_init_trace_skip(child, &regs, -ENOSPC) == 0);
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    while (waitpid(child, &status, 0) == child && !WIFEXITED(status))
    {
        if (WIFSTOPPED(status))
        {
            assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
        }
    }
    assert(WEXITSTATUS(status) == 0);
    /* Nothing was written: both calls were skipped. The child has exited, so its end of
     * the pipe is closed and a read reports end of file rather than blocking. */
    {
        char buffer[4];

        assert(read(pipe_fds[0], buffer, sizeof(buffer)) == 0);
    }
    (void)close(pipe_fds[0]);
}

/**
 * @brief Proves a skip on a tracee that died between the read and the write fails.
 *
 * @details The registers are read at a real stop, so the block is valid; the thread is then
 * killed and reaped before the skip. A supervisor that ignored the write's result would
 * report success for an effect it never applied, and the hit would be counted for a call
 * nobody made.
 */
static void test_skip_on_a_dead_tracee(void)
{
    chaos_init_trace_regs_t regs;
    int pipe_fds[2];
    pid_t child;
    int status = 0;

    assert(pipe(pipe_fds) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        (void)close(pipe_fds[0]);
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        install_trace_filter(__NR_write);
        (void)raise(SIGSTOP);
        (void)syscall(SYS_write, pipe_fds[1], "x", (size_t)1);
        _exit(0);
    }
    (void)close(pipe_fds[1]);
    await_trace_stop(child, &regs);
    assert(kill(child, SIGKILL) == 0);
    assert(waitpid(child, &status, 0) == child);
    errno = 0;
    assert(chaos_init_trace_skip(child, &regs, 10) == -1);
    assert(errno == ESRCH);
    (void)close(pipe_fds[0]);
}

/**
 * @brief Proves an unread register block is refused rather than handed to the kernel.
 *
 * @details chaos_init_trace_read() fails for a thread that is not stopped, and the block
 * it leaves behind must not look like a usable register file: a zeroed one written back
 * would set every register of the tracee to 0.
 */
static void test_unread_registers_are_refused(void)
{
    chaos_init_trace_regs_t regs;

    (void)memset(&regs, 0xee, sizeof(regs));
    regs.size = 0U;
    assert(chaos_init_trace_number(&regs) == -1);
    assert(chaos_init_trace_arg(&regs, 0U) == 0U);
    chaos_init_trace_set_arg(&regs, 0U, 1U);
    errno = 0;
    assert(chaos_init_trace_skip(getpid(), &regs, 1) == -1 && errno == EINVAL);
    errno = 0;
    assert(chaos_init_trace_write(getpid(), &regs) == -1 && errno == EINVAL);
    errno = 0;
    assert(chaos_init_trace_read(getpid(), NULL) == -1 && errno == EINVAL);
    /* This process traces nobody, so reading a live thread's registers fails. */
    assert(chaos_init_trace_read(getpid(), &regs) == -1);
}

int main(void)
{
    test_reads_the_stopped_call();
    test_shortening_an_argument_shortens_the_call();
    test_skipping_a_call();
    test_skip_on_a_dead_tracee();
    test_unread_registers_are_refused();
    return 0;
}
