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
 *   than claiming an effect it never applied;
 * - an entry stop can be continued into the syscall-exit stop, where the result and the
 *   bytes the call wrote are reachable, and continuing from there does not leave the thread
 *   stopping at every later system call;
 * - a call parked at the entry stop comes back at the exit stop exactly once, which is how
 *   the exit stop knows the descriptor the result register overwrote.
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
 * @brief Proves the entry stop can be continued into an exit stop, where the call's result
 *   and the bytes it wrote are both reachable.
 *
 * @details This is what every effect on a *returned* value needs: at the entry stop the
 * length a read will deliver is unknown, so the decision about its bytes can only be made
 * afterwards. Asserted here:
 * - continuing the entry stop with PTRACE_SYSCALL produces a second stop, reported as
 *   `SIGTRAP | 0x80` because PTRACE_O_TRACESYSGOOD is set, which is how it is told from a
 *   signal stop;
 * - at that stop the result register holds what the call returned (3 of the 8 bytes the
 *   pipe had), and the number register still names the call;
 * - the tracee's buffer can be rewritten there, and the tracee sees the change -- the
 *   mechanism CORRUPT is built on;
 * - continuing with PTRACE_CONT does not stop the thread at its next system call, so the
 *   exit stop costs one stop and not a permanent syscall trace.
 */
static void test_exit_stop_reaches_the_result(void)
{
    chaos_init_trace_regs_t regs;
    int pipe_fds[2];
    pid_t child;
    int status = 0;

    assert(pipe(pipe_fds) == 0);
    assert(write(pipe_fds[1], "ABCDEFGH", 8U) == 8);
    /* Away from 3, so the descriptor cannot be mistaken for the 3-byte result below. */
    while (pipe_fds[0] <= 3)
    {
        const int moved = dup(pipe_fds[0]);

        assert(moved > 0);
        (void)close(pipe_fds[0]);
        pipe_fds[0] = moved;
    }
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        char buffer[8];
        ssize_t got;

        (void)close(pipe_fds[1]);
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        install_trace_filter(__NR_read);
        (void)raise(SIGSTOP);
        got = (ssize_t)syscall(SYS_read, pipe_fds[0], buffer, (size_t)3);
        /* Three bytes, with the first one replaced by the supervisor at the exit stop. */
        if (got != 3 || memcmp(buffer, "xBC", 3U) != 0)
        {
            _exit(4);
        }
        /* A second read must run without a stop of its own: PTRACE_CONT, not SYSCALL. */
        if (syscall(SYS_read, pipe_fds[0], buffer, (size_t)2) != 2)
        {
            _exit(5);
        }
        _exit(0);
    }
    (void)close(pipe_fds[1]);
    await_trace_stop(child, &regs);
    assert(
        ptrace(
            PTRACE_SETOPTIONS,
            child,
            0,
            (void *)(long)(PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD)
        ) == 0
    );
    {
        const uint64_t buffer_address = chaos_init_trace_arg(&regs, 1U);

        /* Into the exit stop rather than straight on. */
        assert(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0);
        assert(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
        assert(chaos_init_trace_is_syscall_stop(status));
        assert(chaos_init_trace_read(child, &regs) == 0);
        assert(chaos_init_trace_result(&regs) == 3);
        assert(chaos_init_trace_number(&regs) == __NR_read);
        /* Arguments 1 and up still hold what the caller passed. Argument 0 does not: on
         * aarch64 the result comes back in x0, the register that carried the first
         * argument, so at the exit stop it reads as the result. Whatever needs the first
         * argument -- a descriptor, usually -- has to carry it from the entry stop. This
         * assertion is the pin for that, with a descriptor that is not 3 so it cannot be
         * confused with the 3-byte result. */
        assert(chaos_init_trace_arg(&regs, 1U) == buffer_address);
        assert(chaos_init_trace_arg(&regs, 2U) == 3U);
#if defined(__aarch64__)
        assert(chaos_init_trace_arg(&regs, 0U) == 3U); /* the result, not the descriptor */
#else
        assert(chaos_init_trace_arg(&regs, 0U) == (uint64_t)pipe_fds[0]);
#endif
        /* The bytes are in the tracee now, so they can be changed. */
        {
            struct iovec local;
            struct iovec remote;

            local.iov_base = (void *)"x";
            local.iov_len = 1U;
            remote.iov_base = (void *)(uintptr_t)buffer_address;
            remote.iov_len = 1U;
            assert(process_vm_writev(child, &local, 1U, &remote, 1U, 0U) == 1);
        }
    }
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    /* The second read is a seccomp stop again (the filter), not a syscall stop. */
    assert(waitpid(child, &status, 0) == child && WIFSTOPPED(status));
    assert(!chaos_init_trace_is_syscall_stop(status));
    assert((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)));
    assert(ptrace(PTRACE_CONT, child, 0, 0) == 0);
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
 * @brief Proves a call parked at the entry stop comes back at the exit stop, once.
 *
 * @details The exit stop cannot read the call back from the registers -- on aarch64 the
 * result arrives in the register that held the first argument -- so it has to be carried.
 * Asserted: a parked call comes back unchanged and only once; a thread that parked nothing
 * gets nothing; a second park for the same thread replaces the first, because a thread is
 * in one system call at a time; and a table filled by other threads refuses the next park
 * rather than losing one, so the caller can run that call without the effect.
 */
static void test_parking_a_call(void)
{
    chaos_init_call_t parked;
    chaos_init_call_t taken;
    size_t index;

    memset(&parked, 0, sizeof(parked));
    parked.tid = 4321;
    parked.nr = __NR_read;
    parked.args[0] = 7U;
    parked.args[1] = 0xdeadbeefU;
    parked.args[2] = 64U;
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 0);
    assert(chaos_init_trace_park(&parked) == 0);
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 1);
    assert(taken.tid == parked.tid && taken.nr == parked.nr);
    assert(taken.args[0] == 7U && taken.args[1] == 0xdeadbeefU && taken.args[2] == 64U);
    /* Taken means gone: a second exit stop for the same thread finds nothing. */
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 0);

    /* One entry per thread: the second park replaces the first. */
    assert(chaos_init_trace_park(&parked) == 0);
    parked.args[1] = 0x1234U;
    assert(chaos_init_trace_park(&parked) == 0);
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 1);
    assert(taken.args[1] == 0x1234U);
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 0);

    /* A full table refuses rather than dropping someone else's call. */
    for (index = 0U; index < CHAOS_INIT_TRACE_PENDING; ++index)
    {
        parked.tid = (pid_t)(1000 + index);
        assert(chaos_init_trace_park(&parked) == 0);
    }
    parked.tid = 999;
    assert(chaos_init_trace_park(&parked) == -1);
    for (index = 0U; index < CHAOS_INIT_TRACE_PENDING; ++index)
    {
        assert(chaos_init_trace_unpark((pid_t)(1000 + index), &taken) == 1);
    }
    assert(chaos_init_trace_park(&parked) == 0);
    assert(chaos_init_trace_unpark(parked.tid, &taken) == 1);
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
    assert(chaos_init_trace_result(&regs) == -1);
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
    test_exit_stop_reaches_the_result();
    test_parking_a_call();
    test_skip_on_a_dead_tracee();
    test_unread_registers_are_refused();
    return 0;
}
