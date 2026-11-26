/**
 * @file chaos_init.c
 * @brief `chaos-init`: container PID 1 and seccomp user-notification supervisor
 *        (SECCOMP mode).
 *
 * @details
 * Usage: `chaos-init --libs io,net,memory,process -- <entrypoint> [args...]`
 *
 * @par Process model
 * 1. **Fork.** The child (the future application, the first tracee) builds the filter
 *    (chaos_init_build_filter()), installs it with SECCOMP_FILTER_FLAG_NEW_LISTENER and
 *    sends the listener fd to the parent over a socketpair with SCM_RIGHTS: the one
 *    sendmsg() the filter exempts. Installing a filter needs no privilege once
 *    no_new_privs is set, so this works under Docker's default profile. The alternative,
 *    the parent fetching the fd with pidfd_getfd(), needs CAP_SYS_PTRACE and is blocked
 *    there.
 * 2. **Status, then go.** The parent writes CHAOS_INIT_STATUS_PATH (`state=active`, or
 *    `state=unsupported` with the reason) and only then sends CHAOS_INIT_GO_SIGNAL; the
 *    child waits for it with sigwait(), which the filter never notifies. Whoever observes
 *    the application running therefore reads this run's status, never a stale one. When
 *    the filter cannot be installed (kernel < 5.5, QEMU emulation, a stricter profile,
 *    another supervisor's listener) the application still starts, without chaos.
 * 3. **Serve.** One poll() loop multiplexes a signalfd, a timerfd and the listener. Each
 *    notification is decided by the rule cores of the libraries in --libs and answered:
 *    fail, return a value, run unchanged (CONTINUE), or later (LATENCY, parked in
 *    chaos_init_delay.c so the other threads keep being served).
 *
 * @par PID 1 duties
 * - Signals: SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGWINCH, SIGALRM and
 *   SIGPIPE are blocked before the fork and read from a signalfd, then forwarded to the
 *   child's pid (not its process group). Blocking also matters for PID 1: the kernel
 *   discards signals with default disposition sent to a namespace's init, but not
 *   blocked ones.
 * - Reaping: every SIGCHLD reaps all exited children (orphans included). Outside PID 1,
 *   PR_SET_CHILD_SUBREAPER makes orphans of the application reparent here.
 * - Exit: the application's exit code, or 128 + signal; chaos-init's own failures use
 *   2 (usage), 125 (setup/handover), 126 (not executable), 127 (not found).
 * - Leftovers: outside PID 1, a background copy keeps answering processes the
 *   application left behind (chaos_init_serve_the_rest()).
 *
 * @par Failure behaviour
 * Fail-open for the application: no filter means no chaos, never no start. Fail-fast for
 * the supervisor: once a filter is installed, no state may remain in which notifications
 * go unanswered, since every filtered call would block for good. A child whose handover
 * failed exits 125 itself; the parent kills the child with SIGKILL when the notification
 * sizes are unusable or signalfd/timerfd cannot be created, and exits 125.
 *
 * @par Side effect
 * no_new_privs is inherited by everything the application starts: set-user-ID and file
 * capability binaries no longer gain privileges. It is set only after a probe proved the
 * filter installs (chaos_init_try_install()).
 *
 * @par Test seams (compile-time, used by test/runtime builds)
 * CHAOS_INIT_TEST_RELEASE (fake kernel release), CHAOS_INIT_TEST_HANDOVER_FAILS (handover
 * sendmsg fails with ENOBUFS), CHAOS_INIT_TEST_NO_KILLABLE_WAIT (pre-5.19 filter flags).
 * The process glue in this file is covered by test/runtime/test_init.sh, not unit tests.
 */

#include "chaos_init_core.h"
#include "chaos_init_delay.h"
#include "chaos_init_dns.h"
#include "chaos_init_trace.h"
#include "chaos_init_io.h"
#include "chaos_init_memory.h"
#include "chaos_init_net.h"
#include "chaos_init_proc.h"
#include "chaos_init_process.h"
#include "chaos_init_time.h"
#include "chaos_init_tracee.h"
#include "chaos_init_vdso.h"
#include "chaos_status.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h> /* _IOWR for the SECCOMP_IOCTL_* numbers */
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief Exit codes of chaos-init itself (the application's are passed through). 125-127
 *        follow the `docker run` / shell convention: setup failure, found but not
 *        executable, not found.
 */
#define CHAOS_INIT_EXIT_USAGE 2
#define CHAOS_INIT_EXIT_HANDOVER 125
#define CHAOS_INIT_EXIT_NOT_EXECUTABLE 126
#define CHAOS_INIT_EXIT_NOT_FOUND 127

/**
 * @brief Tells the child the status file is written and it may execute the command. It is
 *        in the forwarded set, so it is already blocked in the child and cannot be lost
 *        when it arrives before sigwait().
 */
#define CHAOS_INIT_GO_SIGNAL SIGUSR1

/**
 * @brief Signals forwarded to the application. SIGCHLD is consumed here (reaping); SIGKILL
 *        and SIGSTOP cannot be caught. Blocked from before the fork until the child
 *        restores the original mask right before exec.
 */
static const int g_chaos_init_forwarded[] = {
    SIGTERM,
    SIGINT,
    SIGHUP,
    SIGQUIT,
    SIGUSR1,
    SIGUSR2,
    SIGWINCH,
    SIGALRM,
    SIGPIPE,
};

/**
 * @brief Test seam: the kernel release to judge instead of uname()'s. A runtime test build
 *        sets an old release to reach the `state=unsupported` path on a current kernel.
 */
#ifdef CHAOS_INIT_TEST_RELEASE
#define CHAOS_INIT_RELEASE(name) CHAOS_INIT_TEST_RELEASE
#else
#define CHAOS_INIT_RELEASE(name) ((name)->release)
#endif

/* Defined here for build hosts whose UAPI headers predate Linux 5.19. */
#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

/**
 * @brief The handover sendmsg(): the listener, or the errno explaining why there is none.
 *        Test seam: CHAOS_INIT_TEST_HANDOVER_FAILS makes it fail with ENOBUFS, so a runtime
 *        test reaches the path where a child with an installed filter must not exec.
 */
#ifdef CHAOS_INIT_TEST_HANDOVER_FAILS
#define CHAOS_INIT_SENDMSG(fd, message, flags) ((void)(message), errno = ENOBUFS, (ssize_t) - 1)
#else
#define CHAOS_INIT_SENDMSG(fd, message, flags) sendmsg((fd), (message), (flags))
#endif

/**
 * @brief Filter flags tried first.
 *
 * @details From Linux 5.19, SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV makes a thread whose
 * notification the supervisor has received wait killably: only a fatal signal interrupts
 * it. Without it, any signal interrupts a parked (delayed) call and the kernel restarts it
 * as a new notification; Go signals its threads constantly (async preemption), so that
 * path is hot. Older kernels reject the flag with EINVAL and chaos_init_install() retries
 * without it; the delay queue then re-binds restarted calls (chaos_init_delay_resume()).
 * Test seam: CHAOS_INIT_TEST_NO_KILLABLE_WAIT builds the pre-5.19 variant.
 */
#ifdef CHAOS_INIT_TEST_NO_KILLABLE_WAIT
#define CHAOS_INIT_FILTER_FLAGS SECCOMP_FILTER_FLAG_NEW_LISTENER
#else
#define CHAOS_INIT_FILTER_FLAGS                                                                    \
    (SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
#endif

/**
 * @brief Bytes reserved for `struct seccomp_notif` and `struct seccomp_notif_resp`. The
 *        kernel may grow both; main() checks SECCOMP_GET_NOTIF_SIZES against this before
 *        serving, because NOTIF_RECV writes the kernel's size, not ours.
 */
#define CHAOS_INIT_NOTIF_BUFFER 512U

/** @brief Fills @p set with SIGCHLD and every forwarded signal. */
static void chaos_init_signal_set(sigset_t *set)
{
    size_t index;

    (void)sigemptyset(set);
    (void)sigaddset(set, SIGCHLD);
    for (index = 0U; index < sizeof(g_chaos_init_forwarded) / sizeof(g_chaos_init_forwarded[0]);
         ++index)
    {
        (void)sigaddset(set, g_chaos_init_forwarded[index]);
    }
}

/**
 * @brief Installs @p program on the calling thread with a notification listener.
 *
 * @details Raw syscall: neither glibc nor musl provides a seccomp() wrapper. Requires
 * no_new_privs (or CAP_SYS_ADMIN). Without SECCOMP_FILTER_FLAG_TSYNC
 * only the calling thread is filtered; the child is single-threaded here.
 *
 * @return The listener fd, or -1 with errno (EBUSY: a filter in the chain already has a
 *         listener; EINVAL: unsupported flags or filter; EACCES: no no_new_privs).
 */
static int chaos_init_install(const struct sock_fprog *program)
{
    int listener =
        (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, CHAOS_INIT_FILTER_FLAGS, program);

    if (listener < 0 && errno == EINVAL)
    {
        /* Before 5.19 the killable-wait flag is unknown (EINVAL); retry without it. */
        listener = (int
        )syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, program);
    }
    return listener;
}

/**
 * @brief Probes whether @p program installs, in a throw-away child, before the caller
 *        commits to no_new_privs.
 *
 * @details no_new_privs is irreversible and inherited by the application. Setting it and
 * then failing to install (EBUSY under another supervisor's listener, EACCES/EPERM from a
 * stricter profile or LSM) would leave an application that runs without chaos yet has
 * lost set-user-ID semantics. The probe sets no_new_privs and installs in a forked process
 * that _exit()s at once (exit_group is never notified, and its orphaned listener dies with
 * it), and reports the errno through its exit status (errno values fit in 8 bits).
 *
 * @return 0 when the install works, or when fork() failed (the real install then reports
 *         any error); otherwise the errno the install failed with, or EINVAL when the
 *         probe did not exit normally.
 */
static int chaos_init_try_install(const struct sock_fprog *program)
{
    const pid_t probe = fork();
    int status = 0;

    if (probe == 0)
    {
        _exit(
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && chaos_init_install(program) >= 0 ? 0
                                                                                            : errno
        );
    }
    if (probe < 0)
    {
        return 0; /* no probe: the real install reports any error itself */
    }
    while (waitpid(probe, &status, 0) < 0 && errno == EINTR)
    {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : EINVAL;
}

/**
 * @brief Non-zero once the application put itself under this process with PTRACE_TRACEME,
 *        i.e. the filter has a traced group or time rules are loaded.
 *
 * @details File scope because the handover sets it and the serve loop reads it. The
 * supervisor has one thread and one application, so one flag is the whole state.
 */
static int g_chaos_init_tracing = 0;

/**
 * @brief Non-zero once an image could not have its vDSO blinded (chaos_init_vdso.h).
 *
 * @details Its clock reads then never reach the filter, so time rules do nothing for that
 * process -- the one thing this mode must not be quiet about. Reported in the status
 * file, where a test can see it.
 */
static int g_chaos_init_vdso_failed = 0;

/**
 * @brief Whether this run disabled Go's Multipath TCP, kept so a status file written
 *        again later (a failed vDSO blinding) says the same as the first one.
 */
static int g_chaos_init_mptcp_off = 0;

/** @brief Whether the status file already says a process could not be read. */
static int g_chaos_init_said_unreadable = 0;

/**
 * @brief Child side of the handover: installs the filter if possible and sends the parent
 *        either the listener (SCM_RIGHTS) or the errno that prevented it.
 *
 * @details Checks run cheapest and reversible first, so that every refusal leaves the
 * application without no_new_privs:
 * 1. kernel release >= 5.5 (ENOTSUP otherwise; CHAOS_INIT_RELEASE seam);
 * 2. SECCOMP_GET_ACTION_AVAIL for SECCOMP_RET_USER_NOTIF;
 * 3. chaos_init_try_install() in a throw-away process;
 * 4. PR_SET_NO_NEW_PRIVS, then the real install.
 *
 * The payload is always the int errno (0 on success), so the parent can tell "refused"
 * (payload > 0, no fd) from "child died" (EOF). With net selected, sendmsg() is filtered
 * and this call passes only through the CHAOS_INIT_HANDOVER_FLAGS exemption.
 *
 * @param handover   The child's socketpair end (O_CLOEXEC).
 * @param installed  Output: 1 when a filter with listener is installed in this process.
 * @return 0 when the child may exec, -1 when it must not: the handover failed, so the
 *         parent will never answer an installed filter.
 */
static int chaos_init_install_and_hand_over(unsigned libs, int handover, int *installed)
{
    struct sock_filter filter[CHAOS_INIT_MAX_FILTER];
    struct sock_fprog program;
    struct utsname name;
    struct msghdr message;
    struct iovec payload;
    union
    {
        struct cmsghdr header;
        char space[CMSG_SPACE(sizeof(int))];
    } control;
    uint32_t notify = SECCOMP_RET_USER_NOTIF;
    long traced[CHAOS_INIT_MAX_FILTER];
    long rule_calls[16];
    long time_clocks[16];
    chaos_init_rule_filter_t rule_filter;
    const chaos_init_rule_filter_t *rules = NULL;
    size_t traced_count = 0U;
    size_t dns_count = 0U;
    /* [0] errno, [1] whether the parent is the tracer, [2] how many TRACE numbers follow,
     * then the numbers: the filter is fixed once installed, so the parent has to know
     * exactly which calls it can expect a stop for. Recomputing it there is not an option
     * -- asking the rule cores publishes a snapshot, and the parent is the process serving
     * notifications from them. */
    long answer[3 + CHAOS_INIT_MAX_FILTER] = {0};
    int error = 0;
    int listener = -1;
    int tracing;

    /* Which calls need a ptrace stop is a property of the rules, and a filter is fixed
     * once installed, so the rule file is read here, before the install. The child's copy
     * of the configuration is thrown away at the exec; the parent reads it again for its
     * decisions. */
    if ((libs & CHAOS_INIT_LIB_IO) != 0U)
    {
        chaos_init_io_start();
        traced_count = chaos_init_io_traced_calls(traced, sizeof(traced) / sizeof(traced[0]));
    }
    if ((libs & CHAOS_INIT_LIB_NET) != 0U)
    {
        chaos_init_net_start();
        traced_count += chaos_init_net_traced_calls(
            traced + traced_count, sizeof(traced) / sizeof(traced[0]) - traced_count
        );
    }
    if ((libs & CHAOS_INIT_LIB_DNS) != 0U)
    {
        chaos_init_dns_start();
        dns_count = chaos_init_dns_calls(rule_calls, sizeof(rule_calls) / sizeof(rule_calls[0]));
    }
    rule_filter.calls = rule_calls;
    rule_filter.call_count = dns_count;
    rule_filter.clocks = time_clocks;
    rule_filter.clock_count = 0U;
    if ((libs & CHAOS_INIT_LIB_TIME) != 0U)
    {
        chaos_init_time_start();
        rule_filter.call_count += chaos_init_time_calls(
            rule_calls + dns_count, sizeof(rule_calls) / sizeof(rule_calls[0]) - dns_count
        );
        rule_filter.clock_count =
            chaos_init_time_clocks(time_clocks, sizeof(time_clocks) / sizeof(time_clocks[0]));
    }
    rules = rule_filter.call_count > 0U ? &rule_filter : NULL;
    /* Time needs a tracer even with nothing traced: the vDSO of every image has to be
     * blinded at its exec stop, or its clock reads never reach the filter at all. */
    tracing = traced_count > 0U || (libs & CHAOS_INIT_LIB_TIME) != 0U;
    program.len = (unsigned short)chaos_init_build_filter(
        libs, handover, traced, traced_count, rules, filter, CHAOS_INIT_MAX_FILTER
    );
    program.filter = filter;
    if (uname(&name) != 0 || !chaos_init_kernel_supported(CHAOS_INIT_RELEASE(&name)))
    {
        error = ENOTSUP;
    }
    /* Needs no no_new_privs: asked before it, so an application that runs without chaos
     * also runs without no_new_privs, which cannot be undone. */
    else if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &notify) != 0)
    {
        error = errno;
    }
    else if ((error = chaos_init_try_install(&program)) != 0)
    {
        /* The probe was refused: report its errno; no_new_privs stays unset. */
    }
    else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        error = errno;
    }
    /* Before the filter, because a RET_TRACE without a tracer fails the call with ENOSYS:
     * the tracer has to exist the moment the filter does. PTRACE_TRACEME needs no
     * capability -- the tracee asks for it itself -- and makes this child's parent, which
     * is the process that owns the listener and runs the serve loop, its tracer. */
    else if (tracing && ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
    {
        error = errno;
    }
    else
    {
        listener = chaos_init_install(&program);
        error = listener < 0 ? errno : 0;
    }

    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    answer[0] = error;
    answer[1] = error == 0 && tracing;
    answer[2] = (long)traced_count;
    memcpy(&answer[3], traced, traced_count * sizeof(traced[0]));
    payload.iov_base = answer;
    payload.iov_len = sizeof(answer);
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    if (listener >= 0)
    {
        message.msg_control = control.space;
        message.msg_controllen = sizeof(control.space);
        control.header.cmsg_level = SOL_SOCKET;
        control.header.cmsg_type = SCM_RIGHTS;
        control.header.cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(&control.header), &listener, sizeof(int));
    }
    /* If this send fails, the parent would block in recvmsg() while this child blocks in
     * sigwait(). Returning -1 makes the child _exit(), which the parent sees as EOF. */
    *installed = listener >= 0;
    if (CHAOS_INIT_SENDMSG(handover, &message, CHAOS_INIT_HANDOVER_FLAGS) !=
        (ssize_t)sizeof(answer))
    {
        return -1;
    }
    /* Traced: stop once, so the parent can set its ptrace options before the application
     * makes its first filtered call. The go signal is blocked and stays pending, so the
     * sigwait() below returns as soon as the parent continues this thread.
     *
     * answer[1], not `tracing`: the stop has to be the one the parent was told about. A
     * library that asks for a tracer (time does, with no rule loaded at all) sets
     * `tracing` before it is known whether the filter can be installed, and on a kernel
     * or in a container that refuses seccomp this child never called PTRACE_TRACEME --
     * stopping then would park the application at a stop nobody continues. */
    if (answer[1] != 0)
    {
        (void)raise(SIGSTOP);
    }
    return 0;
}

/**
 * @brief ENOEXEC fallback of execvp(): runs @p path (a script without `#!`) as
 *        `/bin/sh path args[1]...`.
 *
 * @details Runs in the child after the filter is installed; this second execve() still
 * counts as the application's start (chaos_init_process_decide()) because the image is
 * still chaos-init's. Returns only on failure, with errno from execv(), or ENOEXEC when
 * the argument vector cannot be allocated. @p args is argv from the command on.
 */
static void chaos_init_exec_shell(const char *path, char **args)
{
    size_t count = 0U;
    char **shell;

    while (args[count] != NULL)
    {
        ++count;
    }
    shell = calloc(count + 2U, sizeof(*shell));
    if (shell == NULL)
    {
        errno = ENOEXEC;
        return;
    }
    shell[0] = (char *)"/bin/sh";
    shell[1] = (char *)path;
    if (count > 1U)
    {
        memcpy(shell + 2, args + 1, (count - 1U) * sizeof(*shell));
    }
    (void)execv("/bin/sh", shell);
    free(shell);
}

/**
 * @brief Parent side of the handover: receives the child's errno payload and, on success,
 *        the listener fd.
 *
 * @details MSG_CMSG_CLOEXEC marks the received fd close-on-exec atomically. Only the first
 * control message is inspected; the child sends at most one fd.
 *
 * @param error   Output: the child's errno payload, or 0 when nothing arrived.
 * @param traced  Output: non-zero when the child put itself under this process with
 *                PTRACE_TRACEME and is now stopped, waiting for its ptrace options.
 * @return The listener; -1 when seccomp is unsupported (@p error > 0) or the child ended
 *         before sending (@p error == 0).
 */
static int chaos_init_receive_listener(int socket, int *error, int *traced)
{
    struct msghdr message;
    struct iovec payload;
    struct cmsghdr *header;
    union
    {
        struct cmsghdr header;
        char space[CMSG_SPACE(sizeof(int))];
    } control;
    long answer[3 + CHAOS_INIT_MAX_FILTER] = {0};
    int listener = -1;

    *error = 0;
    *traced = 0;
    memset(&message, 0, sizeof(message));
    payload.iov_base = answer;
    payload.iov_len = sizeof(answer);
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.space;
    message.msg_controllen = sizeof(control.space);
    if (recvmsg(socket, &message, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(answer))
    {
        *error = 0;
        return -1;
    }
    *error = (int)answer[0];
    *traced = (int)answer[1];
    /* The TRACE set the child built the filter from: the deciders ask it before producing
     * a verdict only a trace stop can carry. */
    chaos_init_traced_set(
        &answer[3], (size_t)answer[2] <= (size_t)CHAOS_INIT_MAX_FILTER ? (size_t)answer[2] : 0U
    );
    header = CMSG_FIRSTHDR(&message);
    if (header != NULL && header->cmsg_type == SCM_RIGHTS)
    {
        memcpy(&listener, CMSG_DATA(header), sizeof(int));
    }
    return listener;
}

/**
 * @brief Writes the status file (chaos_status_replace_file(): staged, best effort), creating
 *        /tmp with mode 01777 if missing: `FROM scratch` images have none, and the rule,
 *        status and hits files all live there. chmod() follows mkdir() because the umask
 *        strips mode bits.
 */
static void chaos_init_write_status(unsigned libs, const char *reason, int mptcp_off)
{
    char text[CHAOS_STATUS_BUFFER_SIZE];
    const size_t length = chaos_init_format_status(
        text,
        sizeof(text),
        libs,
        reason,
        (long)getpid(),
        mptcp_off,
        g_chaos_init_vdso_failed,
        chaos_init_unreadable()
    );

    if (mkdir("/tmp", 01777) == 0)
    {
        (void)chmod("/tmp", 01777);
    }
    chaos_status_replace_file(CHAOS_INIT_STATUS_PATH, text, length);
}

/**
 * @brief ioctl() as a raw system call: musl declares the request parameter as int, and the
 *        SECCOMP_IOCTL_* numbers (_IOWR with bit 31 set) do not fit without
 *        implementation-defined conversion. @return The syscall result; errno on -1.
 */
static long chaos_init_ioctl(int fd, unsigned long request, void *argument)
{
    return syscall(SYS_ioctl, fd, request, argument);
}

/**
 * @brief CLOCK_MONOTONIC in milliseconds, truncated. The supervisor itself is under no
 *        filter and no time rule, so the libc clock is the real one.
 */
static uint64_t chaos_init_now_ms(void)
{
    struct timespec now;

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

/**
 * @brief Sends the reply to notification @p id: FAIL as `error = -errno`, RETURN as `val`,
 *        anything else (PASS) as SECCOMP_USER_NOTIF_FLAG_CONTINUE.
 *
 * @details CONTINUE makes the kernel run the call with whatever its arguments point to at
 * that moment, not what the decider read: acceptable for fault injection, which is why
 * the kernel documents CONTINUE as unsuitable for security policy. DELAY never reaches
 * this function; it is converted by chaos_init_delay_answer() first.
 *
 * @param response  Buffer of @p size bytes (the kernel's seccomp_notif_resp size).
 */
static void chaos_init_reply(
    int listener, uint64_t id, const chaos_init_verdict_t *verdict, void *response, size_t size
)
{
    struct seccomp_notif_resp *reply = response;

    memset(reply, 0, size);
    reply->id = id;
    if (verdict->action == CHAOS_INIT_FAIL)
    {
        reply->error = -verdict->error;
    }
    else if (verdict->action == CHAOS_INIT_RETURN)
    {
        reply->val = verdict->value;
    }
    else
    {
        reply->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }
    /* Errors ignored: ENOENT means the thread was killed while waiting (or, pre-5.19, a
     * signal withdrew the notification); there is nobody left to answer. */
    (void)chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, reply);
}

/**
 * @brief Runs the deciders of @p libs over @p call and leaves their verdict in @p verdict.
 *
 * @details The libraries' system calls are disjoint except read, readv, write, writev and
 * close: net claims them on sockets, io decides them on anything else. The first decider
 * that recognises the call owns it, even when its verdict is PASS.
 *
 * Shared by the two paths a call can arrive on, so a traced call is decided by exactly the
 * same rules, qualifiers and hit slots as a notified one.
 */
static void
chaos_init_decide(unsigned libs, const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    memset(verdict, 0, sizeof(*verdict));
    verdict->action = CHAOS_INIT_PASS;
    /* dns first: the send that carries a query is net's call as well, and the name in it
     * is the narrower match. A send that is no query falls through to net. */
    if (!((libs & CHAOS_INIT_LIB_DNS) != 0U && chaos_init_dns_decide(call, verdict)) &&
        !((libs & CHAOS_INIT_LIB_NET) != 0U && chaos_init_net_decide(call, verdict)) &&
        !((libs & CHAOS_INIT_LIB_IO) != 0U && chaos_init_io_decide(call, verdict)) &&
        !((libs & CHAOS_INIT_LIB_MEMORY) != 0U && chaos_init_memory_decide(call, verdict)) &&
        !((libs & CHAOS_INIT_LIB_TIME) != 0U && chaos_init_time_decide(call, verdict)) &&
        (libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        (void)chaos_init_process_decide(call, verdict);
    }
    /* A decision that could not look into the process matched no path and no endpoint,
     * which is a rule looking applied and doing nothing. Said once, in the file a test
     * reads, with the cure in the documentation: --cap-add SYS_PTRACE. */
    if (chaos_init_unreadable() && g_chaos_init_said_unreadable == 0)
    {
        g_chaos_init_said_unreadable = 1;
        chaos_init_write_status(libs, NULL, g_chaos_init_mptcp_off);
    }
}

/**
 * @brief Applies @p verdict to tracee @p tid, stopped at a seccomp stop, and continues it.
 *
 * @details The verdict kinds a notification answers with a reply are answered here through
 * the registers instead: FAIL and RETURN skip the call and hand back the value, SHORTEN
 * replaces the argument that carries the byte count, PASS runs the call untouched. A
 * tracee that died meanwhile is simply continued -- the ptrace calls fail and there is
 * nobody left to answer.
 */
static void chaos_init_trace_answer(pid_t tid, const chaos_init_verdict_t *verdict)
{
    chaos_init_trace_regs_t regs;

    if (verdict->action != CHAOS_INIT_PASS && chaos_init_trace_read(tid, &regs) == 0)
    {
        if (verdict->action == CHAOS_INIT_FAIL)
        {
            (void)chaos_init_trace_skip(tid, &regs, -verdict->error);
        }
        else if (verdict->action == CHAOS_INIT_RETURN)
        {
            (void)chaos_init_trace_skip(tid, &regs, verdict->value);
        }
        else if (verdict->action == CHAOS_INIT_SHORTEN)
        {
            chaos_init_trace_set_arg(&regs, verdict->arg_index, (uint64_t)verdict->value);
            (void)chaos_init_trace_write(tid, &regs);
        }
    }
    (void)ptrace(PTRACE_CONT, tid, 0, 0);
}

/**
 * @brief Sets @p tid up to run the call @p verdict asks for, data and all.
 *
 * @details The argument the call needs in memory goes into the tracee's stack scratch,
 * which is dead space for the duration: nothing of the tracee runs between this stop and
 * the substituted call.
 *
 * @return 0 when the thread is ready to be continued into that call; -1 otherwise.
 */
static int chaos_init_trace_substitute(
    pid_t tid, chaos_init_trace_regs_t *regs, const chaos_init_verdict_t *verdict
)
{
    uint64_t args[CHAOS_INIT_TRACE_ARGS];
    unsigned index;

    for (index = 0U; index < CHAOS_INIT_TRACE_ARGS; ++index)
    {
        args[index] = verdict->instead_args[index];
    }
    if (verdict->instead_size > 0U)
    {
        const uint64_t scratch = chaos_init_trace_scratch(regs);

        if (scratch == 0U ||
            chaos_init_write_memory(tid, scratch, verdict->instead_data, verdict->instead_size) !=
                0)
        {
            return -1;
        }
        args[verdict->instead_arg] = scratch;
    }
    return chaos_init_trace_instead(tid, regs, verdict->instead_nr, args);
}

/**
 * @brief Handles one ptrace stop of @p tid reported by @p status.
 *
 * @details Four kinds arrive here. A syscall-exit stop belongs to a call whose entry stop
 * answered CHAOS_INIT_AFTER; it is told apart by PTRACE_O_TRACESYSGOOD and asks the
 * deciders again with the call's result. A seccomp stop is a call the filter answered with
 * TRACE: its arguments are read out of the registers, the deciders see the same
 * chaos_init_call_t a notification would produce, and the verdict is applied to the
 * registers. A new descendant appears in a stop of its own, and a fork or clone stops its
 * parent; both are continued, the descendant already carrying the tracer and the options
 * (PTRACE_O_TRACEFORK and friends inherit them). Anything else is a signal the application
 * was about to receive, which is delivered rather than swallowed.
 */
static void chaos_init_trace_stop(unsigned libs, pid_t tid, int status)
{
    chaos_init_trace_regs_t regs;
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;
    unsigned index;

    /* The exit stop of a call whose entry stop asked for it. The call comes from the
     * parking table rather than from the registers, because the result overwrites the
     * first argument on aarch64; only the result itself is read here. */
    if (chaos_init_trace_is_syscall_stop(status))
    {
        long promised = 0;

        /* The exit stop of a call the supervisor put there itself: what that call returned
         * is none of the tracee's business, which is told the value the call it asked for
         * would have reported -- or, for a call that only had to run first, gets its own
         * call back and runs it. */
        if (chaos_init_trace_claim(tid, &promised))
        {
            if (chaos_init_trace_read(tid, &regs) == 0)
            {
                if (promised == CHAOS_INIT_TRACE_AGAIN)
                {
                    if (chaos_init_trace_unpark(tid, &call))
                    {
                        (void)chaos_init_trace_resume(tid, &regs, call.nr, call.args);
                    }
                }
                else
                {
                    (void)chaos_init_trace_set_result(tid, &regs, promised);
                }
            }
            (void)ptrace(PTRACE_CONT, tid, 0, 0);
            return;
        }
        if (chaos_init_trace_unpark(tid, &call) && chaos_init_trace_read(tid, &regs) == 0)
        {
            const long result = chaos_init_trace_result(&regs);
            int claimed = 0;

            /* The owner is the decider that claimed the call at the entry stop, found the
             * same way: net takes read and write on a socket, io everything else. */
            if ((libs & CHAOS_INIT_LIB_NET) != 0U)
            {
                claimed = chaos_init_net_decide_result(&call, result);
            }
            if (!claimed && (libs & CHAOS_INIT_LIB_IO) != 0U)
            {
                (void)chaos_init_io_decide_result(&call, result);
            }
        }
        (void)ptrace(PTRACE_CONT, tid, 0, 0);
        return;
    }
    /* A new image: its vDSO is fresh, and nothing in it has looked up a time symbol yet.
     * This is the only moment the lookups can be made to fail, so a clock read reaches
     * the filter at all. A process that cannot be written keeps its vDSO and reads the
     * clock without anybody seeing it, which the status file says. */
    if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
    {
        if ((libs & CHAOS_INIT_LIB_TIME) != 0U && chaos_init_vdso_blind(tid) < 0 &&
            g_chaos_init_vdso_failed == 0)
        {
            /* Said once, in the file a test reads: this image reads the clock where
             * nothing can see it, so its time rules do nothing. */
            g_chaos_init_vdso_failed = 1;
            chaos_init_write_status(libs, NULL, g_chaos_init_mptcp_off);
        }
        (void)ptrace(PTRACE_CONT, tid, 0, 0);
        return;
    }
    if ((status >> 8) != (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8)))
    {
        const int stopped = WSTOPSIG(status);
        /* An event stop and a syscall stop carry SIGTRAP and must not have it
         * re-delivered. A real signal must be, or the application would never see its own
         * SIGTERM, SIGCHLD or SIGPIPE.
         *
         * The stop signals are the exception, and the reason is the whole point of this
         * branch: without PTRACE_SEIZE the kernel reports a group-stop *and* the first
         * stop of a newly attached descendant as a signal-delivery-stop of SIGSTOP, which
         * cannot be told apart from a real one. Re-delivering it put every `fork` and
         * `clone` of the application into a job-control stop before it had run an
         * instruction -- its real parent then saw a stop notification through
         * waitpid(WUNTRACED), and for a thread it stopped the whole group. A forking
         * server broke. The cost of swallowing it instead is that a traced application
         * cannot be suspended with Ctrl-Z or `kill -STOP` while chaos-init traces it,
         * which is a limitation of the mode rather than a fault injected into the
         * application. The earlier comment had this backwards: a group-stop never carries
         * SIGTRAP. */
        const int signal = (stopped == SIGTRAP || stopped == SIGSTOP || stopped == SIGTSTP ||
                            stopped == SIGTTIN || stopped == SIGTTOU)
                               ? 0
                               : stopped;

        (void)ptrace(PTRACE_CONT, tid, 0, (void *)(long)signal);
        return;
    }
    /* A call the supervisor put back after running another one first: already decided, so
     * deciding it again would count a second hit and put it back for ever. */
    if (chaos_init_trace_passing(tid) || chaos_init_trace_read(tid, &regs) != 0)
    {
        (void)ptrace(PTRACE_CONT, tid, 0, 0);
        return;
    }
    memset(&call, 0, sizeof(call));
    call.tid = tid;
    call.nr = (int)chaos_init_trace_number(&regs);
    for (index = 0U; index < CHAOS_INIT_TRACE_ARGS; ++index)
    {
        call.args[index] = chaos_init_trace_arg(&regs, index);
    }
    chaos_init_decide(libs, &call, &verdict);
    /* The effect depends on what the call returns, so it runs and stops again. The call is
     * parked because the exit stop cannot read it back: on aarch64 the result arrives in
     * the register that held the first argument. A table too full to park it runs the call
     * without the effect rather than acting on the wrong descriptor. */
    if (verdict.action == CHAOS_INIT_AFTER && chaos_init_trace_park(&call) == 0)
    {
        (void)ptrace(PTRACE_SYSCALL, tid, 0, 0);
        return;
    }
    /* Another call in its place, or before it. Everything the second stop needs is
     * reserved first -- the promise, and for BEFORE the parked call and the mark that lets
     * the call through when it comes back -- so that a table too full to hold one of them
     * leaves the call unchanged instead of losing it. */
    if (verdict.action == CHAOS_INIT_INSTEAD || verdict.action == CHAOS_INIT_BEFORE)
    {
        const int before = verdict.action == CHAOS_INIT_BEFORE;
        const long promise = before ? CHAOS_INIT_TRACE_AGAIN : verdict.value;

        if (chaos_init_trace_promise(tid, promise) == 0 &&
            (!before || (chaos_init_trace_park(&call) == 0 && chaos_init_trace_pass(tid) == 0)) &&
            chaos_init_trace_substitute(tid, &regs, &verdict) == 0)
        {
            (void)ptrace(PTRACE_SYSCALL, tid, 0, 0);
            return;
        }
        {
            long dropped = 0;
            chaos_init_call_t gone;

            (void)chaos_init_trace_claim(tid, &dropped);
            (void)chaos_init_trace_passing(tid);
            (void)chaos_init_trace_unpark(tid, &gone);
        }
        verdict.action = CHAOS_INIT_PASS;
    }
    if (verdict.action == CHAOS_INIT_DELAY)
    {
        const chaos_init_verdict_t answer = chaos_init_delay_answer(&verdict);

        /* Parked by tid: a thread is in one system call at a time, so that identifies it
         * as a notification id does. It stays stopped until the timer wakes it. */
        if (chaos_init_delay_add(
                (uint64_t)tid, &call, chaos_init_now_ms() + verdict.delay_ms + 1U, &answer, 1
            ) == 0)
        {
            return;
        }
        verdict = answer;
    }
    chaos_init_trace_answer(tid, &verdict);
}

/**
 * @brief Receives one notification, decides it and answers it now or parks it (DELAY).
 *
 * @details Order of operations, each step required by the next:
 * 1. NOTIF_RECV into a zeroed buffer (the kernel requires zeroed input).
 * 2. Re-bind a restarted parked call (pre-5.19), which must not be decided twice.
 * 3. Decide: net first (it claims read/write/close on sockets), then io, memory, process.
 *    Deciders read tracee memory and /proc by tid.
 * 4. NOTIF_ID_VALID, only for non-PASS verdicts: the tid in the notification may have died
 *    and been reused between RECV and the reads, so the decision may describe another
 *    process. ENOENT drops the notification; any other error answers anyway
 *    (chaos_init_caller_gone()). A PASS needs no check: CONTINUE by id cannot misfire.
 * 5. Commit deferred tracee writes (chaos_init_net_commit()), only now that the thread is
 *    known to be the one waiting.
 * 6. Reply, or park until due.
 *
 * Hit counting happens during step 3, so a verdict dropped in step 4 has still been
 * counted for whichever process the reads resolved to.
 */
static void
chaos_init_answer(int listener, unsigned libs, void *request, void *response, size_t response_size)
{
    struct seccomp_notif *notification = request;
    chaos_init_verdict_t verdict;
    chaos_init_call_t call;
    size_t index;

    memset(notification, 0, CHAOS_INIT_NOTIF_BUFFER);
    if (chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification) != 0)
    {
        return; /* EINTR, or the caller died before RECV (ENOENT): nothing to answer */
    }
    call.tid = (pid_t)notification->pid;
    call.nr = notification->data.nr;
    for (index = 0U; index < 6U; ++index)
    {
        call.args[index] = notification->data.args[index];
    }
    /* A parked call that a signal interrupted and the kernel restarted (pre-5.19): it
     * keeps its due time and answer and is neither decided nor counted again. */
    if (chaos_init_delay_resume(&call, notification->id))
    {
        return;
    }
    chaos_init_decide(libs, &call, &verdict);
    /* The decision read memory and /proc by tid: act on it only if that notification is
     * still pending, i.e. the tid still names the waiting thread and not a reused pid. A
     * PASS is checked too when the verdict writes the tracee's memory (REDIRECT): the
     * reply cannot misfire, but the write would. */
    if ((verdict.action != CHAOS_INIT_PASS || verdict.redirect_size > 0U) &&
        chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &notification->id) != 0 &&
        chaos_init_caller_gone(errno))
    {
        return;
    }
    chaos_init_net_commit(&call, &verdict);
    /* Not a delayed clock read: that one is committed by chaos_init_on_time() when it is
     * due, which is the whole point -- a clock read reports the moment it is answered.
     * Committing here as well applied the value effect twice, with two independent draws:
     * two hits for one read, `@every` and `@first` spent at twice the rate, and with a
     * probability below 1 the two draws disagreeing about what the caller finally gets. */
    if (verdict.action != CHAOS_INIT_DELAY)
    {
        chaos_init_time_commit(&call, &verdict);
    }
    if (verdict.action == CHAOS_INIT_DELAY)
    {
        const chaos_init_verdict_t answer = chaos_init_delay_answer(&verdict);

        /* now_ms truncates, so "now" may be up to 1 ms late; +1 ms guarantees the call is
         * held at least delay_ms (at the cost of up to 1 ms extra). */
        if (chaos_init_delay_add(
                notification->id, &call, chaos_init_now_ms() + verdict.delay_ms + 1U, &answer, 0
            ) == 0)
        {
            return;
        }
        /* Queue full (CHAOS_INIT_MAX_DELAYED): drop the delay, apply the rest now. */
        verdict = answer;
    }
    chaos_init_reply(listener, notification->id, &verdict, response, response_size);
}

/**
 * @brief Answers every parked call that is due, writes hits files that waited for
 *        CHAOS_HITS_INTERVAL_MS, and re-arms @p timer for the earlier of the next due call
 *        and the next flush.
 *
 * @details Called after every loop iteration while a listener exists, not only on timer
 * expiry, so a call parked in this iteration is reflected in the timer at once. The timer
 * is absolute CLOCK_MONOTONIC; a zero itimerspec disarms it when nothing is pending.
 */
static void chaos_init_on_time(int timer, int listener, void *response, size_t response_size)
{
    static uint64_t last_flush_ms = 0U;
    const uint64_t now = chaos_init_now_ms();
    struct itimerspec next;
    uint64_t due = 0U;
    uint64_t id;
    int due_traced = 0;

    chaos_init_call_t due_call;
    chaos_init_verdict_t due_verdict;

    while (chaos_init_delay_pop(now, &id, &due_call, &due_verdict, &due_traced))
    {
        /* A clock read reports the time of the moment it is answered, so the value is
         * read and written here rather than when the call was parked. */
        chaos_init_time_commit(&due_call, &due_verdict);
        if (due_traced)
        {
            chaos_init_trace_answer((pid_t)id, &due_verdict);
        }
        else
        {
            chaos_init_reply(listener, id, &due_verdict, response, response_size);
        }
    }
    if (chaos_init_tracee_pending() && now - last_flush_ms >= CHAOS_HITS_INTERVAL_MS)
    {
        chaos_init_tracee_flush(0);
        last_flush_ms = now;
    }
    (void)chaos_init_delay_next(&due);
    if (chaos_init_tracee_pending() && (due == 0U || last_flush_ms + CHAOS_HITS_INTERVAL_MS < due))
    {
        due = last_flush_ms + CHAOS_HITS_INTERVAL_MS;
    }
    memset(&next, 0, sizeof(next));
    if (due != 0U)
    {
        /* A past absolute time fires at once, but exactly 0 would disarm: clamp to now + 1. */
        due = due > now ? due : now + 1U;
        next.it_value.tv_sec = (time_t)(due / 1000U);
        next.it_value.tv_nsec = (long)(due % 1000U) * 1000000L;
    }
    (void)timerfd_settime(timer, TFD_TIMER_ABSTIME, &next, NULL);
}

/**
 * @brief Reaps every exited child, the application and adopted orphans alike, and hands
 *        every ptrace stop to chaos_init_trace_stop(), with waitpid(-1, WNOHANG) until
 *        none is left (one SIGCHLD may stand for several events).
 *
 * @details While the application is traced, the same SIGCHLD reports exits and stops, and
 * a stop is not an exit: treating one as an exit would report the application as finished
 * at its first traced system call. Nothing stops unless the filter has a traced group,
 * so a run without data effects takes the same path it always did.
 *
 * @param child_status  Output: the application's wait status, set only when it was reaped.
 * @return 1 when @p child was among those reaped, else 0.
 */
static int chaos_init_reap(unsigned libs, pid_t child, int *child_status)
{
    int found = 0;

    for (;;)
    {
        int status;
        const pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid <= 0)
        {
            return found;
        }
        if (WIFSTOPPED(status))
        {
            chaos_init_trace_stop(libs, pid, status);
            continue;
        }
        /* Whatever this thread still held in the trace tables goes with it: a thread
         * killed on the way to the exit stop of a traced call never reaches the stop that
         * would have taken its entry. */
        chaos_init_trace_forget(pid);
        if (pid == child)
        {
            *child_status = status;
            found = 1;
        }
    }
}

/**
 * @brief Directory the rule files live in: every one of them is `/tmp/.chaos-<lib>.conf`,
 *        a documented path, so one watch covers all six.
 */
#define CHAOS_INIT_RULE_DIR "/tmp"

/**
 * @brief Whether @p name is a rule file of one of the libraries.
 *
 * @details `.chaos-<lib>.conf`, matched by its ends. This is a cost measure, not a
 * correctness one: a reload the rule files did not need stats them and returns, so
 * answering every event would be right and wasteful. The watched directory is `/tmp`,
 * where every program in the container puts its temporary files, and the libraries their
 * own status and hits files -- waking the supervisor and stat'ing six files for each of
 * those is what this avoids.
 */
static int chaos_init_rule_file(const char *name)
{
    const size_t length = strlen(name);

    return length > sizeof(".chaos-.conf") - 1U && strncmp(name, ".chaos-", 7U) == 0 &&
           strcmp(name + length - (sizeof(".conf") - 1U), ".conf") == 0;
}

/**
 * @brief Re-reads the rule files of @p libs, as the first decision of a call would.
 *
 * @details Publishing a rule file also writes that library's status file, which is the
 * point of doing it without a call: a rule file nobody has called into yet is reported
 * all the same.
 */
static void chaos_init_reload(unsigned libs)
{
    if ((libs & CHAOS_INIT_LIB_IO) != 0U)
    {
        chaos_init_io_reload();
    }
    if ((libs & CHAOS_INIT_LIB_NET) != 0U)
    {
        chaos_init_net_reload();
    }
    if ((libs & CHAOS_INIT_LIB_DNS) != 0U)
    {
        chaos_init_dns_reload();
    }
    if ((libs & CHAOS_INIT_LIB_TIME) != 0U)
    {
        chaos_init_time_reload();
    }
    if ((libs & CHAOS_INIT_LIB_MEMORY) != 0U)
    {
        chaos_init_memory_reload();
    }
    if ((libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        chaos_init_process_reload();
    }
}

/**
 * @brief Reads the pending watch events and reloads the rule files when one of them names
 *        a rule file.
 *
 * @details One reload for the whole batch, and of every library rather than the one named:
 * a prepare whose file did not change stats it and returns, which is cheaper than keeping
 * a name per library here. Events the kernel could not queue are dropped by it
 * (IN_Q_OVERFLOW); the next change, or the next intercepted call, is seen anyway.
 *
 * One read per call, not a drain: a directory as busy as `/tmp` can deliver events as
 * fast as they are read, and a loop here would hold the serve loop away from the
 * notifications it exists for. What is left queued makes the next poll() return at once.
 */
static void chaos_init_watched(int watcher, unsigned libs)
{
    union
    {
        struct inotify_event event; /* the alignment read(2) requires of the buffer */
        char bytes[4096];
    } buffer;
    const ssize_t got = read(watcher, buffer.bytes, sizeof(buffer.bytes));
    size_t offset = 0U;
    int reload = 0;

    while (got > 0 && offset + sizeof(struct inotify_event) <= (size_t)got)
    {
        const struct inotify_event *event =
            (const struct inotify_event *)(const void *)(buffer.bytes + offset);

        if (event->len > 0U && chaos_init_rule_file(event->name))
        {
            reload = 1;
        }
        offset += sizeof(struct inotify_event) + event->len;
    }
    if (reload)
    {
        chaos_init_reload(libs);
    }
}

/**
 * @brief After the application exited: forks a background copy that keeps answering the
 *        processes it left behind (daemons, double forks), when one is needed.
 *
 * @details Leftover processes keep the filter. Once the last listener fd closes, the
 * kernel fails each of their filtered calls with ENOSYS. As PID 1 no copy is needed: PID
 * 1's exit kills every process in its pid namespace. Otherwise the caller exits with the
 * application's code at once (callers see the usual exit), and the copy serves the
 * listener until the kernel reports POLLHUP, meaning no process uses the filter any more
 * (Linux 5.8+; on 5.5-5.7 the copy idles until the container stops). Its stdin, stdout
 * and stderr are redirected to /dev/null so a caller reading chaos-init's output sees EOF.
 *
 * The copy is not the leftovers' ancestor: under Yama `ptrace_scope=1` it cannot read
 * their memory, so their path and endpoint selectors stop matching. If fork() fails, no
 * copy exists and the leftovers get ENOSYS.
 *
 * @return 1 in the background copy, 0 in the process that is to exit (no listener, PID 1,
 *         fork() failed, or the parent side of the fork).
 */
static int chaos_init_serve_the_rest(int listener)
{
    int null_fd;

    if (listener < 0 || getpid() == 1 || fork() != 0)
    {
        return 0;
    }
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0)
    {
        (void)dup2(null_fd, STDIN_FILENO);
        (void)dup2(null_fd, STDOUT_FILENO);
        (void)dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO)
        {
            (void)close(null_fd);
        }
    }
    return 1;
}

/**
 * @brief Entry point; see the file header for the process model. The notification buffers
 *        are unsigned long arrays so they carry the alignment of the kernel structures
 *        they are cast to.
 */
#ifdef CHAOS_INIT_NO_MAIN
/* A unit test includes this file to reach the decision helpers above -- the reply it sends
 * for each verdict, the rule-file name filter, the inotify drain -- and brings its own
 * main(). Everything below needs a container, a filter and a tracee, which is what the
 * seccomp suite provides; the coverage gate records the share this leaves uncovered rather
 * than leaving the file unmeasured, which is how five defects in here stayed invisible. */
#else
int main(int argc, char **argv)
{
    static unsigned long request[CHAOS_INIT_NOTIF_BUFFER / sizeof(unsigned long)];
    static unsigned long response[CHAOS_INIT_NOTIF_BUFFER / sizeof(unsigned long)];
    chaos_init_options_t options;
    struct seccomp_notif_sizes sizes;
    sigset_t forwarded;
    sigset_t original;
    int pair[2];
    int listener;
    int error;
    int signals;
    int timer;
    int watcher = -1;
    int child_status = 0;
    int serving_the_rest = 0;
    int found;
    int mptcp_off;
    static char command_path[4096];
    pid_t child;

    memset(&sizes, 0, sizeof(sizes));
    if (chaos_init_parse_args(argc, argv, &options) != 0)
    {
        (void)fprintf(
            stderr,
            "usage: %s --libs io,net,dns,time,memory,process -- <command> [args...]\n",
            argv[0]
        );
        return CHAOS_INIT_EXIT_USAGE;
    }

    /* Outside PID 1, orphans of the application reparent here and are reaped here. A
     * failure (pre-3.4 kernel) is harmless: such kernels fail the version check anyway. */
    (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    /* Blocked before the fork: signals arriving while the child starts stay pending for
     * the signalfd, and the child inherits the block so the go signal cannot be lost. The
     * child restores the original mask right before exec. SOCK_CLOEXEC keeps the handover
     * socket out of the application. */
    chaos_init_signal_set(&forwarded);
    if (sigprocmask(SIG_BLOCK, &forwarded, &original) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
    {
        perror("chaos-init");
        return CHAOS_INIT_EXIT_HANDOVER;
    }

    /* Resolved before the fork, unfiltered: execvp() in the child would issue one execve()
     * per PATH entry, and only the start of the application is exempt from process rules. */
    found = chaos_init_find_command(
        argv[options.command], getenv("PATH"), command_path, sizeof(command_path)
    );
    /* Probed in the parent, before any filter: where the kernel offers MPTCP, Go 1.24+ is
     * told to use plain TCP, because its MPTCP connections from plain TCP clients cannot be
     * resolved and net rules on them could never match. */
    mptcp_off = (options.libs & CHAOS_INIT_LIB_NET) != 0U && chaos_init_net_mptcp_unresolvable();
    child = fork();
    if (child < 0)
    {
        perror("chaos-init: fork");
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    if (child == 0)
    {
        sigset_t go;
        int received;
        int installed = 0;

        (void)close(pair[0]);
        (void)sigemptyset(&go);
        (void)sigaddset(&go, CHAOS_INIT_GO_SIGNAL);
        /* The go signal is inherited blocked (it is in the forwarded set), so one that
         * arrives before sigwait() stays pending. The handover uses pair[1] at whatever
         * number it got: dup2() to a fixed number would fail under a low RLIMIT_NOFILE and
         * could clobber a descriptor the application inherits. From here on the filter may
         * be installed: everything up to the exec runs under it, and the parent answers
         * only after the go signal. */
        if (chaos_init_install_and_hand_over(options.libs, pair[1], &installed) != 0 ||
            sigwait(&go, &received) != 0 || sigprocmask(SIG_SETMASK, &original, NULL) != 0)
        {
            _exit(CHAOS_INIT_EXIT_HANDOVER);
        }
        /* Only with chaos active: without a filter there are no net rules to serve. */
        if (mptcp_off && installed)
        {
            static char godebug[1024];

            if (chaos_init_godebug_mptcp_off(getenv("GODEBUG"), godebug, sizeof(godebug)))
            {
                (void)setenv("GODEBUG", godebug, 1);
            }
        }
        if (found > 0)
        {
            (void)execv(command_path, argv + options.command);
            if (errno == ENOEXEC)
            {
                chaos_init_exec_shell(command_path, argv + options.command);
            }
        }
        else
        {
            errno = found < 0 ? EACCES : ENOENT;
        }
        /* Exit codes as a shell reports them: 127 not found, 126 anything else. */
        error = errno;
        (void)fprintf(stderr, "chaos-init: %s: %s\n", argv[options.command], strerror(error));
        _exit(error == ENOENT ? CHAOS_INIT_EXIT_NOT_FOUND : CHAOS_INIT_EXIT_NOT_EXECUTABLE);
    }
    /* Closing our copy of the child's end makes recvmsg() see EOF if the child dies. */
    (void)close(pair[1]);

    listener = chaos_init_receive_listener(pair[0], &error, &g_chaos_init_tracing);
    (void)close(pair[0]);
    /* The child is stopped in the SIGSTOP it raised after the handover. Its options are
     * set here, before it can make a filtered call: TRACESECCOMP turns a RET_TRACE into a
     * stop, and the three descendant options matter just as much -- the filter survives
     * fork and exec, and a RET_TRACE with no tracer fails the call with ENOSYS, so every
     * descendant has to be attached as it appears. */
    if (g_chaos_init_tracing)
    {
        int stop_status = 0;
        if (waitpid(child, &stop_status, 0) != child || !WIFSTOPPED(stop_status) ||
            ptrace(
                PTRACE_SETOPTIONS,
                child,
                0,
                (void *)(long)(PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                               PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC)
            ) != 0)
        {
            (void)kill(child, SIGKILL);
            (void)waitpid(child, &child_status, 0);
            (void)fprintf(stderr, "chaos-init: cannot trace the application\n");
            return CHAOS_INIT_EXIT_HANDOVER;
        }
    }
    if (listener >= 0 && (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0 ||
                          sizes.seccomp_notif > CHAOS_INIT_NOTIF_BUFFER ||
                          sizes.seccomp_notif_resp > CHAOS_INIT_NOTIF_BUFFER))
    {
        /* NOTIF_RECV would overrun our buffers. The child has a filter but waits for go;
         * left alive, its first filtered call would block for good. */
        (void)kill(child, SIGKILL);
        (void)fprintf(stderr, "chaos-init: cannot read seccomp notifications\n");
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    /* EOF without payload: the child failed before or during the handover (and may have
     * installed a filter). Nothing to supervise; reap it and fail. */
    if (listener < 0 && error == 0)
    {
        (void)waitpid(child, &child_status, 0);
        (void)fprintf(stderr, "chaos-init: the child ended before the filter was set up\n");
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    /* Rule cores start before the go signal, so the first notification finds them ready.
     * Without a listener they stay untouched (the libraries' status files are not written). */
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_IO) != 0U)
    {
        chaos_init_io_start();
    }
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_NET) != 0U)
    {
        chaos_init_net_start();
    }
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_MEMORY) != 0U)
    {
        chaos_init_memory_start();
    }
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_DNS) != 0U)
    {
        chaos_init_dns_start();
    }
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_TIME) != 0U)
    {
        chaos_init_time_start();
    }
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        chaos_init_process_start(child);
    }
    g_chaos_init_mptcp_off = mptcp_off && listener >= 0;
    chaos_init_write_status(
        options.libs,
        listener >= 0 ? NULL : chaos_init_unsupported_reason(error),
        g_chaos_init_mptcp_off
    );
    /* Status first, then go: whoever sees the application run reads this run's status. */
    (void)kill(child, CHAOS_INIT_GO_SIGNAL);
    /* The go signal is blocked and stays pending, so continuing the stopped child lets its
     * sigwait() take it. Signal 0: the SIGSTOP it raised is swallowed rather than delivered
     * again. */
    if (g_chaos_init_tracing)
    {
        (void)ptrace(PTRACE_CONT, child, 0, 0);
    }

    /* Created after go; signals that arrived meanwhile are still pending (blocked) and
     * are read from the signalfd on the first iteration. */
    signals = signalfd(-1, &forwarded, SFD_CLOEXEC);
    timer = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (signals < 0 || timer < 0)
    {
        perror("chaos-init: signalfd/timerfd");
        (void)kill(child, SIGKILL);
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    /* A replaced rule file is read when it is replaced, not only when the next intercepted
     * call arrives: that call may be seconds away, or may never come in a container that
     * is waiting for the rules to be in place, and the status file a test reads to see
     * them accepted is written by the reload. The watch is on the directory because the
     * file is delivered by rename (`mv -f`), which a watch on the file itself never sees.
     * Without rules to apply (no listener) there is nothing to reload, and a watch that
     * cannot be created costs nothing: every rule file is still read by the next call. */
    if (listener >= 0)
    {
        watcher = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (watcher >= 0 &&
            inotify_add_watch(
                watcher, CHAOS_INIT_RULE_DIR, IN_MOVED_TO | IN_CLOSE_WRITE | IN_DELETE
            ) < 0)
        {
            (void)close(watcher);
            watcher = -1;
        }
    }
    for (;;)
    {
        struct pollfd watched[4];
        nfds_t count = 2;
        /* Which slot the watch got, or 0 when there is none: the slots after the timer
         * depend on what exists, and a count alone has been a trap here before. */
        nfds_t watch_slot = 0;

        watched[0].fd = signals;
        watched[0].events = POLLIN;
        watched[1].fd = timer;
        watched[1].events = POLLIN;
        if (listener >= 0)
        {
            watched[2].fd = listener;
            watched[2].events = POLLIN;
            count = 3;
        }
        if (watcher >= 0)
        {
            watch_slot = count;
            watched[count].fd = watcher;
            watched[count].events = POLLIN;
            ++count;
        }
        if (poll(watched, count, -1) < 0)
        {
            continue; /* EINTR */
        }
        if ((watched[0].revents & POLLIN) != 0)
        {
            struct signalfd_siginfo info;

            if (read(signals, &info, sizeof(info)) == (ssize_t)sizeof(info))
            {
                if (serving_the_rest)
                {
                    /* Background copy: the application is gone and this copy has no
                     * children; signals are drained and ignored. */
                }
                else if (info.ssi_signo != SIGCHLD)
                {
                    (void)kill(child, (int)info.ssi_signo);
                }
                else if (chaos_init_reap(options.libs, child, &child_status))
                {
                    /* Every process's hits are on disk before the exit code is reported. */
                    chaos_init_tracee_flush(1);
                    if (!chaos_init_serve_the_rest(listener))
                    {
                        return chaos_init_exit_code(child_status);
                    }
                    serving_the_rest = 1;
                }
            }
        }
        if ((watched[1].revents & POLLIN) != 0)
        {
            uint64_t expirations;

            /* Drains the expiry count so poll() stops reporting it; the due work runs in
             * chaos_init_on_time() below, which re-arms the timer. */
            if (read(timer, &expirations, sizeof(expirations)) < 0)
            {
                expirations = 0U;
            }
        }
        /* One notification per iteration keeps signals and due delays from starving
         * under a notification storm. POLLIN wins over POLLHUP; a hang-up is seen on a
         * later iteration once nothing is left to receive. */
        if (listener >= 0 && (watched[2].revents & POLLIN) != 0)
        {
            chaos_init_answer(listener, options.libs, request, response, sizes.seccomp_notif_resp);
        }
        else if (listener >= 0 && (watched[2].revents & (POLLHUP | POLLERR)) != 0)
        {
            /* No process uses the filter any more (Linux 5.8+). Parked calls died with
             * their threads. The main process keeps running until SIGCHLD reports the
             * application; the background copy is done. */
            (void)close(listener);
            listener = -1;
            if (serving_the_rest)
            {
                chaos_init_tracee_flush(1);
                return 0;
            }
        }
        if (watch_slot != 0 && (watched[watch_slot].revents & POLLIN) != 0)
        {
            chaos_init_watched(watcher, options.libs);
        }
        if (listener >= 0)
        {
            chaos_init_on_time(timer, listener, response, sizes.seccomp_notif_resp);
        }
    }
}
#endif
