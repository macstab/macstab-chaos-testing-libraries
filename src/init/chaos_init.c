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
#include "chaos_init_io.h"
#include "chaos_init_memory.h"
#include "chaos_init_net.h"
#include "chaos_init_process.h"
#include "chaos_init_tracee.h"
#include "chaos_status.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h> /* _IOWR for the SECCOMP_IOCTL_* numbers */
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
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
    int error = 0;
    int listener = -1;

    program.len =
        (unsigned short)chaos_init_build_filter(libs, handover, filter, CHAOS_INIT_MAX_FILTER);
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
    else
    {
        listener = chaos_init_install(&program);
        error = listener < 0 ? errno : 0;
    }

    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    payload.iov_base = &error;
    payload.iov_len = sizeof(error);
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
    if (CHAOS_INIT_SENDMSG(handover, &message, CHAOS_INIT_HANDOVER_FLAGS) != (ssize_t)sizeof(error))
    {
        return -1;
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
 * @param error  Output: the child's errno payload, or 0 when nothing arrived.
 * @return The listener; -1 when seccomp is unsupported (@p error > 0) or the child ended
 *         before sending (@p error == 0).
 */
static int chaos_init_receive_listener(int socket, int *error)
{
    struct msghdr message;
    struct iovec payload;
    struct cmsghdr *header;
    union
    {
        struct cmsghdr header;
        char space[CMSG_SPACE(sizeof(int))];
    } control;
    int listener = -1;

    *error = 0;
    memset(&message, 0, sizeof(message));
    payload.iov_base = error;
    payload.iov_len = sizeof(*error);
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control.space;
    message.msg_controllen = sizeof(control.space);
    if (recvmsg(socket, &message, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(*error))
    {
        *error = 0;
        return -1;
    }
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
    const size_t length =
        chaos_init_format_status(text, sizeof(text), libs, reason, (long)getpid(), mptcp_off);

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
    memset(&verdict, 0, sizeof(verdict));
    verdict.action = CHAOS_INIT_PASS;
    /* The libraries' system calls are disjoint except read, readv, write, writev and
     * close: net claims them on sockets, io decides them on anything else. The first
     * decider that recognises the call owns it, even when its verdict is PASS. */
    if (!((libs & CHAOS_INIT_LIB_NET) != 0U && chaos_init_net_decide(&call, &verdict)) &&
        !((libs & CHAOS_INIT_LIB_IO) != 0U && chaos_init_io_decide(&call, &verdict)) &&
        !((libs & CHAOS_INIT_LIB_MEMORY) != 0U && chaos_init_memory_decide(&call, &verdict)) &&
        (libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        (void)chaos_init_process_decide(&call, &verdict);
    }
    /* The decision read memory and /proc by tid: act on it only if that notification is
     * still pending, i.e. the tid still names the waiting thread and not a reused pid. */
    if (verdict.action != CHAOS_INIT_PASS &&
        chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &notification->id) != 0 &&
        chaos_init_caller_gone(errno))
    {
        return;
    }
    chaos_init_net_commit(&call, &verdict);
    if (verdict.action == CHAOS_INIT_DELAY)
    {
        const chaos_init_verdict_t answer = chaos_init_delay_answer(&verdict);

        /* now_ms truncates, so "now" may be up to 1 ms late; +1 ms guarantees the call is
         * held at least delay_ms (at the cost of up to 1 ms extra). */
        if (chaos_init_delay_add(
                notification->id, &call, chaos_init_now_ms() + verdict.delay_ms + 1U, &answer
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

    chaos_init_verdict_t due_verdict;

    while (chaos_init_delay_pop(now, &id, &due_verdict))
    {
        chaos_init_reply(listener, id, &due_verdict, response, response_size);
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
 * @brief Reaps every exited child, the application and adopted orphans alike, with
 *        waitpid(-1, WNOHANG) until none is left (one SIGCHLD may stand for several exits).
 * @param child_status  Output: the application's wait status, set only when it was reaped.
 * @return 1 when @p child was among those reaped, else 0.
 */
static int chaos_init_reap(pid_t child, int *child_status)
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
        if (pid == child)
        {
            *child_status = status;
            found = 1;
        }
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

    listener = chaos_init_receive_listener(pair[0], &error);
    (void)close(pair[0]);
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
    if (listener >= 0 && (options.libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        chaos_init_process_start(child);
    }
    chaos_init_write_status(
        options.libs,
        listener >= 0 ? NULL : chaos_init_unsupported_reason(error),
        mptcp_off && listener >= 0
    );
    /* Status first, then go: whoever sees the application run reads this run's status. */
    (void)kill(child, CHAOS_INIT_GO_SIGNAL);

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
    for (;;)
    {
        struct pollfd watched[3];
        nfds_t count = 2;

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
                else if (chaos_init_reap(child, &child_status))
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
        if (count == 3 && (watched[2].revents & POLLIN) != 0)
        {
            chaos_init_answer(listener, options.libs, request, response, sizes.seccomp_notif_resp);
        }
        else if (count == 3 && (watched[2].revents & (POLLHUP | POLLERR)) != 0)
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
        if (listener >= 0)
        {
            chaos_init_on_time(timer, listener, response, sizes.seccomp_notif_resp);
        }
    }
}
