/**
 * @file chaos_init.c
 * @brief chaos-init: PID 1 of a container in SECCOMP injection mode.
 *
 * @details
 * Usage: `chaos-init --libs io,net -- <entrypoint> [args...]`
 *
 * 1. Forks the child that becomes the application. The child sets no_new_privs,
 *    installs the filter of chaos_init_build_filter() with a notification listener
 *    and sends the listener back over a socketpair (the one sendmsg the filter lets
 *    through), then executes the command. Installing needs no privilege, so this
 *    works under Docker's default profile; pidfd_getfd() would need CAP_SYS_PTRACE.
 * 2. Writes CHAOS_INIT_STATUS_PATH: active, or unsupported with the reason, and
 *    only then lets the child execute the command (SIGUSR1, waited for with
 *    sigwait(), which no filter passes on), so whoever sees the application
 *    running reads this run's status. When
 *    the filter cannot be installed (old kernel, emulated architecture, a stricter
 *    profile), the application still starts, without chaos, and the status says why.
 * 3. Answers every notification: the call fails, runs later (LATENCY, parked in
 *    chaos_init_delay.c so other threads go on) or runs unchanged, by the rules
 *    of the libraries named in --libs. Hits files are written per process.
 *    Forwards termination and user signals to the
 *    child, reaps every process that ends up with it (as PID 1, or as a child
 *    subreaper anywhere else), and exits with the child's exit code (128 + signal
 *    when it was killed).
 *
 * no_new_privs also means that set-user-ID programs started by the application do
 * not gain privileges.
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

/** @brief Exit codes of chaos-init itself (the application's are passed through). */
#define CHAOS_INIT_EXIT_USAGE 2
#define CHAOS_INIT_EXIT_HANDOVER 125
#define CHAOS_INIT_EXIT_NOT_EXECUTABLE 126
#define CHAOS_INIT_EXIT_NOT_FOUND 127

/** @brief Tells the child the status is written and it may execute the command. */
#define CHAOS_INIT_GO_SIGNAL SIGUSR1

/** @brief Signals passed on to the application; SIGCHLD is handled here. */
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
 * @brief Kernel release to judge instead of uname()'s; runtime tests build a
 *        variant with an old release to reach the unsupported path.
 */
#ifdef CHAOS_INIT_TEST_RELEASE
#define CHAOS_INIT_RELEASE(name) CHAOS_INIT_TEST_RELEASE
#else
#define CHAOS_INIT_RELEASE(name) ((name)->release)
#endif

#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

/**
 * @brief Filter flags tried first. Since Linux 5.19 a call the supervisor has
 *        received waits killably: a signal no longer interrupts a delayed call,
 *        which the kernel would otherwise restart as a new notification (Go
 *        signals its threads constantly). Older kernels reject the flag; the delay
 *        queue then recognises a restarted call instead (chaos_init_delay_resume).
 *        Runtime tests build a variant without it to reach that path.
 */
#ifdef CHAOS_INIT_TEST_NO_KILLABLE_WAIT
#define CHAOS_INIT_FILTER_FLAGS SECCOMP_FILTER_FLAG_NEW_LISTENER
#else
#define CHAOS_INIT_FILTER_FLAGS                                                                    \
    (SECCOMP_FILTER_FLAG_NEW_LISTENER | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV)
#endif

/** @brief Large enough for the kernel's notification structures (checked at start). */
#define CHAOS_INIT_NOTIF_BUFFER 512U

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
 * @brief In the child: installs the filter and sends the listener (or the error).
 * @return 0 when the child may execute the command, -1 when it must not (a filter
 *         is installed that nobody would answer).
 */
static int chaos_init_install_and_hand_over(unsigned libs)
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
    int error = 0;
    int listener = -1;

    program.len = (unsigned short)chaos_init_build_filter(libs, filter, CHAOS_INIT_MAX_FILTER);
    program.filter = filter;
    if (uname(&name) != 0 || !chaos_init_kernel_supported(CHAOS_INIT_RELEASE(&name)))
    {
        error = ENOTSUP;
    }
    else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        error = errno;
    }
    else
    {
        listener =
            (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, CHAOS_INIT_FILTER_FLAGS, &program);
        if (listener < 0 && errno == EINVAL)
        {
            /* Before 5.19: without the killable wait. */
            listener = (int)syscall(
                SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program
            );
        }
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
    if (sendmsg(CHAOS_INIT_HANDOVER_FD, &message, CHAOS_INIT_HANDOVER_FLAGS) !=
        (ssize_t)sizeof(error))
    {
        return listener >= 0 ? -1 : 0;
    }
    return 0;
}

/**
 * @brief In the parent: receives the listener; -1 with @p error set when there is none.
 * @return The listener, -1 when seccomp is unsupported (@p error > 0) or the child
 *         died before answering (@p error == 0).
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

/** @brief Writes the status file, creating /tmp first (images built FROM scratch lack it). */
static void chaos_init_write_status(unsigned libs, const char *reason)
{
    char text[CHAOS_STATUS_BUFFER_SIZE];
    const size_t length =
        chaos_init_format_status(text, sizeof(text), libs, reason, (long)getpid());

    if (mkdir("/tmp", 01777) == 0)
    {
        (void)chmod("/tmp", 01777);
    }
    chaos_status_replace_file(CHAOS_INIT_STATUS_PATH, text, length);
}

/**
 * @brief ioctl() as a system call: musl declares the request as int, which the
 *        seccomp request numbers overflow.
 */
static long chaos_init_ioctl(int fd, unsigned long request, void *argument)
{
    return syscall(SYS_ioctl, fd, request, argument);
}

/** @brief CLOCK_MONOTONIC in milliseconds (the supervisor is under no time rule). */
static uint64_t chaos_init_now_ms(void)
{
    struct timespec now;

    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

/**
 * @brief Sends the answer to notification @p id: run the call, fail it with
 *        @p verdict's error, or return @p verdict's value without running it.
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
    /* ENOENT: the thread is gone (killed while waiting); nothing to answer. */
    (void)chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, reply);
}

/** @brief Receives one notification and answers it, now or (LATENCY) later. */
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
        return; /* EINTR, or the caller died (ENOENT): nothing to answer */
    }
    call.tid = (pid_t)notification->pid;
    call.nr = notification->data.nr;
    for (index = 0U; index < 6U; ++index)
    {
        call.args[index] = notification->data.args[index];
    }
    /* A delayed call a signal interrupted, restarted by the kernel: it keeps its
     * due time and its verdict, and is neither decided nor counted again. */
    if (chaos_init_delay_resume(&call, notification->id))
    {
        return;
    }
    memset(&verdict, 0, sizeof(verdict));
    verdict.action = CHAOS_INIT_PASS;
    /* The libraries' system calls are disjoint, except read, write and close: net
     * claims them on sockets, io decides them on anything else. */
    if (!((libs & CHAOS_INIT_LIB_NET) != 0U && chaos_init_net_decide(&call, &verdict)) &&
        !((libs & CHAOS_INIT_LIB_IO) != 0U && chaos_init_io_decide(&call, &verdict)) &&
        !((libs & CHAOS_INIT_LIB_MEMORY) != 0U && chaos_init_memory_decide(&call, &verdict)) &&
        (libs & CHAOS_INIT_LIB_PROCESS) != 0U)
    {
        (void)chaos_init_process_decide(&call, &verdict);
    }
    /* The decision read the thread's memory: act on it only if that thread is still
     * the one waiting (its pid could otherwise belong to another process by now). */
    if (verdict.action != CHAOS_INIT_PASS &&
        chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &notification->id) != 0 &&
        chaos_init_caller_gone(errno))
    {
        return;
    }
    if (verdict.action == CHAOS_INIT_DELAY)
    {
        const chaos_init_verdict_t answer = chaos_init_delay_answer(&verdict);

        /* The clock is read in whole milliseconds, rounded down: one more keeps a
         * delay from ending up to a millisecond short. */
        if (chaos_init_delay_add(
                notification->id, &call, chaos_init_now_ms() + verdict.delay_ms + 1U, &answer
            ) == 0)
        {
            return;
        }
        /* The queue is full: no delay, the rest of the verdict now. */
        verdict = answer;
    }
    chaos_init_reply(listener, notification->id, &verdict, response, response_size);
}

/**
 * @brief Continues the delayed calls that are due, writes hits files that waited
 *        for the interval, and sets @p timer to the next of both.
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
        /* An absolute time already past fires at once; 0 would disarm the timer. */
        due = due > now ? due : now + 1U;
        next.it_value.tv_sec = (time_t)(due / 1000U);
        next.it_value.tv_nsec = (long)(due % 1000U) * 1000000L;
    }
    (void)timerfd_settime(timer, TFD_TIMER_ABSTIME, &next, NULL);
}

/**
 * @brief Reaps every exited process; @return 1 once @p child is among them.
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
 * @brief Once the application has exited: whether a background copy of chaos-init
 *        must go on answering the processes it left behind (daemons, double forks).
 *
 * @details They keep the filter; with nobody answering, every filtered call of
 * theirs would fail with ENOSYS. As PID 1 nothing is needed: its exit ends the
 * container's processes. Otherwise this process returns the application's exit
 * code at once, as before, and a forked copy serves the listener until the kernel
 * reports that no process uses the filter any more (POLLHUP, Linux 5.8+). Its
 * standard descriptors are detached so a caller reading chaos-init's output sees
 * the end of it.
 *
 * @return 1 in the background copy, 0 in the process that is to exit.
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

    /* Orphans of the application are reaped here even when chaos-init is not PID 1. */
    (void)prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    /* Blocked before the fork, so no signal is lost while the child starts; the
     * child restores the original mask before it executes the command. */
    chaos_init_signal_set(&forwarded);
    if (sigprocmask(SIG_BLOCK, &forwarded, &original) != 0 ||
        socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
    {
        perror("chaos-init");
        return CHAOS_INIT_EXIT_HANDOVER;
    }

    /* Looked up now: the child's execvp() would try one PATH entry after another,
     * and only the application's first execve is exempt from the process rules. */
    found = chaos_init_find_command(
        argv[options.command], getenv("PATH"), command_path, sizeof(command_path)
    );
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

        (void)close(pair[0]);
        (void)sigemptyset(&go);
        (void)sigaddset(&go, CHAOS_INIT_GO_SIGNAL);
        /* The go signal is blocked (it is among the forwarded ones) until it is
         * waited for, so it cannot be lost if it comes early. */
        if (dup3(pair[1], CHAOS_INIT_HANDOVER_FD, O_CLOEXEC) < 0 ||
            chaos_init_install_and_hand_over(options.libs) != 0 || sigwait(&go, &received) != 0 ||
            sigprocmask(SIG_SETMASK, &original, NULL) != 0)
        {
            _exit(CHAOS_INIT_EXIT_HANDOVER);
        }
        if (found)
        {
            (void)execv(command_path, argv + options.command);
        }
        else
        {
            errno = ENOENT;
        }
        error = errno;
        (void)fprintf(stderr, "chaos-init: %s: %s\n", argv[options.command], strerror(error));
        _exit(error == ENOENT ? CHAOS_INIT_EXIT_NOT_FOUND : CHAOS_INIT_EXIT_NOT_EXECUTABLE);
    }
    (void)close(pair[1]);

    listener = chaos_init_receive_listener(pair[0], &error);
    (void)close(pair[0]);
    if (listener >= 0 && (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0 ||
                          sizes.seccomp_notif > CHAOS_INIT_NOTIF_BUFFER ||
                          sizes.seccomp_notif_resp > CHAOS_INIT_NOTIF_BUFFER))
    {
        /* Without answers every filtered call of the application would hang. */
        (void)kill(child, SIGKILL);
        (void)fprintf(stderr, "chaos-init: cannot read seccomp notifications\n");
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    if (listener < 0 && error == 0)
    {
        (void)waitpid(child, &child_status, 0);
        (void)fprintf(stderr, "chaos-init: the child ended before the filter was set up\n");
        return CHAOS_INIT_EXIT_HANDOVER;
    }
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
        options.libs, listener >= 0 ? NULL : chaos_init_unsupported_reason(error)
    );
    (void)kill(child, CHAOS_INIT_GO_SIGNAL);

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
                    /* The application is gone: nothing to forward or reap. */
                }
                else if (info.ssi_signo != SIGCHLD)
                {
                    (void)kill(child, (int)info.ssi_signo);
                }
                else if (chaos_init_reap(child, &child_status))
                {
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

            /* Only consumes the expiry; what is due is handled below. */
            if (read(timer, &expirations, sizeof(expirations)) < 0)
            {
                expirations = 0U;
            }
        }
        if (count == 3 && (watched[2].revents & POLLIN) != 0)
        {
            chaos_init_answer(listener, options.libs, request, response, sizes.seccomp_notif_resp);
        }
        else if (count == 3 && (watched[2].revents & (POLLHUP | POLLERR)) != 0)
        {
            /* No process uses the filter any more. */
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
