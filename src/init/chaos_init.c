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
 * 3. Answers every notification, forwards termination and user signals to the
 *    child, reaps every process that ends up with it (as PID 1, or as a child
 *    subreaper anywhere else), and exits with the child's exit code (128 + signal
 *    when it was killed).
 *
 * no_new_privs also means that set-user-ID programs started by the application do
 * not gain privileges.
 */

#include "chaos_init_core.h"
#include "chaos_status.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h> /* _IOWR for the SECCOMP_IOCTL_* numbers */
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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
        listener = (int
        )syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
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

/** @brief Answers one notification: every call goes on unchanged for now. */
static void chaos_init_answer(int listener, void *request, void *response, size_t response_size)
{
    struct seccomp_notif *notification = request;
    struct seccomp_notif_resp *reply = response;

    memset(notification, 0, CHAOS_INIT_NOTIF_BUFFER);
    if (chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification) != 0)
    {
        return; /* EINTR, or the caller died (ENOENT): nothing to answer */
    }
    memset(reply, 0, response_size);
    reply->id = notification->id;
    reply->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    (void)chaos_init_ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, reply);
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
    int child_status = 0;
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
        (void)execvp(argv[options.command], argv + options.command);
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
    chaos_init_write_status(
        options.libs, listener >= 0 ? NULL : chaos_init_unsupported_reason(error)
    );
    (void)kill(child, CHAOS_INIT_GO_SIGNAL);

    signals = signalfd(-1, &forwarded, SFD_CLOEXEC);
    if (signals < 0)
    {
        perror("chaos-init: signalfd");
        (void)kill(child, SIGKILL);
        return CHAOS_INIT_EXIT_HANDOVER;
    }
    for (;;)
    {
        struct pollfd watched[2];
        nfds_t count = 1;

        watched[0].fd = signals;
        watched[0].events = POLLIN;
        if (listener >= 0)
        {
            watched[1].fd = listener;
            watched[1].events = POLLIN;
            count = 2;
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
                if (info.ssi_signo != SIGCHLD)
                {
                    (void)kill(child, (int)info.ssi_signo);
                }
                else if (chaos_init_reap(child, &child_status))
                {
                    return chaos_init_exit_code(child_status);
                }
            }
        }
        if (count == 2 && (watched[1].revents & POLLIN) != 0)
        {
            chaos_init_answer(listener, request, response, sizes.seccomp_notif_resp);
        }
        else if (count == 2 && (watched[1].revents & (POLLHUP | POLLERR)) != 0)
        {
            /* No process uses the filter any more. */
            (void)close(listener);
            listener = -1;
        }
    }
}
