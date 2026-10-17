/**
 * @file process_probe.c
 * @brief End-to-end probe for libchaos-process in LD_PRELOAD mode on glibc and musl.
 *
 * @details
 * Proves that rules in the rule file `/tmp/.chaos-process.conf` fault thread creation, process
 * creation, exec and reaping with each function's own error contract. Exit code of each check,
 * its rule, and the behaviour proven:
 *
 * - 10      pthread_create:ERRNO:EAGAIN; returns EAGAIN, errno stays 0 (pthread functions
 *           report errors by return value).
 * - 20-24   pthread_create:LATENCY:100; succeeds and takes >= 80 ms.
 * - 30-32   pthread_create:FAIL_AFTER:EAGAIN,1; the 1st call succeeds, the 2nd returns EAGAIN.
 * - 40      fork:ERRNO:EAGAIN; -1 with errno EAGAIN, no child.
 * - 50-55   fork:LATENCY:100; fork returns >= 80 ms later and the child exits 0.
 * - 60      posix_spawn:ERRNO:EAGAIN; returns EAGAIN, errno stays 0, nothing spawned.
 * - 70-75   posix_spawnp:LATENCY:100; spawns `true` via PATH, >= 80 ms, exit status 0.
 * - 80-83   execve:ERRNO:EACCES; in a forked child, execve returns -1/EACCES instead of
 *           replacing the image.
 * - 90-93   execveat:ERRNO:ENOENT; same, for execveat. Passes without running when the libc
 *           has no execveat symbol (weak reference resolves to NULL, e.g. glibc < 2.34).
 * - 100-103 waitpid:ERRNO:EINTR; -1/EINTR without reaping; the child is reaped after the rule
 *           is cleared, proving the fault consumed no zombie.
 * - 110-115 waitpid:LATENCY:100; reaps the child >= 80 ms later.
 * - 110-114, 120-123  waitpid:ERRNO:ECHILD also fails wait, wait3, wait4 and waitid (glibc and
 *           musl issue their own system calls, so each has its own wrapper); each reaps once the
 *           rule is gone. These codes overlap the previous check's; the order disambiguates.
 * - 130-134 execve:ERRNO:EACCES also fails execv, execvp, execl, execlp and execle, which reach
 *           the kernel on internal libc paths.
 * - 136-139 posix_spawn:ERRNO:EAGAIN fails system (-1/EAGAIN) and popen (NULL/EAGAIN); both
 *           work again once the rule is cleared.
 * - 200-204 the rule file could not be written.
 *
 * posix_spawn is faulted through its own selector: neither glibc's nor musl's posix_spawn calls
 * the public fork() (both clone with CLONE_VM|CLONE_VFORK), so a fork rule never reaches it.
 *
 * Run by test_process_glibc.sh (gcc:bookworm) and test_process_alpine.sh (alpine:3.20), which
 * build the library, compile this file with -pthread in the container and run it with
 * `LD_PRELOAD=/tmp/libchaos-process.so`. Needs /bin/sh, /bin/true and `true` in PATH. Checks
 * run in main()'s order and stop at the first failure.
 *
 * Exit: 0 when every check passes; otherwise the code of the first failing check above. The
 * rule file is left in place (empty after the last check). The probe never skips; execveat is
 * the only check that can pass vacuously.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

extern char **environ;

#ifdef __linux__
extern int
execveat(int directory_fd, const char *path, char *const argv[], char *const envp[], int flags)
    __attribute__((weak));
#endif

static time_t g_config_stamp = 12000;

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

/**
 * @brief Sleeps 2 ms so the next intercepted call re-checks the rule file.
 *
 * With rules loaded, a library stats its rule file at most once per CHAOS_CHECK_INTERVAL_NS
 * (1 ms); a rewrite is seen by the first call after that, not necessarily the next call. The
 * sleep is a raw clock_nanosleep system call, restarted on EINTR, so no wrapper (libchaos-time
 * faults nanosleep) can fail or stretch it.
 */
static void wait_for_rule_check(void)
{
    struct timespec delay = {0, 2000000L};

    while (syscall(SYS_clock_nanosleep, CLOCK_MONOTONIC, 0, &delay, &delay) != 0 && errno == EINTR)
    {
    }
}

/**
 * @brief Replaces the rule file `/tmp/.chaos-process.conf` with @p text plus a newline, then
 *        sets its mtime with utime() to 12000, 12001, ... seconds since the epoch.
 *
 * The explicit, strictly increasing mtime changes the reload change stamp even when two writes
 * land within one filesystem timestamp tick. The stamp is applied by path after fclose().
 *
 * @return 0, or 200 (fopen), 201 (fprintf), 202 (fflush), 204 (fclose), 203 (utime).
 */
static int write_config_now(const char *text)
{
    FILE *config = fopen("/tmp/.chaos-process.conf", "w");
    struct utimbuf stamp;

    if (config == NULL)
    {
        return 200;
    }
    if (fprintf(config, "%s\n", text) < 0)
    {
        fclose(config);
        return 201;
    }
    if (fflush(config) != 0)
    {
        fclose(config);
        return 202;
    }

    if (fclose(config) != 0)
    {
        return 204;
    }
    stamp.actime = g_config_stamp;
    stamp.modtime = g_config_stamp;
    ++g_config_stamp;
    if (utime("/tmp/.chaos-process.conf", &stamp) != 0)
    {
        return 203;
    }

    return 0;
}

/** @brief write_config_now(), then wait_for_rule_check(); returns write_config_now()'s code. */
static int write_config(const char *text)
{
    const int rc = write_config_now(text);

    wait_for_rule_check();
    return rc;
}

/** @brief Empties the rule file: no rules, every wrapper passes through. */
static int clear_config(void)
{
    return write_config("");
}

/**
 * @brief Reaps @p pid with waitpid(), retrying on EINTR.
 * @return 0 when reaped, -1 on any other failure. Must only run with no waitpid ERRNO rule
 *         active, or it spins on an injected EINTR.
 */
static int wait_for_child(pid_t pid, int *status)
{
    for (;;)
    {
        pid_t rc = waitpid(pid, status, 0);

        if (rc == pid)
        {
            return 0;
        }
        if (rc < 0 && errno == EINTR)
        {
            continue;
        }
        return -1;
    }
}

static void *thread_main(void *argument)
{
    return argument;
}

static int probe_pthread_create_errno(void)
{
    pthread_t thread;
    int rc = write_config("pthread_create:ERRNO:EAGAIN");

    if (rc != 0)
    {
        return rc;
    }

    errno = 0;
    rc = pthread_create(&thread, NULL, thread_main, NULL);
    return rc == EAGAIN && errno == 0 ? 0 : 10;
}

static int probe_pthread_create_latency(void)
{
    pthread_t thread;
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int rc = write_config("pthread_create:LATENCY:100");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 20;
    }
    rc = pthread_create(&thread, NULL, thread_main, NULL);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        if (rc == 0)
        {
            (void)pthread_join(thread, NULL);
        }
        return 21;
    }
    if (rc != 0)
    {
        return 22;
    }
    if (pthread_join(thread, NULL) != 0)
    {
        return 23;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 24;
}

static int probe_pthread_create_fail_after(void)
{
    pthread_t thread;
    int rc = write_config("pthread_create:FAIL_AFTER:EAGAIN,1");

    if (rc != 0)
    {
        return rc;
    }

    rc = pthread_create(&thread, NULL, thread_main, NULL);
    if (rc != 0)
    {
        return 30;
    }
    if (pthread_join(thread, NULL) != 0)
    {
        return 31;
    }

    errno = 0;
    rc = pthread_create(&thread, NULL, thread_main, NULL);
    return rc == EAGAIN && errno == 0 ? 0 : 32;
}

static int probe_fork_errno(void)
{
    pid_t pid;
    int rc = write_config("fork:ERRNO:EAGAIN");

    if (rc != 0)
    {
        return rc;
    }

    errno = 0;
    pid = fork();
    return pid == -1 && errno == EAGAIN ? 0 : 40;
}

static int probe_fork_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    pid_t pid;
    int status;
    int rc = write_config("fork:LATENCY:100");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 50;
    }
    pid = fork();
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        if (pid == 0)
        {
            _exit(90);
        }
        if (pid > 0)
        {
            (void)wait_for_child(pid, &status);
        }
        return 51;
    }
    if (pid < 0)
    {
        return 52;
    }
    if (pid == 0)
    {
        _exit(0);
    }
    if (wait_for_child(pid, &status) != 0)
    {
        return 53;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 54;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 55;
}

static int probe_posix_spawn_errno(void)
{
    pid_t pid = 0;
    char *argv[] = {(char *)"/bin/true", NULL};
    int rc = write_config("posix_spawn:ERRNO:EAGAIN");

    if (rc != 0)
    {
        return rc;
    }

    errno = 0;
    rc = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ);
    return rc == EAGAIN && errno == 0 ? 0 : 60;
}

static int probe_posix_spawnp_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    pid_t pid = 0;
    int status;
    char *argv[] = {(char *)"true", NULL};
    int rc = write_config("posix_spawnp:LATENCY:100");

    if (rc != 0)
    {
        return rc;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        return 70;
    }
    rc = posix_spawnp(&pid, "true", NULL, NULL, argv, environ);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        if (rc == 0)
        {
            (void)wait_for_child(pid, &status);
        }
        return 71;
    }
    if (rc != 0)
    {
        return 72;
    }
    if (wait_for_child(pid, &status) != 0)
    {
        return 73;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 74;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 75;
}

static int probe_execve_errno(void)
{
    pid_t pid;
    int status;
    int rc = write_config("execve:ERRNO:EACCES");

    if (rc != 0)
    {
        return rc;
    }

    pid = fork();
    if (pid < 0)
    {
        return 80;
    }
    if (pid == 0)
    {
        char *argv[] = {(char *)"/bin/sh", (char *)"-c", (char *)"exit 77", NULL};

        errno = 0;
        if (execve("/bin/sh", argv, environ) == -1 && errno == EACCES)
        {
            _exit(0);
        }
        _exit(81);
    }
    if (wait_for_child(pid, &status) != 0)
    {
        return 82;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 83;
}

static int probe_execveat_errno(void)
{
    pid_t pid;
    int status;
    int rc = write_config("execveat:ERRNO:ENOENT");

    if (rc != 0)
    {
        return rc;
    }
    if (execveat == NULL)
    {
        return 0;
    }

    pid = fork();
    if (pid < 0)
    {
        return 90;
    }
    if (pid == 0)
    {
        char *argv[] = {(char *)"/bin/sh", (char *)"-c", (char *)"exit 78", NULL};

        errno = 0;
        if (execveat(AT_FDCWD, "/bin/sh", argv, environ, 0) == -1 && errno == ENOENT)
        {
            _exit(0);
        }
        _exit(91);
    }
    if (wait_for_child(pid, &status) != 0)
    {
        return 92;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 93;
}

static int probe_waitpid_errno(void)
{
    pid_t pid;
    int status;
    int rc = write_config("waitpid:ERRNO:EINTR");

    if (rc != 0)
    {
        return rc;
    }

    pid = fork();
    if (pid < 0)
    {
        return 100;
    }
    if (pid == 0)
    {
        _exit(0);
    }

    errno = 0;
    if (waitpid(pid, &status, 0) != -1 || errno != EINTR)
    {
        (void)clear_config();
        (void)wait_for_child(pid, &status);
        return 101;
    }

    rc = clear_config();
    if (rc != 0)
    {
        (void)wait_for_child(pid, &status);
        return rc;
    }
    if (wait_for_child(pid, &status) != 0)
    {
        return 102;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 103;
}

static int probe_waitpid_latency(void)
{
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    pid_t pid;
    int status;
    int rc = write_config("waitpid:LATENCY:100");

    if (rc != 0)
    {
        return rc;
    }

    pid = fork();
    if (pid < 0)
    {
        return 110;
    }
    if (pid == 0)
    {
        _exit(0);
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        (void)wait_for_child(pid, &status);
        return 111;
    }
    if (waitpid(pid, &status, 0) != pid)
    {
        return 112;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        return 113;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return 114;
    }

    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 80LL ? 0 : 115;
}

/*
 * wait(), wait3(), wait4() and waitid() follow the waitpid rules. Each is failed with ECHILD
 * while a child is pending (a value the kernel would never return then, so the fault is
 * unambiguous), then reaps that child once the rule is gone.
 */
static int probe_wait_family(void)
{
    struct rusage usage;
    siginfo_t info;
    pid_t pid;
    int status;
    int form;
    int rc;

    for (form = 0; form < 4; ++form)
    {
        int faulted;

        rc = write_config("waitpid:ERRNO:ECHILD");
        if (rc != 0)
        {
            return rc;
        }
        pid = fork();
        if (pid < 0)
        {
            return 110;
        }
        if (pid == 0)
        {
            _exit(0);
        }

        errno = 0;
        switch (form)
        {
        case 0:
            faulted = wait(&status) == -1;
            break;
        case 1:
            faulted = wait3(&status, 0, &usage) == -1;
            break;
        case 2:
            faulted = wait4(pid, &status, 0, &usage) == -1;
            break;
        default:
            faulted = waitid(P_PID, (id_t)pid, &info, WEXITED) == -1;
            break;
        }
        rc = clear_config();
        if (!faulted || errno != ECHILD)
        {
            (void)wait_for_child(pid, &status);
            return 111 + form;
        }
        if (rc != 0)
        {
            (void)wait_for_child(pid, &status);
            return rc;
        }

        switch (form)
        {
        case 0:
            rc = wait(&status) == pid ? 0 : 120;
            break;
        case 1:
            rc = wait3(&status, 0, &usage) == pid ? 0 : 121;
            break;
        case 2:
            rc = wait4(pid, &status, 0, &usage) == pid ? 0 : 122;
            break;
        default:
            rc = waitid(P_PID, (id_t)pid, &info, WEXITED) == 0 && info.si_pid == pid ? 0 : 123;
            break;
        }
        if (rc != 0)
        {
            return rc;
        }
    }
    return 0;
}

/*
 * Runs exec form @p form (0 execv, 1 execvp, 2 execl, 3 execlp, 4 execle) in a child. The child
 * exits 42 when the exec failed with EACCES, 43 on any other failure; an exec that went through
 * runs /bin/true and exits 0. Returns 1 only for 42.
 */
static int exec_form_faulted(int form)
{
    char *const argv[] = {(char *)"true", NULL};
    pid_t pid = fork();
    int status;

    if (pid < 0)
    {
        return 0;
    }
    if (pid == 0)
    {
        switch (form)
        {
        case 0:
            (void)execv("/bin/true", argv);
            break;
        case 1:
            (void)execvp("true", argv);
            break;
        case 2:
            (void)execl("/bin/true", "true", (char *)NULL);
            break;
        case 3:
            (void)execlp("true", "true", (char *)NULL);
            break;
        default:
            (void)execle("/bin/true", "true", (char *)NULL, environ);
            break;
        }
        _exit(errno == EACCES ? 42 : 43);
    }
    return wait_for_child(pid, &status) == 0 && WIFEXITED(status) && WEXITSTATUS(status) == 42;
}

static int probe_exec_family_and_shell(void)
{
    FILE *stream;
    int form;
    int rc = write_config("execve:ERRNO:EACCES");

    if (rc != 0)
    {
        return rc;
    }
    for (form = 0; form < 5; ++form)
    {
        if (!exec_form_faulted(form))
        {
            (void)clear_config();
            return 130 + form;
        }
    }

    rc = write_config("posix_spawn:ERRNO:EAGAIN");
    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    if (system("true") != -1 || errno != EAGAIN)
    {
        (void)clear_config();
        return 136;
    }
    errno = 0;
    stream = popen("true", "r");
    if (stream != NULL || errno != EAGAIN)
    {
        if (stream != NULL)
        {
            (void)pclose(stream);
        }
        (void)clear_config();
        return 137;
    }

    rc = clear_config();
    if (rc != 0)
    {
        return rc;
    }
    if (system("true") != 0)
    {
        return 138;
    }
    stream = popen("true", "r");
    if (stream == NULL || pclose(stream) != 0)
    {
        return 139;
    }
    return 0;
}

int main(void)
{
    int rc;

    rc = probe_pthread_create_errno();
    if (rc != 0)
        return rc;
    rc = probe_pthread_create_latency();
    if (rc != 0)
        return rc;
    rc = probe_pthread_create_fail_after();
    if (rc != 0)
        return rc;
    rc = probe_fork_errno();
    if (rc != 0)
        return rc;
    rc = probe_fork_latency();
    if (rc != 0)
        return rc;
    rc = probe_posix_spawn_errno();
    if (rc != 0)
        return rc;
    rc = probe_posix_spawnp_latency();
    if (rc != 0)
        return rc;
    rc = probe_execve_errno();
    if (rc != 0)
        return rc;
    rc = probe_execveat_errno();
    if (rc != 0)
        return rc;
    rc = probe_waitpid_errno();
    if (rc != 0)
        return rc;
    rc = probe_waitpid_latency();
    if (rc != 0)
        return rc;
    rc = probe_wait_family();
    if (rc != 0)
        return rc;
    rc = probe_exec_family_and_shell();
    if (rc != 0)
        return rc;

    return 0;
}
