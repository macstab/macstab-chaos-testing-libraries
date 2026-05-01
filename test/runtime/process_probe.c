/**
 * @file process_probe.c
 * @brief Runtime validation probe for libchaos-process under LD_PRELOAD.
 *
 * @details
 * Standalone C program compiled inside a Docker container and executed under
 * `LD_PRELOAD=libchaos-process.so`. Validates end-to-end fault injection for
 * the process library's interposed symbols: `pthread_create`, `fork`,
 * `posix_spawn`, `posix_spawnp`, `execve`, `execveat`, and `waitpid`.
 *
 * Each subtest writes a config rule with a future-mtime timestamp to
 * `/tmp/.chaos-process.conf`, then exercises the interposed symbol and asserts
 * the expected behavior. This probe uses `utime()` rather than `futimens()` to
 * advance the mtime, because `futimens()` requires the fd to remain open past
 * `fclose()`, which conflicts with the write-close-then-stamp ordering needed
 * for `utime()`. The incrementing `g_config_stamp` still guarantees each
 * `write_config()` call produces a strictly newer mtime.
 *
 * Subtests cover:
 * - `ERRNO` on `pthread_create` (synthetic `EAGAIN`; returned as errno-style int)
 * - `LATENCY` on `pthread_create` (≥ 80 ms added sleep before thread creation)
 * - `FAIL_AFTER` on `pthread_create` (N=1: first call succeeds, second returns `EAGAIN`)
 * - `ERRNO` on `fork` (synthetic `EAGAIN`)
 * - `LATENCY` on `fork` (≥ 80 ms added sleep; measured in parent before child reap)
 * - `ERRNO` on `posix_spawn` (synthetic `EAGAIN`; no process created)
 * - `LATENCY` on `posix_spawnp` (≥ 80 ms added sleep; spawns `/bin/true`)
 * - `ERRNO` on `execve` (synthetic `EACCES`; verified in forked child)
 * - `ERRNO` on `execveat` (synthetic `ENOENT`; skipped gracefully if weak symbol is NULL)
 * - `ERRNO` on `waitpid` (synthetic `EINTR`; config cleared before reaping zombie)
 * - `LATENCY` on `waitpid` (≥ 80 ms added sleep; child exits immediately)
 *
 * `pthread_create` errors are returned as the function's int return value, not
 * via `errno` — the probe verifies `rc == EAGAIN && errno == 0` to distinguish
 * this from POSIX-style syscall errors.
 *
 * `posix_spawn` on glibc uses `clone(CLONE_VFORK|CLONE_VM)` internally,
 * bypassing the libc `fork()` symbol; the interposed `posix_spawn` symbol is
 * therefore the only reliable injection point on glibc. On musl, `posix_spawn`
 * calls `fork()` internally, so `fork` rules would also cascade — the probe
 * tests `posix_spawn` directly to avoid this ambiguity.
 *
 * `execveat` is declared as a weak symbol; the probe skips the subtest when
 * the kernel does not expose it (older kernels, non-Linux containers).
 *
 * `waitpid` ERRNO requires a zombie-reap cleanup pass: after confirming the
 * injected error, the config is cleared and `wait_for_child()` is called in a
 * retry loop to release the zombie before the process exits.
 *
 * Returns 0 on success; returns a non-zero numbered exit code identifying
 * the failing subtest.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static int write_config(const char *text)
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

static int clear_config(void)
{
    return write_config("");
}

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

    return 0;
}
