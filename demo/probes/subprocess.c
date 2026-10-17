/* Demo proc2: fork a child that execve()s /bin/true, wait for it, report. Under
 * libchaos-process with `execve:ERRNO:EACCES` the exec fails, the child exits with status
 * 13 (EACCES) and the parent keeps running: a denied subprocess must not take the caller
 * down. The child's own printf line is buffered when stdout is a pipe and _exit() discards
 * it, so under `docker compose run -T` only the parent's line appears. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { "/bin/true", NULL };
        execve("/bin/true", argv, NULL);
        printf("child: execve -> [errno %d] %s\n", errno, strerror(errno));
        _exit(errno);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
        printf("subprocess blocked (child exit=%d) — parent still running\n", WEXITSTATUS(st));
    else
        printf("subprocess ran — parent still running\n");
    return 0;
}
