/* process use-case 2 — fork a child that execve()s /bin/true, and keep running.
 * With execve:ERRNO:EACCES the exec is denied, the child exits non-zero, the PARENT lives. */
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
