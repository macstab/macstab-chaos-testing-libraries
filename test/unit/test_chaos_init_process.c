/**
 * @file test_chaos_init_process.c
 * @brief Unit tests for chaos-init's process decisions.
 *
 * Subsystem under test: `src/init/chaos_init_process.c` (with the process rule
 * core it includes, `chaos_init_proc.c` and `chaos_init_tracee.c`).
 *
 * Coverage approach: calls are built as a notification carries them, with this
 * test process (and a forked child that sleeps) as the caller; clone3's argument
 * structure is this process's memory. The process lookup can be made to fail.
 *
 * Properties under test:
 * - clone is a thread, a spawn (CLONE_VFORK) or a fork by its flags, clone3 too;
 *   fork, vfork, execve, execveat, wait4 and waitid reach their operations;
 * - the application's own start is never faulted, retries from chaos-init's image
 *   included; execs of the application's image are;
 * - LATENCY delays, ERRNO fails, both together delay and then fail;
 * - FAIL_AFTER counts per process and starts over after a reload; a fork child
 *   starts with its parent's counts at the fork, once; a new process that gets
 *   an ended one's entry starts from 0, and so does the child of a fork made
 *   under an earlier rule load;
 * - a rule whose probability is 0, or a process that ended, gets neither a delay
 *   nor an error.
 */

#include <stdint.h>
#include <sys/types.h>

static int g_fail_process = 0;
static uint64_t g_start_offset = 0U; /* > 0: every pid looks taken over by a new process */
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    if (g_fail_process || chaos_init_process_of(tid, tgid, start) != 0)
    {
        return -1;
    }
    *start += g_start_offset;
    return 0;
}
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) test_process_of((tid), (tgid), (start))

#include "../../src/init/chaos_init_process.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <assert.h>
#include <signal.h>
#include <sys/wait.h>

static chaos_init_verdict_t decide_for(pid_t tid, int nr, uint64_t a0)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    memset(&verdict, 0, sizeof(verdict));
    call.tid = tid;
    call.nr = nr;
    call.args[0] = a0;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_process_decide(&call, &verdict) == 1);
    return verdict;
}

static chaos_init_verdict_t decide(int nr, uint64_t a0)
{
    return decide_for(getpid(), nr, a0);
}

static int fails(chaos_init_verdict_t verdict, int error)
{
    return verdict.action == CHAOS_INIT_FAIL && verdict.error == error;
}

static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-process.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-process.conf.new", "/tmp/.chaos-process.conf") == 0);
}

int main(void)
{
    struct clone_args spawn_args;
    chaos_init_verdict_t verdict;
    chaos_init_call_t other;
    char hits[64];
    pid_t child;

    (void)unlink("/tmp/.chaos-process.conf");
    chaos_init_process_start(getpid());
    g_chaos_process_check_interval_ns = 0U;

    memset(&other, 0, sizeof(other));
    other.tid = getpid();
    other.nr = __NR_getpid;
    assert(chaos_init_process_decide(&other, &verdict) == 0);

    write_rules("pthread_create:ERRNO:EAGAIN\n"
                "fork:LATENCY:10\n"
                "fork:ERRNO:ENOMEM\n"
                "posix_spawn:ERRNO:EPERM\n"
                "execve:ERRNO:EACCES\n"
                "execveat:LATENCY:3\n"
                "waitpid:FAIL_AFTER:EINTR,1\n");

    /* The application's own exec starts it, and so does a retry from the same
     * image after it failed (a script without #! run through /bin/sh); once the
     * application's image is in, the next one is faulted. */
    assert(decide(__NR_execve, 0U).action == CHAOS_INIT_PASS);
    assert(decide(__NR_execve, 0U).action == CHAOS_INIT_PASS);
    g_start_offset = 7U;
    assert(fails(decide(__NR_execve, 0U), EACCES));
    g_start_offset = 0U;
    assert(fails(decide(__NR_execve, 0U), EACCES));
    verdict = decide(__NR_execveat, 0U);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 3U && verdict.error == 0);

    /* clone by its flags, clone3 by the flags in its argument structure. */
    assert(fails(decide(__NR_clone, CLONE_VM | CLONE_THREAD | CLONE_SIGHAND), EAGAIN));
    assert(fails(decide(__NR_clone, CLONE_VM | CLONE_VFORK | SIGCHLD), EPERM));
    verdict = decide(__NR_clone, SIGCHLD);
    assert(
        verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 10U && verdict.error == ENOMEM
    );
#ifdef __NR_clone3
    memset(&spawn_args, 0, sizeof(spawn_args));
    spawn_args.flags = CLONE_VM | CLONE_VFORK;
    assert(fails(decide(__NR_clone3, (uint64_t)(uintptr_t)&spawn_args), EPERM));
    assert(decide(__NR_clone3, 0U).error == ENOMEM); /* unreadable: a fork */
#else
    (void)spawn_args;
#endif
#ifdef __NR_fork
    assert(decide(__NR_fork, 0U).error == ENOMEM);
#endif
#ifdef __NR_vfork
    assert(fails(decide(__NR_vfork, 0U), EPERM));
#endif

    /* FAIL_AFTER: the first wait passes, then waits fail, per process. */
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide(__NR_waitid, 0U), EINTR));
    child = fork();
    if (child == 0)
    {
        pause();
        _exit(0);
    }
    assert(child > 0);
    assert(decide_for(child, __NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide_for(child, __NR_wait4, 0U), EINTR));
    assert(kill(child, SIGKILL) == 0 && waitpid(child, NULL, 0) == child);

    /* A reload starts the counters over. */
    write_rules("waitpid:FAIL_AFTER:EINTR,1 # reloaded\n");
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide(__NR_wait4, 0U), EINTR));

    /* A fork child starts with the counts its parent had at the fork, as the
     * library's child inherits them; the fork's counts go to one child only. */
    {
        pid_t forked;
        pid_t later;

        assert(fails(decide(__NR_wait4, 0U), EINTR)); /* the parent's count is past 1 */
        assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
        forked = fork();
        if (forked == 0)
        {
            pause();
            _exit(0);
        }
        later = fork();
        if (later == 0)
        {
            pause();
            _exit(0);
        }
        assert(forked > 0 && later > 0);
        assert(fails(decide_for(forked, __NR_wait4, 0U), EINTR));
        assert(decide_for(later, __NR_wait4, 0U).action == CHAOS_INIT_PASS);
        assert(kill(forked, SIGKILL) == 0 && waitpid(forked, NULL, 0) == forked);
        assert(kill(later, SIGKILL) == 0 && waitpid(later, NULL, 0) == later);
    }

    /* The counts of a fork made before a reload are not handed on: the child
     * starts from 0 under the new rules, as its parent does. */
    {
        pid_t forked;

        assert(fails(decide(__NR_wait4, 0U), EINTR)); /* the parent's count is past 1 */
        assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
        write_rules("waitpid:FAIL_AFTER:EINTR,1 # reloaded again\n");
        forked = fork();
        if (forked == 0)
        {
            pause();
            _exit(0);
        }
        assert(forked > 0);
        assert(decide_for(forked, __NR_wait4, 0U).action == CHAOS_INIT_PASS);
        assert(fails(decide_for(forked, __NR_wait4, 0U), EINTR));
        assert(kill(forked, SIGKILL) == 0 && waitpid(forked, NULL, 0) == forked);
        (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-process.hits.%ld", (long)forked);
        (void)unlink(hits);
    }

    /* A new process in an ended one's entry does not get its counts. */
    g_start_offset = 1U;
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide(__NR_wait4, 0U), EINTR));
    g_start_offset = 0U;

    /* A process that ended is not counted, and its call runs. */
    g_fail_process = 1;
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    write_rules("fork:ERRNO:ENOMEM\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    write_rules("fork:LATENCY:10\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    g_fail_process = 0;

    /* A rule whose probability is 0 never fires: no delay, no error. */
    write_rules("fork:LATENCY:10@0.0\nfork:ERRNO:ENOMEM@0.0\n");
    verdict = decide(__NR_clone, SIGCHLD);
    assert(verdict.action == CHAOS_INIT_PASS && verdict.error == 0);

    /* posix_spawnp cannot be told from posix_spawn: its rule rejects the file. */
    write_rules("fork:ERRNO:ENOMEM\nposix_spawnp:ERRNO:EPERM\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    {
        char status[256] = {0};
        FILE *file = fopen("/tmp/.chaos-process.status", "r");

        assert(file != NULL && fread(status, 1U, sizeof(status) - 1U, file) > 0U);
        (void)fclose(file);
        assert(strstr(status, "line=2\nreason=unsupported in seccomp mode\n") != NULL);
    }
    write_rules("*:ERRNO:ENOMEM\n");
    assert(fails(decide(__NR_clone, SIGCHLD), ENOMEM));

    (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-process.hits.%ld", (long)getpid());
    assert(access(hits, F_OK) == 0);
    (void)unlink(hits);
    (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-process.hits.%ld", (long)child);
    (void)unlink(hits);
    (void)unlink("/tmp/.chaos-process.conf");
    return 0;
}
