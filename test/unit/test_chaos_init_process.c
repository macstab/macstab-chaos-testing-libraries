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
 * - the application's own first execve is never faulted, later ones are;
 * - LATENCY delays, ERRNO fails, both together delay and then fail;
 * - FAIL_AFTER counts per process and starts over after a reload.
 */

#include <stdint.h>
#include <sys/types.h>

static int g_fail_process = 0;
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);
static int test_process_of(pid_t tid, pid_t *tgid, uint64_t *start)
{
    return g_fail_process ? -1 : chaos_init_process_of(tid, tgid, start);
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

    /* The application's own exec starts it; the next one is faulted. */
    assert(decide(__NR_execve, 0U).action == CHAOS_INIT_PASS);
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

    /* A process that ended is not counted, and its call runs. */
    g_fail_process = 1;
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    write_rules("fork:ERRNO:ENOMEM\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    g_fail_process = 0;

    (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-process.hits.%ld", (long)getpid());
    assert(access(hits, F_OK) == 0);
    (void)unlink(hits);
    (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-process.hits.%ld", (long)child);
    (void)unlink(hits);
    (void)unlink("/tmp/.chaos-process.conf");
    return 0;
}
