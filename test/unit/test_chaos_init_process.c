/**
 * @file test_chaos_init_process.c
 * @brief Proves chaos-init maps process-lifecycle system calls onto libchaos-process
 *        rules, including per-process FAIL_AFTER state across forks and reloads.
 *
 * @details Unit under test: `chaos_init_process_decide()` in
 * `src/init/chaos_init_process.c`, compiled in by `#include` with the libchaos-process
 * rule core, `chaos_init_proc.c` and `chaos_init_tracee.c`.
 *
 * Isolation: no supervisor and no seccomp filter. Calls are `chaos_init_call_t` values
 * filled as a notification fills them. The caller is this process, or a forked child
 * parked in pause(2) so it has a real /proc entry and a real parent link (the fork
 * inheritance logic resolves the parent through `/proc/<pid>/status`). clone3's
 * `struct clone_args` lives in this process, which is the caller, so the real
 * process_vm_readv(2) path reads it.
 *
 * Seam: `CHAOS_INIT_PROCESS_OF` is defined before the include to wrap the real
 * `chaos_init_process_of()`. `g_fail_process` makes every lookup fail (the caller
 * vanished); `g_start_offset` shifts the start/image fingerprint, which the tracee table
 * reads as a different process on the same pid (pid reuse, or a new image after execve).
 *
 * Properties proven:
 * - clone maps by flags: CLONE_THREAD is pthread_create, CLONE_VFORK is posix_spawn,
 *   anything else is fork; clone3 reads the same flags from its argument structure and
 *   an unreadable structure counts as fork; fork, vfork, execve, execveat, wait4 and
 *   waitid reach their operations;
 * - the application's first execve, and retries of it from chaos-init's own image, are
 *   never faulted; once the image changes, execve is faulted;
 * - LATENCY gives DELAY, ERRNO gives FAIL, both on one call give DELAY carrying the errno;
 * - FAIL_AFTER counts per process and restarts from 0 after a reload; a fork child
 *   inherits its parent's counts at the fork, and only the first child takes them; a
 *   new process on a reused entry starts from 0, as does the child of a fork made under
 *   an earlier rule load;
 * - probability 0, or a caller that cannot be resolved, yields neither delay nor errno;
 * - a posix_spawnp rule rejects the whole rule file in SECCOMP mode (status file names
 *   the line), because the PATH search happens in libc and is invisible here.
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

/**
 * @brief Decides a process call by @p tid with first argument @p a0; asserts process
 *        owns it. The verdict is pre-set to FAIL so a PASS proves it was written.
 */
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

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
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

    /* chaos_init_process_start(getpid()) declared this process the application. Its
     * first execve is its own start and must pass, and so must a retry from the same
     * image (execve of a script without #! fails, then libc reruns it via /bin/sh).
     * Shifting the fingerprint simulates the application image having loaded: from then
     * on execve is faulted, also after the fingerprint returns, because the start
     * exemption is spent. */
    assert(decide(__NR_execve, 0U).action == CHAOS_INIT_PASS);
    assert(decide(__NR_execve, 0U).action == CHAOS_INIT_PASS);
    g_start_offset = 7U;
    assert(fails(decide(__NR_execve, 0U), EACCES));
    g_start_offset = 0U;
    assert(fails(decide(__NR_execve, 0U), EACCES));
    verdict = decide(__NR_execveat, 0U);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 3U && verdict.error == 0);

    /* clone maps by flags; clone3 reads the flags from its argument structure in the
     * caller's memory, and a NULL (unreadable) structure falls back to fork. */
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

    /* FAIL_AFTER,1: the first wait passes, later ones fail; wait4 and waitid share the
     * waitpid counter. The parked child has its own counter, so its first wait passes
     * although this process's counter is exhausted. */
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

    /* A reload (new text, so a new load) restarts this process's counters from 0. */
    write_rules("waitpid:FAIL_AFTER:EINTR,1 # reloaded\n");
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide(__NR_wait4, 0U), EINTR));

    /* A fork child starts with its parent's counts at the fork, as an LD_PRELOAD child
     * inherits them with its memory. One decided fork has one child: `forked` takes the
     * counts (first wait fails), `later` was never decided as a fork and starts at 0. */
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

    /* Counts of a fork decided under an earlier load are not handed on: after the
     * reload the child starts from 0, as its parent does. */
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

    /* Pid reuse: a shifted fingerprint on the same pid is a new process, which gets a
     * fresh entry and counts from 0 instead of the old holder's exhausted counter. */
    g_start_offset = 1U;
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    assert(fails(decide(__NR_wait4, 0U), EINTR));
    g_start_offset = 0U;

    /* Fail-open for a vanished caller: with the lookup failing, no hit slot exists, so
     * FAIL_AFTER, ERRNO and LATENCY all pass the call through uncounted. */
    g_fail_process = 1;
    assert(decide(__NR_wait4, 0U).action == CHAOS_INIT_PASS);
    write_rules("fork:ERRNO:ENOMEM\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    write_rules("fork:LATENCY:10\n");
    assert(decide(__NR_clone, SIGCHLD).action == CHAOS_INIT_PASS);
    g_fail_process = 0;

    /* Probability 0 never fires: neither the delay nor the errno leaks into the verdict. */
    write_rules("fork:LATENCY:10@0.0\nfork:ERRNO:ENOMEM@0.0\n");
    verdict = decide(__NR_clone, SIGCHLD);
    assert(verdict.action == CHAOS_INIT_PASS && verdict.error == 0);

    /* posix_spawnp is indistinguishable from posix_spawn at the system call level, so
     * such a rule could never fire; the whole file is rejected (the fork rule on line 1
     * does not apply) and the status file names line 2. A `*` selector still matches. */
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
