/**
 * @file bench_process.c
 * @brief Per-call overhead of the libchaos-process wrappers for thread and process creation.
 *
 * @details
 * Each hooked call has `_passthrough`, `_match_no_fire` and `_errno` variants sharing
 * one iteration body. `run-bench.sh` runs each without LD_PRELOAD (baseline) and with
 * LD_PRELOAD=libchaos-process.so plus `benchmark/scenarios/process-<stem>-*.conf`
 * copied to the rule file `/tmp/.chaos-process.conf` (treatment).
 *
 * | Kernel           | Iteration                                     | Iteration cap |
 * |------------------|-----------------------------------------------|---------------|
 * | `pthread_create` | create + join a thread that returns at once   | 20000         |
 * | `waitpid_nohang` | `waitpid(-1, WNOHANG)` with no children        | default       |
 * | `fork_wait`      | fork; child `_exit(0)`; parent waitpid        | 5000          |
 * | `execve_short`   | fork; child execve("/bin/true"); parent wait  | 1000          |
 *
 * The caps in `run-bench.sh` keep the slow kernels (tens to hundreds of microseconds
 * per iteration in the 1.0.1 matrix) to a bounded run time. Those iterations are
 * dominated by clone, page-table copy, exec and reaping, so the relative wrapper
 * overhead is far smaller than for the sub-microsecond kernels of the other binaries.
 *
 * Scenario status at this revision: every process scenario writes the probability as
 * `ERRNO:<name>,<p>`, but libchaos-process expects `ERRNO:<name>@<p>`. The rule is
 * rejected, so `_match_no_fire` and `_errno` measure the passthrough path. See the
 * scenario files.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct bench_process_state
{
    int rc;
} bench_process_state_t;

static void *bench_process_thread_main(void *arg)
{
    (void)arg;
    return NULL;
}

static void bench_process_iter_pthread_create(void *user_state)
{
    bench_process_state_t *s = (bench_process_state_t *)user_state;
    pthread_t              tid;

    s->rc = pthread_create(&tid, NULL, bench_process_thread_main, NULL);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    if (s->rc == 0)
    {
        (void)pthread_join(tid, NULL);
    }
}

CHAOS_BENCH("process", pthread_create_passthrough,    bench_process_state_t,
            NULL, bench_process_iter_pthread_create, NULL)
CHAOS_BENCH("process", pthread_create_match_no_fire,  bench_process_state_t,
            NULL, bench_process_iter_pthread_create, NULL)
CHAOS_BENCH("process", pthread_create_errno,          bench_process_state_t,
            NULL, bench_process_iter_pthread_create, NULL)

/* -------------------------------------------------------------- fork_wait ---
 * fork, child `_exit(0)` (no atexit handlers, no stdio flush of inherited buffers),
 * parent waitpid. Hooked calls on the timed path: fork and waitpid.
 */
static void bench_process_iter_fork_wait(void *user_state)
{
    bench_process_state_t *s = (bench_process_state_t *)user_state;
    pid_t pid = fork();
    if (pid == 0) {
        _exit(0);
    }
    s->rc = pid;
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    if (pid > 0) {
        int status = 0;
        (void)waitpid(pid, &status, 0);
        CHAOS_BENCH_DO_NOT_OPTIMIZE(status);
    }
}

CHAOS_BENCH("process", fork_wait_passthrough,    bench_process_state_t,
            NULL, bench_process_iter_fork_wait, NULL)
CHAOS_BENCH("process", fork_wait_match_no_fire,  bench_process_state_t,
            NULL, bench_process_iter_fork_wait, NULL)
CHAOS_BENCH("process", fork_wait_errno,          bench_process_state_t,
            NULL, bench_process_iter_fork_wait, NULL)

/* ----------------------------------------------------------- waitpid_nohang ---
 * `waitpid(-1, &status, WNOHANG)` with no children: returns -1/ECHILD at once. The
 * cheapest call that still enters the waitpid wrapper; no reaping is involved. The
 * `_errno` scenario injects the same ECHILD.
 */
static void bench_process_iter_waitpid_nohang(void *user_state)
{
    bench_process_state_t *s = (bench_process_state_t *)user_state;
    int status = 0;
    s->rc = (int)waitpid((pid_t)-1, &status, WNOHANG);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(status);
}

CHAOS_BENCH("process", waitpid_nohang_passthrough,    bench_process_state_t,
            NULL, bench_process_iter_waitpid_nohang, NULL)
CHAOS_BENCH("process", waitpid_nohang_match_no_fire,  bench_process_state_t,
            NULL, bench_process_iter_waitpid_nohang, NULL)
CHAOS_BENCH("process", waitpid_nohang_errno,          bench_process_state_t,
            NULL, bench_process_iter_waitpid_nohang, NULL)

/* ----------------------------------------------------------- execve_short ---
 * fork, child execve("/bin/true") with an empty environment, parent waitpid. The
 * empty envp drops LD_PRELOAD, so /bin/true runs without the library and the timed
 * cost is the same exec in both arms; only the fork and execve wrappers differ. If
 * execve fails the child exits 127. /bin/true exists in both the Debian and Alpine
 * benchmark images.
 */
static void bench_process_iter_execve_short(void *user_state)
{
    bench_process_state_t *s = (bench_process_state_t *)user_state;
    static char * const argv[] = { (char *)"/bin/true", (char *)NULL };
    static char * const envp[] = { (char *)NULL };
    pid_t pid = fork();
    if (pid == 0) {
        (void)execve("/bin/true", argv, envp);
        _exit(127);
    }
    s->rc = pid;
    if (pid > 0) {
        int status = 0;
        (void)waitpid(pid, &status, 0);
        CHAOS_BENCH_DO_NOT_OPTIMIZE(status);
    }
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

CHAOS_BENCH("process", execve_short_passthrough,    bench_process_state_t,
            NULL, bench_process_iter_execve_short, NULL)
CHAOS_BENCH("process", execve_short_match_no_fire,  bench_process_state_t,
            NULL, bench_process_iter_execve_short, NULL)
CHAOS_BENCH("process", execve_short_errno,          bench_process_state_t,
            NULL, bench_process_iter_execve_short, NULL)
