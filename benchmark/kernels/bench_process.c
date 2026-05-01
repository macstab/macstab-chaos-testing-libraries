/**
 * @file bench_process.c
 * @brief Stage 3 microbenchmarks for libchaos-process.
 *
 * @details
 * Three benchmarks against `pthread_create + pthread_join` of a no-op
 * thread.  This exercises the chaos-process library's `pthread_create`
 * interception cost without the full ~100 µs of `fork()` (which would
 * dominate any per-call overhead measurement).
 *
 *  1. `pthread_create_passthrough`   — no rule loaded.
 *  2. `pthread_create_match_no_fire` — probability=0 rule on `pthread_create`.
 *  3. `pthread_create_errno`         — probability=1 EAGAIN injection.
 *
 * For `fork()` and `posix_spawn()`, use `--mode=SINGLE_SHOT` against a
 * dedicated single-shot benchmark (Stage 4); their per-call cost is too
 * high for a million-iteration loop.
 *
 * The thread function does nothing; per-iteration cost is dominated
 * by clone, stack alloc, and join.  On Linux glibc this is ~10 µs;
 * the chaos library's overhead is on the order of nanoseconds, so a
 * detectable signal requires careful statistics — we run with
 * `--iters=20000` by default in `run-bench.sh` to match the higher
 * per-call cost while keeping the run under a minute.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
