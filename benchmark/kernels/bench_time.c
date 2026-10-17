/**
 * @file bench_time.c
 * @brief Per-call overhead of the libchaos-time wrappers for clock_gettime, nanosleep, usleep.
 *
 * @details
 * Every hooked function gets three registered benchmarks that share one iteration body.
 * `run-bench.sh` runs each name twice: once without LD_PRELOAD (baseline: the libc
 * call alone) and once with LD_PRELOAD=libchaos-time.so plus a scenario written to the
 * rule file `/tmp/.chaos-time.conf` (treatment). The driver attributes the median
 * difference to the wrapper. Keeping the C code identical in both arms is what makes
 * the difference attributable; the arms differ only in the process environment.
 *
 * | Suffix           | Scenario (`benchmark/scenarios/`)     | Wrapper path measured        |
 * |------------------|---------------------------------------|------------------------------|
 * | `_passthrough`   | `empty.conf` (no rules)               | wrapper with empty rule set  |
 * | `_match_no_fire` | `<stem>-match-no-fire.conf`, prob 0.0 | rule scan + probability draw |
 * | `_errno`         | `<stem>-errno.conf`, ERRNO, prob 1.0  | full effect dispatch         |
 *
 * `clock_gettime_baseline` plays the `_passthrough` role for clock_gettime; its name
 * predates the suffix convention and the sweep keeps it.
 *
 * Measured:
 *  - One call through the real function. With LD_PRELOAD the wrapper forwards to the
 *    libc clock_gettime resolved with `dlsym(RTLD_NEXT)`, which still uses the vDSO, so
 *    both arms include the vDSO read and the delta is the wrapper alone. Before the
 *    real function is resolved the wrapper issues `syscall(SYS_clock_gettime)`; warmup
 *    runs past that window.
 *  - The `_errno` arm skips the real function, so its delta is wrapper cost minus the
 *    skipped libc/kernel work and can be negative for the sleep calls.
 *
 * Not measured:
 *  - Cold-call cost (first PLT resolution, first TLS access, first rule-file load):
 *    warmup absorbs it. `--mode=SINGLE_SHOT` times a single call of any benchmark;
 *    `run-bench.sh` does not use it.
 *  - Reload cost: no kernel rewrites the rule file during measurement.
 *
 * Anti-DCE: each iteration stores the return value (and, for clock_gettime, the
 * timespec) in the state and passes it through CHAOS_BENCH_DO_NOT_OPTIMIZE, so the
 * compiler can remove neither the call nor the store.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Per-benchmark state for the clock_gettime kernels: output timespec and return code.
 *
 * @details Reused across iterations. The kernel marks both fields live after every
 * call, so the store cannot be dropped and the call cannot be hoisted out of the loop.
 */
typedef struct bench_time_state
{
    struct timespec result;
    int             rc;
} bench_time_state_t;

/**
 * @brief Iteration body of all three clock_gettime benchmarks: one
 *        `clock_gettime(CLOCK_MONOTONIC)` call.
 *
 * @details In the `_errno` arm the call returns -1 with errno EINVAL and leaves
 * `result` unwritten; the kernel does not check either, because only the timing matters.
 */
static void bench_time_iter_clock_gettime(void *user_state)
{
    bench_time_state_t *s = (bench_time_state_t *)user_state;
    s->rc = clock_gettime(CLOCK_MONOTONIC, &s->result);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->result);
}

CHAOS_BENCH("time", clock_gettime_baseline,
            bench_time_state_t,
            NULL, bench_time_iter_clock_gettime, NULL)

CHAOS_BENCH("time", clock_gettime_match_no_fire,
            bench_time_state_t,
            NULL, bench_time_iter_clock_gettime, NULL)

CHAOS_BENCH("time", clock_gettime_errno,
            bench_time_state_t,
            NULL, bench_time_iter_clock_gettime, NULL)

/* ---------------------------------------------------------- nanosleep_zero ---
 * `nanosleep({0, 0})`: the cheapest call that still enters the nanosleep wrapper and,
 * in the baseline and the first two arms, a real syscall. The `_errno` arm returns
 * -1/EINTR without the syscall.
 */
typedef struct bench_time_sleep_state
{
    struct timespec req;
    struct timespec rem;
    int             rc;
} bench_time_sleep_state_t;

static void bench_time_iter_nanosleep_zero(void *user_state)
{
    bench_time_sleep_state_t *s = (bench_time_sleep_state_t *)user_state;
    s->req.tv_sec  = 0;
    s->req.tv_nsec = 0;
    s->rc = nanosleep(&s->req, &s->rem);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

CHAOS_BENCH("time", nanosleep_zero_passthrough,    bench_time_sleep_state_t,
            NULL, bench_time_iter_nanosleep_zero, NULL)
CHAOS_BENCH("time", nanosleep_zero_match_no_fire,  bench_time_sleep_state_t,
            NULL, bench_time_iter_nanosleep_zero, NULL)
CHAOS_BENCH("time", nanosleep_zero_errno,          bench_time_sleep_state_t,
            NULL, bench_time_iter_nanosleep_zero, NULL)

/* ------------------------------------------------------------- usleep_zero ---
 * `usleep(0)`: exercises the separate usleep wrapper and its rule selector. The real
 * usleep runs with the wrapper's reentrancy guard raised, so a libc usleep built on
 * nanosleep does not pass through the nanosleep wrapper a second time.
 */
typedef struct bench_time_usleep_state
{
    int rc;
} bench_time_usleep_state_t;

static void bench_time_iter_usleep_zero(void *user_state)
{
    bench_time_usleep_state_t *s = (bench_time_usleep_state_t *)user_state;
    s->rc = usleep(0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

CHAOS_BENCH("time", usleep_zero_passthrough,    bench_time_usleep_state_t,
            NULL, bench_time_iter_usleep_zero, NULL)
CHAOS_BENCH("time", usleep_zero_match_no_fire,  bench_time_usleep_state_t,
            NULL, bench_time_iter_usleep_zero, NULL)
CHAOS_BENCH("time", usleep_zero_errno,          bench_time_usleep_state_t,
            NULL, bench_time_iter_usleep_zero, NULL)
