/**
 * @file bench_time.c
 * @brief Stage 1 microbenchmarks for libchaos-time.
 *
 * @details
 * This binary registers three benchmarks for the libchaos-time hot path:
 *
 *  1. `clock_gettime_baseline` — calls `clock_gettime(CLOCK_MONOTONIC)`
 *     in a tight loop with no chaos rule installed.  When run *without*
 *     LD_PRELOAD, this is the absolute reference: pure libc / vDSO cost.
 *     When run *with* LD_PRELOAD and an empty chaos config, this measures
 *     the *passthrough* overhead — the cost added by the TLS guard, the
 *     snapshot pointer load, and the early-return path.
 *
 *  2. `clock_gettime_match_no_fire` — same call, but a probability=0
 *     rule is installed so the rule scan executes but never fires.
 *     Measures the cost of selector-match + dice-roll vs passthrough.
 *
 *  3. `clock_gettime_errno` — same call, but a probability=1 ERRNO rule
 *     is installed so every call returns -1 with `errno=EINVAL`.  Measures
 *     the full effect-dispatch path including the synthetic error setup.
 *
 * The wrapper script (`run-bench.sh`) decides whether to launch the
 * binary with or without LD_PRELOAD; the C code is identical in both.
 * That keeps "baseline vs treatment" a single concept rather than a
 * branching maintenance burden.
 *
 * **What the benchmarks DO measure.**
 *  - User-space cost of one clock_gettime call (vDSO under glibc, libc
 *    syscall wrapper under LD_PRELOAD interposition).
 *  - The chaos library's per-call overhead in each path (passthrough,
 *    rule-scan, effect dispatch).
 *
 * **What the benchmarks DO NOT measure.**
 *  - Cold-call cost: warmup absorbs first-PLT / first-TLS / first-config
 *    overhead.  Use `--mode=SINGLE_SHOT` benchmarks for that (Stage 2).
 *  - Reload-cycle cost: that's a separate `bench_reload.c` binary
 *    (Stage 2).
 *  - vDSO bypass cost: libchaos-time interposes the libc PLT entry,
 *    which on glibc is itself the vDSO dispatcher — the interposition
 *    captures the call before vDSO routing happens, so we measure the
 *    full libc path on the treatment side regardless of how the
 *    baseline routes.  This is documented behavior, not a regression.
 *
 * **Anti-DCE protocol.**
 * Every iteration writes to `state->result` (so the call has an
 * observable effect) and immediately marks the result live with
 * `CHAOS_BENCH_DO_NOT_OPTIMIZE`.  The compiler is forbidden from
 * eliminating either the call or the store.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Per-benchmark state: a single timespec result slot.
 *
 * @details The slot is reused across iterations.  Because the harness
 * marks `result` as live after each call, the compiler cannot fold the
 * store away or hoist the call out of the loop.
 */
typedef struct bench_time_state
{
    struct timespec result;
    int             rc;
} bench_time_state_t;

/**
 * @brief Iter callback for all three benchmarks: one clock_gettime call.
 *
 * @details The body is identical regardless of whether LD_PRELOAD
 * intercepts the symbol — the harness measures the call in both
 * configurations and the wrapper attributes the delta to the chaos
 * library's overhead.
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
 * `nanosleep` with a {0,0} timespec.  Linux returns immediately without
 * scheduling away.  Tests the chaos hook on the cheapest possible
 * `nanosleep` invocation.
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
 * `usleep(0)` — POSIX micro-sleep with zero microseconds.  Maps onto
 * nanosleep on Linux but goes through the libc usleep wrapper, exercising
 * the libchaos-time `usleep` hook specifically (separate dispatch from
 * `nanosleep`).
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
