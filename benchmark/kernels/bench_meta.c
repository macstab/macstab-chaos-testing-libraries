/**
 * @file bench_meta.c
 * @brief Harness self-validation benchmarks.
 *
 * @details
 * Two kernels that validate the benchmark harness itself rather than a
 * chaos library:
 *
 *  1. `nop_loop_1k` — accumulates 1000 integer additions with no memory
 *     traffic beyond the single state slot.  Expected cost: ~300–3000 ns/iter
 *     (loop body + branch prediction), depending on the host.  If the harness
 *     reports a value far outside this range, the timer calibration is suspect.
 *
 *  2. `clock_overhead` — one `clock_gettime(CLOCK_MONOTONIC_RAW)` call per
 *     iteration, measuring the vDSO overhead in isolation.  Expected: 5–30
 *     ns/iter on a modern Linux/vDSO host.  If the harness overhead_ns field
 *     is comparable to or larger than this number, the harness's own timer
 *     reads are too expensive for the workloads being measured.
 *
 * These kernels are used by `make bench-validate` to assert that the harness
 * is producing plausible numbers on the current host.
 */

#include "chaos_bench.h"

#include <stdint.h>
#include <time.h>

/* ---- nop_loop_1k -------------------------------------------------------- */

typedef struct bench_meta_loop_state
{
    uint64_t seed; /**< Prevents the compiler from constant-folding the loop. */
    uint64_t sink; /**< Receives the loop result; kept live by DO_NOT_OPTIMIZE. */
} bench_meta_loop_state_t;

static void bench_meta_loop_setup(void *user_state)
{
    bench_meta_loop_state_t *s = (bench_meta_loop_state_t *)user_state;
    s->seed = 0x123456789abcdef0ULL;
    s->sink = 0;
}

static void bench_meta_loop_iter(void *user_state)
{
    bench_meta_loop_state_t *s = (bench_meta_loop_state_t *)user_state;
    uint64_t x = s->seed;
    int      i;
    for (i = 0; i < 1000; ++i)
        x += (uint64_t)i;
    s->sink = x;
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->sink);
}

/* ---- clock_overhead ----------------------------------------------------- */

typedef struct bench_meta_clock_state
{
    struct timespec ts;
    int             rc;
} bench_meta_clock_state_t;

static void bench_meta_clock_iter(void *user_state)
{
    bench_meta_clock_state_t *s = (bench_meta_clock_state_t *)user_state;
    s->rc = clock_gettime(CLOCK_MONOTONIC_RAW, &s->ts);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->ts.tv_nsec);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
}

/* ---- registration ------------------------------------------------------- */

CHAOS_BENCH("meta", nop_loop_1k, bench_meta_loop_state_t,
            bench_meta_loop_setup, bench_meta_loop_iter, NULL)

CHAOS_BENCH("meta", clock_overhead, bench_meta_clock_state_t,
            NULL, bench_meta_clock_iter, NULL)
