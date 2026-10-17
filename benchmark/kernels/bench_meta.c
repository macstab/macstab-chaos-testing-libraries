/**
 * @file bench_meta.c
 * @brief Harness self-validation kernels: they measure the harness, not a libchaos library.
 *
 * @details
 * `make -f benchmark/Makefile.bench bench-validate` runs both kernels (1000 warmup,
 * 10000 measured iterations) and prints the expected range before each result. The
 * check is by eye: nothing asserts on the numbers. Neither kernel is part of the
 * `run-bench.sh` sweep and neither is run under LD_PRELOAD.
 *
 * | Kernel           | Iteration body                                 | Expected     |
 * |------------------|------------------------------------------------|--------------|
 * | `nop_loop_1k`    | 1000 dependent 64-bit additions on a register  | 300–3000 ns  |
 * | `clock_overhead` | one `clock_gettime(CLOCK_MONOTONIC_RAW)`       | 5–30 ns      |
 *
 * Reading the results:
 *  - `nop_loop_1k` far outside its range points at timer calibration (cycle-to-ns
 *    conversion). The loop has a closed form (`seed + 499500`); if the compiler applies
 *    final-value replacement the body collapses to one add and the result drops to a
 *    few ns. A result far below 300 ns therefore indicates folding, not a fast host.
 *  - `clock_overhead` is the cost of one vDSO clock read. If the envelope's
 *    `timer.overhead_ns` is of the same order, the harness's own timer reads dominate any
 *    kernel that costs only a few tens of ns, and `--batch` is required for it.
 */

#include "chaos_bench.h"

#include <stdint.h>
#include <time.h>

/* ---- nop_loop_1k -------------------------------------------------------- */

typedef struct bench_meta_loop_state
{
    uint64_t seed; /**< Runtime start value, so the final sum is not a compile-time constant. */
    uint64_t sink; /**< Loop result; CHAOS_BENCH_DO_NOT_OPTIMIZE keeps the loop alive. */
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
