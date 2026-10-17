/**
 * @file chaos_bench.h
 * @brief Public API of the benchmark harness: descriptor registration and
 *        optimizer barriers for benchmark kernels.
 *
 * @details
 * The harness measures the per-call cost of the `libchaos-<lib>` wrappers (pass-through, rule
 * match without firing, rule firing) against an unpreloaded baseline. It owns the timer, the
 * dead-code-elimination barriers, the percentile statistics, host-environment capture and the
 * JSON envelope. Isolation (CPU pinning, governor, IRQ steering, LD_PRELOAD) is the caller's
 * job: `run-bench.sh` in Docker on a developer machine, or a tuned bare-metal Linux host.
 *
 * **Operational model.**
 * One process runs one benchmark. `run-bench.sh` executes the binary once per benchmark name
 * so each run starts with a fresh address space and cold predictor, cache and TLB state, and
 * so a crashing kernel cannot contaminate the next one. There is no in-process scheduler; the
 * iteration callback runs on the main thread only.
 *
 * **Execution mode.**
 * At startup the runner checks host isolation (chaos_bench_isolation.c) and tags the JSON
 * envelope:
 *  - `OFFICIAL`: every check passed: governor `performance`, a non-empty
 *    `/sys/devices/system/cpu/isolated`, no `/.dockerenv`, SMT off on cpu0 and, on x86, the
 *    `constant_tsc` and `nonstop_tsc` CPU flags.
 *  - `ADVISORY`: at least one check failed. Numbers are still computed and the envelope lists
 *    each failure; they are fit for same-host A/B comparison, not for citation.
 *
 * Docker on a developer machine is always `ADVISORY` because the container cannot control the
 * host's scheduler, governor or IRQ affinity. The harness binary is identical in both settings.
 *
 * **Measurement hazards the harness handles.**
 * 1. Dead-code elimination, constant folding and loop-invariant hoisting:
 *    @ref CHAOS_BENCH_DO_NOT_OPTIMIZE and @ref CHAOS_BENCH_CLOBBER_MEMORY.
 * 2. Timer reordering: serializing `rdtscp`+`lfence` (x86) or `isb; mrs cntvct_el0; isb`
 *    (aarch64) reads with a compiler memory clobber (chaos_bench_timer.c).
 * 3. Cold-call effects (lazy PLT binding, first TLS access, first rule-file load, page
 *    faults): a warmup loop of `--warmup` iterations (default 10000) before measurement.
 * 4. Timer-read cost dominating sub-100 ns operations: `--batch=N` times N calls per timing
 *    window and reports the per-call quotient. Batching is manual, never automatic.
 *
 * **Delegated to the caller.**
 * - CPU pinning (`taskset`, `--cpuset-cpus`, `sched_setaffinity`).
 * - Governor configuration (`cpupower`, `/sys/.../scaling_governor`).
 * - SMT-sibling shutdown (`/sys/devices/system/cpu/cpu*\/online`).
 * - IRQ affinity (`/proc/irq/\*\/smp_affinity`).
 * - Dropping caches between trials (`/proc/sys/vm/drop_caches`).
 * - Setting LD_PRELOAD before exec.
 *
 * Cross-run statistics (Wilcoxon rank-sum test, bootstrap confidence interval on the median
 * delta) live in `driver/chaos_bench_driver.py`, which aggregates several envelopes per
 * benchmark; this harness reports one run.
 *
 * **Thread-safety.** `chaos_bench_register` and @ref CHAOS_BENCH are for ELF constructors
 * only. Nothing enforces this, but the registry has no locking. Benchmark callbacks run
 * single-threaded.
 *
 * **Stability.** The names in this header are the source contract for benchmark kernels.
 * Reordering the fields of @ref chaos_bench_descriptor_t breaks @ref CHAOS_BENCH, which
 * initialises the struct positionally.
 */

#ifndef CHAOS_BENCH_H
#define CHAOS_BENCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Measurement mode, named after JMH's `@BenchmarkMode`.
 *
 * @details The runner records one sample per timing window in every mode; the modes differ
 * only as listed below. The mode name is echoed in the envelope's `config.mode`.
 * - `AVG_TIME` (default): `--iters` timing windows; statistics over all samples.
 * - `THROUGHPUT`: accepted by `--mode` but not implemented as a time-boxed loop; the runner
 *   measures it exactly like `AVG_TIME`. It is absent from the `--help` text.
 * - `SAMPLE_TIME`: measured exactly like `AVG_TIME`; kept for JMH naming parity.
 * - `SINGLE_SHOT`: one timing window (still `--batch` calls), one sample. For cold-path
 *   costs, run with `--warmup=0`. The envelope still reports the requested `--iters` as
 *   `measurement_iters`; `stats.samples` is 1.
 */
typedef enum chaos_bench_mode
{
    CHAOS_BENCH_MODE_AVG_TIME    = 0,
    CHAOS_BENCH_MODE_THROUGHPUT,
    CHAOS_BENCH_MODE_SAMPLE_TIME,
    CHAOS_BENCH_MODE_SINGLE_SHOT
} chaos_bench_mode_t;

/**
 * @brief Optional setup callback, run once before warmup.
 *
 * @details Called after the zero-initialised state buffer is allocated and after the
 * scenario rule file is installed, before the sample buffer is allocated and before warmup.
 * It may allocate, open descriptors and write @p user_state. It has no error return: a setup
 * that cannot establish its precondition must `abort()`, because measuring a half-initialised
 * kernel produces plausible but wrong numbers.
 *
 * @param[in,out] user_state  The descriptor's state buffer (`state_size` bytes, at least 1);
 *                            never NULL.
 */
typedef void (*chaos_bench_setup_fn)(void *user_state);

/**
 * @brief Iteration callback, the measured operation.
 *
 * @details Called through a function pointer, so the call itself is never inlined into the
 * timing loop and its cost (a few ns) is part of every sample, identically for baseline and
 * preloaded runs. Each call must do the same work; route results through
 * @ref CHAOS_BENCH_DO_NOT_OPTIMIZE so the compiler cannot elide them. One sample is the cost
 * of `batch_size` consecutive calls divided by `batch_size`.
 *
 * @param[in,out] user_state  The descriptor's state buffer; never NULL.
 */
typedef void (*chaos_bench_iter_fn)(void *user_state);

/**
 * @brief Optional teardown callback.
 *
 * @details Called after the measurement loop and after statistics are computed, before the
 * JSON envelope is written. The harness frees the state buffer itself right afterwards, so
 * teardown only releases resources the state refers to (descriptors, mappings, child
 * processes). Not called if the sample-buffer allocation after setup fails (exit code 6).
 *
 * @param[in,out] user_state  The descriptor's state buffer; never NULL.
 */
typedef void (*chaos_bench_teardown_fn)(void *user_state);

/**
 * @brief Static descriptor for one benchmark, emitted and registered by @ref CHAOS_BENCH.
 *
 * @details Each @ref CHAOS_BENCH expansion defines one descriptor plus an ELF constructor
 * that links it into the global registry before `main`. A binary may register at most
 * `CHAOS_BENCH_MAX_REGISTERED` (256) descriptors; registration aborts beyond that.
 *
 * The macro fills every field; benchmark code must not modify the descriptor afterwards.
 * `next` belongs to the registry and must start as NULL.
 */
typedef struct chaos_bench_descriptor
{
    const char              *name;       /**< Unique within the binary. */
    const char              *category;   /**< Subsystem tag, e.g. "time". */
    chaos_bench_setup_fn     setup;      /**< Optional; may be NULL. */
    chaos_bench_iter_fn      iter;       /**< Required; must not be NULL. */
    chaos_bench_teardown_fn  teardown;   /**< Optional; may be NULL. */
    size_t                   state_size; /**< Bytes allocated for user_state. */
    struct chaos_bench_descriptor *next; /**< Internal: registry link. */
} chaos_bench_descriptor_t;

/**
 * @brief Prepends @p desc to the global registry.
 *
 * @details Called by the constructor that @ref CHAOS_BENCH emits. Head insertion keeps
 * registration O(1); the resulting order follows constructor order, which neither C nor the
 * linker specifies across translation units, so nothing may depend on it (`--list` output
 * order included).
 *
 * Aborts with a message on stderr if @p desc is NULL, if `desc->iter` is NULL, or if 256
 * descriptors are already registered: each is a build defect that must not yield a binary
 * that silently skips benchmarks.
 *
 * @param[in,out] desc  Statically allocated descriptor. The registry keeps the pointer for the
 *                      lifetime of the process and writes `desc->next`.
 */
void chaos_bench_register(chaos_bench_descriptor_t *desc);

/**
 * @brief Optimizer barrier: forces the value @p p to be materialised.
 *
 * @details Same technique as Google Benchmark's `DoNotOptimize`. The empty asm takes @p p as
 * an input operand, so the compiler must compute it (no dead-code elimination of the producing
 * call), and declares a `"memory"` clobber, so the compiler must assume the asm reads and
 * writes any memory (no hoisting or sinking of loads and stores across it).
 *
 * The `"r,m"` alternative constraint lets the compiler keep the operand in a register or in
 * memory, whichever is cheaper; the asm emits no instructions, so the barrier costs nothing at
 * run time beyond the work it preserves.
 *
 * @param p  An lvalue or rvalue whose computation must survive, passed by value (for example
 *           `s->rc`). The macro does not take its address.
 */
#define CHAOS_BENCH_DO_NOT_OPTIMIZE(p) \
    do { __asm__ volatile("" : : "r,m"(p) : "memory"); } while (0)

/**
 * @brief Optimizer barrier: assumes all memory may have been read and written.
 *
 * @details Same technique as Google Benchmark's `ClobberMemory`. Emits no instructions. Use
 * it where a kernel's stores must be treated as observed, or between steps that the compiler
 * could otherwise merge or move across loop iterations; @ref CHAOS_BENCH_DO_NOT_OPTIMIZE only
 * anchors a single value. The runner itself places one on both sides of every timing window.
 */
#define CHAOS_BENCH_CLOBBER_MEMORY() \
    do { __asm__ volatile("" : : : "memory"); } while (0)

/**
 * @brief Defines and registers one benchmark.
 *
 * @details
 * Usage:
 * @code
 *     CHAOS_BENCH("time", clock_gettime_passthrough,
 *                 my_state_t, my_setup, my_iter, my_teardown);
 * @endcode
 *
 * Expands to a file-scope `static chaos_bench_descriptor_t chaos_bench_desc_<name>` and a
 * `static` constructor `chaos_bench_ctor_<name>` that passes it to `chaos_bench_register`.
 * Both are `static`, so equal names in different translation units do not collide at link
 * time; `chaos_bench_registry_find` then returns whichever registered last.
 *
 * @param category_lit  Subsystem tag as a quoted string expression, e.g. `"time"`. The macro
 *                      does not stringify it. Values used by the kernels: `"io"`, `"net"`,
 *                      `"dns"`, `"time"`, `"memory"`, `"process"`, `"meta"`.
 * @param name_lit      Benchmark identifier, a bare C identifier. Stringified as the JSON
 *                      `benchmark.name` and matched against `--benchmark=`.
 * @param state_type    Type of the per-benchmark state; the runner allocates
 *                      `sizeof(state_type)` zeroed bytes. Use any small type (e.g. `int`)
 *                      when no state is needed.
 * @param setup_fn      Setup callback or NULL.
 * @param iter_fn       Iteration callback; must not be NULL (registration aborts).
 * @param teardown_fn   Teardown callback or NULL.
 */
#define CHAOS_BENCH(category_lit, name_lit, state_type, setup_fn, iter_fn, teardown_fn) \
    static chaos_bench_descriptor_t chaos_bench_desc_##name_lit = {        \
        /* .name      = */ #name_lit,                                      \
        /* .category  = */ (category_lit),                                 \
        /* .setup     = */ (setup_fn),                                     \
        /* .iter      = */ (iter_fn),                                      \
        /* .teardown  = */ (teardown_fn),                                  \
        /* .state_size= */ sizeof(state_type),                             \
        /* .next      = */ (chaos_bench_descriptor_t *)0                   \
    };                                                                     \
    __attribute__((constructor)) static void                               \
    chaos_bench_ctor_##name_lit(void)                                      \
    {                                                                      \
        chaos_bench_register(&chaos_bench_desc_##name_lit);                \
    }

#ifdef __cplusplus
}
#endif

#endif /* CHAOS_BENCH_H */
