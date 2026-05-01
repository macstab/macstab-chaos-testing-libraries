/**
 * @file chaos_bench.h
 * @brief Public API of the chaos-testing-libraries benchmark harness.
 *
 * @details
 * A JMH-class benchmark harness, in C, for the LD_PRELOAD `.so` libraries in
 * this repository.  The harness is intentionally minimal in surface and
 * uncompromising in measurement discipline: it owns the timer, the
 * dead-code-elimination defenses, the percentile statistics, and the
 * environment capture, and delegates *isolation* (CPU pinning, governor,
 * IRQ steering) to a wrapper layer (Docker on Tier 1 — every developer
 * machine; bare-metal Linux on Tier 2 — release-grade host).
 *
 * **Operational model.**
 * One process executes one benchmark, start to finish.  A wrapper script
 * (`run-bench.sh`) invokes the binary once per benchmark name so each run
 * gets a fresh address space, a virgin branch predictor, and uncontaminated
 * cache / TLB state.  There is no in-process scheduler.  Concurrent
 * benchmarks are out of scope for Stage 1 — a benchmark function executes
 * on a single thread per process invocation.
 *
 * **Mode advertisement.**
 * The harness inspects the host at startup and publishes its execution mode
 * in the JSON envelope:
 *  - `OFFICIAL` — every isolation precondition holds (governor=performance,
 *    `isolcpus` contains the bound CPU, no SMT sibling co-tenant, …).
 *  - `ADVISORY` — at least one precondition failed; results are still
 *    computed and reported, but the JSON carries explicit warnings and
 *    must not be cited as authoritative.
 *
 * Tier 1 (Docker on a developer machine) is intrinsically `ADVISORY`
 * because the kernel scheduler, frequency governor, and IRQ affinity are
 * controlled by the host OS, not by the container.  Tier 2 (a host with
 * `isolcpus`/`nohz_full`/`rcu_nocbs` at boot, governor pinned, IRQs
 * steered) elevates the same harness to `OFFICIAL`.  The harness itself
 * is identical across tiers.
 *
 * **What the harness defends against.**
 * 1. Dead-code elimination, constant folding, and hoisting by the
 *    optimizer — see @ref CHAOS_BENCH_DO_NOT_OPTIMIZE and
 *    @ref CHAOS_BENCH_CLOBBER_MEMORY.
 * 2. Timer skew and reordering — see @ref chaos_bench_timer.h
 *    (rdtscp/cntvct serialized read with full memory clobber).
 * 3. Cold-call effects (TLS init, lazy PLT resolution, page faults) —
 *    handled by configurable warmup iterations.
 * 4. Sub-µs-op timer-overhead tax — handled by batching: the harness can
 *    measure groups of N ops per timing window when single-op cost falls
 *    below the timer cost threshold.
 *
 * **What the harness does NOT do (delegated to the wrapper).**
 * - CPU pinning (`taskset` / `--cpuset-cpus` / `sched_setaffinity`).
 * - Governor configuration (`cpupower` / `/sys/.../scaling_governor`).
 * - SMT-sibling shutdown (`/sys/devices/system/cpu/cpu*\/online`).
 * - IRQ affinity changes (`/proc/irq/\*\/smp_affinity`).
 * - Drop-caches between trials (`/proc/sys/vm/drop_caches`).
 * - LD_PRELOAD setup (the wrapper sets it before exec).
 *
 * **Stage scope.**
 * Stage 1 (this version) covers: TSC-based timing on x86_64 / aarch64,
 * percentile statistics, environment capture, advisory/official mode
 * detection, JSON output, and one subsystem (`libchaos-time`) end-to-end.
 * Stage 2 will add `perf_event_open` PMU sampling, bootstrap confidence
 * intervals, KS/Wilcoxon A/B testing, and a Python orchestration driver.
 * Stage 3 covers the remaining five subsystems plus multi-thread sweeps
 * and the reload-contention benchmark.
 *
 * **Thread-safety.** The registration API (`chaos_bench_register`,
 * @ref CHAOS_BENCH) is constructor-only and not callable after `main`;
 * benchmark iteration functions run single-threaded.
 *
 * **Stability.** The names declared in this header are part of the
 * benchmark binary's source contract.  Field reordering of public structs
 * is a breaking change.
 */

#ifndef CHAOS_BENCH_H
#define CHAOS_BENCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Measurement mode for a benchmark, mirroring JMH's `@BenchmarkMode`.
 *
 * @details
 * - `AVG_TIME`     — fixed iteration count; reports per-op nanoseconds.
 *   The default and most common mode for hot-path microbenchmarks.
 * - `THROUGHPUT`   — fixed wall-clock window; reports ops/second.  Useful
 *   for scaling sweeps where iteration count varies with system speed.
 * - `SAMPLE_TIME`  — same as `AVG_TIME` but every per-iteration sample is
 *   stored individually (rather than batched-and-averaged), enabling full
 *   percentile and CDF analysis.  Memory-bounded by `measurement_iterations`.
 * - `SINGLE_SHOT`  — measures exactly one invocation.  Used for cold-path
 *   measurements (first dlsym, first config read, first TLS init).
 */
typedef enum chaos_bench_mode
{
    CHAOS_BENCH_MODE_AVG_TIME    = 0,
    CHAOS_BENCH_MODE_THROUGHPUT,
    CHAOS_BENCH_MODE_SAMPLE_TIME,
    CHAOS_BENCH_MODE_SINGLE_SHOT
} chaos_bench_mode_t;

/**
 * @brief Optional per-benchmark setup callback.
 *
 * @details Invoked once after the user-state buffer is allocated and before
 * the warmup loop begins.  Permitted to allocate and to mutate
 * @p user_state.  Aborts the benchmark on failure (the descriptor's setup
 * is expected to be infallible; signal failure via `abort()` if a
 * precondition cannot be satisfied).
 *
 * @param[in,out] user_state  Pointer to the descriptor's pre-allocated
 *                            per-benchmark state buffer; never NULL.
 */
typedef void (*chaos_bench_setup_fn)(void *user_state);

/**
 * @brief Per-iteration callback executed inside the timed loop.
 *
 * @details Must be lightweight and reproducible.  The benchmark author is
 * responsible for marking inputs and outputs with @ref
 * CHAOS_BENCH_DO_NOT_OPTIMIZE so the optimizer cannot elide the work.
 * The harness measures the wall-clock cost of one call to this function
 * (or, for batched measurements, the cost of `batch_size` calls amortized).
 *
 * @param[in,out] user_state  Pointer to the per-benchmark state; never NULL.
 */
typedef void (*chaos_bench_iter_fn)(void *user_state);

/**
 * @brief Optional per-benchmark teardown callback.
 *
 * @details Invoked after the measurement loop completes (and before the
 * statistics phase).  The state buffer is freed by the harness immediately
 * afterwards; this callback exists for releasing resources external to
 * @p user_state (file descriptors, mappings, child processes).
 *
 * @param[in,out] user_state  Pointer to the per-benchmark state; never NULL.
 */
typedef void (*chaos_bench_teardown_fn)(void *user_state);

/**
 * @brief Static descriptor identifying one benchmark, registered at
 *        constructor time via @ref CHAOS_BENCH.
 *
 * @details A benchmark binary contains an unbounded number of these
 * descriptors, one per @ref CHAOS_BENCH macro expansion.  At image load
 * time the per-descriptor constructor links each into a global linked
 * list; the runner's `main` walks the list to find the requested name.
 *
 * Fields are populated by the macro and must not be mutated thereafter.
 * The `next` field is reserved for the registry; benchmark code must
 * leave it as-NULL.
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
 * @brief Appends a descriptor to the global registry.
 *
 * @details Called from the per-benchmark constructor emitted by
 * @ref CHAOS_BENCH.  Operates on a singly-linked list with insertion at
 * the head; ordering across translation units is unspecified (matches
 * constructor ordering, which is unspecified by the language standard).
 *
 * @param[in,out] desc  Caller-owned, statically allocated descriptor.
 *                      The harness retains the pointer for the lifetime
 *                      of the process.  Must not be NULL.
 */
void chaos_bench_register(chaos_bench_descriptor_t *desc);

/**
 * @brief Compiler-fence intrinsic: marks @p p as live to the optimizer.
 *
 * @details Equivalent to Google Benchmark's `DoNotOptimize`.  The inline
 * asm declares @p p as both an input and a memory-clobber, which forbids
 * the optimizer from:
 * 1. Eliminating the computation that produced @p p (DCE).
 * 2. Hoisting the use of @p p outside the surrounding loop.
 * 3. Reordering memory operations across the barrier.
 *
 * The constraint `"r,m"` permits the operand to live in a register or in
 * memory, so the compiler is free to choose its own placement; the asm
 * itself emits no instructions.  The `"memory"` clobber forces the
 * compiler to consider any prior store as observed.
 *
 * @param p  Address of the value being kept live.  Macro takes the
 *           address of its argument internally.
 */
#define CHAOS_BENCH_DO_NOT_OPTIMIZE(p) \
    do { __asm__ volatile("" : : "r,m"(p) : "memory"); } while (0)

/**
 * @brief Compiler-fence intrinsic: clobbers all memory state.
 *
 * @details Equivalent to Google Benchmark's `ClobberMemory`.  Forces the
 * compiler to assume every memory location may have been read or written
 * by the asm block.  Use *between* timed iterations to defeat
 * loop-invariant code motion and partial constant folding that
 * @ref CHAOS_BENCH_DO_NOT_OPTIMIZE alone may not reach.
 */
#define CHAOS_BENCH_CLOBBER_MEMORY() \
    do { __asm__ volatile("" : : : "memory"); } while (0)

/**
 * @brief Registers one benchmark by emitting a descriptor and its
 *        constructor entry.
 *
 * @details
 * Usage:
 * @code
 *     CHAOS_BENCH("time", clock_gettime_passthrough,
 *                 my_state_t, my_setup, my_iter, my_teardown);
 * @endcode
 *
 * The macro emits two static symbols: a `chaos_bench_descriptor_t`
 * named `chaos_bench_desc_<name>` and a constructor function named
 * `chaos_bench_ctor_<name>`.  At image load time the constructor is
 * invoked and registers the descriptor with the harness.
 *
 * @param category_lit  Subsystem string literal (no quotes — the macro
 *                      adds them).  Conventional values: `"io"`, `"net"`,
 *                      `"dns"`, `"time"`, `"memory"`, `"process"`.
 * @param name_lit      Benchmark identifier — a valid C identifier.  Used
 *                      verbatim as the JSON `benchmark` field and as the
 *                      `--benchmark=` CLI value.
 * @param state_type    C type of the per-benchmark state struct.  May be
 *                      `int` or any small placeholder if state is unused;
 *                      the harness allocates `sizeof(state_type)` bytes.
 * @param setup_fn      Setup callback or NULL.
 * @param iter_fn       Iteration callback (must be non-NULL).
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
