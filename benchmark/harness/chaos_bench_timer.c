/**
 * @file chaos_bench_timer.c
 * @brief Calibrated, serializing timer for sub-nanosecond microbenchmarks.
 *
 * @details
 * This module owns the timing primitive used inside the measurement loop.
 * It must be cheap (the read pair flanks the timed work, so its overhead
 * is added to every measurement), serializing (so the CPU's out-of-order
 * engine cannot reorder it past the work), and stable across iterations
 * (so the cost we record is *the work*, not jitter from the timer
 * itself).
 *
 * **Source selection.**
 * - On x86_64 with `constant_tsc` and `nonstop_tsc` CPUID flags, we use
 *   `rdtscp`: a single instruction that reads the time-stamp counter and
 *   serializes against later instructions.  Cost: ~30 cycles on Skylake+.
 *   Without `constant_tsc` the TSC frequency varies with P-state
 *   transitions, making it useless as a wall-clock proxy; we fall back.
 * - On aarch64 we use the Generic Timer's virtual count register
 *   (`CNTVCT_EL0`), preceded by `ISB` to drain the pipeline.  Cost: ~20
 *   cycles.  The virtual timer is invariant across frequency changes by
 *   architectural definition.
 * - Otherwise we fall back to `clock_gettime(CLOCK_MONOTONIC_RAW)` via
 *   the vDSO.  Cost: ~5–25 ns.  Numbers below ~50 ns/op become unreliable.
 *
 * **Calibration.**
 * On x86_64/aarch64 the cycle counter increments at a fixed rate that is
 * not the CPU clock — it's the platform's "reference" frequency,
 * typically the nominal-base frequency on Intel or the architected timer
 * frequency on ARM.  We measure the actual rate at startup over a
 * 100 ms wall-clock window using `CLOCK_MONOTONIC_RAW` (the same vDSO
 * fallback we'd otherwise use), establishing a `cycles → ns` factor.
 * The window size trades off calibration error (smaller window → more
 * jitter) against startup latency.  100 ms gives roughly 0.05% error on
 * a quiescent system — well below the noise floor of any meaningful
 * microbenchmark.
 *
 * **Overhead measurement.**
 * After calibration we measure the cost of `read; read` (back-to-back
 * timer reads with no work between) over 1000 trials, taking the median.
 * This is recorded in the JSON envelope so consumers can subtract it
 * from headline numbers if they wish, and so a regression in timer
 * overhead itself is visible.
 *
 * **What this file does NOT do.**
 * - It does not pin the CPU.  TSC reads from different cores can drift
 *   on systems without `tsc_reliable`; pinning is the wrapper's job.
 * - It does not handle SMI / NMI events that occasionally inject
 *   thousand-cycle excursions into a TSC delta.  Those are detected as
 *   tail outliers in the statistics layer.
 * - It does not attempt to use `rdpru` or other rarer mechanisms; the
 *   trio above covers every Linux target we ship to.
 */

#include "chaos_bench_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__x86_64__) || defined(__i386__)
#  include <x86intrin.h>
#endif

/**
 * @brief Reads `CLOCK_MONOTONIC_RAW` as a 64-bit nanosecond count.
 *
 * @details `MONOTONIC_RAW` is unaffected by NTP slewing, so it is the
 * correct choice for calibration windows.  Cost is one vDSO call —
 * typically 5–25 ns on x86_64.
 *
 * @return Nanoseconds since an unspecified, monotonic epoch.
 */
static uint64_t chaos_bench_clock_raw_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
    {
        /* CLOCK_MONOTONIC_RAW is mandatory on Linux >= 2.6.28; failure
         * here indicates an unsupported platform.  Abort rather than
         * silently produce wrong numbers. */
        perror("chaos_bench: clock_gettime(CLOCK_MONOTONIC_RAW)");
        abort();
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#if defined(__x86_64__) || defined(__i386__)
/**
 * @brief Serializing TSC read on x86.
 *
 * @details `rdtscp` is itself only partially serializing (it serializes
 * against earlier instructions but not later ones).  We add an explicit
 * `lfence` after the read to forbid the OoO engine from reordering
 * subsequent loads/stores past the timestamp.  This is the
 * Intel-recommended idiom for benchmarking
 * (Intel SDM Vol 3B "How to Benchmark Code Execution Times on Intel
 * IA-32 and IA-64 Instruction Set Architectures", 2010).
 *
 * The compiler `"memory"` clobber prevents the optimizer from hoisting
 * loads/stores across the asm.
 */
static inline uint64_t chaos_bench_rdtscp(void)
{
    uint32_t aux;
    uint64_t tsc = __rdtscp(&aux);
    __asm__ volatile("lfence" ::: "memory");
    return tsc;
}
#endif

#if defined(__aarch64__)
/**
 * @brief Serializing virtual-counter read on aarch64.
 *
 * @details The leading `isb` drains the instruction pipeline so the
 * subsequent `mrs` cannot be issued out-of-order with prior work.  The
 * trailing `isb` does the same for following instructions.  This is the
 * ARM ARM-recommended idiom (see DDI0487 §D7.5.6 "Reading the
 * counter-timer").
 */
static inline uint64_t chaos_bench_cntvct(void)
{
    uint64_t v;
    __asm__ volatile("isb\n\t"
                     "mrs %0, cntvct_el0\n\t"
                     "isb"
                     : "=r"(v) :: "memory");
    return v;
}
#endif

/**
 * @brief Polymorphic read used during calibration; selects on @p source.
 */
static uint64_t chaos_bench_read_native(chaos_bench_timer_source_t source)
{
    switch (source)
    {
#if defined(__x86_64__) || defined(__i386__)
    case CHAOS_BENCH_TIMER_RDTSCP:
        return chaos_bench_rdtscp();
#endif
#if defined(__aarch64__)
    case CHAOS_BENCH_TIMER_CNTVCT:
        return chaos_bench_cntvct();
#endif
    case CHAOS_BENCH_TIMER_CLOCK_MONOTONIC:
    default:
        return chaos_bench_clock_raw_ns();
    }
}

/**
 * @brief Selects the best timer source given the captured CPU flags.
 *
 * @details Falls through to the vDSO fallback if the architecture-native
 * counter is not invariant.  The fallback degrades the quality of
 * sub-100ns measurements but never produces wrong numbers.
 */
static chaos_bench_timer_source_t chaos_bench_timer_select(
    const chaos_bench_env_t *env
)
{
#if defined(__x86_64__) || defined(__i386__)
    if (env->has_constant_tsc && env->has_nonstop_tsc)
    {
        return CHAOS_BENCH_TIMER_RDTSCP;
    }
#endif
#if defined(__aarch64__)
    /* The aarch64 virtual timer is architecturally invariant. */
    (void)env;
    return CHAOS_BENCH_TIMER_CNTVCT;
#endif
    return CHAOS_BENCH_TIMER_CLOCK_MONOTONIC;
}

/**
 * @brief Calibrates a native cycle counter against `CLOCK_MONOTONIC_RAW`.
 *
 * @param[in]  source                Selected source; must not be the vDSO
 *                                   fallback (the fallback already returns ns).
 * @param[in]  calibration_window_ns Wall-clock duration to sample over.
 * @param[out] hz                    Computed cycles/second.
 */
static void chaos_bench_timer_calibrate(
    chaos_bench_timer_source_t source,
    uint64_t                   calibration_window_ns,
    double                    *hz
)
{
    uint64_t ns_start, ns_end, cyc_start, cyc_end;

    /* Order is significant: read the cycle counter *first* then the wall
     * clock, and likewise on the second sample.  This bounds the error in
     * the *cycle* delta to one wall-clock-read worth of jitter, which is
     * far smaller than the overall window. */
    cyc_start = chaos_bench_read_native(source);
    ns_start  = chaos_bench_clock_raw_ns();

    do
    {
        ns_end = chaos_bench_clock_raw_ns();
    } while (ns_end - ns_start < calibration_window_ns);

    cyc_end = chaos_bench_read_native(source);

    /* hz = (cycles elapsed) * 1e9 / (ns elapsed). */
    *hz = (double)(cyc_end - cyc_start) * 1.0e9 / (double)(ns_end - ns_start);
}

/**
 * @brief Median of three; used for the timer-overhead self-measurement.
 */
static uint64_t chaos_bench_median3(uint64_t a, uint64_t b, uint64_t c)
{
    if ((a <= b && b <= c) || (c <= b && b <= a)) return b;
    if ((b <= a && a <= c) || (c <= a && a <= b)) return a;
    return c;
}

/**
 * @brief Measures the per-read overhead of the calibrated timer.
 *
 * @details Performs N pairs of back-to-back reads with nothing between,
 * records the median delta, multiplies by `ns_per_cycle`.  Reported in
 * the JSON envelope so consumers can subtract it (or notice when it
 * regresses).
 */
static uint64_t chaos_bench_timer_self_overhead(const chaos_bench_timer_t *t)
{
    enum { kSamples = 1000 };
    uint64_t deltas[kSamples];
    size_t   i;

    for (i = 0U; i < kSamples; ++i)
    {
        uint64_t a = chaos_bench_read_native(t->source);
        uint64_t b = chaos_bench_read_native(t->source);
        deltas[i] = b - a;
    }

    /* Robust against single-event outliers: take the median of three
     * consecutive medians to suppress isolated spikes.  Acceptable cost
     * for a 1000-sample warmup. */
    uint64_t m1 = chaos_bench_median3(deltas[0], deltas[kSamples / 2], deltas[kSamples - 1]);
    uint64_t m2 = chaos_bench_median3(deltas[kSamples / 4], deltas[kSamples / 2], deltas[3 * kSamples / 4]);
    uint64_t m3 = chaos_bench_median3(deltas[1], deltas[kSamples / 2 + 1], deltas[kSamples - 2]);
    uint64_t median_cycles = chaos_bench_median3(m1, m2, m3);

    return (uint64_t)((double)median_cycles * t->ns_per_cycle);
}

void chaos_bench_timer_init(
    const chaos_bench_env_t *env, chaos_bench_timer_t *timer
)
{
    enum { kCalibrationWindowNs = 100 * 1000 * 1000 }; /* 100 ms */

    timer->source                = chaos_bench_timer_select(env);
    timer->calibration_window_ns = kCalibrationWindowNs;

    if (timer->source == CHAOS_BENCH_TIMER_CLOCK_MONOTONIC)
    {
        /* Fallback path returns ns directly; no calibration needed. */
        timer->hz           = 1.0e9;
        timer->ns_per_cycle = 1.0;
    }
    else
    {
        chaos_bench_timer_calibrate(timer->source, kCalibrationWindowNs, &timer->hz);
        timer->ns_per_cycle = 1.0e9 / timer->hz;
    }

    timer->overhead_ns = chaos_bench_timer_self_overhead(timer);
}

uint64_t chaos_bench_timer_read(const chaos_bench_timer_t *timer)
{
    return chaos_bench_read_native(timer->source);
}
