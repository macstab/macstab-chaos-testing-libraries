/**
 * @file chaos_bench_timer.c
 * @brief Selection, calibration and self-measurement of the timer that brackets every timing
 *        window.
 *
 * @details
 * The timer read pair flanks the measured work, so it must be cheap (its cost is in every
 * sample), serializing (the CPU must not overlap it with the work) and invariant (its rate
 * must not change with CPU frequency or idle states).
 *
 * **Source selection** (@ref chaos_bench_timer_source_t).
 * - x86 with both `constant_tsc` and `nonstop_tsc` in `/proc/cpuinfo`: `rdtscp` followed by
 *   `lfence`, roughly 30 cycles on Skylake and later. Without `constant_tsc` the TSC rate
 *   follows P-state changes; without `nonstop_tsc` it stops in deep C-states. Either makes
 *   cycle counts useless as time, so the fallback is used.
 * - aarch64: the virtual count register `CNTVCT_EL0`, bracketed by `isb`, roughly 20 cycles.
 *   Its rate is architecturally fixed, so no flag check is needed.
 * - Anything else: `clock_gettime(CLOCK_MONOTONIC_RAW)` via the vDSO, roughly 5-25 ns per
 *   read. Per-call results below about 50 ns are then dominated by timer cost; use `--batch`.
 *
 * **Calibration.**
 * TSC and CNTVCT tick at a fixed reference rate that is not the core clock. Startup measures
 * that rate against `CLOCK_MONOTONIC_RAW` over a 100 ms busy-wait window and derives
 * `ns_per_cycle`. A shorter window raises the relative error (clock-read cost over window);
 * a longer one delays every benchmark process. 100 ms gives about 0.05 % error on a
 * quiescent system, below run-to-run noise. A second, independent 10 ms calibration then
 * cross-checks the result and aborts if the two differ by more than 1 %.
 *
 * **Overhead measurement.**
 * After calibration, 1000 back-to-back read pairs are timed and a median-of-medians estimate
 * of their cost is stored as `overhead_ns`. It is reported, not subtracted, so consumers can
 * correct headline numbers and a timer-cost regression stays visible.
 *
 * **Failure behaviour.** Fail-closed: if `CLOCK_MONOTONIC_RAW` fails or the calibrations
 * disagree, the process aborts rather than emit numbers on a broken time base.
 *
 * **Not handled here.**
 * - CPU pinning. TSCs of different cores can be offset on hosts without `tsc_reliable`;
 *   `run-bench.sh` pins the process.
 * - SMI/NMI excursions of thousands of cycles in single samples. They show up in the upper
 *   percentiles (p99.9, p99.99), not in the median.
 * - `rdpru` and other rarer counters; the three sources above cover every supported target.
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
 * @details `CLOCK_MONOTONIC_RAW` is not slewed by NTP or adjtime, so a calibration window
 * measured with it is not distorted by frequency correction in progress. One vDSO call,
 * typically 5-25 ns on x86_64. Aborts on failure.
 *
 * @return Nanoseconds since an unspecified, monotonic epoch.
 */
static uint64_t chaos_bench_clock_raw_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
    {
        /* CLOCK_MONOTONIC_RAW exists since Linux 2.6.28; failure means an unsupported
         * platform. Abort rather than calibrate against garbage. */
        perror("chaos_bench: clock_gettime(CLOCK_MONOTONIC_RAW)");
        abort();
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#if defined(__x86_64__) || defined(__i386__)
/**
 * @brief Serializing TSC read on x86.
 *
 * @details `rdtscp` waits for all earlier instructions to execute before reading the TSC,
 * but later instructions may start before it completes. The trailing `lfence` stops later
 * instructions from starting early, so the work after a start read cannot leak in front of
 * it. This is the idiom from Intel's white paper "How to Benchmark Code Execution Times on
 * Intel IA-32 and IA-64 Instruction Set Architectures" (2010).
 *
 * The `"memory"` clobber keeps the compiler from moving loads or stores across the read.
 * The `TSC_AUX` value returned in @c aux (the CPU id) is ignored.
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
 * @details Counter reads are not ordered with other instructions. The leading `isb` makes the
 * `mrs` wait for earlier instructions; the trailing `isb` keeps later instructions from
 * starting before it. This is the idiom the Arm ARM (DDI0487, "Reading the counter-timer")
 * prescribes for ordered counter reads.
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
 * @brief Reads @p source; the fallback (and any source not compiled for this architecture)
 *        returns `CLOCK_MONOTONIC_RAW` nanoseconds.
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
 * @details x86 uses rdtscp only with both invariance flags; aarch64 always uses CNTVCT; any
 * other case gets the `CLOCK_MONOTONIC_RAW` fallback, which costs resolution on sub-100 ns
 * operations but never mis-scales time.
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
    /* CNTVCT_EL0 runs at the fixed CNTFRQ rate by architectural definition. */
    (void)env;
    return CHAOS_BENCH_TIMER_CNTVCT;
#endif
    return CHAOS_BENCH_TIMER_CLOCK_MONOTONIC;
}

/**
 * @brief Measures the tick rate of @p source against `CLOCK_MONOTONIC_RAW`.
 *
 * @details Busy-waits for at least @p calibration_window_ns. Both counters keep running
 * while the thread is preempted, so preemption inside the window is harmless; preemption
 * between the paired reads at either end adds its full duration to the error.
 *
 * @param[in]  source                rdtscp or cntvct; the fallback already counts ns.
 * @param[in]  calibration_window_ns Minimum wall-clock window, ns.
 * @param[out] hz                    Measured ticks per second.
 */
static void chaos_bench_timer_calibrate(
    chaos_bench_timer_source_t source,
    uint64_t                   calibration_window_ns,
    double                    *hz
)
{
    uint64_t ns_start, ns_end, cyc_start, cyc_end;

    /* Order matters: cycles then clock at the start, clock then cycles at the end. The
     * cycle interval therefore encloses the clock interval and exceeds it by at most one
     * clock read at each end, so hz is biased high by at most about two clock reads per
     * window (well under 0.01 % at 100 ms). */
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
 * @brief Aborts if a second, independent 10 ms calibration differs from @p hz by more than
 *        1 %.
 *
 * @details A disagreement means the counter rate is not stable on this host: the TSC is
 * not actually invariant (P-state changes reach it), a hypervisor virtualises it badly, or
 * heavy steal time distorted one window. Any benchmark number derived from it would be
 * mis-scaled, so the process aborts with a diagnostic on stderr (fail-closed).
 *
 * The 1 % threshold sits far above the error of a healthy 10 ms window (a few clock reads
 * over 10 ms) and below the scaling error that would visibly shift benchmark results.
 *
 * @param[in] source  Source used for the primary calibration.
 * @param[in] hz      Rate from the primary calibration; must be non-zero.
 */
static void chaos_bench_timer_validate_calibration(
    chaos_bench_timer_source_t source,
    double                     hz
)
{
    enum { kValidationWindowNs = 10 * 1000 * 1000 }; /* 10 ms */
    double hz_check;
    double drift;

    chaos_bench_timer_calibrate(source, kValidationWindowNs, &hz_check);

    drift = (hz_check - hz) / hz;
    if (drift < 0.0) drift = -drift;

    if (drift > 0.01)
    {
        fprintf(stderr,
            "chaos_bench: timer calibration disagreement: "
            "primary=%.0f Hz  check=%.0f Hz  drift=%.2f%%  (threshold 1%%)\n"
            "chaos_bench: possible causes: P-state transitions, "
            "virtualised TSC without constant_tsc, or heavy hypervisor steal.\n"
            "chaos_bench: aborting — benchmark numbers would be unreliable.\n",
            hz, hz_check, drift * 100.0);
        abort();
    }
}

/**
 * @brief Median of three values; building block of the overhead estimate.
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
 * @details Times 1000 pairs of back-to-back reads with nothing between them and converts
 * a robust central estimate of their deltas to ns (truncated to whole ns). The estimate is a
 * median of three medians-of-three over nine fixed positions of the unsorted delta array (a
 * "ninther"), not the exact median: it costs no sort and still ignores isolated spikes from
 * interrupts or SMIs. Uses `t->source` and `t->ns_per_cycle`, so it runs after calibration.
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

    /* Ninther over positions {0, N/2, N-1}, {N/4, N/2, 3N/4}, {1, N/2+1, N-2}: one outlier
     * can corrupt at most one inner median, which the outer median then discards. */
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
        /* The fallback already counts ns; calibration_window_ns stays at its nominal value
         * in the envelope even though no calibration ran. */
        timer->hz           = 1.0e9;
        timer->ns_per_cycle = 1.0;
    }
    else
    {
        chaos_bench_timer_calibrate(timer->source, kCalibrationWindowNs, &timer->hz);
        timer->ns_per_cycle = 1.0e9 / timer->hz;
        chaos_bench_timer_validate_calibration(timer->source, timer->hz);
    }

    timer->overhead_ns = chaos_bench_timer_self_overhead(timer);
}

uint64_t chaos_bench_timer_read(const chaos_bench_timer_t *timer)
{
    return chaos_bench_read_native(timer->source);
}
