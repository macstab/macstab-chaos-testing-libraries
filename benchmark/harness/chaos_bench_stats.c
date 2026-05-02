/**
 * @file chaos_bench_stats.c
 * @brief Statistics over per-iteration nanosecond samples.
 *
 * @details
 * Stage 1 computes a fixed set of summary statistics: `min`, `max`, `mean`,
 * `stdev`, and percentiles `p50/p90/p99/p999/p9999` plus `median` (alias
 * for `p50`).  Percentile values use the type-7 (R-7) interpolation
 * scheme — the same default used by NumPy, R, and Pandas — so values
 * are directly comparable to analyses produced in those tools.
 *
 * **What's *not* here, and where it goes.**
 *  - Bootstrap confidence intervals (Stage 2): require ~10 ms of
 *    additional work per benchmark, deferred until the Python A/B
 *    driver lands so the work happens once per *report*, not per *trial*.
 *  - KS test for non-normality (Stage 2): same reasoning.
 *  - Outlier trimming: Stage 1 reports raw stats with `samples_after_trim
 *    == samples`.  Stage 2 will trim by MAD-based rejection at the
 *    driver layer where we have full samples preserved.
 *
 * **Numerical hygiene.**
 *  - `stdev` is computed via the corrected two-pass algorithm: first
 *    pass for the mean, second pass for the squared deviations.  The
 *    naive single-pass sum-of-squares formula is catastrophic when
 *    samples cluster around a large mean (it loses all bits of
 *    precision in the subtraction step).  The two-pass cost is ~2× a
 *    single-pass scan, which is negligible against the millions of ns
 *    of measurement work that produced the samples.
 *  - Percentile interpolation uses `double` throughout to avoid
 *    rounding artifacts on small sample sets.
 *
 * **Sort cost.**
 *  - `qsort(3)` on `double` over up to @ref CHAOS_BENCH_MAX_SAMPLES (1 M)
 *    samples completes in <50 ms on a contemporary CPU — well within
 *    the post-measurement budget.  No allocation.
 */

#include "chaos_bench_internal.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief `qsort` comparator for `double` arrays, ascending.
 *
 * @details Uses subtraction-and-sign to avoid the classic
 * "(a > b) - (a < b)" trick failing on NaN inputs, but the harness
 * never produces NaN samples (all inputs are positive cycle deltas
 * scaled by a positive ns_per_cycle factor) so either form is safe.
 */
static int chaos_bench_double_cmp(const void *lhs, const void *rhs)
{
    double a = *(const double *)lhs;
    double b = *(const double *)rhs;
    return (a > b) - (a < b);
}

/**
 * @brief Computes one percentile from a sorted array using R-7 interpolation.
 *
 * @details R-7 is the default in NumPy and R: for a target rank
 * `h = (N-1) * p`, the percentile is a linear interpolation between the
 * floor and ceiling indices.  Returns the floor sample when `N == 1` or
 * when @p p falls exactly on an integer index.
 *
 * @param[in] sorted        Pre-sorted ascending array.
 * @param[in] sample_count  Length of @p sorted; must be > 0.
 * @param[in] p             Probability in [0.0, 1.0].
 *
 * @return The interpolated percentile value.
 */
static double chaos_bench_percentile(
    const double *sorted, size_t sample_count, double p
)
{
    if (sample_count == 1U)
    {
        return sorted[0];
    }
    /* h is a 0-based fractional index. */
    double h        = ((double)sample_count - 1.0) * p;
    size_t lo       = (size_t)h;
    size_t hi       = lo + 1U;
    double fraction = h - (double)lo;

    if (hi >= sample_count)
    {
        return sorted[sample_count - 1U];
    }
    return sorted[lo] + (sorted[hi] - sorted[lo]) * fraction;
}

void chaos_bench_stats_compute(
    double *samples, size_t sample_count, chaos_bench_stats_t *out
)
{
    size_t i;
    double sum;
    double mean;
    double sum_sq;

    /* Caller invariant; we assert by clearing the output and bailing on
     * the degenerate case rather than crashing. */
    memset(out, 0, sizeof(*out));
    if (sample_count == 0U)
    {
        return;
    }

    qsort(samples, sample_count, sizeof(*samples), chaos_bench_double_cmp);

    sum = 0.0;
    for (i = 0U; i < sample_count; ++i)
    {
        sum += samples[i];
    }
    mean = sum / (double)sample_count;

    sum_sq = 0.0;
    for (i = 0U; i < sample_count; ++i)
    {
        double d = samples[i] - mean;
        sum_sq += d * d;
    }

    out->samples            = sample_count;
    out->samples_after_trim = sample_count;
    out->min_ns             = samples[0];
    out->max_ns             = samples[sample_count - 1U];
    out->mean_ns            = mean;
    /* Sample stdev (Bessel's correction) — what `numpy.std(ddof=1)` gives. */
    out->stdev_ns           = sample_count > 1U
                                  ? sqrt(sum_sq / (double)(sample_count - 1U))
                                  : 0.0;
    out->median_ns          = chaos_bench_percentile(samples, sample_count, 0.50);
    out->p50_ns             = out->median_ns;
    out->p90_ns             = chaos_bench_percentile(samples, sample_count, 0.90);
    out->p95_ns             = chaos_bench_percentile(samples, sample_count, 0.95);
    out->p99_ns             = chaos_bench_percentile(samples, sample_count, 0.99);
    out->p999_ns            = chaos_bench_percentile(samples, sample_count, 0.999);
    out->p9999_ns           = chaos_bench_percentile(samples, sample_count, 0.9999);
}
