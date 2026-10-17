/**
 * @file chaos_bench_stats.c
 * @brief Summary statistics over the per-call nanosecond samples of one run.
 *
 * @details
 * Computes `min`, `max`, `mean`, sample `stdev`, and the percentiles p50 (also reported as
 * `median`), p90, p95, p99, p99.9 and p99.99. Percentiles use type-7 (R-7) linear
 * interpolation, the default of NumPy, R and pandas, so values are directly comparable with
 * analyses done in those tools.
 *
 * **Deliberately absent.**
 *  - Confidence intervals and hypothesis tests: one run is one observation. The Python
 *    driver (`driver/chaos_bench_driver.py`) compares runs with a Wilcoxon rank-sum test and
 *    a bootstrap confidence interval on the median delta.
 *  - Outlier trimming: none; `samples_after_trim == samples`. Tail events stay visible in
 *    the upper percentiles instead of being discarded.
 *
 * **Numerics.**
 *  - `stdev` uses the two-pass algorithm (mean first, then squared deviations). The
 *    single-pass sum-of-squares formula cancels catastrophically when samples cluster tightly
 *    around a large mean, which is exactly the shape of a stable benchmark. The second pass
 *    costs one more scan, negligible next to the measurement that produced the samples.
 *  - All arithmetic is in `double`.
 *
 * **Cost.** One in-place `qsort(3)` over at most @ref CHAOS_BENCH_MAX_SAMPLES (1 Mi) doubles,
 * under 50 ms on a contemporary CPU, after the timed loop. No allocation.
 */

#include "chaos_bench_internal.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief `qsort` comparator for `double`, ascending.
 *
 * @details `(a > b) - (a < b)` returns -1/0/1 without the overflow and truncation of
 * `(int)(a - b)`. It treats NaN as equal to everything, which would break qsort's ordering
 * contract; samples are never NaN because they are unsigned cycle deltas times a finite,
 * positive `ns_per_cycle`.
 */
static int chaos_bench_double_cmp(const void *lhs, const void *rhs)
{
    double a = *(const double *)lhs;
    double b = *(const double *)rhs;
    return (a > b) - (a < b);
}

/**
 * @brief Returns percentile @p p of @p sorted using R-7 interpolation.
 *
 * @details With the 0-based rank `h = (N-1) * p`, the result is
 * `sorted[floor(h)] + (sorted[floor(h)+1] - sorted[floor(h)]) * frac(h)`. `N == 1` returns
 * the only sample; `p == 1.0` returns the maximum.
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

    /* Zero the result first so sample_count == 0 yields all-zero statistics instead of
     * reading samples[-1]. */
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
    /* Sample stdev with Bessel's correction, equal to numpy.std(ddof=1); 0 for one sample. */
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
