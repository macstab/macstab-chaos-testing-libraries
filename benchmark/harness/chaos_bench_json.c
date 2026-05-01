/**
 * @file chaos_bench_json.c
 * @brief Hand-rolled JSON envelope writer.
 *
 * @details
 * The harness output is a single JSON object per benchmark invocation,
 * written to a caller-supplied `FILE *` (typically `stdout` or a file
 * specified by `--output`).  We hand-roll the writer because:
 *  - The schema is fixed and small; pulling in a JSON dependency would
 *    triple the harness binary size for no functional benefit.
 *  - The writer must run *after* the timed loop (no allocation in the
 *    hot path is required), so we trade compactness against
 *    no-runtime-deps simplicity.
 *  - String escaping is restricted to the subset that actually appears
 *    in our values (newline, double-quote, backslash, control bytes).
 *
 * **Schema (versioned via `schema_version`).**
 * @code
 * {
 *   "schema_version": 1,
 *   "benchmark":   { "name": "...", "category": "..." },
 *   "config":      { "mode": "AVG_TIME", "warmup_iters": N, "measurement_iters": N, "batch_size": N },
 *   "execution":   { "mode": "OFFICIAL"|"ADVISORY", "warnings": [...] },
 *   "timer":       { "source": "...", "calibrated_hz": ..., "ns_per_cycle": ..., "overhead_ns": ... },
 *   "scenario":    { "path": "...", "active": true|false },
 *   "stats":       { "samples": N, "min_ns": ..., "max_ns": ..., "mean_ns": ..., "stdev_ns": ...,
 *                    "p50_ns": ..., "p90_ns": ..., "p99_ns": ..., "p999_ns": ..., "p9999_ns": ... },
 *   "environment": { "kernel_release": "...", "kernel_version": "...", "cpu_model": "...",
 *                    "governor": "...", "isolated_cpus": "...", "thp_enabled": "...",
 *                    "smt_active": true|false, "container": true|false, "libc": "...",
 *                    "git_sha": "...", "build_cflags": "...", "ld_preload": "...",
 *                    "constant_tsc": true|false, "nonstop_tsc": true|false }
 * }
 * @endcode
 *
 * Schema bumps are breaking: a Stage 2 driver consuming Stage 1 JSON
 * checks `schema_version` and refuses to compare across versions.
 */

#include "chaos_bench_internal.h"
#include "chaos_bench_perf.h"

#include <stdio.h>
#include <string.h>

/**
 * @brief Writes a JSON-escaped string literal (without surrounding quotes).
 *
 * @details Escapes the JSON-mandatory set: `"`, `\`, `\b`, `\f`, `\n`,
 * `\r`, `\t`, plus control bytes `< 0x20` via `\u00XX`.  All other bytes
 * pass through.  The harness inputs are ASCII or UTF-8 captured from
 * `/proc` paths, so the simple byte-passthrough does the right thing on
 * UTF-8 too.
 */
static void chaos_bench_json_write_escaped(FILE *out, const char *s)
{
    if (s == NULL)
    {
        return;
    }
    for (; *s != '\0'; ++s)
    {
        unsigned char c = (unsigned char)*s;
        switch (c)
        {
        case '"':  fputs("\\\"", out); break;
        case '\\': fputs("\\\\", out); break;
        case '\b': fputs("\\b",  out); break;
        case '\f': fputs("\\f",  out); break;
        case '\n': fputs("\\n",  out); break;
        case '\r': fputs("\\r",  out); break;
        case '\t': fputs("\\t",  out); break;
        default:
            if (c < 0x20U)
            {
                fprintf(out, "\\u%04x", (unsigned)c);
            }
            else
            {
                fputc((int)c, out);
            }
            break;
        }
    }
}

/**
 * @brief Convenience: writes `"key": "<escaped value>"` followed by an
 *        optional trailing comma + newline.
 */
static void chaos_bench_json_str_field(
    FILE *out, const char *key, const char *value, int trailing_comma
)
{
    fprintf(out, "    \"%s\": \"", key);
    chaos_bench_json_write_escaped(out, value);
    fputs(trailing_comma ? "\",\n" : "\"\n", out);
}

/**
 * @brief Convenience: writes `"key": <bool>`.
 */
static void chaos_bench_json_bool_field(
    FILE *out, const char *key, int value, int trailing_comma
)
{
    fprintf(out, "    \"%s\": %s%s\n",
            key,
            value ? "true" : "false",
            trailing_comma ? "," : "");
}

/**
 * @brief Translates the timer-source enum to a stable string.
 */
static const char *chaos_bench_timer_source_str(chaos_bench_timer_source_t s)
{
    switch (s)
    {
    case CHAOS_BENCH_TIMER_RDTSCP:          return "rdtscp";
    case CHAOS_BENCH_TIMER_CNTVCT:          return "cntvct_el0";
    case CHAOS_BENCH_TIMER_CLOCK_MONOTONIC: return "clock_monotonic_raw";
    default:                                 return "unknown";
    }
}

/**
 * @brief Translates the mode enum to a stable string.
 */
static const char *chaos_bench_mode_str(chaos_bench_mode_t m)
{
    switch (m)
    {
    case CHAOS_BENCH_MODE_AVG_TIME:    return "AVG_TIME";
    case CHAOS_BENCH_MODE_THROUGHPUT:  return "THROUGHPUT";
    case CHAOS_BENCH_MODE_SAMPLE_TIME: return "SAMPLE_TIME";
    case CHAOS_BENCH_MODE_SINGLE_SHOT: return "SINGLE_SHOT";
    default:                           return "UNKNOWN";
    }
}

void chaos_bench_json_write_envelope(
    FILE                          *out,
    const chaos_bench_descriptor_t *desc,
    chaos_bench_mode_t              mode,
    size_t                          warmup_iters,
    size_t                          measurement_iters,
    size_t                          batch_size,
    chaos_bench_exec_mode_t         exec_mode,
    const chaos_bench_warning_t    *warnings,
    size_t                          warning_count,
    const chaos_bench_timer_t      *timer,
    const chaos_bench_env_t        *env,
    const char                     *scenario_path,
    int                             scenario_active,
    const chaos_bench_stats_t      *stats,
    const chaos_bench_pmu_t        *pmu
)
{
    size_t i;

    fputs("{\n", out);
    fputs("  \"schema_version\": 1,\n", out);

    fputs("  \"benchmark\": {\n", out);
    chaos_bench_json_str_field(out, "name",     desc->name,     1);
    chaos_bench_json_str_field(out, "category", desc->category, 0);
    fputs("  },\n", out);

    fputs("  \"config\": {\n", out);
    chaos_bench_json_str_field(out, "mode", chaos_bench_mode_str(mode), 1);
    fprintf(out, "    \"warmup_iters\": %zu,\n",      warmup_iters);
    fprintf(out, "    \"measurement_iters\": %zu,\n", measurement_iters);
    fprintf(out, "    \"batch_size\": %zu\n",         batch_size);
    fputs("  },\n", out);

    fputs("  \"execution\": {\n", out);
    chaos_bench_json_str_field(
        out, "mode",
        exec_mode == CHAOS_BENCH_EXEC_OFFICIAL ? "OFFICIAL" : "ADVISORY",
        1
    );
    fputs("    \"warnings\": [", out);
    for (i = 0U; i < warning_count; ++i)
    {
        if (i > 0U) fputs(", ", out);
        fputs("{\"check\": \"", out);
        chaos_bench_json_write_escaped(out, warnings[i].check);
        fputs("\", \"detail\": \"", out);
        chaos_bench_json_write_escaped(out, warnings[i].detail);
        fputs("\"}", out);
    }
    fputs("]\n", out);
    fputs("  },\n", out);

    fputs("  \"timer\": {\n", out);
    chaos_bench_json_str_field(out, "source",
                               chaos_bench_timer_source_str(timer->source), 1);
    fprintf(out, "    \"calibrated_hz\": %.3f,\n",         timer->hz);
    fprintf(out, "    \"ns_per_cycle\": %.6f,\n",          timer->ns_per_cycle);
    fprintf(out, "    \"calibration_window_ns\": %llu,\n",
            (unsigned long long)timer->calibration_window_ns);
    fprintf(out, "    \"overhead_ns\": %llu\n",
            (unsigned long long)timer->overhead_ns);
    fputs("  },\n", out);

    fputs("  \"scenario\": {\n", out);
    chaos_bench_json_str_field(out, "path",
                               scenario_path != NULL ? scenario_path : "",
                               1);
    chaos_bench_json_bool_field(out, "active", scenario_active, 0);
    fputs("  },\n", out);

    fputs("  \"stats\": {\n", out);
    fprintf(out, "    \"samples\": %zu,\n",            stats->samples);
    fprintf(out, "    \"samples_after_trim\": %zu,\n", stats->samples_after_trim);
    fprintf(out, "    \"min_ns\":    %.3f,\n", stats->min_ns);
    fprintf(out, "    \"max_ns\":    %.3f,\n", stats->max_ns);
    fprintf(out, "    \"mean_ns\":   %.3f,\n", stats->mean_ns);
    fprintf(out, "    \"stdev_ns\":  %.3f,\n", stats->stdev_ns);
    fprintf(out, "    \"median_ns\": %.3f,\n", stats->median_ns);
    fprintf(out, "    \"p50_ns\":    %.3f,\n", stats->p50_ns);
    fprintf(out, "    \"p90_ns\":    %.3f,\n", stats->p90_ns);
    fprintf(out, "    \"p95_ns\":    %.3f,\n", stats->p95_ns);
    fprintf(out, "    \"p99_ns\":    %.3f,\n", stats->p99_ns);
    fprintf(out, "    \"p999_ns\":   %.3f,\n", stats->p999_ns);
    fprintf(out, "    \"p9999_ns\":  %.3f\n",  stats->p9999_ns);
    fputs("  },\n", out);

    fputs("  \"pmu\": {\n", out);
    if (pmu != NULL && pmu->available)
    {
        fputs("    \"available\": true,\n", out);
        fputs("    \"counters\": {\n", out);
        for (i = 0U; i < CHAOS_BENCH_PMU_COUNTER_COUNT; ++i)
        {
            fprintf(out, "      \"%s\": %llu%s\n",
                    chaos_bench_pmu_counter_names[i],
                    (unsigned long long)pmu->total[i],
                    (i + 1U) < CHAOS_BENCH_PMU_COUNTER_COUNT ? "," : "");
        }
        fputs("    }\n", out);
    }
    else
    {
        fputs("    \"available\": false,\n", out);
        chaos_bench_json_str_field(out, "reason",
                                   pmu != NULL ? pmu->reason : "uninitialized",
                                   0);
    }
    fputs("  },\n", out);

    fputs("  \"environment\": {\n", out);
    chaos_bench_json_str_field(out, "kernel_release", env->kernel_release, 1);
    chaos_bench_json_str_field(out, "kernel_version", env->kernel_version, 1);
    chaos_bench_json_str_field(out, "cpu_model",      env->cpu_model,      1);
    chaos_bench_json_str_field(out, "cpu_flags",      env->cpu_flags_blob, 1);
    chaos_bench_json_str_field(out, "governor",       env->governor,       1);
    chaos_bench_json_str_field(out, "isolated_cpus",  env->isolated_cpus,  1);
    chaos_bench_json_str_field(out, "thp_enabled",    env->thp_enabled,    1);
    chaos_bench_json_str_field(out, "libc",           env->libc_id,        1);
    chaos_bench_json_str_field(out, "git_sha",        env->git_sha,        1);
    chaos_bench_json_str_field(out, "build_cflags",   env->build_cflags,   1);
    chaos_bench_json_str_field(out, "ld_preload",     env->ld_preload,     1);
    chaos_bench_json_bool_field(out, "smt_active",    env->smt_active,     1);
    chaos_bench_json_bool_field(out, "container",     env->container_marker, 1);
    chaos_bench_json_bool_field(out, "constant_tsc",  env->has_constant_tsc, 1);
    chaos_bench_json_bool_field(out, "nonstop_tsc",   env->has_nonstop_tsc,  0);
    fputs("  }\n", out);

    fputs("}\n", out);
    fflush(out);
}
