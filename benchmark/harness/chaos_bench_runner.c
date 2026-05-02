/**
 * @file chaos_bench_runner.c
 * @brief Process entry point: parse argv, calibrate, run one benchmark, emit JSON.
 *
 * @details
 * One process executes one benchmark from start to finish.  The runner
 * is intentionally minimal — the cycle is:
 *   1. Parse argv (`--benchmark`, `--mode`, `--warmup`, `--iters`,
 *      `--batch`, `--scenario`, `--scenario-target`, `--output`, `--list`).
 *   2. Capture environment + check isolation (publishes mode in JSON).
 *   3. Calibrate timer.
 *   4. Find the descriptor by name (the constructor list is fully
 *      populated by the time `main` runs).
 *   5. If a scenario file is requested, copy it into the chaos config
 *      target path and bump its mtime to a future value (the existing
 *      future-mtime convention used by the runtime probes).
 *   6. Allocate the descriptor's per-benchmark state buffer.
 *   7. Invoke setup → warmup loop → measurement loop → teardown.
 *   8. Compute statistics.
 *   9. Emit the JSON envelope.
 *
 * The runner does *not* fork, pin to a CPU, or set LD_PRELOAD.  All of
 * those are the wrapper script's job (`run-bench.sh`), so the same
 * runner code is reusable in any orchestration environment without
 * recompilation.
 *
 * **Loop discipline.**
 * The measurement loop reads the timer once before the iteration and
 * once after, recording the cycle delta.  Per-iteration sample is
 * stored in a pre-allocated `double` array so we can sort and compute
 * percentiles after the loop completes.  We *do not* call malloc inside
 * the loop, take a fast-path on the timer, or branch on anything other
 * than the loop counter — the optimizer is encouraged to unroll
 * trivially.
 *
 * **What `batch_size > 1` does.**
 * For sub-100ns iteration costs, the timer-read pair (~30 cycles) is a
 * meaningful fraction of the measurement.  The runner can be told to
 * call the iter callback `batch_size` times per timing window,
 * amortizing the timer overhead.  The reported value is per-op
 * (delta_ns / batch_size).  Batch size is exposed in the JSON for
 * downstream auditing.
 */

#include "chaos_bench.h"
#include "chaos_bench_internal.h"
#include "chaos_bench_perf.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Externally defined in chaos_bench_register.c. */
extern void chaos_bench_registry_list(FILE *out);

/* Defaults — overridable by argv. */
#define CHAOS_BENCH_DEFAULT_WARMUP_ITERS       10000U
#define CHAOS_BENCH_DEFAULT_MEASUREMENT_ITERS  200000U
#define CHAOS_BENCH_DEFAULT_BATCH_SIZE         1U

/**
 * @brief Parsed argv values.
 */
typedef struct chaos_bench_args
{
    const char        *benchmark;
    chaos_bench_mode_t mode;
    size_t             warmup_iters;
    size_t             measurement_iters;
    size_t             batch_size;
    const char        *scenario_path;     /**< Source config file. */
    const char        *scenario_target;   /**< Where the chaos lib reads it. */
    const char        *output_path;       /**< NULL ⇒ stdout. */
    int                list_and_exit;
} chaos_bench_args_t;

static void chaos_bench_print_usage(FILE *out, const char *argv0)
{
    fprintf(out,
        "Usage: %s [options]\n"
        "\n"
        "  --benchmark=NAME        select benchmark (required unless --list)\n"
        "  --mode=MODE             AVG_TIME (default) | SAMPLE_TIME | SINGLE_SHOT\n"
        "  --warmup=N              warmup iterations (default %u)\n"
        "  --iters=N               measurement iterations (default %u, max %u)\n"
        "  --batch=N               ops per timing window (default %u)\n"
        "  --scenario=PATH         chaos config file to install before running\n"
        "  --scenario-target=PATH  destination path (e.g. /tmp/.chaos-time.conf)\n"
        "  --output=PATH           JSON output path (default: stdout)\n"
        "  --list                  list registered benchmarks and exit\n"
        "  -h, --help              show this help\n",
        argv0,
        CHAOS_BENCH_DEFAULT_WARMUP_ITERS,
        CHAOS_BENCH_DEFAULT_MEASUREMENT_ITERS,
        CHAOS_BENCH_MAX_SAMPLES,
        CHAOS_BENCH_DEFAULT_BATCH_SIZE
    );
}

static int chaos_bench_parse_mode(const char *s, chaos_bench_mode_t *out)
{
    if      (strcmp(s, "AVG_TIME")    == 0) { *out = CHAOS_BENCH_MODE_AVG_TIME;    return 0; }
    else if (strcmp(s, "SAMPLE_TIME") == 0) { *out = CHAOS_BENCH_MODE_SAMPLE_TIME; return 0; }
    else if (strcmp(s, "SINGLE_SHOT") == 0) { *out = CHAOS_BENCH_MODE_SINGLE_SHOT; return 0; }
    else if (strcmp(s, "THROUGHPUT")  == 0) { *out = CHAOS_BENCH_MODE_THROUGHPUT;  return 0; }
    return -1;
}

static int chaos_bench_parse_args(int argc, char **argv, chaos_bench_args_t *out)
{
    static const struct option long_opts[] = {
        {"benchmark",        required_argument, 0, 'b'},
        {"mode",             required_argument, 0, 'm'},
        {"warmup",           required_argument, 0, 'w'},
        {"iters",            required_argument, 0, 'i'},
        {"batch",            required_argument, 0, 'B'},
        {"scenario",         required_argument, 0, 's'},
        {"scenario-target",  required_argument, 0, 't'},
        {"output",           required_argument, 0, 'o'},
        {"list",             no_argument,       0, 'l'},
        {"help",             no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int c;

    out->benchmark         = NULL;
    out->mode              = CHAOS_BENCH_MODE_AVG_TIME;
    out->warmup_iters      = CHAOS_BENCH_DEFAULT_WARMUP_ITERS;
    out->measurement_iters = CHAOS_BENCH_DEFAULT_MEASUREMENT_ITERS;
    out->batch_size        = CHAOS_BENCH_DEFAULT_BATCH_SIZE;
    out->scenario_path     = NULL;
    out->scenario_target   = NULL;
    out->output_path       = NULL;
    out->list_and_exit     = 0;

    while ((c = getopt_long(argc, argv, "b:m:w:i:B:s:t:o:lh", long_opts, NULL)) != -1)
    {
        switch (c)
        {
        case 'b': out->benchmark       = optarg; break;
        case 'w': out->warmup_iters    = (size_t)strtoull(optarg, NULL, 10); break;
        case 'i': out->measurement_iters = (size_t)strtoull(optarg, NULL, 10); break;
        case 'B': out->batch_size      = (size_t)strtoull(optarg, NULL, 10); break;
        case 's': out->scenario_path   = optarg; break;
        case 't': out->scenario_target = optarg; break;
        case 'o': out->output_path     = optarg; break;
        case 'l': out->list_and_exit   = 1; break;
        case 'h': chaos_bench_print_usage(stdout, argv[0]); return 1;
        case 'm':
            if (chaos_bench_parse_mode(optarg, &out->mode) != 0)
            {
                fprintf(stderr, "chaos_bench: unknown mode '%s'\n", optarg);
                return -1;
            }
            break;
        default:
            chaos_bench_print_usage(stderr, argv[0]);
            return -1;
        }
    }

    if (!out->list_and_exit && out->benchmark == NULL)
    {
        fprintf(stderr, "chaos_bench: --benchmark is required\n");
        chaos_bench_print_usage(stderr, argv[0]);
        return -1;
    }
    if (out->measurement_iters == 0U ||
        out->measurement_iters > CHAOS_BENCH_MAX_SAMPLES)
    {
        fprintf(stderr, "chaos_bench: --iters must be in [1, %u]\n",
                CHAOS_BENCH_MAX_SAMPLES);
        return -1;
    }
    if (out->batch_size == 0U)
    {
        fprintf(stderr, "chaos_bench: --batch must be > 0\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Copies @p src to @p dst and stamps the destination's mtime to
 *        a future value so the chaos library's reload mechanism picks
 *        the file up on its next prepare() call.
 *
 * @details Mirrors the future-mtime convention used by the runtime
 * probes (test/runtime/\*_probe.c).  A fixed offset (60 s) is large
 * enough that a benchmark process cannot outrun the kernel's mtime
 * granularity.
 */
static int chaos_bench_install_scenario(const char *src, const char *dst)
{
    char       buffer[8192];
    int        in_fd  = -1;
    int        out_fd = -1;
    ssize_t    n;
    struct timespec stamp[2];
    int        rc = -1;

    in_fd = open(src, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0)
    {
        fprintf(stderr, "chaos_bench: cannot open scenario %s: %s\n",
                src, strerror(errno));
        return -1;
    }
    out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out_fd < 0)
    {
        fprintf(stderr, "chaos_bench: cannot write scenario target %s: %s\n",
                dst, strerror(errno));
        (void)close(in_fd);
        return -1;
    }
    while ((n = read(in_fd, buffer, sizeof(buffer))) > 0)
    {
        ssize_t written = 0;
        while (written < n)
        {
            ssize_t w = write(out_fd, buffer + written, (size_t)(n - written));
            if (w < 0)
            {
                fprintf(stderr, "chaos_bench: write %s failed: %s\n",
                        dst, strerror(errno));
                goto cleanup;
            }
            written += w;
        }
    }
    if (n < 0)
    {
        fprintf(stderr, "chaos_bench: read %s failed: %s\n",
                src, strerror(errno));
        goto cleanup;
    }

    /* Future mtime: 60 s ahead of now, mirroring runtime probes. */
    if (clock_gettime(CLOCK_REALTIME, &stamp[0]) != 0)
    {
        fprintf(stderr, "chaos_bench: clock_gettime: %s\n", strerror(errno));
        goto cleanup;
    }
    stamp[0].tv_sec += 60;
    stamp[1] = stamp[0];
    if (futimens(out_fd, stamp) != 0)
    {
        fprintf(stderr, "chaos_bench: futimens %s failed: %s\n",
                dst, strerror(errno));
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (in_fd  >= 0) (void)close(in_fd);
    if (out_fd >= 0) (void)close(out_fd);
    return rc;
}

/**
 * @brief Allocates the descriptor's state buffer (zero-initialised).
 */
static void *chaos_bench_alloc_state(const chaos_bench_descriptor_t *desc)
{
    if (desc->state_size == 0U)
    {
        /* Allocate one byte so the iter callback always receives a
         * non-NULL pointer; the iter must ignore it. */
        return calloc(1U, 1U);
    }
    return calloc(1U, desc->state_size);
}

/**
 * @brief Runs the warmup phase: invokes iter @p iters times without
 *        recording any samples.
 *
 * @details Warmup exists to cross every cold-state threshold before
 * measurement begins:
 *  - Lazy PLT resolution of `clock_gettime` and any other PLT-bound
 *    function used by the iter callback.
 *  - First TLS-slot allocation in the chaos library's reentrancy guard.
 *  - First config snapshot prepare (which includes opening the chaos
 *    config file the wrapper installed).
 *  - Branch predictor and BTB warm-up.
 *  - Page faults on any not-yet-touched pages of the iter callback.
 */
static void chaos_bench_warmup(
    const chaos_bench_descriptor_t *desc, void *user_state, size_t iters
)
{
    size_t i;
    for (i = 0U; i < iters; ++i)
    {
        desc->iter(user_state);
    }
    CHAOS_BENCH_CLOBBER_MEMORY();
}

/**
 * @brief Runs the measurement phase: records per-iteration sample in @p out.
 *
 * @details Each sample is `(t_after - t_before) / batch_size`, converted
 * to ns by the calibrated timer.  We bracket the iter call(s) with full
 * memory clobbers so the optimizer cannot reorder loads/stores across
 * the timing boundary.
 *
 * The inner loop over `batch_size` exists so the timer-overhead tax
 * doesn't dominate sub-100ns measurements.  When `batch_size == 1` the
 * compiler is free to unroll it away.
 */
static void chaos_bench_measure(
    const chaos_bench_descriptor_t *desc,
    void                            *user_state,
    size_t                           iters,
    size_t                           batch_size,
    const chaos_bench_timer_t       *timer,
    double                          *out_ns
)
{
    size_t i;

    for (i = 0U; i < iters; ++i)
    {
        size_t   b;
        uint64_t before;
        uint64_t after;

        CHAOS_BENCH_CLOBBER_MEMORY();
        before = chaos_bench_timer_read(timer);
        for (b = 0U; b < batch_size; ++b)
        {
            desc->iter(user_state);
        }
        after = chaos_bench_timer_read(timer);
        CHAOS_BENCH_CLOBBER_MEMORY();

        out_ns[i] = chaos_bench_timer_cycles_to_ns(timer, after - before)
                  / (double)batch_size;
    }
}

int main(int argc, char **argv)
{
    chaos_bench_args_t          args;
    chaos_bench_env_t           env;
    chaos_bench_warning_t       warnings[CHAOS_BENCH_MAX_WARNINGS];
    size_t                      warning_count;
    chaos_bench_exec_mode_t     exec_mode;
    chaos_bench_timer_t         timer;
    chaos_bench_descriptor_t   *desc;
    chaos_bench_stats_t         stats;
    double                     *samples;
    void                       *state;
    FILE                       *out;
    int                         scenario_active = 0;
    int                         rc_arg;

    rc_arg = chaos_bench_parse_args(argc, argv, &args);
    if (rc_arg < 0) return 2;
    if (rc_arg > 0) return 0;

    if (args.list_and_exit)
    {
        chaos_bench_registry_list(stdout);
        return 0;
    }

    chaos_bench_env_capture(&env);
    exec_mode = chaos_bench_isolation_check(&env, warnings, &warning_count);

    chaos_bench_timer_init(&env, &timer);

    desc = chaos_bench_registry_find(args.benchmark);
    if (desc == NULL)
    {
        fprintf(stderr, "chaos_bench: benchmark '%s' not registered\n",
                args.benchmark);
        return 3;
    }

    /* Install scenario before any iter call (so the chaos library's
     * first reload after warmup picks it up). */
    if (args.scenario_path != NULL && args.scenario_target != NULL)
    {
        if (chaos_bench_install_scenario(args.scenario_path,
                                         args.scenario_target) != 0)
        {
            return 4;
        }
        scenario_active = 1;
    }

    state = chaos_bench_alloc_state(desc);
    if (state == NULL)
    {
        fprintf(stderr, "chaos_bench: cannot alloc state\n");
        return 5;
    }
    if (desc->setup != NULL)
    {
        desc->setup(state);
    }

    samples = calloc(args.measurement_iters, sizeof(*samples));
    if (samples == NULL)
    {
        fprintf(stderr, "chaos_bench: cannot alloc sample buffer\n");
        free(state);
        return 6;
    }

    chaos_bench_warmup(desc, state, args.warmup_iters);

    /* Open PMU after warmup so first-PLT / first-page-fault costs are
     * not counted; close it before stats so the JSON writer can include
     * the deltas. */
    chaos_bench_pmu_t pmu;
    (void)chaos_bench_pmu_init(&pmu);
    chaos_bench_pmu_start(&pmu);

    if (args.mode == CHAOS_BENCH_MODE_SINGLE_SHOT)
    {
        chaos_bench_measure(desc, state, 1U, args.batch_size, &timer, samples);
        chaos_bench_pmu_stop(&pmu);
        chaos_bench_stats_compute(samples, 1U, &stats);
    }
    else
    {
        chaos_bench_measure(desc, state, args.measurement_iters,
                            args.batch_size, &timer, samples);
        chaos_bench_pmu_stop(&pmu);
        chaos_bench_stats_compute(samples, args.measurement_iters, &stats);
    }

    if (desc->teardown != NULL)
    {
        desc->teardown(state);
    }
    free(state);
    free(samples);

    if (args.output_path != NULL)
    {
        out = fopen(args.output_path, "w");
        if (out == NULL)
        {
            fprintf(stderr, "chaos_bench: cannot open output %s: %s\n",
                    args.output_path, strerror(errno));
            return 7;
        }
    }
    else
    {
        out = stdout;
    }

    chaos_bench_json_write_envelope(
        out, desc, args.mode,
        args.warmup_iters, args.measurement_iters, args.batch_size,
        exec_mode, warnings, warning_count,
        &timer, &env,
        args.scenario_path != NULL ? args.scenario_path : "",
        scenario_active,
        &stats,
        &pmu
    );

    chaos_bench_pmu_close(&pmu);

    if (out != stdout)
    {
        (void)fclose(out);
    }

    /* Clean up the installed scenario so subsequent benches start from
     * a known state (the wrapper script also does this for safety). */
    if (scenario_active)
    {
        (void)unlink(args.scenario_target);
    }

    return 0;
}
