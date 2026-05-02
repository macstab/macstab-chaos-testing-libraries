# chaos-testing-libraries — Benchmark Harness

A JMH-class benchmark suite for the six `LD_PRELOAD` libraries in this
repository (`libchaos-time`, `libchaos-io`, `libchaos-net`,
`libchaos-dns`, `libchaos-memory`, `libchaos-process`). The harness is
written in C, runs in Docker for portability, and produces
schema-versioned JSON envelopes that capture statistics, hardware
counters, environment provenance, and an explicit `OFFICIAL` /
`ADVISORY` execution mode.

---

## TL;DR

```sh
# Smoke test — 30 seconds:
./benchmark/run-bench.sh --smoke

# Full Stage 1+3 sweep — ~5 minutes for all six subsystems:
./benchmark/run-bench.sh --full

# Same, on musl/Alpine:
./benchmark/run-bench.sh --full --libc=alpine

# Multi-run + A/B comparison:
./benchmark/run-bench.sh --full --runs=5 --compare
```

Reports land in `benchmark/reports/<git-sha>/`. With `--compare`, a
human-readable A/B comparison drops at
`benchmark/reports/<git-sha>/comparison.md`.

---

## Two-tier methodology

| Tier | Where it runs | Variance | Use |
|---|---|---|---|
| **Tier 1 (this repo)** | Docker on any developer machine | 1–25 % | dev-loop change detection, PR CI |
| **Tier 2** | bare-metal Linux with `isolcpus`, `nohz_full`, `governor=performance`, IRQ steered | <1 % | release-grade headline numbers |

The same harness binary runs in both. The JSON envelope's
`execution.mode` field declares which tier the run is from:
`OFFICIAL` only when every isolation precondition is satisfied;
`ADVISORY` everywhere else (including all containers).

The `--compare` driver respects this tag — it will run on `ADVISORY`
data but the consumer is expected to apply tier-appropriate regression
thresholds.

---

## Architecture

```
benchmark/
├── harness/                    # the libchaos-bench library
│   ├── chaos_bench.h           # public API for kernels
│   ├── chaos_bench_timer.c     # rdtscp / cntvct_el0 / clock_gettime; calibrates TSC↔ns
│   ├── chaos_bench_perf.c      # perf_event_open(2) PMU panel; stub on non-Linux
│   ├── chaos_bench_stats.c     # percentile statistics (R-7 interpolation)
│   ├── chaos_bench_env.c       # /proc, /sys, /.dockerenv capture
│   ├── chaos_bench_isolation.c # OFFICIAL/ADVISORY mode decider
│   ├── chaos_bench_json.c      # hand-rolled JSON writer, schema v1
│   ├── chaos_bench_register.c  # constructor-based descriptor registry
│   └── chaos_bench_runner.c    # main: argv → calibrate → measure → emit
├── kernels/
│   ├── bench_time.c            # libchaos-time (clock_gettime)
│   ├── bench_io.c              # libchaos-io (pread)
│   ├── bench_net.c             # libchaos-net (send over AF_UNIX socketpair)
│   ├── bench_dns.c             # libchaos-dns (getaddrinfo localhost)
│   ├── bench_memory.c          # libchaos-memory (madvise DONTNEED)
│   └── bench_process.c         # libchaos-process (pthread_create + join)
├── scenarios/                  # chaos config fixtures, one per cell of the matrix
├── docker/
│   ├── Dockerfile.bench-glibc  # debian:12-slim + gcc + python3
│   └── Dockerfile.bench-alpine # alpine:3.19 + gcc + python3 (musl)
├── driver/
│   └── chaos_bench_driver.py   # A/B comparison: Mann-Whitney U + bootstrap CI
├── Makefile.bench              # opt-in: include from root or invoke directly
├── run-bench.sh                # the orchestrator
├── reports/<git-sha>/          # JSON output (gitignored)
└── README.md                   # this file
```

---

## What we measure

Each library has three benchmarks following the same pattern:

| Benchmark | Description | What's exercised |
|---|---|---|
| `<symbol>_passthrough`   | LD_PRELOAD active, no rule loaded     | TLS guard + snapshot pointer + early-return |
| `<symbol>_match_no_fire` | LD_PRELOAD active, probability=0 rule | TLS guard + snapshot + selector match + dice roll |
| `<symbol>_errno`         | LD_PRELOAD active, probability=1 rule | full effect-dispatch path |

Plus the implicit baseline: same binary run *without* `LD_PRELOAD`, which
gives the absolute reference (raw libc/kernel cost). The driver
compares each `_passthrough`/`_errno`/etc. against the baseline run of
the same benchmark.

The wrapper script (`run-bench.sh`) tags each output JSON with a scenario
name (`baseline`, `passthrough`, `match-no-fire`, `errno`) so the
driver can group and compare without parsing config files.

---

## What the harness defends against

1. **Dead-code elimination** — every iteration calls
   `CHAOS_BENCH_DO_NOT_OPTIMIZE(result)` to mark the call's output as
   live, and `CHAOS_BENCH_CLOBBER_MEMORY()` between iterations to
   prevent loop-invariant code motion.
2. **Timer skew and reordering** — TSC reads use `rdtscp` + `lfence`
   (x86) or `isb; mrs cntvct_el0; isb` (aarch64), preventing the OoO
   engine from reordering the timestamp read past surrounding work.
3. **Cold-call cost** — configurable warmup iterations (default 10 000)
   absorb first-PLT, first-TLS, first-config-read costs.
4. **Sub-ns timer-overhead tax** — `--batch=N` lets you amortize the
   timer-read pair across N ops when single-op cost falls below the
   timer cost.
5. **Cross-trial state leak** — each benchmark runs in a fresh process
   (the wrapper invokes the binary once per benchmark name), giving
   each trial virgin ASLR, branch predictor, and TLB state.

---

## What the harness does NOT do (delegated)

| Concern | Where it is handled | Why |
|---|---|---|
| CPU pinning              | `taskset` / `--cpuset-cpus` | host-level, container can't change |
| Frequency governor       | `cpupower` / `/sys/.../scaling_governor` | host-only API |
| SMT-sibling shutdown     | `/sys/devices/system/cpu/cpu*/online` | host-only |
| IRQ affinity             | `/proc/irq/*/smp_affinity` | host-only |
| LD_PRELOAD setup         | `run-bench.sh` | one concept, set once |
| Page cache state         | `posix_fadvise` / `drop_caches` | per-benchmark setup, currently not needed |

The harness *checks* these at startup and tags `ADVISORY` if any
isolation precondition fails. It does not attempt to *enforce* them.

---

## JSON envelope schema (v1)

```jsonc
{
  "schema_version": 1,
  "benchmark":   { "name": "...", "category": "..." },
  "config":      { "mode": "AVG_TIME", "warmup_iters": 10000, "measurement_iters": 200000, "batch_size": 1 },
  "execution":   { "mode": "OFFICIAL"|"ADVISORY",
                   "warnings": [{"check": "governor", "detail": "..."}, ...] },
  "timer":       { "source": "rdtscp"|"cntvct_el0"|"clock_monotonic_raw",
                   "calibrated_hz": ..., "ns_per_cycle": ...,
                   "calibration_window_ns": ..., "overhead_ns": ... },
  "scenario":    { "path": "...", "active": true|false },
  "stats":       { "samples": N, "min_ns": ..., "max_ns": ...,
                   "mean_ns": ..., "stdev_ns": ...,
                   "median_ns": ..., "p50_ns": ..., "p90_ns": ...,
                   "p99_ns": ..., "p999_ns": ..., "p9999_ns": ... },
  "pmu":         { "available": true|false,
                   "reason": "..." (if false),
                   "counters": { "cycles": N, "instructions": N, "branches": N,
                                 "branch_misses": N, "cache_references": N,
                                 "cache_misses": N, "dtlb_load_misses": N,
                                 "context_switches": N, "cpu_migrations": N,
                                 "page_faults": N } },
  "environment": { "kernel_release": "...", "kernel_version": "...",
                   "cpu_model": "...", "cpu_flags": "...",
                   "governor": "...", "isolated_cpus": "...",
                   "thp_enabled": "...", "libc": "glibc"|"musl"|"unknown",
                   "git_sha": "...", "build_cflags": "...",
                   "ld_preload": "...", "smt_active": true|false,
                   "container": true|false, "constant_tsc": true|false,
                   "nonstop_tsc": true|false }
}
```

Schema bumps are breaking. The `chaos_bench_driver.py` consumer checks
`schema_version` and refuses to compare across mismatched versions.

---

## Running the A/B comparison driver

```sh
python3 benchmark/driver/chaos_bench_driver.py \
    benchmark/reports/<git-sha>/ \
    --md \
    --output benchmark/reports/<git-sha>/comparison.md
```

Per-benchmark output includes:

- **Baseline median (ns)** — median across all `ld_preload=""` runs of this benchmark.
- **Treatment median (ns)** — median across all `ld_preload=<lib>` runs.
- **Δ (ns) and Δ (%)** — treatment minus baseline.
- **p-value** — Mann-Whitney U test (rank-sum, two-sided), normal approximation.
- **r** — rank-biserial effect size, `z / sqrt(n_total)`.
- **95% CI Δ** — bootstrap (2 000 resamples) on the median delta.
- **regression flag (⚠️)** — fires when *all three* of: p < 0.01, |r| > 0.5, Δ > 3 %.

The triple-condition rule prevents false positives from sample-size
inflation alone. Tune via `--regression-p`, `--regression-r`,
`--regression-pct` flags.

---

## Adding a new benchmark

1. **Pick a kernel binary** matching the subsystem
   (`bench_<subsystem>.c` under `benchmark/kernels/`).
2. **Add a state struct, setup, iter, teardown** as plain C functions.
3. **Register with `CHAOS_BENCH(category_lit, name_lit, state_t,
   setup_fn, iter_fn, teardown_fn)`** at the bottom of the file.
4. **Add scenarios** under `benchmark/scenarios/` for the rule cells you
   want to exercise (typically `<lib>-<symbol>-match-no-fire.conf` and
   `<lib>-<symbol>-errno.conf`).
5. **Add `run_one` lines** in `run-bench.sh` for each cell.

The `CHAOS_BENCH` macro expands to a static descriptor + a
`__attribute__((constructor))` that registers it; nothing in the
runner needs editing.

---

## Stage roadmap

| Stage | Status | Capabilities |
|---|---|---|
| **Stage 1** | ✅ done | TSC timer, percentiles, env capture, advisory/official mode, JSON v1, `bench_time` |
| **Stage 2** | ✅ done | `perf_event_open` PMU panel, Python A/B driver with Mann-Whitney + bootstrap CI, Markdown report |
| **Stage 3** | ✅ done | All six subsystem binaries, alpine/musl Docker image, full sweep wrapper |
| **Stage 4** | planned | Reload-contention multi-thread benchmark; sample-time CDF dumps; HTML report; multi-thread sweeps; `fork()` and `posix_spawn()` SINGLE_SHOT benchmarks; `mmap` allocator-size sweep |

Stage 4 deliberately holds the multi-thread reload-contention benchmark
because it is a different shape than per-call microbenchmarks (the unit
of measurement is "CAS-loser overhead per N concurrent threads", not
"ns per call") and warrants its own design pass.

---

## Known limitations and what we explicitly do *not* claim

- **Tier 1 (Docker on developer machine) numbers are not authoritative.**
  Variance is typically 5–25 %. The harness self-flags this as
  `ADVISORY` and the driver respects it.
- **Bootstrap CI is computed pure-Python** in the driver — for very
  large sample sets (>10 k runs per arm) it is slow. Realistic sweeps
  are 5–20 runs per arm; CI computes in under 100 ms there.
- **PMU counters require `CAP_PERFMON` or `perf_event_paranoid <= 2`.**
  `run-bench.sh` adds `--cap-add=SYS_ADMIN` to the Docker invocation
  for this reason. On hardened hosts the JSON envelope's `pmu`
  section will say `available: false` with a precise reason.
- **macOS host runs are sanity-only.** Apple Silicon's `cntvct_el0`
  works for timing, but `/proc` and `/sys` are absent so the
  environment capture is mostly empty. Build verification only.
- **vDSO bypass on glibc.** `libchaos-time` interposes the libc PLT
  entry, which is invoked *before* glibc routes through vDSO. The
  treatment side therefore measures the full libc path; the baseline
  side measures vDSO directly. This is documented architecturally —
  the delta is a real cost, not a regression.
