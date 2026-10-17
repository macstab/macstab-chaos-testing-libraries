# chaos-testing-libraries — Benchmark Harness

Measures what each `libchaos-<lib>` wrapper adds to the call it wraps. Every benchmark
runs the same C loop twice, without `LD_PRELOAD` (baseline) and with the library and a
scenario rule file (treatment); the difference of the medians is the wrapper's cost.
The harness is C, runs in Docker for portability, and writes one schema-versioned JSON
envelope per run with statistics, hardware counters, environment provenance and an
`OFFICIAL` / `ADVISORY` execution mode. Methodology and published numbers:
[`docs/BENCHMARKS.md`](../docs/BENCHMARKS.md).

---

## TL;DR

```sh
./benchmark/run-bench.sh --smoke                  # clock_gettime baseline/passthrough only
./benchmark/run-bench.sh --full                   # every library and benchmark (default)
./benchmark/run-bench.sh --full --libc=alpine     # the same on musl (Alpine 3.19)
./benchmark/run-bench.sh --full --runs=5 --compare
```

Envelopes land in `benchmark/reports/<short-sha>/` as
`<benchmark>.<arm>.<run>.json`. `--compare` then writes
`benchmark/reports/<short-sha>/comparison.md` and exits 1 if the driver flags a
regression. The driver needs at least 5 runs per arm to reach p < 0.01.

| Option / variable | Effect |
|---|---|
| `--smoke` / `--full` | two `clock_gettime` cells / every cell (default) |
| `--libc=glibc` / `--libc=alpine` (`musl`) | Debian 12 image (default) / Alpine 3.19 image |
| `--runs=N` | repeat the whole sweep N times (default 1) |
| `--compare` | run `driver/chaos_bench_driver.py` on the host afterwards (needs `python3`) |
| `BENCH_WARMUP` | warmup iterations per run (default 10 000) |
| `BENCH_ITERS` | measured iterations per run (default 200 000); slow kernels use fixed caps of 20 000, 5 000 (`fork_wait`) and 1 000 (`execve_short`) |
| `BENCH_REPORT_DIR` | host report directory; the container always writes to the default path, so with an override `--compare` reads a directory the sweep did not write |

The container runs with `--cpuset-cpus=0,1`, `--memory=2g`, `--cap-add=SYS_ADMIN` and
`--security-opt seccomp=unconfined`; the last two let `perf_event_open` work.

---

## Two-tier methodology

| Tier | Where it runs | Variance | Use |
|---|---|---|---|
| **Tier 1 (this repo)** | Docker on any developer machine or CI runner | 1–25 % | change detection in the dev loop and PR CI |
| **Tier 2** | bare-metal Linux with `isolcpus`, `nohz_full`, `governor=performance`, IRQs steered | <1 % | release-grade headline numbers |

The same binaries run in both. `execution.mode` in each envelope is `OFFICIAL` only when
every isolation check passes, `ADVISORY` otherwise, which includes every container run
(the `container` check fails on `/.dockerenv`). The driver records the mode but applies
the same thresholds to both; the consumer chooses tier-appropriate thresholds.

| Check | Passes when |
|---|---|
| `governor` | cpu0's governor reads `performance` |
| `isolcpus` | `/sys/devices/system/cpu/isolated` is non-empty (not whether this process runs on one) |
| `container` | `/.dockerenv` is absent |
| `smt` | cpu0's sibling list names one CPU |
| `constant_tsc`, `nonstop_tsc` | the CPU flag is present (x86 only) |

---

## Architecture

```
benchmark/
├── harness/                     # the chaos-bench library linked into every kernel binary
│   ├── chaos_bench.h            # kernel API: CHAOS_BENCH, DO_NOT_OPTIMIZE, CLOBBER_MEMORY
│   ├── chaos_bench_timer.c      # rdtscp / CNTVCT_EL0 / CLOCK_MONOTONIC_RAW; calibration
│   ├── chaos_bench_perf.c       # perf_event_open(2) counter panel; stub off Linux
│   ├── chaos_bench_stats.c      # mean, stdev, R-7 percentiles
│   ├── chaos_bench_env.c        # /proc, /sys, /.dockerenv capture
│   ├── chaos_bench_isolation.c  # OFFICIAL / ADVISORY decision
│   ├── chaos_bench_json.c       # JSON envelope writer, schema v1
│   ├── chaos_bench_register.c   # constructor-based descriptor registry
│   └── chaos_bench_runner.c     # main: options → calibrate → measure → emit
├── kernels/                     # one binary per library, plus bench_meta (harness self-check)
├── scenarios/                   # rule files: <lib>-<fn>-{match-no-fire,errno}.conf, *-empty.conf
├── docker/                      # Dockerfile.bench-glibc (debian:12-slim), -alpine (alpine:3.19)
├── driver/
│   ├── chaos_bench_driver.py    # A/B and release-over-release comparison (stdlib only)
│   └── build_matrix.py          # release benchmark matrix
├── Makefile.bench               # bench-build, bench-list, bench-smoke, bench-validate, bench-clean
├── run-bench.sh                 # the sweep
└── reports/<short-sha>/         # envelopes and comparison.md
```

One process runs one benchmark: options, environment capture, timer calibration
(about 110 ms), scenario install, warmup, measurement, statistics, envelope. A
scenario is copied to the rule file with its mtime set 60 s into the future and removed
after the run.

---

## What we measure

Every measured function has three benchmarks sharing one iteration body; each runs as
a baseline arm and a treatment arm, tagged `baseline`, `passthrough`, `match-no-fire`
or `errno`:

| Benchmark | Treatment rule file | Path measured |
|---|---|---|
| `<fn>_passthrough` | `*-empty.conf` (no rules) | wrapper entry, empty rule set, forward |
| `<fn>_match_no_fire` | matching rule, probability 0 | rule match + probability draw, forward |
| `<fn>_errno` | matching rule, probability 1 | full effect dispatch; the real call is skipped |

`_errno` skips the real function, so its delta can be negative.

| Library | Functions (`<fn>`) |
|---|---|
| `libchaos-time` | `clock_gettime` (passthrough arm named `clock_gettime_baseline`), `nanosleep_zero`, `usleep_zero` |
| `libchaos-io` | `pread`, `read`, `write`, `readv`, `writev`, `open_close`, `openat_close`, `fsync`, `fdatasync`, `ftruncate`, `fallocate`, `sendfile` |
| `libchaos-net` | `send`, `recv`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `socket_close`, `shutdown` (AF_UNIX socketpair) |
| `libchaos-dns` | `getaddrinfo`, `getnameinfo` (loopback, answered from `/etc/hosts`) |
| `libchaos-memory` | `madvise`, `mprotect`, `munmap` |
| `libchaos-process` | `pthread_create`, `waitpid_nohang`, `fork_wait`, `execve_short` |

`--smoke` runs only `clock_gettime_baseline`, both arms. `bench_meta` (`nop_loop_1k`,
`clock_overhead`) validates the harness itself:
`make -f benchmark/Makefile.bench bench-validate`.

---

## What the harness defends against

1. **Dead-code elimination.** `CHAOS_BENCH_DO_NOT_OPTIMIZE(result)` keeps each call's
   result live; `CHAOS_BENCH_CLOBBER_MEMORY()` around each timing window stops the
   compiler from moving memory accesses across it.
2. **Timer reordering.** `rdtscp` followed by `lfence` (x86, only with `constant_tsc`
   and `nonstop_tsc`) or `isb`-bracketed `CNTVCT_EL0` (aarch64) keep the timestamp read
   from overlapping the measured work. Elsewhere `CLOCK_MONOTONIC_RAW` is used.
3. **Bad time base.** The counter rate is calibrated against `CLOCK_MONOTONIC_RAW`
   over 100 ms and cross-checked by an independent 10 ms calibration; the process
   aborts if they differ by more than 1 %.
4. **Timer cost.** The cost of a timer-read pair is measured (median of medians over
   1000 pairs) and reported as `timer.overhead_ns`, not subtracted. `--batch=N` runs N
   calls per timing window for operations near the timer cost.
5. **Cold-call cost.** Warmup iterations (default 10 000) absorb first-PLT, first-TLS
   and first-rule-load costs.
6. **Cross-trial state.** Each benchmark arm runs in a fresh process: its own ASLR
   layout, branch-predictor and TLB state.

Samples are not trimmed (`samples_after_trim == samples`): tail events stay visible in
p99.9 and p99.99.

---

## What the harness does NOT do (delegated)

| Concern | Where it is handled | Why |
|---|---|---|
| CPU pinning | `taskset` / `--cpuset-cpus` (`run-bench.sh` pins to CPUs 0,1) | host-level; the runner never pins |
| Frequency governor | `cpupower` / `/sys/.../scaling_governor` | host-only; checked, not set |
| SMT siblings | `/sys/devices/system/cpu/cpu*/online` | host-only; checked, not set |
| IRQ affinity | `/proc/irq/*/smp_affinity` | host-only; not checked |
| `nohz_full`, `rcu_nocbs`, thermal throttling | host provisioning | no single sysfs signal; shows up as variance |
| `LD_PRELOAD` and scenarios | `run-bench.sh` | the runner never forks or sets the environment |
| Page cache state | `posix_fadvise` / `drop_caches` | not needed by the current kernels |

---

## JSON envelope schema (v1)

```jsonc
{
  "schema_version": 1,
  "benchmark":   { "name": "...", "category": "..." },
  "config":      { "mode": "AVG_TIME"|"SAMPLE_TIME"|"SINGLE_SHOT", "warmup_iters": 10000,
                   "measurement_iters": 200000, "batch_size": 1 },
  "execution":   { "mode": "OFFICIAL"|"ADVISORY",
                   "warnings": [{"check": "governor", "detail": "..."}, ...] },
  "timer":       { "source": "rdtscp"|"cntvct_el0"|"clock_monotonic_raw",
                   "calibrated_hz": ..., "ns_per_cycle": ...,
                   "calibration_window_ns": ..., "overhead_ns": ... },
  "scenario":    { "path": "...", "active": true|false },
  "stats":       { "samples": N, "samples_after_trim": N, "min_ns": ..., "max_ns": ...,
                   "mean_ns": ..., "stdev_ns": ..., "median_ns": ..., "p50_ns": ...,
                   "p90_ns": ..., "p95_ns": ..., "p99_ns": ..., "p999_ns": ...,
                   "p9999_ns": ... },
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

A schema bump is a breaking change. The driver does not check `schema_version`: it
reads `benchmark.name`, `stats.median_ns` and `stats.samples` and skips envelopes
without them, so mixing schema versions in one directory is the caller's error.

---

## Running the A/B comparison driver

```sh
python3 benchmark/driver/chaos_bench_driver.py \
    benchmark/reports/<short-sha>/ \
    --md \
    --output benchmark/reports/<short-sha>/comparison.md
```

Envelopes are grouped by benchmark name; `environment.ld_preload == ""` is the
baseline arm. Per benchmark:

- **Baseline / treatment median (ns)**: median of the per-run medians of each arm.
- **Δ (ns), Δ (%)**: treatment minus baseline.
- **p-value**: Mann-Whitney U, two-sided, normal approximation.
- **r**: rank-biserial effect size, `z / sqrt(n_total)`.
- **95 % CI Δ**: bootstrap over 2000 resamples of the median delta.
- **Regression flag (⚠️)**: all three of p < 0.01, |r| > 0.5, Δ > 3 %. Requiring
  all three stops sample size alone from producing a flag. Tune with
  `--regression-p`, `--regression-r`, `--regression-pct`.

`--vs-prev <dir>` switches to release-over-release mode (treatment against the previous
release's treatment, threshold `--vs-prev-pct`, default 15 %); `release.yml` uses it.
Exit codes: 0 no regression, 1 regression flagged, 2 fatal input error.

---

## Adding a new benchmark

1. **Kernel**: in `benchmark/kernels/bench_<category>.c`, a state struct and
   `setup`, `iter`, `teardown` functions.
2. **Register** `<fn>_passthrough`, `<fn>_match_no_fire` and `<fn>_errno` with
   `CHAOS_BENCH(category_lit, name_lit, state_t, setup_fn, iter_fn, teardown_fn)`.
   The macro expands to a static descriptor and an `__attribute__((constructor))`
   that registers it; the runner needs no edit.
3. **Scenarios**: `benchmark/scenarios/<lib>-<fn>-match-no-fire.conf` and
   `<lib>-<fn>-errno.conf`.
4. **Sweep**: one `run_trio` line in `run-bench.sh` (with an iteration cap for calls
   slower than about 10 µs).
5. Check with `make -f benchmark/Makefile.bench bench-list`.

---

## Stage roadmap

| Stage | Status | Capabilities |
|---|---|---|
| **Stage 1** | ✅ done | TSC timer, percentiles, environment capture, advisory/official mode, JSON v1, `bench_time` |
| **Stage 2** | ✅ done | `perf_event_open` counter panel, Python A/B driver with Mann-Whitney + bootstrap CI, Markdown report |
| **Stage 3** | ✅ done | All six library binaries, Alpine/musl image, full sweep; loop benchmarks for `fork_wait` and `execve_short` |
| **Stage 4** | planned | Reload-contention multi-thread benchmark; sample-time CDF dumps; HTML report; multi-thread sweeps; `posix_spawn` and `SINGLE_SHOT` cold-call benchmarks; `mmap` allocator-size sweep |

The reload-contention benchmark has a different unit of measurement ("CAS-loser
overhead per N concurrent threads", not "ns per call") and needs its own design.

---

## Known limitations and what we explicitly do *not* claim

- **Tier 1 numbers are not authoritative.** Variance is typically 5–25 %; every
  container run is tagged `ADVISORY`.
- **The bootstrap is pure Python.** It is slow above about 10 k runs per arm; at the
  5–20 runs per arm of a realistic sweep it takes under 100 ms.
- **Counters need privilege.** `perf_event_open` needs `CAP_PERFMON` (Linux 5.8+),
  `CAP_SYS_ADMIN`, or `perf_event_paranoid` ≤ 2; `run-bench.sh` adds
  `--cap-add=SYS_ADMIN`. When refused, `pmu.available` is `false` and `pmu.reason`
  carries the `strerror` text.
- **macOS runs are build checks.** `CNTVCT_EL0` times correctly on Apple Silicon, but
  `/proc` and `/sys` are absent, so the environment capture is mostly empty, and the
  libraries themselves build only on Linux.
- **`clock_gettime` stays on the vDSO in both arms.** The wrapper forwards to the libc
  `clock_gettime` resolved with `dlsym(RTLD_NEXT)`, which still reads the vDSO, so the
  delta is the wrapper alone, not a syscall-versus-vDSO difference.
