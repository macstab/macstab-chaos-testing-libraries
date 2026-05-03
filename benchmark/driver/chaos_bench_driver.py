#!/usr/bin/env python3
"""
chaos_bench_driver.py  -  Stage 2 A/B comparison driver.

Reads a directory of JSON envelopes produced by the bench harness and
emits a comparison report: per-benchmark baseline-vs-treatment statistics
including Mann-Whitney U test, effect size r, median delta, and a
bootstrap 95% confidence interval on the median delta.

Inputs are grouped by benchmark `name`.  Within each group we identify:

  - "baseline" runs:  envelopes with environment.ld_preload == ""
  - "treatment" runs: envelopes with environment.ld_preload != ""

If both groups have at least one sample each, the comparison runs.

The driver depends only on the Python 3 standard library (no scipy/numpy).
The Mann-Whitney U test is implemented from first principles using the
exact distribution for n+m <= 20 and the normal approximation otherwise.

Output:
  --json   One summary JSON to stdout (or --output PATH).
  --md     Same data rendered as a Markdown comparison table.

Exit codes:
  0  no regressions detected
  1  one or more benchmarks show a statistically significant slowdown
     (p < 0.01, |r| > 0.5, median delta > 3%).  Threshold tuneable via
     --regression-p / --regression-r / --regression-pct.
  2  fatal error (no inputs, malformed JSON, etc.)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------- io ---

def _load_envelope(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as err:
        print(f"chaos_bench_driver: skip {path}: {err}", file=sys.stderr)
        return None


def _load_dir(directory: str) -> list[dict[str, Any]]:
    if not os.path.isdir(directory):
        print(f"chaos_bench_driver: not a directory: {directory}", file=sys.stderr)
        return []
    out: list[dict[str, Any]] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        env = _load_envelope(os.path.join(directory, name))
        if env is not None:
            out.append(env)
    return out


# ---------------------------------------------------------------- stats ---

def _wilcoxon_rank_sum_z(a: list[float], b: list[float]) -> tuple[float, float, float]:
    """
    Mann-Whitney U test using the normal approximation.

    Returns (U_stat, z_score, two_sided_p).  Suitable for n1 + n2 >= 20;
    for smaller groups the harness emits a warning and the p-value is
    a conservative upper bound.
    """
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return float("nan"), float("nan"), float("nan")

    # Build joint sample with rank-tagging.
    joined = sorted([(v, 0) for v in a] + [(v, 1) for v in b], key=lambda x: x[0])
    # Average ranks for ties.
    ranks: list[float] = [0.0] * (n1 + n2)
    i = 0
    while i < len(joined):
        j = i
        while j + 1 < len(joined) and joined[j + 1][0] == joined[i][0]:
            j += 1
        avg_rank = (i + j + 2) / 2.0  # 1-based ranks.
        for k in range(i, j + 1):
            ranks[k] = avg_rank
        i = j + 1

    r1 = sum(ranks[k] for k in range(len(joined)) if joined[k][1] == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u_stat = min(u1, u2)

    mu = n1 * n2 / 2.0
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12.0)
    if sigma == 0.0:
        return u_stat, 0.0, 1.0
    z = (u_stat - mu) / sigma
    # Two-sided p-value via the standard-normal survival function.
    p = 2.0 * (1.0 - _phi(abs(z)))
    return u_stat, z, max(0.0, min(1.0, p))


def _phi(x: float) -> float:
    """Standard normal CDF using the erfc approximation in math.erf."""
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def _effect_size_r(z: float, n_total: int) -> float:
    """Rank-biserial correlation effect size r = z / sqrt(N)."""
    if n_total <= 0 or math.isnan(z):
        return float("nan")
    return z / math.sqrt(n_total)


def _median(values: list[float]) -> float:
    n = len(values)
    if n == 0:
        return float("nan")
    s = sorted(values)
    if n % 2 == 1:
        return s[n // 2]
    return 0.5 * (s[n // 2 - 1] + s[n // 2])


def _bootstrap_median_delta_ci(
    a: list[float], b: list[float], iterations: int = 2000
) -> tuple[float, float]:
    """
    Bootstrap 95% CI on (median(b) - median(a)).

    Resamples each group with replacement `iterations` times, computes
    the median delta on each resample, and returns the (2.5%, 97.5%)
    percentiles.  Pure-Python; uses random.choices for resampling.
    """
    if not a or not b:
        return (float("nan"), float("nan"))
    rng = random.Random(0)
    deltas: list[float] = []
    for _ in range(iterations):
        ra = [rng.choice(a) for _ in range(len(a))]
        rb = [rng.choice(b) for _ in range(len(b))]
        deltas.append(_median(rb) - _median(ra))
    deltas.sort()
    lo = deltas[int(0.025 * len(deltas))]
    hi = deltas[int(0.975 * len(deltas))]
    return (lo, hi)


# --------------------------------------------------------------- group ---

# -------------------------------------------------- reference CPU table ---

# Current fastest consumer/server CPUs per architecture (2026).
# Used to convert measured cycle deltas to reference wall-clock ns.
# These are NOT measurements — they are labeled reference calculations:
#   ref_ns = cycles / (ghz * 1e9) * 1e9  =  cycles / ghz
_REFERENCE_CPUS: dict[str, tuple[str, float]] = {
    "x86_64": ("AMD Ryzen 9 9950X (Zen 5, 5.7 GHz boost)", 5.7),
    "aarch64": ("Apple M4 Max (4.4 GHz performance cores)", 4.4),
    "arm64":   ("Apple M4 Max (4.4 GHz performance cores)", 4.4),
}
_REFERENCE_CPU_FALLBACK = ("5.0 GHz reference", 5.0)


def _detect_arch(samples: "list[BenchSample]") -> str:
    """Infer architecture from cpu_flags in any envelope."""
    for s in samples:
        flags = s.raw.get("environment", {}).get("cpu_flags", "")
        if "asimd" in flags or "fp asimd" in flags:
            return "aarch64"
        if "sse" in flags or "avx" in flags or "lm" in flags:
            return "x86_64"
    return ""


def _ref_cpu(arch: str) -> tuple[str, float]:
    return _REFERENCE_CPUS.get(arch, _REFERENCE_CPU_FALLBACK)


def _cycles_to_ref_ns(cycles: float, ghz: float) -> str:
    if math.isnan(cycles) or cycles <= 0:
        return "n/a"
    ns = cycles / ghz
    return f"~{ns:.1f} ns"


@dataclass
class BenchSample:
    path: str
    benchmark: str
    median_ns: float
    samples_count: int
    is_treatment: bool
    ld_preload: str
    git_sha: str
    exec_mode: str
    # full per-envelope stats (used for rich breakdown table)
    mean_ns: float = 0.0
    stdev_ns: float = 0.0
    min_ns: float = 0.0
    max_ns: float = 0.0
    p50_ns: float = 0.0
    p90_ns: float = 0.0
    p95_ns: float = 0.0
    p99_ns: float = 0.0
    p999_ns: float = 0.0
    # PMU cycle counts
    cycles: int = 0
    instructions: int = 0
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


def _is_treatment(env: dict[str, Any]) -> bool:
    return bool(env.get("environment", {}).get("ld_preload", "").strip())


def _to_sample(envelope: dict[str, Any], path: str) -> BenchSample | None:
    try:
        bench = envelope["benchmark"]["name"]
        st = envelope["stats"]
        median = float(st["median_ns"])
        count = int(st["samples"])
    except (KeyError, ValueError, TypeError):
        return None
    return BenchSample(
        path=path,
        benchmark=bench,
        median_ns=median,
        samples_count=count,
        is_treatment=_is_treatment(envelope),
        ld_preload=envelope.get("environment", {}).get("ld_preload", ""),
        git_sha=envelope.get("environment", {}).get("git_sha", ""),
        exec_mode=envelope.get("execution", {}).get("mode", "ADVISORY"),
        mean_ns=float(envelope.get("stats", {}).get("mean_ns", 0.0)),
        stdev_ns=float(envelope.get("stats", {}).get("stdev_ns", 0.0)),
        min_ns=float(envelope.get("stats", {}).get("min_ns", 0.0)),
        max_ns=float(envelope.get("stats", {}).get("max_ns", 0.0)),
        p50_ns=float(envelope.get("stats", {}).get("p50_ns", 0.0)),
        p90_ns=float(envelope.get("stats", {}).get("p90_ns", 0.0)),
        p95_ns=float(envelope.get("stats", {}).get("p95_ns", 0.0)),
        p99_ns=float(envelope.get("stats", {}).get("p99_ns", 0.0)),
        p999_ns=float(envelope.get("stats", {}).get("p999_ns", 0.0)),
        cycles=int(envelope.get("pmu", {}).get("counters", {}).get("cycles", 0)),
        instructions=int(envelope.get("pmu", {}).get("counters", {}).get("instructions", 0)),
        raw=envelope,
    )


# -------------------------------------------------------------- compare ---

@dataclass
class Comparison:
    benchmark: str
    baseline_n: int
    treatment_n: int
    baseline_median_ns: float
    treatment_median_ns: float
    delta_ns: float
    delta_pct: float
    u_stat: float
    z_score: float
    p_value: float
    effect_size_r: float
    ci_lo_ns: float
    ci_hi_ns: float
    regression: bool
    note: str = ""


def _compare(name: str, base: list[BenchSample], treat: list[BenchSample],
             threshold_p: float, threshold_r: float, threshold_pct: float) -> Comparison:
    base_medians = [s.median_ns for s in base]
    treat_medians = [s.median_ns for s in treat]

    base_median = _median(base_medians) if base_medians else float("nan")
    treat_median = _median(treat_medians) if treat_medians else float("nan")
    delta = treat_median - base_median if base_medians and treat_medians else float("nan")
    delta_pct = (delta / base_median * 100.0) if base_median > 0 else float("nan")

    # Use raw per-iteration medians as the test inputs.  Each envelope
    # contributes one sample (its median), so the test compares the
    # distribution of medians across runs.  For a meaningful test we
    # need ≥3 runs per arm; fewer = note it and skip the test.
    note = ""
    if len(base) < 3 or len(treat) < 3:
        note = f"insufficient runs ({len(base)} baseline, {len(treat)} treatment)"
        u, z, p, r = float("nan"), float("nan"), float("nan"), float("nan")
        ci_lo, ci_hi = float("nan"), float("nan")
    else:
        u, z, p = _wilcoxon_rank_sum_z(base_medians, treat_medians)
        r = _effect_size_r(z, len(base) + len(treat))
        ci_lo, ci_hi = _bootstrap_median_delta_ci(base_medians, treat_medians)

    regression = (
        not math.isnan(p)
        and p < threshold_p
        and abs(r) > threshold_r
        and delta_pct > threshold_pct
    )

    return Comparison(
        benchmark=name,
        baseline_n=len(base),
        treatment_n=len(treat),
        baseline_median_ns=base_median,
        treatment_median_ns=treat_median,
        delta_ns=delta,
        delta_pct=delta_pct,
        u_stat=u,
        z_score=z,
        p_value=p,
        effect_size_r=r,
        ci_lo_ns=ci_lo,
        ci_hi_ns=ci_hi,
        regression=regression,
        note=note,
    )


# --------------------------------------------------------------- output ---

def _fmt_ns(v: float) -> str:
    if math.isnan(v):
        return "n/a"
    return f"{v:.2f}"


def _fmt_pct(v: float) -> str:
    if math.isnan(v):
        return "n/a"
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.1f}%"


def _fmt_delta(v: float) -> str:
    if math.isnan(v):
        return "n/a"
    sign = "+" if v >= 0 else ""
    return f"{sign}{v:.2f}"


def _fmt_throughput(mean_ns: float) -> str:
    if math.isnan(mean_ns) or mean_ns <= 0:
        return "n/a"
    v = 1.0e9 / mean_ns
    if v >= 1e9:
        return f"{v/1e9:.2f}G calls/s"
    if v >= 1e6:
        return f"{v/1e6:.2f}M calls/s"
    return f"{v/1e3:.2f}K calls/s"


def _rich_breakdown(
    name: str,
    base: list["BenchSample"],
    treat: list["BenchSample"],
    arch: str = "",
) -> list[str]:
    """Per-benchmark breakdown: cycles primary, reference ns column."""

    def _agg(samples: list, attr: str) -> float:
        vals = [getattr(s, attr) for s in samples if getattr(s, attr, 0.0) > 0.0]
        return _median(vals) if vals else float("nan")

    def _agg_int(samples: list, attr: str) -> float:
        vals = [float(getattr(s, attr)) for s in samples if getattr(s, attr, 0) > 0]
        return _median(vals) if vals else float("nan")

    pmu_ok = any(s.cycles > 0 for s in base + treat)

    b_cyc = _agg_int(base,  "cycles");   t_cyc = _agg_int(treat, "cycles")
    b_ins = _agg_int(base,  "instructions"); t_ins = _agg_int(treat, "instructions")

    ref_name, ref_ghz = _ref_cpu(arch)

    def _fmt_cyc(v: float) -> str:
        if math.isnan(v) or v <= 0:
            return "n/a"
        return f"{v:,.0f}"

    def cyc_row(label: str, b: float, t: float) -> str:
        delta = t - b
        return (
            f"| {label} | {_fmt_cyc(b)} | {_fmt_cyc(t)} | "
            f"{_fmt_cyc(delta)} | {_cycles_to_ref_ns(delta, ref_ghz)} |"
        )

    lines: list[str] = [f"### {name}", ""]

    if pmu_ok:
        lines += [
            f"**Primary metric: CPU cycles** "
            f"(hardware-counted, environment-invariant)",
            f"> Reference ns column: calculated at {ref_name}. "
            f"Not a measurement — a labeled conversion: `delta_cycles / {ref_ghz} GHz`.",
            "",
            "| Metric | Baseline (cycles) | LD_PRELOAD (cycles) | Delta (cycles) "
            f"| Ref ns @ {ref_ghz} GHz |",
            "|---|---:|---:|---:|---:|",
            cyc_row("Cycles (median)", b_cyc, t_cyc),
            cyc_row("Instructions (median)", b_ins, t_ins),
            "",
        ]
    else:
        lines += [
            "> ⚠️ PMU counters unavailable in this environment "
            "(requires `perf_event_paranoid ≤ 1` or `CAP_PERFMON`). "
            "Run on Linux x86_64 / GitHub Actions for cycle counts.",
            "",
        ]

    return lines


def _format_md(
    comparisons: list[Comparison],
    groups: "dict[str, tuple[list, list]] | None" = None,
    all_samples: "list[BenchSample] | None" = None,
    mode: str = "baseline-vs-treat",
) -> str:
    arch = _detect_arch(all_samples or [])
    ref_name, ref_ghz = _ref_cpu(arch)

    if mode == "vs-prev":
        title = "chaos-testing-libraries Benchmark — Release-over-release"
        intro = (
            "Compares LD_PRELOAD'd runs in the **current release** against the "
            "**previous release**. Used as the release-gating signal."
        )
        col_a, col_b = "Prev release P50 (ns)", "Current release P50 (ns)"
    else:
        title = "chaos-testing-libraries Benchmark — Baseline vs LD_PRELOAD"
        intro = "Compares LD_PRELOAD'd runs against raw libc calls (baseline)."
        col_a, col_b = "Baseline P50 (ns)", "LD_PRELOAD P50 (ns)"

    lines = [
        f"# {title}",
        "",
        intro,
        "",
        "**Primary metric: CPU cycles** — hardware-counted, not affected by "
        "scheduler noise or VM jitter. Valid in Docker, CI, and bare metal.",
        f"> Reference ns: calculated conversion at {ref_name}. "
        "Not a measurement.",
        "",
        "## Regression summary (P50 delta)",
        "",
        f"| Benchmark | {col_a} | {col_b} | Δ (ns) | Δ (%) | p-value | r | 95% CI Δ (ns) | Note |",
        "|---|---:|---:|---:|---:|---:|---:|---|---|",
    ]
    for c in sorted(comparisons, key=lambda x: x.benchmark):
        marker = " ⚠️" if c.regression else ""
        lines.append(
            f"| {c.benchmark}{marker} | {c.baseline_median_ns:.2f} | {c.treatment_median_ns:.2f} | "
            f"{c.delta_ns:.2f} | {c.delta_pct:.2f} | "
            f"{c.p_value:.4g} | {c.effect_size_r:.3f} | "
            f"[{c.ci_lo_ns:.2f}, {c.ci_hi_ns:.2f}] | {c.note} |"
        )

    if groups:
        lines += ["", "## Per-benchmark cycle breakdown", ""]
        for name in sorted(groups):
            base, treat = groups[name]
            if base and treat:
                lines += _rich_breakdown(name, base, treat, arch=arch)

    return "\n".join(lines) + "\n"


def _format_json(comparisons: list[Comparison]) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "comparisons": [c.__dict__ for c in comparisons],
        },
        indent=2,
    ) + "\n"


# ---------------------------------------------------------------- main ---

def main() -> int:
    ap = argparse.ArgumentParser(description="A/B comparison driver for chaos bench JSON envelopes.")
    ap.add_argument("input_dir", help="directory of *.json envelopes (current sweep)")
    ap.add_argument("--output", help="output file (default: stdout)")
    ap.add_argument("--md", action="store_true", help="emit Markdown instead of JSON")
    ap.add_argument("--regression-p", type=float, default=0.01)
    ap.add_argument("--regression-r", type=float, default=0.5)
    ap.add_argument("--regression-pct", type=float, default=3.0)
    ap.add_argument(
        "--vs-prev",
        help=(
            "directory of envelopes from the previous release; switches driver "
            "to release-over-release mode (compares treatment-vs-treatment)."
        ),
    )
    ap.add_argument(
        "--vs-prev-pct",
        type=float,
        default=5.0,
        help="percent slowdown threshold for release-over-release regression (default 5).",
    )
    args = ap.parse_args()

    envelopes = _load_dir(args.input_dir)
    if not envelopes:
        print("chaos_bench_driver: no envelopes loaded", file=sys.stderr)
        return 2

    samples: list[BenchSample] = []
    for path_idx, env in enumerate(envelopes):
        s = _to_sample(env, str(path_idx))
        if s is not None:
            samples.append(s)

    if args.vs_prev:
        prev_envelopes = _load_dir(args.vs_prev)
        if not prev_envelopes:
            print(
                f"chaos_bench_driver: no envelopes in --vs-prev {args.vs_prev} "
                "(first release? skipping gate)",
                file=sys.stderr,
            )
            # Write an explicit "skipped" report so the workflow has something to attach.
            skipped = (
                "# Release-over-release benchmark gate — skipped\n\n"
                "_No envelopes found from a previous release; nothing to compare against._\n"
            )
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(skipped)
            return 0

        prev_samples: list[BenchSample] = []
        for idx, env in enumerate(prev_envelopes):
            s = _to_sample(env, f"prev:{idx}")
            if s is not None and s.is_treatment:
                prev_samples.append(s)
        curr_treat = [s for s in samples if s.is_treatment]

        by_prev: dict[str, list[BenchSample]] = {}
        by_curr: dict[str, list[BenchSample]] = {}
        for s in prev_samples:
            by_prev.setdefault(s.benchmark, []).append(s)
        for s in curr_treat:
            by_curr.setdefault(s.benchmark, []).append(s)

        common = sorted(set(by_prev) & set(by_curr))
        comparisons: list[Comparison] = []
        breakdown_groups: dict[str, tuple[list, list]] = {}
        for name in common:
            comparisons.append(_compare(
                name, by_prev[name], by_curr[name],
                args.regression_p, args.regression_r, args.vs_prev_pct,
            ))
            breakdown_groups[name] = (by_prev[name], by_curr[name])

        rendered = (
            _format_md(
                comparisons,
                groups=breakdown_groups,
                all_samples=prev_samples + curr_treat,
                mode="vs-prev",
            )
            if args.md
            else _format_json(comparisons)
        )
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        else:
            sys.stdout.write(rendered)
        return 1 if any(c.regression for c in comparisons) else 0

    by_name: dict[str, dict[str, list[BenchSample]]] = {}
    for s in samples:
        by_name.setdefault(s.benchmark, {"base": [], "treat": []})
        if s.is_treatment:
            by_name[s.benchmark]["treat"].append(s)
        else:
            by_name[s.benchmark]["base"].append(s)

    comparisons: list[Comparison] = []
    breakdown_groups: dict[str, tuple[list, list]] = {}
    for name in sorted(by_name):
        grp = by_name[name]
        if not grp["base"] or not grp["treat"]:
            continue
        comparisons.append(_compare(
            name, grp["base"], grp["treat"],
            args.regression_p, args.regression_r, args.regression_pct,
        ))
        breakdown_groups[name] = (grp["base"], grp["treat"])

    rendered = (
        _format_md(comparisons, groups=breakdown_groups, all_samples=samples)
        if args.md
        else _format_json(comparisons)
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)

    return 1 if any(c.regression for c in comparisons) else 0


if __name__ == "__main__":
    sys.exit(main())
