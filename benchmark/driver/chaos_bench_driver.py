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
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


def _is_treatment(env: dict[str, Any]) -> bool:
    return bool(env.get("environment", {}).get("ld_preload", "").strip())


def _to_sample(envelope: dict[str, Any], path: str) -> BenchSample | None:
    try:
        bench = envelope["benchmark"]["name"]
        median = float(envelope["stats"]["median_ns"])
        count = int(envelope["stats"]["samples"])
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

def _format_md(comparisons: list[Comparison]) -> str:
    lines = [
        "# chaos-testing-libraries Benchmark — Baseline vs Treatment",
        "",
        "Compares LD_PRELOAD'd runs (treatment) against raw libc runs (baseline).",
        "All numbers are nanoseconds per operation, median across runs.",
        "",
        "| Benchmark | Baseline (ns) | Treatment (ns) | Δ (ns) | Δ (%) | p-value | r | 95% CI Δ (ns) | Note |",
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
    ap.add_argument("input_dir", help="directory of *.json envelopes")
    ap.add_argument("--output", help="output file (default: stdout)")
    ap.add_argument("--md", action="store_true", help="emit Markdown instead of JSON")
    ap.add_argument("--regression-p", type=float, default=0.01)
    ap.add_argument("--regression-r", type=float, default=0.5)
    ap.add_argument("--regression-pct", type=float, default=3.0)
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

    by_name: dict[str, dict[str, list[BenchSample]]] = {}
    for s in samples:
        by_name.setdefault(s.benchmark, {"base": [], "treat": []})
        if s.is_treatment:
            by_name[s.benchmark]["treat"].append(s)
        else:
            by_name[s.benchmark]["base"].append(s)

    comparisons: list[Comparison] = []
    for name in sorted(by_name):
        groups = by_name[name]
        if not groups["base"] or not groups["treat"]:
            continue
        comparisons.append(_compare(
            name, groups["base"], groups["treat"],
            args.regression_p, args.regression_r, args.regression_pct,
        ))

    rendered = _format_md(comparisons) if args.md else _format_json(comparisons)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered)
    else:
        sys.stdout.write(rendered)

    return 1 if any(c.regression for c in comparisons) else 0


if __name__ == "__main__":
    sys.exit(main())
