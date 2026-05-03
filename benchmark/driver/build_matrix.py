#!/usr/bin/env python3
"""build_matrix.py — render a per-variant benchmark matrix Markdown file.

Reads one or more directories of bench JSON envelopes (each tagged with a
variant label like "glibc-amd64") and emits a single Markdown table:
  - Rows:    benchmark names (one per `benchmark.name` in envelope)
  - Columns: variants in fixed order (musl-arm64, musl-amd64,
             glibc-arm64, glibc-amd64)
  - Cells:   "treatment-median (ns) (Δ%)" or "—" if not benched

Intended to be committed to the repo root as ${TAG}-benchmarks.md so
release perf can be browsed online instead of downloaded.
"""

from __future__ import annotations

import argparse
import math
import os
import sys

# chaos_bench_driver lives in the same directory; reuse its loaders.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chaos_bench_driver import _load_dir, _to_sample, _median  # noqa: E402


VARIANT_ORDER = ["musl-arm64", "musl-amd64", "glibc-arm64", "glibc-amd64"]


def _collect(variant_dirs: dict[str, str]) -> dict:
    """Returns {(benchmark, variant): {"baseline": [...ns], "treatment": [...ns]}}."""
    table: dict = {}
    for variant, directory in variant_dirs.items():
        envs = _load_dir(directory)
        for idx, env in enumerate(envs):
            s = _to_sample(env, f"{variant}:{idx}")
            if s is None:
                continue
            key = (s.benchmark, variant)
            slot = table.setdefault(key, {"baseline": [], "treatment": []})
            (slot["treatment"] if s.is_treatment else slot["baseline"]).append(s.median_ns)
    return table


def _cell(slot: dict | None) -> str:
    if not slot or not slot["treatment"]:
        return "—"
    treat = _median(slot["treatment"])
    if math.isnan(treat):
        return "—"
    base = _median(slot["baseline"]) if slot["baseline"] else float("nan")
    if math.isnan(base) or base <= 0:
        return f"{treat:.1f} ns"
    pct = (treat - base) / base * 100.0
    sign = "+" if pct >= 0 else ""
    return f"{treat:.1f} ns ({sign}{pct:.1f}%)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--variant",
        nargs=2,
        action="append",
        metavar=("VARIANT", "DIR"),
        default=[],
        help="repeatable: --variant glibc-amd64 path/to/envelopes",
    )
    ap.add_argument("--output", required=True, help="path to write .md file")
    ap.add_argument("--version", required=True, help="release version, e.g. 1.0.0")
    args = ap.parse_args()

    variant_dirs: dict[str, str] = {}
    for variant, directory in args.variant:
        if variant not in VARIANT_ORDER:
            print(
                f"build_matrix: unknown variant '{variant}' "
                f"(known: {', '.join(VARIANT_ORDER)})",
                file=sys.stderr,
            )
            return 2
        variant_dirs[variant] = directory

    table = _collect(variant_dirs)
    benchmarks = sorted({k[0] for k in table})

    present = [v for v in VARIANT_ORDER if v in variant_dirs]
    missing = [v for v in VARIANT_ORDER if v not in variant_dirs]

    lines: list[str] = [
        f"# chaos-testing-libraries {args.version} — benchmark matrix",
        "",
        "Each cell shows the LD_PRELOAD'd treatment **median latency** "
        "(ns) and the relative overhead vs the no-preload baseline (Δ%).",
        "",
        f"- Variants benched in this release: **{', '.join(present) or '(none)'}**",
    ]
    if missing:
        lines.append(
            f"- Variants not benched: {', '.join(missing)} "
            "(no bench data on this release; cells show \"—\")"
        )
    lines += [
        "",
        "| Benchmark | " + " | ".join(VARIANT_ORDER) + " |",
        "|---" + "|---:" * len(VARIANT_ORDER) + "|",
    ]

    for bench in benchmarks:
        cells = [_cell(table.get((bench, v))) for v in VARIANT_ORDER]
        lines.append(f"| `{bench}` | " + " | ".join(cells) + " |")

    if not benchmarks:
        lines.append("| _no benchmarks loaded_ |" + " |" * len(VARIANT_ORDER))

    lines += [
        "",
        "## Methodology",
        "",
        "- 5 runs per arm (baseline = no `LD_PRELOAD`, treatment = with chaos lib).",
        "- Cell metric = median of treatment-run medians; Δ% = "
        "`(treatment_median − baseline_median) / baseline_median × 100`.",
        "- Statistical regression criteria (Mann-Whitney U + bootstrap CI) live "
        "in [`benchmark/driver/chaos_bench_driver.py`]"
        "(benchmark/driver/chaos_bench_driver.py).",
        "- Methodology + reference-CPU calibration: "
        "[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).",
        "- Tier-1 ADVISORY data from a GitHub Actions runner. For "
        "OFFICIAL-grade absolute numbers, deploy on bare metal with "
        "isolated CPUs.",
        "",
    ]

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
