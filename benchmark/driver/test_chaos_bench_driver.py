#!/usr/bin/env python3
"""Tests of chaos_bench_driver.py --vs-prev, the release-over-release gate's decision.

Synthetic envelopes, 10 runs per side, a fixed median per run plus a small spread, so every
case is deterministic. Run: python3 benchmark/driver/test_chaos_bench_driver.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chaos_bench_driver.py")
SUITE_HEADER = "# lib passthrough prefix iters empty stem mode krev srev\n"


def write_sweep(
    directory: str, medians: dict[str, float], suite: str | None, cpu: str = "EPYC 9V74"
) -> None:
    """Writes 10 preloaded envelopes per benchmark (median + 0..9 ns, on @cpu) and suite.tsv."""
    os.makedirs(directory, exist_ok=True)
    for name, median in medians.items():
        for run in range(10):
            envelope = {
                "benchmark": {"name": name},
                "stats": {"median_ns": median + run, "samples": 1000},
                "environment": {"ld_preload": "/lib/libchaos-io.so", "cpu_model": cpu},
            }
            with open(os.path.join(directory, f"{name}.treat.{run}.json"), "w") as fh:
                json.dump(envelope, fh)
    if suite is not None:
        with open(os.path.join(directory, "suite.tsv"), "w") as fh:
            fh.write(SUITE_HEADER + suite)


def gate(prev: str, curr: str, *extra: str) -> tuple[int, str]:
    out = os.path.join(curr, "report.md")
    rc = subprocess.run(
        [sys.executable, DRIVER, "--vs-prev", prev, "--vs-prev-pct", "15", "--md",
         "--output", out, *extra, curr],
        check=False,
    ).returncode
    with open(out, encoding="utf-8") as fh:
        return rc, fh.read()


class VsPrevGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.prev = os.path.join(self.tmp.name, "prev")
        self.curr = os.path.join(self.tmp.name, "curr")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_significant_slowdown_above_both_thresholds_fails(self) -> None:
        row = "io read_passthrough read - io-empty.conf io-read full 1 1\n"
        write_sweep(self.prev, {"read_passthrough": 1000.0}, row)
        write_sweep(self.curr, {"read_passthrough": 1300.0}, row)
        rc, report = gate(self.prev, self.curr, "--vs-prev-min-ns", "25")
        self.assertEqual(rc, 1)
        self.assertIn("read_passthrough ⚠️", report)

    def test_min_ns_keeps_a_small_absolute_slowdown_from_failing(self) -> None:
        row = "time clock_gettime_baseline clock_gettime - empty.conf c smoke 1 1\n"
        write_sweep(self.prev, {"clock_gettime_baseline": 40.0}, row)
        write_sweep(self.curr, {"clock_gettime_baseline": 60.0}, row)  # +50 %, +20 ns
        self.assertEqual(gate(self.prev, self.curr, "--vs-prev-min-ns", "25")[0], 0)
        self.assertEqual(gate(self.prev, self.curr)[0], 1)

    def test_changed_revision_is_rebaselined_not_gated(self) -> None:
        write_sweep(self.prev, {"read_errno": 1000.0},
                    "io read_passthrough read - io-empty.conf io-read full 1 1\n")
        write_sweep(self.curr, {"read_errno": 3000.0},
                    "io read_passthrough read - io-empty.conf io-read full 2 2\n")
        rc, report = gate(self.prev, self.curr)
        self.assertEqual(rc, 0)
        self.assertIn("re-baselined (k1.s1 -> k2.s2), not gated", report)

    def test_different_cpu_is_reported_not_gated(self) -> None:
        row = "dns getnameinfo_passthrough getnameinfo - d.conf d full 1 1\n"
        write_sweep(self.prev, {"getnameinfo_errno": 510.0}, row, cpu="EPYC 9V74")
        write_sweep(self.curr, {"getnameinfo_errno": 641.0}, row, cpu="EPYC 9V45")
        rc, report = gate(self.prev, self.curr, "--vs-prev-min-ns", "25")
        self.assertEqual(rc, 3)
        self.assertIn("Not gated: different CPU", report)
        self.assertIn("different CPU, not gated", report)
        self.assertNotIn("getnameinfo_errno ⚠️", report)  # no row flagged

    def test_same_cpu_slowdown_still_fails(self) -> None:
        row = "dns getnameinfo_passthrough getnameinfo - d.conf d full 1 1\n"
        write_sweep(self.prev, {"getnameinfo_errno": 510.0}, row, cpu="EPYC 9V45")
        write_sweep(self.curr, {"getnameinfo_errno": 641.0}, row, cpu="EPYC 9V45")
        self.assertEqual(gate(self.prev, self.curr, "--vs-prev-min-ns", "25")[0], 1)

    def test_missing_suite_counts_as_revision_one(self) -> None:
        write_sweep(self.prev, {"read_errno": 1000.0, "read_passthrough": 500.0}, None)
        write_sweep(self.curr, {"read_errno": 3000.0, "read_passthrough": 900.0},
                    "io read_passthrough read - io-empty.conf io-read full 1 2\n")
        rc, report = gate(self.prev, self.curr)
        # read_errno's scenario revision moved (s1 -> s2): re-baselined. The passthrough arm
        # depends on the kernel revision only, still 1: gated, and +80 % fails.
        self.assertEqual(rc, 1)
        self.assertIn("read_errno | ", report)
        self.assertIn("re-baselined (k1.s1 -> k1.s2)", report)
        self.assertIn("read_passthrough ⚠️", report)


if __name__ == "__main__":
    unittest.main()
