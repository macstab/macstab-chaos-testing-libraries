#!/bin/sh
# =============================================================================
# benchmark/release-gate.sh - release-over-release benchmark gate.
#
# Compares this sweep's preloaded runs with those of the last accepted release,
# per variant and benchmark, with benchmark/driver/chaos_bench_driver.py
# --vs-prev. Used by release.yml after a tag and by bench.yml on every pull
# request into main, so the same gate decides before and after the tag.
#
# Usage: benchmark/release-gate.sh <current-root> <report-dir> [<this-tag>]
#   <current-root>  one directory per variant (glibc-amd64, musl-amd64,
#                   glibc-arm64, musl-arm64) holding this sweep's envelopes and
#                   the suite.tsv run-bench.sh copies there; a missing or empty
#                   variant is skipped
#   <report-dir>    receives benchmark-vs-prev-<variant>.md and gate-summary.md
#   <this-tag>      the release being gated, excluded from the baseline search
#
# Baseline: the most recently published release that is neither a draft nor a
# prerelease. Prereleases are excluded because this gate marks a regressed
# release as one: the next release is measured against the last accepted
# release, never against a regressed one. Its bench-envelopes-*-<variant>.tar.gz
# assets are downloaded with gh.
#
# A benchmark is flagged when it is slower than the baseline by more than
# GATE_PCT percent and more than GATE_MIN_NS nanoseconds (median of run
# medians), and the difference is significant (rank-sum p < 0.01, |r| > 0.5).
# A benchmark whose suite.tsv revision differs between the two releases is
# reported as re-baselined and not gated. A variant whose sweep ran on another CPU
# model than the baseline (hosted runners vary) is reported but not gated.
#
# Environment: GH_TOKEN (gh), GATE_PCT (default 15), GATE_MIN_NS (default 25)
# Exit: 0 no regression, or nothing to compare against; 1 a regression on any
# variant; 2 usage error or a failed download.
# =============================================================================

set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <current-root> <report-dir> [<this-tag>]" >&2
    exit 2
fi
CURRENT=$1
REPORTS=$2
THIS_TAG=${3:-}
GATE_PCT=${GATE_PCT:-15}
GATE_MIN_NS=${GATE_MIN_NS:-25}
DRIVER="$(cd "$(dirname "$0")" && pwd)/driver/chaos_bench_driver.py"
VARIANTS="glibc-amd64 musl-amd64 glibc-arm64 musl-arm64"
PREV_DIR=$(mktemp -d)
trap 'rm -rf "$PREV_DIR"' EXIT INT TERM

mkdir -p "$REPORTS"
SUMMARY="$REPORTS/gate-summary.md"

BASELINE=$(gh release list --limit 50 --json tagName,isDraft,isPrerelease,publishedAt \
    --jq "[.[] | select(.tagName != \"$THIS_TAG\" and .isDraft == false
                        and .isPrerelease == false)]
          | sort_by(.publishedAt) | reverse | .[0].tagName // \"\"")

{
    echo "# Release-over-release benchmark gate"
    echo ""
    echo "- Gated: ${THIS_TAG:-this pull request}"
    echo "- Baseline: ${BASELINE:-none} (last published release that is not a prerelease)"
    echo "- Flagged when slower by > ${GATE_PCT} % and > ${GATE_MIN_NS} ns, p < 0.01, |r| > 0.5"
    echo ""
    echo "| Variant | Verdict |"
    echo "|---|---|"
} > "$SUMMARY"

if [ -z "$BASELINE" ]; then
    echo "| all | skipped: no accepted release to compare with |" >> "$SUMMARY"
    echo "release-gate: no accepted release; nothing to compare" >&2
    exit 0
fi

if ! gh release download "$BASELINE" --pattern 'bench-envelopes-*.tar.gz' --dir "$PREV_DIR"; then
    echo "release-gate: cannot download the envelopes of $BASELINE" >&2
    exit 2
fi

any=0
for v in $VARIANTS; do
    if [ -z "$(ls "$CURRENT/$v"/*.json 2>/dev/null)" ]; then
        echo "| $v | skipped: this sweep produced no envelopes |" >> "$SUMMARY"
        continue
    fi
    tarball=$(ls "$PREV_DIR"/bench-envelopes-*-"$v".tar.gz 2>/dev/null | head -1 || true)
    if [ -z "$tarball" ]; then
        echo "| $v | skipped: $BASELINE has no envelopes for it |" >> "$SUMMARY"
        echo "_Gate skipped for ${v}: ${BASELINE} has no envelopes for it._" \
            > "$REPORTS/benchmark-vs-prev-$v.md"
        continue
    fi
    mkdir -p "$PREV_DIR/$v"
    tar -xzf "$tarball" -C "$PREV_DIR/$v"
    rc=0
    python3 "$DRIVER" --vs-prev "$PREV_DIR/$v" \
        --vs-prev-pct "$GATE_PCT" --vs-prev-min-ns "$GATE_MIN_NS" \
        --md --output "$REPORTS/benchmark-vs-prev-$v.md" "$CURRENT/$v" || rc=$?
    case "$rc" in
        0) echo "| $v | pass |" >> "$SUMMARY" ;;
        1) echo "| $v | **regression** (see benchmark-vs-prev-$v.md) |" >> "$SUMMARY"; any=1 ;;
        3) echo "| $v | not gated: baseline and sweep ran on different CPU models |" >> "$SUMMARY" ;;
        *) echo "| $v | driver error (exit $rc) |" >> "$SUMMARY"
           echo "release-gate: driver failed on $v (exit $rc)" >&2
           exit 2 ;;
    esac
done

echo "release-gate: baseline $BASELINE, regression=$any" >&2
exit "$any"
