#!/bin/sh
# =============================================================================
# benchmark/run-bench.sh - baseline vs LD_PRELOAD benchmark sweep in Docker.
#
# Builds a Tier 1 image (glibc or musl), then inside it builds the six
# libchaos libraries and the harness and runs every benchmark twice: without
# LD_PRELOAD (baseline) and with the library plus a scenario copied to its
# rule file (passthrough, match-no-fire, errno). Each run writes one JSON
# envelope, <report-dir>/<benchmark>.<arm>.<run>.json, tagged ADVISORY.
#
# Usage: ./benchmark/run-bench.sh [options]     (run from anywhere)
#   --full            every library and benchmark (default)
#   --smoke           libchaos-time clock_gettime baseline/passthrough only
#   --libc=glibc      Debian 12 image (default)
#   --libc=alpine     Alpine 3.19 musl image (alias: --libc=musl)
#   --runs=N          repeat the whole sweep N times (default 1); the driver
#                     needs >= 5 runs per arm to flag a regression at p < 0.01
#   --compare         after the sweep, write <report-dir>/comparison.md with
#                     benchmark/driver/chaos_bench_driver.py (needs python3)
#   --check-scenarios instead of a sweep, prove every scenario of benchmark/suite.tsv
#                     does what its arm claims: each errno scenario loads (status
#                     state=ok, rules >= 1) and fires (>= 1 hit) on its benchmark, each
#                     match-no-fire scenario is the errno scenario with probability 0,
#                     and each empty scenario loads with 0 rules. Exit 1 on any failure.
#   --in-container    internal: the inner half, run by the outer half
#   -h, --help        print this text
# Environment:
#   BENCH_WARMUP      warmup iterations per run (default 10000)
#   BENCH_ITERS       measured iterations per run (default 200000; slow
#                     kernels use fixed lower caps)
#   BENCH_REPORT_DIR  host report dir (default benchmark/reports/<short-sha>);
#                     mounted into the container as /reports
# The benchmarks, their libraries, iteration caps and scenarios are listed in
# benchmark/suite.tsv.
# Exit: 2 unknown option, 3 no docker, 1 regression flagged by --compare or a
# failed --check-scenarios, otherwise the status of the first failing command.
# =============================================================================

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_WARMUP="${BENCH_WARMUP:-10000}"
BENCH_ITERS="${BENCH_ITERS:-200000}"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo nogit)"
BENCH_REPORT_DIR="${BENCH_REPORT_DIR:-$REPO_ROOT/benchmark/reports/$GIT_SHA}"

mode=full
libc=glibc
runs=1
compare=0
in_container=0
for arg in "$@"; do
    case "$arg" in
        --full)            mode=full ;;
        --check)           mode=check ;;
        --smoke)           mode=smoke ;;
        --libc=glibc)      libc=glibc ;;
        --libc=alpine)     libc=alpine ;;
        --libc=musl)       libc=alpine ;;
        --runs=*)          runs="${arg#--runs=}" ;;
        --compare)         compare=1 ;;
        --check-scenarios) mode=check ;;
        --in-container)    in_container=1 ;;
        -h|--help)
            sed -n '2,38p' "$0"; exit 0 ;;
        *)
            echo "run-bench.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

case "$libc" in
    glibc)  image="chaos-bench-glibc:local"; dockerfile="Dockerfile.bench-glibc" ;;
    alpine) image="chaos-bench-alpine:local"; dockerfile="Dockerfile.bench-alpine" ;;
esac

# ------------------------------------------------------------------ outer ----
if [ "$in_container" -eq 0 ]; then
    cd "$REPO_ROOT"
    if ! command -v docker >/dev/null 2>&1; then
        echo "run-bench.sh: docker not found in PATH" >&2; exit 3
    fi

    echo ">>> building benchmark Docker image $image"
    docker build --quiet -t "$image" \
        -f "benchmark/docker/$dockerfile" benchmark/docker

    mkdir -p "$BENCH_REPORT_DIR"
    echo ">>> running $mode sweep ($libc, $runs run(s)); reports → $BENCH_REPORT_DIR"

    # --cpuset-cpus=0,1 keeps the run on two fixed CPUs so the scheduler cannot
    # migrate it across the whole machine between runs; --memory=2g bounds it.
    # PMU access: --cap-add=SYS_ADMIN satisfies perf_event_open's capability check
    # on every kernel (CAP_PERFMON exists only from Linux 5.8), and
    # seccomp=unconfined lifts Docker's default seccomp profile, which blocks
    # perf_event_open on some Docker versions. Without them the harness still runs
    # and the envelope reports the PMU as unavailable.
    # The report directory is mounted at /reports, so the container writes exactly where
    # --compare (and a BENCH_REPORT_DIR override) reads.
    docker run --rm \
        --cpuset-cpus="0,1" \
        --memory=2g \
        --cap-add=SYS_ADMIN \
        --security-opt seccomp=unconfined \
        -e BENCH_WARMUP="$BENCH_WARMUP" \
        -e BENCH_ITERS="$BENCH_ITERS" \
        -e BENCH_REPORT_DIR=/reports \
        -v "$REPO_ROOT":/work \
        -v "$(cd "$BENCH_REPORT_DIR" && pwd)":/reports \
        "$image" \
        sh /work/benchmark/run-bench.sh --in-container --"$mode" --runs="$runs" --libc="$libc"
    if [ "$mode" = check ]; then
        exit 0
    fi

    if [ "$compare" -eq 1 ]; then
        echo ">>> running A/B comparison driver"
        python3 "$REPO_ROOT/benchmark/driver/chaos_bench_driver.py" \
            --md \
            --output "$BENCH_REPORT_DIR/comparison.md" \
            "$BENCH_REPORT_DIR"
        echo ">>> comparison report: $BENCH_REPORT_DIR/comparison.md"
    fi
    exit $?
fi

# ------------------------------------------------------------------ inner ----
cd /work

# Per-libc build directories: the checkout is bind-mounted, so a shared build/ would let make
# reuse glibc objects in the musl image (or the reverse) and every preload would fail to load.
LIB_DIR=build/bench-$libc
BIN_DIR=benchmark/build/$libc

echo ">>> [container] building chaos libraries into $LIB_DIR"
make -j"$(nproc 2>/dev/null || echo 2)" BUILD_DIR="$LIB_DIR" \
    "$LIB_DIR"/libchaos-time.so \
    "$LIB_DIR"/libchaos-io.so \
    "$LIB_DIR"/libchaos-net.so \
    "$LIB_DIR"/libchaos-dns.so \
    "$LIB_DIR"/libchaos-memory.so \
    "$LIB_DIR"/libchaos-process.so >/dev/null

echo ">>> [container] building benchmark harness + kernels into $BIN_DIR"
make -f benchmark/Makefile.bench BENCH_BUILD_DIR="$BIN_DIR" bench-clean >/dev/null 2>&1 || true
make -f benchmark/Makefile.bench BENCH_BUILD_DIR="$BIN_DIR" bench-build >/dev/null

mkdir -p "$BENCH_REPORT_DIR"

# Scenario files live in the bind-mounted repository; the harness copies the
# chosen one to the library's rule file (--scenario-target) before setup.
SCEN_DIR=/work/benchmark/scenarios
SUITE=/work/benchmark/suite.tsv

run_one() {
    bench_name="$1"; binary="$2"; ld_preload="$3"; scenario="$4"; target="$5"; tag="$6"
    out="$BENCH_REPORT_DIR/${bench_name}.${tag}.${run_idx}.json"
    if [ -n "$ld_preload" ] && [ -n "$scenario" ]; then
        LD_PRELOAD="$ld_preload" \
            "$binary" --benchmark="$bench_name" \
                      --warmup="$BENCH_WARMUP" --iters="$BENCH_ITERS" \
                      --scenario="$scenario" --scenario-target="$target" \
                      --output="$out"
    elif [ -n "$ld_preload" ]; then
        LD_PRELOAD="$ld_preload" \
            "$binary" --benchmark="$bench_name" \
                      --warmup="$BENCH_WARMUP" --iters="$BENCH_ITERS" \
                      --output="$out"
    else
        "$binary" --benchmark="$bench_name" \
                  --warmup="$BENCH_WARMUP" --iters="$BENCH_ITERS" \
                  --output="$out"
    fi
    # A zero exit with no envelope means the run never reached the JSON writer
    # (for example a rule that broke one of the harness's own libc calls).
    if [ ! -s "$out" ]; then
        echo "run-bench.sh: ERROR: $bench_name ($tag) produced no envelope" >&2
        echo "  output:    $out" >&2
        echo "  scenario:  ${scenario:-<none>}" >&2
        echo "  target:    ${target:-<none>}" >&2
        echo "  preload:   ${ld_preload:-<none>}" >&2
        return 1
    fi
}

# Whether bench binary $1 registers benchmark $2 (fallocate and sendfile exist only
# in Linux builds of bench_io).
registered() {
    "$1" --list 2>/dev/null | cut -f 2 | grep -qx "$2"
}

# Rules of a scenario without comments and blank lines; with $2 = zero, every
# trailing probability (`:p`, `@p`) of an errno scenario rewritten to 0.0, which is
# what its match-no-fire scenario must equal.
scenario_rules() {
    sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$1" |
        if [ "${2:-}" = zero ]; then sed -E 's/([:@])1(\.0+)?([[:space:]]|$)/\10.0\3/'; else cat; fi
}

# Sum of the hit counts in the hits files of library $1.
hits_total() {
    cat /tmp/.chaos-"$1".hits.* 2>/dev/null | awk -F '\t' '{ s += $1 } END { print s + 0 }'
}

check_failures=0
check_fail() {
    echo "FAIL $*" >&2
    check_failures=$((check_failures + 1))
}

# check_load LIB BIN BENCH SCENARIO WANT_RULES WANT_HITS: runs BENCH for 64 measured
# iterations (no warmup) with SCENARIO as the rule file and checks that the run succeeds
# and writes its envelope, the library's status (state=ok, rules) and hits.
# WANT_RULES "0" means exactly 0, "+" at least 1; WANT_HITS "+" means at least 64 hits:
# the rule fires on every measured call, not only once (a rule that also breaks the
# kernel's setup or the harness's own calls aborts the run after one hit).
# The rule file is installed here, before the process starts, and stays until it ends:
# the harness's own --scenario install removes it before writing its envelope, and a
# library that intercepts that write (io, net) would reload and replace the status.
check_load() {
    lib="$1"; bin="$2"; bench="$3"; scen="$4"; want_rules="$5"; want_hits="$6"
    rm -f /tmp/.chaos-"$lib".*
    cp "$SCEN_DIR/$scen" /tmp/.chaos-"$lib".conf
    rm -f /tmp/check.json
    run_rc=0
    LD_PRELOAD=/work/"$LIB_DIR"/libchaos-"$lib".so "$bin" --benchmark="$bench" \
        --warmup=0 --iters=64 --output=/tmp/check.json >/tmp/check.out 2>&1 || run_rc=$?
    status=$(cat /tmp/.chaos-"$lib".status 2>/dev/null || true)
    state=$(printf '%s\n' "$status" | sed -n 's/^state=//p')
    rules=$(printf '%s\n' "$status" | sed -n 's/^rules=//p')
    hits=$(hits_total "$lib")
    if [ "$run_rc" -ne 0 ] || [ ! -s /tmp/check.json ]; then
        check_fail "$bench: $scen breaks the run (exit $run_rc): $(tail -n 2 /tmp/check.out | tr '\n' ' ')"
    elif [ "$state" != ok ]; then
        check_fail "$bench: $scen does not load: $(printf '%s' "$status" | tr '\n' ' ')"
    elif [ "$want_rules" = 0 ] && [ "${rules:-x}" != 0 ]; then
        check_fail "$bench: $scen should have no rules, has ${rules:-?}"
    elif [ "$want_rules" = + ] && [ "${rules:-0}" -lt 1 ]; then
        check_fail "$bench: $scen loads no rule"
    elif [ "$want_hits" = + ] && [ "$hits" -lt 64 ]; then
        check_fail "$bench: $scen fires $hits times in 64 calls, not on every call"
    else
        echo "ok   $bench: $scen (rules=${rules}, hits=${hits})"
    fi
    rm -f /tmp/.chaos-"$lib".*
}

if [ "$mode" = check ]; then
    grep -v '^#' "$SUITE" | while read -r lib pt pfx iters empty stem when krev srev; do
        [ -n "$lib" ] || continue
        bin=/work/"$BIN_DIR"/bench_"$lib"
        if ! registered "$bin" "${pfx}_errno"; then
            [ "$when" = linux ] && { echo "skip $pfx: not registered here"; continue; }
            check_fail "${pfx}_errno is not registered in bench_$lib"; continue
        fi
        errno_scen="$stem-errno.conf"
        nofire_scen="$stem-match-no-fire.conf"
        if [ "$(scenario_rules "$SCEN_DIR/$errno_scen" zero)" != "$(scenario_rules "$SCEN_DIR/$nofire_scen")" ]; then
            check_fail "$nofire_scen is not $errno_scen with probability 0"
        fi
        check_load "$lib" "$bin" "${pfx}_errno" "$errno_scen" + +
        check_load "$lib" "$bin" "${pfx}_match_no_fire" "$nofire_scen" + -
        check_load "$lib" "$bin" "$pt" "$empty" 0 -
    done > /tmp/check.log 2>&1
    cat /tmp/check.log
    failed=$(grep -c '^FAIL' /tmp/check.log || true)
    echo ">>> [container] scenario check: $failed failure(s)"
    [ "$failed" -eq 0 ]
    exit
fi

# The suite travels with the envelopes: the release gate reads each benchmark's revision
# from it.
cp "$SUITE" "$BENCH_REPORT_DIR/suite.tsv"

run_idx=0
while [ "$run_idx" -lt "$runs" ]; do
    run_idx=$((run_idx + 1))
    echo ">>> [container] sweep run $run_idx / $runs"
    grep -v '^#' "$SUITE" | while read -r lib pt pfx iters empty stem when krev srev; do
        [ -n "$lib" ] || continue
        [ "$mode" = smoke ] && [ "$when" != smoke ] && continue
        bin=/work/"$BIN_DIR"/bench_"$lib"
        so=/work/"$LIB_DIR"/libchaos-"$lib".so
        tgt=/tmp/.chaos-"$lib".conf
        if [ "$when" = linux ] && ! registered "$bin" "$pt"; then
            echo ">>> [container] $pfx not registered in bench_$lib; skipped"
            continue
        fi
        saved="$BENCH_ITERS"
        [ "$iters" != - ] && BENCH_ITERS="$iters"
        run_one "$pt" "$bin" "" "" "" baseline
        run_one "$pt" "$bin" "$so" "$SCEN_DIR/$empty" "$tgt" passthrough
        if [ "$mode" != smoke ]; then
            run_one "${pfx}_match_no_fire" "$bin" "" "" "" baseline
            run_one "${pfx}_match_no_fire" "$bin" "$so" "$SCEN_DIR/$stem-match-no-fire.conf" "$tgt" match-no-fire
            run_one "${pfx}_errno" "$bin" "" "" "" baseline
            run_one "${pfx}_errno" "$bin" "$so" "$SCEN_DIR/$stem-errno.conf" "$tgt" errno
        fi
        BENCH_ITERS="$saved"
    done
done

echo ">>> [container] reports collected:"
ls -1 "$BENCH_REPORT_DIR" | head -40
echo "    (full list: ls $BENCH_REPORT_DIR)"
