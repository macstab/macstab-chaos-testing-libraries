#!/bin/sh
# =============================================================================
# benchmark/run-bench.sh
#
# Stage 2/3 wrapper: drives the chaos-bench harness inside the Tier 1
# Docker images (glibc/debian or musl/alpine), builds the .so libraries
# and the harness, runs each benchmark with the right scenario / LD_PRELOAD
# combination, collects JSON envelopes into benchmark/reports/<git-sha>/,
# and (optionally) runs the A/B comparison driver.
#
# Usage:
#   ./benchmark/run-bench.sh [--smoke|--full]      # default: full
#   ./benchmark/run-bench.sh --libc=alpine         # musl image instead of glibc
#   ./benchmark/run-bench.sh --runs=N              # repeat each cell N times
#   ./benchmark/run-bench.sh --compare             # run driver after sweep
#   ./benchmark/run-bench.sh --in-container        # inner mode (set by Docker)
#
# Environment overrides:
#   BENCH_WARMUP       warmup iterations (default: 10000)
#   BENCH_ITERS        measurement iterations (default: 200000)
#   BENCH_REPORT_DIR   output directory (default: benchmark/reports/<sha>)
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
        --smoke)           mode=smoke ;;
        --libc=glibc)      libc=glibc ;;
        --libc=alpine)     libc=alpine ;;
        --libc=musl)       libc=alpine ;;
        --runs=*)          runs="${arg#--runs=}" ;;
        --compare)         compare=1 ;;
        --in-container)    in_container=1 ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
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

    # --cap-add SYS_ADMIN gives the container CAP_PERFMON-equivalent on
    # most distros so perf_event_open works.  --security-opt is needed
    # on hardened daemons.  Without these the harness still runs, but
    # the JSON envelope will say `pmu.available: false`.
    docker run --rm \
        --cpuset-cpus="0,1" \
        --memory=2g \
        --cap-add=SYS_ADMIN \
        --security-opt seccomp=unconfined \
        -e BENCH_WARMUP="$BENCH_WARMUP" \
        -e BENCH_ITERS="$BENCH_ITERS" \
        -e BENCH_REPORT_DIR=/work/benchmark/reports/"$GIT_SHA" \
        -v "$REPO_ROOT":/work \
        "$image" \
        sh /work/benchmark/run-bench.sh --in-container --"$mode" --runs="$runs"

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

echo ">>> [container] building chaos libraries"
make -j"$(nproc 2>/dev/null || echo 2)" \
    build/libchaos-time.so \
    build/libchaos-io.so \
    build/libchaos-net.so \
    build/libchaos-dns.so \
    build/libchaos-memory.so \
    build/libchaos-process.so >/dev/null

echo ">>> [container] building benchmark harness + kernels"
make -f benchmark/Makefile.bench bench-clean >/dev/null 2>&1 || true
make -f benchmark/Makefile.bench bench-build >/dev/null

mkdir -p "$BENCH_REPORT_DIR"

# Map (subsystem, scenario_tag) → (LD_PRELOAD path, target path).
SCEN_DIR=/work/benchmark/scenarios

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
}

run_idx=0
while [ "$run_idx" -lt "$runs" ]; do
    run_idx=$((run_idx + 1))
    echo ">>> [container] sweep run $run_idx / $runs"

    # ---- libchaos-time ---------------------------------------------------
    BIN=/work/benchmark/build/bench_time
    LIB=/work/build/libchaos-time.so
    TGT=/tmp/.chaos-time.conf
    run_one clock_gettime_baseline "$BIN" "" "" "" baseline
    run_one clock_gettime_baseline "$BIN" "$LIB" "$SCEN_DIR/empty.conf" "$TGT" passthrough
    if [ "$mode" = full ]; then
        run_one clock_gettime_match_no_fire "$BIN" "" "" "" baseline
        run_one clock_gettime_match_no_fire "$BIN" "$LIB" \
                "$SCEN_DIR/clock_gettime-match-no-fire.conf" "$TGT" match-no-fire
        run_one clock_gettime_errno "$BIN" "" "" "" baseline
        run_one clock_gettime_errno "$BIN" "$LIB" \
                "$SCEN_DIR/clock_gettime-errno.conf" "$TGT" errno
    fi

    if [ "$mode" = smoke ]; then continue; fi

    # ---- libchaos-io -----------------------------------------------------
    BIN=/work/benchmark/build/bench_io
    LIB=/work/build/libchaos-io.so
    TGT=/tmp/.chaos-io.conf
    run_one pread_passthrough   "$BIN" "" "" "" baseline
    run_one pread_passthrough   "$BIN" "$LIB" "$SCEN_DIR/io-empty.conf" "$TGT" passthrough
    run_one pread_match_no_fire "$BIN" "" "" "" baseline
    run_one pread_match_no_fire "$BIN" "$LIB" "$SCEN_DIR/io-pread-match-no-fire.conf" "$TGT" match-no-fire
    run_one pread_errno         "$BIN" "" "" "" baseline
    run_one pread_errno         "$BIN" "$LIB" "$SCEN_DIR/io-pread-errno.conf" "$TGT" errno

    # ---- libchaos-net ----------------------------------------------------
    BIN=/work/benchmark/build/bench_net
    LIB=/work/build/libchaos-net.so
    TGT=/tmp/.chaos-net.conf
    run_one send_passthrough   "$BIN" "" "" "" baseline
    run_one send_passthrough   "$BIN" "$LIB" "$SCEN_DIR/net-empty.conf" "$TGT" passthrough
    run_one send_match_no_fire "$BIN" "" "" "" baseline
    run_one send_match_no_fire "$BIN" "$LIB" "$SCEN_DIR/net-send-match-no-fire.conf" "$TGT" match-no-fire
    run_one send_errno         "$BIN" "" "" "" baseline
    run_one send_errno         "$BIN" "$LIB" "$SCEN_DIR/net-send-errno.conf" "$TGT" errno

    # ---- libchaos-dns ----------------------------------------------------
    BIN=/work/benchmark/build/bench_dns
    LIB=/work/build/libchaos-dns.so
    TGT=/tmp/.chaos-dns.conf
    run_one getaddrinfo_passthrough   "$BIN" "" "" "" baseline
    run_one getaddrinfo_passthrough   "$BIN" "$LIB" "$SCEN_DIR/dns-empty.conf" "$TGT" passthrough
    run_one getaddrinfo_match_no_fire "$BIN" "" "" "" baseline
    run_one getaddrinfo_match_no_fire "$BIN" "$LIB" "$SCEN_DIR/dns-getaddrinfo-match-no-fire.conf" "$TGT" match-no-fire
    run_one getaddrinfo_errno         "$BIN" "" "" "" baseline
    run_one getaddrinfo_errno         "$BIN" "$LIB" "$SCEN_DIR/dns-getaddrinfo-errno.conf" "$TGT" errno

    # ---- libchaos-memory -------------------------------------------------
    BIN=/work/benchmark/build/bench_memory
    LIB=/work/build/libchaos-memory.so
    TGT=/tmp/.chaos-memory.conf
    run_one madvise_passthrough   "$BIN" "" "" "" baseline
    run_one madvise_passthrough   "$BIN" "$LIB" "$SCEN_DIR/memory-empty.conf" "$TGT" passthrough
    run_one madvise_match_no_fire "$BIN" "" "" "" baseline
    run_one madvise_match_no_fire "$BIN" "$LIB" "$SCEN_DIR/memory-madvise-match-no-fire.conf" "$TGT" match-no-fire
    run_one madvise_errno         "$BIN" "" "" "" baseline
    run_one madvise_errno         "$BIN" "$LIB" "$SCEN_DIR/memory-madvise-errno.conf" "$TGT" errno

    # ---- libchaos-process ------------------------------------------------
    BIN=/work/benchmark/build/bench_process
    LIB=/work/build/libchaos-process.so
    TGT=/tmp/.chaos-process.conf
    # pthread_create is ~10 µs/op; run with fewer iters to keep wall time reasonable.
    SAVED_ITERS="$BENCH_ITERS"
    BENCH_ITERS=20000
    run_one pthread_create_passthrough   "$BIN" "" "" "" baseline
    run_one pthread_create_passthrough   "$BIN" "$LIB" "$SCEN_DIR/process-empty.conf" "$TGT" passthrough
    run_one pthread_create_match_no_fire "$BIN" "" "" "" baseline
    run_one pthread_create_match_no_fire "$BIN" "$LIB" "$SCEN_DIR/process-pthread-match-no-fire.conf" "$TGT" match-no-fire
    run_one pthread_create_errno         "$BIN" "" "" "" baseline
    run_one pthread_create_errno         "$BIN" "$LIB" "$SCEN_DIR/process-pthread-errno.conf" "$TGT" errno
    BENCH_ITERS="$SAVED_ITERS"
done

echo ">>> [container] reports collected:"
ls -1 "$BENCH_REPORT_DIR" | head -40
echo "    (full list: ls $BENCH_REPORT_DIR)"
