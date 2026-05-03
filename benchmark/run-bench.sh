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
    # Sanity check: the bench harness always writes a JSON envelope on
    # successful completion.  Empty/missing file means the binary
    # crashed before reaching the runner output stage — usually a chaos
    # rule self-DOS'd a libc call at startup, a scenario syntax error,
    # or an unknown --benchmark name.  Set -e will already have aborted
    # on non-zero exit; this guards the "exit 0, no output" case.
    if [ ! -s "$out" ]; then
        echo "run-bench.sh: ERROR: $bench_name ($tag) produced no envelope" >&2
        echo "  output:    $out" >&2
        echo "  scenario:  ${scenario:-<none>}" >&2
        echo "  target:    ${target:-<none>}" >&2
        echo "  preload:   ${ld_preload:-<none>}" >&2
        return 1
    fi
}

# Run a baseline + 3-scenario trio for one hooked function with optional
# per-call iter throttling.  Heavy hooks like fork/execve/getaddrinfo
# pass an "iters" override; cheap hooks pass "" to keep BENCH_ITERS.
# Args: bench_prefix, iters_override, binary, lib, empty_conf, conf_stem, target
run_trio() {
    pfx="$1"; iters="$2"; bin="$3"; lib="$4"; empty="$5"; stem="$6"; tgt="$7"
    saved="$BENCH_ITERS"
    [ -n "$iters" ] && BENCH_ITERS="$iters"
    run_one "${pfx}_passthrough"    "$bin" "" "" "" baseline
    run_one "${pfx}_passthrough"    "$bin" "$lib" "$SCEN_DIR/$empty" "$tgt" passthrough
    run_one "${pfx}_match_no_fire"  "$bin" "" "" "" baseline
    run_one "${pfx}_match_no_fire"  "$bin" "$lib" "$SCEN_DIR/${stem}-match-no-fire.conf" "$tgt" match-no-fire
    run_one "${pfx}_errno"          "$bin" "" "" "" baseline
    run_one "${pfx}_errno"          "$bin" "$lib" "$SCEN_DIR/${stem}-errno.conf" "$tgt" errno
    BENCH_ITERS="$saved"
}

# Run a baseline + 3-scenario trio for one hooked function with optional
# per-call iter throttling.  Heavy hooks like fork/execve/getaddrinfo
# pass an "iters" override; cheap hooks pass "" to keep BENCH_ITERS.
# Args: bench_prefix, iters_override, binary, lib, empty_conf, conf_stem, target
run_trio() {
    pfx="$1"; iters="$2"; bin="$3"; lib="$4"; empty="$5"; stem="$6"; tgt="$7"
    saved="$BENCH_ITERS"
    [ -n "$iters" ] && BENCH_ITERS="$iters"
    run_one "${pfx}_passthrough"    "$bin" "" "" "" baseline
    run_one "${pfx}_passthrough"    "$bin" "$lib" "$SCEN_DIR/$empty" "$tgt" passthrough
    run_one "${pfx}_match_no_fire"  "$bin" "" "" "" baseline
    run_one "${pfx}_match_no_fire"  "$bin" "$lib" "$SCEN_DIR/${stem}-match-no-fire.conf" "$tgt" match-no-fire
    run_one "${pfx}_errno"          "$bin" "" "" "" baseline
    run_one "${pfx}_errno"          "$bin" "$lib" "$SCEN_DIR/${stem}-errno.conf" "$tgt" errno
    BENCH_ITERS="$saved"
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
        run_trio nanosleep_zero "" "$BIN" "$LIB" empty.conf time-nanosleep "$TGT"
        run_trio usleep_zero    "" "$BIN" "$LIB" empty.conf time-usleep    "$TGT"
    fi

    if [ "$mode" = smoke ]; then continue; fi

    # ---- libchaos-io -----------------------------------------------------
    BIN=/work/benchmark/build/bench_io
    LIB=/work/build/libchaos-io.so
    TGT=/tmp/.chaos-io.conf
    run_trio pread        ""      "$BIN" "$LIB" io-empty.conf io-pread        "$TGT"
    run_trio read         ""      "$BIN" "$LIB" io-empty.conf io-read         "$TGT"
    run_trio write        ""      "$BIN" "$LIB" io-empty.conf io-write        "$TGT"
    run_trio readv        ""      "$BIN" "$LIB" io-empty.conf io-readv        "$TGT"
    run_trio writev       ""      "$BIN" "$LIB" io-empty.conf io-writev       "$TGT"
    run_trio open_close   20000   "$BIN" "$LIB" io-empty.conf io-open-close   "$TGT"
    run_trio openat_close 20000   "$BIN" "$LIB" io-empty.conf io-openat-close "$TGT"
    run_trio fsync        20000   "$BIN" "$LIB" io-empty.conf io-fsync        "$TGT"
    run_trio fdatasync    20000   "$BIN" "$LIB" io-empty.conf io-fdatasync    "$TGT"
    run_trio ftruncate    ""      "$BIN" "$LIB" io-empty.conf io-ftruncate    "$TGT"
    # Linux-only kernels (compiled out on Darwin); the binary returns
    # "unknown benchmark" silently if absent — `|| true` gates that.
    run_trio fallocate    20000   "$BIN" "$LIB" io-empty.conf io-fallocate    "$TGT" || true
    run_trio sendfile     ""      "$BIN" "$LIB" io-empty.conf io-sendfile     "$TGT" || true

    # ---- libchaos-net ----------------------------------------------------
    BIN=/work/benchmark/build/bench_net
    LIB=/work/build/libchaos-net.so
    TGT=/tmp/.chaos-net.conf
    run_trio send         ""      "$BIN" "$LIB" net-empty.conf net-send         "$TGT"
    run_trio recv         ""      "$BIN" "$LIB" net-empty.conf net-recv         "$TGT"
    run_trio sendto       ""      "$BIN" "$LIB" net-empty.conf net-sendto       "$TGT"
    run_trio recvfrom     ""      "$BIN" "$LIB" net-empty.conf net-recvfrom     "$TGT"
    run_trio sendmsg      ""      "$BIN" "$LIB" net-empty.conf net-sendmsg      "$TGT"
    run_trio recvmsg      ""      "$BIN" "$LIB" net-empty.conf net-recvmsg      "$TGT"
    run_trio socket_close 20000   "$BIN" "$LIB" net-empty.conf net-socket-close "$TGT"
    run_trio shutdown     20000   "$BIN" "$LIB" net-empty.conf net-shutdown     "$TGT"

    # ---- libchaos-dns ----------------------------------------------------
    BIN=/work/benchmark/build/bench_dns
    LIB=/work/build/libchaos-dns.so
    TGT=/tmp/.chaos-dns.conf
    run_trio getaddrinfo 20000  "$BIN" "$LIB" dns-empty.conf dns-getaddrinfo "$TGT"
    run_trio getnameinfo 20000  "$BIN" "$LIB" dns-empty.conf dns-getnameinfo "$TGT"

    # ---- libchaos-memory -------------------------------------------------
    BIN=/work/benchmark/build/bench_memory
    LIB=/work/build/libchaos-memory.so
    TGT=/tmp/.chaos-memory.conf
    run_trio madvise  ""  "$BIN" "$LIB" memory-empty.conf memory-madvise  "$TGT"
    run_trio mprotect ""  "$BIN" "$LIB" memory-empty.conf memory-mprotect "$TGT"
    run_trio munmap   ""  "$BIN" "$LIB" memory-empty.conf memory-munmap   "$TGT"

    # ---- libchaos-process ------------------------------------------------
    BIN=/work/benchmark/build/bench_process
    LIB=/work/build/libchaos-process.so
    TGT=/tmp/.chaos-process.conf
    run_trio pthread_create  20000 "$BIN" "$LIB" process-empty.conf process-pthread "$TGT"
    run_trio waitpid_nohang  ""    "$BIN" "$LIB" process-empty.conf process-waitpid "$TGT"
    run_trio fork_wait       5000  "$BIN" "$LIB" process-empty.conf process-fork    "$TGT"
    run_trio execve_short    1000  "$BIN" "$LIB" process-empty.conf process-execve  "$TGT"
done

echo ">>> [container] reports collected:"
ls -1 "$BENCH_REPORT_DIR" | head -40
echo "    (full list: ls $BENCH_REPORT_DIR)"
