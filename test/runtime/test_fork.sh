#!/bin/sh
#
# test_fork.sh: per-process rule state across vfork, fork and posix_spawn, on glibc and musl
# (Docker).
#
# Proves how an `@first=1` budget, the hits files and the PRNG behave in child processes. fork_probe
# opens a faulted file, starts a child that opens it, and opens it again:
#
# - vfork: the child shares the parent's memory and runs no atfork handler, so it must
#   neither take over nor reset the parent's budget, and writes no hits file. Expected:
#   "parent=EIO child=ok parent=ok", 1 hit in 1 hits file.
# - fork: the atfork child handler gives the child its own budget and hits file. Expected:
#   "parent=EIO child=EIO parent=ok", 2 hits in 2 files.
# - posix_spawn: the exec'd child starts with fresh state; the parent is unaffected.
#   Expected as for fork.
# - draws: under a 0.5 probability rule a forked child's 64 outcomes must differ from the
#   parent's, i.e. the child reseeds its PRNG instead of repeating the parent's numbers.
# - faults: with all six libraries preloaded and no rule file, a forked child may take at
#   most 60 minor page faults (10 per library) more than without them. The atfork handlers
#   reset per-process state; a store to a page the child shares copy-on-write costs it a
#   fault, so they store only values that changed. 2.0.0 stored unconditionally and took
#   about 130 extra faults per fork (fork_wait 20-34 % slower than 1.0.1).
#
# Hits are summed from the `# first` rule's lines in /tmp/.chaos-io.hits.*.
#
# Method: for glibc (gcc:bookworm) and then musl (alpine:3.20), docker buildx builds libchaos-io
# (make cross-<libc>-<arch>), and a fresh container of the same image compiles fork_probe.c and runs
# the four checks.
#
# Usage:   test_fork.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_FORK_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when both libcs pass all checks; non-zero when any check fails (all checks of a
#          libc still run and report) or a build fails; 2 on bad usage; CHAOS_SKIP_EXIT when
#          the host or platform is not amd64/arm64, docker is missing or its daemon is
#          unreachable.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_FORK_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "fork test skipped: unsupported host architecture $(uname -m)" >&2
            exit "${CHAOS_SKIP_EXIT:-0}"
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        ARCH=amd64
        ;;
    linux/arm64)
        ARCH=arm64
        ;;
    *)
        echo "fork test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "fork test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "fork test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

CHECK_SCRIPT='
set -eu
failures=0

case "$LIBC" in
    musl) apk add --no-cache build-base >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/fork-probe /work/test/runtime/fork_probe.c
mkdir -p /tmp/fork-data
: > /tmp/fork-data/file
so=/out/libchaos-io-$LIBC-'"$ARCH"'.so

check() {
    mode=$1
    expected=$2
    hits=$3
    files=$4

    rm -f /tmp/.chaos-io.hits.*
    echo "/tmp/fork-data:open:EIO:1.0 @first=1 # first" > /tmp/.chaos-io.conf
    line=$(LD_PRELOAD=$so /tmp/fork-probe "$mode")
    got_files=$(ls /tmp/.chaos-io.hits.* 2>/dev/null | wc -l)
    got_hits=$(cat /tmp/.chaos-io.hits.* 2>/dev/null | awk -F "\t" "\$2 ~ /# first/ { s += \$1 } END { print s + 0 }")
    if [ "$line" = "$expected" ] && [ "$got_hits" -eq "$hits" ] && [ "$got_files" -eq "$files" ]; then
        echo "ok   $LIBC $mode: $line, $hits hits in $files files"
    else
        echo "FAIL $LIBC $mode: got \"$line\", $got_hits hits in $got_files files;" \
            "want \"$expected\", $hits hits in $files files" >&2
        cat /tmp/.chaos-io.hits.* >&2 || true
        failures=$((failures + 1))
    fi
    rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.hits.*
}

check vfork "parent=EIO child=ok parent=ok" 1 1
check fork "parent=EIO child=EIO parent=ok" 2 2
check spawn "parent=EIO child=EIO parent=ok" 2 2

echo "/tmp/fork-data:open:EIO:0.5" > /tmp/.chaos-io.conf
draws=$(LD_PRELOAD=$so /tmp/fork-probe draws)
rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.hits.*
if [ "$draws" = different ]; then
    echo "ok   $LIBC fork: the child draws its own random numbers"
else
    echo "FAIL $LIBC fork: parent and child drew $draws numbers" >&2
    failures=$((failures + 1))
fi

d=/out
six=$d/libchaos-io-$LIBC-'"$ARCH"'.so:$d/libchaos-net-$LIBC-'"$ARCH"'.so:$d/libchaos-dns-$LIBC-'"$ARCH"'.so
six=$six:$d/libchaos-time-$LIBC-'"$ARCH"'.so:$d/libchaos-memory-$LIBC-'"$ARCH"'.so
six=$six:$d/libchaos-process-$LIBC-'"$ARCH"'.so
rm -f /tmp/.chaos-*.conf
bare=$(/tmp/fork-probe faults)
loaded=$(LD_PRELOAD=$six /tmp/fork-probe faults)
if [ $((loaded - bare)) -le 60 ]; then
    echo "ok   $LIBC fork: a child takes $loaded page faults with all six libraries, $bare without"
else
    echo "FAIL $LIBC fork: a child takes $loaded page faults with all six libraries, $bare" \
        "without; at most 60 more allowed" >&2
    failures=$((failures + 1))
fi
[ "$failures" -eq 0 ]
'

for libc in glibc musl; do
    if [ "$libc" = glibc ]; then
        base=gcc:bookworm
    else
        base=alpine:3.20
    fi
    docker buildx build \
        --platform "$DOCKER_PLATFORM" \
        --build-arg BASE_IMAGE="$base" \
        --build-arg MAKE_TARGET="cross-$libc-$ARCH" \
        --output "type=local,dest=$TMP_DIR/$libc" \
        -f "$ROOT_DIR/docker/Dockerfile.build" \
        "$ROOT_DIR" >/dev/null

    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -e LIBC="$libc" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
