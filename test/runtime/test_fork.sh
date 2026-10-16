#!/bin/sh
#
# test_fork.sh — per-process state across vfork, fork and posix_spawn (Docker).
#
# Builds libchaos-io for glibc (gcc:bookworm) and musl (alpine:3.20). An open rule
# with @first=1 faults the first open of each process. fork_probe opens the file,
# starts a child that opens it, and opens it again:
#
# - vfork: the child shares the parent's memory and runs no atfork handler, so it
#   must neither take over nor reset the parent's budget, and writes no hits file;
# - fork: the atfork handler gives the child its own budget and hits file;
# - posix_spawn: the exec'd child starts fresh; the parent is unaffected.
#
# Usage:   test_fork.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_FORK_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

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
