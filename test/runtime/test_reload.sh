#!/bin/sh
#
# test_reload.sh — @first holds while the rule file is reloaded under load (Docker).
#
# Builds libchaos-io for glibc (gcc:bookworm) and musl (alpine:3.20) and runs
# reload_probe in a container limited to two CPUs, where threads are preempted
# between taking a rule copy and firing it: six threads fire an @first=1 rule while
# the main thread reloads the rule file twice per round. No round may fail more
# than one open; a reload must neither lose a firing nor give the rule a fresh budget.
#
# Usage:   test_reload.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_RELOAD_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_RELOAD_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "reload test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "reload test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "reload test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "reload test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

CHECK_SCRIPT='
set -eu
case "$LIBC" in
    musl) apk add --no-cache build-base >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -pthread -o /tmp/reload-probe /work/test/runtime/reload_probe.c
so=/out/libchaos-io-$LIBC-'"$ARCH"'.so
failures=0
for pause in 0 200; do
    if LD_PRELOAD=$so /tmp/reload-probe 1000 $pause; then
        echo "ok   $LIBC io: @first=1 held over 1000 rounds of reloads (pause $pause us)"
    else
        echo "FAIL $LIBC io: @first=1 broke under reloads (pause $pause us)" >&2
        failures=$((failures + 1))
    fi
done
rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.status /tmp/.chaos-io.hits.*
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
        --cpus=2 \
        -e LIBC="$libc" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
