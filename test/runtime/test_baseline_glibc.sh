#!/bin/sh
#
# test_baseline_glibc.sh — the release build loads into ordinary programs on glibc 2.31 (Docker).
#
# Builds every libchaos library exactly as `make docker-build-all` does for a release
# (gcc:10, glibc 2.31, the oldest glibc the libraries support) and preloads them into
# programs that never link libpthread: cat and sh. On glibc before 2.34 pthread_once
# and pthread_create live in libpthread, so a library that needs either at load time
# fails with "undefined symbol" or aborts before main() for every such program.
# Each library runs alone and all six together, and libchaos-process must still
# start and fault threads in a program that does link libpthread.
#
# Usage:   test_baseline_glibc.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_BASELINE_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
BASE_IMAGE=gcc:10

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_BASELINE_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "baseline glibc test skipped: unsupported host architecture $(uname -m)" >&2
            exit "${CHAOS_SKIP_EXIT:-0}"
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        MAKE_TARGET=cross-glibc-amd64
        ARCH=amd64
        ;;
    linux/arm64)
        MAKE_TARGET=cross-glibc-arm64
        ARCH=arm64
        ;;
    *)
        echo "baseline glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "baseline glibc test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "baseline glibc test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE="$BASE_IMAGE" \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

for lib in io net memory time process dns; do
    [ -f "$TMP_DIR/out/libchaos-$lib-glibc-$ARCH.so" ]
done

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    "$BASE_IMAGE" \
    sh -eu -c "
        echo \"glibc \$(getconf GNU_LIBC_VERSION)\"
        gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -pthread -o /tmp/thread-probe /work/test/runtime/thread_probe.c
        all=''
        for lib in io net memory time process dns; do
            so=/out/libchaos-\$lib-glibc-$ARCH.so
            all=\"\$all\${all:+:}\$so\"
            out=\$(LD_PRELOAD=\$so cat /etc/hostname)
            [ -n \"\$out\" ]
            LD_PRELOAD=\$so sh -c 'echo child > /dev/null'
            LD_PRELOAD=\$so /tmp/thread-probe
            echo \"ok   libchaos-\$lib loads into cat, sh and a threaded program\"
        done
        LD_PRELOAD=\$all cat /etc/hostname > /dev/null
        LD_PRELOAD=\$all sh -c 'cat /etc/hostname > /dev/null'
        LD_PRELOAD=\$all /tmp/thread-probe
        echo 'ok   all six libraries load together'
        printf 'pthread_create:ERRNO:EAGAIN\\n' > /tmp/.chaos-process.conf
        LD_PRELOAD=/out/libchaos-process-glibc-$ARCH.so /tmp/thread-probe 11
        LD_PRELOAD=\$all /tmp/thread-probe 11
        rm -f /tmp/.chaos-process.conf
        echo 'ok   libchaos-process faults pthread_create resolved after load'
    "
