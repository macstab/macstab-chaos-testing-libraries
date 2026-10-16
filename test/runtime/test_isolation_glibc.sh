#!/bin/sh
#
# test_isolation_glibc.sh — no library's rules change another library's effects (Docker).
#
# Builds all libchaos libraries for the target platform using Docker buildx with
# a glibc (debian:bookworm) base, then runs isolation_probe for io, net, dns,
# memory and process, each preloaded together with libchaos-time in both orders.
# libchaos-time fails every usleep and nanosleep; the library's own LATENCY
# delay must still last its full duration.
# Then net, dns, memory and process run with libchaos-io failing every file
# access under /tmp: they must still read their rule files (/tmp/.chaos-*).
#
# Usage:   test_isolation_glibc.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_ISOLATION_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-isolation-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_ISOLATION_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "isolation glibc test skipped: unsupported host architecture $(uname -m)" >&2
            exit 0
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
        echo "isolation glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "isolation glibc test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "isolation glibc test skipped: docker daemon not accessible" >&2
    exit 0
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=gcc:bookworm \
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
    gcc:bookworm \
    sh -eu -c "
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/isolation-probe /work/test/runtime/isolation_probe.c
        time_lib=/out/libchaos-time-glibc-$ARCH.so
        for lib in io net dns memory process; do
            so=/out/libchaos-\$lib-glibc-$ARCH.so
            LD_PRELOAD=\$so:\$time_lib /tmp/isolation-probe \$lib
            LD_PRELOAD=\$time_lib:\$so /tmp/isolation-probe \$lib
        done
        io_lib=/out/libchaos-io-glibc-$ARCH.so
        for lib in net dns memory process; do
            so=/out/libchaos-\$lib-glibc-$ARCH.so
            LD_PRELOAD=\$io_lib:\$so /tmp/isolation-probe control:\$lib
            LD_PRELOAD=\$so:\$io_lib /tmp/isolation-probe control:\$lib
        done
    "
