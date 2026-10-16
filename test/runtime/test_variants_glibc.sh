#!/bin/sh
#
# test_variants_glibc.sh — glibc's alternate entry points are faulted like the base calls (Docker).
#
# Builds the libchaos libraries for the target platform using Docker buildx with a
# glibc (debian:bookworm) base, then runs variants_probe under LD_PRELOAD of io,
# memory and net. Every large-file name (open64, pread64, mmap64, ...) and every
# fortified variant (__read_chk, __open_2, __recv_chk, ...) must report the errno
# its rule injects, exactly as the base function does.
#
# Usage:   test_variants_glibc.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_VARIANTS_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-variants-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_VARIANTS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "variants glibc test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "variants glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "variants glibc test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "variants glibc test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=gcc:bookworm \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

for lib in io net memory; do
    [ -f "$TMP_DIR/out/libchaos-$lib-glibc-$ARCH.so" ]
done

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    gcc:bookworm \
    sh -eu -c "
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -O2 -o /tmp/variants-probe /work/test/runtime/variants_probe.c
        for lib in io memory net; do
            echo \"libchaos-\$lib:\"
            LD_PRELOAD=/out/libchaos-\$lib-glibc-$ARCH.so /tmp/variants-probe \$lib
        done
    "
