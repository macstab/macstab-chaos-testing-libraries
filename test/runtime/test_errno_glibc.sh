#!/bin/sh
#
# test_errno_glibc.sh — every libchaos library leaves errno alone when idle (Docker).
#
# Builds all libchaos libraries for the target platform using Docker buildx with
# a glibc (debian:bookworm) base, then runs errno_probe under LD_PRELOAD of each
# library in turn: once without a config file and once with a config file that
# holds no rules. Every successful call must leave errno exactly as it was; the
# library's own stat/open/read and socket lookups must not leak into it.
#
# Usage:   test_errno_glibc.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_ERRNO_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-errno-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_ERRNO_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "errno glibc test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "errno glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "errno glibc test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "errno glibc test skipped: docker daemon not accessible" >&2
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
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/errno-probe /work/test/runtime/errno_probe.c
        for lib in io net memory time process dns; do
            rm -f /tmp/.chaos-\$lib.conf
            echo \"libchaos-\$lib, no config file:\"
            LD_PRELOAD=/out/libchaos-\$lib-glibc-$ARCH.so /tmp/errno-probe
            printf '# errno probe: no rules\\n' > /tmp/.chaos-\$lib.conf
            echo \"libchaos-\$lib, config file without rules:\"
            LD_PRELOAD=/out/libchaos-\$lib-glibc-$ARCH.so /tmp/errno-probe
            rm -f /tmp/.chaos-\$lib.conf
        done
    "
