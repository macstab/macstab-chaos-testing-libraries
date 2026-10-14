#!/bin/sh
#
# test_sharing_glibc.sh — libchaos-io and libchaos-net share read/write/close safely (Docker).
#
# Builds the libraries for the target platform using Docker buildx with a glibc
# (debian:bookworm) base, then runs every sharing_probe scenario under io alone,
# net alone, io then net, and net then io. Files must only ever see io's rules and
# sockets only net's, whatever the preload order; close keeps Linux semantics; the
# fd cache follows close, dup2 and other threads. Finally a program whose library
# constructors do file I/O must start under the preload (the lazy symbol table).
#
# Usage:   test_sharing_glibc.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_SHARING_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-sharing-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_SHARING_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "sharing glibc test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "sharing glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "sharing glibc test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "sharing glibc test skipped: docker daemon not accessible" >&2
    exit 0
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=gcc:bookworm \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

for lib in io net; do
    [ -f "$TMP_DIR/out/libchaos-$lib-glibc-$ARCH.so" ]
done

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    gcc:bookworm \
    sh -eu -c "
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -O2 -pthread -o /tmp/sharing-probe /work/test/runtime/sharing_probe.c
        IO=/out/libchaos-io-glibc-$ARCH.so
        NET=/out/libchaos-net-glibc-$ARCH.so
        for preload in \"\$IO\" \"\$NET\" \"\$IO \$NET\" \"\$NET \$IO\"; do
            echo \"== LD_PRELOAD=\$preload\"
            for scenario in socket-rules file-rules close-reset close-errno cache-threads cache-dup2 no-rules; do
                LD_PRELOAD=\"\$preload\" /tmp/sharing-probe \$scenario
            done
        done
        echo '== constructors doing file I/O start under the preload'
        LD_PRELOAD=\"\$NET \$IO\" setpriv --dump >/dev/null
        LD_PRELOAD=\"\$IO \$NET\" setpriv --dump >/dev/null
        echo 'ok   setpriv starts'
    "
