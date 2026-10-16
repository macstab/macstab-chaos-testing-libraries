#!/bin/sh
#
# test_path_forms.sh — unlink, rmdir, rename, truncate and creat are faulted (Docker).
#
# Builds libchaos-io for glibc (debian:bookworm) and musl (alpine:3.20) and runs
# path_forms_probe under each. Both libcs implement these path forms with their own
# system calls rather than through the *at or descriptor forms, so each needs its
# own wrapper to reach the unlink, rename_to, truncate and open rules.
#
# Usage:   test_path_forms.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_PATH_FORMS_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_PATH_FORMS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "path forms test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "path forms test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "path forms test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "path forms test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

for libc in glibc musl; do
    if [ "$libc" = glibc ]; then
        base=gcc:bookworm
        run_image=gcc:bookworm
        setup=true
    else
        base=alpine:3.20
        run_image=alpine:3.20
        setup="apk add --no-cache build-base >/dev/null"
    fi
    docker buildx build \
        --platform "$DOCKER_PLATFORM" \
        --build-arg BASE_IMAGE="$base" \
        --build-arg MAKE_TARGET="cross-$libc-$ARCH" \
        --output "type=local,dest=$TMP_DIR/$libc" \
        -f "$ROOT_DIR/docker/Dockerfile.build" \
        "$ROOT_DIR" >/dev/null
    [ -f "$TMP_DIR/$libc/libchaos-io-$libc-$ARCH.so" ]

    echo "libchaos-io ($libc):"
    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$run_image" \
        sh -eu -c "
            $setup
            gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/path-forms-check /work/test/runtime/path_forms_probe.c
            LD_PRELOAD=/out/libchaos-io-$libc-$ARCH.so /tmp/path-forms-check
        "
done
