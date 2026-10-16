#!/bin/sh
#
# test_stdio.sh — buffered stdio reads and writes are faulted by the io rules (Docker).
#
# Builds libchaos-io for glibc (gcc:bookworm) and musl (alpine:3.20) and runs
# stdio_probe under each. Both libcs read and write FILE streams with their own
# internal system calls, so fread, fgets, fwrite, fprintf and friends need their own
# wrappers. On glibc the probe is also built with _FORTIFY_SOURCE=2, which turns
# its calls into __fread_chk, __fgets_chk and __fprintf_chk.
#
# Usage:   test_stdio.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_STDIO_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_STDIO_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "stdio test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "stdio test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "stdio test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "stdio test skipped: docker daemon not accessible" >&2
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
            gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/stdio-check /work/test/runtime/stdio_probe.c
            LD_PRELOAD=/out/libchaos-io-$libc-$ARCH.so /tmp/stdio-check
            if [ $libc = glibc ]; then
                gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -D_FORTIFY_SOURCE=2 -o /tmp/stdio-check-fortified /work/test/runtime/stdio_probe.c
                LD_PRELOAD=/out/libchaos-io-$libc-$ARCH.so /tmp/stdio-check-fortified
            fi
        "
done
