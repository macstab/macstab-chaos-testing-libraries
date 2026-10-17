#!/bin/sh
#
# test_stdio.sh: libchaos-io read/write rules fault buffered stdio (fread, fgets, fgetc, getline,
# fwrite, fputs, fprintf, fflush) on glibc and musl (Docker).
#
# Proves that FILE-stream I/O, which both libcs perform with internal system calls instead of the
# exported read()/write(), is faulted like a real I/O error and that fclose drops the fd cache entry
# (stdio_probe.c lists every check). On glibc the probe is also built with _FORTIFY_SOURCE=2, which
# routes its calls to __fread_chk, __fgets_chk and __fprintf_chk, so the fortified wrappers are
# proven too.
#
# Method: for glibc (gcc:bookworm) and then musl (alpine:3.20), docker buildx builds libchaos-io
# (make cross-<libc>-<arch>), and a fresh container of the same image compiles stdio_probe.c and
# runs it with LD_PRELOAD of that build.
#
# Usage:   test_stdio.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_STDIO_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when every build passes; the probe's 1 or 2 for the first failing run; non-zero
#          when a build fails or yields no library; 2 on bad usage; CHAOS_SKIP_EXIT when the
#          host or platform is not amd64/arm64, docker is missing or its daemon is
#          unreachable.

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
