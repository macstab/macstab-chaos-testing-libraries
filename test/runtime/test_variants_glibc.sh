#!/bin/sh
#
# test_variants_glibc.sh: glibc's large-file (open64, pread64, mmap64, ...) and fortified
# (__read_chk, __open_2, __recv_chk, __poll_chk, ...) entry points are faulted exactly like the base
# calls (Docker).
#
# Proves that a program compiled with _FILE_OFFSET_BITS=64 or _FORTIFY_SOURCE, which binds to those
# names instead of the base ones, is still subject to every rule; variants_probe.c lists each
# symbol.
#
# Method: docker buildx builds the glibc libraries (make cross-glibc-<arch>) on gcc:bookworm; a
# fresh gcc:bookworm container compiles variants_probe.c and runs it once per library (io, memory,
# net) under LD_PRELOAD of that library.
#
# Usage:   test_variants_glibc.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_VARIANTS_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when every variant was faulted; the probe's 1 or 2 for the first failing library;
#          non-zero when the build fails or a library is missing; 2 on bad usage;
#          CHAOS_SKIP_EXIT when the host or platform is not amd64/arm64, docker is missing
#          or its daemon is unreachable.

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
