#!/bin/sh
#
# test_memory_glibc.sh: libchaos-memory end-to-end in LD_PRELOAD mode on glibc (Debian bookworm,
# glibc 2.36).
#
# Proves, for one architecture per run, that mmap (anon and file targets), mprotect, madvise,
# posix_madvise and munmap honour ERRNO and LATENCY rules, each with its own error contract;
# memory_probe.c lists every check.
#
# Method: docker buildx builds libchaos-memory-glibc-<arch>.so (make cross-glibc-<arch>) from
# docker/Dockerfile.build on gcc:bookworm. Then a fresh gcc:bookworm container compiles
# test/runtime/memory_probe.c from the read-only repository mount and runs it with
# LD_PRELOAD=/tmp/libchaos-memory.so. The probe is compiled in the target image so it uses the same
# libc the library was built against.
#
# Usage:   test_memory_glibc.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_MEMORY_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test` and,
#          once per platform, by `make test-matrix`.
# Exit:    the probe's exit code (0 = every check passed; memory_probe.c lists the others);
#          non-zero when the build fails or yields no library; 2 on bad usage;
#          CHAOS_SKIP_EXIT when the host or platform is not amd64/arm64, docker is missing
#          or its daemon is unreachable.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-memory-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_MEMORY_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "memory glibc test skipped: unsupported host architecture $(uname -m)" >&2
            exit "${CHAOS_SKIP_EXIT:-0}"
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        MAKE_TARGET=cross-glibc-amd64
        OUTPUT_LIB=libchaos-memory-glibc-amd64.so
        ;;
    linux/arm64)
        MAKE_TARGET=cross-glibc-arm64
        OUTPUT_LIB=libchaos-memory-glibc-arm64.so
        ;;
    *)
        echo "memory glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "memory glibc test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "memory glibc test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=gcc:bookworm \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

[ -f "$TMP_DIR/out/$OUTPUT_LIB" ]

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    gcc:bookworm \
    sh -eu -c "
        cp /out/$OUTPUT_LIB /tmp/libchaos-memory.so
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/memory-probe /work/test/runtime/memory_probe.c
        LD_PRELOAD=/tmp/libchaos-memory.so /tmp/memory-probe
    "
