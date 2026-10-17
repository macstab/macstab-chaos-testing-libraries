#!/bin/sh
#
# test_process_alpine.sh: libchaos-process end-to-end in LD_PRELOAD mode on musl (Alpine 3.20).
#
# Proves, for one architecture per run, that pthread_create, fork, posix_spawn/posix_spawnp, the
# exec family, system, popen and the wait family honour ERRNO, LATENCY and FAIL_AFTER rules with
# each function's own error contract; process_probe.c lists every check.
#
# Method: docker buildx builds libchaos-process-musl-<arch>.so (make cross-musl-<arch>) from
# docker/Dockerfile.build on alpine:3.20. Then a fresh alpine:3.20 container (build-base installed
# at run time) compiles test/runtime/process_probe.c from the read-only repository mount and runs it
# with LD_PRELOAD=/tmp/libchaos-process.so. The probe is compiled in the target image so it uses the
# same libc the library was built against.
#
# posix_spawn is faulted through its own selector: neither glibc's nor musl's posix_spawn calls the
# public fork() (both clone with CLONE_VM|CLONE_VFORK), so fork rules do not reach it.
#
# Usage:   test_process_alpine.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_PROCESS_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test` and,
#          once per platform, by `make test-matrix`.
# Exit:    the probe's exit code (0 = every check passed; process_probe.c lists the others);
#          non-zero when the build fails or yields no library; 2 on bad usage;
#          CHAOS_SKIP_EXIT when the host or platform is not amd64/arm64, docker is missing
#          or its daemon is unreachable.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_PROCESS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "process alpine test skipped: unsupported host architecture $(uname -m)" >&2
            exit "${CHAOS_SKIP_EXIT:-0}"
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        MAKE_TARGET=cross-musl-amd64
        OUTPUT_LIB=libchaos-process-musl-amd64.so
        ;;
    linux/arm64)
        MAKE_TARGET=cross-musl-arm64
        OUTPUT_LIB=libchaos-process-musl-arm64.so
        ;;
    *)
        echo "process alpine test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "process alpine test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "process alpine test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=alpine:3.20 \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

[ -f "$TMP_DIR/out/$OUTPUT_LIB" ]

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    alpine:3.20 \
    sh -eu -c "
        apk add --no-cache build-base >/dev/null
        cp /out/$OUTPUT_LIB /tmp/libchaos-process.so
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -pthread -o /tmp/process-probe /work/test/runtime/process_probe.c
        LD_PRELOAD=/tmp/libchaos-process.so /tmp/process-probe
    "
