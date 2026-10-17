#!/bin/sh
#
# test_reload.sh: an @first budget holds while the rule file is reloaded under concurrent firing, on
# glibc and musl (Docker).
#
# Proves that reloading a rule file that keeps an `@first=1` rule neither resets nor duplicates its
# budget while threads are firing it: in 1000 rounds, six threads hammer open() while the main
# thread reloads twice per round, and no round may fail more than one open (reload_probe.c). The
# container is limited to two CPUs so threads are preempted between copying a rule and firing it,
# which is where a budget race would show.
#
# Method: for glibc (gcc:bookworm) and then musl (alpine:3.20), docker buildx builds libchaos-io
# (make cross-<libc>-<arch>), and a fresh container of the same image (--cpus=2) compiles
# reload_probe.c and runs it with pauses of 0 and 200 us between reloads.
#
# Usage:   test_reload.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_RELOAD_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when both libcs pass both pauses; non-zero when any run broke @first (both pauses
#          still run and report) or a build fails; 2 on bad usage; CHAOS_SKIP_EXIT when the
#          host or platform is not amd64/arm64, docker is missing or its daemon is
#          unreachable.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_RELOAD_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "reload test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "reload test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "reload test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "reload test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

CHECK_SCRIPT='
set -eu
case "$LIBC" in
    musl) apk add --no-cache build-base >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -pthread -o /tmp/reload-probe /work/test/runtime/reload_probe.c
so=/out/libchaos-io-$LIBC-'"$ARCH"'.so
failures=0
for pause in 0 200; do
    if LD_PRELOAD=$so /tmp/reload-probe 1000 $pause; then
        echo "ok   $LIBC io: @first=1 held over 1000 rounds of reloads (pause $pause us)"
    else
        echo "FAIL $LIBC io: @first=1 broke under reloads (pause $pause us)" >&2
        failures=$((failures + 1))
    fi
done
rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.status /tmp/.chaos-io.hits.*
[ "$failures" -eq 0 ]
'

for libc in glibc musl; do
    if [ "$libc" = glibc ]; then
        base=gcc:bookworm
    else
        base=alpine:3.20
    fi
    docker buildx build \
        --platform "$DOCKER_PLATFORM" \
        --build-arg BASE_IMAGE="$base" \
        --build-arg MAKE_TARGET="cross-$libc-$ARCH" \
        --output "type=local,dest=$TMP_DIR/$libc" \
        -f "$ROOT_DIR/docker/Dockerfile.build" \
        "$ROOT_DIR" >/dev/null

    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        --cpus=2 \
        -e LIBC="$libc" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
