#!/bin/sh
#
# test_sharing_glibc.sh: libchaos-io and libchaos-net share read/write/readv/writev/close safely in
# every preload order (glibc, Docker).
#
# Proves that files only ever see libchaos-io's rules and sockets only libchaos-net's, whatever the
# order in LD_PRELOAD; that close keeps Linux semantics (the fd is closed even when an error is
# injected); and that libchaos-io's fd cache follows close, dup2 and other threads. Finally proves
# the lazy symbol table: setpriv's linked libraries do file I/O in their constructors, which can
# reach a wrapper before that library's own constructor has resolved its real functions; setpriv
# must still start under both orders.
#
# Method: docker buildx builds the glibc libraries (make cross-glibc-<arch>) on gcc:bookworm; a
# fresh gcc:bookworm container compiles sharing_probe.c and runs all seven scenarios under
# LD_PRELOAD of io, net, "io net" and "net io", then runs `setpriv --dump` under both combined
# orders.
#
# Usage:   test_sharing_glibc.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_SHARING_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when every scenario passes and setpriv starts; the first failing command's status
#          otherwise; non-zero when the build fails or a library is missing; 2 on bad usage;
#          CHAOS_SKIP_EXIT when the host or platform is not amd64/arm64, docker is missing
#          or its daemon is unreachable.

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
        echo "sharing glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "sharing glibc test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "sharing glibc test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
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
