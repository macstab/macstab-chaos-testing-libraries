#!/bin/sh
#
# test_hits.sh — every library counts how often each rule fired (Docker).
#
# Builds all libchaos libraries for glibc (gcc:bookworm) and musl (alpine:3.20). For
# each library a rule file holds one rule that fires and one that never matches;
# hits_probe calls the faulted operation twice, and runs twice. The hits files of the
# two processes must add up to 4 for the firing rule and 0 for the other.
#
# Usage:   test_hits.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_HITS_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_HITS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "hits test skipped: unsupported host architecture $(uname -m)" >&2
            exit 0
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
        echo "hits test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "hits test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "hits test skipped: docker daemon not accessible" >&2
    exit 0
fi

CHECK_SCRIPT='
set -eu
failures=0

case "$LIBC" in
    musl) apk add --no-cache build-base >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/hits-probe /work/test/runtime/hits_probe.c
mkdir -p /tmp/hits-data

rules() {
    case "$1" in
        io) echo "/tmp/hits-data:open:EIO:1.0"; echo "/tmp/elsewhere:open:EIO:1.0" ;;
        net) echo "tcp4://127.0.0.1:9:connect:ECONNREFUSED:1.0"; echo "tcp4://127.0.0.1:10:connect:ECONNREFUSED:1.0" ;;
        dns) echo "dns://api.example.com:LATENCY:1"; echo "dns://other.example.com:LATENCY:1" ;;
        time) echo "nanosleep:ERRNO:EINTR"; echo "usleep:ERRNO:EINTR" ;;
        memory) echo "mmap/anon:ERRNO:ENOMEM"; echo "mprotect:ERRNO:ENOMEM" ;;
        process) echo "fork:ERRNO:EAGAIN"; echo "waitpid:ERRNO:EINTR" ;;
    esac
}

for lib in io net dns time memory process; do
    so=/out/libchaos-$lib-$LIBC-'"$ARCH"'.so
    rm -f /tmp/.chaos-$lib.hits.*
    rules "$lib" | sed "s/\$/ # hits/" > /tmp/.chaos-$lib.conf
    fired=$(rules "$lib" | head -1)
    idle=$(rules "$lib" | tail -1)

    LD_PRELOAD=$so /tmp/hits-probe "$lib"
    LD_PRELOAD=$so /tmp/hits-probe "$lib"

    files=$(ls /tmp/.chaos-$lib.hits.* 2>/dev/null | wc -l)
    total=$(cat /tmp/.chaos-$lib.hits.* 2>/dev/null | awk -F "\t" -v r="$fired # hits" "\$2 == r { s += \$1 } END { print s + 0 }")
    other=$(cat /tmp/.chaos-$lib.hits.* 2>/dev/null | awk -F "\t" -v r="$idle # hits" "\$2 == r { s += \$1 } END { print s + 0 }")
    if [ "$files" -eq 2 ] && [ "$total" -eq 4 ] && [ "$other" -eq 0 ]; then
        echo "ok   $LIBC $lib: 4 hits from 2 processes, idle rule 0"
    else
        echo "FAIL $LIBC $lib: files=$files fired=$total idle=$other" >&2
        cat /tmp/.chaos-$lib.hits.* >&2 || true
        failures=$((failures + 1))
    fi
    rm -f /tmp/.chaos-$lib.conf /tmp/.chaos-$lib.hits.*
done
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
        -e LIBC="$libc" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
