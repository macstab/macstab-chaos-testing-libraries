#!/bin/sh
#
# test_hits.sh — every library counts how often each rule fired (Docker).
#
# Builds all libchaos libraries for glibc (gcc:bookworm) and musl (alpine:3.20). For
# each library a rule file holds one rule that fires and one that never matches;
# hits_probe calls the faulted operation twice, and runs twice. The hits files of the
# two processes must add up to 4 for the firing rule and 0 for the other. Then a rule
# with @first=1 must fire once per process, and one whose @until passed never.
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

    # @first=1 fires once per process; a window that ended long ago never fires.
    { echo "$fired @first=1 # first"; echo "$fired @until=1 # expired"; } > /tmp/.chaos-$lib.conf
    LD_PRELOAD=$so /tmp/hits-probe "$lib"
    LD_PRELOAD=$so /tmp/hits-probe "$lib"
    first=$(cat /tmp/.chaos-$lib.hits.* 2>/dev/null | awk -F "\t" -v r="$fired @first=1 # first" "\$2 == r { s += \$1 } END { print s + 0 }")
    expired=$(cat /tmp/.chaos-$lib.hits.* 2>/dev/null | awk -F "\t" -v r="$fired @until=1 # expired" "\$2 == r { s += \$1 } END { print s + 0 }")
    if [ "$first" -eq 2 ] && [ "$expired" -eq 0 ]; then
        echo "ok   $LIBC $lib: @first=1 fired once per process, expired window never"
    else
        echo "FAIL $LIBC $lib: @first=1 total=$first, expired=$expired" >&2
        cat /tmp/.chaos-$lib.hits.* >&2 || true
        failures=$((failures + 1))
    fi
    rm -f /tmp/.chaos-$lib.conf /tmp/.chaos-$lib.hits.*
done

# Hits of the last interval reach the file while the process still runs: 100
# hits, past the 64 written at once, then the interval passes and one more call.
so=/out/libchaos-io-$LIBC-'"$ARCH"'.so
echo "/tmp/hits-data:open:EIO:1.0 # burst" > /tmp/.chaos-io.conf
burst=$(LD_PRELOAD=$so /tmp/hits-probe burst)
if [ "$burst" -eq 100 ]; then
    echo "ok   $LIBC io: 100 hits on file while the process runs"
else
    echo "FAIL $LIBC io: $burst hits on file while the process runs, want 100" >&2
    failures=$((failures + 1))
fi
rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.hits.*

# A delay is a hit like any other effect and honours @first: hits_probe calls the
# operation twice, so @first=1 delays once per process.
for lib in io net; do
    so=/out/libchaos-$lib-$LIBC-'"$ARCH"'.so
    case "$lib" in
        io) rule="/tmp/hits-data:open:LATENCY:1" ;;
        net) rule="tcp4://127.0.0.1:9:connect:LATENCY:1" ;;
    esac
    echo "$rule @first=1 # delay" > /tmp/.chaos-$lib.conf
    LD_PRELOAD=$so /tmp/hits-probe "$lib"
    LD_PRELOAD=$so /tmp/hits-probe "$lib"
    delays=$(cat /tmp/.chaos-$lib.hits.* 2>/dev/null | awk -F "\t" "\$2 ~ /# delay/ { s += \$1 } END { print s + 0 }")
    if [ "$delays" -eq 2 ]; then
        echo "ok   $LIBC $lib: LATENCY @first=1 delayed once per process"
    else
        echo "FAIL $LIBC $lib: LATENCY @first=1 hits=$delays" >&2
        failures=$((failures + 1))
    fi
    rm -f /tmp/.chaos-$lib.conf /tmp/.chaos-$lib.hits.*
done

# @size: hits_probe maps 4096 bytes, so only the gate below that size fires.
so=/out/libchaos-memory-$LIBC-'"$ARCH"'.so
{ echo "mmap/anon:ERRNO:ENOMEM @size>4095 # small"; echo "mmap/anon:LATENCY:1 @size>4096 # large"; } > /tmp/.chaos-memory.conf
LD_PRELOAD=$so /tmp/hits-probe memory
small=$(cat /tmp/.chaos-memory.hits.* 2>/dev/null | awk -F "\t" "\$2 ~ /# small/ { s += \$1 } END { print s + 0 }")
large=$(cat /tmp/.chaos-memory.hits.* 2>/dev/null | awk -F "\t" "\$2 ~ /# large/ { s += \$1 } END { print s + 0 }")
if [ "$small" -eq 2 ] && [ "$large" -eq 0 ]; then
    echo "ok   $LIBC memory: @size>4095 fired on 4096-byte maps, @size>4096 did not"
else
    echo "FAIL $LIBC memory: @size small=$small large=$large" >&2
    failures=$((failures + 1))
fi
rm -f /tmp/.chaos-memory.conf /tmp/.chaos-memory.hits.*
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
