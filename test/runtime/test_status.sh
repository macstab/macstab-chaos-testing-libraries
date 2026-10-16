#!/bin/sh
#
# test_status.sh — every library reports a rejected rule file in its status file (Docker).
#
# Builds all libchaos libraries for glibc (gcc:bookworm) and musl (alpine:3.20), then,
# for each library, starts a program under LD_PRELOAD with three rule files in turn:
#
#   - a file whose third line is invalid  -> state=error naming line 3 and its text
#   - a file with one valid rule          -> state=ok, rules=1
#   - no rule file                        -> no status file
#
# The status is written by the library's constructor, so the program needs to call
# nothing. Each report must carry the pid of the program that loaded the rules.
# On glibc, a rule file reloaded after the program switched to de_DE.UTF-8 must
# read the same (locale_probe).
#
# Usage:   test_status.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_STATUS_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_STATUS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "status test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "status test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "status test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "status test skipped: docker daemon not accessible" >&2
    exit 0
fi

# One valid rule per library; "bogus-rule" is invalid for all of them.
CHECK_SCRIPT='
set -eu
failures=0

valid_rule() {
    case "$1" in
        io) echo "/data:write:EIO:1.0" ;;
        net) echo "tcp4://127.0.0.1:9010:connect:ECONNREFUSED:1.0" ;;
        dns) echo "dns://api.example.com:LATENCY:20" ;;
        time) echo "nanosleep:ERRNO:EINTR" ;;
        memory) echo "mprotect:LATENCY:25" ;;
        process) echo "fork:ERRNO:EAGAIN" ;;
    esac
}

# Starts /bin/true with the library preloaded; prints the pid it ran as.
load_rules() {
    sh -c "echo \$\$; exec env LD_PRELOAD=$1 /bin/true"
}

expect_status() {
    lib=$1
    pid=$2
    expected=$3
    actual=$(cat "/tmp/.chaos-$lib.status" 2>/dev/null || echo "<no status file>")

    if [ "$actual" = "$(printf "%s\npid=%s" "$expected" "$pid")" ]; then
        echo "ok   $LIBC $lib: $(echo "$expected" | head -1)"
    else
        echo "FAIL $LIBC $lib: expected" >&2
        printf "%s\npid=%s\n" "$expected" "$pid" >&2
        echo "got" >&2
        echo "$actual" >&2
        failures=$((failures + 1))
    fi
}

for lib in io net dns time memory process; do
    so=/out/libchaos-$lib-$LIBC-'"$ARCH"'.so
    conf=/tmp/.chaos-$lib.conf
    rule=$(valid_rule "$lib")

    printf "# header\n%s\nbogus-rule # typo\n" "$rule" > "$conf"
    pid=$(load_rules "$so")
    expect_status "$lib" "$pid" "$(printf "state=error\nrules=0\nline=3\nreason=invalid rule\ntext=bogus-rule # typo")"

    printf "%s\n" "$rule" > "$conf.new"
    mv -f "$conf.new" "$conf"
    pid=$(load_rules "$so")
    expect_status "$lib" "$pid" "$(printf "state=ok\nrules=1")"

    rm -f "$conf"
    load_rules "$so" >/dev/null
    if [ -e "/tmp/.chaos-$lib.status" ]; then
        echo "FAIL $LIBC $lib: status file left without a rule file" >&2
        failures=$((failures + 1))
    else
        echo "ok   $LIBC $lib: no rule file, no status file"
    fi
done

# A program that switches to a locale with a decimal comma (a JVM does, from LANG)
# must still get "1.0" read as a probability (glibc; musl has no such locales).
if [ "$LIBC" = glibc ]; then
    if apt-get update >/dev/null 2>&1 && apt-get install -y --no-install-recommends locales >/dev/null 2>&1 &&
        localedef -i de_DE -f UTF-8 de_DE.UTF-8 >/dev/null 2>&1; then
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/locale-probe /work/test/runtime/locale_probe.c
        echo "# idle" > /tmp/.chaos-io.conf
        got=$(LD_PRELOAD=/out/libchaos-io-$LIBC-'"$ARCH"'.so /tmp/locale-probe)
        rm -f /tmp/.chaos-io.conf
        if [ "$got" = EIO ]; then
            echo "ok   $LIBC io: a rule read under de_DE.UTF-8 applies"
        else
            echo "FAIL $LIBC io: a rule read under de_DE.UTF-8: $got" >&2
            failures=$((failures + 1))
        fi
    else
        echo "skip $LIBC: the de_DE locale could not be installed"
    fi
fi
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
        -v "$ROOT_DIR/test/runtime:/work/test/runtime:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
