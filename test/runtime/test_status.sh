#!/bin/sh
#
# test_status.sh: every library reports the outcome of loading its rule file in its status file, on
# glibc and musl (Docker).
#
# Proves, for each of the six libraries, that the constructor alone (the program, /bin/true, calls
# nothing) writes /tmp/.chaos-<lib>.status, and that each report carries the pid of the process that
# loaded the rules:
#
#   - third line invalid   -> state=error, rules=0, line=3, reason=invalid rule, text=<line>
#   - one valid rule       -> state=ok, rules=1
#   - no rule file         -> no status file (a stale one is removed)
#
# On glibc it further proves that a non-root user (setpriv uid 1000) can update a status file root
# created in sticky /tmp, by rewriting it in place since it cannot rename over it, and that a rule
# file read after the program switched to de_DE.UTF-8 still parses "1.0" as a probability
# (locale_probe.c). The locale check prints "skip" and passes when the locale cannot be installed
# (it needs apt network access).
#
# Method: for glibc (gcc:bookworm) and then musl (alpine:3.20), docker buildx builds all libraries
# (make cross-<libc>-<arch>), and a fresh container of the same image runs the checks with
# test/runtime mounted read-only.
#
# Usage:   test_status.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_STATUS_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; QEMU binfmt for a foreign platform. Run by `make test`.
# Exit:    0 when every check passes; non-zero when any check fails (all checks of a libc
#          still run and report) or a build fails; 2 on bad usage; CHAOS_SKIP_EXIT when the
#          host or platform is not amd64/arm64, docker is missing or its daemon is
#          unreachable.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
# The build output is mounted into the containers, where uid 1000 (setpriv) must load the
# libraries: mktemp creates the directory 0700, so open it up (the builds get chmod a+rX
# below).
chmod 755 "$TMP_DIR"

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
        echo "status test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "status test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "status test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

# Runs inside each container. valid_rule gives one rule every library accepts in its own
# grammar; "bogus-rule" is invalid for all six.
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

# Images often start as root and run the application as another user. In sticky /tmp that
# user cannot rename over the status file root created, so the library must rewrite it in
# place; the file stays owned by root. glibc image only: it ships setpriv.
if [ "$LIBC" = glibc ] && command -v setpriv >/dev/null 2>&1; then
    so=/out/libchaos-io-$LIBC-'"$ARCH"'.so
    echo "/data:write:EIO:1.0" > /tmp/.chaos-io.conf
    load_rules "$so" >/dev/null
    printf "bogus-rule\n" > /tmp/.chaos-io.conf.new
    mv -f /tmp/.chaos-io.conf.new /tmp/.chaos-io.conf
    setpriv --reuid=1000 --regid=1000 --clear-groups env LD_PRELOAD="$so" /bin/true
    state=$(head -1 /tmp/.chaos-io.status)
    owner=$(stat -c %u /tmp/.chaos-io.status)
    if [ "$state" = state=error ] && [ "$owner" = 0 ]; then
        echo "ok   $LIBC io: another user updates the status file root wrote"
    else
        echo "FAIL $LIBC io: a load by another user left $state (owner $owner)" >&2
        failures=$((failures + 1))
    fi
    rm -f /tmp/.chaos-io.conf /tmp/.chaos-io.status /tmp/.chaos-staging-*
fi

# A program that switches to a locale with a decimal comma (a JVM does, from LANG) must
# still get "1.0" read as a probability. glibc only: musl locales do not change the decimal
# point.
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
    chmod -R a+rX "$TMP_DIR/$libc"

    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -e LIBC="$libc" \
        -v "$TMP_DIR/$libc:/out:ro" \
        -v "$ROOT_DIR/test/runtime:/work/test/runtime:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
