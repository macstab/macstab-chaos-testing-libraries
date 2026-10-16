#!/bin/sh
#
# test_seccomp.sh — io, net, memory and process rules in SECCOMP mode (Docker).
#
# Builds chaos-init (docker/Dockerfile.build) and a statically linked Go program
# (CGO_ENABLED=0, the kind LD_PRELOAD cannot reach), then runs them and a static
# C probe under chaos-init in glibc and musl containers, with Docker's default
# security profile:
#
# - an open rule fails the open with its errno (C and Go), unmatched paths open;
# - a LATENCY rule delays the open (C and Go);
# - @first=1 fires once per process, a forked child included, and each process
#   writes its own hits file;
# - the io status file reports the loaded rules;
# - a connect rule refuses the connection (C and Go), a recv LATENCY rule delays
#   the server side's read (Go), and the net status file reports the rules;
# - an mmap rule fails a mapping of its size (C and Go), a fork rule fails fork
#   (C), a posix_spawn rule fails Go's os/exec, an execve rule fails a later
#   exec but never the start of the application itself.
#
# Without chaos-init the same opens succeed. Under emulation (amd64 on an arm64
# host) seccomp is unavailable and the test is skipped.
#
# Usage:   test_seccomp.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_SECCOMP_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_SECCOMP_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "seccomp test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "seccomp test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "seccomp test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "seccomp test skipped: docker daemon not accessible" >&2
    exit 0
fi

CHECK_SCRIPT='
set -eu
failures=0
expect() {
    if [ "$2" = "$3" ]; then
        echo "ok   $LIBC $1"
    else
        echo "FAIL $LIBC $1: got \"$2\", want \"$3\"" >&2
        failures=$((failures + 1))
    fi
}
at_least() {
    if [ "$2" -ge "$3" ]; then
        echo "ok   $LIBC $1 ($2 ms)"
    else
        echo "FAIL $LIBC $1: $2 ms, want at least $3" >&2
        failures=$((failures + 1))
    fi
}

case "$LIBC" in
    musl) apk add --no-cache build-base >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static -o /tmp/probe /work/test/runtime/seccomp_probe.c
init=/out/chaos-init-'"$ARCH"'
go=/out/seccomp-go
mkdir -p /tmp/sec/data /tmp/sec/slow /tmp/sec/once

state=$($init --libs io -- /bin/cat /tmp/.chaos-init.status | head -1)
if [ "$state" != "state=active" ]; then
    echo "skip $LIBC: seccomp mode unavailable here ($($init --libs io -- /bin/cat /tmp/.chaos-init.status | sed -n 2p))"
    exit 0
fi

expect "C: no rules, no chaos-init: open works" "$(/tmp/probe open /tmp/sec/data/x)" "ok"
printf "%s\n" "/tmp/sec/data:open:EIO:1.0 # t" "/tmp/sec/slow:open:LATENCY:150 # t" \
    "/tmp/sec/once:open:EACCES:1.0 @first=1 # t" > /tmp/.chaos-io.conf
expect "C: without chaos-init the rule does nothing" "$(/tmp/probe open /tmp/sec/data/x)" "ok"
expect "C: open rule fails the open" "$($init --libs io -- /tmp/probe open /tmp/sec/data/x)" "EIO"
expect "C: an unmatched path opens" "$($init --libs io -- /tmp/probe open /tmp/sec/other)" "ok"
at_least "C: LATENCY delays the open" "$($init --libs io -- /tmp/probe openms /tmp/sec/slow/x)" 150
expect "Go: open rule fails the open" "$($init --libs io -- $go open /tmp/sec/data/x)" "EIO"
expect "Go: an unmatched path opens" "$($init --libs io -- $go open /tmp/sec/other)" "ok"
at_least "Go: LATENCY delays the open" "$($init --libs io -- $go openms /tmp/sec/slow/x)" 150
expect "Go: without chaos-init the rule does nothing" "$($go open /tmp/sec/data/x)" "ok"

rm -f /tmp/.chaos-io.hits.*
expect "@first=1 once per process, forked child included" \
    "$($init --libs io -- /tmp/probe first /tmp/sec/once/x)" "parent=EACCES,ok child=EACCES"
files=$(ls /tmp/.chaos-io.hits.* | wc -l)
once=$(cat /tmp/.chaos-io.hits.* | awk -F "\t" "\$2 ~ /once/ { s += \$1 } END { print s + 0 }")
expect "one hits file per process, @first hits summed" "$files $once" "2 2"
expect "io status reports the rules" "$(head -2 /tmp/.chaos-io.status | tr "\n" " ")" "state=ok rules=3 "

printf "%s\n" "tcp4://127.0.0.1:7777:connect:ECONNREFUSED:1.0 # t" \
    "tcp4://127.0.0.1:7778:recv:LATENCY:150 # t" > /tmp/.chaos-net.conf
expect "C: without chaos-init the connect rule does nothing" "$(/tmp/probe connect 7777)" "ok"
expect "C: connect rule refuses the connection" "$($init --libs net -- /tmp/probe connect 7777)" "ECONNREFUSED"
expect "C: another port connects" "$($init --libs net -- /tmp/probe connect 7779)" "ok"
expect "Go: connect rule refuses the dial" "$($init --libs net -- $go dial 7777)" "ECONNREFUSED"
expect "Go: another port dials" "$($init --libs net -- $go dial 7779)" "ok"
at_least "Go: recv LATENCY delays the server read" "$($init --libs net -- $go recvms 7778)" 150
expect "Go: io and net together" "$($init --libs io,net -- $go open /tmp/sec/data/x) $($init --libs io,net -- $go dial 7777)" "EIO ECONNREFUSED"
expect "net status reports the rules" "$(head -2 /tmp/.chaos-net.status | tr "\n" " ")" "state=ok rules=2 "

printf "%s\n" "mmap/anon:ERRNO:ENOMEM @size>1234566 @size<1234568 # t" > /tmp/.chaos-memory.conf
expect "C: mmap rule fails a mapping of its size" "$($init --libs memory -- /tmp/probe mmap 1234567)" "ENOMEM"
expect "C: other sizes map" "$($init --libs memory -- /tmp/probe mmap 4096)" "ok"
expect "Go: mmap rule fails a mapping of its size" "$($init --libs memory -- $go mmap 1234567)" "ENOMEM"
expect "Go: other sizes map, the runtime runs" "$($init --libs memory -- $go mmap 4096)" "ok"

printf "%s\n" "fork:ERRNO:ENOMEM # t" "posix_spawn:ERRNO:EAGAIN # t" "execve:ERRNO:EACCES # t" > /tmp/.chaos-process.conf
expect "C: the application starts despite an execve rule" "$($init --libs process -- /tmp/probe open /tmp/sec/other)" "ok"
expect "C: fork rule fails fork" "$($init --libs process -- /tmp/probe fork)" "ENOMEM"
expect "C: execve rule fails a later exec" "$($init --libs process -- /tmp/probe exec)" "EACCES"
expect "Go: posix_spawn rule fails os/exec" "$($init --libs process -- $go spawn)" "EAGAIN"
expect "Go: without chaos-init os/exec works" "$($go spawn)" "ok"
rm -f /tmp/.chaos-process.conf
expect "all libraries at once" "$($init --libs io,net,memory,process -- $go dial 7777)" "ECONNREFUSED"
[ "$failures" -eq 0 ]
'

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=alpine:3.20 \
    --build-arg MAKE_TARGET="cross-init-$ARCH" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null
docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -e CGO_ENABLED=0 \
    -v "$ROOT_DIR/test/runtime/seccomp_go:/src:ro" \
    -v "$TMP_DIR/out:/out" \
    -w /src \
    golang:1.23-alpine \
    go build -o /out/seccomp-go main.go
if [ ! -x "$TMP_DIR/out/chaos-init-$ARCH" ] || [ ! -x "$TMP_DIR/out/seccomp-go" ]; then
    echo "FAIL chaos-init-$ARCH or the Go probe was not built" >&2
    exit 1
fi

for libc in glibc musl; do
    if [ "$libc" = glibc ]; then
        base=gcc:bookworm
    else
        base=alpine:3.20
    fi
    docker run --rm \
        --platform "$DOCKER_PLATFORM" \
        -e LIBC="$libc" \
        -v "$TMP_DIR/out:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done
