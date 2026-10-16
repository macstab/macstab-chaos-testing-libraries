#!/bin/sh
#
# test_init.sh — chaos-init process model in SECCOMP mode (Docker).
#
# Builds chaos-init with docker/Dockerfile.build (one static binary per
# architecture) and runs it in glibc (gcc:bookworm) and musl (alpine:3.20)
# containers under Docker's default security profile, with the filter of all
# libraries active. The supervisor still lets every call through, so the
# application must behave exactly as without it:
#
# - files, sockets, mmap, fork and exec work, for a static and a dynamic program;
# - the status file says active (or unsupported, with the reason);
# - exit codes and death by signal pass through; SIGTERM reaches the application;
# - orphans are reaped; a missing command exits 127;
# - a file limit of 256 neither stops the application nor the mode;
# - a kernel older than 5.5 (test build) starts the application without a filter;
# - a handover the child cannot send (test build) ends the start instead of hanging;
# - a profile that refuses seccomp starts it without a filter and without
#   no_new_privs.
#
# Under emulation (amd64 on an arm64 host) seccomp is unavailable: then only the
# unsupported path is checked.
#
# Usage:   test_init.sh [linux/amd64|linux/arm64]
# Env:     CHAOS_INIT_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_INIT_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "init test skipped: unsupported host architecture $(uname -m)" >&2
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
        echo "init test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "init test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "init test skipped: docker daemon not accessible" >&2
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

case "$LIBC" in
    musl) apk add --no-cache build-base linux-headers >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static -o /tmp/probe /work/test/runtime/init_probe.c
gcc -D_GNU_SOURCE -I/work/src -I/work/src/common -I/work/src/core -I/work/src/config -I/work/src/effects \
    -I/work/src/init -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static \
    -DCHAOS_INIT_TEST_RELEASE="\"4.19.0\"" -o /tmp/chaos-init-old /work/src/init/chaos_init*.c
gcc -D_GNU_SOURCE -I/work/src -I/work/src/common -I/work/src/core -I/work/src/config -I/work/src/effects \
    -I/work/src/init -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static \
    -DCHAOS_INIT_TEST_RELEASE="\"4.19.0\"" -DCHAOS_INIT_TEST_HANDOVER_FAILS -o /tmp/chaos-init-lost /work/src/init/chaos_init*.c
init=/out/chaos-init-'"$ARCH"'
all=io,net,dns,time,memory,process

status=$($init --libs io,net -- /tmp/probe status)
case "$status" in
    *"reason=seccomp user notification not available"*)
        echo "skip $LIBC: seccomp unavailable here (emulated architecture), checking only the unsupported path"
        emulated=1 ;;
    *) emulated=0
       expect "status active" "$(echo "$status" | head -2 | tr "\n" " ")" "state=active libs=io,net " ;;
esac

expect "static program works under the filter" "$($init --libs $all -- /tmp/probe work)" "work ok (0)"
expect "dynamic program works under the filter" "$($init --libs $all -- /bin/sh -c "ls / >/dev/null && echo dyn-ok")" "dyn-ok"

set +e
$init --libs $all -- /tmp/probe exit 7; expect "exit code passes through" "$?" "7"
$init --libs $all -- /tmp/probe selfkill; expect "death by SIGKILL is 137" "$?" "137"
$init --libs $all -- /no/such/program 2>/dev/null; expect "missing command is 127" "$?" "127"
$init --libs disk -- /tmp/probe exit 0 2>/dev/null; expect "unknown library is a usage error" "$?" "2"
$init --libs $all -- /tmp/probe term > /tmp/term.out &
pid=$!
tries=0
while ! grep -q ready /tmp/term.out 2>/dev/null && [ $tries -lt 50 ]; do sleep 0.1; tries=$((tries + 1)); done
kill -TERM $pid; wait $pid; expect "SIGTERM reaches the application" "$?" "42"
set -e
expect "orphans are reaped" "$($init --libs $all -- /tmp/probe orphans)" "zombies=0"

# The listener goes over whatever descriptor the child has, so a low file limit
# neither stops the container nor the mode.
expect "file limit 256: the application starts" "$( (ulimit -n 256; $init --libs $all -- /tmp/probe work) 2>&1)" "work ok (0)"
if [ "$emulated" -eq 0 ]; then
    expect "file limit 256: the mode is active" "$( (ulimit -n 256; $init --libs io -- /tmp/probe status) | head -1)" "state=active"
fi

old=$(/tmp/chaos-init-old --libs io -- /tmp/probe status | head -2 | tr "\n" " ")
expect "old kernel: unsupported, with the reason" "$old" "state=unsupported reason=kernel older than 5.5 "
expect "old kernel: the application still runs" "$(/tmp/chaos-init-old --libs $all -- /tmp/probe work)" "work ok (0)"
code=0
timeout -s KILL 10 /tmp/chaos-init-lost --libs io -- /tmp/probe work >/dev/null 2>&1 || code=$?
expect "a handover that cannot be sent ends the start, no hang" "$code" "125"
[ "$failures" -eq 0 ]
'

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=alpine:3.20 \
    --build-arg MAKE_TARGET="cross-init-$ARCH" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null
if [ ! -x "$TMP_DIR/out/chaos-init-$ARCH" ]; then
    echo "FAIL chaos-init-$ARCH was not built" >&2
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

# A profile that refuses seccomp: the application runs without chaos, and without
# no_new_privs, which chaos-init only sets once seccomp answers.
printf '%s' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["seccomp"],"action":"SCMP_ACT_ERRNO"}]}' \
    > "$TMP_DIR/no-seccomp.json"
refused=$(docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    --security-opt seccomp="$TMP_DIR/no-seccomp.json" \
    -v "$TMP_DIR/out:/out:ro" \
    alpine:3.20 \
    sh -c "/out/chaos-init-$ARCH --libs io -- grep NoNewPrivs /proc/self/status | tr -d '\t '; sed -n 2p /tmp/.chaos-init.status")
want="NoNewPrivs:0
reason=seccomp refused by the container's security settings"
if [ "$refused" = "$want" ]; then
    echo "ok   seccomp refused: no chaos, no no_new_privs"
else
    echo "FAIL seccomp refused: got \"$refused\", want \"$want\"" >&2
    exit 1
fi
