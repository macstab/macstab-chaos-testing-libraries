#!/bin/sh
#
# test_init.sh: chaos-init keeps the process model transparent in SECCOMP mode, on glibc and musl
# (Docker).
#
# Proves that with the seccomp user-notification filter of all six libraries installed and no rule
# active, the tracee behaves exactly as without chaos-init:
#
# - a static (init_probe.c) and a dynamic program (/bin/sh, ls) can use files, sockets, mmap,
#   fork and exec;
# - the status file says state=active with the selected libraries (or unsupported, with the
#   reason);
# - exit codes and death by signal pass through (7, 137); SIGTERM reaches the application
#   (42); a missing command exits 127; an unknown library is a usage error (2);
# - orphans re-parented to chaos-init are reaped;
# - RLIMIT_NOFILE 256 neither stops the application nor the mode;
# - a kernel older than 5.5 (test build, CHAOS_INIT_TEST_RELEASE=4.19.0) starts the
#   application without a filter and reports why;
# - a listener handover the child cannot send (test build, CHAOS_INIT_TEST_HANDOVER_FAILS)
#   ends the start with 125 within 10 s instead of hanging;
# - a container seccomp profile that refuses seccomp(), or only the filter install (as
#   EBUSY from another supervisor would), starts the application without chaos and without
#   no_new_privs, which chaos-init sets only once seccomp answers.
#
# Under emulation (a foreign architecture through QEMU) seccomp user notification is unavailable;
# the suite detects that from the status file and checks only the unsupported path.
#
# Method: docker buildx builds the static chaos-init (make cross-init-<arch>) on alpine:3.20. In
# gcc:bookworm and then alpine:3.20 containers under Docker's default seccomp profile, init_probe.c
# and the two test builds of chaos-init are compiled from the read-only repository mount and the
# checks run. The refusal checks then run in alpine:3.20 with custom seccomp profiles.
#
# Usage:   test_init.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_INIT_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: docker with buildx; a kernel with seccomp user notification (5.5+) for the
#          active path. Run by `make test`.
# Exit:    0 when every check passes; 1 when chaos-init was not built or a refusal check
#          fails; non-zero when a container check fails (all checks of a libc still run and
#          report); 2 on bad usage; CHAOS_SKIP_EXIT when the host or platform is not
#          amd64/arm64, docker is missing or its daemon is unreachable.

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
        echo "init test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "init test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "init test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
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

# The child hands its notification listener to chaos-init on whatever descriptor number it
# has free, so a low file limit must neither stop the application nor disable the mode.
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

# A profile that refuses seccomp() outright: the application runs without chaos and without
# no_new_privs, which chaos-init sets only once seccomp answers.
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

# A profile that answers the capability query but refuses the filter install
# (SECCOMP_SET_MODE_FILTER, op 1), as the kernel does with EBUSY when another supervisor
# already holds a listener: the same outcome is required.
printf '%s' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["seccomp"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":1,"op":"SCMP_CMP_EQ"}]}]}' \
    > "$TMP_DIR/no-filter.json"
refused=$(docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    --security-opt seccomp="$TMP_DIR/no-filter.json" \
    -v "$TMP_DIR/out:/out:ro" \
    alpine:3.20 \
    sh -c "/out/chaos-init-$ARCH --libs io -- grep NoNewPrivs /proc/self/status | tr -d '\t '; sed -n 2p /tmp/.chaos-init.status")
if [ "$refused" = "$want" ]; then
    echo "ok   filter refused: no chaos, no no_new_privs"
else
    echo "FAIL filter refused: got \"$refused\", want \"$want\"" >&2
    exit 1
fi
