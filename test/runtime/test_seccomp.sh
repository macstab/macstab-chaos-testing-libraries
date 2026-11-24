#!/bin/sh
#
# test_seccomp.sh: io, net, memory and process rules applied by chaos-init in SECCOMP mode, on glibc
# and musl (Docker).
#
# Proves that chaos-init applies rules to programs LD_PRELOAD cannot reach: a static C probe
# (seccomp_probe.c) and a static Go program (seccomp_go, CGO_ENABLED=0, raw system calls). Under
# Docker's default seccomp profile:
#
# - io: an open rule fails the open with its errno (C, Go) and unmatched paths open; LATENCY
#   delays the open (C, Go), also under SIGALRM every 20 ms, where the delay is neither cut
#   short nor restarted per signal and counts one hit (also with the pre-5.19 test build,
#   CHAOS_INIT_TEST_NO_KILLABLE_WAIT); a rule naming a symlink covers the real file;
#   @first=1 fires once per process, a forked child included, one hits file per process; an
#   execve starts a new process for @first while the old image keeps its hits file; the
#   status file reports the rules;
# - lifecycle: when chaos-init is not PID 1, the application exit code returns at once and
#   an orphan it left is still answered (its rule applied, or the open allowed where Yama
#   ptrace_scope hides its path), never ENOSYS; the background chaos-init exits with it;
# - net: a connect rule refuses the connection (C, Go); recv LATENCY delays the server read
#   (Go); a poll TIMEOUT makes select and poll wait out 200 ms with nothing ready while a
#   select without timeout still returns; the status file reports the rules;
# - memory: an mmap rule gated by @size fails only mappings of that size (C, Go); on glibc an
#   mmap/file rule makes the dynamic loader of /bin/ls fail (exit 127);
# - process: an execve rule never blocks the start of the application itself (direct, PATH
#   search, #!-less script via /bin/sh), a non-executable command exits 126, a later exec is
#   refused, a fork rule fails fork (C), a posix_spawn rule fails Go os/exec;
# - a rule SECCOMP mode cannot apply (CORRUPT) rejects the whole file, named in the status;
# - TORN is applied through a ptrace stop: the returned count and the file size both drop
#   below ten and agree, and a fork of the traced application still runs; TRICKLE cuts a
#   stream receive to its chunk and leaves the rest in the socket; CORRUPT flips one bit of
#   what a read delivered, decided at the stop after the call;
# - without chaos-init the same rules change nothing.
#
# Under emulation (a foreign architecture through QEMU) seccomp user notification is unavailable:
# the suite exits CHAOS_SKIP_EXIT from inside the container.
#
# Method: docker buildx builds the static chaos-init (make cross-init-<arch>) on alpine:3.20 and
# golang:1.24-alpine builds seccomp_go. In gcc:bookworm and then alpine:3.20 containers,
# seccomp_probe.c and the pre-5.19 chaos-init test build are compiled from the read-only repository
# mount and the checks run.
#
# Usage:   test_seccomp.sh [linux/amd64|linux/arm64]   (default: the host architecture)
# Env:     CHAOS_SECCOMP_DOCKER_PLATFORM  platform when no argument is given
#          CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1); passed into
#          the containers
# Prereqs: docker with buildx; a kernel with seccomp user notification (5.5+). Run by
#          `make test`.
# Exit:    0 when every check passes; 1 when chaos-init or the Go probe was not built;
#          non-zero when a container check fails (all checks of a libc still run and
#          report); 2 on bad usage; CHAOS_SKIP_EXIT when the host or platform is not
#          amd64/arm64, docker is missing, its daemon is unreachable, or SECCOMP mode is
#          unavailable in the container.

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
        echo "seccomp test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit "${CHAOS_SKIP_EXIT:-0}"
        ;;
esac

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "seccomp test skipped: docker not available" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

if ! docker version >/dev/null 2>&1; then
    echo "seccomp test skipped: docker daemon not accessible" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

# The user-switch case with CAP_SYS_PTRACE; run in its own container, because the main run
# proves chaos-init needs no capability at all.
PTRACE_SCRIPT='
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
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static -o /tmp/probe /work/test/runtime/seccomp_probe.c
init=/out/chaos-init-'"$ARCH"'
mkdir -p /tmp/sec/drop && chmod 777 /tmp/sec/drop
printf "%s\n" "/tmp/sec/drop:open:EIO:1.0 # t" > /tmp/.chaos-io.conf
expect "C: with CAP_SYS_PTRACE the path rule matches after the switch" \
    "$($init --libs io -- /tmp/probe setuid /tmp/sec/drop/x)" "open=EIO mmap=ok"
expect "C: and nothing was unreadable" \
    "$(grep -c "^unreadable=yes$" /tmp/.chaos-init.status || true)" "0"
[ "$failures" -eq 0 ]
'

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
    musl) apk add --no-cache build-base linux-headers >/dev/null ;;
esac
gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static -o /tmp/probe /work/test/runtime/seccomp_probe.c
# A chaos-init test build that behaves as on kernels before 5.19, which lack the killable
# notification wait: there a signal restarts a delayed call as a new notification.
(cd /work && gcc -D_GNU_SOURCE -Isrc -Isrc/common -Isrc/core -Isrc/config -Isrc/effects \
    -Isrc/wrappers -Isrc/net -Isrc/dns -Isrc/time -Isrc/process -Isrc/memory -Isrc/init \
    -std=c99 -Wall -Wextra -Werror -pedantic -O2 -static -DCHAOS_INIT_TEST_NO_KILLABLE_WAIT \
    -o /tmp/chaos-init-restart src/init/chaos_init*.c)
init=/out/chaos-init-'"$ARCH"'
go=/out/seccomp-go
mkdir -p /tmp/sec/data /tmp/sec/slow /tmp/sec/once

state=$($init --libs io -- /bin/cat /tmp/.chaos-init.status | head -1)
if [ "$state" != "state=active" ]; then
    echo "skip $LIBC: seccomp mode unavailable here ($($init --libs io -- /bin/cat /tmp/.chaos-init.status | sed -n 2p))"
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

expect "C: no rules, no chaos-init: open works" "$(/tmp/probe open /tmp/sec/data/x)" "ok"
printf "%s\n" "/tmp/sec/data:open:EIO:1.0 # t" "/tmp/sec/slow:open:LATENCY:150 # t" \
    "/tmp/sec/once:open:EACCES:1.0 @first=1 # t" > /tmp/.chaos-io.conf
# A signal every 20 ms must neither cut the delay short nor restart it. The kernel restarts an
# interrupted call as a new notification; without the 5.19 killable wait, and without the
# delay queue recognising the restart, each one would be delayed again and the call would
# never finish. Both builds must take 150-2000 ms and count one hit.
for variant in "$init" /tmp/chaos-init-restart; do
    rm -f /tmp/.chaos-io.hits.*
    ms=$(timeout 10 $variant --libs io -- /tmp/probe signalled /tmp/sec/slow/x || echo 99999)
    if [ "$ms" -ge 150 ] && [ "$ms" -lt 2000 ]; then
        echo "ok   $LIBC $variant: LATENCY 150 under SIGALRM every 20 ms took $ms ms"
    else
        echo "FAIL $LIBC $variant: LATENCY 150 under SIGALRM every 20 ms took $ms ms" >&2
        failures=$((failures + 1))
    fi
    expect "$variant: the interrupted delay counted once" \
        "$(cat /tmp/.chaos-io.hits.* 2>/dev/null | awk -F "\t" "\$2 ~ /slow/ { s += \$1 } END { print s + 0 }")" "1"
done
# chaos-init is not PID 1 here (sh is). When the application exits, its exit code is returned
# at once, and the child it left behind is still answered, rules included, instead of every
# filtered call of that child failing with ENOSYS.
rm -f /tmp/sec/orphan.out
code=0
$init --libs io -- /tmp/probe orphan /tmp/sec/data/x /tmp/sec/orphan.out >/dev/null || code=$?
expect "the application exit code returns before its orphan is done" "$code $(cat /tmp/sec/orphan.out 2>/dev/null || echo none)" "3 none"
sleep 1
# The chaos-init copy that answers the orphan is not its ancestor. Where Yama lets only
# ancestors read a process (ptrace_scope 1, the Ubuntu default), the orphan path arguments are
# unreadable and the open is allowed. Answered either way, never ENOSYS and never blocked.
if [ "$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo 0)" = 0 ]; then
    expect "the orphan is still answered, its rule applied" "$(cat /tmp/sec/orphan.out 2>/dev/null)" "EIO"
else
    expect "the orphan is still answered (Yama: its path unread)" "$(cat /tmp/sec/orphan.out 2>/dev/null)" "ok"
fi
expect "the background chaos-init ends with the last process" \
    "$(grep -l chaos-init /proc/[0-9]*/comm 2>/dev/null | wc -l | tr -d " ")" "0"
# A rule written with the name of a symlink covers the files under its real name, which is the
# name /proc reports for an open descriptor.
mkdir -p /tmp/sec/real && echo data > /tmp/sec/real/f && ln -sfn /tmp/sec/real /tmp/sec/link
cp /tmp/.chaos-io.conf /tmp/sec/io.conf
echo "/tmp/sec/link:read:EIO:1.0 # t" > /tmp/.chaos-io.conf
expect "C: read rule on the name of a link" "$($init --libs io -- /tmp/probe read /tmp/sec/real/f)" "EIO"
cp /tmp/sec/io.conf /tmp/.chaos-io.conf
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
rm -f /tmp/.chaos-io.hits.*
expect "@first=1 again after an execve, as for a new process" \
    "$($init --libs io -- sh -c "{ true; } 3</tmp/sec/once/x 2>/dev/null; exec /tmp/probe open /tmp/sec/once/x")" "EACCES"
files=$(ls /tmp/.chaos-io.hits.* | wc -l)
once=$(cat /tmp/.chaos-io.hits.* | awk -F "\t" "\$2 ~ /once/ { s += \$1 } END { print s + 0 }")
expect "the image an execve replaced keeps its hits file" "$files $once" "2 2"
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
printf "%s\n" "tcp4://127.0.0.1:7781:poll:TIMEOUT:1.0 # t" > /tmp/.chaos-net.conf
expect "C: TIMEOUT waits out select and poll, with nothing left ready" \
    "$($init --libs net -- /tmp/probe waits 7781)" "select=0,0,waited poll=0,0 forever=1"
printf "%s\n" "tcp4://127.0.0.1:7777:connect:ECONNREFUSED:1.0 # t" \
    "tcp4://127.0.0.1:7778:recv:LATENCY:150 # t" > /tmp/.chaos-net.conf

printf "%s\n" "mmap/anon:ERRNO:ENOMEM @size>1234566 @size<1234568 # t" > /tmp/.chaos-memory.conf
expect "C: mmap rule fails a mapping of its size" "$($init --libs memory -- /tmp/probe mmap 1234567)" "ENOMEM"
expect "C: other sizes map" "$($init --libs memory -- /tmp/probe mmap 4096)" "ok"
expect "Go: mmap rule fails a mapping of its size" "$($init --libs memory -- $go mmap 1234567)" "ENOMEM"
expect "Go: other sizes map, the runtime runs" "$($init --libs memory -- $go mmap 4096)" "ok"
# The dynamic loader is part of the process too (docs/SECCOMP.md section 5): an mmap/file
# rule keeps a dynamic program from mapping its libraries, so it exits 127 (glibc only).
if [ "$LIBC" = glibc ]; then
    printf "%s\n" "mmap/file:ERRNO:ENOMEM # t" > /tmp/.chaos-memory.conf
    code=0
    $init --libs memory -- /bin/ls / >/dev/null 2>&1 || code=$?
    expect "the loader of a dynamic program is faulted too" "$code" "127"
fi
rm -f /tmp/.chaos-memory.conf

printf "%s\n" "fork:ERRNO:ENOMEM # t" "posix_spawn:ERRNO:EAGAIN # t" "execve:ERRNO:EACCES # t" > /tmp/.chaos-process.conf
expect "C: the application starts despite an execve rule" "$($init --libs process -- /tmp/probe open /tmp/sec/other)" "ok"
mkdir -p /tmp/sec/bin && cp /tmp/probe /tmp/sec/bin/probe-in-path
expect "C: one found by PATH search starts too" \
    "$(PATH=/nonexistent:/tmp/sec/bin $init --libs process -- probe-in-path open /tmp/sec/other)" "ok"
# As execvp() does: a script without #! runs through /bin/sh and is still the start the execve
# rule leaves alone; a command found only without execute permission is refused (126), not
# missing (127).
printf "%s\n" "echo script-ok" > /tmp/sec/noshebang && chmod 755 /tmp/sec/noshebang
expect "C: a script without #! starts through /bin/sh" "$($init --libs process -- /tmp/sec/noshebang)" "script-ok"
printf "%s\n" "echo no" > /tmp/sec/bin/not-executable && chmod 644 /tmp/sec/bin/not-executable
code=0
PATH=/tmp/sec/bin $init --libs process -- not-executable 2>/dev/null || code=$?
expect "C: a command that cannot be executed exits 126" "$code" "126"
expect "C: fork rule fails fork" "$($init --libs process -- /tmp/probe fork)" "ENOMEM"
expect "C: execve rule fails a later exec" "$($init --libs process -- /tmp/probe exec)" "EACCES"
expect "Go: posix_spawn rule fails os/exec" "$($init --libs process -- $go spawn)" "EAGAIN"
expect "Go: without chaos-init os/exec works" "$($go spawn)" "ok"
rm -f /tmp/.chaos-process.conf
expect "all libraries at once" "$($init --libs io,net,memory,process -- $go dial 7777)" "ECONNREFUSED"

printf "%s\n" "/tmp/sec/data:open:EIO:1.0 # t" "/tmp/sec/data:statfs:FULL:1.0 # t" > /tmp/.chaos-io.conf
expect "a rule SECCOMP mode cannot apply rejects the file" "$($init --libs io -- /tmp/probe open /tmp/sec/data/x)" "ok"
expect "the status file names it" "$(sed -n 3,4p /tmp/.chaos-io.status | tr "\n" " ")" \
    "line=2 reason=unsupported in seccomp mode "

# TORN through a ptrace stop: the count is shortened in the register before the kernel reads
# it, so the returned count and the file size drop together and both stay under ten. A
# supervisor that faked the count without shortening the call would leave ten bytes behind.
printf "%s\n" "/tmp/sec/data:write:TORN:1.0 # t" > /tmp/.chaos-io.conf
torn=$($init --libs io -- /tmp/probe torn /tmp/sec/data/torn)
expect "C: TORN reports a shortened count" "$(echo "$torn" | sed -n "s/^wrote=\\([1-9]\\) file=.*/short/p")" "short"
expect "C: TORN really shortened the write" "$(echo "$torn" | sed -n "s/^wrote=\\([1-9]\\) file=\\1$/match/p")" "match"
expect "C: the TORN rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-io.status | tr "\n" " ")" "state=ok rules=1 "
# TRICKLE through a trace stop: every receive is cut to the chunk, so the first returns 4
# of the ten bytes sent and the second -- which asks for the remaining 6 -- is cut to 4 as
# well. Both numbers below the request is what shows the register was shortened.
printf "%s\n" "*:recv:TRICKLE:4 # t" > /tmp/.chaos-net.conf
expect "C: TRICKLE shortens every receive" "$($init --libs net -- /tmp/probe trickle 7801)" \
    "first=4 rest=4"
expect "C: the TRICKLE rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-net.status | tr "\n" " ")" "state=ok rules=1 "
rm -f /tmp/.chaos-net.conf

# CORRUPT through the stop after the call: the entry stop cannot know how many bytes a read
# will deliver, so the thread runs on into its syscall-exit stop and one bit of what it
# delivered is flipped there. Exactly one byte differs and exactly one of its bits.
printf "%s\n" "/tmp/sec/data:read:CORRUPT:1.0 # t" > /tmp/.chaos-io.conf
expect "C: CORRUPT flips one bit of a read" \
    "$($init --libs io -- /tmp/probe corrupt /tmp/sec/data/c)" "changed=1 onebit=1"
expect "C: the CORRUPT rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-io.status | tr "\n" " ")" "state=ok rules=1 "
# The same effect on a receive, the net path to the same stop.
printf "%s\n" "*:recv:CORRUPT:1.0 # t" > /tmp/.chaos-net.conf
expect "C: CORRUPT flips one bit of a receive" \
    "$($init --libs net -- /tmp/probe netcorrupt 7802)" "changed=1 onebit=1"
expect "C: the net CORRUPT rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-net.status | tr "\n" " ")" "state=ok rules=1 "

# DUP needs both stops: the first receive runs and its bytes are kept at the exit stop, the
# next read is answered with them without running, and the payload that arrived meanwhile
# follows. A replay that did not happen would show as first=one second=two.
printf "%s\n" "*:recv:DUP:1.0 # t" > /tmp/.chaos-net.conf
expect "C: DUP replays the kept payload once" "$($init --libs net -- /tmp/probe dup 7803)" \
    "first=one second=one third=two"
expect "C: the DUP rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-net.status | tr "\n" " ")" "state=ok rules=1 "
rm -f /tmp/.chaos-net.conf

# write:DROP needs a call of the supervisor in the tracee: the write is replaced by
# the lseek that moves the offset on by the count it reports, so the next write lands past
# the hole. The second write is the one that proves it -- its bytes are at offset ten.
printf "%s\n" "/tmp/sec/data:write:DROP:1.0 @first=1 # t" > /tmp/.chaos-io.conf
expect "C: a dropped write moves the offset on" \
    "$($init --libs io -- /tmp/probe drop /tmp/sec/data/dropped)" \
    "wrote=10,4 zeros=1 tenth=B"
expect "C: the write DROP rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-io.status | tr "\n" " ")" "state=ok rules=1 "

# close:RESET is the other half of that machinery: the setsockopt has to run before the
# close, not instead of it, so the supervisor substitutes it, puts the close back and lets
# the second stop through. The peer is what proves it -- a FIN reads as end of file, an RST
# as ECONNRESET.
expect "C: without a rule the peer reads end of file" "$($init --libs net -- /tmp/probe reset 7804)" \
    "peer=eof"
printf "%s\n" "*:close:RESET:1.0 # t" > /tmp/.chaos-net.conf
expect "C: close RESET aborts the connection" "$($init --libs net -- /tmp/probe reset 7805)" \
    "peer=ECONNRESET"
expect "C: the RESET rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-net.status | tr "\n" " ")" "state=ok rules=1 "
# A socket a forked child still holds is left alone -- SO_LINGER would reset it at the
# close of that child, where no rule is looking. The suppression is reported in the header
# lines of the hits file, so a rule that never gets to fire is not silent about it.
rm -f /tmp/.chaos-net.hits.*
expect "C: a shared socket is not reset" "$($init --libs net -- /tmp/probe shared 7806)" \
    "peer=eof"
expect "C: the suppression is reported" \
    "$(cat /tmp/.chaos-net.hits.* | sed -n "s/^suppressed.shared=\([1-9][0-9]*\)$/counted/p" | head -1)" \
    "counted"
rm -f /tmp/.chaos-net.conf

# Time: a clock read is served from the vDSO, so the supervisor makes the lookups of every
# new image fail and then answers the reads itself. OFFSET shows in the wall second, FREEZE
# makes two reads agree, REGRESS makes the second one earlier -- and a rule on one clock
# leaves the others alone, because the filter tests the clock argument.
reference=$($init --libs time -- /tmp/probe clock realtime)
expect "C: without a rule the clock behaves" \
    "$(echo "$reference" | sed -n "s/^sec=[0-9]* same=0 back=0$/behaves/p")" "behaves"
printf "%s\n" "clock_gettime/realtime:OFFSET:3600000 # t" > /tmp/.chaos-time.conf
shifted=$($init --libs time -- /tmp/probe clock realtime)
expect "C: OFFSET moves the wall clock" \
    "$(( $(echo "$shifted" | sed -n "s/^sec=\([0-9]*\) .*/\1/p") - \
         $(echo "$reference" | sed -n "s/^sec=\([0-9]*\) .*/\1/p") >= 3599 ? 1 : 0 ))" "1"
expect "C: the time rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-time.status | tr "\n" " ")" "state=ok rules=1 "
expect "C: another clock is left alone" \
    "$($init --libs time -- /tmp/probe clock monotonic | sed -n "s/^sec=[0-9]* same=0 back=0$/behaves/p")" \
    "behaves"
printf "%s\n" "clock_gettime/realtime:FREEZE:1.0 # t" > /tmp/.chaos-time.conf
expect "C: FREEZE holds the clock" \
    "$($init --libs time -- /tmp/probe clock realtime | sed -n "s/^sec=[0-9]* same=1 back=0$/frozen/p")" \
    "frozen"
printf "%s\n" "clock_gettime/monotonic:REGRESS:5000 # t" > /tmp/.chaos-time.conf
expect "C: REGRESS steps the clock back" \
    "$($init --libs time -- /tmp/probe clock monotonic | sed -n "s/^sec=[0-9]* same=0 back=1$/stepped/p")" \
    "stepped"
# The same against a static Go binary, which is the case LD_PRELOAD cannot reach at all:
# time.Now() takes both clocks from the vDSO, so the offset has to show in the wall second
# while time.Since stays right.
printf "%s\n" "clock_gettime/realtime:OFFSET:3600000 # t" > /tmp/.chaos-time.conf
go_clock=$($init --libs time -- $go clock)
expect "Go: the wall clock is shifted and time.Since is not" \
    "$(echo "$go_clock" | sed -n "s/^sec=[0-9]* same=true since=2[0-9]ms$/shifted/p")" "shifted"
expect "Go: the vDSO of the Go image was blinded" \
    "$(grep -c "^vdso=failed$" /tmp/.chaos-init.status)" "0"
rm -f /tmp/.chaos-time.conf

# dns: the lookup is a library function, so what SECCOMP mode sees is the query the
# resolver sends -- and that carries the name. A LATENCY rule for one name holds exactly
# that query; another name goes out at once. The answer-changing effects are rejected,
# because the answer is assembled inside the resolver.
printf "%s\n" "dns://slow.example.com:LATENCY:200 # t" > /tmp/.chaos-dns.conf
at_least "C: a dns rule holds the query for its name" \
    "$($init --libs dns -- /tmp/probe dnsquery slow.example.com)" 200
expect "C: and lets another name through" \
    "$($init --libs dns -- /tmp/probe dnsquery fast.example.com)" "0"
expect "C: the dns rule is applied, not rejected" \
    "$(sed -n 1,2p /tmp/.chaos-dns.status | tr "\n" " ")" "state=ok rules=1 "
printf "%s\n" "dns://slow.example.com:EAI_NONAME:1.0 # t" > /tmp/.chaos-dns.conf
expect "C: an answer-changing dns rule rejects the file" \
    "$($init --libs dns -- /tmp/probe dnsquery slow.example.com)" "0"
expect "C: and says why" \
    "$(sed -n 3,4p /tmp/.chaos-dns.status | tr "\n" " ")" \
    "line=1 reason=unsupported in seccomp mode "
rm -f /tmp/.chaos-dns.conf

# A process that drops privileges becomes non-dumpable, and the kernel then refuses every
# look into it: its path cannot be read, so a path rule does not match it. That is a rule
# that looks applied and does nothing, so the supervisor says so in its status file. The
# same case with CAP_SYS_PTRACE is further down, in a container that has it.
mkdir -p /tmp/sec/drop && chmod 777 /tmp/sec/drop
printf "%s\n" "*:open:EIO:1.0 # t" > /tmp/.chaos-io.conf
printf "%s\n" "mmap/anon:ERRNO:ENOMEM @size>1048576 # t" > /tmp/.chaos-memory.conf
# Not even a `*` path rule matches: every io selector is a path, and the path of this open
# lives in the process the kernel will not let the supervisor read. A memory rule names no
# path and still fires, which is the line between what survives a user switch and what
# does not.
expect "C: no path rule matches a process that dropped privileges" \
    "$($init --libs io,memory -- /tmp/probe setuid /tmp/sec/drop/x)" "open=ok mmap=ENOMEM"
expect "C: and the supervisor says why" \
    "$(grep -c "^unreadable=yes$" /tmp/.chaos-init.status)" "1"
rm -f /tmp/.chaos-memory.conf

# A forked child of the tracee is traced too: without PTRACE_O_TRACEFORK its filtered calls
# would fail with ENOSYS, because a RET_TRACE with no tracer does.
printf "%s\n" "/tmp/sec/data:open:EIO:1.0 # t" "/tmp/sec/data:write:TORN:1.0 # t" > /tmp/.chaos-io.conf
expect "C: a fork of a traced application still runs" \
    "$($init --libs io -- /tmp/probe first /tmp/sec/data/x)" "parent=EIO,EIO child=EIO"
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
    golang:1.24-alpine \
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
        -e CHAOS_SKIP_EXIT="${CHAOS_SKIP_EXIT:-0}" \
        -v "$TMP_DIR/out:/out:ro" \
        -v "$ROOT_DIR:/work:ro" \
        "$base" \
        sh -c "$CHECK_SCRIPT"
done

# The other half of the user-switch case, in a container that holds CAP_SYS_PTRACE: the
# kernel then lets the supervisor read a non-dumpable process, so the path rule matches
# after all and nothing is reported. This is the documented cure for it, so it is tested
# rather than claimed. One libc is enough: the check is the kernel's, not the library's.
docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    --cap-add SYS_PTRACE \
    -e LIBC="privileged" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    gcc:bookworm \
    sh -c "$PTRACE_SCRIPT"
