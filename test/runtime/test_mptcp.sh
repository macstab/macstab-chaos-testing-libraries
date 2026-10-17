#!/bin/sh
#
# test_mptcp.sh: chaos-init's socket-address queries for Multipath TCP sockets match the kernel's
# answers (host).
#
# Go listens and dials with MPTCP by default from 1.24 where the kernel offers it. Such sockets are
# in no /proc/net table, so chaos-init asks sock_diag for them. This suite proves those answers are
# right; it runs on the host because the host kernel decides whether MPTCP exists (Docker Desktop's
# kernel has none). It builds mptcp_probe.c with chaos-init's query code and compares, for MPTCP and
# TCP sockets, chaos-init's local and peer addresses with the kernel's.
#
# Usage:   test_mptcp.sh
# Env:     CHAOS_SKIP_EXIT  exit status of a skip (default 0; CI sets 1)
# Prereqs: Linux, cc. Run by `make test`.
# Exit:    the probe's 0 (all match) or 1 (mismatch or setup failure); non-zero when the
#          probe does not compile; CHAOS_SKIP_EXIT when the host is not Linux or the kernel
#          has no MPTCP (probe exit 77).

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if [ "$(uname -s)" != Linux ]; then
    echo "mptcp test skipped: not Linux" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi

cc -D_GNU_SOURCE -I"$ROOT_DIR/src" -I"$ROOT_DIR/src/common" -I"$ROOT_DIR/src/net" \
    -I"$ROOT_DIR/src/init" -std=c99 -Wall -Wextra -Werror -pedantic -O1 \
    -o "$TMP_DIR/mptcp_probe" "$ROOT_DIR/test/runtime/mptcp_probe.c"

# Diagnostics: the kernel version, the MPTCP sysctl and whether mptcp_diag is loaded or
# available decide whether sock_diag can answer for MPTCP sockets.
echo "kernel $(uname -r); net.mptcp.enabled=$(cat /proc/sys/net/mptcp/enabled 2>/dev/null || echo none);" \
    "mptcp_diag $(grep -q '^mptcp_diag ' /proc/modules 2>/dev/null && echo loaded || echo 'not loaded');" \
    "module $(find /lib/modules/"$(uname -r)" -name 'mptcp_diag*' 2>/dev/null | head -1 || true)"
rc=0
"$TMP_DIR/mptcp_probe" || rc=$?
if [ "$rc" = 77 ]; then
    echo "mptcp test skipped: the kernel has no MPTCP" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi
exit "$rc"
