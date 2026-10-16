#!/bin/sh
#
# test_mptcp.sh — chaos-init's socket queries for Multipath TCP sockets (host).
#
# Go listens with Multipath TCP by default from 1.24 where the kernel offers it.
# Such sockets are in no /proc/net table; chaos-init asks sock_diag for them.
# This runs on the host, whose kernel decides whether MPTCP exists (Docker
# Desktop's does not): it builds mptcp_probe.c with chaos-init's queries and
# compares their answers with the kernel's own for MPTCP sockets.
#
# Usage:   test_mptcp.sh
# Prereqs: Linux, cc; skipped (exit CHAOS_SKIP_EXIT, default 0) without MPTCP.

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

rc=0
"$TMP_DIR/mptcp_probe" || rc=$?
if [ "$rc" = 77 ]; then
    echo "mptcp test skipped: the kernel has no MPTCP" >&2
    exit "${CHAOS_SKIP_EXIT:-0}"
fi
exit "$rc"
