#!/bin/sh
#
# check_coverage.sh — Source-line coverage gate for libchaos-io.
#
# Compiles all src/ and test/ files with --coverage (gcov instrumentation),
# runs the unit tests, then calls gcov on each instrumented object and asserts
# that each source file meets its minimum per-file line-coverage percentage.
# Exits non-zero if any threshold is not met.
#
# Usage:   check_coverage.sh
# Env:     CC, CPPFLAGS, CFLAGS, BUILD_DIR  (forwarded to make(1))
# Prereqs: gcc or clang with gcov support; make

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD_DIR=${BUILD_DIR:-build-coverage}
CC=${CC:-cc}
CPPFLAGS=${CPPFLAGS:--D_GNU_SOURCE -Isrc -Isrc/core -Isrc/config -Isrc/effects -Isrc/wrappers}
CFLAGS=${CFLAGS:--std=c99 -Wall -Wextra -Werror -pedantic -Os}

cd "$ROOT_DIR"
rm -rf "$BUILD_DIR"

make unit \
    BUILD_DIR="$BUILD_DIR" \
    CC="$CC" \
    CPPFLAGS="$CPPFLAGS" \
    CFLAGS="$CFLAGS -O0 --coverage" \
    LDFLAGS="--coverage" >/dev/null

check_target() {
    gcno_path=$1
    source_path=$2
    minimum_pct=$3
    output=$(gcov "$gcno_path")

    printf '%s\n' "$output"
    printf '%s\n' "$output" | awk -v file="$source_path" -v min_pct="$minimum_pct" '
        $0 == "File \047" file "\047" { want = 1; next }
        want && $1 == "Lines" {
            pct = $2;
            sub(/^executed:/, "", pct);
            sub(/%$/, "", pct);
            if ((pct + 0.0) >= (min_pct + 0.0)) {
                ok = 1;
            }
            exit ok ? 0 : 1;
        }
        END {
            exit ok ? 0 : 1;
        }
    '
}

resolve_gcno() {
    base_name=$1
    plain_path=$BUILD_DIR/$base_name.gcno
    duplicate_path=$BUILD_DIR/$base_name-$base_name.gcno

    if [ -f "$plain_path" ]; then
        printf '%s\n' "$plain_path"
        return 0
    fi
    if [ -f "$duplicate_path" ]; then
        printf '%s\n' "$duplicate_path"
        return 0
    fi

    printf 'missing gcno for %s\n' "$base_name" >&2
    exit 1
}

CONFIG_GCNO=$(resolve_gcno test_config_parse)
ACTIONS_GCNO=$(resolve_gcno test_actions)
FDCACHE_GCNO=$(resolve_gcno test_fdcache)
CHAOS_IO_GCNO=$(resolve_gcno test_chaos_io)
NET_ACTIONS_GCNO=$(resolve_gcno test_net_actions)
NET_ENDPOINT_GCNO=$(resolve_gcno test_net_endpoint)
NET_CONFIG_GCNO=$(resolve_gcno test_net_config)
NET_RUNTIME_GCNO=$(resolve_gcno test_net_runtime)
CHAOS_NET_GCNO=$(resolve_gcno test_chaos_net)
DNS_ACTIONS_GCNO=$(resolve_gcno test_dns_actions)
DNS_CONFIG_GCNO=$(resolve_gcno test_dns_config)
DNS_RUNTIME_GCNO=$(resolve_gcno test_dns_runtime)
CHAOS_DNS_GCNO=$(resolve_gcno test_chaos_dns)
TIME_ACTIONS_GCNO=$(resolve_gcno test_time_actions)
TIME_CONFIG_GCNO=$(resolve_gcno test_time_config)
TIME_RUNTIME_GCNO=$(resolve_gcno test_time_runtime)
CHAOS_TIME_GCNO=$(resolve_gcno test_chaos_time)
MEMORY_ACTIONS_GCNO=$(resolve_gcno test_memory_actions)
MEMORY_CONFIG_GCNO=$(resolve_gcno test_memory_config)
MEMORY_RUNTIME_GCNO=$(resolve_gcno test_memory_runtime)
CHAOS_MEMORY_GCNO=$(resolve_gcno test_chaos_memory)
PROCESS_ACTIONS_GCNO=$(resolve_gcno test_process_actions)
PROCESS_CONFIG_GCNO=$(resolve_gcno test_process_config)
PROCESS_RUNTIME_GCNO=$(resolve_gcno test_process_runtime)
CHAOS_PROCESS_GCNO=$(resolve_gcno test_chaos_process)

check_target "$CONFIG_GCNO" "src/config/chaos_io_config.c" "100.00"
check_target "$ACTIONS_GCNO" "src/effects/chaos_io_actions.c" "100.00"
check_target "$FDCACHE_GCNO" "src/config/chaos_io_fdcache.c" "100.00"
check_target "$CHAOS_IO_GCNO" "src/core/chaos_io.c" "100.00"
check_target "$CHAOS_IO_GCNO" "src/wrappers/chaos_io_open.c" "100.00"
check_target "$CHAOS_IO_GCNO" "src/wrappers/chaos_io_rw.c" "100.00"
check_target "$CHAOS_IO_GCNO" "src/wrappers/chaos_io_fsops.c" "100.00"
check_target "$CHAOS_IO_GCNO" "src/wrappers/chaos_io_sync.c" "100.00"
check_target "$NET_ACTIONS_GCNO" "src/net/chaos_net_actions.c" "100.00"
check_target "$NET_ENDPOINT_GCNO" "src/net/chaos_net_endpoint.c" "100.00"
check_target "$NET_CONFIG_GCNO" "src/net/chaos_net_config.c" "100.00"
check_target "$NET_RUNTIME_GCNO" "src/net/chaos_net.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_extra.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_socket.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_wait.c" "100.00"
check_target "$DNS_ACTIONS_GCNO" "src/dns/chaos_dns_actions.c" "100.00"
check_target "$DNS_CONFIG_GCNO" "src/dns/chaos_dns_config.c" "85.00"
check_target "$DNS_RUNTIME_GCNO" "src/dns/chaos_dns.c" "100.00"
check_target "$CHAOS_DNS_GCNO" "src/dns/chaos_dns_lookup.c" "85.00"
check_target "$TIME_ACTIONS_GCNO" "src/time/chaos_time_actions.c" "100.00"
check_target "$TIME_CONFIG_GCNO" "src/time/chaos_time_config.c" "100.00"
check_target "$TIME_RUNTIME_GCNO" "src/time/chaos_time.c" "100.00"
check_target "$CHAOS_TIME_GCNO" "src/time/chaos_time_hooks.c" "100.00"
check_target "$MEMORY_ACTIONS_GCNO" "src/memory/chaos_memory_actions.c" "100.00"
check_target "$MEMORY_CONFIG_GCNO" "src/memory/chaos_memory_config.c" "100.00"
check_target "$MEMORY_RUNTIME_GCNO" "src/memory/chaos_memory.c" "100.00"
check_target "$CHAOS_MEMORY_GCNO" "src/memory/chaos_memory_hooks.c" "100.00"
check_target "$PROCESS_ACTIONS_GCNO" "src/process/chaos_process_actions.c" "100.00"
check_target "$PROCESS_CONFIG_GCNO" "src/process/chaos_process_config.c" "100.00"
check_target "$PROCESS_RUNTIME_GCNO" "src/process/chaos_process.c" "100.00"
check_target "$CHAOS_PROCESS_GCNO" "src/process/chaos_process_hooks.c" "100.00"

echo "coverage check passed"
