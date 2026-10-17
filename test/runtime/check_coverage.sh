#!/bin/sh
#
# check_coverage.sh: 100% line-coverage gate for every library, chaos-init and the shared
# headers.
#
# Proves: each listed source file reaches 100.00% executed lines in the unit test that owns it
# (check_target), and each shared header (src/common/*.h and every <lib>_internal.h) has every
# executable line run by at least one unit test (check_union). Any untested line in a wrapper,
# parser or effect is a gate failure, not a statistic.
#
# Method: wipes BUILD_DIR, runs `make unit` with `-O0 --coverage` appended to CFLAGS (the last
# -O wins, so no line is optimised away), then parses gcov output per .gcno. A header compiled
# into many tests is merged across all of them: a line counts as run when any test ran it.
#
# Usage:   check_coverage.sh                (`make coverage` runs it with BUILD_DIR=build-coverage)
# Env:     CC, CPPFLAGS, CFLAGS, BUILD_DIR  forwarded to make (defaults below)
# Prereqs: a compiler with gcov support (gcc + gcov, or clang with a gcov-compatible tool); make
# Exit:    0 every gate met; non-zero at the first file below 100%, a header line no test ran
#          (listed as `<file>:<line> not run by any test`), or a missing .gcno. Never skips.

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

# check_union: a header every library includes is compiled into many tests, so no single .gcno
# is authoritative. Runs gcov -p (path-mangled report names, '/' -> '#') on every .gcno, keeps
# each run's reports in its own directory, then merges the reports for this header: a line is
# executable if any report lists it and run if any report has a non-zero count. Fails unless
# the header has executable lines and none is missed.
check_union() {
    source_path=$1
    key=$(printf '%s' "$source_path" | sed 's|/|#|g')
    union_dir=$BUILD_DIR/union
    rm -rf "$union_dir"
    mkdir -p "$union_dir"
    index=0
    for gcno in "$BUILD_DIR"/*.gcno; do
        index=$((index + 1))
        mkdir -p "$union_dir/$index"
        gcov -p "$gcno" >/dev/null 2>&1 || true
        for report in ./*.gcov; do
            [ -e "$report" ] && mv "$report" "$union_dir/$index/"
        done
    done
    cat "$union_dir"/*/*"$key.gcov" 2>/dev/null | awk -v file="$source_path" '
        BEGIN { FS = ":" }
        {
            count = $1; gsub(/ /, "", count); line = $2 + 0;
            if (count == "-" || line == 0) next;
            seen[line] = 1;
            if (count != "#####" && count != "=====") run[line] = 1;
        }
        END {
            total = 0; missed = 0;
            for (line in seen) { total++; if (!(line in run)) { missed++; printf "%s:%d not run by any test\n", file, line } }
            printf "File \047%s\047 (all tests)\nLines executed:%.2f%% of %d\n", file, total ? 100 * (total - missed) / total : 0, total;
            exit (total > 0 && missed == 0) ? 0 : 1;
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
CHAOS_INIT_GCNO=$(resolve_gcno test_chaos_init)
DNS_OWNED_GCNO=$(resolve_gcno test_dns_owned)
CHAOS_INIT_IO_GCNO=$(resolve_gcno test_chaos_init_io)
CHAOS_INIT_NET_GCNO=$(resolve_gcno test_chaos_init_net)
CHAOS_INIT_MEMORY_GCNO=$(resolve_gcno test_chaos_init_memory)
CHAOS_INIT_PROCESS_GCNO=$(resolve_gcno test_chaos_init_process)
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
check_target "$CHAOS_IO_GCNO" "src/wrappers/chaos_io_stdio.c" "100.00"
check_target "$NET_ACTIONS_GCNO" "src/net/chaos_net_actions.c" "100.00"
check_target "$NET_ENDPOINT_GCNO" "src/net/chaos_net_endpoint.c" "100.00"
check_target "$NET_CONFIG_GCNO" "src/net/chaos_net_config.c" "100.00"
check_target "$NET_RUNTIME_GCNO" "src/net/chaos_net.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_extra.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_socket.c" "100.00"
check_target "$CHAOS_NET_GCNO" "src/net/chaos_net_wait.c" "100.00"
check_target "$DNS_ACTIONS_GCNO" "src/dns/chaos_dns_actions.c" "100.00"
check_target "$DNS_CONFIG_GCNO" "src/dns/chaos_dns_config.c" "100.00"
check_target "$DNS_RUNTIME_GCNO" "src/dns/chaos_dns.c" "100.00"
check_target "$CHAOS_DNS_GCNO" "src/dns/chaos_dns_lookup.c" "100.00"
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

check_target "$DNS_OWNED_GCNO" "src/dns/chaos_dns_owned.c" "100.00"
check_target "$CHAOS_INIT_GCNO" "src/init/chaos_init_core.c" "100.00"
check_target "$CHAOS_INIT_GCNO" "src/init/chaos_init_delay.c" "100.00"
check_target "$CHAOS_INIT_GCNO" "src/init/chaos_init_proc.c" "100.00"
check_target "$CHAOS_INIT_GCNO" "src/init/chaos_init_tracee.c" "100.00"
check_target "$CHAOS_INIT_IO_GCNO" "src/init/chaos_init_io.c" "100.00"
check_target "$CHAOS_INIT_NET_GCNO" "src/init/chaos_init_net.c" "100.00"
check_target "$CHAOS_INIT_MEMORY_GCNO" "src/init/chaos_init_memory.c" "100.00"
check_target "$CHAOS_INIT_PROCESS_GCNO" "src/init/chaos_init_process.c" "100.00"
for header in src/common/chaos_clock.h src/common/chaos_hits.h src/common/chaos_once.h \
    src/common/chaos_policy.h src/common/chaos_sleep.h src/common/chaos_status.h \
    src/core/chaos_io_internal.h src/net/chaos_net_internal.h src/dns/chaos_dns_internal.h \
    src/time/chaos_time_internal.h src/memory/chaos_memory_internal.h \
    src/process/chaos_process_internal.h; do
    check_union "$header"
done

echo "coverage check passed"

# check_target leaves gcov's .gcov reports in the working directory (the repository root);
# they are intermediates. On failure the script exits earlier and leaves them for inspection.
rm -f ./*.gcov
