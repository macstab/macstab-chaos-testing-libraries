#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${BUILD_DIR:-build-coverage}
CC=${CC:-cc}
CPPFLAGS=${CPPFLAGS:--D_GNU_SOURCE -Isrc}
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
    output=$(gcov "$gcno_path")

    printf '%s\n' "$output"
    printf '%s\n' "$output" | awk -v file="$source_path" '
        $0 == "File \047" file "\047" { want = 1; next }
        want && $1 == "Lines" {
            if ($2 == "executed:100.00%") {
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

check_target "$CONFIG_GCNO" "src/chaos_io_config.c"
check_target "$ACTIONS_GCNO" "src/chaos_io_actions.c"
check_target "$FDCACHE_GCNO" "src/chaos_io_fdcache.c"
check_target "$CHAOS_IO_GCNO" "src/chaos_io.c"
check_target "$CHAOS_IO_GCNO" "src/chaos_io_open.c"
check_target "$CHAOS_IO_GCNO" "src/chaos_io_rw.c"
check_target "$CHAOS_IO_GCNO" "src/chaos_io_sync.c"

echo "coverage check passed"
