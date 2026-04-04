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

check_target "$BUILD_DIR/test_config_parse-test_config_parse.gcno" "src/chaos_io_config.c"
check_target "$BUILD_DIR/test_actions-test_actions.gcno" "src/chaos_io_actions.c"
check_target "$BUILD_DIR/test_fdcache-test_fdcache.gcno" "src/chaos_io_fdcache.c"
check_target "$BUILD_DIR/test_chaos_io-test_chaos_io.gcno" "src/chaos_io.c"

echo "coverage check passed"
