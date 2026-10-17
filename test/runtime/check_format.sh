#!/bin/sh
#
# check_format.sh: clang-format gate and formatter for every C source under src/ and test/.
#
# --check (default, `make fmt-check`) proves that every .c and .h file is byte-identical to
# clang-format's output under the repository's .clang-format; it stops at the first deviating
# file and prints its unified diff. --write (`make fmt`) reformats all files in place.
#
# Usage:   check_format.sh [--check|--write]
# Env:     CLANG_FORMAT  clang-format binary to use instead of the one found in PATH
# Prereqs: clang-format (CLANG_FORMAT, then PATH, then `xcrun --find` on macOS); output can
#          differ between clang-format major versions.
# Exit:    0 all files conform (or were rewritten); 1 a file deviates or no clang-format was
#          found; 2 unknown mode. Never skips.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
MODE=${1:---check}

find_clang_format() {
    if [ -n "${CLANG_FORMAT:-}" ] && command -v "${CLANG_FORMAT}" >/dev/null 2>&1; then
        command -v "${CLANG_FORMAT}"
        return 0
    fi
    if command -v clang-format >/dev/null 2>&1; then
        command -v clang-format
        return 0
    fi
    if command -v xcrun >/dev/null 2>&1; then
        xcrun --find clang-format 2>/dev/null && return 0
    fi

    echo "clang-format is required for C style checks" >&2
    exit 1
}

list_files() {
    find "$ROOT_DIR/src" "$ROOT_DIR/test" -type f \( -name '*.c' -o -name '*.h' \) | sort
}

FORMATTER=$(find_clang_format)

case "$MODE" in
    --write)
        list_files | while IFS= read -r file; do
            "$FORMATTER" -style=file -i "$file"
        done
        ;;
    --check)
        list_files | while IFS= read -r file; do
            tmp=$(mktemp)
            "$FORMATTER" -style=file "$file" >"$tmp"
            if ! cmp -s "$file" "$tmp"; then
                diff -u "$file" "$tmp" || true
                rm -f "$tmp"
                exit 1
            fi
            rm -f "$tmp"
        done
        ;;
    *)
        echo "usage: $0 [--check|--write]" >&2
        exit 2
        ;;
esac
