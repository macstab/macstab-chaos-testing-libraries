#!/bin/sh
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
