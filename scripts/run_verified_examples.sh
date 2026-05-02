#!/usr/bin/env bash
# Extract and run every ```sh verified``` block from docs/*.md.
# Blocks without the "verified" tag are silently skipped.
#
# Each block runs in an isolated temp directory with:
#   - set -euo pipefail (first failure aborts that block)
#   - 30-second timeout
#   - REPO_ROOT exported so blocks can reference the project root
#
# Exit codes: 0 = all verified blocks passed, 1 = one or more failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS_DIR="${REPO_ROOT}/docs"
TIMEOUT_CMD="timeout"

# GNU timeout vs macOS gtimeout
if ! command -v timeout >/dev/null 2>&1; then
    if command -v gtimeout >/dev/null 2>&1; then
        TIMEOUT_CMD="gtimeout"
    else
        echo "WARNING: timeout command not found — blocks will run without time limit" >&2
        TIMEOUT_CMD=""
    fi
fi

PASS=0
FAIL=0
SKIP=0

run_block() {
    local file="$1"
    local block_num="$2"
    local block_content="$3"

    local tmpdir
    tmpdir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" RETURN

    local script_file="${tmpdir}/block_${block_num}.sh"

    {
        printf '#!/usr/bin/env bash\n'
        printf 'set -euo pipefail\n'
        printf 'export REPO_ROOT="%s"\n' "$REPO_ROOT"
        printf 'cd "%s"\n' "$REPO_ROOT"
        printf '%s\n' "$block_content"
    } >"$script_file"

    chmod +x "$script_file"

    local label
    label="$(basename "$file"):block-${block_num}"

    local exit_code=0
    if [ -n "$TIMEOUT_CMD" ]; then
        $TIMEOUT_CMD 30 bash "$script_file" >"${tmpdir}/stdout" 2>"${tmpdir}/stderr" || exit_code=$?
    else
        bash "$script_file" >"${tmpdir}/stdout" 2>"${tmpdir}/stderr" || exit_code=$?
    fi

    if [ "$exit_code" -eq 0 ]; then
        printf '[PASS] %s\n' "$label"
        PASS=$((PASS + 1))
    elif [ "$exit_code" -eq 124 ]; then
        printf '[FAIL] %s — timed out after 30s\n' "$label" >&2
        FAIL=$((FAIL + 1))
    else
        printf '[FAIL] %s — exit %d\n' "$label" "$exit_code" >&2
        if [ -s "${tmpdir}/stdout" ]; then
            printf '  stdout:\n'
            sed 's/^/    /' "${tmpdir}/stdout" >&2
        fi
        if [ -s "${tmpdir}/stderr" ]; then
            printf '  stderr:\n'
            sed 's/^/    /' "${tmpdir}/stderr" >&2
        fi
        FAIL=$((FAIL + 1))
    fi
}

extract_and_run() {
    local file="$1"
    local in_block=0
    local block_num=0
    local block_lines=""

    while IFS= read -r line || [ -n "$line" ]; do
        if [ "$in_block" -eq 0 ]; then
            if printf '%s' "$line" | grep -qE '^```sh[[:space:]]+verified'; then
                in_block=1
                block_lines=""
                block_num=$((block_num + 1))
            elif printf '%s' "$line" | grep -qE '^```(bash|shell)[[:space:]]+verified'; then
                in_block=1
                block_lines=""
                block_num=$((block_num + 1))
            fi
        else
            if printf '%s' "$line" | grep -qE '^```[[:space:]]*$'; then
                in_block=0
                run_block "$file" "$block_num" "$block_lines"
            else
                block_lines="${block_lines}${line}
"
            fi
        fi
    done <"$file"
}

# Find docs to scan — use a while loop to stay POSIX-safe on bash 3 (macOS)
if [ "$#" -gt 0 ]; then
    for f in "$@"; do
        if grep -qE '^```(sh|bash|shell)[[:space:]]+verified' "$f" 2>/dev/null; then
            extract_and_run "$f"
        else
            SKIP=$((SKIP + 1))
        fi
    done
else
    while IFS= read -r f; do
        if grep -qE '^```(sh|bash|shell)[[:space:]]+verified' "$f" 2>/dev/null; then
            extract_and_run "$f"
        else
            SKIP=$((SKIP + 1))
        fi
    done < <(find "$DOCS_DIR" -maxdepth 2 -name '*.md' | sort)
fi

printf '\n--- verified-examples: %d passed, %d failed, %d files with no verified blocks ---\n' \
    "$PASS" "$FAIL" "$SKIP"

[ "$FAIL" -eq 0 ]
