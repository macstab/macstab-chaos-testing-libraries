#!/usr/bin/env bash
# Executes the documentation's runnable examples so that they cannot rot: every fenced block
# whose info string is `sh verified`, `bash verified` or `shell verified` (fence at column 0).
# Untagged blocks are illustrative and ignored. Run by `make verify-docs` and by ci.yml.
#
# Usage:  run_verified_examples.sh [file.md ...]
#         Without arguments, scans docs/*.md and docs/*/*.md (find -maxdepth 2), sorted.
#
# Each block becomes its own bash script, run with:
#   - set -euo pipefail, so the first failing command fails the block
#   - working directory = repository root, REPO_ROOT exported (blocks are not sandboxed: files
#     they create outside /tmp land in the checkout)
#   - a 30 s limit via timeout(1), or gtimeout on macOS; with neither, no limit (warned)
#   - stdout/stderr captured and printed only when the block fails
# Blocks are independent: state (variables, cd) does not carry over from one block to the next.
#
# Output: one [PASS]/[FAIL] line per block and a summary line.
# Exit status: 0 when every block passed (also when none were found), 1 otherwise.
# Requires bash >= 3.2 (macOS /bin/bash); uses only features available there.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DOCS_DIR="${REPO_ROOT}/docs"
TIMEOUT_CMD="timeout"

# GNU coreutils names it timeout; Homebrew coreutils on macOS installs it as gtimeout.
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

# run_block FILE N CONTENT: wraps CONTENT in a script under a fresh mktemp -d directory, runs
# it, records the result in PASS/FAIL. Exit 124 is timeout(1)'s marker for an expired limit.
# The RETURN trap removes the directory however the function returns; double quotes expand
# $tmpdir now, as intended (hence the SC2064 suppression).
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

# extract_and_run FILE: line-by-line fence scanner. An opening fence with the verified tag
# starts a block, the next bare ``` closes it and runs it. Nested fences are not supported, and
# an unclosed block at end of file is silently not run.
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

# Files without a single verified block count as SKIP. The default list is read with
# while-read from process substitution instead of mapfile, which bash 3.2 lacks; this also
# keeps PASS/FAIL updates in the current shell (a pipe would run the loop in a subshell).
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
