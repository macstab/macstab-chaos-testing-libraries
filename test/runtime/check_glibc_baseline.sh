#!/bin/sh
#
# check_glibc_baseline.sh: fails when a glibc build of a library needs a newer glibc than the
# baseline.
#
# Proves: no libchaos-*-glibc-*.so in the dist directory references a GLIBC_x.y symbol version
# above GLIBC_BASELINE. glibc is backward- but not forward-compatible: a library linked against
# glibc 2.36 binds stat@GLIBC_2.33 and dlsym@GLIBC_2.34, and the loader then refuses it in every
# image with an older glibc (Ubuntu 20.04, Debian 11, RHEL 8, Amazon Linux 2, Elasticsearch's
# image). The floor is kept low by building on an old toolchain (gcc:10 in docker-build-all);
# this gate stops a base-image bump from raising it silently.
#
# Method: the highest GLIBC_ version in `objdump -T` per library, compared with `sort -V`.
#
# Usage:   check_glibc_baseline.sh [dist-dir]      (default <repo>/dist; release.yml passes dist)
# Env:     GLIBC_BASELINE  highest permitted symbol version (default 2.17, the aarch64 floor)
# Prereqs: objdump (binutils), sort -V
# Exit:    0 every library within the baseline; 1 any library above it (the offending symbols
#          are printed to stderr) or no glibc library found. Never skips.

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
DIST_DIR=${1:-"${ROOT_DIR}/dist"}
BASELINE=${GLIBC_BASELINE:-2.17}
status=0

for lib in "${DIST_DIR}"/libchaos-*-glibc-*.so; do
    [ -e "${lib}" ] || { echo "no glibc libraries in ${DIST_DIR}" >&2; exit 1; }
    required=$(objdump -T "${lib}" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/GLIBC_//' | sort -uV | tail -n 1)
    highest=$(printf '%s\n%s\n' "${required}" "${BASELINE}" | sort -V | tail -n 1)
    if [ "${highest}" != "${BASELINE}" ]; then
        echo "FAIL $(basename "${lib}"): needs GLIBC_${required} > baseline ${BASELINE}" >&2
        objdump -T "${lib}" | grep -E "GLIBC_${required}([^.0-9]|$)" >&2 || true
        status=1
    else
        echo "ok   $(basename "${lib}"): GLIBC_${required}"
    fi
done

exit "${status}"
