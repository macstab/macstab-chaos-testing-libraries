#!/bin/sh
#
# test_dns_glibc.sh — libchaos-dns runtime validation on glibc (Docker).
#
# Builds libchaos-dns.so for the target platform using Docker buildx with a
# glibc (debian:bookworm) base, then runs the pre-compiled dns_probe binary
# under LD_PRELOAD in a glibc container. Validates getaddrinfo and getnameinfo
# fault injection (EAI_*, LATENCY, REWRITE, OVERRIDE, FILTER_FAMILY, SHUFFLE,
# LIMIT) on glibc amd64 and arm64.
#
# Usage:   test_dns_glibc.sh [linux/amd64|linux/arm64]
#          Defaults to the host architecture when no argument is given.
# Env:     CHAOS_DNS_DOCKER_PLATFORM  platform override
# Prereqs: docker with buildx and multi-arch support

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)
IMAGE_TAG=libchaos-dns-glibc-probe:local

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

DOCKER_PLATFORM=${1:-${CHAOS_DNS_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "dns glibc test skipped: unsupported host architecture $(uname -m)" >&2
            exit 0
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        MAKE_TARGET=cross-glibc-amd64
        OUTPUT_LIB=libchaos-dns-glibc-amd64.so
        ;;
    linux/arm64)
        MAKE_TARGET=cross-glibc-arm64
        OUTPUT_LIB=libchaos-dns-glibc-arm64.so
        ;;
    *)
        echo "dns glibc test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

cleanup() {
    docker image rm -f "$IMAGE_TAG" >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "dns glibc test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "dns glibc test skipped: docker daemon not accessible" >&2
    exit 0
fi

docker buildx build \
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=gcc:bookworm \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

[ -f "$TMP_DIR/out/$OUTPUT_LIB" ]

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    -v "$ROOT_DIR:/work:ro" \
    gcc:bookworm \
    sh -eu -c "
        cp /out/$OUTPUT_LIB /tmp/libchaos-dns.so
        gcc -D_GNU_SOURCE -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/dns-probe /work/test/runtime/dns_probe.c
        LD_PRELOAD=/tmp/libchaos-dns.so /tmp/dns-probe
    "
