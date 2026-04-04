#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

if ! command -v docker >/dev/null 2>&1; then
    echo "alpine test skipped: docker not available" >&2
    exit 0
fi

if ! docker version >/dev/null 2>&1; then
    echo "alpine test skipped: docker daemon not accessible" >&2
    exit 0
fi

docker buildx build \
    --platform linux/amd64 \
    --build-arg BASE_IMAGE=alpine:3.20 \
    --build-arg MAKE_TARGET=cross-musl-amd64 \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

[ -f "$TMP_DIR/out/libchaos-io-musl-amd64.so" ]
echo "alpine build test passed"
