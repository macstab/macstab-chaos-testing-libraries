#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
TMP_DIR=$(mktemp -d)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [linux/amd64|linux/arm64]" >&2
    exit 2
fi

# Allow an explicit Docker target so musl checks do not silently track the host arch.
DOCKER_PLATFORM=${1:-${CHAOS_IO_DOCKER_PLATFORM:-}}
if [ -z "$DOCKER_PLATFORM" ]; then
    case "$(uname -m)" in
        x86_64|amd64)
            DOCKER_PLATFORM=linux/amd64
            ;;
        arm64|aarch64)
            DOCKER_PLATFORM=linux/arm64
            ;;
        *)
            echo "alpine test skipped: unsupported host architecture $(uname -m)" >&2
            exit 0
            ;;
    esac
fi

case "$DOCKER_PLATFORM" in
    linux/amd64)
        DOCKER_PLATFORM=linux/amd64
        MAKE_TARGET=cross-musl-amd64
        OUTPUT_LIB=libchaos-io-musl-amd64.so
        ;;
    linux/arm64)
        DOCKER_PLATFORM=linux/arm64
        MAKE_TARGET=cross-musl-arm64
        OUTPUT_LIB=libchaos-io-musl-arm64.so
        ;;
    *)
        echo "alpine test skipped: unsupported docker platform $DOCKER_PLATFORM" >&2
        exit 0
        ;;
esac

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
    --platform "$DOCKER_PLATFORM" \
    --build-arg BASE_IMAGE=alpine:3.20 \
    --build-arg MAKE_TARGET="$MAKE_TARGET" \
    --output "type=local,dest=$TMP_DIR/out" \
    -f "$ROOT_DIR/docker/Dockerfile.build" \
    "$ROOT_DIR" >/dev/null

[ -f "$TMP_DIR/out/$OUTPUT_LIB" ]

docker run --rm \
    --platform "$DOCKER_PLATFORM" \
    -v "$TMP_DIR/out:/out:ro" \
    alpine:3.20 \
    sh -eu -c "
        apk add --no-cache build-base >/dev/null

        cat >/tmp/probe.c <<'EOF'
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

static int write_config(const char *line, time_t stamp)
{
    struct timespec times[2];
    FILE *config = fopen(\"/tmp/.chaos-io.conf\", \"w\");

    if (config == NULL) {
        return 30;
    }
    if (fprintf(config, \"%s\\n\", line) < 0) {
        fclose(config);
        return 31;
    }
    if (fflush(config) != 0) {
        fclose(config);
        return 32;
    }

    times[0].tv_sec = stamp;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    if (futimens(fileno(config), times) != 0) {
        fclose(config);
        return 33;
    }
    if (fclose(config) != 0) {
        return 34;
    }

    return 0;
}

static int write_payload(const char *path, const char *payload)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    size_t len = strlen(payload);
    ssize_t rc;

    if (fd < 0) {
        return 10;
    }

    rc = write(fd, payload, len);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved;
    }

    if ((size_t)rc != len) {
        close(fd);
        return 11;
    }

    if (close(fd) != 0) {
        return 12;
    }

    return 0;
}

static int openat_write_payload(const char *dir_path, const char *name, const char *payload)
{
    int dirfd = open(dir_path, O_RDONLY);
    int fd;
    size_t len = strlen(payload);
    ssize_t rc;

    if (dirfd < 0) {
        return 44;
    }

    fd = openat(dirfd, name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        int saved = errno;
        close(dirfd);
        return saved == 0 ? 45 : saved;
    }

    rc = write(fd, payload, len);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        close(dirfd);
        return saved == 0 ? 46 : saved;
    }

    if ((size_t)rc != len) {
        close(fd);
        close(dirfd);
        return 47;
    }

    if (close(fd) != 0) {
        close(dirfd);
        return 48;
    }
    if (close(dirfd) != 0) {
        return 49;
    }

    return 0;
}

static int torn_write_payload(const char *path, const char *payload)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    size_t len = strlen(payload);
    ssize_t rc;

    if (fd < 0) {
        return 40;
    }

    rc = write(fd, payload, len);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 41 : saved;
    }

    if (rc <= 0 || (size_t)rc >= len) {
        close(fd);
        return 42;
    }

    if (close(fd) != 0) {
        return 43;
    }

    return 0;
}

static int sendfile_copy_payload(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        return 50;
    }
    if (fstat(in_fd, &st) != 0) {
        close(in_fd);
        return 51;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return 52;
    }

    rc = sendfile(out_fd, in_fd, NULL, (size_t)st.st_size);
    if (rc < 0) {
        int saved = errno;
        close(out_fd);
        close(in_fd);
        return saved == 0 ? 53 : saved;
    }
    if ((size_t)rc != (size_t)st.st_size) {
        close(out_fd);
        close(in_fd);
        return 54;
    }

    if (close(out_fd) != 0) {
        close(in_fd);
        return 55;
    }
    if (close(in_fd) != 0) {
        return 56;
    }

    return 0;
}

static int torn_sendfile_copy_payload(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        return 57;
    }
    if (fstat(in_fd, &st) != 0) {
        close(in_fd);
        return 58;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return 59;
    }

    rc = sendfile(out_fd, in_fd, NULL, (size_t)st.st_size);
    if (rc < 0) {
        int saved = errno;
        close(out_fd);
        close(in_fd);
        return saved == 0 ? 60 : saved;
    }
    if (rc <= 0 || (size_t)rc >= (size_t)st.st_size) {
        close(out_fd);
        close(in_fd);
        return 61;
    }

    if (close(out_fd) != 0) {
        close(in_fd);
        return 62;
    }
    if (close(in_fd) != 0) {
        return 63;
    }

    return 0;
}

static int fsync_with_latency(const char *path)
{
    struct timespec start;
    struct timespec end;
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);

    if (fd < 0) {
        return 20;
    }
    if (write(fd, \"abc\", 3) != 3) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 21 : saved;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return 22;
    }
    if (fsync(fd) != 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 23 : saved;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        close(fd);
        return 24;
    }
    if (close(fd) != 0) {
        return 25;
    }

    return elapsed_ms(&start, &end) >= 150LL ? 0 : 26;
}

int main(void)
{
    time_t now = time(NULL);

    if (write_payload(\"/tmp/target.bin\", \"hello\") != 0) {
        return 1;
    }

    if (write_config(\"/tmp/target.bin:write:EIO:1.0\", now + 1) != 0) {
        return 3;
    }

    if (write_payload(\"/tmp/target.bin\", \"hello\") != EIO) {
        return 4;
    }

    if (mkdir(\"/tmp/openat-dir\", 0700) != 0 && errno != EEXIST) {
        return 5;
    }

    if (write_config(\"/tmp/openat-dir/child.bin:open:EIO:1.0\", now + 2) != 0) {
        return 6;
    }

    if (openat_write_payload(\"/tmp/openat-dir\", \"child.bin\", \"hello\") != EIO) {
        return 7;
    }

    if (write_payload(\"/tmp/sendfile-src.bin\", \"sendfile\") != 0) {
        return 8;
    }

    if (write_config(\"/tmp/sendfile-dst.bin:write:EIO:1.0\", now + 3) != 0) {
        return 9;
    }

    if (sendfile_copy_payload(\"/tmp/sendfile-src.bin\", \"/tmp/sendfile-dst.bin\") != EIO) {
        return 10;
    }

    if (write_config(\"/tmp/sendfile-dst.bin:write:TORN:1.0\", now + 4) != 0) {
        return 11;
    }

    if (torn_sendfile_copy_payload(\"/tmp/sendfile-src.bin\", \"/tmp/sendfile-dst.bin\") != 0) {
        return 12;
    }

    if (write_config(\"/tmp/target.bin:write:TORN:1.0\", now + 5) != 0) {
        return 13;
    }

    if (torn_write_payload(\"/tmp/target.bin\", \"hello\") != 0) {
        return 14;
    }

    if (write_config(\"/tmp/target.bin:fsync:LATENCY:200\", now + 6) != 0) {
        return 15;
    }

    if (fsync_with_latency(\"/tmp/target.bin\") != 0) {
        return 16;
    }

    return 0;
}
EOF

        gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/probe /tmp/probe.c
        cp /out/$OUTPUT_LIB /tmp/libchaos-io.so
        LD_PRELOAD=/tmp/libchaos-io.so /tmp/probe
    "

echo "alpine runtime test passed ($OUTPUT_LIB)"
