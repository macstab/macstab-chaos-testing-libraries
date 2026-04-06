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
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/uio.h>
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

static int writev_payload(const char *path, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);
    ssize_t rc;

    if (fd < 0) {
        return 44;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = writev(fd, iov, 2);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 45 : saved;
    }
    if ((size_t)rc != first_len + second_len) {
        close(fd);
        return 46;
    }

    if (close(fd) != 0) {
        return 47;
    }

    return 0;
}

static int torn_writev_payload(const char *path, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);
    size_t total = first_len + second_len;
    ssize_t rc;

    if (fd < 0) {
        return 48;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = writev(fd, iov, 2);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 49 : saved;
    }
    if (rc <= 0 || (size_t)rc >= total) {
        close(fd);
        return 50;
    }

    if (close(fd) != 0) {
        return 51;
    }

    return 0;
}

static int readv_check_payload(const char *path, const char *expected, int expect_difference)
{
    size_t len = strlen(expected);
    size_t first_len = len > 1U ? len / 2U : len;
    size_t second_len = len - first_len;
    char first_buf[(first_len == 0U) ? 1U : first_len];
    char second_buf[(second_len == 0U) ? 1U : second_len];
    struct iovec iov[2];
    int fd = open(path, O_RDONLY);
    ssize_t rc;
    int same;

    if (fd < 0) {
        return 52;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = readv(fd, iov, 2);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 53 : saved;
    }
    if ((size_t)rc != len) {
        close(fd);
        return 54;
    }

    same = memcmp(first_buf, expected, first_len) == 0
        && memcmp(second_buf, expected + first_len, second_len) == 0;
    if (close(fd) != 0) {
        return 55;
    }

    if (expect_difference) {
        return same ? 56 : 0;
    }
    return same ? 0 : 57;
}

static int preadv_check_payload(
    const char *path,
    off_t offset,
    const char *expected,
    int expect_difference)
{
    size_t len = strlen(expected);
    size_t first_len = len > 1U ? len / 2U : len;
    size_t second_len = len - first_len;
    char first_buf[(first_len == 0U) ? 1U : first_len];
    char second_buf[(second_len == 0U) ? 1U : second_len];
    struct iovec iov[2];
    int fd = open(path, O_RDONLY);
    ssize_t rc;
    int same;

    if (fd < 0) {
        return 58;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = preadv(fd, iov, 2, offset);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 59 : saved;
    }
    if ((size_t)rc != len) {
        close(fd);
        return 60;
    }

    same = memcmp(first_buf, expected, first_len) == 0
        && memcmp(second_buf, expected + first_len, second_len) == 0;
    if (close(fd) != 0) {
        return 61;
    }

    if (expect_difference) {
        return same ? 62 : 0;
    }
    return same ? 0 : 63;
}

static int pwritev_payload(const char *path, off_t offset, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_WRONLY);
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);
    ssize_t rc;

    if (fd < 0) {
        return 64;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = pwritev(fd, iov, 2, offset);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 65 : saved;
    }
    if ((size_t)rc != first_len + second_len) {
        close(fd);
        return 66;
    }

    if (close(fd) != 0) {
        return 67;
    }

    return 0;
}

static int torn_pwritev_payload(const char *path, off_t offset, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_WRONLY);
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);
    size_t total = first_len + second_len;
    ssize_t rc;

    if (fd < 0) {
        return 68;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = pwritev(fd, iov, 2, offset);
    if (rc < 0) {
        int saved = errno;
        close(fd);
        return saved == 0 ? 69 : saved;
    }
    if (rc <= 0 || (size_t)rc >= total) {
        close(fd);
        return 70;
    }

    if (close(fd) != 0) {
        return 71;
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

static int copy_file_range_copy_payload(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        return 64;
    }
    if (fstat(in_fd, &st) != 0) {
        close(in_fd);
        return 65;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return 66;
    }

    rc = copy_file_range(in_fd, NULL, out_fd, NULL, (size_t)st.st_size, 0U);
    if (rc < 0) {
        int saved = errno;
        close(out_fd);
        close(in_fd);
        return saved == 0 ? 67 : saved;
    }
    if ((size_t)rc != (size_t)st.st_size) {
        close(out_fd);
        close(in_fd);
        return 68;
    }

    if (close(out_fd) != 0) {
        close(in_fd);
        return 69;
    }
    if (close(in_fd) != 0) {
        return 70;
    }

    return 0;
}

static int torn_copy_file_range_copy_payload(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        return 71;
    }
    if (fstat(in_fd, &st) != 0) {
        close(in_fd);
        return 72;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        close(in_fd);
        return 73;
    }

    rc = copy_file_range(in_fd, NULL, out_fd, NULL, (size_t)st.st_size, 0U);
    if (rc < 0) {
        int saved = errno;
        close(out_fd);
        close(in_fd);
        return saved == 0 ? 74 : saved;
    }
    if (rc <= 0 || (size_t)rc >= (size_t)st.st_size) {
        close(out_fd);
        close(in_fd);
        return 75;
    }

    if (close(out_fd) != 0) {
        close(in_fd);
        return 76;
    }
    if (close(in_fd) != 0) {
        return 77;
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

    if (write_payload(\"/tmp/readv-src.bin\", \"readv\") != 0) {
        return 8;
    }

    if (readv_check_payload(\"/tmp/readv-src.bin\", \"readv\", 0) != 0) {
        return 9;
    }

    if (write_config(\"/tmp/readv-src.bin:read:CORRUPT:1.0\", now + 3) != 0) {
        return 10;
    }

    if (readv_check_payload(\"/tmp/readv-src.bin\", \"readv\", 1) != 0) {
        return 11;
    }

    if (write_config(\"/tmp/writev-target.bin:write:EIO:1.0\", now + 4) != 0) {
        return 12;
    }

    if (writev_payload(\"/tmp/writev-target.bin\", \"wr\", \"itev\") != EIO) {
        return 13;
    }

    if (write_config(\"/tmp/writev-target.bin:write:TORN:1.0\", now + 5) != 0) {
        return 14;
    }

    if (torn_writev_payload(\"/tmp/writev-target.bin\", \"wr\", \"itev\") != 0) {
        return 15;
    }

    if (write_payload(\"/tmp/preadv-src.bin\", \"preadv\") != 0) {
        return 16;
    }

    if (preadv_check_payload(\"/tmp/preadv-src.bin\", 1, \"read\", 0) != 0) {
        return 17;
    }

    if (write_config(\"/tmp/preadv-src.bin:pread:CORRUPT:1.0\", now + 6) != 0) {
        return 18;
    }

    if (preadv_check_payload(\"/tmp/preadv-src.bin\", 1, \"read\", 1) != 0) {
        return 19;
    }

    if (write_payload(\"/tmp/pwritev-target.bin\", \"........\") != 0) {
        return 20;
    }

    if (write_config(\"/tmp/pwritev-target.bin:pwrite:EIO:1.0\", now + 7) != 0) {
        return 21;
    }

    if (pwritev_payload(\"/tmp/pwritev-target.bin\", 1, \"pw\", \"rite\") != EIO) {
        return 22;
    }

    if (write_config(\"/tmp/pwritev-target.bin:pwrite:TORN:1.0\", now + 8) != 0) {
        return 23;
    }

    if (torn_pwritev_payload(\"/tmp/pwritev-target.bin\", 1, \"pw\", \"rite\") != 0) {
        return 24;
    }

    if (write_payload(\"/tmp/sendfile-src.bin\", \"sendfile\") != 0) {
        return 25;
    }

    if (write_config(\"/tmp/sendfile-dst.bin:write:EIO:1.0\", now + 9) != 0) {
        return 26;
    }

    if (sendfile_copy_payload(\"/tmp/sendfile-src.bin\", \"/tmp/sendfile-dst.bin\") != EIO) {
        return 27;
    }

    if (write_config(\"/tmp/sendfile-dst.bin:write:TORN:1.0\", now + 10) != 0) {
        return 28;
    }

    if (torn_sendfile_copy_payload(\"/tmp/sendfile-src.bin\", \"/tmp/sendfile-dst.bin\") != 0) {
        return 29;
    }

    if (write_payload(\"/tmp/copy-range-src.bin\", \"copy-range\") != 0) {
        return 30;
    }

    if (write_config(\"/tmp/copy-range-dst.bin:write:EIO:1.0\", now + 11) != 0) {
        return 31;
    }

    if (copy_file_range_copy_payload(\"/tmp/copy-range-src.bin\", \"/tmp/copy-range-dst.bin\") != EIO) {
        return 32;
    }

    if (write_config(\"/tmp/copy-range-dst.bin:write:TORN:1.0\", now + 12) != 0) {
        return 33;
    }

    if (torn_copy_file_range_copy_payload(\"/tmp/copy-range-src.bin\", \"/tmp/copy-range-dst.bin\") != 0) {
        return 34;
    }

    if (write_config(\"/tmp/target.bin:write:TORN:1.0\", now + 13) != 0) {
        return 35;
    }

    if (torn_write_payload(\"/tmp/target.bin\", \"hello\") != 0) {
        return 36;
    }

    if (write_config(\"/tmp/target.bin:fsync:LATENCY:200\", now + 14) != 0) {
        return 37;
    }

    if (fsync_with_latency(\"/tmp/target.bin\") != 0) {
        return 38;
    }

    return 0;
}
EOF

        gcc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o /tmp/probe /tmp/probe.c
        cp /out/$OUTPUT_LIB /tmp/libchaos-io.so
        LD_PRELOAD=/tmp/libchaos-io.so /tmp/probe
    "

echo "alpine runtime test passed ($OUTPUT_LIB)"
