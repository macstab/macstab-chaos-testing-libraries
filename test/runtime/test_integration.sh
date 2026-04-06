#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
LIB_PATH="$ROOT_DIR/build/libchaos-io.so"
CONFIG_PATH="/tmp/.chaos-io.conf"
TMP_DIR=$(mktemp -d)
BACKUP_CONFIG=""

cleanup() {
    status=$?
    rm -rf "$TMP_DIR"
    if [ -n "$BACKUP_CONFIG" ] && [ -f "$BACKUP_CONFIG" ]; then
        cp "$BACKUP_CONFIG" "$CONFIG_PATH"
        rm -f "$BACKUP_CONFIG"
    else
        rm -f "$CONFIG_PATH"
    fi
    exit "$status"
}

trap cleanup EXIT INT TERM

if [ "$(uname -s)" != "Linux" ]; then
    echo "integration test skipped: requires Linux" >&2
    exit 0
fi

if [ -f "$CONFIG_PATH" ]; then
    BACKUP_CONFIG=$(mktemp)
    cp "$CONFIG_PATH" "$BACKUP_CONFIG"
fi

make -C "$ROOT_DIR" native >/dev/null

cat > "$TMP_DIR/fixture.c" <<'EOF'
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

static int write_once(const char *path, const char *payload)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }

    rc = write(fd, payload, strlen(payload));
    if (rc < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return 0;
}

static int read_once(const char *path)
{
    char buffer[128];
    int fd = open(path, O_RDONLY);
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }

    rc = read(fd, buffer, sizeof(buffer));
    if (rc < 0) {
        perror("read");
        close(fd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    if (write(STDOUT_FILENO, buffer, (size_t)rc) != rc) {
        return 1;
    }

    return 0;
}

static int openat_write_once(const char *dir_path, const char *name, const char *payload)
{
    int dirfd = open(dir_path, O_RDONLY);
    int fd;
    ssize_t rc;

    if (dirfd < 0) {
        perror("open dir");
        return 1;
    }

    fd = openat(dirfd, name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) {
        perror("openat");
        close(dirfd);
        return 1;
    }

    rc = write(fd, payload, strlen(payload));
    if (rc < 0) {
        perror("write");
        close(fd);
        close(dirfd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close file");
        close(dirfd);
        return 1;
    }
    if (close(dirfd) != 0) {
        perror("close dir");
        return 1;
    }

    return 0;
}

static int writev_once(const char *path, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    ssize_t rc;
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);

    if (fd < 0) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = writev(fd, iov, 2);
    if (rc < 0) {
        perror("writev");
        close(fd);
        return 1;
    }
    if ((size_t)rc != first_len + second_len) {
        close(fd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return 0;
}

static int readv_once(const char *path)
{
    int fd = open(path, O_RDONLY);
    struct stat st;
    size_t total;
    size_t first_len;
    size_t second_len;
    char first_buf[128];
    char second_buf[128];
    struct iovec iov[2];
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }
    if (fstat(fd, &st) != 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    total = (size_t)st.st_size;
    first_len = total > 1U ? total / 2U : total;
    second_len = total - first_len;
    if (total > sizeof(first_buf) + sizeof(second_buf)) {
        close(fd);
        return 1;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = readv(fd, iov, 2);
    if (rc < 0) {
        perror("readv");
        close(fd);
        return 1;
    }
    if ((size_t)rc != total) {
        close(fd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }
    if (first_len > 0U && write(STDOUT_FILENO, first_buf, first_len) != (ssize_t)first_len) {
        return 1;
    }
    if (second_len > 0U && write(STDOUT_FILENO, second_buf, second_len) != (ssize_t)second_len) {
        return 1;
    }

    return 0;
}

static int readv_corrupt_check_once(const char *path, const char *expected)
{
    size_t len = strlen(expected);
    size_t first_len = len > 1U ? len / 2U : len;
    size_t second_len = len - first_len;
    char first_buf[(first_len == 0U) ? 1U : first_len];
    char second_buf[(second_len == 0U) ? 1U : second_len];
    struct iovec iov[2];
    int fd = open(path, O_RDONLY);
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = readv(fd, iov, 2);
    if (rc < 0) {
        perror("readv");
        close(fd);
        return 1;
    }
    if ((size_t)rc != len) {
        close(fd);
        return 1;
    }
    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return (memcmp(first_buf, expected, first_len) != 0
        || memcmp(second_buf, expected + first_len, second_len) != 0) ? 0 : 1;
}

static int sendfile_copy_once(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        perror("open source");
        return 1;
    }
    if (fstat(in_fd, &st) != 0) {
        perror("fstat");
        close(in_fd);
        return 1;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        perror("open target");
        close(in_fd);
        return 1;
    }

    rc = sendfile(out_fd, in_fd, NULL, (size_t)st.st_size);
    if (rc < 0) {
        perror("sendfile");
        close(out_fd);
        close(in_fd);
        return 1;
    }

    if (close(out_fd) != 0) {
        perror("close target");
        close(in_fd);
        return 1;
    }
    if (close(in_fd) != 0) {
        perror("close source");
        return 1;
    }

    return 0;
}

static int preadv_once(const char *path, off_t offset, size_t length)
{
    size_t first_len = length > 1U ? length / 2U : length;
    size_t second_len = length - first_len;
    char first_buf[(first_len == 0U) ? 1U : first_len];
    char second_buf[(second_len == 0U) ? 1U : second_len];
    struct iovec iov[2];
    int fd = open(path, O_RDONLY);
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = preadv(fd, iov, 2, offset);
    if (rc < 0) {
        perror("preadv");
        close(fd);
        return 1;
    }
    if ((size_t)rc != length) {
        close(fd);
        return 1;
    }
    if (close(fd) != 0) {
        perror("close");
        return 1;
    }
    if (first_len > 0U && write(STDOUT_FILENO, first_buf, first_len) != (ssize_t)first_len) {
        return 1;
    }
    if (second_len > 0U && write(STDOUT_FILENO, second_buf, second_len) != (ssize_t)second_len) {
        return 1;
    }

    return 0;
}

static int preadv_corrupt_check_once(const char *path, off_t offset, const char *expected)
{
    size_t len = strlen(expected);
    size_t first_len = len > 1U ? len / 2U : len;
    size_t second_len = len - first_len;
    char first_buf[(first_len == 0U) ? 1U : first_len];
    char second_buf[(second_len == 0U) ? 1U : second_len];
    struct iovec iov[2];
    int fd = open(path, O_RDONLY);
    ssize_t rc;

    if (fd < 0) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = first_buf;
    iov[0].iov_len = first_len;
    iov[1].iov_base = second_buf;
    iov[1].iov_len = second_len;
    rc = preadv(fd, iov, 2, offset);
    if (rc < 0) {
        perror("preadv");
        close(fd);
        return 1;
    }
    if ((size_t)rc != len) {
        close(fd);
        return 1;
    }
    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return (memcmp(first_buf, expected, first_len) != 0
        || memcmp(second_buf, expected + first_len, second_len) != 0) ? 0 : 1;
}

static int copy_file_range_copy_once(const char *source_path, const char *target_path)
{
    int in_fd = open(source_path, O_RDONLY);
    int out_fd;
    struct stat st;
    ssize_t rc;

    if (in_fd < 0) {
        perror("open source");
        return 1;
    }
    if (fstat(in_fd, &st) != 0) {
        perror("fstat");
        close(in_fd);
        return 1;
    }

    out_fd = open(target_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out_fd < 0) {
        perror("open target");
        close(in_fd);
        return 1;
    }

    rc = copy_file_range(in_fd, NULL, out_fd, NULL, (size_t)st.st_size, 0U);
    if (rc < 0) {
        perror("copy_file_range");
        close(out_fd);
        close(in_fd);
        return 1;
    }

    if (close(out_fd) != 0) {
        perror("close target");
        close(in_fd);
        return 1;
    }
    if (close(in_fd) != 0) {
        perror("close source");
        return 1;
    }

    return 0;
}

static int pwritev_once(const char *path, off_t offset, const char *first, const char *second)
{
    struct iovec iov[2];
    int fd = open(path, O_WRONLY);
    ssize_t rc;
    size_t first_len = strlen(first);
    size_t second_len = strlen(second);

    if (fd < 0) {
        perror("open");
        return 1;
    }

    iov[0].iov_base = (void *)first;
    iov[0].iov_len = first_len;
    iov[1].iov_base = (void *)second;
    iov[1].iov_len = second_len;
    rc = pwritev(fd, iov, 2, offset);
    if (rc < 0) {
        perror("pwritev");
        close(fd);
        return 1;
    }
    if ((size_t)rc != first_len + second_len) {
        close(fd);
        return 1;
    }

    if (close(fd) != 0) {
        perror("close");
        return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        return 2;
    }

    if (strcmp(argv[1], "write") == 0) {
        if (argc < 4) {
            return 2;
        }
        return write_once(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "read") == 0) {
        return read_once(argv[2]);
    }
    if (strcmp(argv[1], "openat-write") == 0) {
        if (argc < 5) {
            return 2;
        }
        return openat_write_once(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "writev-write") == 0) {
        if (argc < 5) {
            return 2;
        }
        return writev_once(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "readv-read") == 0) {
        return readv_once(argv[2]);
    }
    if (strcmp(argv[1], "readv-corrupt-check") == 0) {
        if (argc < 4) {
            return 2;
        }
        return readv_corrupt_check_once(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "sendfile-copy") == 0) {
        if (argc < 4) {
            return 2;
        }
        return sendfile_copy_once(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "preadv-read") == 0) {
        if (argc < 5) {
            return 2;
        }
        return preadv_once(argv[2], (off_t)atoll(argv[3]), (size_t)strtoul(argv[4], NULL, 10));
    }
    if (strcmp(argv[1], "preadv-corrupt-check") == 0) {
        if (argc < 5) {
            return 2;
        }
        return preadv_corrupt_check_once(argv[2], (off_t)atoll(argv[3]), argv[4]);
    }
    if (strcmp(argv[1], "copy-file-range-copy") == 0) {
        if (argc < 4) {
            return 2;
        }
        return copy_file_range_copy_once(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "pwritev-write") == 0) {
        if (argc < 6) {
            return 2;
        }
        return pwritev_once(argv[2], (off_t)atoll(argv[3]), argv[4], argv[5]);
    }

    return 2;
}
EOF

cc -std=c99 -Wall -Wextra -Werror -pedantic -o "$TMP_DIR/fixture" "$TMP_DIR/fixture.c"
TARGET="$TMP_DIR/target.bin"
OPENAT_DIR="$TMP_DIR/openat-dir"
OPENAT_TARGET="$OPENAT_DIR/child.bin"
WRITEV_TARGET="$TMP_DIR/writev-target.bin"
READV_SOURCE="$TMP_DIR/readv-src.bin"
SENDFILE_SOURCE="$TMP_DIR/sendfile-src.bin"
SENDFILE_TARGET="$TMP_DIR/sendfile-dst.bin"
PREADV_SOURCE="$TMP_DIR/preadv-src.bin"
COPY_RANGE_SOURCE="$TMP_DIR/copy-range-src.bin"
COPY_RANGE_TARGET="$TMP_DIR/copy-range-dst.bin"
PWRITEV_TARGET="$TMP_DIR/pwritev-target.bin"

mkdir "$OPENAT_DIR"

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$TARGET")
[ "$OUTPUT" = "hello" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" openat-write "$OPENAT_DIR" "child.bin" "openat"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$OPENAT_TARGET")
[ "$OUTPUT" = "openat" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" writev-write "$WRITEV_TARGET" "wr" "itev"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$WRITEV_TARGET")
[ "$OUTPUT" = "writev" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$READV_SOURCE" "readv"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" readv-read "$READV_SOURCE")
[ "$OUTPUT" = "readv" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$SENDFILE_SOURCE" "sendfile"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" sendfile-copy "$SENDFILE_SOURCE" "$SENDFILE_TARGET"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$SENDFILE_TARGET")
[ "$OUTPUT" = "sendfile" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$PREADV_SOURCE" "preadv"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" preadv-read "$PREADV_SOURCE" 1 4)
[ "$OUTPUT" = "read" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$COPY_RANGE_SOURCE" "copy-range"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" copy-file-range-copy "$COPY_RANGE_SOURCE" "$COPY_RANGE_TARGET"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$COPY_RANGE_TARGET")
[ "$OUTPUT" = "copy-range" ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$PWRITEV_TARGET" "........"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" pwritev-write "$PWRITEV_TARGET" 1 "pw" "rite"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$PWRITEV_TARGET")
[ "$OUTPUT" = ".pwrite." ]

printf '%s:write:EIO:1.0\n' "$TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null 2>&1; then
    echo "expected write to fail with injected EIO" >&2
    exit 1
fi

printf '%s:open:EIO:1.0\n' "$OPENAT_TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" openat-write "$OPENAT_DIR" "child.bin" "openat" >/dev/null 2>&1; then
    echo "expected openat write to fail with injected open EIO" >&2
    exit 1
fi

printf '%s:write:EIO:1.0\n' "$WRITEV_TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" writev-write "$WRITEV_TARGET" "wr" "itev" >/dev/null 2>&1; then
    echo "expected writev write to fail with injected EIO" >&2
    exit 1
fi

printf '%s:read:CORRUPT:1.0\n' "$READV_SOURCE" > "$CONFIG_PATH"
if ! LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" readv-corrupt-check "$READV_SOURCE" "readv" >/dev/null 2>&1; then
    echo "expected readv read to be corrupted" >&2
    exit 1
fi

printf '%s:write:EIO:1.0\n' "$SENDFILE_TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" sendfile-copy "$SENDFILE_SOURCE" "$SENDFILE_TARGET" >/dev/null 2>&1; then
    echo "expected sendfile copy to fail with injected EIO" >&2
    exit 1
fi

printf '%s:pread:CORRUPT:1.0\n' "$PREADV_SOURCE" > "$CONFIG_PATH"
if ! LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" preadv-corrupt-check "$PREADV_SOURCE" 1 "read" >/dev/null 2>&1; then
    echo "expected preadv read to be corrupted" >&2
    exit 1
fi

printf '%s:write:EIO:1.0\n' "$COPY_RANGE_TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" copy-file-range-copy "$COPY_RANGE_SOURCE" "$COPY_RANGE_TARGET" >/dev/null 2>&1; then
    echo "expected copy_file_range copy to fail with injected EIO" >&2
    exit 1
fi

printf '%s:pwrite:EIO:1.0\n' "$PWRITEV_TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" pwritev-write "$PWRITEV_TARGET" 1 "pw" "rite" >/dev/null 2>&1; then
    echo "expected pwritev write to fail with injected EIO" >&2
    exit 1
fi

printf '%s:write:LATENCY:200\n' "$TARGET" > "$CONFIG_PATH"
START=$(date +%s%3N)
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null
END=$(date +%s%3N)
ELAPSED_MS=$((END - START))
[ "$ELAPSED_MS" -ge 150 ]

printf '%s:write:TORN:1.0\n' "$SENDFILE_TARGET" > "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" sendfile-copy "$SENDFILE_SOURCE" "$SENDFILE_TARGET" >/dev/null
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$SENDFILE_TARGET")
[ "${#OUTPUT}" -gt 0 ]
[ "${#OUTPUT}" -lt 8 ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$TARGET")
[ "$OUTPUT" = "hello" ]

echo "integration test passed"
