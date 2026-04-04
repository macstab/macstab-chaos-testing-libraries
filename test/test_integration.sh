#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
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
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
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

    return 2;
}
EOF

cc -std=c99 -Wall -Wextra -Werror -pedantic -o "$TMP_DIR/fixture" "$TMP_DIR/fixture.c"
TARGET="$TMP_DIR/target.bin"

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello"
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$TARGET")
[ "$OUTPUT" = "hello" ]

printf '%s:write:EIO:1.0\n' "$TARGET" > "$CONFIG_PATH"
if LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null 2>&1; then
    echo "expected write to fail with injected EIO" >&2
    exit 1
fi

printf '%s:write:LATENCY:200\n' "$TARGET" > "$CONFIG_PATH"
START=$(date +%s%3N)
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null
END=$(date +%s%3N)
ELAPSED_MS=$((END - START))
[ "$ELAPSED_MS" -ge 150 ]

rm -f "$CONFIG_PATH"
LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" write "$TARGET" "hello" >/dev/null
OUTPUT=$(LD_PRELOAD="$LIB_PATH" "$TMP_DIR/fixture" read "$TARGET")
[ "$OUTPUT" = "hello" ]

echo "integration test passed"
