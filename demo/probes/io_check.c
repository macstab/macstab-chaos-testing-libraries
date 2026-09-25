/* io use-case 2 — write a record, fsync, read it back N times, verify a checksum.
 * With /data:read:CORRUPT:p a bit is flipped in the returned buffer → mismatch. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

static unsigned long sum(const unsigned char *b, int n) {
    unsigned long s = 1469598103934665603UL;           /* FNV-1a */
    for (int i = 0; i < n; i++) { s ^= b[i]; s *= 1099511628211UL; }
    return s;
}

int main(void) {
    unsigned char buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = (unsigned char)(i * 31 + 7);
    unsigned long want = sum(buf, 4096);

    int fd = open("/data/record.bin", O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) { perror("open"); return 2; }
    if (write(fd, buf, 4096) != 4096) { perror("write"); return 2; }
    fsync(fd);

    int mismatch = 0;
    for (int i = 0; i < 20; i++) {
        unsigned char got[4096];
        lseek(fd, 0, SEEK_SET);
        if (read(fd, got, 4096) != 4096) { perror("read"); return 2; }
        int ok = sum(got, 4096) == want;
        printf("read %2d: %s\n", i, ok ? "OK" : "CHECKSUM MISMATCH — silent corruption detected");
        if (!ok) mismatch = 1;
    }
    close(fd);
    return mismatch ? 0 : 0;   /* both outcomes are informative; exit 0 either way */
}
