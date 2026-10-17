/* Demo io3: one 4096-byte write() to /data/torn. Under libchaos-io with
 * `/data:write:TORN:1.0` the wrapper passes a shorter count to the real write, so only a
 * prefix reaches the file and write() returns that short count. Code that ignores the return
 * value of write() loses the tail silently. */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    char buf[4096];
    memset(buf, 'x', sizeof buf);
    int fd = open("/data/torn", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    ssize_t r = write(fd, buf, sizeof buf);
    if (r >= 0 && r < (ssize_t)sizeof buf)
        printf("write(4096) returned %zd — TORN short write, %zd bytes lost\n",
               r, (ssize_t)sizeof buf - r);
    else
        printf("write(4096) returned %zd (no fault)\n", r);
    close(fd);
    return 0;
}
