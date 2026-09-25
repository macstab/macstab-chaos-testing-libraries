/* io use-case (blog fault 1) — a torn write. With /data:write:TORN:p the
 * write() returns a SHORT count: some bytes never reached the page cache. */
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
