/* memory use-case 1 — an anonymous mmap. With mmap/anon:ERRNO:ENOMEM it returns
 * MAP_FAILED, the off-heap OOM a JVM -Xmx can never trigger. */
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
int main(void) {
    void *p = mmap(NULL, 4 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) printf("mmap(anon) FAILED: [errno %d] %s\n", errno, strerror(errno));
    else                 printf("mmap ok at %p\n", p);
    return 0;
}
