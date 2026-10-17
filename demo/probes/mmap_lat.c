/* Demo mem2: times one 1 MiB anonymous mmap with CLOCK_MONOTONIC. Under libchaos-memory
 * with `mmap:LATENCY:150` the call takes ~150 ms longer, modelling an allocation stall under
 * memory pressure. Only libchaos-memory is preloaded, so the clock read is not altered. */
#include <stdio.h>
#include <time.h>
#include <sys/mman.h>
static double ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }
int main(void) {
    double a = ms();
    void *p = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    double b = ms();
    printf("mmap took %.1f ms (%s)\n", b - a, p == MAP_FAILED ? "FAILED" : "ok");
    return 0;
}
