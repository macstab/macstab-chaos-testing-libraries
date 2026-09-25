/* memory use-case 2 — time an mmap. With mmap:LATENCY:150 it gains ~150 ms, modelling
 * an allocation-path / page-reclaim stall. Timing is real: only the memory lib is loaded. */
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
