/* time use-case 2 — CLOCK_MONOTONIC steps backward. The config starts at OFFSET:0; the
 * probe rewrites it to OFFSET:-5000 between two reads, so the second read lands earlier
 * and elapsed goes negative — the exact hazard a VM migration / NTP step creates. */
#include <stdio.h>
#include <time.h>

static double mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(void) {
    double t0 = mono_ms();
    FILE *f = fopen("/tmp/.chaos-time.conf", "w");         /* the "jump" */
    fputs("clock_gettime/monotonic:OFFSET:-5000\n", f);
    fclose(f);
    double t1 = mono_ms();
    double dt = t1 - t0;
    printf("t0=%.1f  t1=%.1f  elapsed=%.1f ms\n", t0, t1, dt);
    if (dt < 0) {
        printf("BROKEN: monotonic went BACKWARD — every timeout/backoff/rate-limiter is now wrong\n");
        return 0;
    }
    printf("elapsed non-negative (increase the jump if the host coalesced the reads)\n");
    return 0;
}
