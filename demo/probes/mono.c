/* Demo time2: CLOCK_MONOTONIC going backwards. The rule file starts with
 * `clock_gettime/monotonic:OFFSET:0`; between two reads the probe itself rewrites it to
 * OFFSET:-5000, so the second read is ~5000 ms earlier and the computed elapsed time is
 * negative: the failure every timeout, backoff and rate limiter built on "monotonic never
 * decreases" mishandles. The kernel clock never goes backwards; only the values returned to
 * this process do. libchaos-time looks at the rule file at most once per 1 ms after its
 * first load; if the rewrite and the second read fall inside that window, the old rule
 * still applies and the probe takes the non-negative branch (the printed hint about the
 * jump size does not apply to that case; rerunning does). */
#include <stdio.h>
#include <time.h>

static double mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(void) {
    double t0 = mono_ms();
    FILE *f = fopen("/tmp/.chaos-time.conf", "w");         /* the backward step */
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
