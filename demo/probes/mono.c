/* Demo time2: CLOCK_MONOTONIC going backwards. The rule file starts with
 * `clock_gettime/monotonic:OFFSET:0`; between two reads the probe itself rewrites it to
 * OFFSET:-5000, so the second read is ~5000 ms earlier and the computed elapsed time is
 * negative: the failure every timeout, backoff and rate limiter built on "monotonic never
 * decreases" mishandles. The kernel clock never goes backwards; only the values returned to
 * this process do. libchaos-time looks at the rule file at most once per 1 ms after its
 * first load, and on a host where both reads fall inside that window the old rule still
 * applies. That looked like a flaky demo and was really a missing wait, so the probe sleeps
 * past the interval before reading again. The sleep is real: the rule names
 * clock_gettime/monotonic, so no nanosleep rule matches it. */
#include <stdio.h>
#include <time.h>

static double mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

int main(void) {
    struct timespec settle = {0, 5000000};                 /* 5 ms > the 1 ms look interval */
    double t0 = mono_ms();
    FILE *f = fopen("/tmp/.chaos-time.conf", "w");         /* the backward step */
    fputs("clock_gettime/monotonic:OFFSET:-5000\n", f);
    fclose(f);
    nanosleep(&settle, NULL);
    double t1 = mono_ms();
    double dt = t1 - t0;
    printf("t0=%.1f  t1=%.1f  elapsed=%.1f ms\n", t0, t1, dt);
    if (dt < 0) {
        printf("BROKEN: monotonic went BACKWARD — every timeout/backoff/rate-limiter is now wrong\n");
        return 0;
    }
    printf("elapsed non-negative: the rule file was not re-read\n");
    return 0;
}
