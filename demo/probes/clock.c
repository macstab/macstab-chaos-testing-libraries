/* Demo time1: prints CLOCK_REALTIME in whole seconds. docker-compose runs it once bare and
 * once under libchaos-time with `clock_gettime/realtime:OFFSET:3600000` (ms) and prints the
 * difference, expected ~3600 s: the wall-clock skew that makes a fresh token look expired. */
#include <stdio.h>
#include <time.h>
int main(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    printf("%ld\n", (long)t.tv_sec);
    return 0;
}
