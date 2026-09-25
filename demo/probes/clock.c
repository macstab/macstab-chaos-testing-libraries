/* time use-case 1 — read CLOCK_REALTIME. With clock_gettime/realtime:OFFSET:ms the
 * returned time is shifted; run once without the lib and once with it to see the skew. */
#include <stdio.h>
#include <time.h>
int main(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    printf("%ld\n", (long)t.tv_sec);
    return 0;
}
