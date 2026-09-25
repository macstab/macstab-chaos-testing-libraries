/* process use-case 1 — create threads in a loop. With pthread_create:FAIL_AFTER:EAGAIN,N
 * the first N succeed, then every one returns EAGAIN — deterministic thread exhaustion. */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
static void *noop(void *_) { (void)_; return NULL; }
int main(void) {
    for (int i = 1; i <= 16; i++) {
        pthread_t t;
        int r = pthread_create(&t, NULL, noop, NULL);   /* returns the errno directly */
        if (r) { printf("thread %2d: pthread_create FAILED (%s)\n", i, strerror(r)); break; }
        printf("thread %2d: ok\n", i);
        pthread_join(t, NULL);
    }
    return 0;
}
