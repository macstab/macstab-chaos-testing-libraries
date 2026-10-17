/* Demo proc1: creates and joins up to 16 threads one at a time and stops at the first
 * failure. Under libchaos-process with `pthread_create:FAIL_AFTER:EAGAIN,8` the first 8
 * calls succeed and every later one returns EAGAIN: deterministic thread exhaustion
 * without touching RLIMIT_NPROC or kernel limits. */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
static void *noop(void *_) { (void)_; return NULL; }
int main(void) {
    for (int i = 1; i <= 16; i++) {
        pthread_t t;
        int r = pthread_create(&t, NULL, noop, NULL);   /* returns the error number; errno unused */
        if (r) { printf("thread %2d: pthread_create FAILED (%s)\n", i, strerror(r)); break; }
        printf("thread %2d: ok\n", i);
        pthread_join(t, NULL);
    }
    return 0;
}
