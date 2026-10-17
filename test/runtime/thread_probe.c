/**
 * @file thread_probe.c
 * @brief Proves that pthread_create works under the preloaded libraries and that a
 *        libchaos-process rule still faults it when libpthread is linked.
 *
 * @details
 * On glibc before 2.34, pthread_create lives in libpthread, not libc. In a program that does
 * not link libpthread the symbol does not exist at start-up, so libchaos-process resolves it
 * lazily; this probe links -pthread, so the symbol appears and must be found and faulted.
 *
 * Usage: thread_probe [expected-errno]; 0 or omitted means the thread must start. Run by
 * test_baseline_glibc.sh with no argument and with 11 (EAGAIN on Linux) under
 * `pthread_create:ERRNO:EAGAIN`.
 *
 * Exit: 0 when pthread_create returned the expected value; 1 otherwise.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @brief Thread body: returns at once. */
static void *run(void *argument)
{
    return argument;
}

int main(int argc, char **argv)
{
    const int expected = argc > 1 ? atoi(argv[1]) : 0;
    pthread_t thread;
    int rc;

    rc = pthread_create(&thread, NULL, run, NULL);
    if (rc == 0)
    {
        (void)pthread_join(thread, NULL);
    }
    if (rc != expected)
    {
        (void)fprintf(stderr, "FAIL pthread_create: rc=%d, expected %d\n", rc, expected);
        return 1;
    }
    (void)printf("ok   pthread_create returned %d (%s)\n", rc, rc == 0 ? "started" : strerror(rc));
    return 0;
}
