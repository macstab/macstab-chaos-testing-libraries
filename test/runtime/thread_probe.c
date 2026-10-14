/**
 * @file thread_probe.c
 * @brief Runtime probe: threads work under libchaos-process, and a rule still faults them.
 *
 * On glibc before 2.34 `pthread_create` lives in libpthread, not libc. A program
 * that does not link libpthread never loads it, so the library cannot resolve the
 * symbol at startup; a program that does link it must still be faulted.
 *
 * Usage: thread_probe [expected-errno]   (0 or omitted: the thread must start)
 * Exit code 0 when pthread_create returned the expected value, 1 otherwise.
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
