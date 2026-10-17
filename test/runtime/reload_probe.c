/**
 * @file reload_probe.c
 * @brief Proves that an `@first=1` budget survives reloads of the rule file under concurrent
 *        firing: a reload that keeps a rule must not give it a fresh budget.
 *
 * @details
 * Six threads open `/tmp/reload-<round>/file` in a tight loop (the path does not exist, so
 * ENOENT is normal and EIO can only come from the rule). Per round the main thread installs
 * `/tmp/reload-<round>:open:EIO:1.0 @first=1`, waits <pause_us>, then installs a second file
 * that keeps the same rule and adds an unrelated one, and waits again: two reloads per round
 * while the threads are mid-fire. A round's rule may fail at most one open; a second EIO means
 * the reload reset or duplicated the @first budget (or two threads both claimed it).
 * Rounds with no EIO at all are not counted as failures.
 *
 * Rule files are replaced atomically (write `.new`, rename), as the framework's writers do.
 *
 * Usage: reload_probe <rounds> <pause_us>, rounds 1-10000, under LD_PRELOAD of libchaos-io;
 * run by test_reload.sh with 1000 rounds and pauses of 0 and 200 us.
 *
 * Exit: 0 when no round failed more than one open; 1 otherwise (the first 3 broken rounds and
 * the total are printed); 2 on bad usage or a setup failure.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 6
#define MAX_ROUNDS 10000

static volatile int g_stop = 0;
static volatile int g_round = 0;
static volatile long g_failed[MAX_ROUNDS];

/** @brief Worker: opens the current round's path forever, counting EIO per round. */
static void *opener(void *unused)
{
    char path[64];

    (void)unused;
    while (!g_stop)
    {
        const int round = g_round;
        int fd;

        (void)snprintf(path, sizeof(path), "/tmp/reload-%d/file", round);
        fd = open(path, O_RDONLY);
        if (fd >= 0)
        {
            (void)close(fd);
        }
        else if (errno == EIO)
        {
            (void)__sync_fetch_and_add(&g_failed[round], 1L);
        }
    }
    return NULL;
}

/** @brief Replaces `/tmp/.chaos-io.conf` atomically via `.new` + rename(); exits 2 on error. */
static void write_rules(const char *rules)
{
    const int fd = open("/tmp/.chaos-io.conf.new", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    if (fd < 0 || write(fd, rules, strlen(rules)) != (ssize_t)strlen(rules) || close(fd) != 0 ||
        rename("/tmp/.chaos-io.conf.new", "/tmp/.chaos-io.conf") != 0)
    {
        perror("rules");
        exit(2);
    }
}

int main(int argc, char **argv)
{
    pthread_t threads[THREADS];
    char rules[256];
    int rounds;
    int pause_us;
    int round;
    int index;
    int broken = 0;

    if (argc != 3 || (rounds = atoi(argv[1])) <= 0 || rounds > MAX_ROUNDS)
    {
        (void)fprintf(stderr, "usage: %s <rounds> <pause_us>\n", argv[0]);
        return 2;
    }
    pause_us = atoi(argv[2]);
    for (index = 0; index < THREADS; ++index)
    {
        if (pthread_create(&threads[index], NULL, opener, NULL) != 0)
        {
            return 2;
        }
    }
    for (round = 0; round < rounds; ++round)
    {
        g_round = round;
        (void)snprintf(rules, sizeof(rules), "/tmp/reload-%d:open:EIO:1.0 @first=1\n", round);
        write_rules(rules);
        (void)usleep((useconds_t)pause_us);
        (void)snprintf(
            rules,
            sizeof(rules),
            "/tmp/reload-%d:open:EIO:1.0 @first=1\n/tmp/reload-none:open:EIO:1.0\n",
            round
        );
        write_rules(rules);
        (void)usleep((useconds_t)pause_us);
    }
    g_stop = 1;
    for (index = 0; index < THREADS; ++index)
    {
        (void)pthread_join(threads[index], NULL);
    }
    for (round = 0; round < rounds; ++round)
    {
        if (g_failed[round] > 1L)
        {
            if (++broken <= 3)
            {
                (void)printf("round %d: @first=1 failed %ld opens\n", round, g_failed[round]);
            }
        }
    }
    (void)printf("%d of %d rounds broke @first=1\n", broken, rounds);
    return broken == 0 ? 0 : 1;
}
