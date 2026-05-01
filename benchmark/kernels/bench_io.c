/**
 * @file bench_io.c
 * @brief Stage 3 microbenchmarks for libchaos-io.
 *
 * @details
 * Three benchmarks exercise the libchaos-io hot paths:
 *
 *  1. `pread_passthrough` — `pread(fd, buf, 64, 0)` against an open
 *     tmpfile, with no rule installed.  Without LD_PRELOAD this is
 *     pure libc / kernel cost; with LD_PRELOAD this measures the chaos
 *     library's TLS guard + snapshot pointer load + rule scan + early
 *     return overhead.
 *  2. `pread_match_no_fire` — same call, with a probability=0 rule
 *     loaded so the selector match runs but the dice never trigger.
 *  3. `pread_errno` — same call, probability=1 ERRNO rule, exercising
 *     the full effect-dispatch path.
 *
 * Setup creates an anonymous tmpfile via `mkstemp`, fills the first 4 KiB
 * with deterministic bytes, and unlinks the path so the file disappears
 * on teardown.  Iter does one `pread` of 64 bytes from offset 0; the
 * choice of offset 0 means each call hits the page-cached first block,
 * so we measure the path-resolution + chaos overhead, not the
 * device.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BENCH_IO_PAYLOAD_BYTES 64
#define BENCH_IO_FILE_BYTES    4096

/**
 * @brief Per-benchmark state: open tmpfile + result buffer.
 *
 * @details The buffer is 64 bytes — enough to be representative but
 * small enough to fit in one cache line plus a bit, so the iter cost
 * is dominated by the syscall+chaos path, not the memcpy.
 */
typedef struct bench_io_state
{
    int     fd;
    char    buffer[BENCH_IO_PAYLOAD_BYTES];
    ssize_t rc;
} bench_io_state_t;

static void bench_io_setup(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    char path[] = "/tmp/chaos-bench-io.XXXXXX";
    char fill[BENCH_IO_FILE_BYTES];
    ssize_t written;

    s->fd = mkstemp(path);
    if (s->fd < 0)
    {
        perror("bench_io: mkstemp");
        abort();
    }
    /* Unlink immediately; the fd keeps the file alive. */
    (void)unlink(path);

    memset(fill, 0xA5, sizeof(fill));
    written = write(s->fd, fill, sizeof(fill));
    if (written != (ssize_t)sizeof(fill))
    {
        perror("bench_io: write");
        abort();
    }
}

static void bench_io_iter_pread(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    s->rc = pread(s->fd, s->buffer, sizeof(s->buffer), 0);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->buffer);
}

static void bench_io_teardown(void *user_state)
{
    bench_io_state_t *s = (bench_io_state_t *)user_state;
    if (s->fd >= 0)
    {
        (void)close(s->fd);
    }
}

CHAOS_BENCH("io", pread_passthrough,    bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)
CHAOS_BENCH("io", pread_match_no_fire,  bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)
CHAOS_BENCH("io", pread_errno,          bench_io_state_t,
            bench_io_setup, bench_io_iter_pread, bench_io_teardown)
