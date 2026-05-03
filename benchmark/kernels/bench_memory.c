/**
 * @file bench_memory.c
 * @brief Stage 3 microbenchmarks for libchaos-memory.
 *
 * @details
 * Three benchmarks against `madvise(addr, 4096, MADV_DONTNEED)` on a
 * pre-allocated 1 MiB private mapping.  We use `madvise` instead of
 * `mmap`/`munmap` for the iter call because:
 *  - mmap/munmap exercise the allocator's mmap-threshold path on
 *    glibc; on musl every malloc above ~28 KiB is already an mmap.
 *    Either way the *cost* is dominated by VMA list manipulation,
 *    which is measurable but variable.
 *  - madvise is a fixed-cost VMA hint; it lets the chaos overhead
 *    show through clearly.
 *
 * For mmap-path coverage, see Stage 4 (when we add the malloc-allocator
 * size sweep).
 *
 *  1. `madvise_passthrough`    — no rule loaded.
 *  2. `madvise_match_no_fire`  — probability=0 rule on `madvise`.
 *  3. `madvise_errno`          — probability=1 EINVAL injection.
 */

#include "chaos_bench.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define BENCH_MEMORY_REGION_BYTES (1U << 20) /* 1 MiB */
#define BENCH_MEMORY_HINT_BYTES   4096U

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
#endif

typedef struct bench_memory_state
{
    void   *mapping;
    size_t  mapping_size;
    int     rc;
} bench_memory_state_t;

static void bench_memory_setup(void *user_state)
{
    bench_memory_state_t *s = (bench_memory_state_t *)user_state;
    s->mapping_size = BENCH_MEMORY_REGION_BYTES;
    s->mapping = mmap(NULL, s->mapping_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (s->mapping == MAP_FAILED)
    {
        perror("bench_memory: mmap");
        abort();
    }
    /* Pre-touch every page so subsequent madvise calls do not race a
     * fault-in path.  The chaos library's overhead is the same either
     * way, but baseline-vs-treatment must compare equal pre-conditions. */
    memset(s->mapping, 0x5A, s->mapping_size);
}

static void bench_memory_iter_madvise(void *user_state)
{
    bench_memory_state_t *s = (bench_memory_state_t *)user_state;
    /* Hint a single page near the start; do not dontneed the whole
     * region (would force a fault-in chain that dominates the next
     * iteration). */
    s->rc = madvise(s->mapping, BENCH_MEMORY_HINT_BYTES, MADV_DONTNEED);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    /* Touch the page so the dontneed actually frees the backing on
     * subsequent calls. */
    *((volatile char *)s->mapping) = 0x5A;
}

static void bench_memory_teardown(void *user_state)
{
    bench_memory_state_t *s = (bench_memory_state_t *)user_state;
    if (s->mapping != NULL && s->mapping != MAP_FAILED)
    {
        (void)munmap(s->mapping, s->mapping_size);
    }
}

CHAOS_BENCH("memory", madvise_passthrough,    bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_madvise, bench_memory_teardown)
CHAOS_BENCH("memory", madvise_match_no_fire,  bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_madvise, bench_memory_teardown)
CHAOS_BENCH("memory", madvise_errno,          bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_madvise, bench_memory_teardown)

/* --------------------------------------------------------------- mprotect ---
 * Toggle PROT_READ on/off on a single page each iter.  Two calls per iter
 * to leave the page in the original state (PROT_READ|PROT_WRITE), so
 * iters don't drift.
 */
static void bench_memory_iter_mprotect(void *user_state)
{
    bench_memory_state_t *s = (bench_memory_state_t *)user_state;
    int rc = mprotect(s->mapping, BENCH_MEMORY_HINT_BYTES, PROT_READ);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
    rc = mprotect(s->mapping, BENCH_MEMORY_HINT_BYTES, PROT_READ | PROT_WRITE);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
}

CHAOS_BENCH("memory", mprotect_passthrough,    bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_mprotect, bench_memory_teardown)
CHAOS_BENCH("memory", mprotect_match_no_fire,  bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_mprotect, bench_memory_teardown)
CHAOS_BENCH("memory", mprotect_errno,          bench_memory_state_t,
            bench_memory_setup, bench_memory_iter_mprotect, bench_memory_teardown)

/* ----------------------------------------------------------------- munmap ---
 * Per-iter `mmap` 1 page anonymous + immediate `munmap`.  Pairs the two
 * but only `munmap` is hooked by libchaos-memory; the mmap is overhead.
 */
typedef struct bench_memory_munmap_state
{
    int unused;
} bench_memory_munmap_state_t;

static void bench_memory_iter_munmap(void *user_state)
{
    (void)user_state;
    void *p = mmap(NULL, BENCH_MEMORY_HINT_BYTES,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        int rc = munmap(p, BENCH_MEMORY_HINT_BYTES);
        CHAOS_BENCH_DO_NOT_OPTIMIZE(rc);
    }
    CHAOS_BENCH_DO_NOT_OPTIMIZE(p);
}

CHAOS_BENCH("memory", munmap_passthrough,    bench_memory_munmap_state_t,
            NULL, bench_memory_iter_munmap, NULL)
CHAOS_BENCH("memory", munmap_match_no_fire,  bench_memory_munmap_state_t,
            NULL, bench_memory_iter_munmap, NULL)
CHAOS_BENCH("memory", munmap_errno,          bench_memory_munmap_state_t,
            NULL, bench_memory_iter_munmap, NULL)
