/**
 * @file bench_memory.c
 * @brief Per-call overhead of the libchaos-memory wrappers for madvise, mprotect and munmap.
 *
 * @details
 * Each hooked call has `_passthrough`, `_match_no_fire` and `_errno` variants sharing
 * one iteration body. `run-bench.sh` runs each without LD_PRELOAD (baseline) and with
 * LD_PRELOAD=libchaos-memory.so plus `benchmark/scenarios/memory-<fn>-*.conf` copied to
 * the rule file `/tmp/.chaos-memory.conf` (treatment).
 *
 * The madvise and mprotect kernels work on one page of a 1 MiB private anonymous
 * mapping created and pre-faulted in setup, so the iteration never pays for creating
 * a VMA. mmap itself is not timed in isolation: its cost depends on the address-space
 * layout and, for small sizes, on the allocator's mmap threshold, which differs between
 * glibc and musl.
 *
 * Scenario status at this revision: every memory scenario writes the probability as
 * `ERRNO:<name>,<p>`, but libchaos-memory expects `ERRNO:<name>@<p>`. The rule is
 * rejected, so `_match_no_fire` and `_errno` measure the passthrough path (the 1.0.1
 * matrix shows all three arms within noise of each other). See the scenario files.
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
    /* Fault in every page now, so the first measured iterations do not pay for page
     * faults the later ones skip; both arms then start from the same resident state. */
    memset(s->mapping, 0x5A, s->mapping_size);
}

static void bench_memory_iter_madvise(void *user_state)
{
    bench_memory_state_t *s = (bench_memory_state_t *)user_state;
    /* One page only: the cost of MADV_DONTNEED grows with the number of resident pages
     * it drops, and dropping the whole 1 MiB would swamp the wrapper. */
    s->rc = madvise(s->mapping, BENCH_MEMORY_HINT_BYTES, MADV_DONTNEED);
    CHAOS_BENCH_DO_NOT_OPTIMIZE(s->rc);
    /* Refault the page so the next MADV_DONTNEED has a resident page to drop. The
     * touch (one write fault that allocates a zeroed page) is part of every timed
     * iteration. If an ERRNO rule fired, the page would stay resident and this write
     * would not fault. */
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
 * Two mprotect calls per iteration on the first page: read-only, then back to
 * read-write, so every iteration starts from the same protection. Both calls are
 * wrapped, so the delta covers two wrappers. Changing the protection of one page in
 * a larger VMA splits and remerges the VMA, which is part of the baseline cost.
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
 * Map one anonymous page and unmap it again. libchaos-memory wraps both calls; the
 * scenario has a munmap rule only, so mmap contributes a no-match pass through its
 * wrapper to every arm. If a munmap ERRNO rule fired, every iteration would leak one
 * page of address space (200000 iterations: about 780 MiB of virtual memory, never
 * touched).
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
