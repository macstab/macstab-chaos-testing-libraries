/**
 * @file test_chaos_init_memory.c
 * @brief Unit tests for chaos-init's memory decisions.
 *
 * Subsystem under test: `src/init/chaos_init_memory.c` (with the memory rule core
 * it includes, `chaos_init_proc.c` and `chaos_init_tracee.c`).
 *
 * Coverage approach: calls are built as a notification carries them, with this
 * test process as the caller; everything memory matches on is in the arguments.
 *
 * Properties under test:
 * - each memory call reaches its operation, mmap with its anon/file kind;
 * - LATENCY delays, ERRNO fails, both together delay and then fail;
 * - `@size` sees the length; other system calls are not memory's.
 * - a process that ended after its call matched is not counted, and its call runs;
 * - counts follow rule texts, also across two reloads between the process's calls.
 */

#include "../../src/init/chaos_init_memory.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <assert.h>
#include <sys/mman.h>

static chaos_init_verdict_t decide(int nr, uint64_t length, uint64_t flags)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    memset(&verdict, 0, sizeof(verdict));
    call.tid = getpid();
    call.nr = nr;
    call.args[1] = length;
    call.args[3] = flags;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_memory_decide(&call, &verdict) == 1);
    return verdict;
}

static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-memory.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-memory.conf.new", "/tmp/.chaos-memory.conf") == 0);
}

int main(void)
{
    const uint64_t anon = MAP_PRIVATE | MAP_ANONYMOUS;
    chaos_init_verdict_t verdict;
    chaos_init_call_t other;
    char hits[64];

    (void)unlink("/tmp/.chaos-memory.conf");
    chaos_init_memory_start();
    g_chaos_memory_check_interval_ns = 0U;

    memset(&other, 0, sizeof(other));
    other.tid = getpid();
    other.nr = __NR_getpid;
    assert(chaos_init_memory_decide(&other, &verdict) == 0);
    assert(decide(__NR_mmap, 4096U, anon).action == CHAOS_INIT_PASS);

    write_rules("mmap/anon:ERRNO:ENOMEM @size>4095\n"
                "mmap/anon:LATENCY:20 @size>65536\n"
                "mmap/file:LATENCY:7\n"
                "munmap:ERRNO:EINVAL\n"
                "mprotect:LATENCY:5\n"
                "madvise:ERRNO:EAGAIN\n");

    /* mmap by kind, with the length for @size; LATENCY and ERRNO together. */
    assert(decide(__NR_mmap, 100U, anon).action == CHAOS_INIT_PASS);
    verdict = decide(__NR_mmap, 4096U, anon);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == ENOMEM);
    verdict = decide(__NR_mmap, 1U << 20, anon);
    assert(
        verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 20U && verdict.error == ENOMEM
    );
    verdict = decide(__NR_mmap, 4096U, MAP_PRIVATE);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 7U && verdict.error == 0);

    /* The other operations. */
    verdict = decide(__NR_munmap, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EINVAL);
    verdict = decide(__NR_mprotect, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 5U);
    verdict = decide(__NR_madvise, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EAGAIN);

    /* A process that ended after its call matched is not counted, and its call runs. */
    memset(&other, 0, sizeof(other));
    other.tid = 999999999;
    other.nr = __NR_munmap;
    other.args[1] = 4096U;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_memory_decide(&other, &verdict) == 1 && verdict.action == CHAOS_INIT_PASS);

    /* The rule file changes twice between two calls the process makes, the second
     * change bringing back the snapshot buffer of the first: the new text still
     * starts at zero instead of taking the count of the one it replaced. */
    write_rules("madvise:ERRNO:EAGAIN @first=1\n");
    verdict = decide(__NR_madvise, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EAGAIN);
    assert(decide(__NR_madvise, 4096U, 0U).action == CHAOS_INIT_PASS);
    write_rules("munmap:ERRNO:EINVAL\n");
    assert(decide(__NR_madvise, 4096U, 0U).action == CHAOS_INIT_PASS); /* loads, no match */
    write_rules("madvise:ERRNO:ENOMEM @first=1\n");
    verdict = decide(__NR_madvise, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == ENOMEM);
    assert(decide(__NR_madvise, 4096U, 0U).action == CHAOS_INIT_PASS);

    (void)snprintf(hits, sizeof(hits), "/tmp/.chaos-memory.hits.%ld", (long)getpid());
    assert(access(hits, F_OK) == 0);
    (void)unlink(hits);
    (void)unlink("/tmp/.chaos-memory.conf");
    return 0;
}
