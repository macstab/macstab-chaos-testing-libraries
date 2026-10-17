/**
 * @file test_chaos_init_memory.c
 * @brief Proves chaos-init maps memory system calls onto libchaos-memory rules and
 *        turns them into the right SECCOMP-mode verdict.
 *
 * @details Unit under test: `chaos_init_memory_decide()` in `src/init/chaos_init_memory.c`,
 * compiled in by `#include` together with the libchaos-memory rule core it embeds,
 * `chaos_init_proc.c` (/proc lookups) and `chaos_init_tracee.c` (per-process hit slots).
 *
 * Isolation: no supervisor, no seccomp filter and no tracee. Each call is a
 * `chaos_init_call_t` filled the way a seccomp notification fills it, with this test
 * process as the caller (`tid = getpid()`), so the real /proc lookup resolves it to a
 * live process. Memory rules match on arguments only (operation, mmap flags for
 * anon/file, `args[1]` as the length for `@size`), so no tracee memory has to be read.
 * The rule file is replaced by an atomic rename(2), and
 * `g_chaos_memory_check_interval_ns = 0` makes every decision re-check it.
 *
 * Properties proven:
 * - mmap, munmap, mprotect and madvise reach their operation; mmap is anon or file by
 *   MAP_ANONYMOUS; any other system call returns 0 (not memory's);
 * - LATENCY gives DELAY, ERRNO gives FAIL, both on one call give DELAY carrying the errno;
 * - `@size` compares against the call's length;
 * - a caller whose process cannot be resolved is not counted and its call passes;
 * - hit counts follow the rule text across reloads, also when the config core hands back
 *   the same snapshot buffer after two reloads (the mtime still marks a new load);
 * - a hit writes the caller's hits file (`/tmp/.chaos-memory.hits.<pid>`).
 */

#include "../../src/init/chaos_init_memory.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_tracee.c"

#include <assert.h>
#include <sys/mman.h>

/**
 * @brief Decides a memory call made by this process and asserts memory owns it.
 *
 * @details The verdict is pre-set to FAIL so that a PASS result proves the decision
 * wrote the verdict rather than leaving stale state.
 */
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

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
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

    /* mmap by kind and length: 100 bytes matches nothing, 4096 trips `@size>4095` only,
     * 1 MiB also trips the LATENCY rule (DELAY that then fails), a file mapping (no
     * MAP_ANONYMOUS) only the file LATENCY rule. */
    assert(decide(__NR_mmap, 100U, anon).action == CHAOS_INIT_PASS);
    verdict = decide(__NR_mmap, 4096U, anon);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == ENOMEM);
    verdict = decide(__NR_mmap, 1U << 20, anon);
    assert(
        verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 20U && verdict.error == ENOMEM
    );
    verdict = decide(__NR_mmap, 4096U, MAP_PRIVATE);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 7U && verdict.error == 0);

    /* munmap, mprotect and madvise each reach their own operation's rule. */
    verdict = decide(__NR_munmap, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EINVAL);
    verdict = decide(__NR_mprotect, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 5U);
    verdict = decide(__NR_madvise, 4096U, 0U);
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EAGAIN);

    /* Fail-open for a vanished caller: tid 999999999 has no /proc entry, so no hit slot
     * exists; the matching munmap rule must not fire and the verdict resets to PASS. */
    memset(&other, 0, sizeof(other));
    other.tid = 999999999;
    other.nr = __NR_munmap;
    other.args[1] = 4096U;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_memory_decide(&other, &verdict) == 1 && verdict.action == CHAOS_INIT_PASS);

    /* Two reloads between calls: the second reload reuses the snapshot buffer of the
     * first, so state pointer equality alone would miss it. The new `@first=1` text
     * must start from zero hits, not inherit the exhausted count of the text it
     * replaced at the same index. */
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
