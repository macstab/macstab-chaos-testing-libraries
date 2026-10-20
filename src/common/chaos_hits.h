/**
 * @file chaos_hits.h
 * @brief Per-rule hit counters, the hits file (`/tmp/.chaos-<lib>.hits.<n>`) and the
 *        seqlock that guards lock-free reads of a rule snapshot.
 *
 * @details
 * A rule that parses but never fires is the second silent failure next to a rejected
 * rule file (chaos_status.h): its selector does not match what the program actually
 * does. Every library therefore counts the hits of each rule, and each process writes
 * its counts to a hits file of its own:
 *
 * @code
 * 3<TAB>tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 # net
 * 0<TAB>tcp4://127.0.0.1:6379:recv:LATENCY:200 # redis
 * @endcode
 *
 * One line per rule of the active rule file: the decimal count, a tab, and the rule as
 * written (control characters replaced, at most CHAOS_STATUS_TEXT_MAX bytes). The file
 * suffix `<n>` is normally the pid (chaos_hits_file_number_for() explains when it is
 * not). A reader sums all `/tmp/.chaos-<lib>.hits.*` files to get totals over processes.
 *
 * @par Slot pool and reload
 * The counters live in a pool of slots each library keeps beside its two rule snapshots.
 * chaos_hits_assign() gives a rule that survives a reload (same text) the very same
 * slot, so its count, `@first` claims and REGRESS state continue, and a hit through a
 * rule copy taken before the reload is neither lost nor counted twice. Each rule copy a
 * wrapper holds carries its slot pointer and the slot generation. When a rule leaves
 * the file, chaos_hits_release() bumps its slot's generation; a copy that outlived its
 * rule (held across a blocking call) then neither fires nor counts against the rule that
 * reuses the slot.
 *
 * @par Write cadence (implemented by each library's report hook)
 * The file is rewritten on each of a process's first CHAOS_HITS_EAGER (64) hits, then at
 * most every CHAOS_HITS_INTERVAL_MS (100 ms) on a hit or rule-file check, and once more at
 * normal exit. A hit that is not due makes no system call.
 *
 * @par fork, vfork, exec
 * - fork: the child starts from zero (chaos_hits_pool_after_fork() from the atfork
 *   handler) so the parent's hits are not reported twice.
 * - vfork: the child shares the parent's memory and runs no atfork handler; its hits land
 *   in the parent's slots, and only the process whose pid owns the counts writes them.
 * - execve: same pid, fresh image; chaos_hits_file_number_for() picks a new suffix so the
 *   old image's file survives.
 *
 * File I/O uses the raw system calls of chaos_status.h, so libchaos-io rules cannot fail
 * or delay a report, and errno is preserved.
 */

#ifndef CHAOS_HITS_H
#define CHAOS_HITS_H

#include "chaos_clock.h"
#include "chaos_status.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @brief Assigns @p value to @p lvalue only when it differs.
 *
 * @details For atfork child handlers. After fork() every page of the parent is shared
 * copy-on-write, and the first store to a page costs the child a page fault and a page
 * copy (several microseconds each). A child that inherited nothing to reset then touches
 * no page at all, since reads of shared pages are free. @p value is evaluated twice.
 */
#define CHAOS_STORE_IF_CHANGED(lvalue, value)                                                      \
    do                                                                                             \
    {                                                                                              \
        if ((lvalue) != (value))                                                                   \
        {                                                                                          \
            (lvalue) = (value);                                                                    \
        }                                                                                          \
    } while (0)

/** @brief Number of first hits per process that each rewrite the hits file at once. */
#define CHAOS_HITS_EAGER 64U

/** @brief Minimum time in ms between two rewrites of a process's hits file after the eager hits. */
#define CHAOS_HITS_INTERVAL_MS 100U

/** @brief Upper bound of one hits-file line: 20-digit count, tab, rule text, newline. */
#define CHAOS_HITS_LINE_MAX (20U + 1U + CHAOS_STATUS_TEXT_MAX + 1U)

/**
 * @brief Per-rule state that must outlive a reload: hit count, `@first` claims, effect
 *        state, and the generation that tells a live rule copy from a stale one.
 */
typedef struct chaos_hit_slot chaos_hit_slot_t;

struct chaos_hit_slot
{
    /** Hits of this rule in this process; incremented atomically, reset in a forked child. */
    volatile uint64_t count;
    /**
     * Hits claimed under `@first=N` (chaos_policy_fire()): claim count in the low 32 bits,
     * low 32 bits of the owning generation in the high 32 bits. One word, so one CAS
     * checks the allowance and the ownership together.
     */
    volatile uint64_t claimed;
    /**
     * Effect state that must survive reloads. libchaos-time REGRESS: 0 idle, 1 armed,
     * 3 one thread is deciding the jump, 2 jumped.
     */
    volatile uint64_t state;
    /** Library hook called after each counted hit to schedule a hits-file write; may be NULL. */
    void (*report)(chaos_hit_slot_t *slot);
    /**
     * Incremented atomically whenever the slot's rule leaves the rule file
     * (chaos_hits_release()) or the pool is reset; outdates every rule copy taken before.
     */
    volatile uint64_t generation;
    /** Non-zero while a rule of the active or next snapshot holds the slot; reload owner only. */
    unsigned char used;
};

/**
 * @name Snapshot sequence (a seqlock)
 *
 * Readers copy a rule out of the active snapshot without a lock. The libraries keep two
 * snapshots and rewrite the inactive one on reload, so two reloads after a reader started
 * its copy the same storage is cleared and refilled. A reader preempted mid-copy could get
 * half of one rule and half of another, or a rule whose slot was already cleared (a NULL
 * slot fires without `@first`). The sequence is odd from the moment a reload starts
 * rewriting a snapshot until it is published; a reader samples it before the copy,
 * re-checks after, and discards a copy that saw an odd value or a change.
 *
 * Full barriers (`__sync_synchronize()`) order the sequence accesses against the data
 * copy on both sides. Writes are by the single reload owner only, so the increments need
 * not be atomic; both writer calls are idempotent so an aborted reload can call them again.
 * @{
 */

/** @brief Reader: samples the sequence before copying; pass the result to read_valid. */
static inline uint64_t chaos_snapshot_read_begin(const volatile uint64_t *sequence)
{
    const uint64_t begin = *sequence;

    __sync_synchronize();
    return begin;
}

/** @brief Reader: non-zero when the copy made since @p begin is consistent and usable. */
static inline int chaos_snapshot_read_valid(const volatile uint64_t *sequence, uint64_t begin)
{
    __sync_synchronize();
    return (begin & 1U) == 0U && *sequence == begin;
}

/** @brief Writer: marks the snapshot as being rewritten (makes the sequence odd; idempotent). */
static inline void chaos_snapshot_write_begin(volatile uint64_t *sequence)
{
    if ((*sequence & 1U) == 0U)
    {
        ++*sequence;
    }
    __sync_synchronize();
}

/** @brief Writer: marks the snapshot complete (makes the sequence even; idempotent). */
static inline void chaos_snapshot_write_end(volatile uint64_t *sequence)
{
    __sync_synchronize();
    if ((*sequence & 1U) != 0U)
    {
        ++*sequence;
    }
}

/** @} */

/** @brief Claim word with zero claims, tagged with @p generation (chaos_hit_slot::claimed). */
static inline uint64_t chaos_hit_claims_none(uint64_t generation)
{
    return (uint64_t)(uint32_t)generation << 32;
}

/** @brief Claim count held in claim word @p claimed. */
static inline uint64_t chaos_hit_claims(uint64_t claimed)
{
    return claimed & UINT64_C(0xffffffff);
}

/**
 * @brief Non-zero when @p slot still belongs to a rule copy that captured @p generation;
 *        always true for a NULL slot.
 */
static inline int chaos_hit_slot_current(const chaos_hit_slot_t *slot, uint64_t generation)
{
    return slot == NULL || slot->generation == generation;
}

/**
 * @brief Assigns a slot from @p pool to each of the @p next_count rules of the snapshot
 *        being built.
 *
 * @details A rule whose text equals a rule of the active snapshot gets that rule's slot
 * object, so count, `@first` claims and REGRESS state carry over without copying and
 * hits through pre-reload rule copies still land. Any other rule gets the next unused
 * slot, cleared, with its claim word re-tagged to the slot's current generation. Rules
 * with identical text share one slot, and therefore one count and one `@first` allowance.
 *
 * The pool holds twice a library's rule limit, one snapshot's worth for the active and
 * one for the next; a rule left without a slot (impossible at that size) gets NULL and
 * counts nothing. Cost: O(next_count * active_count) string compares, on reload only.
 *
 * Caller: the reload owner only; slot `used` flags are not synchronised.
 *
 * @param pool          Slot pool of the library.
 * @param pool_size     Number of slots in @p pool.
 * @param active        Slots of the active snapshot, @p active_count entries (NULL allowed).
 * @param active_texts  Rule texts of the active snapshot.
 * @param active_count  Rules in the active snapshot.
 * @param next          Receives one slot pointer per new rule.
 * @param next_texts    Rule texts of the new snapshot.
 * @param next_count    Rules in the new snapshot.
 * @param report        Report hook stored in every assigned slot.
 */
static inline void chaos_hits_assign(
    chaos_hit_slot_t *pool,
    size_t pool_size,
    chaos_hit_slot_t *const *active,
    const char (*active_texts)[CHAOS_STATUS_TEXT_MAX + 1U],
    size_t active_count,
    chaos_hit_slot_t **next,
    const char (*next_texts)[CHAOS_STATUS_TEXT_MAX + 1U],
    size_t next_count,
    void (*report)(chaos_hit_slot_t *slot)
)
{
    size_t free_slot = 0U;
    size_t index;

    for (index = 0U; index < next_count; ++index)
    {
        size_t previous;

        next[index] = NULL;
        for (previous = 0U; previous < active_count; ++previous)
        {
            if (active[previous] != NULL && strcmp(active_texts[previous], next_texts[index]) == 0)
            {
                next[index] = active[previous];
                break;
            }
        }
        if (next[index] == NULL)
        {
            while (free_slot < pool_size && pool[free_slot].used)
            {
                ++free_slot;
            }
            if (free_slot == pool_size)
            {
                continue;
            }
            next[index] = &pool[free_slot];
            next[index]->count = 0U;
            next[index]->claimed = chaos_hit_claims_none(next[index]->generation);
            next[index]->state = 0U;
        }
        next[index]->used = 1U;
        next[index]->report = report;
    }
}

/**
 * @brief After the snapshot holding @p kept is published, frees every other used slot of
 *        @p pool and bumps its generation.
 *
 * @details A copy of a removed rule may still be held by a blocking call; once the
 * generation moves on, that copy neither fires nor counts, including after the slot is
 * reassigned. The generation is bumped atomically because readers compare it without a
 * lock. Caller: the reload owner only.
 */
static inline void chaos_hits_release(
    chaos_hit_slot_t *pool, size_t pool_size, chaos_hit_slot_t *const *kept, size_t kept_count
)
{
    size_t index;

    for (index = 0U; index < pool_size; ++index)
    {
        size_t held;

        if (!pool[index].used)
        {
            continue;
        }
        for (held = 0U; held < kept_count && kept[held] != &pool[index]; ++held)
        {
        }
        if (held == kept_count)
        {
            pool[index].used = 0U;
            (void)__sync_fetch_and_add(&pool[index].generation, 1U);
        }
    }
}

/**
 * @brief Frees and clears every slot of @p pool and outdates every rule copy holding one;
 *        called when a library (re)initialises its rule cache to the empty state.
 */
static inline void chaos_hits_pool_reset(chaos_hit_slot_t *pool, size_t pool_size)
{
    size_t index;

    for (index = 0U; index < pool_size; ++index)
    {
        pool[index].used = 0U;
        pool[index].count = 0U;
        pool[index].state = 0U;
        (void)__sync_fetch_and_add(&pool[index].generation, 1U);
        pool[index].claimed = chaos_hit_claims_none(pool[index].generation);
    }
}

/**
 * @brief Atfork child handler: zeroes inherited counts and `@first` claims so the child
 *        reports only its own hits; resets REGRESS state 3 (decision in progress) to 1.
 *
 * @details Only the forking thread survives in the child, so a REGRESS decision another
 * parent thread had claimed (state 3) would never complete; it returns to armed. A fork
 * in the middle of a reload leaves the slots of the half-built snapshot marked used with
 * no reload left to release them; every slot outside the @p active snapshot is released
 * here. REGRESS state 2 (already jumped) is inherited unchanged.
 */
static inline void chaos_hits_pool_after_fork(
    chaos_hit_slot_t *pool, size_t pool_size, chaos_hit_slot_t *const *active, size_t active_count
)
{
    size_t index;

    chaos_hits_release(pool, pool_size, active, active_count);
    /* Only slots that changed are written: an untouched pool costs the child no page. */
    for (index = 0U; index < pool_size; ++index)
    {
        CHAOS_STORE_IF_CHANGED(pool[index].count, 0U);
        CHAOS_STORE_IF_CHANGED(pool[index].claimed, chaos_hit_claims_none(pool[index].generation));
        if (pool[index].state == 3U)
        {
            pool[index].state = 1U;
        }
    }
}

/**
 * @brief Counts one hit on @p slot (atomic add) and calls the slot's report hook.
 *
 * @param slot  The rule's slot; NULL for a rule copy outside a snapshot (unit tests),
 *              which is not counted.
 */
static inline void chaos_hit_record(chaos_hit_slot_t *slot)
{
    if (slot == NULL)
    {
        return;
    }
    (void)__sync_fetch_and_add(&slot->count, 1U);
    if (slot->report != NULL)
    {
        slot->report(slot);
    }
}

/**
 * @brief CLOCK_MONOTONIC in ms, read without libchaos-time; 0 when no clock is readable.
 *
 * @details Uses the vDSO (no system call per hit) and falls back to a raw
 * `clock_gettime` system call where no vDSO clock exists.
 */
static inline uint64_t chaos_hits_now_ms(void)
{
    struct timespec now;
    const uint64_t vdso_ns = chaos_clock_now_ns();

    if (vdso_ns != 0U)
    {
        return vdso_ns / UINT64_C(1000000);
    }
    if (CHAOS_CLOCK_RAW_GETTIME(CLOCK_MONOTONIC, &now) != 0)
    {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

/**
 * @brief Chooses the hits-file suffix for the image running as @p pid: @p pid itself, or
 *        `pid * 10^9 + salt` when `<prefix>.<pid>` already exists.
 *
 * @details An execve keeps the pid but loads the library afresh, and the replaced image
 * ran no destructor: its file holds the hits counted before the exec, and reusing the
 * name would wipe them. The same applies to a file left by a dead process with a recycled
 * pid. The alternative suffix appends nine digits from the monotonic clock (plus the
 * attempt number) to the pid; it exceeds pid_max (at most 2^22) and so cannot collide with
 * a plain pid suffix. Up to 8 candidates are probed; the last one is returned even if it
 * exists, and chaos_hits_write_for() resolves a remaining clash. A path longer than 127
 * bytes stops probing.
 *
 * Callers: each library at load and in a forked child; chaos-init for each tracee.
 * Assumes a 64-bit `long`. errno is preserved.
 *
 * @param prefix  File name without the suffix, e.g. `/tmp/.chaos-net.hits`.
 * @param pid     Process the file is for.
 * @return The suffix number.
 */
static inline long chaos_hits_file_number_for(const char *prefix, long pid)
{
    const int saved_errno = errno;
    const uint64_t salt = chaos_clock_now_ns();
    long number = pid;
    char path[128];
    unsigned attempt;

    for (attempt = 0U; attempt < 8U; ++attempt)
    {
        if ((size_t)snprintf(path, sizeof(path), "%s.%ld", prefix, number) >= sizeof(path) ||
            !CHAOS_STATUS_EXISTS(path))
        {
            break;
        }
        number = pid * 1000000000L + (long)((salt + attempt) % UINT64_C(1000000000));
    }
    errno = saved_errno;
    return number;
}

/** @brief chaos_hits_file_number_for() for the calling process. */
static inline long chaos_hits_file_number(const char *prefix)
{
    return chaos_hits_file_number_for(prefix, (long)getpid());
}

/**
 * @brief Writes (atomically replaces) the hits file of process @p pid.
 *
 * @details The suffix *@p number is checked for existence when chosen, but another
 * process may claim the same name before either writes: containers sharing /tmp each run
 * their application as pid 1. Until this process owns its file, a write therefore only
 * creates (chaos_status_publish() with `exclusive`) and never replaces; when the name is
 * taken, a new suffix is chosen and *@p number updated, up to 4 attempts. After the first
 * successful create *@p owned is set and later writes replace the file.
 *
 * Silently writes nothing when the formatted report does not fit @p buffer or the path
 * exceeds 127 bytes. errno is preserved (chaos_status_publish()). Not reentrant: callers
 * serialise writes per process.
 *
 * @param prefix       File name without the suffix, e.g. `/tmp/.chaos-net.hits`.
 * @param pid          Process whose hits these are.
 * @param number       In/out: suffix of its file; updated when the name is taken.
 * @param owned        In/out: non-zero once this process created the file; start at 0.
 * @param slots        Counters, @p count entries; a NULL entry is written as 0.
 * @param texts        Rule texts, @p count entries of CHAOS_STATUS_TEXT_MAX + 1 bytes.
 * @param count        Number of rules.
 * @param buffer       Scratch of at least @p count * CHAOS_HITS_LINE_MAX + 1 bytes.
 * @param buffer_size  Size of @p buffer in bytes.
 */
static inline void chaos_hits_write_for(
    const char *prefix,
    long pid,
    long *number,
    int *owned,
    chaos_hit_slot_t *const *slots,
    const char (*texts)[CHAOS_STATUS_TEXT_MAX + 1U],
    size_t count,
    char *buffer,
    size_t buffer_size
)
{
    char path[128];
    size_t length = 0U;
    size_t index;
    unsigned attempt;

    for (index = 0U; index < count; ++index)
    {
        const unsigned long long hits = slots[index] != NULL ? slots[index]->count : 0U;
        int rc;

        rc = snprintf(buffer + length, buffer_size - length, "%llu\t%s\n", hits, texts[index]);
        if (rc < 0 || (size_t)rc >= buffer_size - length)
        {
            return;
        }
        length += (size_t)rc;
    }
    for (attempt = 0U; attempt < 4U; ++attempt)
    {
        if ((size_t)snprintf(path, sizeof(path), "%s.%ld", prefix, *number) >= sizeof(path))
        {
            return;
        }
        if (*owned)
        {
            chaos_status_replace_file(path, buffer, length);
            return;
        }
        if (chaos_status_publish(path, buffer, length, 1) == 0)
        {
            *owned = 1;
            return;
        }
        *number = chaos_hits_file_number_for(prefix, pid);
    }
}

#endif
