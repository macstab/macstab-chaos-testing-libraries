/**
 * @file chaos_hits.h
 * @brief Per-rule hit counters, reported in `/tmp/.chaos-<lib>.hits.<number>`.
 *
 * @details
 * A rule that parses but never fires is the other silent failure next to a
 * rejected rule file (see chaos_status.h): the selector does not match what the
 * program really does. Every library therefore counts, per rule, how often the
 * rule's effect was applied, and each process reports its counts in its own file,
 * named by its pid (see chaos_hits_file_number() for a program started by execve):
 *
 * @code
 * 3<TAB>tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 # net
 * 0<TAB>tcp4://127.0.0.1:6379:recv:LATENCY:200 # redis
 * @endcode
 *
 * One line per rule of the active rule file, the rule as written (at most
 * CHAOS_STATUS_TEXT_MAX bytes). A reader sums the files of all processes.
 *
 * The counters live in a pool of slots each library keeps beside its two
 * snapshots (chaos_hits_assign()): a rule that is still in the file after a
 * reload keeps the very same slot, so a firing through a rule copy taken before
 * the reload is neither lost nor counted twice. Every rule copy handed to a
 * wrapper carries a pointer to its slot and the slot's generation; a slot whose
 * rule left the file gets a new generation (chaos_hits_release()), so a copy that
 * outlived its rule, held across a blocking call, neither fires nor counts
 * against the rule that reuses the slot.
 *
 * The file is rewritten on each of a process's first CHAOS_HITS_EAGER hits, then
 * at most every CHAOS_HITS_INTERVAL_MS on a hit, and when the process exits
 * normally; a hit that is not due to be written makes no system call. A forked
 * child starts again from zero (an atfork handler clears the counts it inherited),
 * so the parent's hits are not reported twice. A vfork child shares the parent's
 * memory and runs no atfork handler; it counts into the parent's slots but never
 * writes a file of its own.
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

/** @brief Hits a process reports at once, before switching to the interval. */
#define CHAOS_HITS_EAGER 64U

/** @brief Shortest time between two rewrites of a process's hits file. */
#define CHAOS_HITS_INTERVAL_MS 100U

/** @brief Hits-file bytes per rule: a 20-digit count, a tab, the text and a newline. */
#define CHAOS_HITS_LINE_MAX (20U + 1U + CHAOS_STATUS_TEXT_MAX + 1U)

/** @brief Counter of one rule in one snapshot. */
typedef struct chaos_hit_slot chaos_hit_slot_t;

struct chaos_hit_slot
{
    volatile uint64_t count;
    /**
     * Firings claimed under `@first=N` (see chaos_policy.h): the count in the low
     * 32 bits, the low 32 bits of the generation it belongs to in the high ones
     * (chaos_hit_claims()). One word, so a claim checks both at once.
     */
    volatile uint64_t claimed;
    /** Effect state that must survive reloads (libchaos-time REGRESS: 0, 1 armed, 2 jumped). */
    volatile uint64_t state;
    /** Library hook that reports the counts after a hit on this slot; NULL forces a report. */
    void (*report)(chaos_hit_slot_t *slot);
    /** Bumped each time the slot's rule leaves the rule file (chaos_hits_release()). */
    volatile uint64_t generation;
    /** Held by a rule of the active or the next snapshot (the reload owner's business). */
    unsigned char used;
};

/**
 * @name Snapshot sequence (a seqlock)
 *
 * A reader copies a rule out of the active snapshot without a lock. Two reloads
 * later the same snapshot is cleared and refilled, and a reader preempted in the
 * middle of its copy would get half of one rule and half of another, or a rule
 * whose hit slot was already cleared (a NULL slot fires without `@first`). A
 * snapshot's sequence is odd from the moment a reload starts rewriting it until it
 * is published; a reader notes it before the copy and checks it after, and a copy
 * that saw a change is not used.
 * @{
 */

/** @brief Reader: the sequence before copying out of a snapshot. */
static inline uint64_t chaos_snapshot_read_begin(const volatile uint64_t *sequence)
{
    const uint64_t begin = *sequence;

    __sync_synchronize();
    return begin;
}

/** @brief Reader: whether the copy made since @p begin is whole. */
static inline int chaos_snapshot_read_valid(const volatile uint64_t *sequence, uint64_t begin)
{
    __sync_synchronize();
    return (begin & 1U) == 0U && *sequence == begin;
}

/** @brief Writer: the snapshot is being rewritten (idempotent). */
static inline void chaos_snapshot_write_begin(volatile uint64_t *sequence)
{
    if ((*sequence & 1U) == 0U)
    {
        ++*sequence;
    }
    __sync_synchronize();
}

/** @brief Writer: the snapshot is complete again (idempotent). */
static inline void chaos_snapshot_write_end(volatile uint64_t *sequence)
{
    __sync_synchronize();
    if ((*sequence & 1U) != 0U)
    {
        ++*sequence;
    }
}

/** @} */

/** @brief A claim word with no claims for @p generation (see chaos_hit_slot::claimed). */
static inline uint64_t chaos_hit_claims_none(uint64_t generation)
{
    return (uint64_t)(uint32_t)generation << 32;
}

/** @brief The number of claims in claim word @p claimed. */
static inline uint64_t chaos_hit_claims(uint64_t claimed)
{
    return claimed & UINT64_C(0xffffffff);
}

/** @brief Whether @p slot still belongs to a rule copy given it at @p generation. */
static inline int chaos_hit_slot_current(const chaos_hit_slot_t *slot, uint64_t generation)
{
    return slot == NULL || slot->generation == generation;
}

/**
 * @brief Gives the @p next_count rules of a new snapshot their slots in @p pool.
 *
 * @details A rule whose text is in the active snapshot gets that rule's slot: the
 * same object, so its count, `@first` claims and REGRESS state go on without a
 * copy, and firings through rule copies taken before the reload still land. Any
 * other rule gets a free slot, cleared. Rules that share their text share a slot.
 * The pool holds twice a library's rule limit, enough for the active and the next
 * snapshot; a rule left without one (impossible by that size) counts nothing.
 * Called by the reload owner only.
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
 * @brief Once the snapshot holding @p kept is active: frees every other slot of
 *        @p pool and gives it a new generation.
 *
 * @details A rule copy of a rule no longer in the file may still be held by a
 * blocking call; with the new generation it neither fires nor counts, also not
 * after the slot went to another rule. Called by the reload owner only.
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

/** @brief Frees every slot of @p pool and outdates every rule copy holding one. */
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
 * @brief In a forked child: clears the counts and claims the child inherited, so
 *        it starts its own; a REGRESS decision in progress in the parent is undone.
 *
 * @details A fork in the middle of a reload leaves the slots of the snapshot that
 * was being built marked used, with no reload left to release them: they are
 * released here, all but the @p active_count of the @p active snapshot.
 */
static inline void chaos_hits_pool_after_fork(
    chaos_hit_slot_t *pool, size_t pool_size, chaos_hit_slot_t *const *active, size_t active_count
)
{
    size_t index;

    chaos_hits_release(pool, pool_size, active, active_count);
    for (index = 0U; index < pool_size; ++index)
    {
        pool[index].count = 0U;
        pool[index].claimed = chaos_hit_claims_none(pool[index].generation);
        if (pool[index].state == 3U)
        {
            pool[index].state = 1U;
        }
    }
}

/**
 * @brief Counts one application of the rule owning @p slot.
 *
 * @param slot  The rule's slot; NULL for a rule outside a snapshot (unit tests).
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
 * @brief Milliseconds on CLOCK_MONOTONIC, read without passing through libchaos-time.
 *
 * @details From the vDSO, so counting a hit makes no system call; a raw system call
 * where there is no vDSO clock.
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
 * @brief Number of the hits file of the image running as @p pid: the pid, or a
 *        number beyond any pid when a file of that pid already exists.
 *
 * @details A program started by execve keeps the pid but loads the library anew,
 * and no destructor ran in the image it replaced: that image's file holds the hits
 * counted before the exec, and writing to the same name would wipe them. The pid
 * followed by nine digits of the load time is beyond pid_max (at most 2^22), so a
 * reader summing every `<prefix>.<digits>` counts both. A file a dead process with
 * the same pid left behind is kept the same way. The libraries call it at load and
 * in a forked child, chaos-init for each process it supervises; errno is left as
 * it was.
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

/** @brief chaos_hits_file_number_for() the calling process. */
static inline long chaos_hits_file_number(const char *prefix)
{
    return chaos_hits_file_number_for(prefix, (long)getpid());
}

/**
 * @brief Writes the hits file numbered @p pid.
 *
 * @details chaos-init writes them for the processes it supervises, by pid; the
 * libraries write their own under chaos_hits_file_number().
 *
 * @param prefix  File name without the number, e.g. `/tmp/.chaos-net.hits`.
 * @param pid     Number of the file: a pid, or chaos_hits_file_number().
 * @param slots   Counters, @p count entries; a NULL entry counts as 0.
 * @param texts   Rule texts, @p count entries of CHAOS_STATUS_TEXT_MAX + 1 bytes.
 * @param count   Number of rules.
 * @param buffer  Scratch of at least @p count * CHAOS_HITS_LINE_MAX + 1 bytes.
 */
static inline void chaos_hits_write_for(
    const char *prefix,
    long pid,
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

    if ((size_t)snprintf(path, sizeof(path), "%s.%ld", prefix, pid) >= sizeof(path))
    {
        return;
    }
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
    chaos_status_replace_file(path, buffer, length);
}

#endif
