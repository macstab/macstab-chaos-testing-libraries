/**
 * @file chaos_hits.h
 * @brief Per-rule hit counters, reported in `/tmp/.chaos-<lib>.hits.<pid>`.
 *
 * @details
 * A rule that parses but never fires is the other silent failure next to a
 * rejected rule file (see chaos_status.h): the selector does not match what the
 * program really does. Every library therefore counts, per rule, how often the
 * rule's effect was applied, and each process reports its counts in its own file:
 *
 * @code
 * 3<TAB>tcp4://127.0.0.1:5432:connect:ECONNREFUSED:1.0 # net
 * 0<TAB>tcp4://127.0.0.1:6379:recv:LATENCY:200 # redis
 * @endcode
 *
 * One line per rule of the active rule file, the rule as written (at most
 * CHAOS_STATUS_TEXT_MAX bytes). A reader sums the files of all processes.
 *
 * The count lives in the rule file's snapshot; a rule that is still in the file
 * after a reload keeps its count. Every rule copy handed to a wrapper carries a
 * pointer to its slot, so the wrapper that applies the effect counts it without
 * looking the rule up again.
 *
 * The file is rewritten on each of a process's first CHAOS_HITS_EAGER hits, then
 * at most every CHAOS_HITS_INTERVAL_MS on a hit, and when the process exits
 * normally. A forked child starts again from zero, so the parent's hits are not
 * reported twice.
 */

#ifndef CHAOS_HITS_H
#define CHAOS_HITS_H

#include "chaos_status.h"

#include <stdint.h>
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
    /** Library hook that reports the counts after a hit on this slot; NULL forces a report. */
    void (*report)(chaos_hit_slot_t *slot);
};

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

/** @brief Milliseconds on CLOCK_MONOTONIC, read without passing through libchaos-time. */
static inline uint64_t chaos_hits_now_ms(void)
{
    struct timespec now;

#ifdef __linux__
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) != 0)
#else
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
#endif
    {
        return 0U;
    }
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

/**
 * @brief Writes the hits file of the calling process.
 *
 * @param prefix  File name without the pid, e.g. `/tmp/.chaos-net.hits`.
 * @param slots   Counters, @p count entries.
 * @param texts   Rule texts, @p count entries of CHAOS_STATUS_TEXT_MAX + 1 bytes.
 * @param count   Number of rules.
 * @param buffer  Scratch of at least @p count * CHAOS_HITS_LINE_MAX + 1 bytes.
 */
static inline void chaos_hits_write(
    const char *prefix,
    const chaos_hit_slot_t *slots,
    const char (*texts)[CHAOS_STATUS_TEXT_MAX + 1U],
    size_t count,
    char *buffer,
    size_t buffer_size
)
{
    char path[128];
    size_t length = 0U;
    size_t index;

    if ((size_t)snprintf(path, sizeof(path), "%s.%ld", prefix, (long)getpid()) >= sizeof(path))
    {
        return;
    }
    for (index = 0U; index < count; ++index)
    {
        const int rc = snprintf(
            buffer + length,
            buffer_size - length,
            "%llu\t%s\n",
            (unsigned long long)slots[index].count,
            texts[index]
        );

        if (rc < 0 || (size_t)rc >= buffer_size - length)
        {
            return;
        }
        length += (size_t)rc;
    }
    chaos_status_replace_file(path, buffer, length);
}

#endif
