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
 * The count lives in the rule file's snapshot; a rule that is still in the file
 * after a reload keeps its count. Every rule copy handed to a wrapper carries a
 * pointer to its slot, so the wrapper that applies the effect counts it without
 * looking the rule up again.
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
    /** Firings claimed under `@first=N` (see chaos_policy.h); never more than N succeed. */
    volatile uint64_t claimed;
    /** Effect state that must survive reloads (libchaos-time REGRESS: 0, 1 armed, 2 jumped). */
    volatile uint64_t state;
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
 * @brief Number of the calling image's hits file: its pid, or a number beyond any
 *        pid when a file of that pid already exists.
 *
 * @details A program started by execve keeps the pid but loads the library anew,
 * and no destructor ran in the image it replaced: that image's file holds the hits
 * counted before the exec, and writing to the same name would wipe them. The pid
 * followed by nine digits of the load time is beyond pid_max (at most 2^22), so a
 * reader summing every `<prefix>.<digits>` counts both. A file a dead process with
 * the same pid left behind is kept the same way. Called at load and in a forked
 * child; errno is left as it was.
 */
static inline long chaos_hits_file_number(const char *prefix)
{
    const int saved_errno = errno;
    const long pid = (long)getpid();
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

/**
 * @brief Writes the hits file numbered @p pid.
 *
 * @details chaos-init writes them for the processes it supervises, by pid; the
 * libraries write their own under chaos_hits_file_number().
 *
 * @param prefix  File name without the number, e.g. `/tmp/.chaos-net.hits`.
 * @param pid     Number of the file: a pid, or chaos_hits_file_number().
 * @param slots   Counters, @p count entries.
 * @param texts   Rule texts, @p count entries of CHAOS_STATUS_TEXT_MAX + 1 bytes.
 * @param count   Number of rules.
 * @param buffer  Scratch of at least @p count * CHAOS_HITS_LINE_MAX + 1 bytes.
 */
static inline void chaos_hits_write_for(
    const char *prefix,
    long pid,
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

    if ((size_t)snprintf(path, sizeof(path), "%s.%ld", prefix, pid) >= sizeof(path))
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
