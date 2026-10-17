/**
 * @file chaos_init_tracee.c
 * @brief `chaos-init`: the per-process rule state table (see chaos_init_tracee.h).
 *
 * @details All storage is static: the process table here, slot arrays in each library's
 * CHAOS_INIT_RULES_STORAGE(). Lookups are linear over CHAOS_INIT_MAX_TRACEES (128)
 * entries; chaos_init_tracee_of() costs two /proc reads (chaos_init_process_of()), and on
 * a full table one identity check per entry. Single-threaded use only.
 *
 * Test seam: CHAOS_INIT_PROCESS_OF replaces the /proc identity lookup.
 */

#include "chaos_init_tracee.h"

#include "chaos_init_proc.h"

#include <string.h>

/** @brief Registration slots; four libraries register today (io, net, memory, process). */
#define CHAOS_INIT_MAX_LIBS 6U

/**
 * @brief Test seam: resolves a tid to (tgid, identity), the identity being start time and
 *        image (chaos_init_process_of()). Unit tests substitute a fake process table.
 */
#ifndef CHAOS_INIT_PROCESS_OF
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) chaos_init_process_of((tid), (tgid), (start))
#endif

/** @brief One table entry; `tgid` and `start` together identify the process image. */
typedef struct chaos_init_tracee
{
    pid_t tgid; /**< 0 when free. */
    uint64_t start;
    uint64_t age;    /**< Order of last use, to drop the longest unused when nothing ended. */
    uint64_t serial; /**< Order of allocation: which process holds the entry. */
} chaos_init_tracee_t;

static chaos_init_tracee_t g_chaos_init_tracees[CHAOS_INIT_MAX_TRACEES];
static uint64_t g_chaos_init_age = 0U;
static uint64_t g_chaos_init_serial = 0U;
static chaos_init_rules_t *g_chaos_init_rules[CHAOS_INIT_MAX_LIBS];
static size_t g_chaos_init_rule_libs = 0U;

/**
 * @brief 64-bit FNV-1a of a rule text: the key under which counts survive a reload. A
 *        collision (about 2^-64 per pair) would hand one rule's counts to another.
 */
static uint64_t chaos_init_hash(const char *text)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);

    while (*text != '\0')
    {
        hash = (hash ^ (unsigned char)*text++) * UINT64_C(0x100000001b3);
    }
    return hash;
}

/**
 * @brief `report` hook of every per-process slot: the core calls it after each hit
 *        (chaos_hit_slot_t::report) to schedule the hits file write.
 */
static void chaos_init_tracee_report(chaos_hit_slot_t *slot);

int chaos_init_tracee_register(chaos_init_rules_t *rules)
{
    if (g_chaos_init_rule_libs == CHAOS_INIT_MAX_LIBS || rules->max_rules > CHAOS_INIT_MAX_RULES)
    {
        return -1;
    }
    g_chaos_init_rules[g_chaos_init_rule_libs++] = rules;
    return 0;
}

/**
 * @brief Brings @p tracee's slots of @p rules to the active snapshot; no-op when already
 *        there. Each new rule inherits the counts of the first old rule with the same text
 *        hash (duplicate texts thus start from the same counts); a new text starts at
 *        zero. Every slot gets the report hook.
 */
static void chaos_init_tracee_sync(chaos_init_rules_t *rules, int tracee)
{
    const chaos_init_text_t *texts;
    uint64_t generation;
    const size_t count = rules->snapshot(&texts, &generation);
    chaos_hit_slot_t *slots = &rules->slots[(size_t)tracee * rules->max_rules];
    uint64_t *hashes = &rules->hashes[(size_t)tracee * rules->max_rules];
    static chaos_hit_slot_t old_slots[CHAOS_INIT_MAX_RULES];
    static uint64_t old_hashes[CHAOS_INIT_MAX_RULES];
    const size_t old_count = rules->count[tracee];
    const size_t new_count = count < rules->max_rules ? count : rules->max_rules;
    size_t index;

    if (rules->generation[tracee] == generation)
    {
        return;
    }
    /* Old slots go to static scratch first: a count may move to a lower index and would
     * otherwise be overwritten before it is read. */
    memcpy(old_slots, slots, old_count * sizeof(*slots));
    memcpy(old_hashes, hashes, old_count * sizeof(*hashes));
    for (index = 0U; index < new_count; ++index)
    {
        size_t old;

        hashes[index] = chaos_init_hash(texts[index]);
        memset(&slots[index], 0, sizeof(slots[index]));
        for (old = 0U; old < old_count; ++old)
        {
            if (old_hashes[old] == hashes[index])
            {
                slots[index] = old_slots[old];
                break;
            }
        }
        slots[index].report = chaos_init_tracee_report;
    }
    rules->generation[tracee] = generation;
    rules->count[tracee] = new_count;
}

/**
 * @brief Writes @p tracee's hits file for @p rules (after syncing to the active snapshot)
 *        and clears its pending flag.
 */
static void chaos_init_tracee_write(chaos_init_rules_t *rules, int tracee)
{
    const chaos_init_text_t *texts;
    uint64_t generation;
    const size_t count = rules->snapshot(&texts, &generation);

    static chaos_hit_slot_t *slots[CHAOS_INIT_MAX_RULES];
    size_t index;

    chaos_init_tracee_sync(rules, tracee);
    rules->pending[tracee] = 0U;
    for (index = 0U; index < rules->max_rules; ++index)
    {
        slots[index] = &rules->slots[(size_t)tracee * rules->max_rules + index];
    }
    const long tgid = (long)g_chaos_init_tracees[tracee].tgid;
    /* The number of the file this entry created, 0 before its first write. Until then a
     * number is chosen afresh: a file of this pid may hold the hits of the image an
     * execve() replaced, or of a dead process with the same pid, and must not be wiped.
     * chaos_hits_write_for() creates exclusively and moves on if the name is taken. */
    long number = rules->file[tracee];
    int owned = number != 0;

    if (!owned)
    {
        number = chaos_hits_file_number_for(rules->hits_prefix, tgid);
    }
    chaos_hits_write_for(
        rules->hits_prefix,
        tgid,
        &number,
        &owned,
        slots,
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) texts,
        count < rules->max_rules ? count : rules->max_rules,
        rules->buffer,
        rules->max_rules * CHAOS_HITS_LINE_MAX + 1U
    );
    rules->file[tracee] = owned ? number : 0;
}

/* Finds the library and process owning @p slot by address range, then writes the hits
 * file at once for the first CHAOS_HITS_EAGER hits and marks it pending afterwards (the
 * timer flushes pending files every CHAOS_HITS_INTERVAL_MS). */
static void chaos_init_tracee_report(chaos_hit_slot_t *slot)
{
    size_t lib;

    for (lib = 0U; lib < g_chaos_init_rule_libs; ++lib)
    {
        chaos_init_rules_t *rules = g_chaos_init_rules[lib];
        const size_t cells = CHAOS_INIT_MAX_TRACEES * rules->max_rules;

        if (slot >= rules->slots && slot < rules->slots + cells)
        {
            const int tracee = (int)((size_t)(slot - rules->slots) / rules->max_rules);

            if (++rules->total[tracee] <= CHAOS_HITS_EAGER)
            {
                chaos_init_tracee_write(rules, tracee);
            }
            else
            {
                rules->pending[tracee] = 1U;
            }
            return;
        }
    }
}

/**
 * @brief Writes what is pending for @p tracee and frees its entry, resetting every
 *        library's per-process state (generation 0 forces a fresh sync on reuse).
 */
static void chaos_init_tracee_drop(int tracee)
{
    size_t lib;

    for (lib = 0U; lib < g_chaos_init_rule_libs; ++lib)
    {
        chaos_init_rules_t *rules = g_chaos_init_rules[lib];

        if (rules->pending[tracee])
        {
            chaos_init_tracee_write(rules, tracee);
        }
        rules->generation[tracee] = 0U;
        rules->count[tracee] = 0U;
        rules->total[tracee] = 0U;
        rules->file[tracee] = 0;
    }
    g_chaos_init_tracees[tracee].tgid = 0;
}

/**
 * @brief Writes and frees the entries whose process ended or whose pid now names another
 *        process (identity mismatch). @return The first freed index, or -1.
 *
 * @details Called only on a full table, so every entry is occupied.
 */
static int chaos_init_tracee_reclaim(void)
{
    int free_index = -1;
    size_t index;

    for (index = 0U; index < CHAOS_INIT_MAX_TRACEES; ++index)
    {
        pid_t tgid;
        uint64_t start;

        if (CHAOS_INIT_PROCESS_OF(g_chaos_init_tracees[index].tgid, &tgid, &start) != 0 ||
            tgid != g_chaos_init_tracees[index].tgid || start != g_chaos_init_tracees[index].start)
        {
            chaos_init_tracee_drop((int)index);
            if (free_index < 0)
            {
                free_index = (int)index;
            }
        }
    }
    return free_index;
}

int chaos_init_tracee_of(pid_t tid)
{
    pid_t tgid;
    uint64_t start;
    int free_index = -1;
    int oldest = 0;
    size_t index;

    if (CHAOS_INIT_PROCESS_OF(tid, &tgid, &start) != 0)
    {
        return -1;
    }
    for (index = 0U; index < CHAOS_INIT_MAX_TRACEES; ++index)
    {
        const chaos_init_tracee_t *entry = &g_chaos_init_tracees[index];

        if (entry->tgid == tgid && entry->start == start)
        {
            g_chaos_init_tracees[index].age = ++g_chaos_init_age;
            return (int)index;
        }
        if (entry->tgid == tgid)
        {
            /* Same tgid, different identity: the pid was reused or execve() loaded a new
             * image. Write the old entry's hits and start over. */
            chaos_init_tracee_drop((int)index);
        }
        if (g_chaos_init_tracees[index].tgid == 0 && free_index < 0)
        {
            free_index = (int)index;
        }
        if (g_chaos_init_tracees[index].age < g_chaos_init_tracees[oldest].age)
        {
            oldest = (int)index;
        }
    }
    if (free_index < 0)
    {
        free_index = chaos_init_tracee_reclaim();
    }
    if (free_index < 0)
    {
        chaos_init_tracee_drop(oldest);
        free_index = oldest;
    }
    g_chaos_init_tracees[free_index].tgid = tgid;
    g_chaos_init_tracees[free_index].start = start;
    g_chaos_init_tracees[free_index].age = ++g_chaos_init_age;
    g_chaos_init_tracees[free_index].serial = ++g_chaos_init_serial;
    return free_index;
}

int chaos_init_tracee_find(pid_t tgid)
{
    size_t index;

    for (index = 0U; tgid > 0 && index < CHAOS_INIT_MAX_TRACEES; ++index)
    {
        if (g_chaos_init_tracees[index].tgid == tgid)
        {
            return (int)index;
        }
    }
    return -1;
}

pid_t chaos_init_tracee_tgid(int tracee)
{
    return g_chaos_init_tracees[tracee].tgid;
}

uint64_t chaos_init_tracee_serial(int tracee)
{
    return g_chaos_init_tracees[tracee].serial;
}

chaos_hit_slot_t *chaos_init_tracee_slot(chaos_init_rules_t *rules, int tracee, size_t rule_index)
{
    chaos_init_tracee_sync(rules, tracee);
    if (rule_index >= rules->count[tracee] || rule_index >= rules->max_rules)
    {
        return NULL;
    }
    return &rules->slots[(size_t)tracee * rules->max_rules + rule_index];
}

chaos_hit_slot_t *chaos_init_tracee_hit(
    chaos_init_rules_t *rules,
    pid_t tid,
    chaos_hit_slot_t *const *hits,
    size_t count,
    const chaos_hit_slot_t *hit
)
{
    size_t index;
    int tracee;

    /* The copy's position in the snapshot is the rule index. */
    for (index = 0U; index < count && hits[index] != hit; ++index)
    {
    }
    if (hit == NULL || index == count || (tracee = chaos_init_tracee_of(tid)) < 0)
    {
        return NULL;
    }
    return chaos_init_tracee_slot(rules, tracee, index);
}

void chaos_init_tracee_flush(int all)
{
    size_t lib;
    size_t tracee;

    for (lib = 0U; lib < g_chaos_init_rule_libs; ++lib)
    {
        chaos_init_rules_t *rules = g_chaos_init_rules[lib];

        for (tracee = 0U; tracee < CHAOS_INIT_MAX_TRACEES; ++tracee)
        {
            if (g_chaos_init_tracees[tracee].tgid != 0 &&
                (rules->pending[tracee] || (all && rules->total[tracee] != 0U)))
            {
                chaos_init_tracee_write(rules, (int)tracee);
            }
        }
    }
}

int chaos_init_tracee_pending(void)
{
    size_t lib;
    size_t tracee;

    for (lib = 0U; lib < g_chaos_init_rule_libs; ++lib)
    {
        for (tracee = 0U; tracee < CHAOS_INIT_MAX_TRACEES; ++tracee)
        {
            if (g_chaos_init_rules[lib]->pending[tracee])
            {
                return 1;
            }
        }
    }
    return 0;
}
