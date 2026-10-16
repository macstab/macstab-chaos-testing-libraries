/**
 * @file chaos_init_tracee.c
 * @brief chaos-init: per-process rule state of supervised processes.
 */

#include "chaos_init_tracee.h"

#include "chaos_init_proc.h"

#include <string.h>

/** @brief Libraries that can be registered (io, net, memory, process, ...). */
#define CHAOS_INIT_MAX_LIBS 6U

/**
 * @brief How a process is told from another: its pid and its start time.
 *        Unit tests replace the lookup.
 */
#ifndef CHAOS_INIT_PROCESS_OF
#define CHAOS_INIT_PROCESS_OF(tid, tgid, start) chaos_init_process_of((tid), (tgid), (start))
#endif

typedef struct chaos_init_tracee
{
    pid_t tgid; /**< 0 when free. */
    uint64_t start;
    uint64_t age; /**< Order of allocation, to drop the oldest when nothing ended. */
} chaos_init_tracee_t;

static chaos_init_tracee_t g_chaos_init_tracees[CHAOS_INIT_MAX_TRACEES];
static uint64_t g_chaos_init_age = 0U;
static chaos_init_rules_t *g_chaos_init_rules[CHAOS_INIT_MAX_LIBS];
static size_t g_chaos_init_rule_libs = 0U;

/** @brief FNV-1a of a rule text. */
static uint64_t chaos_init_hash(const char *text)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);

    while (*text != '\0')
    {
        hash = (hash ^ (unsigned char)*text++) * UINT64_C(0x100000001b3);
    }
    return hash;
}

/** @brief Called by the core on every hit of a tracee slot. */
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

/** @brief Brings @p tracee's slots of @p rules to the active snapshot. */
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
    /* Each count moves to the rule with the same text; a new text starts at zero.
     * The old slots are copied first, since a count may move to a lower index. */
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

/** @brief Writes @p tracee's hits file of @p rules. */
static void chaos_init_tracee_write(chaos_init_rules_t *rules, int tracee)
{
    const chaos_init_text_t *texts;
    uint64_t generation;
    const size_t count = rules->snapshot(&texts, &generation);

    chaos_init_tracee_sync(rules, tracee);
    rules->pending[tracee] = 0U;
    chaos_hits_write_for(
        rules->hits_prefix,
        (long)g_chaos_init_tracees[tracee].tgid,
        &rules->slots[(size_t)tracee * rules->max_rules],
        (const char(*)[CHAOS_STATUS_TEXT_MAX + 1U]) texts,
        count < rules->max_rules ? count : rules->max_rules,
        rules->buffer,
        rules->max_rules * CHAOS_HITS_LINE_MAX + 1U
    );
}

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

/** @brief Writes what is pending for @p tracee and frees its entry. */
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
    }
    g_chaos_init_tracees[tracee].tgid = 0;
}

/**
 * @brief Frees entries of processes that ended; @return the first free index, or -1.
 *
 * @details Only called on a full table, so every entry belongs to a process.
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
            return (int)index;
        }
        if (entry->tgid == tgid)
        {
            /* The pid of an ended process, now another one's: start over. */
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
    return free_index;
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
    const chaos_hit_slot_t *hits,
    size_t count,
    const chaos_hit_slot_t *hit
)
{
    int tracee;

    if (hit < hits || hit >= hits + count || (tracee = chaos_init_tracee_of(tid)) < 0)
    {
        return NULL;
    }
    return chaos_init_tracee_slot(rules, tracee, (size_t)(hit - hits));
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
