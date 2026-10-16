/**
 * @file chaos_init_tracee.h
 * @brief chaos-init: per-process rule state (hits, `@first`) of supervised processes.
 *
 * @details With LD_PRELOAD every process has its own copy of each library and so
 * its own counters. The supervisor serves all processes of the container, so it
 * keeps that state per process: a table of processes (tgid + start time) and, per
 * library, one hit slot per rule and process. A rule copy the core decides on gets
 * the calling process's slot as `rule.hit`, so probability, `@first`, windows and
 * counting stay in the core (chaos_policy_fire). After a reload of the rule file a
 * process's counts move to the rules with the same text, as the libraries do.
 *
 * Hits files are written as `<prefix>.<tgid>`, the format the libraries write:
 * eagerly for a process's first CHAOS_HITS_EAGER hits, then at most every
 * CHAOS_HITS_INTERVAL_MS (chaos_init_tracee_flush() from the supervisor's timer).
 */

#ifndef CHAOS_INIT_TRACEE_H
#define CHAOS_INIT_TRACEE_H

#include "chaos_hits.h"
#include "chaos_status.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/** @brief Processes tracked at once; when full, the state of an ended one is dropped. */
#define CHAOS_INIT_MAX_TRACEES 128U

/** @brief Largest CHAOS_<LIB>_MAX_RULES a library may register with. */
#define CHAOS_INIT_MAX_RULES 256U

/** @brief Rule text as the libraries store it. */
typedef char chaos_init_text_t[CHAOS_STATUS_TEXT_MAX + 1U];

/** @brief One library's view for the table: its rules, its hits file, its slots. */
typedef struct chaos_init_rules
{
    const char *hits_prefix; /**< e.g. "/tmp/.chaos-io.hits" */
    size_t max_rules;        /**< The library's CHAOS_<LIB>_MAX_RULES. */
    /**
     * The active snapshot: its rule texts and a load counter that starts at 1 and
     * grows with every load (0 marks slots that never saw a snapshot).
     * @return Number of rules.
     */
    size_t (*snapshot)(const chaos_init_text_t **texts, uint64_t *generation);
    chaos_hit_slot_t *slots; /**< CHAOS_INIT_MAX_TRACEES * max_rules */
    uint64_t *hashes;        /**< Text hash per slot, to carry counts over reloads. */
    uint64_t *generation;    /**< Per process: the snapshot its slots belong to. */
    size_t *count;           /**< Per process: rules in that snapshot. */
    uint64_t *total;         /**< Per process: hits counted. */
    unsigned char *pending;  /**< Per process: hits not yet written. */
    char *buffer;            /**< Hits file scratch: max_rules * CHAOS_HITS_LINE_MAX + 1. */
    long *file;              /**< Per process: its hits file's number; 0 before the first. */
} chaos_init_rules_t;

/** @brief Declares the storage of a library's chaos_init_rules_t (at file scope). */
#define CHAOS_INIT_RULES_STORAGE(name, max)                                                        \
    static chaos_hit_slot_t name##_slots[CHAOS_INIT_MAX_TRACEES * (max)];                          \
    static uint64_t name##_hashes[CHAOS_INIT_MAX_TRACEES * (max)];                                 \
    static uint64_t name##_generation[CHAOS_INIT_MAX_TRACEES];                                     \
    static size_t name##_count[CHAOS_INIT_MAX_TRACEES];                                            \
    static uint64_t name##_total[CHAOS_INIT_MAX_TRACEES];                                          \
    static unsigned char name##_pending[CHAOS_INIT_MAX_TRACEES];                                   \
    static char name##_buffer[(max) * CHAOS_HITS_LINE_MAX + 1U];                                   \
    static long name##_file[CHAOS_INIT_MAX_TRACEES]

/**
 * @brief Registers a library; at most CHAOS_INIT_MAX_LIBS, with at most
 *        CHAOS_INIT_MAX_RULES rules. @return 0, or -1.
 */
int chaos_init_tracee_register(chaos_init_rules_t *rules);

/**
 * @brief The table index of the process thread @p tid belongs to; -1 if unknown.
 *
 * @details Allocates an entry for a new process. When the table is full, entries of
 * processes that ended (or whose pid now belongs to another process) are written
 * and freed first; if none ended, the oldest entry is.
 */
int chaos_init_tracee_of(pid_t tid);

/**
 * @brief The hit slot of rule @p rule_index (of the active snapshot) for process
 *        @p tracee, its counts carried over from the previous snapshot by text.
 */
chaos_hit_slot_t *chaos_init_tracee_slot(chaos_init_rules_t *rules, int tracee, size_t rule_index);

/**
 * @brief The slot a matched rule copy counts in for the process of thread @p tid.
 *
 * @param hit    The copy's `hit`: a slot of the snapshot @p hits (@p count rules).
 * @return The process's slot of that rule, or NULL when @p hit is not one of the
 *         snapshot's or the process cannot be identified (it ended).
 */
chaos_hit_slot_t *chaos_init_tracee_hit(
    chaos_init_rules_t *rules,
    pid_t tid,
    chaos_hit_slot_t *const *hits,
    size_t count,
    const chaos_hit_slot_t *hit
);

/** @brief Writes every pending hits file, or all of them when @p all. */
void chaos_init_tracee_flush(int all);

/** @brief Whether any hits file waits for the interval. */
int chaos_init_tracee_pending(void);

#endif
