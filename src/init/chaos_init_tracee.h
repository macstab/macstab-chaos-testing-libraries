/**
 * @file chaos_init_tracee.h
 * @brief `chaos-init`: per-process rule state (hits, `@first`, windows) of tracees.
 *
 * @details Under LD_PRELOAD every process has its own copy of each library and thus its
 * own hit counters. The supervisor serves every process of the container from one address
 * space, so it keeps that state per process explicitly:
 *
 * - a table of CHAOS_INIT_MAX_TRACEES processes, keyed by tgid plus the identity value of
 *   chaos_init_process_of() (start time mixed with code/stack start), so a reused pid or
 *   an execve() starts from zero, as a fresh library load would;
 * - per registered library, one chaos_hit_slot_t per (process, rule).
 *
 * A decider matches a rule copy against the library's active snapshot, then replaces the
 * copy's `hit` with the calling process's slot (chaos_init_tracee_hit()). Probability,
 * `@first`, `@from`/`@until` and counting thus stay in the unchanged rule core
 * (chaos_policy_fire). After a reload a process's counts move to the rules with the same
 * text (64-bit FNV-1a of the text), as the libraries carry them over.
 *
 * Hits files are named `<prefix>.<n>`, the libraries' format: n is the tgid, or a number
 * beyond pid_max when a file of that pid already exists (a replaced image's, or a dead
 * process's; chaos_hits_file_number_for()). They are written on each of a process's first
 * CHAOS_HITS_EAGER hits, then at most every CHAOS_HITS_INTERVAL_MS from the supervisor's
 * timer (chaos_init_tracee_flush()), when an entry is dropped, and for everyone when the
 * application exits.
 *
 * Not thread-safe; static scratch buffers make every function non-reentrant. The
 * supervisor is single-threaded.
 */

#ifndef CHAOS_INIT_TRACEE_H
#define CHAOS_INIT_TRACEE_H

#include "chaos_hits.h"
#include "chaos_status.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Processes tracked at once. On a full table the entries of ended processes are
 *        written and freed first; if none ended, the least recently used one is.
 */
#define CHAOS_INIT_MAX_TRACEES 128U

/** @brief Largest CHAOS_<LIB>_MAX_RULES a library may register with (sizes scratch arrays). */
#define CHAOS_INIT_MAX_RULES 256U

/** @brief Rule text as the libraries store it in their snapshots. */
typedef char chaos_init_text_t[CHAOS_STATUS_TEXT_MAX + 1U];

/**
 * @brief One library's registration: how to read its active snapshot, where its hits files
 *        go, and the storage of its per-process slots (CHAOS_INIT_RULES_STORAGE()).
 */
typedef struct chaos_init_rules
{
    const char *hits_prefix; /**< e.g. "/tmp/.chaos-io.hits" */
    size_t max_rules;        /**< The library's CHAOS_<LIB>_MAX_RULES. */
    /**
     * Reports the active snapshot: its rule texts and a load counter that starts at 1 and
     * grows on every reload (0 marks per-process slots that never saw a snapshot).
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

/**
 * @brief Defines, at file scope, the static arrays a chaos_init_rules_t points to, named
 *        `<name>_slots`, `<name>_hashes`, ... (no heap: the binary is static and PID 1).
 */
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
 * @brief Registers a library; @p rules must outlive the process.
 * @return 0, or -1 when CHAOS_INIT_MAX_LIBS (6) are registered or `max_rules` exceeds
 *         CHAOS_INIT_MAX_RULES.
 */
int chaos_init_tracee_register(chaos_init_rules_t *rules);

/**
 * @brief The table index of the process thread @p tid belongs to, allocating one for a
 *        process not seen before.
 *
 * @details An entry with the same tgid but a different identity (pid reused, or a new
 * image after execve()) is written and freed first. On a full table, entries of processes
 * that ended (or whose pid now belongs to another process) are written and freed; if none
 * ended, the least recently used entry is evicted: its pending hits are written, and a
 * later call of that process starts its counts from zero.
 *
 * @return The index, or -1 when the thread is gone (/proc lookup failed).
 */
int chaos_init_tracee_of(pid_t tid);

/** @brief The table index of process @p tgid if it has an entry, else -1; allocates nothing. */
int chaos_init_tracee_find(pid_t tgid);

/** @brief The tgid that holds entry @p tracee (0 when free). */
pid_t chaos_init_tracee_tgid(int tracee);

/**
 * @brief Allocation serial of entry @p tracee, unique per process that ever held an entry.
 *        State kept by index elsewhere (FAIL_AFTER counters) belongs to the current holder
 *        only while this value is unchanged.
 */
uint64_t chaos_init_tracee_serial(int tracee);

/**
 * @brief The hit slot of rule @p rule_index of the active snapshot for process @p tracee,
 *        first syncing the process's slots to that snapshot (counts carried over by text).
 * @return The slot, or NULL when @p rule_index is out of range.
 */
chaos_hit_slot_t *chaos_init_tracee_slot(chaos_init_rules_t *rules, int tracee, size_t rule_index);

/**
 * @brief Translates a matched rule copy's snapshot slot into the calling process's slot.
 *
 * @param tid    Calling thread.
 * @param hits   The snapshot's slot pointers, @p count entries.
 * @param hit    The copy's `hit`: one of @p hits.
 * @return The process's slot for that rule, or NULL when @p hit is NULL or not one of
 *         @p hits, or the thread is gone. A NULL result means: do not fire.
 */
chaos_hit_slot_t *chaos_init_tracee_hit(
    chaos_init_rules_t *rules,
    pid_t tid,
    chaos_hit_slot_t *const *hits,
    size_t count,
    const chaos_hit_slot_t *hit
);

/**
 * @brief Writes every hits file with unwritten hits; with @p all, also every process that
 *        has counted any hit (used when the application exits).
 */
void chaos_init_tracee_flush(int all);

/** @brief Whether any process has hits waiting for the interval. */
int chaos_init_tracee_pending(void);

#endif
