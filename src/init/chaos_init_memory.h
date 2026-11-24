/**
 * @file chaos_init_memory.h
 * @brief `chaos-init`: libchaos-memory rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies ERRNO and LATENCY on mmap, munmap, mprotect and madvise;
 * see chaos_init_memory.c.
 */

#ifndef CHAOS_INIT_MEMORY_H
#define CHAOS_INIT_MEMORY_H

#include "chaos_init_call.h"

/**
 * @brief Initialises the memory rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG from getrandom() and registers its per-process slots.
 *        Call once, before the first decision.
 */
void chaos_init_memory_start(void);

/**
 * @brief Decides @p call by the memory rules (`/tmp/.chaos-memory.conf`).
 * @return 1 when it is a memory system call (and @p verdict is set, PASS when no rule
 *         fires), else 0.
 */
int chaos_init_memory_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

/**
 * @brief Re-reads `/tmp/.chaos-memory.conf` now, outside a decision.
 *
 * @details What a decision does first, done without one: the rule file is stat'ed and, if
 * it changed, loaded and published, which also rewrites this library's status file. Called
 * when the rule file was replaced (the inotify watch in chaos_init.c), so that a rule file
 * nobody has called into yet is still reported -- under `LD_PRELOAD` the constructor does
 * that at process start, and a status file that only appears with the first intercepted
 * call would be a difference between the two modes that nothing explains.
 */
void chaos_init_memory_reload(void);

#endif
