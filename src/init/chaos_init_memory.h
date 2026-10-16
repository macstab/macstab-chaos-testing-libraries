/**
 * @file chaos_init_memory.h
 * @brief chaos-init: libchaos-memory rules for system calls of supervised processes.
 */

#ifndef CHAOS_INIT_MEMORY_H
#define CHAOS_INIT_MEMORY_H

#include "chaos_init_call.h"

/** @brief Prepares the memory rule state. Call once before deciding. */
void chaos_init_memory_start(void);

/**
 * @brief Decides @p call by the memory rules (`/tmp/.chaos-memory.conf`).
 * @return 1 when it is a memory system call (and @p verdict is set), 0 otherwise.
 */
int chaos_init_memory_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

#endif
