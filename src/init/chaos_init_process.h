/**
 * @file chaos_init_process.h
 * @brief chaos-init: libchaos-process rules for system calls of supervised processes.
 */

#ifndef CHAOS_INIT_PROCESS_H
#define CHAOS_INIT_PROCESS_H

#include "chaos_init_call.h"

/**
 * @brief Prepares the process rule state. Call once before deciding.
 *
 * @param application  The child chaos-init started: its first execve() is the one
 *                     that starts the application and is never faulted (with
 *                     LD_PRELOAD the library is not loaded at that point either).
 */
void chaos_init_process_start(pid_t application);

/**
 * @brief Decides @p call by the process rules (`/tmp/.chaos-process.conf`).
 * @return 1 when it is a process system call (and @p verdict is set), 0 otherwise.
 */
int chaos_init_process_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

#endif
