/**
 * @file chaos_init_process.h
 * @brief `chaos-init`: libchaos-process rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies ERRNO, LATENCY and FAIL_AFTER on clone/clone3/fork/vfork,
 * execve, execveat, wait4 and waitid; see chaos_init_process.c.
 */

#ifndef CHAOS_INIT_PROCESS_H
#define CHAOS_INIT_PROCESS_H

#include "chaos_init_call.h"

/**
 * @brief Initialises the process rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG and registers its per-process slots. Call once, before
 *        the first decision.
 *
 * @param application  The child chaos-init forked. Its execve() calls made while it still
 *                     runs chaos-init's image start the application and are never
 *                     faulted, matching LD_PRELOAD, where the library is not loaded yet
 *                     at that point.
 */
void chaos_init_process_start(pid_t application);

/**
 * @brief Decides @p call by the process rules (`/tmp/.chaos-process.conf`).
 * @return 1 when it is a process system call (and @p verdict is set, PASS when no rule
 *         fires), else 0.
 */
int chaos_init_process_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

#endif
