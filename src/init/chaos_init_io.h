/**
 * @file chaos_init_io.h
 * @brief `chaos-init`: libchaos-io rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies ERRNO (not on close) and LATENCY; see chaos_init_io.c.
 */

#ifndef CHAOS_INIT_IO_H
#define CHAOS_INIT_IO_H

#include "chaos_init_call.h"

/**
 * @brief Initialises the io rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG from getrandom() and registers its per-process slots.
 *        Call once, before the first decision.
 */
void chaos_init_io_start(void);

/**
 * @brief Decides @p call by the io rules (`/tmp/.chaos-io.conf`). Call after the net
 *        decider, which claims read/write/close on sockets.
 * @return 1 when it is an io system call (and @p verdict is set, PASS when no rule fires),
 *         else 0.
 */
int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

#endif
