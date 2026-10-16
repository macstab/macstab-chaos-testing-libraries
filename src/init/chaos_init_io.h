/**
 * @file chaos_init_io.h
 * @brief chaos-init: libchaos-io rules for system calls of supervised processes.
 */

#ifndef CHAOS_INIT_IO_H
#define CHAOS_INIT_IO_H

#include "chaos_init_call.h"

/** @brief Loads nothing yet; prepares the io rule state. Call once before deciding. */
void chaos_init_io_start(void);

/**
 * @brief Decides @p call by the io rules (`/tmp/.chaos-io.conf`).
 * @return 1 when it is an io system call (and @p verdict is set), 0 otherwise.
 */
int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

#endif
