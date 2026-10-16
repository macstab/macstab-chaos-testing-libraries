/**
 * @file chaos_init_net.h
 * @brief chaos-init: libchaos-net rules for system calls of supervised processes.
 */

#ifndef CHAOS_INIT_NET_H
#define CHAOS_INIT_NET_H

#include "chaos_init_call.h"

/** @brief Prepares the net rule state. Call once before deciding. */
void chaos_init_net_start(void);

/**
 * @brief Decides @p call by the net rules (`/tmp/.chaos-net.conf`).
 *
 * @details read, readv, write, writev and close are net calls only on a socket;
 * on anything else 0 is returned so the io rules decide them.
 *
 * @return 1 when it is a net call (and @p verdict is set), 0 otherwise.
 */
int chaos_init_net_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

/**
 * @brief Carries out what @p verdict leaves to be written into the thread's
 *        memory (a timed-out wait's buffers). Called only once the notification
 *        is known to be the thread's still: a pid reused by another process meanwhile
 *        must not be written to.
 */
void chaos_init_net_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict);

#endif
