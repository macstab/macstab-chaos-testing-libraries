/**
 * @file chaos_init_net.h
 * @brief `chaos-init`: libchaos-net rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies ERRNO (not on close), LATENCY and, on the poll family,
 * TIMEOUT. Endpoints are resolved from outside the tracee; see chaos_init_net.c.
 */

#ifndef CHAOS_INIT_NET_H
#define CHAOS_INIT_NET_H

#include "chaos_init_call.h"

/**
 * @brief Initialises the net rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG from getrandom() and registers its per-process slots.
 *        Call once, before the first decision.
 */
void chaos_init_net_start(void);

/**
 * @brief Decides @p call by the net rules (`/tmp/.chaos-net.conf`).
 *
 * @details read, readv, write, writev and close belong to net only when the descriptor is
 * a socket (`/proc/<tid>/fd/<fd>` reads `socket:[...]`); otherwise 0 is returned and the
 * io decider gets them. Endpoints are resolved only when a loaded rule targets the call's
 * operation, so rules on connect alone leave recv and epoll at the base cost.
 *
 * @return 1 when it is a net call (and @p verdict is set, PASS when no rule fires), else 0.
 */
int chaos_init_net_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

/**
 * @brief Whether this kernel offers Multipath TCP but sock_diag cannot look its sockets up
 *        (no mptcp_diag), in which case net rules on MPTCP sockets could never match.
 *
 * @details Probes with a loopback MPTCP listener of its own and asks sock_diag for it. A
 * kernel without MPTCP returns false: Go falls back to plain TCP there. Any failure after
 * the socket was created counts as unresolvable. Called before the fork, in the
 * supervisor's network namespace.
 */
int chaos_init_net_mptcp_unresolvable(void);

/**
 * @brief Performs the tracee memory writes @p verdict defers: for a TIMEOUT, "nothing ready"
 *        into the wait's buffers (`clear_ready`); no-op otherwise.
 *
 * @details Must run only after SECCOMP_IOCTL_NOTIF_ID_VALID confirmed that the notified
 * thread still waits; a pid reused by another process meanwhile must not be written to.
 * A small window remains between that check and the write.
 */
void chaos_init_net_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict);

#endif
