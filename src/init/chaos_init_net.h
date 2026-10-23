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
 * @brief Whether this kernel offers Multipath TCP, in which case some MPTCP sockets can
 *        never be resolved and net rules on them could never match.
 *
 * @details A connection an MPTCP listener accepts from a plain TCP client falls back to TCP
 * but stays an MPTCP socket (sockprotoname "MPTCP"). sock_diag lists MPTCP sockets by their
 * MPTCP token, and a fallback connection has none, so it is in no MPTCP dump and in no
 * /proc/net table either: its endpoints cannot be read from outside, even where mptcp_diag
 * exists. Go 1.24+ listens with MPTCP by default, so every plain TCP client of a Go server
 * creates such a connection. chaos-init therefore turns MPTCP off for Go whenever this
 * returns true. Probes by creating an MPTCP socket; called before the fork, in the
 * supervisor's network namespace.
 *
 * @return 1 when socket(IPPROTO_MPTCP) succeeds; 0 when the kernel has no MPTCP (Go then
 *         uses plain TCP by itself).
 */
int chaos_init_net_mptcp_unresolvable(void);

/**
 * @brief Whether sock_diag can look up MPTCP sockets that have an MPTCP token (listeners and
 *        MPTCP-capable connections): mptcp_diag is present.
 *
 * @details Probes with a loopback MPTCP listener of its own and asks sock_diag for it. Used
 * by the host probe (test/runtime/mptcp_probe.c) to know which MPTCP lookups this kernel
 * can answer; a fallback connection is never found, whatever this returns.
 *
 * @return 1 when the probe listener is found; 0 without MPTCP or on any failure.
 */
int chaos_init_net_mptcp_diag_available(void);

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
