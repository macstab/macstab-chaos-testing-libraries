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

#include <stddef.h>

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

/**
 * @brief The system call numbers the filter must answer with TRACE for the rules currently
 *        in `/tmp/.chaos-net.conf`.
 *
 * @details Reads the rule file (as a decision would) and names, for every rule whose
 * effect needs the tracee's registers, the calls of that operation whose length sits in a
 * register. Called in the child before it installs the filter; see
 * chaos_init_io_traced_calls() for why it happens there and what it costs.
 *
 * `read` is shared with io, so a rule that traces it moves every read onto the trace path,
 * file reads included: a filter has one action per system call number.
 *
 * @param out       Receives the numbers; NULL yields 0.
 * @param capacity  Entries @p out can hold; the result is truncated to it.
 * @return How many numbers were written.
 */
size_t chaos_init_net_traced_calls(long *out, size_t capacity);

/**
 * @brief Decides @p call again at its syscall-exit stop, where @p result is what it
 *        returned, and applies an effect that needed it (CORRUPT).
 *
 * @details Reached only for a call whose entry stop answered CHAOS_INIT_AFTER, with the
 * call as the entry stop saw it: see chaos_init_io_decide_result(). The draw happens here,
 * so a receive that delivered nothing counts no hit.
 *
 * @return 1 when it is a net system call, else 0.
 */
int chaos_init_net_decide_result(const chaos_init_call_t *call, long result);

/**
 * @brief Re-reads `/tmp/.chaos-net.conf` now, outside a decision.
 *
 * @details What a decision does first, done without one: the rule file is stat'ed and, if
 * it changed, loaded and published, which also rewrites this library's status file. Called
 * when the rule file was replaced (the inotify watch in chaos_init.c), so that a rule file
 * nobody has called into yet is still reported -- under `LD_PRELOAD` the constructor does
 * that at process start, and a status file that only appears with the first intercepted
 * call would be a difference between the two modes that nothing explains.
 */
void chaos_init_net_reload(void);

#endif
