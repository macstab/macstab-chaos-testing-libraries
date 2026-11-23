/**
 * @file chaos_init_io.h
 * @brief `chaos-init`: libchaos-io rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies ERRNO (not on close) and LATENCY; see chaos_init_io.c.
 */

#ifndef CHAOS_INIT_IO_H
#define CHAOS_INIT_IO_H

#include "chaos_init_call.h"

#include <stddef.h>

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

/**
 * @brief The system call numbers the filter must answer with TRACE for the rules currently
 *        in `/tmp/.chaos-io.conf`.
 *
 * @details Reads the rule file (as a decision would) and names, for every rule whose
 * effect needs the tracee's registers, the calls of that operation whose byte count sits
 * in a register. Called in the child before it installs the filter, because a filter is
 * fixed once installed: a rule file that gains its first such effect later cannot start
 * tracing until the container restarts, and says so.
 *
 * Duplicates are removed, so the result can be handed to chaos_init_build_filter() as is.
 *
 * @param out       Receives the numbers; NULL yields 0.
 * @param capacity  Entries @p out can hold; the result is truncated to it.
 * @return How many numbers were written.
 */
size_t chaos_init_io_traced_calls(long *out, size_t capacity);

/**
 * @brief Decides @p call again at its syscall-exit stop, where @p result is what it
 *        returned, and applies an effect that needed it (CORRUPT).
 *
 * @details Reached only for a call whose entry stop answered CHAOS_INIT_AFTER. The same
 * rule is selected as at the entry stop -- the argument registers still hold the caller's
 * values -- and the draw happens here, so a read that returned nothing counts no hit.
 * There is no verdict: the call has already run, and the effect is a byte of the tracee's
 * buffer.
 *
 * @return 1 when it is an io system call, else 0.
 */
int chaos_init_io_decide_result(const chaos_init_call_t *call, long result);

#endif
