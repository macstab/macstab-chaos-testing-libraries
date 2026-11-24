/**
 * @file chaos_init_time.h
 * @brief `chaos-init`: libchaos-time rules applied to tracee system calls.
 *
 * @details SECCOMP mode applies every time effect: ERRNO and LATENCY on a clock read and
 * on a sleep, and OFFSET, REGRESS and FREEZE on the value a clock read returns. The read
 * itself does not run -- the supervisor reads the same clock, applies the effect and
 * answers with the value -- which is why the effects need nothing of the tracee but the
 * output pointer. See chaos_init_time.c.
 *
 * A clock read only reaches the supervisor once the tracee's vDSO lookups fail
 * (chaos_init_vdso.h); without that step the C library and the Go runtime read the clock
 * without a system call and no rule could ever fire.
 */

#ifndef CHAOS_INIT_TIME_H
#define CHAOS_INIT_TIME_H

#include "chaos_init_call.h"

#include <stddef.h>

/**
 * @brief Initialises the time rule core (the rule file is read lazily, on the first
 *        decision), seeds its PRNG from getrandom() and registers its per-process slots.
 *        Call once, before the first decision.
 */
void chaos_init_time_start(void);

/**
 * @brief Decides @p call by the time rules (`/tmp/.chaos-time.conf`).
 *
 * @details A clock read whose value a rule changes is answered by the supervisor
 * (CHAOS_INIT_RETURN with the value written at commit time); a sleep runs as it is, with
 * LATENCY and ERRNO before it, as in the library.
 *
 * @return 1 when it is a time system call (and @p verdict is set, PASS when no rule
 *         fires), else 0.
 */
int chaos_init_time_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict);

/**
 * @brief Writes the value a decided clock read returns into the tracee.
 *
 * @details Called when the reply is about to go out, as chaos_init_net_commit() is: the
 * clock is read here, so a delayed read answers with the time after its delay, exactly as
 * the library's does. The value-changing effects (OFFSET, REGRESS, FREEZE) are looked up
 * and drawn here too, which is where the library draws them -- after the call it decided
 * to let run.
 *
 * Does nothing for a verdict chaos_init_time_decide() did not ask it for.
 */
void chaos_init_time_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict);

/**
 * @brief The system calls the filter has to notify for the loaded rules.
 *
 * @details A clock read is `clock_gettime` and, for CLOCK_REALTIME, also `gettimeofday`
 * and (x86_64) `time`; a sleep is `nanosleep` and `clock_nanosleep`. Only what a rule can
 * act on is notified, so a rule file about sleeps costs clock reads nothing.
 *
 * @param out       Receives the system call numbers.
 * @param capacity  Entries @p out holds; a longer set is truncated.
 * @return How many were written.
 */
size_t chaos_init_time_calls(long *out, size_t capacity);

/**
 * @brief The clocks the loaded rules name, for the filter's argument test.
 *
 * @details `clock_gettime` carries the clock in its first argument, so the filter can
 * notify the clocks a rule names and let every other one run untouched -- which is what
 * keeps a monotonic read cheap while a rule works on the wall clock. A rule without a
 * clock (`*` or `clock_gettime`) names them all, which this reports as the empty set.
 *
 * @param out       Receives the clock ids.
 * @param capacity  Entries @p out holds; a longer set is truncated.
 * @return How many were written; 0 means "every clock" or "no clock read rule".
 */
size_t chaos_init_time_clocks(long *out, size_t capacity);

/**
 * @brief Re-reads `/tmp/.chaos-time.conf` now, outside a decision.
 *
 * @details What a decision does first, done without one: the rule file is stat'ed and, if
 * it changed, loaded and published, which also rewrites this library's status file. Called
 * when the rule file was replaced (the inotify watch in chaos_init.c), so that a rule file
 * nobody has called into yet is still reported -- under `LD_PRELOAD` the constructor does
 * that at process start, and a status file that only appears with the first intercepted
 * call would be a difference between the two modes that nothing explains.
 */
void chaos_init_time_reload(void);

#endif
