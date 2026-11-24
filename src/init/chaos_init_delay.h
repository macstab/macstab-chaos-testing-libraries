/**
 * @file chaos_init_delay.h
 * @brief `chaos-init`: the queue of notifications held back by LATENCY (or a waited-out
 *        TIMEOUT) until they are due.
 *
 * @details The supervisor is single-threaded and answers notifications in order. A
 * delayed call is therefore not slept on: it is parked here unanswered (its thread stays
 * blocked in the kernel) and answered from the timerfd handler when due, so the tracee's
 * other threads keep being served meanwhile.
 *
 * The queue is an unordered array; every operation is O(n) with n <= CHAOS_INIT_MAX_DELAYED.
 * Not thread-safe; only the supervisor's main loop uses it. Due times are CLOCK_MONOTONIC
 * milliseconds.
 */

#ifndef CHAOS_INIT_DELAY_H
#define CHAOS_INIT_DELAY_H

#include "chaos_init_call.h"

#include <stdint.h>

/**
 * @brief Capacity of the queue. A call that finds it full gets the rest of its verdict at
 *        once, without the delay.
 */
#define CHAOS_INIT_MAX_DELAYED 1024U

/**
 * @brief The answer a DELAY verdict turns into when due: FAIL with `error` if set, else
 *        RETURN `value` if `returns`, else PASS. `delay_ms` is cleared.
 */
chaos_init_verdict_t chaos_init_delay_answer(const chaos_init_verdict_t *verdict);

/**
 * @brief Parks call @p id until @p due_ms, when it is answered with @p answer (PASS, FAIL
 *        or RETURN). Both structures are copied.
 *
 * @param traced  Non-zero when @p id is the tid of a tracee stopped at a seccomp stop
 *                rather than a notification id: the answer is then applied to its
 *                registers and the thread continued, not sent to the listener. A thread is
 *                in one system call at a time, so its tid identifies the parked call as a
 *                notification id does.
 * @return 0, or -1 when the queue is full.
 */
int chaos_init_delay_add(
    uint64_t id,
    const chaos_init_call_t *call,
    uint64_t due_ms,
    const chaos_init_verdict_t *answer,
    int traced
);

/**
 * @brief Re-binds a parked call that the kernel re-notified under a new id @p id.
 *
 * @details Without SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (before Linux 5.19) a signal
 * interrupts a thread waiting for its answer; the kernel withdraws the notification, runs
 * the handler and restarts the system call as a new notification, so the old id can no
 * longer be answered. A thread is in one system call at a time, so a parked entry with the
 * same tid, number and raw arguments is that call: it takes the new id and keeps its
 * original due time and answer, and is neither decided nor counted again. On 5.19+ this
 * finds nothing and costs one scan per notification.
 *
 * @return 1 when @p call was parked (now under @p id), 0 otherwise.
 */
int chaos_init_delay_resume(const chaos_init_call_t *call, uint64_t id);

/** @brief Stores the earliest due time in @p due_ms. @return 1, or 0 when nothing is parked. */
int chaos_init_delay_next(uint64_t *due_ms);

/**
 * @brief Removes one entry due at or before @p now_ms into @p id, @p call, @p answer and
 *        @p traced; call repeatedly to drain. @return 1, or 0 when none is due.
 *
 * @details The call comes back with the answer because an answer can still have work to
 * do in the tracee: a clock read reports the time of the moment it is answered, which
 * means reading the clock and writing the value here (chaos_init_time_commit()).
 */
int chaos_init_delay_pop(
    uint64_t now_ms,
    uint64_t *id,
    chaos_init_call_t *call,
    chaos_init_verdict_t *answer,
    int *traced
);

#endif
