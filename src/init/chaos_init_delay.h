/**
 * @file chaos_init_delay.h
 * @brief chaos-init: calls held back by a LATENCY rule until they are due.
 *
 * @details The supervisor answers notifications one after another; a delayed call
 * is parked here and continued when its time comes, so the other threads of the
 * application are not delayed with it.
 */

#ifndef CHAOS_INIT_DELAY_H
#define CHAOS_INIT_DELAY_H

#include "chaos_init_call.h"

#include <stdint.h>

/** @brief Calls held at once; a call beyond that is not delayed. */
#define CHAOS_INIT_MAX_DELAYED 1024U

/**
 * @brief Parks notification @p id of @p call until @p due_ms; then it fails with
 *        @p error, or runs when @p error is 0. @return 0, or -1 when full.
 */
int chaos_init_delay_add(uint64_t id, const chaos_init_call_t *call, uint64_t due_ms, int error);

/**
 * @brief Takes over a parked call that came back as notification @p id.
 *
 * @details Before Linux 5.19 a signal interrupts a call waiting for its answer;
 * the kernel restarts it as a new notification and the parked one can no longer
 * be answered. A thread is in one system call at a time, so a parked entry of the
 * same thread with the same call is that call: it is answered under the new id at
 * its original due time.
 *
 * @return 1 when @p call was parked (now under @p id), 0 otherwise.
 */
int chaos_init_delay_resume(const chaos_init_call_t *call, uint64_t id);

/** @brief The earliest due time into @p due_ms. @return 0 when nothing is parked. */
int chaos_init_delay_next(uint64_t *due_ms);

/** @brief Removes one call due at @p now_ms into @p id and @p error. @return 0 when none is due. */
int chaos_init_delay_pop(uint64_t now_ms, uint64_t *id, int *error);

#endif
