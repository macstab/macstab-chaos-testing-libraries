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

#include <stdint.h>

/** @brief Calls held at once; a call beyond that is not delayed. */
#define CHAOS_INIT_MAX_DELAYED 1024U

/** @brief Parks notification @p id until @p due_ms. @return 0, or -1 when full. */
int chaos_init_delay_add(uint64_t id, uint64_t due_ms);

/** @brief The earliest due time into @p due_ms. @return 0 when nothing is parked. */
int chaos_init_delay_next(uint64_t *due_ms);

/** @brief Removes one call due at @p now_ms into @p id. @return 0 when none is due. */
int chaos_init_delay_pop(uint64_t now_ms, uint64_t *id);

#endif
