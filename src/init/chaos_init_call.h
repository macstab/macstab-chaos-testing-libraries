/**
 * @file chaos_init_call.h
 * @brief chaos-init: one notified system call and the supervisor's answer to it.
 */

#ifndef CHAOS_INIT_CALL_H
#define CHAOS_INIT_CALL_H

#include <stdint.h>
#include <sys/types.h>

/** @brief A system call a supervised thread is waiting in. */
typedef struct chaos_init_call
{
    pid_t tid;        /**< The calling thread (not its process). */
    int nr;           /**< System call number of this architecture. */
    uint64_t args[6]; /**< Raw arguments; pointers are the thread's addresses. */
} chaos_init_call_t;

/** @brief What happens to the call. */
typedef enum chaos_init_action
{
    CHAOS_INIT_PASS = 0, /**< The kernel runs it unchanged. */
    CHAOS_INIT_FAIL,     /**< It returns -1 with `error`, without running. */
    CHAOS_INIT_DELAY,    /**< It runs unchanged after `delay_ms`. */
    CHAOS_INIT_RETURN    /**< It returns `value` without running (poll TIMEOUT: 0). */
} chaos_init_action_t;

typedef struct chaos_init_verdict
{
    chaos_init_action_t action;
    int error;
    unsigned delay_ms;
    long value;
} chaos_init_verdict_t;

#endif
