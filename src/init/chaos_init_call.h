/**
 * @file chaos_init_call.h
 * @brief `chaos-init`: one notified system call and the supervisor's verdict on it.
 *
 * @details The per-library deciders (chaos_init_<lib>_decide()) turn a chaos_init_call_t
 * into a chaos_init_verdict_t; chaos_init.c turns the verdict into a seccomp reply,
 * possibly after parking it in the delay queue (chaos_init_delay.h).
 */

#ifndef CHAOS_INIT_CALL_H
#define CHAOS_INIT_CALL_H

#include <stdint.h>
#include <sys/types.h>

/** @brief A system call a tracee thread is blocked in, copied from `struct seccomp_notif`. */
typedef struct chaos_init_call
{
    pid_t tid;        /**< Calling thread id in the supervisor's pid namespace (not the tgid). */
    int nr;           /**< System call number of the native ABI. */
    uint64_t args[6]; /**< Raw arguments; pointers are addresses in the tracee. */
} chaos_init_call_t;

/** @brief What the supervisor does with the call. */
typedef enum chaos_init_action
{
    CHAOS_INIT_PASS = 0, /**< Reply SECCOMP_USER_NOTIF_FLAG_CONTINUE: the kernel runs it. */
    CHAOS_INIT_FAIL,     /**< Reply -`error`: returns -1/`error` without running. */
    CHAOS_INIT_DELAY,    /**< Park for `delay_ms`, then answer per chaos_init_delay_answer(). */
    CHAOS_INIT_RETURN    /**< Reply `value` without running (poll-family TIMEOUT: 0). */
} chaos_init_action_t;

/**
 * @brief Verdict of a decider. Zero-initialised plus `action = CHAOS_INIT_PASS` is the
 *        neutral verdict. `delay_ms` is the hold time of a DELAY in milliseconds.
 */
typedef struct chaos_init_verdict
{
    chaos_init_action_t action;
    int error; /**< FAIL, or DELAY that fails when due: positive errno. */
    unsigned delay_ms;
    long value;  /**< RETURN, or DELAY with `returns`: the return value. */
    int returns; /**< DELAY: when due, return `value` instead of running. */
    /** TIMEOUT on a wait: write "nothing ready" into the caller's buffers. Done by
     *  chaos_init_net_commit() only after SECCOMP_IOCTL_NOTIF_ID_VALID confirmed the
     *  thread still waits, so a reused pid is never written to. */
    int clear_ready;
} chaos_init_verdict_t;

#endif
