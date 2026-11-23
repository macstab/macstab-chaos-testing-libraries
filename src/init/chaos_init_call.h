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
    CHAOS_INIT_RETURN,   /**< Reply `value` without running (poll-family TIMEOUT: 0). */
    CHAOS_INIT_SHORTEN,  /**< Run it with argument `arg_index` replaced by `value` (TORN). */
    CHAOS_INIT_AFTER     /**< Run it, then decide again with its result (CORRUPT). */
} chaos_init_action_t;

/**
 * @brief Verdict of a decider. Zero-initialised plus `action = CHAOS_INIT_PASS` is the
 *        neutral verdict. `delay_ms` is the hold time of a DELAY in milliseconds.
 *
 * @par Deciding after the call
 * CHAOS_INIT_AFTER means the effect depends on what the call returned, which the entry
 * stop cannot know: the thread is continued into its syscall-exit stop and the deciders
 * are asked again, this time with the result. Nothing is parked in between -- the kernel
 * saves the argument registers at entry and restores them on return, so the exit stop
 * reads the same descriptor, buffer and count the entry stop saw, and selects the same
 * rule. No draw happens at the entry stop for such an effect, so a call that returns
 * nothing to change counts no hit, exactly as in the library.
 *
 * @par Which verdicts reach which path
 * A notification reply can PASS, FAIL, DELAY or RETURN. SHORTEN needs the tracee's
 * registers and therefore only arises for a system call the filter answers with
 * `SECCOMP_RET_TRACE`; on that path every other verdict is applied through the registers
 * too, because a number cannot be notified and traced at once
 * ([docs/development/SECCOMP-PTRACE.md](../../docs/development/SECCOMP-PTRACE.md)).
 */
typedef struct chaos_init_verdict
{
    chaos_init_action_t action;
    int error; /**< FAIL, or DELAY that fails when due: positive errno. */
    unsigned delay_ms;
    long value;  /**< RETURN, or DELAY with `returns`: the return value. SHORTEN: the count. */
    int returns; /**< DELAY: when due, return `value` instead of running. */
    /**
     * SHORTEN: which argument `value` replaces. Only a call that reports its byte count in
     * a register can be shortened, so the index is the one the decode table names; the
     * vectored forms carry their count in memory and are never shortened.
     */
    unsigned arg_index;
    /** TIMEOUT on a wait: write "nothing ready" into the caller's buffers. Done by
     *  chaos_init_net_commit() only after SECCOMP_IOCTL_NOTIF_ID_VALID confirmed the
     *  thread still waits, so a reused pid is never written to. */
    int clear_ready;
} chaos_init_verdict_t;

#endif
