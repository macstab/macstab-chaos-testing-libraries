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
    CHAOS_INIT_AFTER,    /**< Run it, then decide again with its result (CORRUPT). */
    CHAOS_INIT_INSTEAD,  /**< Run `instead_nr`(`instead_args`), then report `value` (DROP). */
    CHAOS_INIT_BEFORE    /**< Run `instead_nr`(`instead_args`) first, then the call (RESET). */
} chaos_init_action_t;

/**
 * @brief Verdict of a decider. Zero-initialised plus `action = CHAOS_INIT_PASS` is the
 *        neutral verdict. `delay_ms` is the hold time of a DELAY in milliseconds.
 *
 * @par Deciding after the call
 * CHAOS_INIT_AFTER means the effect depends on what the call returned, which the entry
 * stop cannot know: the thread is continued into its syscall-exit stop and the deciders
 * are asked again, this time with the result. The call is carried there in the parking
 * table (chaos_init_trace_park()), because the result arrives in the register that held
 * the first argument on aarch64. No draw happens at the entry stop for such an effect, so
 * a call that returns nothing to change counts no hit, exactly as in the library.
 *
 * @par Running another call instead, or first
 * CHAOS_INIT_INSTEAD replaces the call with the one in `instead_nr` and `instead_args`,
 * which is how an effect that needs a second system call to keep the descriptor
 * consistent is applied from outside: a dropped `write` has to move the file offset on by
 * as much as it claims to have written. The tracee is told `value`, not what the
 * substituted call returned.
 *
 * CHAOS_INIT_BEFORE runs that call and then the original one: `close:RESET` needs a
 * `setsockopt(SO_LINGER)` to take effect on the socket the close then aborts. Its
 * argument is in memory, so `instead_data` is put into the tracee's stack scratch and its
 * address goes into argument `instead_arg`. The original call is put back and stops once
 * more, which the supervisor lets through rather than deciding twice.
 *
 * @par Which verdicts reach which path
 * A notification reply can PASS, FAIL, DELAY or RETURN. SHORTEN, AFTER and INSTEAD need
 * the tracee's registers and therefore only arise for a system call the filter answers
 * with `SECCOMP_RET_TRACE`; on that path every other verdict is applied through the
 * registers too, because a number cannot be notified and traced at once
 * ([docs/development/SECCOMP-PTRACE.md](../../docs/development/SECCOMP-PTRACE.md)).
 */
typedef struct chaos_init_verdict
{
    chaos_init_action_t action;
    int error; /**< FAIL, or DELAY that fails when due: positive errno. */
    unsigned delay_ms;
    long value;      /**< RETURN, or DELAY with `returns`: the return value. SHORTEN: the count. */
    int returns;     /**< DELAY: when due, return `value` instead of running. */
    long instead_nr; /**< INSTEAD, BEFORE: the system call to run in its place or first. */
    uint64_t instead_args[6];      /**< INSTEAD, BEFORE: that call's arguments. */
    unsigned char instead_data[8]; /**< BEFORE: bytes for the tracee's scratch. */
    unsigned instead_size;         /**< BEFORE: how many of them; 0 when it needs none. */
    unsigned instead_arg;          /**< BEFORE: the argument the scratch address goes into. */
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
    /** A clock read the supervisor answers itself: chaos_init_time_commit() reads the
     *  clock, applies the effect and writes the value, at the moment the answer goes
     *  out -- so a delayed read reports the time after its delay. */
    int writes_time;
} chaos_init_verdict_t;

#endif
