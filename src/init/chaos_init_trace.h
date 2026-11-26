/**
 * @file chaos_init_trace.h
 * @brief Register access for a tracee stopped at a seccomp trace stop.
 *
 * @details A `SECCOMP_RET_USER_NOTIF` reply can fail a call, delay it or return a value,
 * but it cannot reach the tracee's registers. The data effects need exactly that: TORN and
 * TRICKLE shorten a length argument before the kernel reads it, DROP skips a call and
 * reports its count, CORRUPT acts on what the call wrote. Those arrive instead as a
 * `SECCOMP_RET_TRACE` stop (`PTRACE_EVENT_SECCOMP`), where the registers are readable and
 * writable.
 *
 * This module is the whole architecture-dependent part of that: which register holds the
 * system call number, which hold the arguments, and which carries the return value.
 * Everything above it works in terms of "argument 2" and "the return value".
 *
 * | | aarch64 | x86_64 |
 * |---|---|---|
 * | number | `x8` (`regs[8]`) | `orig_rax` |
 * | arguments | `x0`-`x5` (`regs[0..5]`) | `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` |
 * | return | `x0` (`regs[0]`) | `rax` |
 *
 * @par Acting after the call
 * An effect on what a call *returned* -- CORRUPT flips a bit of the bytes a read
 * delivered -- cannot be decided at the entry stop, because the length is not known yet.
 * Continuing the entry stop with `PTRACE_SYSCALL` instead of `PTRACE_CONT` produces a
 * second stop once the kernel is done, where chaos_init_trace_result() reads what the call
 * returned and the tracee's memory holds the bytes. That stop is a syscall-stop, told from
 * a signal stop by `PTRACE_O_TRACESYSGOOD`, which makes the kernel report it as
 * `SIGTRAP | 0x80`. It is continued with `PTRACE_CONT`, so the thread is not stopped again
 * at its next system call.
 *
 * The call itself has to be carried from the entry stop (chaos_init_trace_park()): on
 * aarch64 the result comes back in `x0`, the register that held the first argument, so at
 * the exit stop the descriptor is gone. Arguments 1 and up survive on both architectures,
 * but one of them being enough is not something to rely on.
 *
 * @par Skipping a call
 * Setting the number to -1 makes the kernel skip the call, and the return register is then
 * what the tracee receives. That is how DROP reports a count it never wrote and how a
 * failure is injected from this path. The number is *not* changed into another call: the
 * kernel refuses that at a seccomp stop.
 *
 * How the number is written differs, and only this file knows: x86_64 takes it from
 * `orig_rax` in the ordinary register block, while **aarch64 ignores a changed `x8`** and
 * reads the number from its own `NT_ARM_SYSTEM_CALL` regset. Writing `regs[8]` there looks
 * like it works and does nothing, which is why chaos_init_trace_skip() performs the write
 * itself instead of only preparing the block.
 *
 * @par Module: chaos-init
 * @par Stability: private / internal
 */

#ifndef CHAOS_INIT_TRACE_H
#define CHAOS_INIT_TRACE_H

#include "chaos_init_call.h"

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

/** @brief Arguments a system call can carry. */
#define CHAOS_INIT_TRACE_ARGS 6U

/** @brief One tracee's register file, as this module reads and writes it. */
typedef struct chaos_init_trace_regs
{
    /** Opaque architecture register block; read with chaos_init_trace_read(). */
    unsigned char raw[512];
    size_t size; /**< Bytes of `raw` the kernel filled. */
} chaos_init_trace_regs_t;

/**
 * @brief Reads @p tid's registers at a stop.
 *
 * @param tid   Stopped tracee.
 * @param regs  Output.
 * @return 0 on success; -1 with errno (the thread died, or is not stopped).
 */
int chaos_init_trace_read(pid_t tid, chaos_init_trace_regs_t *regs);

/**
 * @brief Writes @p regs back to @p tid.
 *
 * @param tid   Stopped tracee.
 * @param regs  Registers, as read and then modified.
 * @return 0 on success; -1 with errno.
 */
int chaos_init_trace_write(pid_t tid, const chaos_init_trace_regs_t *regs);

/** @brief The system call number @p regs stopped on. */
long chaos_init_trace_number(const chaos_init_trace_regs_t *regs);

/**
 * @brief What the call returned, read at a syscall-exit stop.
 *
 * @details The same register the ABI returns in, which on both architectures is also the
 * one that held the first argument at entry. A negative value is the kernel's `-errno`.
 *
 * @param regs  Registers read at the exit stop.
 */
long chaos_init_trace_result(const chaos_init_trace_regs_t *regs);

/**
 * @brief Remembers @p call until its thread reaches the exit stop.
 *
 * @details One entry per thread, because a thread is in one system call at a time; a
 * second park for the same thread replaces the first. Parking is what makes the exit stop
 * able to name the call: see the note on `x0` above.
 *
 * @param call  The call as the entry stop saw it; copied.
 * @return 0, or -1 when more threads are inside a traced call than the table holds, in
 *         which case the caller runs the call without the effect.
 */
int chaos_init_trace_park(const chaos_init_call_t *call);

/**
 * @brief Takes @p tid's parked call back out, if it has one.
 *
 * @param tid   The thread at its exit stop.
 * @param call  Output; untouched when nothing was parked.
 * @return 1 when a call was parked for @p tid, else 0.
 */
int chaos_init_trace_unpark(pid_t tid, chaos_init_call_t *call);

/**
 * @brief Whether @p status is a syscall-stop rather than a signal or event stop.
 *
 * @details True for `SIGTRAP | 0x80`, which the kernel reports only with
 * `PTRACE_O_TRACESYSGOOD` set. Without that option a syscall-stop is indistinguishable
 * from an ordinary SIGTRAP, so the option is not optional for anything that waits for one.
 */
int chaos_init_trace_is_syscall_stop(int status);

/**
 * @brief Argument @p index of the stopped call.
 *
 * @param regs   Registers read at the stop.
 * @param index  0 to CHAOS_INIT_TRACE_ARGS - 1; anything else yields 0.
 */
uint64_t chaos_init_trace_arg(const chaos_init_trace_regs_t *regs, unsigned index);

/**
 * @brief Replaces argument @p index in @p regs; the caller writes them back.
 *
 * @param regs   Registers read at the stop.
 * @param index  0 to CHAOS_INIT_TRACE_ARGS - 1; anything else is a no-op.
 * @param value  New value.
 */
void chaos_init_trace_set_arg(chaos_init_trace_regs_t *regs, unsigned index, uint64_t value);

/**
 * @brief Makes @p tid skip the call it stopped on and return @p value.
 *
 * @details Sets the number to -1, which the kernel skips, and the return register to
 * @p value, then writes both back. A negative value is what the tracee sees as -1 with
 * that errno, exactly as a failing call reports it. The caller does not call
 * chaos_init_trace_write() afterwards; this does it.
 *
 * @param tid    Stopped tracee.
 * @param regs   Registers read at the stop; modified.
 * @param value  Return value for the tracee.
 * @return 0 on success; -1 with errno.
 */
int chaos_init_trace_skip(pid_t tid, chaos_init_trace_regs_t *regs, long value);

/**
 * @brief Makes @p tid run @p number with @p args in place of the call it stopped on.
 *
 * @details The arguments go into the argument registers and the number where the kernel
 * reads it for dispatch, so the thread runs another call entirely when it is continued
 * with `PTRACE_SYSCALL`. The seccomp filter has already run for this entry, so the
 * substituted call is not filtered again and stops only on its way out.
 *
 * The caller does not call chaos_init_trace_write() afterwards; this does it.
 *
 * @param tid     Stopped tracee.
 * @param regs    Registers read at the stop; modified.
 * @param number  System call to run instead.
 * @param args    CHAOS_INIT_TRACE_ARGS arguments for it.
 * @return 0 on success; -1 with errno.
 */
int chaos_init_trace_instead(
    pid_t tid, chaos_init_trace_regs_t *regs, long number, const uint64_t *args
);

/**
 * @brief Sets what the finished call at @p tid's exit stop returns.
 *
 * @details Only the return register, because at an exit stop the call is over and its
 * number no longer decides anything. The caller does not call chaos_init_trace_write()
 * afterwards; this does it.
 *
 * @param tid    Stopped tracee.
 * @param regs   Registers read at the exit stop; modified.
 * @param value  Return value for the tracee.
 * @return 0 on success; -1 with errno.
 */
int chaos_init_trace_set_result(pid_t tid, chaos_init_trace_regs_t *regs, long value);

/**
 * @brief Where in the tracee a substituted call's argument can be put.
 *
 * @details Below the stack pointer, which the stopped thread's own frame does not use: the
 * kernel runs a system call on its own stack, and nothing in the tracee runs between the
 * stop and the substituted call. The area is dead again as soon as that call returns.
 *
 * @param regs  Registers read at the stop.
 * @return The address, or 0 when the registers were never read.
 */
uint64_t chaos_init_trace_scratch(const chaos_init_trace_regs_t *regs);

/**
 * @brief Puts @p number and @p args back and steps @p tid onto the instruction that
 *        issued them, so the call it was stopped at runs after all.
 *
 * @details Used at the exit stop of a substituted call that had to run *before* the
 * original one rather than in its place. The program counter goes back by one system call
 * instruction, so the thread issues the call again -- which the filter answers again, and
 * the caller has to let that second stop through (chaos_init_trace_pass()).
 *
 * The number goes into the register the instruction reads, not the one the kernel copies
 * it to: this call has not been dispatched yet.
 *
 * The caller does not call chaos_init_trace_write() afterwards; this does it.
 *
 * @return 0 on success; -1 with errno.
 */
int chaos_init_trace_resume(
    pid_t tid, chaos_init_trace_regs_t *regs, long number, const uint64_t *args
);

/**
 * @brief Remembers that @p tid's next stop is a call the supervisor already decided.
 *
 * @details A call put back by chaos_init_trace_resume() stops again, because seccomp
 * filters it like any other. Deciding it twice would count a second hit and loop, so the
 * mark says to let it run.
 *
 * @return 0, or -1 when the table is full.
 */
int chaos_init_trace_pass(pid_t tid);

/**
 * @brief Whether @p tid's stop is such a call, forgetting the mark if it is.
 *
 * @return 1 when the stop is to be let through, else 0.
 */
int chaos_init_trace_passing(pid_t tid);

/**
 * @brief Promised value that means "put the original call back", not "return this".
 *
 * @details No system call returns it, so it cannot collide with a real promise.
 */
#define CHAOS_INIT_TRACE_AGAIN LONG_MIN

/**
 * @brief Remembers the value @p tid's next exit stop has to report to the tracee.
 *
 * @details What a substituted call (chaos_init_trace_instead()) returns is the other
 * call's business, not the tracee's: the promise is the value the original call would
 * have had. One per thread, as parking is.
 *
 * @return 0, or -1 when the table is full, in which case the caller must not substitute.
 */
int chaos_init_trace_promise(pid_t tid, long value);

/**
 * @brief Takes @p tid's promised value, if it has one.
 *
 * @param tid    The thread at its exit stop.
 * @param value  Output; untouched when nothing was promised.
 * @return 1 when a value was promised for @p tid, else 0.
 */
int chaos_init_trace_claim(pid_t tid, long *value);

/**
 * @brief Drops every entry a thread held in the three per-thread tables.
 *
 * @details Called for each reaped process. A thread killed while continued towards the
 * exit stop of a traced call -- the stop that would have consumed its entry -- never
 * reaches it, so without this the tables fill up: after 256 such threads every CORRUPT,
 * DUP, write DROP and close RESET rule stops firing for the rest of the container's life,
 * with nothing said about it. Before that, a reused thread id claims the dead thread's
 * promise and has an unrelated call's return value overwritten.
 *
 * @param tid  Thread that ended.
 */
void chaos_init_trace_forget(pid_t tid);

#endif
