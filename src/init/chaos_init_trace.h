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

#endif
