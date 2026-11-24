/**
 * @file chaos_init_vdso.h
 * @brief `chaos-init`: making a tracee read the clock through the kernel.
 *
 * @details `clock_gettime`, `gettimeofday` and `time` are served from the vDSO, a page
 * the kernel maps into every process: the C library and the Go runtime look the symbols
 * up there at startup and call them directly, without a system call. No filter sees such
 * a read, which is why time rules had no effect in SECCOMP mode at all.
 *
 * The way in is the lookup, not the code: a symbol whose name no longer matches is not
 * found, and every one of those runtimes then falls back to the system call it carries
 * for exactly that case (glibc's `INLINE_VSYSCALL`, musl's `__vdsosym`, Go's
 * `vdsoClockgettimeSym`). So the supervisor renames the time symbols in the tracee's own
 * copy of the mapping, and from then on the clock is read through the kernel, where the
 * filter and the deciders reach it.
 *
 * @par Why this and not a patched vDSO
 * Rewriting the vDSO's code would keep the reads cheap (no system call), at the price of
 * hand-written machine code per architecture, a state page in the tracee and a copy of
 * the kernel's timekeeping arithmetic. Renaming three strings costs one write per
 * `execve` and no architecture-specific code at all. The price is paid per clock read of
 * a process under a time rule, which is measured in
 * [docs/development/SECCOMP-PTRACE.md](../../docs/development/SECCOMP-PTRACE.md).
 *
 * @par When
 * At the `PTRACE_EVENT_EXEC` stop, before the new image has run one instruction and so
 * before it has looked anything up. A `fork` child inherits the renamed mapping; a child
 * that execs gets a fresh vDSO and its own stop.
 *
 * @par Access
 * The vDSO is mapped read-only and executable. `process_vm_writev()` cannot write it, but
 * `/proc/<pid>/mem` can (`FOLL_FORCE`), and because the mapping is private the write
 * copies the page for that process alone: no other process in the container, and no other
 * container, sees the renamed symbols. A process that is not dumpable, or has changed
 * user, cannot be written and keeps its vDSO -- its clock reads then stay invisible, which
 * is reported rather than passed over (`state=degraded`).
 *
 * @par Module: chaos-init
 * @par Stability: private / internal
 */

#ifndef CHAOS_INIT_VDSO_H
#define CHAOS_INIT_VDSO_H

#include <sys/types.h>

/**
 * @brief Renames the time symbols of @p pid's vDSO so lookups by name fail.
 *
 * @details Reads `/proc/<pid>/auxv` for `AT_SYSINFO_EHDR`, walks the ELF header and the
 * dynamic segment to the symbol and string tables, and overwrites the first byte of each
 * time symbol's name. `__kernel_rt_sigreturn` and `clock_getres` are left alone: the
 * first is how a signal handler returns, the second reads no clock.
 *
 * @param pid  A stopped tracee.
 * @return How many symbols were renamed (0 when the process has no vDSO, which is
 *         possible), or -1 when it could not be read or written.
 */
int chaos_init_vdso_blind(pid_t pid);

#endif
