/**
 * @file chaos_init_proc.h
 * @brief `chaos-init`: reading a tracee's arguments, descriptors and identity from outside.
 *
 * @details A notification carries only the thread id and six raw arguments. Pointer
 * arguments are dereferenced with process_vm_readv(); descriptors and the working
 * directory are resolved through `/proc/<tid>/...`.
 *
 * @par Access
 * process_vm_readv/writev need PTRACE_MODE_ATTACH_REALCREDS on the target, the /proc fd,
 * cwd and stat entries PTRACE_MODE_READ: both hold for a tracee of the same uid that
 * gained no privilege. Docker's default seccomp profile allows the calls. Yama
 * `ptrace_scope=1` additionally restricts ATTACH to ancestors, which `chaos-init` is as
 * PID 1 but its background copy (chaos_init.c) is not; `ptrace_scope>=2` forbids it
 * outright. A tracee that changes uid becomes unreadable. In each case the reads fail,
 * path and endpoint selectors do not match, and selectors on the operation alone still do.
 *
 * @par TOCTOU
 * Everything read here can change before the kernel acts on the call: another thread can
 * rewrite a path buffer or dup2() over a descriptor. A decision may therefore rest on
 * stale data. This is acceptable for fault injection (the worst case is a fault applied
 * to, or withheld from, the wrong call) and is why chaos-init must never be used as a
 * security boundary.
 */

#ifndef CHAOS_INIT_PROC_H
#define CHAOS_INIT_PROC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Copies @p size bytes at @p address in process @p pid into @p out.
 * @return 0, or -1 with errno set: process_vm_readv()'s errno (EPERM: not readable for
 *         us, ESRCH: gone, EFAULT: unmapped); a short read keeps errno as it was, or sets
 *         EFAULT when it was 0.
 */
int chaos_init_read_memory(pid_t pid, uint64_t address, void *out, size_t size);

/**
 * @brief Copies @p size bytes of @p data to @p address in process @p pid; errno as for
 *        chaos_init_read_memory(). @return 0, or -1.
 */
int chaos_init_write_memory(pid_t pid, uint64_t address, const void *data, size_t size);

/**
 * @brief Copies the NUL-terminated string at @p address of @p pid into @p out.
 *
 * @details Reads in chunks that never cross a 4 KiB boundary, so a string ending just
 * before an unmapped page is read like any other (one process_vm_readv() spanning into the
 * unmapped page would fail).
 *
 * @return Its length (NUL excluded), or -1: unreadable (errno from
 *         chaos_init_read_memory()) or no NUL within @p size bytes (ENAMETOOLONG).
 */
long chaos_init_read_string(pid_t pid, uint64_t address, char *out, size_t size);

/**
 * @brief readlink() of `/proc/<pid>/<name>` (e.g. "cwd", "fd/5"), NUL-terminated; a target
 *        longer than @p size - 1 bytes is silently truncated.
 * @return Its length, or -1 (size 0, path too long, or readlink() failed).
 */
long chaos_init_proc_link(pid_t pid, const char *name, char *out, size_t size);

/**
 * @brief The thread group of thread @p tid and an identity value for the image it runs.
 *
 * @details The identity starts from the start time (clock ticks since boot,
 * `/proc/<tgid>/stat` field 22), which distinguishes a process from a later one that got
 * the same pid. The start of code and stack (fields 26 and 28) are mixed in because
 * execve() keeps pid and start time but maps a new image: the new program is then a new
 * process for the rules, as under LD_PRELOAD. The kernel shows those two fields as 0 to a
 * reader without ptrace access; the identity then reduces to the start time.
 *
 * @param tgid   Output: the thread group id (`/proc/<tid>/status` Tgid).
 * @param start  Output: the identity value; meaningful only for equality.
 * @return 0, or -1 when the thread is gone or /proc is malformed.
 */
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);

/** @brief The parent of process @p pid (`/proc/<pid>/status` PPid); -1 when it is gone. */
pid_t chaos_init_parent_of(pid_t pid);

#endif
