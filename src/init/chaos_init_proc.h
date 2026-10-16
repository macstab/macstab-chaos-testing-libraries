/**
 * @file chaos_init_proc.h
 * @brief chaos-init: what a supervised process passed and who it is.
 *
 * @details A notification carries the calling thread's id and its raw arguments.
 * Pointers in them are read from the thread's memory (process_vm_readv, allowed
 * for a process of the same user under Docker's default profile); descriptors and
 * the working directory are resolved through /proc.
 */

#ifndef CHAOS_INIT_PROC_H
#define CHAOS_INIT_PROC_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Copies @p size bytes at @p address of process @p pid into @p out.
 * @return 0, or -1 with errno set (EPERM: the process is not readable for us).
 */
int chaos_init_read_memory(pid_t pid, uint64_t address, void *out, size_t size);

/**
 * @brief Copies @p size bytes of @p data to @p address of process @p pid.
 * @return 0, or -1 with errno set.
 */
int chaos_init_write_memory(pid_t pid, uint64_t address, const void *data, size_t size);

/**
 * @brief Copies the NUL-terminated string at @p address of @p pid into @p out.
 *
 * @details Reads page by page, so a string that ends just before an unmapped page
 * is read like any other.
 *
 * @return Its length, or -1 (unreadable, or not terminated within @p size bytes).
 */
long chaos_init_read_string(pid_t pid, uint64_t address, char *out, size_t size);

/**
 * @brief readlink() of `/proc/<pid>/<name>` (e.g. "cwd", "fd/5"), NUL-terminated.
 * @return Its length, or -1.
 */
long chaos_init_proc_link(pid_t pid, const char *name, char *out, size_t size);

/**
 * @brief The process (thread group) thread @p tid belongs to, and its start time.
 *
 * @details The start time (clock ticks since boot, /proc/<pid>/stat field 22)
 * tells a process from a later one that got the same pid.
 *
 * @return 0, or -1 when the thread is gone.
 */
int chaos_init_process_of(pid_t tid, pid_t *tgid, uint64_t *start);

#endif
