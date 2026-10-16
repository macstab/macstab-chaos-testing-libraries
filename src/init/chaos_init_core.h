/**
 * @file chaos_init_core.h
 * @brief chaos-init: the logic of the seccomp supervisor that needs no system calls.
 *
 * @details
 * chaos-init is the SECCOMP injection mode for programs LD_PRELOAD cannot reach
 * (statically linked binaries, Go). It runs as the container's PID 1, starts the
 * real entrypoint as its child under a seccomp filter whose matching system calls
 * are passed to it (user notification), and answers each one.
 *
 * This header holds what can be tested without a kernel: argument parsing, the BPF
 * filter, the status file text, the exit code and the kernel version check. The
 * process handling lives in chaos_init.c.
 */

#ifndef CHAOS_INIT_CORE_H
#define CHAOS_INIT_CORE_H

#include <linux/filter.h>
#include <stddef.h>

/** @name Library bits for --libs */
/**@{*/
#define CHAOS_INIT_LIB_IO 0x01U
#define CHAOS_INIT_LIB_NET 0x02U
#define CHAOS_INIT_LIB_DNS 0x04U
#define CHAOS_INIT_LIB_TIME 0x08U
#define CHAOS_INIT_LIB_MEMORY 0x10U
#define CHAOS_INIT_LIB_PROCESS 0x20U
/**@}*/

/**
 * @brief Descriptor the child hands the listener over on.
 *
 * @details The filter is already installed when the child sends the listener, so
 * the one sendmsg() doing it must not be passed to the supervisor that is waiting
 * for it. The filter lets through a sendmsg() on exactly this descriptor with
 * exactly CHAOS_INIT_HANDOVER_FLAGS, a combination no program uses
 * (MSG_CMSG_CLOEXEC only means something to recvmsg()).
 */
#define CHAOS_INIT_HANDOVER_FD 1000
#define CHAOS_INIT_HANDOVER_FLAGS (MSG_NOSIGNAL | MSG_CMSG_CLOEXEC)

/** @brief Where chaos-init reports whether the mode is active. */
#define CHAOS_INIT_STATUS_PATH "/tmp/.chaos-init.status"

/** @brief Room for the longest filter (all libraries); chaos_init_build_filter() checks it. */
#define CHAOS_INIT_MAX_FILTER 128U

/** @brief Parsed command line: `chaos-init --libs io,net -- <command> [args...]`. */
typedef struct chaos_init_options
{
    unsigned libs; /**< CHAOS_INIT_LIB_* bits. */
    int command;   /**< Index of the command in argv. */
} chaos_init_options_t;

/**
 * @brief Parses the command line.
 * @return 0, or -1 when it is not `--libs <names> -- <command>` with known names.
 */
int chaos_init_parse_args(int argc, char **argv, chaos_init_options_t *options);

/**
 * @brief Writes the BPF filter for @p libs into @p out.
 *
 * @details Calls of another architecture pass. The system calls of the libraries
 * are passed to the supervisor (SECCOMP_RET_USER_NOTIF), everything else is allowed,
 * except the one handover sendmsg() (see CHAOS_INIT_HANDOVER_FD).
 *
 * @return Number of instructions, or 0 if @p capacity is too small.
 */
size_t chaos_init_build_filter(unsigned libs, struct sock_filter *out, size_t capacity);

/** @brief Exit code for a waitpid() status: the child's, or 128 + its signal. */
int chaos_init_exit_code(int status);

/** @brief Whether kernel @p release (uname) has user notification with CONTINUE (5.5+). */
int chaos_init_kernel_supported(const char *release);

/**
 * @brief Finds @p command as execvp() would: as given when it holds a '/', else the
 *        first executable regular file of that name in @p path (":"-separated; NULL
 *        means "/usr/local/bin:/usr/bin:/bin"; an empty entry is the current directory).
 *
 * @details chaos-init looks the command up before the fork and executes the result
 * with execv(): execvp() would try one directory after another with execve(), and
 * only the application's first execve is exempt from the process rules.
 *
 * @return 1 with the path in @p out; 0 when there is none (or it does not fit).
 */
int chaos_init_find_command(const char *command, const char *path, char *out, size_t size);

/** @brief Why seccomp could not be installed, for the status file. */
const char *chaos_init_unsupported_reason(int error);

/**
 * @brief Formats the status file: `state=active` when @p reason is NULL, else
 *        `state=unsupported` with the reason.
 * @return Bytes written (NUL excluded), 0 if @p size is too small.
 */
size_t
chaos_init_format_status(char *buffer, size_t size, unsigned libs, const char *reason, long pid);

#endif
