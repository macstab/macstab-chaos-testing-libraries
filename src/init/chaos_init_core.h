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
 * @brief Flags of the sendmsg() the child hands the listener over with.
 *
 * @details The filter is already installed when the child sends the listener, so
 * the one sendmsg() doing it must not be passed to the supervisor that is waiting
 * for it. The filter lets through a sendmsg() on exactly the handover descriptor
 * with exactly these flags, a combination no program uses (MSG_CMSG_CLOEXEC only
 * means something to recvmsg()). The descriptor is the child's end of the
 * socketpair, whatever its number; it is closed when the command is executed.
 */
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
 * except the one handover sendmsg() on @p handover_fd (see CHAOS_INIT_HANDOVER_FLAGS).
 *
 * @return Number of instructions, or 0 if @p capacity is too small.
 */
size_t
chaos_init_build_filter(unsigned libs, int handover_fd, struct sock_filter *out, size_t capacity);

/** @brief Exit code for a waitpid() status: the child's, or 128 + its signal. */
int chaos_init_exit_code(int status);

/** @brief Whether kernel @p release (uname) has user notification with CONTINUE (5.5+). */
int chaos_init_kernel_supported(const char *release);

/**
 * @brief Whether a failed NOTIF_ID_VALID check (@p error) says the notified thread
 *        is gone.
 *
 * @details Only ENOENT does. Any other error proves nothing (5.5 to 5.8 know the
 * request only under its older number and answer EINVAL), and the call is answered
 * anyway: a reply goes by notification id and never reaches another thread, while
 * one left out keeps the thread blocked for good.
 */
int chaos_init_caller_gone(int error);

/**
 * @brief Finds @p command as execvp() would: as given when it holds a '/', else the
 *        first executable regular file of that name in @p path (":"-separated; NULL
 *        means "/usr/local/bin:/usr/bin:/bin"; an empty entry is the current directory).
 *
 * @details chaos-init looks the command up before the fork and executes the result
 * with execv(): execvp() would try one directory after another with execve(), and
 * only the application's first execve is exempt from the process rules.
 *
 * @return 1 with the path in @p out; 0 when there is none (or it does not fit); -1
 *         when the only files of that name cannot be executed (execvp(): EACCES).
 */
int chaos_init_find_command(const char *command, const char *path, char *out, size_t size);

/** @brief Why seccomp could not be installed, for the status file. */
const char *chaos_init_unsupported_reason(int error);

/**
 * @brief Formats the status file: `state=active` when @p reason is NULL, else
 *        `state=unsupported` with the reason; `mptcp=off` when @p mptcp_off.
 * @return Bytes written (NUL excluded), 0 if @p size is too small.
 */
size_t chaos_init_format_status(
    char *buffer, size_t size, unsigned libs, const char *reason, long pid, int mptcp_off
);

/**
 * @brief The application's GODEBUG with Multipath TCP off (`multipathtcp=0`), from
 *        its @p current value (NULL when unset).
 *
 * @details For hosts whose kernel offers MPTCP without letting its sockets be
 * looked up (no mptcp_diag): Go listens with MPTCP there by default from 1.24, and
 * net rules on such sockets could not match. A multipathtcp setting of the user's
 * own is kept.
 *
 * @return 1 with the new value in @p out; 0 to leave GODEBUG as it is.
 */
int chaos_init_godebug_mptcp_off(const char *current, char *out, size_t size);

#endif
