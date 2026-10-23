/**
 * @file chaos_init_core.h
 * @brief `chaos-init` logic that makes no system call: argument parsing, the BPF filter,
 *        the status file text, exit codes, kernel and errno classification.
 *
 * @details
 * `chaos-init` is SECCOMP mode: fault injection for programs LD_PRELOAD cannot reach
 * (static binaries, `CGO_ENABLED=0` Go, `FROM scratch` C). It runs as the container's
 * PID 1, starts the entrypoint as its child (the tracee) under a seccomp filter that
 * routes the selected libraries' system calls to it (SECCOMP_RET_USER_NOTIF), and answers
 * each notification by the same rule files and rule cores the libraries use.
 *
 * Everything here is a pure function of its arguments (plus stat()/access() in
 * chaos_init_find_command()), so the unit tests exercise it without a kernel, a listener
 * or a child. Process handling lives in chaos_init.c.
 *
 * @par Platform
 * x86_64 and aarch64, little-endian only (chaos_init_core.c refuses anything else at
 * compile time). Kernel 5.5+ for SECCOMP_USER_NOTIF_FLAG_CONTINUE.
 */

#ifndef CHAOS_INIT_CORE_H
#define CHAOS_INIT_CORE_H

#include <linux/filter.h>
#include <stddef.h>

/** @name Library bits for --libs (bit order is also the order of `libs=` in the status file) */
/**@{*/
#define CHAOS_INIT_LIB_IO 0x01U
#define CHAOS_INIT_LIB_NET 0x02U
#define CHAOS_INIT_LIB_DNS 0x04U
#define CHAOS_INIT_LIB_TIME 0x08U
#define CHAOS_INIT_LIB_MEMORY 0x10U
#define CHAOS_INIT_LIB_PROCESS 0x20U
/**@}*/

/**
 * @brief sendmsg() flags of the single call that hands the listener from the child to the
 *        supervisor; the filter exempts exactly this call from notification.
 *
 * @details The child installs the filter before it can send the listener, so when net is
 * selected that sendmsg() would itself be notified to a supervisor that has no listener
 * yet: a deadlock. The filter therefore lets through sendmsg() whose fd argument is the
 * handover descriptor and whose flags argument equals this value exactly (low 32 bits of
 * both are compared). MSG_CMSG_CLOEXEC has meaning only for recvmsg(), so no real sender
 * passes this combination. The handover descriptor is the child's socketpair end, whatever
 * number it got; it is O_CLOEXEC and gone once the entrypoint is executed. The exemption
 * itself stays in the filter: a later sendmsg() on a reused descriptor of that number with
 * exactly these flags would also pass unnotified.
 */
#define CHAOS_INIT_HANDOVER_FLAGS (MSG_NOSIGNAL | MSG_CMSG_CLOEXEC)

/** @brief Status file of `chaos-init`: whether SECCOMP mode is active, and if not, why. */
#define CHAOS_INIT_STATUS_PATH "/tmp/.chaos-init.status"

/**
 * @brief Capacity in BPF instructions, and in collected system call numbers, of the filter
 *        buffer. chaos_init_build_filter() returns 0 when the program would not fit.
 */
#define CHAOS_INIT_MAX_FILTER 128U

/** @brief Parsed command line: `chaos-init --libs io,net -- <command> [args...]`. */
typedef struct chaos_init_options
{
    unsigned libs; /**< CHAOS_INIT_LIB_* bits; never 0 after a successful parse. */
    int command;   /**< Index of the command in argv; always 4. */
} chaos_init_options_t;

/**
 * @brief Parses `--libs <name>[,<name>...] -- <command> [args...]`.
 *
 * @details The grammar is fixed positionally: argv[1] `--libs`, argv[2] the list, argv[3]
 * `--`, argv[4] the command. Names: io, net, dns, time, memory, process. dns and time are
 * accepted (one rule set for both modes) but add no system call to the filter: clocks are
 * read through the vDSO and name resolution is a library function, so seccomp never sees
 * either. An empty name (`io,,net`, trailing comma) is unknown.
 *
 * @param options  Output; written only partially on failure.
 * @return 0, or -1 on any deviation from the grammar or an unknown name.
 */
int chaos_init_parse_args(int argc, char **argv, chaos_init_options_t *options);

/**
 * @brief Writes the seccomp BPF program for @p libs into @p out.
 *
 * @details Program shape, in order:
 * 1. `seccomp_data.arch` other than this build's AUDIT_ARCH: ALLOW. The supervisor decodes
 *    only its native ABI; i386 (`int 0x80`) calls pass unfiltered.
 * 2. x86_64 only: nr >= 0x40000000 (x32 ABI): ALLOW.
 * 3. When sendmsg is among the calls: the handover exemption (see CHAOS_INIT_HANDOVER_FLAGS),
 *    otherwise USER_NOTIF for every sendmsg.
 * 4. One JEQ per remaining system call number, each jumping to the trailing USER_NOTIF.
 * 5. ALLOW, then USER_NOTIF.
 *
 * Numbers shared by several libraries (read, readv, write, writev, close) appear once.
 * The tests form a linear JEQ chain of at most CHAOS_INIT_MAX_FILTER - 16 entries; that
 * bound also keeps every forward jump within classic BPF's 8-bit jt/jf offsets.
 *
 * @param handover_fd  The child's descriptor of the handover socketpair.
 * @param out          Output program of @p capacity instructions.
 * @return Number of instructions written, or 0 if @p capacity is too small.
 */
size_t
chaos_init_build_filter(unsigned libs, int handover_fd, struct sock_filter *out, size_t capacity);

/**
 * @brief Converts a waitpid() status to the exit code chaos-init returns: the child's own
 *        code, or 128 + the signal number when a signal killed it (shell convention).
 */
int chaos_init_exit_code(int status);

/**
 * @brief Whether uname() release string @p release is 5.5 or newer, the first kernel with
 *        SECCOMP_USER_NOTIF_FLAG_CONTINUE. Without CONTINUE the supervisor could not let a
 *        call run unchanged.
 * @return 1 if supported; 0 if older, NULL or not of the form `<major>.<minor>...`.
 */
int chaos_init_kernel_supported(const char *release);

/**
 * @brief Whether the errno @p error of a failed SECCOMP_IOCTL_NOTIF_ID_VALID proves that the
 *        notified thread is gone.
 *
 * @details Only ENOENT does. Kernels 5.5 to 5.8 know the ioctl only under its original
 * request number and answer the current one with EINVAL; that and any other error prove
 * nothing. The caller then answers anyway: a reply is addressed by notification id and can
 * never reach another thread, while a notification left unanswered blocks its thread
 * until it is killed.
 *
 * @return 1 for ENOENT, else 0.
 */
int chaos_init_caller_gone(int error);

/**
 * @brief Resolves @p command as execvp() would, before the fork.
 *
 * @details A command containing '/' is taken as given. Otherwise each `:`-separated entry
 * of @p path is tried in order (NULL means "/usr/local/bin:/usr/bin:/bin"; an empty entry
 * means the current directory); the first regular file with execute permission (access()
 * X_OK, i.e. checked against the real uid) wins. chaos-init then runs the result with a
 * single execv(): execvp() would issue one execve() per PATH entry, and only the
 * application's first execve() is exempt from process rules (chaos_init_process_start()).
 *
 * @param out   Receives the path; a candidate that would be truncated is skipped.
 * @return 1 with the path in @p out; 0 when none exists (or none fits); -1 when only
 *         non-executable regular files of that name exist (execvp() reports EACCES).
 */
int chaos_init_find_command(const char *command, const char *path, char *out, size_t size);

/**
 * @brief Human-readable `reason=` text for an errno that prevented installing the filter.
 *
 * @details EINVAL: user notification unavailable (typical under QEMU emulation); ENOSYS:
 * no seccomp; EACCES/EPERM: refused by the container's security settings; ENOTSUP: kernel
 * older than 5.5. On Linux ENOTSUP equals EOPNOTSUPP, which SECCOMP_GET_ACTION_AVAIL
 * returns for an unknown action, so that also reads "kernel older than 5.5". Anything
 * else (EBUSY under another supervisor's listener, for one) is "could not be installed".
 *
 * @return A static string; never NULL.
 */
const char *chaos_init_unsupported_reason(int error);

/**
 * @brief Formats the status file.
 *
 * @details Active (@p reason NULL): `state=active`, `libs=`, `pid=`, plus `mptcp=off` when
 * @p mptcp_off. Unsupported: `state=unsupported`, `reason=`, `libs=`, `pid=`. One
 * `key=value` per line, each newline-terminated; libs are listed in bit order.
 *
 * @return Bytes written (NUL excluded); 0 if @p size is too small (buffer content then
 *         unspecified).
 */
size_t chaos_init_format_status(
    char *buffer, size_t size, unsigned libs, const char *reason, long pid, int mptcp_off
);

/**
 * @brief Computes the application's GODEBUG with Multipath TCP disabled (`multipathtcp=0`)
 *        from its @p current value (NULL when unset).
 *
 * @details Used wherever the kernel offers MPTCP (chaos_init_net_mptcp_unresolvable()): Go
 * 1.24+ listens with MPTCP by default there, and a connection it accepts from a plain TCP
 * client falls back to TCP in a form whose endpoints cannot be resolved, so net rules on it
 * could never match. A
 * `multipathtcp=` setting the user already made (at the start, or after a comma) wins.
 *
 * @return 1 with the new value in @p out; 0 to leave GODEBUG unchanged (user setting
 *         present, or the result does not fit in @p size).
 */
int chaos_init_godebug_mptcp_off(const char *current, char *out, size_t size);

#endif
