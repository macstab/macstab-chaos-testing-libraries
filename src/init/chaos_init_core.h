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
#include <stdint.h>

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
 * `--`, argv[4] the command. Names: io, net, dns, time, memory, process. dns is accepted
 * (one rule set for both modes) but adds no system call to the filter: name resolution is
 * a library function, so seccomp never sees it. An empty name (`io,,net`, trailing comma)
 * is unknown.
 *
 * @param options  Output; written only partially on failure.
 * @return 0, or -1 on any deviation from the grammar or an unknown name.
 */
int chaos_init_parse_args(int argc, char **argv, chaos_init_options_t *options);

/**
 * @brief The part of the filter that comes from the rule files rather than from a table.
 *
 * @details Two libraries decide what to notify from what their rules say. **time**: a
 * clock read is served from the vDSO, so the filter only ever sees one once the tracee's
 * lookups have been made to fail (chaos_init_vdso.h) -- and then it sees every one of
 * them. `clock_gettime` carries the clock in its first argument, so the filter tests it
 * and notifies only the clocks a rule names, which leaves a monotonic read untouched while
 * a rule works on the wall clock; an empty clock list means every clock, which is what a
 * rule without one asks for. **dns**: the sends a resolver makes, which are worth a
 * notification only while a rule can act on one (chaos_init_dns_calls()).
 */
typedef struct chaos_init_rule_filter
{
    const long *calls;  /**< Numbers to notify: chaos_init_dns_calls() and
                             chaos_init_time_calls() together. */
    size_t call_count;  /**< Entries in @c calls. */
    const long *clocks; /**< Clock ids for `clock_gettime` (chaos_init_time_clocks()). */
    size_t clock_count; /**< Entries in @c clocks; 0 means every clock. */
} chaos_init_rule_filter_t;

/**
 * @brief Writes the seccomp BPF program for @p libs into @p out.
 *
 * @details Program shape, in order:
 * 1. `seccomp_data.arch` other than this build's AUDIT_ARCH: ALLOW. The supervisor decodes
 *    only its native ABI; i386 (`int 0x80`) calls pass unfiltered.
 * 2. x86_64 only: nr >= 0x40000000 (x32 ABI): ALLOW.
 * 3. When sendmsg is among the calls: the handover exemption (see CHAOS_INIT_HANDOVER_FLAGS),
 *    otherwise USER_NOTIF for every sendmsg.
 * 4. One JEQ per traced number, each jumping to the trailing TRACE.
 * 5. One JEQ per remaining system call number, each jumping to the trailing USER_NOTIF.
 * 6. ALLOW, USER_NOTIF, and TRACE when anything is traced.
 *
 * Numbers shared by several libraries (read, readv, write, writev, close) appear once.
 * The tests form a linear JEQ chain of at most CHAOS_INIT_MAX_FILTER - 17 entries; that
 * bound also keeps every forward jump within classic BPF's 8-bit jt/jf offsets.
 *
 * @par Why two groups
 * A notification reply can fail a call, delay it or return a value, but cannot reach the
 * tracee's registers, which the data effects need (TORN shortens a length, CORRUPT acts
 * after the call). Those need `SECCOMP_RET_TRACE` and a ptrace stop. The two cannot be
 * combined per call: across stacked filters USER_NOTIF outranks TRACE, so a notified
 * number can never also be traced, and every number belongs to exactly one group. A
 * traced number therefore carries *all* of its effects through ptrace, errno and latency
 * included. Details and the measurements behind the choice:
 * [docs/development/SECCOMP-PTRACE.md](../../docs/development/SECCOMP-PTRACE.md).
 *
 * @param handover_fd   The child's descriptor of the handover socketpair.
 * @param traced        Numbers to answer with TRACE, read only when @p traced_count is
 *                      above 0, so NULL with 0 builds the program this supervisor built
 *                      before traced effects existed.
 * @param traced_count  Entries in @p traced.
 * @param clock         The time rules' calls and clocks, or NULL when no time rule is
 *                      loaded (chaos_init_rule_filter_t).
 * @param out           Output program of @p capacity instructions.
 * @return Number of instructions written, or 0 if @p capacity is too small.
 */
size_t chaos_init_build_filter(
    unsigned libs,
    int handover_fd,
    const long *traced,
    size_t traced_count,
    const chaos_init_rule_filter_t *clock,
    struct sock_filter *out,
    size_t capacity
);

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
 * @p mptcp_off, `vdso=failed` when @p vdso_failed and `unreadable=yes` when
 * @p unreadable. Unsupported: `state=unsupported`, `reason=`, `libs=`, `pid=`. One
 * `key=value` per line, each newline-terminated; libs are listed in bit order.
 *
 * `vdso=failed` says that an image kept its vDSO (chaos_init_vdso.h), so its clock reads
 * never reach the filter and time rules do nothing for it. `unreadable=yes` says the
 * kernel refused a look into a process (chaos_init_unreadable()), so path and endpoint
 * selectors did not match it. Both are written again when they happen, after the
 * application has started.
 *
 * @return Bytes written (NUL excluded); 0 if @p size is too small (buffer content then
 *         unspecified).
 */
size_t chaos_init_format_status(
    char *buffer,
    size_t size,
    unsigned libs,
    const char *reason,
    long pid,
    int mptcp_off,
    int vdso_failed,
    int unreadable
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

/**
 * @brief The process seed a library starts with: `CHAOS_SEED` from the environment, else
 *        64 random bits.
 *
 * @details Same contract as under `LD_PRELOAD` (see the libraries' internal headers), so a
 * test reproduces the same faults in either mode: `CHAOS_SEED=<decimal u64>` fixes every
 * decision, nothing else does. A malformed or out-of-range value is ignored rather than
 * refused -- the seed decides which faults fire, not whether the rules are valid.
 *
 * Only the libraries whose draws follow from the rule and the evaluation number honour it
 * so far; the rest still mix a thread id into their per-thread generator, where a seed
 * promises nothing.
 *
 * @return The seed.
 */
uint64_t chaos_init_seed(void);

/**
 * @brief Records the system calls the installed filter answers with TRACE.
 *
 * @details A seccomp filter cannot be changed once installed, so this set is fixed for the
 * life of the container while the rule file is not: a reload can add an effect that needs
 * a trace stop the filter does not provide. Without knowing the set, the deciders produce
 * a verdict only a trace stop can carry, the notification path answers CONTINUE, and a
 * hit is reported for a fault that never happened. Called once, after the handover.
 *
 * @param calls  Numbers to remember; NULL or @p count 0 records an empty set.
 * @param count  How many, truncated to what the store holds.
 */
void chaos_init_traced_set(const long *calls, size_t count);

/**
 * @brief Whether the installed filter answers @p nr with TRACE.
 *
 * @return 1 when it does, else 0 -- including when no set was recorded, which is the case
 *         for a supervisor that installed no TRACE instruction at all.
 */
int chaos_init_traced(long nr);

#endif
