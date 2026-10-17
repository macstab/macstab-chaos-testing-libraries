/**
 * @file chaos_io_wrappers.h
 * @brief Lookups shared by the libchaos-io wrapper units: descriptor-to-rule and
 *        (dirfd, path)-to-matchable-path.
 *
 * @details
 * The wrappers are split over five units (open, rw, sync, stdio, fsops), but every
 * descriptor-based wrapper must resolve and match the same way, and every
 * (dirfd, path) wrapper must build the same match string. Both live here; nothing else
 * crosses wrapper units.
 *
 * @par Thread safety
 * Both functions are safe from any thread: they use the thread-local guard and PRNG, the
 * lock-free process-wide fd cache, and lock-free snapshot reads. Both preserve errno.
 */

#ifndef CHAOS_IO_WRAPPERS_H
#define CHAOS_IO_WRAPPERS_H

#include "chaos_io_config.h"

/**
 * @brief Rule lookup of every descriptor-based wrapper: refresh rules, resolve @p fd to a
 *        path (fd cache, else `/proc/self/fd/<fd>`), select the longest-prefix rule.
 *
 * @details Fail-open: any internal failure (rule file unusable, descriptor unresolvable,
 * excluded path, empty rule set, torn snapshot copy) returns 0 and the wrapper passes the
 * call through. Descriptors 0-2 always return 0.
 *
 * @param[in]  fd         Descriptor.
 * @param[in]  operation  Operation to look up.
 * @param[out] rule       Receives a by-value copy of the rule (chaos_io_rule_t lists the
 *                        two members that still reference shared state); NULL returns 0.
 * @return Non-zero when a rule matched; whether it fires is decided by the effect
 *         helpers.
 *
 * @pre chaos_io_ensure_symbols() was called; the caller is not inside a library section
 *      (chaos_io_in_internal() is 0).
 */
int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule);

/**
 * @brief chaos_io_match_fd_rule() for a call that moves @p size bytes.
 *
 * @details Stores @p size in `rule->call_size` so the rule's `@size>N` / `@size<N` gate
 * is checked when the effect is decided. Without it, call_size stays CHAOS_POLICY_NO_SIZE
 * and a size-gated rule never fires.
 */
int chaos_io_match_fd_rule_sized(
    int fd, chaos_io_operation_t operation, uint64_t size, chaos_io_rule_t *rule
);

/**
 * @brief Builds the normalised absolute path an `openat()`-style (@p dirfd, @p path) pair
 *        names, for rule matching.
 *
 * @details
 * - Absolute @p path: used as written.
 * - Relative @p path with AT_FDCWD: joined to getcwd(), called inside the guard with
 *   errno preserved.
 * - Relative @p path with a directory descriptor: joined to that descriptor's path (fd
 *   cache, else `/proc/self/fd/<dirfd>`); fails for @p dirfd <= 2.
 * The result is then normalised lexically (chaos_io_normalize_path()). Symbolic links in
 * @p path are not resolved here: a path written through a link matches a rule written
 * with that link name, not one written with the target's name (descriptor-based calls on
 * the opened file then match by the kernel's resolved name).
 *
 * Failure is not an error for the caller: the wrapper skips path-based injection and
 * calls the real function.
 *
 * @param[in]  dirfd               Directory descriptor or AT_FDCWD.
 * @param[in]  path                Caller's path; NULL returns 0.
 * @param[out] resolved_path       Buffer; NULL returns 0.
 * @param[in]  resolved_path_size  Capacity in bytes, NUL included; 0 returns 0.
 * @return Non-zero on success; 0 when the base cannot be resolved or the result does not
 *         fit.
 */
int chaos_io_resolve_at_path(
    int dirfd, const char *path, char *resolved_path, size_t resolved_path_size
);

#endif
