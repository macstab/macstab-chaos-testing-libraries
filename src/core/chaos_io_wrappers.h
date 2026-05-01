/**
 * @file chaos_io_wrappers.h
 * @brief Cross-wrapper helper declarations for the libchaos-io preload library.
 *
 * @details
 * The interposed libc symbols are split across several `.c` files to keep
 * each translation unit focused.  Those units still share two helper entry
 * points that must behave identically regardless of which wrapper is calling
 * them:
 *
 * - `chaos_io_match_fd_rule()` – the single, canonical sequence for
 *   "check config freshness, resolve fd to path, match a rule" used by
 *   every descriptor-based wrapper.
 * - `chaos_io_resolve_at_path()` – the canonical resolution of an
 *   `openat()`-style (dirfd, path) pair into a matchable string, shared
 *   between the open wrappers and the filesystem-operation wrappers.
 *
 * No other cross-wrapper state is declared here.  Each wrapper translation
 * unit includes the subsystem headers it needs directly.
 *
 * **Module ownership:** core/
 * **Stability:** internal – not part of any public ABI
 * **Thread-safety:** both functions are safe to call concurrently from
 * different threads; they operate on thread-local state (fd cache, PRNG,
 * guard) and shared read-only config snapshots.
 */

#ifndef CHAOS_IO_WRAPPERS_H
#define CHAOS_IO_WRAPPERS_H

/*
 * Internal helper declarations shared between wrapper compilation units.
 *
 * The library keeps exported interposers split across several `.c` files, but
 * fd-backed wrappers still need one common rule-selection entry point so they
 * all interpret config and fd-cache state the same way.
 */

#include "chaos_io_config.h"

/**
 * @brief Performs the canonical fd-to-rule lookup for descriptor-based wrappers.
 *
 * @details Centralizes the sequence: refresh config snapshot if stale, resolve
 * the fd to a path via the thread-local cache or `/proc/self/fd/<fd>`, then
 * select the longest-prefix matching rule from the active snapshot for the
 * given operation.
 *
 * This is the only path through which descriptor-based wrappers (`read`,
 * `write`, `close`, `fsync`, etc.) acquire a rule.  Keeping it in one place
 * guarantees that all wrappers observe the same config freshness and exclusion
 * semantics.
 *
 * @param[in]  fd         The file descriptor to resolve.  Descriptors 0–2
 *                        (stdin/stdout/stderr) are always passed through and
 *                        the function returns 0 immediately for them.
 * @param[in]  operation  The operation type to look up.
 * @param[out] rule       Populated with the matched rule on success.
 *                        The caller owns this storage; no pointers inside
 *                        `rule` point into shared library state.
 *
 * @return Non-zero when a matching rule was found and written to `*rule`;
 *         zero when no rule matched or when the fd is excluded.
 *
 * @pre  `rule != NULL`.
 * @pre  The library constructor has already resolved all `g_chaos_io_real_*`
 *       symbols.
 *
 * @note Returns 0 (passthrough) rather than propagating errors on any
 *       internal failure (config read error, fd resolution failure, empty
 *       config).  This is the "fail-open" contract: injection never prevents
 *       the target application from making progress due to a library bug.
 */
int chaos_io_match_fd_rule(int fd, chaos_io_operation_t operation, chaos_io_rule_t *rule);

/**
 * @brief Resolves an `openat()`-style (dirfd, path) pair to a matchable string.
 *
 * @details Handles three cases:
 * 1. `path` is absolute – copied into `resolved_path` directly.
 * 2. `dirfd == AT_FDCWD` – resolved relative to the current working directory
 *    obtained via `getcwd()` inside the internal guard.
 * 3. `dirfd` is a real descriptor – the directory path is obtained from the
 *    thread-local fd cache or via `readlink("/proc/self/fd/<dirfd>")`, then
 *    joined with `path` lexically.
 *
 * The join is purely lexical: `.` and `..` segments are not normalized.  The
 * resulting string is only used for prefix matching against config rules, not
 * for filesystem access, so normalization is not required.
 *
 * @param[in]  dirfd              Directory fd, or `AT_FDCWD`.
 * @param[in]  path               User-supplied path string.  Must not be NULL.
 * @param[out] resolved_path      Buffer to receive the resolved string.
 *                                Must not be NULL.
 * @param[in]  resolved_path_size Byte capacity of `resolved_path`, including
 *                                the terminating NUL.
 *
 * @return Non-zero when resolution succeeded and `*resolved_path` contains a
 *         valid null-terminated string; zero when resolution failed (e.g. the
 *         dirfd could not be resolved, or the result would not fit in
 *         `resolved_path_size` bytes).
 *
 * @post On success, `resolved_path` is a null-terminated string of length
 *       less than `resolved_path_size`.
 *
 * @note Failure is not an error from the caller's perspective.  The wrapper
 *       simply has no path to match against and skips pre-call injection,
 *       falling back to the post-open fd-cache seeding path instead.
 */
int chaos_io_resolve_at_path(
    int dirfd, const char *path, char *resolved_path, size_t resolved_path_size
);

#endif
