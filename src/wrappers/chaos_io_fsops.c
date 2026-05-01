/**
 * @file chaos_io_fsops.c
 * @brief File lifecycle and capacity wrappers for libchaos-io.
 *
 * @details
 * This unit owns the interposed entry points for file-system–level operations
 * that are neither ordinary fd I/O nor sync boundaries: `ftruncate(2)`,
 * `fallocate(2)` (Linux only), `unlinkat(2)`, and `renameat(2)`.
 *
 * **Rule matching differences from read/write wrappers.**
 * `ftruncate` and `fallocate` arrive with a file descriptor and use the
 * standard `chaos_io_match_fd_rule()` path.  `unlinkat` and `renameat`
 * arrive with (dirfd, path) pairs and must resolve those to matchable
 * absolute strings before any rule can be found.
 *
 * **fd-cache invalidation after filesystem mutations.**
 * - `close`: invalidates the specific closed fd (see `chaos_io_sync.c`).
 * - `unlinkat`: calls `chaos_io_fdcache_reset()` on success.  An unlink
 *   removes a directory entry but does not change what any live fd resolves
 *   to via `/proc/self/fd`; however, the library conservatively resets the
 *   cache because a subsequent open of the same path (after re-creation)
 *   would still return the same path string from `/proc/self/fd`, meaning
 *   stale cache entries would silently serve correct-looking but
 *   semantically stale data.
 * - `renameat`: calls `chaos_io_fdcache_reset()` on success.  A rename can
 *   make any path alias change atomically.  It is impossible to selectively
 *   invalidate the affected entries without knowing every path that was
 *   previously resolved under the old name, so a full reset is the only
 *   safe option.
 *
 * **`renameat` dual-path rule selection.**
 * A rename has two path identities: source (`oldpath`, matched against
 * `rename_from` rules) and destination (`newpath`, matched against
 * `rename_to` rules).  `chaos_io_match_rename_rule()` evaluates both,
 * picks the longer-prefix match, and breaks ties in favor of the
 * destination rule.  The destination preference reflects the common
 * atomic-replace pattern (write to temp, rename to final): operators
 * typically care more about the final path identity than the temporary name.
 *
 * **Module ownership:** wrappers/
 * **Stability:** internal
 */

/*
 * File lifecycle and capacity wrappers for libchaos-io.
 *
 * This unit owns the file-manipulation calls that are neither ordinary fd I/O
 * nor sync boundaries: size changes, space reservation, rename, and unlink.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <fcntl.h>
#include <unistd.h>

/* --- Real-call trampolines ------------------------------------------------------- */

/** @brief Calls the real `ftruncate()` while preserving the recursion guard. */
static int chaos_io_call_real_ftruncate(int fd, off_t length)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_ftruncate(fd, length);
    chaos_io_leave_internal(previous);
    return result;
}

#ifdef __linux__
/** @brief Calls the real Linux `fallocate()` while preserving the recursion guard. */
static int chaos_io_call_real_fallocate(int fd, int mode, off_t offset, off_t length)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_fallocate(fd, mode, offset, length);
    chaos_io_leave_internal(previous);
    return result;
}
#endif

/** @brief Calls the real `unlinkat()` while preserving the recursion guard. */
static int chaos_io_call_real_unlinkat(int dirfd, const char *path, int flags)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_unlinkat(dirfd, path, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Calls the real `renameat()` while preserving the recursion guard. */
static int
chaos_io_call_real_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    chaos_io_leave_internal(previous);
    return result;
}

/* --- Path-based rule matching helpers ------------------------------------------- */

/**
 * @brief Matches one already-resolved path against the loaded config snapshot.
 *
 * @details Combines the exclusion check with `chaos_io_config_match_loaded()`
 * in a single call.  Unlike `chaos_io_config_match_path()`, this function
 * does not trigger a config reload; the caller must have already called
 * `chaos_io_config_prepare()`.
 *
 * @param[in]  operation  Operation to match against.
 * @param[in]  path       Resolved absolute path.  May be NULL.
 * @param[out] rule       Populated on success.  Must not be NULL.
 * @return Non-zero when a rule matched; zero otherwise.
 */
static int chaos_io_match_loaded_path_rule(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    if (path == NULL || rule == NULL || chaos_io_is_excluded_path(path))
    {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/**
 * @brief Selects the active rename rule across both source and destination paths.
 *
 * @details Resolves both the old and new paths via `chaos_io_resolve_at_path()`,
 * ensures the config is current with `chaos_io_config_prepare()`, then
 * independently queries the `rename_from` and `rename_to` rule classes.
 *
 * **Tie-breaking rule:** if both sides have a rule and their `path_len`
 * values are equal, the destination (`rename_to`) rule wins.  This preference
 * exists because the most common chaos scenario for rename is testing the
 * durability of the atomic-replace pattern (temp file → final path), where the
 * destination path is the semantically significant one.  "Longer prefix wins"
 * ensures a more specific rule always beats a broader one regardless of
 * directionality.
 *
 * @param[in]  olddirfd  Directory fd or `AT_FDCWD` for the source path.
 * @param[in]  oldpath   Source pathname.  May be NULL.
 * @param[in]  newdirfd  Directory fd or `AT_FDCWD` for the destination path.
 * @param[in]  newpath   Destination pathname.  May be NULL.
 * @param[out] rule      Populated with the winning rule on success.
 *                       Must not be NULL.
 * @return Non-zero when at least one rule was found; zero to pass through.
 */
static int chaos_io_match_rename_rule(
    int olddirfd, const char *oldpath, int newdirfd, const char *newpath, chaos_io_rule_t *rule
)
{
    char old_resolved[CHAOS_IO_MAX_PATH];
    char new_resolved[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t from_rule;
    chaos_io_rule_t to_rule;
    int old_ok;
    int new_ok;
    int have_from = 0;
    int have_to = 0;

    if (rule == NULL)
    {
        return 0;
    }

    old_ok = chaos_io_resolve_at_path(olddirfd, oldpath, old_resolved, sizeof(old_resolved));
    new_ok = chaos_io_resolve_at_path(newdirfd, newpath, new_resolved, sizeof(new_resolved));
    if (!old_ok && !new_ok)
    {
        return 0;
    }
    if (!chaos_io_config_prepare())
    {
        return 0;
    }

    if (old_ok)
    {
        have_from =
            chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_FROM, old_resolved, &from_rule);
    }
    if (new_ok)
    {
        have_to = chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_TO, new_resolved, &to_rule);
    }

    if (!have_from && !have_to)
    {
        return 0;
    }
    /*
     * Destination wins on equal path_len to prefer the final-path identity in
     * atomic-replace scenarios.
     */
    if (have_to && (!have_from || to_rule.path_len >= from_rule.path_len))
    {
        *rule = to_rule;
        return 1;
    }

    *rule = from_rule;
    return 1;
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed `ftruncate(2)` entry point.
 *
 * @details Uses the standard fd-backed rule lookup.  Only `ERRNO` and
 * `LATENCY` effects are meaningful for a truncation call; `TORN` and
 * `CORRUPT` are rejected at config parse time.
 *
 * @param[in] fd      File descriptor to truncate.
 * @param[in] length  New file size in bytes.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int ftruncate(int fd, off_t length)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_TRUNCATE, &rule))
    {
        return chaos_io_call_real_ftruncate(fd, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_ftruncate(fd, length);
}

#ifdef __linux__
/**
 * @brief Interposed Linux `fallocate(2)` entry point.
 *
 * @details Uses the standard fd-backed rule lookup.  Only `ERRNO` and
 * `LATENCY` effects are meaningful; space reservation cannot be torn or
 * corrupted in a useful way.
 *
 * @param[in] fd      File descriptor to allocate space for.
 * @param[in] mode    Allocation mode flags (e.g. `FALLOC_FL_KEEP_SIZE`).
 * @param[in] offset  Byte offset of the region to allocate.
 * @param[in] length  Byte length of the region to allocate.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int fallocate(int fd, int mode, off_t offset, off_t length)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_ALLOCATE, &rule))
    {
        return chaos_io_call_real_fallocate(fd, mode, offset, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_fallocate(fd, mode, offset, length);
}
#endif

/**
 * @brief Interposed `unlinkat(2)` entry point.
 *
 * @details Path resolution is attempted first; if it fails the wrapper falls
 * through to the real call without injection.  On a successful real unlink the
 * thread fd-cache is fully reset because the unlinked path may have been
 * cached under one or more descriptors opened before the unlink—subsequent
 * resolutions via `/proc/self/fd` would still yield the now-deleted path,
 * and keeping stale cache entries for such descriptors is harmless in
 * practice but confusing to reason about.
 *
 * A synthetic `ERRNO` failure does not reset the cache because the file still
 * exists from the caller's perspective.
 *
 * @param[in] dirfd  Directory fd or `AT_FDCWD`.
 * @param[in] path   Pathname to unlink.
 * @param[in] flags  Flags (e.g. `AT_REMOVEDIR`).
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int unlinkat(int dirfd, const char *path, int flags)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    int rc;

    if (chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(dirfd, path, resolved_path, sizeof(resolved_path)) ||
        chaos_io_is_excluded_path(resolved_path) || !chaos_io_config_prepare() ||
        !chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, resolved_path, &rule))
    {
        rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
        if (rc == 0)
        {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        /* Synthetic failure: file still exists; do not invalidate cache. */
        return -1;
    }

    rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
    if (rc == 0)
    {
        chaos_io_fdcache_reset();
    }
    return rc;
}

/**
 * @brief Interposed `renameat(2)` entry point.
 *
 * @details Both source and destination may carry rules through `rename_from`
 * and `rename_to`.  `chaos_io_match_rename_rule()` handles the dual-path
 * lookup and tie-breaking.
 *
 * Successful renames reset the thread fd cache because the rename is atomic
 * from the kernel's perspective: after it returns, any path that used to
 * reach the old name now reaches the new name, and vice versa if `newpath`
 * previously existed.  It is impossible to selectively invalidate only the
 * affected cache entries without tracking every path that might be an alias,
 * so a full reset is the only safe option.
 *
 * A synthetic `ERRNO` failure does not reset the cache because the rename
 * did not happen.
 *
 * @param[in] olddirfd  Directory fd or `AT_FDCWD` for the source path.
 * @param[in] oldpath   Source pathname.
 * @param[in] newdirfd  Directory fd or `AT_FDCWD` for the destination path.
 * @param[in] newpath   Destination pathname.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    chaos_io_rule_t rule;
    int rc;

    if (chaos_io_in_internal() ||
        !chaos_io_match_rename_rule(olddirfd, oldpath, newdirfd, newpath, &rule))
    {
        rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
        if (rc == 0)
        {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        /* Synthetic failure: rename did not happen; paths unchanged; keep cache. */
        return -1;
    }

    rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (rc == 0)
    {
        chaos_io_fdcache_reset();
    }
    return rc;
}
