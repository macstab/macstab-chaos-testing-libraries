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

/* Calls the real `ftruncate()` while preserving the recursion guard. */
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
/* Calls the real Linux `fallocate()` while preserving the recursion guard. */
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

/* Calls the real `unlinkat()` while preserving the recursion guard. */
static int chaos_io_call_real_unlinkat(int dirfd, const char *path, int flags)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_unlinkat(dirfd, path, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/* Calls the real `renameat()` while preserving the recursion guard. */
static int chaos_io_call_real_renameat(
    int olddirfd,
    const char *oldpath,
    int newdirfd,
    const char *newpath)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    chaos_io_leave_internal(previous);
    return result;
}

/* Matches one already resolved path against the loaded config snapshot. */
static int chaos_io_match_loaded_path_rule(
    chaos_io_operation_t operation,
    const char *path,
    chaos_io_rule_t *rule)
{
    if (path == NULL || rule == NULL || chaos_io_is_excluded_path(path)) {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/*
 * Selects the active rename rule across both source and destination paths.
 *
 * The config surface keeps source and destination explicit through
 * `rename_from` and `rename_to`. If both sides match, the longer prefix wins;
 * equal-length ties prefer the destination rule because atomic replace flows
 * typically care more about the final path identity.
 */
static int chaos_io_match_rename_rule(
    int olddirfd,
    const char *oldpath,
    int newdirfd,
    const char *newpath,
    chaos_io_rule_t *rule)
{
    char old_resolved[CHAOS_IO_MAX_PATH];
    char new_resolved[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t from_rule;
    chaos_io_rule_t to_rule;
    int old_ok;
    int new_ok;
    int have_from = 0;
    int have_to = 0;

    if (rule == NULL) {
        return 0;
    }

    old_ok = chaos_io_resolve_at_path(olddirfd, oldpath, old_resolved, sizeof(old_resolved));
    new_ok = chaos_io_resolve_at_path(newdirfd, newpath, new_resolved, sizeof(new_resolved));
    if (!old_ok && !new_ok) {
        return 0;
    }
    if (!chaos_io_config_prepare()) {
        return 0;
    }

    if (old_ok) {
        have_from = chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_FROM, old_resolved, &from_rule);
    }
    if (new_ok) {
        have_to = chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_TO, new_resolved, &to_rule);
    }

    if (!have_from && !have_to) {
        return 0;
    }
    if (have_to && (!have_from || to_rule.path_len >= from_rule.path_len)) {
        *rule = to_rule;
        return 1;
    }

    *rule = from_rule;
    return 1;
}

/* Interposed `ftruncate(2)` entry point. */
CHAOS_IO_EXPORT int ftruncate(int fd, off_t length)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_TRUNCATE, &rule)) {
        return chaos_io_call_real_ftruncate(fd, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    return chaos_io_call_real_ftruncate(fd, length);
}

#ifdef __linux__
/* Interposed Linux `fallocate(2)` entry point. */
CHAOS_IO_EXPORT int fallocate(int fd, int mode, off_t offset, off_t length)
{
    chaos_io_rule_t rule;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_ALLOCATE, &rule)) {
        return chaos_io_call_real_fallocate(fd, mode, offset, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    return chaos_io_call_real_fallocate(fd, mode, offset, length);
}
#endif

/*
 * Interposed `unlinkat(2)` entry point.
 *
 * A successful unlink changes path identity for any matching fd cache entries,
 * so the current thread cache is reset after success.
 */
CHAOS_IO_EXPORT int unlinkat(int dirfd, const char *path, int flags)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    int rc;

    if (chaos_io_in_internal()
        || !chaos_io_resolve_at_path(dirfd, path, resolved_path, sizeof(resolved_path))
        || chaos_io_is_excluded_path(resolved_path)
        || !chaos_io_config_prepare()
        || !chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, resolved_path, &rule)) {
        rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
        if (rc == 0) {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
    if (rc == 0) {
        chaos_io_fdcache_reset();
    }
    return rc;
}

/*
 * Interposed `renameat(2)` entry point.
 *
 * Both source and destination may carry rules through `rename_from` and
 * `rename_to`. Successful renames invalidate the current thread fd cache
 * because resolved paths may have changed for live descriptors.
 */
CHAOS_IO_EXPORT int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    chaos_io_rule_t rule;
    int rc;

    if (chaos_io_in_internal() || !chaos_io_match_rename_rule(olddirfd, oldpath, newdirfd, newpath, &rule)) {
        rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
        if (rc == 0) {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
        chaos_io_rule_apply_latency(&rule);
    } else if (chaos_io_rule_apply_errno(&rule)) {
        return -1;
    }

    rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (rc == 0) {
        chaos_io_fdcache_reset();
    }
    return rc;
}
