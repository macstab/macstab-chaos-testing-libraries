/**
 * @file chaos_io_statfs.c
 * @brief Free-space wrappers: statfs, fstatfs, statvfs, fstatvfs (and glibc `64` aliases).
 *
 * @details
 * | Wrapper | Operation | Matched by |
 * |---------|-----------|------------|
 * | statfs, statvfs | `statfs` | path |
 * | fstatfs, fstatvfs | `statfs` | descriptor |
 *
 * @par Why the operation exists
 * A program that watches free space does not learn about it from a failing write: it asks,
 * decides, and acts before the disk is full -- Elasticsearch moves to read-only at 95 %,
 * Kafka stops a log directory, a database refuses new segments. None of that is reachable
 * by failing `write` with ENOSPC, because the decision is taken from an answer, not from an
 * error.
 *
 * @par Effects
 * - FULL reports no free space at all.
 * - FREE reports the rule's byte count as free, rounded down to whole blocks.
 * - ERRNO and LATENCY as everywhere else.
 *
 * Both free-space effects rewrite the same two counts, `f_bfree` and `f_bavail`, after a
 * successful real call, and leave the total alone: a filling filesystem is being modelled,
 * not a shrinking one. The available count is never left above the free one, which no
 * filesystem reports. The two structures disagree on the unit -- `struct statfs` counts
 * blocks in `f_bsize`, `struct statvfs` in `f_frsize` -- so each wrapper passes its own
 * (chaos_io_free_blocks()).
 *
 * The inode counts are not touched. "Full" in the sense a storage test means is about
 * bytes; a filesystem out of inodes is a different fault, and faking both at once would
 * make a rule say two things.
 *
 * @par What the kernel is asked
 * The real call always runs: the answer is the kernel's, with two fields rewritten. A
 * failing real call is reported unchanged, so a rule never turns an error into a fake
 * answer. A path or descriptor whose rule does not match, or which does not resolve to a
 * path at all (a closed descriptor, no `/proc`), is forwarded untouched, exactly as in
 * the read and write wrappers.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>

/** @brief Real statfs() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_statfs(const char *path, struct statfs *buffer)
{
    int previous;
    int result;

    if (g_chaos_io_real_statfs == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_statfs, path, buffer);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_statfs(path, buffer);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real fstatfs() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_fstatfs(int fd, struct statfs *buffer)
{
    int previous;
    int result;

    if (g_chaos_io_real_fstatfs == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_fstatfs, fd, buffer);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_fstatfs(fd, buffer);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Real statvfs() inside a library section.
 *
 * @details There is no statvfs system call: the C library builds the structure from
 * statfs. Before resolution the wrapper therefore has nothing to fall back to and fails
 * with ENOSYS, which is what a program sees when the symbol is missing anyway. That window
 * is the constructor's own dlsym, and no C library asks for free space inside it.
 */
static int chaos_io_call_real_statvfs(const char *path, struct statvfs *buffer)
{
    int previous;
    int result;

    if (g_chaos_io_real_statvfs == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_statvfs(path, buffer);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real fstatvfs() inside a library section; ENOSYS before resolution (statvfs). */
static int chaos_io_call_real_fstatvfs(int fd, struct statvfs *buffer)
{
    int previous;
    int result;

    if (g_chaos_io_real_fstatvfs == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_fstatvfs(fd, buffer);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Rewrites the free-block counts of a `struct statfs` answer.
 *
 * @param[in,out] rule    Firing rule; a non-free-space effect leaves @p buffer alone.
 * @param[in,out] buffer  Answer of a successful real call.
 */
static void chaos_io_apply_statfs(chaos_io_rule_t *rule, struct statfs *buffer)
{
    uint64_t blocks = 0U;

    if (!chaos_io_free_blocks(rule, (uint64_t)buffer->f_bsize, &blocks) ||
        !chaos_io_rule_should_trigger(rule))
    {
        return;
    }
    /* Never more free than there is: the total is left alone on purpose, so a free count
     * above it would make `total - free` underflow for every reader that works out used
     * space that way -- a rule written to clear a watermark would trip a used-space alarm
     * instead. */
    if (blocks > (uint64_t)buffer->f_blocks)
    {
        blocks = (uint64_t)buffer->f_blocks;
    }
    buffer->f_bfree = (__typeof__(buffer->f_bfree))blocks;
    buffer->f_bavail = (__typeof__(buffer->f_bavail))blocks;
}

/**
 * @brief Rewrites the free-block counts of a `struct statvfs` answer.
 *
 * @param[in,out] rule    Firing rule; a non-free-space effect leaves @p buffer alone.
 * @param[in,out] buffer  Answer of a successful real call.
 */
static void chaos_io_apply_statvfs(chaos_io_rule_t *rule, struct statvfs *buffer)
{
    uint64_t blocks = 0U;

    if (!chaos_io_free_blocks(rule, (uint64_t)buffer->f_frsize, &blocks) ||
        !chaos_io_rule_should_trigger(rule))
    {
        return;
    }
    if (blocks > (uint64_t)buffer->f_blocks)
    {
        blocks = (uint64_t)buffer->f_blocks;
    }
    buffer->f_bfree = (fsblkcnt_t)blocks;
    buffer->f_bavail = (fsblkcnt_t)blocks;
}

/**
 * @brief Interposed statfs(2): `statfs` rules on the path; ERRNO, LATENCY, FREE, FULL.
 *
 * @return 0 with @p buffer filled; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int statfs(const char *path, struct statfs *buffer)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(AT_FDCWD, path, resolved_path, sizeof(resolved_path)) ||
        chaos_io_is_excluded_path(resolved_path) ||
        !chaos_io_config_match_path(CHAOS_IO_OP_STATFS, resolved_path, &rule))
    {
        return chaos_io_call_real_statfs(path, buffer);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_statfs(path, buffer);
    /* A successful call wrote the buffer, so it is not NULL: the kernel answers a NULL
     * one with EFAULT, which is reported unchanged. */
    if (rc == 0)
    {
        chaos_io_apply_statfs(&rule, buffer);
    }
    return rc;
}

/**
 * @brief Interposed fstatfs(2): `statfs` rules on the descriptor's path.
 *
 * @return 0 with @p buffer filled; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int fstatfs(int fd, struct statfs *buffer)
{
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_STATFS, &rule))
    {
        return chaos_io_call_real_fstatfs(fd, buffer);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_fstatfs(fd, buffer);
    /* A successful call wrote the buffer, so it is not NULL: the kernel answers a NULL
     * one with EFAULT, which is reported unchanged. */
    if (rc == 0)
    {
        chaos_io_apply_statfs(&rule, buffer);
    }
    return rc;
}

/**
 * @brief Interposed statvfs(3): `statfs` rules on the path, counts in `f_frsize` units.
 *
 * @return 0 with @p buffer filled; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int statvfs(const char *path, struct statvfs *buffer)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(AT_FDCWD, path, resolved_path, sizeof(resolved_path)) ||
        chaos_io_is_excluded_path(resolved_path) ||
        !chaos_io_config_match_path(CHAOS_IO_OP_STATFS, resolved_path, &rule))
    {
        return chaos_io_call_real_statvfs(path, buffer);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_statvfs(path, buffer);
    /* A successful call wrote the buffer, so it is not NULL: the kernel answers a NULL
     * one with EFAULT, which is reported unchanged. */
    if (rc == 0)
    {
        chaos_io_apply_statvfs(&rule, buffer);
    }
    return rc;
}

/**
 * @brief Interposed fstatvfs(3): `statfs` rules on the descriptor's path.
 *
 * @return 0 with @p buffer filled; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int fstatvfs(int fd, struct statvfs *buffer)
{
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_STATFS, &rule))
    {
        return chaos_io_call_real_fstatvfs(fd, buffer);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    rc = chaos_io_call_real_fstatvfs(fd, buffer);
    /* A successful call wrote the buffer, so it is not NULL: the kernel answers a NULL
     * one with EFAULT, which is reported unchanged. */
    if (rc == 0)
    {
        chaos_io_apply_statvfs(&rule, buffer);
    }
    return rc;
}

/* ---------------------------------------------------------------------------
 * glibc alternate entry points: the large-file names are separate symbols with the same
 * signatures, and a program built with large-file support binds to them.
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__) && defined(__LP64__)

CHAOS_IO_EXPORT int statfs64(const char *path, struct statfs64 *buffer)
    __attribute__((alias("statfs")));
CHAOS_IO_EXPORT int fstatfs64(int fd, struct statfs64 *buffer) __attribute__((alias("fstatfs")));
CHAOS_IO_EXPORT int statvfs64(const char *path, struct statvfs64 *buffer)
    __attribute__((alias("statvfs")));
CHAOS_IO_EXPORT int fstatvfs64(int fd, struct statvfs64 *buffer) __attribute__((alias("fstatvfs")));

#endif
