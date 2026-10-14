/**
 * @file chaos_io_sync.c
 * @brief Sync and lifecycle wrappers for libchaos-io.
 *
 * @details
 * This file implements the interposed entry points for `close(2)`,
 * `fsync(2)`, and `fdatasync(2)`.  All three operate on existing file
 * descriptors and share the same fd-backed rule lookup path as the read/write
 * wrappers, but they differ in how they update fd-cache state after the real
 * libc call.
 *
 * **`close` cache invalidation discipline.**
 * The fd-cache entry is invalidated only after a successful return from the
 * real `close()`.  This ordering is deliberate: if `close()` fails (returning
 * -1), the file descriptor is still live and its cached path remains valid.
 * Invalidating before the call would permanently lose the path mapping for a
 * descriptor that could still be used or closed again.  Invalidating after a
 * failed close would also be wrong for the same reason: a caller that retries
 * the close after `EINTR` should still get fault injection for it.
 *
 * **`fsync` and `fdatasync`.**
 * Neither sync call modifies fd-cache state.  They support only `ERRNO` and
 * `LATENCY` effects because `TORN` and `CORRUPT` have no meaningful
 * interpretation for a sync boundary operation.
 *
 * **Effect execution model for all three wrappers:**
 * - `LATENCY`: pre-call, unconditional sleep.
 * - `ERRNO`: pre-call; the real syscall is skipped and -1 is returned.
 * - No post-call mutation path exists for any of these operations.
 *
 * **Module ownership:** wrappers/
 * **Stability:** internal
 */

/*
 * Sync and lifecycle wrappers for libchaos-io.
 *
 * These wrappers all operate on existing file descriptors and share the same
 * fd-backed rule lookup path as the read/write wrappers, but they differ in how
 * they update cache state after the real libc call.
 */

#include "chaos_io_actions.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <limits.h>

/**
 * @brief Interposed `close(2)` entry point.
 *
 * @details Linux releases the descriptor in every case, even when `close()`
 * reports an error (EIO on NFS write-back, EINTR), and programs therefore never
 * retry it. The wrapper keeps that contract: the real close always runs, and an
 * injected error is reported after it. A synthetic error that left the descriptor
 * open would leak it in exactly the programs that handle close correctly.
 *
 * The real close is the next definition in the chain (another chaos library or
 * libc), so a library that shares `close` sees every call. The cache entry is
 * invalidated whatever the close returned, for the same reason: the descriptor is
 * gone and its number may be handed out again by the next open.
 *
 * @param[in] fd  File descriptor to close.
 * @return 0 on success; -1 with `errno` set on a real or injected failure.
 */
CHAOS_IO_EXPORT int close(int fd)
{
    chaos_io_rule_t rule;
    int matched;
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    matched = !chaos_io_in_internal() && chaos_io_match_fd_rule(fd, CHAOS_IO_OP_CLOSE, &rule);
    if (matched && rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);
    chaos_io_fdcache_invalidate(fd);

    if (matched && rule.effect != CHAOS_IO_EFFECT_LATENCY && chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    return rc;
}

/**
 * @brief Interposed `dup2(2)`: forwards unchanged, then invalidates @p newfd.
 *
 * @details dup2 silently closes @p newfd when it was open and makes it refer to
 * @p oldfd's file, so whatever the cache held for @p newfd is stale.
 */
CHAOS_IO_EXPORT int dup2(int oldfd, int newfd)
{
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_dup2(oldfd, newfd);
    chaos_io_leave_internal(previous);
    if (rc >= 0 && oldfd != newfd)
    {
        chaos_io_fdcache_invalidate(newfd);
    }
    return rc;
}

#ifdef __linux__
/**
 * @brief Interposed Linux `dup3(2)`: forwards unchanged, then invalidates @p newfd.
 */
CHAOS_IO_EXPORT int dup3(int oldfd, int newfd, int flags)
{
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_dup3(oldfd, newfd, flags);
    chaos_io_leave_internal(previous);
    if (rc >= 0)
    {
        chaos_io_fdcache_invalidate(newfd);
    }
    return rc;
}
#endif

#ifndef CLOSE_RANGE_CLOEXEC
/** @brief close_range(2) flag: mark the range close-on-exec instead of closing it. */
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

/**
 * @brief Interposed `close_range(2)`: forwards unchanged, then invalidates the range.
 *
 * @details Reports ENOSYS when the C library has no `close_range`, as that libc
 * itself would. With CLOSE_RANGE_CLOEXEC nothing is closed now (the descriptors
 * go at exec, together with this process image), so nothing is invalidated.
 * A range at least as wide as the cache invalidates every slot.
 */
CHAOS_IO_EXPORT int close_range(unsigned int first, unsigned int last, int flags)
{
    unsigned int fd;
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    if (g_chaos_io_real_close_range == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_close_range(first, last, flags);
    chaos_io_leave_internal(previous);
    if (rc != 0 || ((unsigned int)flags & CLOSE_RANGE_CLOEXEC) != 0U || last < first)
    {
        return rc;
    }
    if (last - first >= CHAOS_IO_FD_CACHE_SLOTS - 1U)
    {
        chaos_io_fdcache_reset();
        return rc;
    }
    for (fd = first; fd <= last && fd <= (unsigned int)INT_MAX; ++fd)
    {
        chaos_io_fdcache_invalidate((int)fd);
    }
    return rc;
}

/**
 * @brief Interposed `fsync(2)` entry point.
 *
 * @details There is no post-call mutation path. Once libc has been called, the wrapper
 * is finished.  The `TORN` and `CORRUPT` effects are not applicable to a sync
 * operation; the config validator rejects such rules at parse time.
 *
 * @param[in] fd  File descriptor to flush.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int fsync(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FSYNC, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_fsync(fd);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fsync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

/**
 * @brief Interposed `fdatasync(2)` entry point.
 *
 * @details Execution sequence is intentionally identical to `fsync()`.
 * The two operations share the same fault semantics: both can be delayed or
 * made to return an error; neither produces observable data output.
 *
 * @param[in] fd  File descriptor to flush.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int fdatasync(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FDATASYNC, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_fdatasync(fd);
        chaos_io_leave_internal(previous);
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fdatasync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}
