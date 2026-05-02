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

/**
 * @brief Interposed `close(2)` entry point.
 *
 * @details The fd-cache invalidation rule is critical: if the cache were
 * invalidated before the real close and libc then returned an error, the
 * library would have lost the path mapping for a descriptor that is still
 * live.  Post-success invalidation is the only safe ordering.
 *
 * Both the "no matching rule" fast path and the "rule matched" slow path
 * share the same post-call invalidation logic to ensure the cache is always
 * updated consistently regardless of whether a fault was applied.
 *
 * Note that an `ERRNO` rule that fires before the real close does NOT
 * invalidate the cache.  The caller receives a synthetic failure; from the
 * caller's perspective the descriptor is still open, and the cache must
 * reflect that.
 *
 * @param[in] fd  File descriptor to close.
 * @return 0 on success; -1 with `errno` set on failure.
 */
CHAOS_IO_EXPORT int close(int fd)
{
    chaos_io_rule_t rule;
    int rc;
    int previous;

    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_CLOSE, &rule))
    {
        previous = chaos_io_enter_internal();
        rc = g_chaos_io_real_close(fd);
        chaos_io_leave_internal(previous);
        if (rc == 0)
        {
            chaos_io_fdcache_invalidate(fd);
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        /* Synthetic failure: descriptor is still live, do not touch the cache. */
        return -1;
    }

    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);
    if (rc == 0)
    {
        chaos_io_fdcache_invalidate(fd);
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
