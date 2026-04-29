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

/*
 * Interposed `close(2)` entry point.
 *
 * The post-close invalidation rule is critical. If the cache were invalidated
 * before the real close and libc then returned an error, the library would have
 * lost the path mapping for a descriptor that is still live.
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

/*
 * Interposed `fsync(2)` entry point.
 *
 * There is no post-call mutation path. Once libc has been called, the wrapper
 * is finished.
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

/*
 * Interposed `fdatasync(2)` entry point.
 *
 * Execution sequence is intentionally the same as `fsync()`.
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
