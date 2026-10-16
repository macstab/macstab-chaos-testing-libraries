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
#include <fcntl.h>
#include <sys/syscall.h>

/* --- Real-call trampolines ------------------------------------------------------- */

/*
 * Each trampoline makes the system call itself while its `g_chaos_io_real_*`
 * pointer is still NULL: a call that arrives during symbol resolution. The
 * directory and pipe streams are the C library's own objects and fail with ENOSYS.
 */

/** @brief Calls the real `close()` while preserving the recursion guard. */
static int chaos_io_call_real_close(int fd)
{
    int previous;
    int rc;

    if (g_chaos_io_real_close == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_close, fd);
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_close(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

/**
 * @brief Calls the real `dup2()` while preserving the recursion guard.
 *
 * @details aarch64 has no dup2 system call. dup3 does the same, except that it
 * refuses equal descriptors, which dup2 accepts when the descriptor is open.
 */
static int chaos_io_call_real_dup2(int oldfd, int newfd)
{
    int previous;
    int rc;

    if (g_chaos_io_real_dup2 == NULL)
    {
        if (oldfd == newfd)
        {
            return CHAOS_IO_SYSCALL(SYS_fcntl, oldfd, F_GETFD) < 0 ? -1 : newfd;
        }
        return (int)CHAOS_IO_SYSCALL(SYS_dup3, oldfd, newfd, 0);
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_dup2(oldfd, newfd);
    chaos_io_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/** @brief Calls the real Linux `dup3()` while preserving the recursion guard. */
static int chaos_io_call_real_dup3(int oldfd, int newfd, int flags)
{
    int previous;
    int rc;

    if (g_chaos_io_real_dup3 == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_dup3, oldfd, newfd, flags);
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_dup3(oldfd, newfd, flags);
    chaos_io_leave_internal(previous);
    return rc;
}
#endif

/** @brief Calls the real `closedir()` while preserving the recursion guard. */
static int chaos_io_call_real_closedir(DIR *directory)
{
    int previous;
    int rc;

    if (g_chaos_io_real_closedir == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_closedir(directory);
    chaos_io_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `pclose()` while preserving the recursion guard. */
static int chaos_io_call_real_pclose(FILE *stream)
{
    int previous;
    int rc;

    if (g_chaos_io_real_pclose == NULL)
    {
        errno = ENOSYS;
        return -1;
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_pclose(stream);
    chaos_io_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `fsync()` while preserving the recursion guard. */
static int chaos_io_call_real_fsync(int fd)
{
    int previous;
    int rc;

    if (g_chaos_io_real_fsync == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_fsync, fd);
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fsync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

/** @brief Calls the real `fdatasync()` while preserving the recursion guard. */
static int chaos_io_call_real_fdatasync(int fd)
{
    int previous;
    int rc;

    if (g_chaos_io_real_fdatasync == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_fdatasync, fd);
    }
    previous = chaos_io_enter_internal();
    rc = g_chaos_io_real_fdatasync(fd);
    chaos_io_leave_internal(previous);
    return rc;
}

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

    chaos_io_ensure_symbols();
    matched = !chaos_io_in_internal() && chaos_io_match_fd_rule(fd, CHAOS_IO_OP_CLOSE, &rule);
    if (matched && rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }

    rc = chaos_io_call_real_close(fd);
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

    chaos_io_ensure_symbols();
    rc = chaos_io_call_real_dup2(oldfd, newfd);
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

    chaos_io_ensure_symbols();
    rc = chaos_io_call_real_dup3(oldfd, newfd, flags);
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
 * @brief Interposed `closedir(3)`: closes the directory, then forgets its descriptor.
 *
 * @details The C library closes a directory's descriptor with its own system call,
 * which the close() wrapper never sees; the next descriptor with that number would
 * otherwise be taken for the directory.
 */
CHAOS_IO_EXPORT int closedir(DIR *directory)
{
    const int saved_errno = errno;
    int fd;
    int rc;

    /* Declared nonnull: read through a volatile so a NULL test is not dropped. */
    DIR *volatile checked = directory;

    chaos_io_ensure_symbols();
    fd = checked != NULL ? dirfd(directory) : -1;
    errno = saved_errno;
    rc = chaos_io_call_real_closedir(directory);
    chaos_io_fdcache_invalidate(fd);
    return rc;
}

/**
 * @brief Interposed `pclose(3)`: closes the pipe stream, then forgets its descriptor.
 *
 * @details Like closedir(): the C library closes the descriptor itself.
 */
CHAOS_IO_EXPORT int pclose(FILE *stream)
{
    const int saved_errno = errno;
    int fd;
    int rc;

    FILE *volatile checked = stream;

    chaos_io_ensure_symbols();
    fd = checked != NULL ? fileno(stream) : -1;
    errno = saved_errno;
    rc = chaos_io_call_real_pclose(stream);
    chaos_io_fdcache_invalidate(fd);
    return rc;
}

#ifndef SYS_close_range
/** @brief close_range(2), Linux 5.9: the same number on x86_64 and aarch64. */
#define SYS_close_range 436
#endif

/**
 * @brief closefrom() where the C library has none: the close_range system call
 *        (Linux 5.9), else every descriptor up to the limit, as glibc does.
 */
static void chaos_io_close_from(int lowfd)
{
    const int saved_errno = errno;
    long fd;
    long limit;

    if (lowfd < 0)
    {
        lowfd = 0;
    }
    if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U, 0) == 0)
    {
        errno = saved_errno;
        return;
    }
    limit = sysconf(_SC_OPEN_MAX);
    for (fd = lowfd; fd < limit; ++fd)
    {
        (void)syscall(SYS_close, fd);
    }
    errno = saved_errno;
}

/**
 * @brief Interposed `closefrom(3)`: closes every descriptor from @p lowfd up, then
 *        forgets them all.
 *
 * @details glibc closes them with the close_range system call, which the
 * close_range() wrapper never sees. Exported also where the C library has no
 * closefrom (musl, glibc before 2.34), so it works there too instead of being a
 * function that does nothing.
 */
CHAOS_IO_EXPORT void closefrom(int lowfd)
{
    int previous;

    chaos_io_ensure_symbols();
    previous = chaos_io_enter_internal();
    if (g_chaos_io_real_closefrom != NULL)
    {
        g_chaos_io_real_closefrom(lowfd);
    }
    else
    {
        chaos_io_close_from(lowfd);
    }
    chaos_io_leave_internal(previous);
    chaos_io_fdcache_reset();
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

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FSYNC, &rule))
    {
        return chaos_io_call_real_fsync(fd);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_fsync(fd);
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

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_FDATASYNC, &rule))
    {
        return chaos_io_call_real_fdatasync(fd);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_fdatasync(fd);
}
