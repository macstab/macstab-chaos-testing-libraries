/**
 * @file chaos_io_sync.c
 * @brief Descriptor lifecycle and sync wrappers: close, dup2, dup3, close_range, closedir,
 *        pclose, closefrom, fsync, fdatasync.
 *
 * @details
 * Two jobs:
 * - Apply `close`, `fsync` and `fdatasync` rules (ERRNO, LATENCY; the parser rejects TORN
 *   and CORRUPT for these operations).
 * - Keep the fd cache truthful: every call that frees or retargets a descriptor
 *   invalidates it, including closes libc performs with internal system calls the close()
 *   wrapper never sees (closedir, pclose, closefrom).
 *
 * @par close
 * Linux releases the descriptor in every case, even when close() reports an error (EIO on
 * NFS write-back, EINTR), and correct programs therefore never retry it. The wrapper keeps
 * that contract: a LATENCY rule delays before the close, the real close always runs, the
 * cache slot is invalidated whatever close returned, and an ERRNO rule is reported only
 * after the descriptor is gone. A synthetic error that left the descriptor open would
 * leak it in exactly the programs that handle close correctly.
 *
 * @par fsync, fdatasync
 * ERRNO fails the call without syncing; LATENCY delays it. Neither touches the cache.
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
 * Each trampoline calls the real function inside a library section and issues the system
 * call itself while its `g_chaos_io_real_*` pointer is still NULL (a call during symbol
 * resolution). closedir and pclose operate on libc objects no system call can stand in
 * for; they fail with ENOSYS then.
 */

/** @brief Real close() inside a library section; raw system call before resolution. */
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
 * @brief Real dup2() inside a library section; before resolution emulated with system
 *        calls.
 *
 * @details aarch64 has no dup2 system call. dup3 is equivalent except that it rejects
 * equal descriptors with EINVAL, while dup2 returns @p newfd when it is open (EBADF
 * otherwise); that case is answered with an F_GETFD probe.
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
/** @brief Real dup3() inside a library section; raw system call before resolution. */
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

/** @brief Real closedir() inside a library section; -1/ENOSYS before resolution. */
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

/** @brief Real pclose() inside a library section; -1/ENOSYS before resolution. */
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

/** @brief Real fsync() inside a library section; raw system call before resolution. */
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

/** @brief Real fdatasync() inside a library section; raw system call before resolution. */
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
 * @brief Interposed close(2): `close` rules; the descriptor is always closed, an injected
 *        error is reported after the close.
 *
 * @details The rule is matched before the close (afterwards the descriptor has no path).
 * The real close is the next definition in the chain (another libchaos library or libc),
 * so a library later in `LD_PRELOAD` that also wraps close sees every call, injected
 * failures included. The cache slot is invalidated whatever close returned: the number
 * may be handed out again by the next open. The ERRNO decision (and its hit) happens
 * after the close.
 *
 * @param[in] fd  Descriptor to close.
 * @return The real result, or -1 with the rule's errno when an ERRNO rule fired (the
 *         descriptor is closed either way).
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
 * @brief Interposed dup2(2): no rules; on success invalidates @p newfd.
 *
 * @details dup2 silently closes @p newfd when it was open and points it at @p oldfd's
 * file, so whatever the cache held for @p newfd is stale. Equal descriptors change
 * nothing and are not invalidated.
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
/** @brief Interposed dup3(2): no rules; on success invalidates @p newfd, as dup2(). */
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
/** @brief close_range(2) flag (Linux 5.11): mark the range close-on-exec instead of closing. */
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

/**
 * @brief Interposed close_range(2): no rules; on success invalidates the closed range.
 *
 * @details -1/ENOSYS when libc has no close_range (glibc before 2.34, musl), which is what
 * a program linked against such a libc would get. With CLOSE_RANGE_CLOEXEC nothing closes
 * now (the descriptors go at exec, together with this image and its cache), so nothing is
 * invalidated. A range of 32 descriptors or more covers every slot and resets the whole
 * cache instead of looping, which also bounds the cost of `close_range(3, ~0U, 0)`.
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
 * @brief Interposed closedir(3): closes the directory, then invalidates its descriptor.
 *
 * @details libc closes a directory's descriptor with its own system call, which close()
 * never sees; the next descriptor with that number would otherwise be matched as the
 * directory. errno from dirfd() is discarded; the result and errno are closedir()'s.
 */
CHAOS_IO_EXPORT int closedir(DIR *directory)
{
    const int saved_errno = errno;
    int fd;
    int rc;

    /* closedir is declared nonnull, so the compiler may delete a plain NULL test; reading
     * the pointer through a volatile keeps the test. */
    DIR *volatile checked = directory;

    chaos_io_ensure_symbols();
    fd = checked != NULL ? dirfd(directory) : -1;
    errno = saved_errno;
    rc = chaos_io_call_real_closedir(directory);
    chaos_io_fdcache_invalidate(fd);
    return rc;
}

/**
 * @brief Interposed pclose(3): closes the pipe stream, then invalidates its descriptor;
 *        libc closes it with its own system call, as for closedir().
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
/** @brief close_range(2) system call number (Linux 5.9): 436 on x86_64 and aarch64 alike. */
#define SYS_close_range 436
#endif

/**
 * @brief closefrom() for a libc without one: the close_range system call (Linux 5.9+),
 *        else close() on every descriptor below `sysconf(_SC_OPEN_MAX)`, as glibc's
 *        fallback does. errno preserved.
 *
 * @details Raw system calls, so a later library's close wrapper does not see each close
 * (glibc's closefrom behaves the same).
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
 * @brief Interposed closefrom(3): closes every descriptor >= @p lowfd, then resets the
 *        whole fd cache.
 *
 * @details glibc closes them with the close_range system call, which the close_range()
 * wrapper never sees. Exported also where libc has no closefrom (musl, glibc before 2.34),
 * where chaos_io_close_from() provides it, so a program that finds the symbol at run time
 * gets a working implementation.
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
 * @brief Interposed fsync(2): `fsync` rules; ERRNO fails without syncing, LATENCY delays.
 *
 * @details An injected EIO models the classic lost write-back error: the data the caller
 * believes durable is not.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
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
 * @brief Interposed fdatasync(2): `fdatasync` rules, same semantics as fsync() (separate
 *        operation so the two can be faulted independently).
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
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
