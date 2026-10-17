/**
 * @file chaos_net_wait.c
 * @brief Wrappers for the multiplexed waits: poll, ppoll, select, pselect, epoll_wait,
 *        epoll_pwait (the POLL operation).
 *
 * @details
 * @par Matching a set of descriptors:
 *   A wait covers many descriptors (sockets, pipes, eventfds, files). The wrapper scans
 *   them in order and uses the first whose endpoint resolves and matches a POLL rule, so
 *   one matching socket in the set is enough for the rule to apply to the whole call.
 *   Each descriptor is resolved with chaos_net_endpoint_from_activity_fd(), which in
 *   practice means its local address (getsockname succeeds on every socket); non-sockets
 *   are skipped (ENOTSOCK).
 *
 * @par One reload check per call:
 *   chaos_net_config_prepare() runs once per wait, before the scan, and each descriptor
 *   is matched with chaos_net_config_match_endpoint_loaded(). Whether the rule file is
 *   stat(2)ed at all is decided by the 1 ms throttle (CHAOS_CHECK_INTERVAL_NS, vDSO
 *   clock), not by the size of the set. With no active rule the scan is skipped and no
 *   descriptor is looked up.
 *
 * @par epoll (Linux):
 *   epoll_wait gets only the epoll descriptor. The watched descriptors are listed in
 *   /proc/self/fdinfo/<epfd>, one `tfd: <fd>` line each; the file is read in 512-byte
 *   pieces (a wait may run in a signal handler on a small alternate stack) and at most
 *   256 KiB of it is scanned, about 4000 watched descriptors. Descriptors beyond that, or
 *   added or removed concurrently, may be missed. An unreadable fdinfo means no match
 *   (fail-open).
 *
 * @par TIMEOUT:
 *   A firing TIMEOUT does not call the real wait. It waits out the call's own timeout as
 *   if nothing became ready -- a ppoll on no descriptors, under the call's signal mask for
 *   ppoll, pselect and epoll_pwait, so a signal ends it with EINTR as it would end the
 *   real wait -- then:
 *   - poll/ppoll: clears every revents and returns 0.
 *   - select/pselect: clears every fd_set and returns 0; select's timeout reads 0
 *     afterwards, as Linux leaves it.
 *   - epoll_wait/epoll_pwait: returns 0.
 *   A wait without a timeout (-1, or NULL) never times out, so TIMEOUT does not apply to
 *   it: returning 0 at once would be a result the kernel never gives, and a caller
 *   retrying on it would spin. Nor does it apply to a timespec the kernel would refuse
 *   (EINVAL); that call is left to the real wait.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>

/**
 * @brief Whether descriptor @p fd matches a POLL rule in the active snapshot.
 *
 * @details chaos_net_endpoint_from_activity_fd() (local address, else peer), then
 * chaos_net_config_match_endpoint_loaded(). The caller has run chaos_net_config_prepare()
 * for this call.
 *
 * @param fd    Descriptor to examine.
 * @param rule  Output: the matching rule copy.
 * @return Non-zero if @p fd matches; 0 otherwise (including for non-sockets).
 */
static int chaos_net_wait_match_fd_loaded(int fd, chaos_net_rule_t *rule)
{
    chaos_net_endpoint_t endpoint;

    return chaos_net_endpoint_from_activity_fd(fd, &endpoint) &&
           chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_POLL, &endpoint, rule);
}

/**
 * @brief First descriptor of a pollfd array that matches a POLL rule.
 *
 * @details chaos_net_config_prepare() once, then the entries in order; negative fds are
 * skipped, as poll() ignores them. Stops at the first match.
 *
 * @param fds   pollfd array; NULL yields 0.
 * @param nfds  Entries in @p fds.
 * @param rule  Output: the matching rule copy.
 * @return Non-zero if any descriptor matched; 0 otherwise or while no rule is active.
 */
static int chaos_net_wait_match_pollfds(struct pollfd *fds, nfds_t nfds, chaos_net_rule_t *rule)
{
    nfds_t index;

    if (fds == NULL || rule == NULL || !chaos_net_config_prepare())
    {
        return 0;
    }

    for (index = 0U; index < nfds; ++index)
    {
        if (fds[index].fd >= 0 && chaos_net_wait_match_fd_loaded(fds[index].fd, rule))
        {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief First descriptor of select()/pselect() sets that matches a POLL rule.
 *
 * @details chaos_net_config_prepare() once, then fds 0 to @p nfds - 1 that are in at
 * least one set. Stops at the first match.
 *
 * @param nfds      The select() nfds argument (highest fd + 1); <= 0 yields 0.
 * @param readfds   Read set; may be NULL.
 * @param writefds  Write set; may be NULL.
 * @param exceptfds Exception set; may be NULL.
 * @param rule      Output: the matching rule copy.
 * @return Non-zero if any watched descriptor matched; 0 otherwise.
 */
static int chaos_net_wait_match_fdsets(
    int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, chaos_net_rule_t *rule
)
{
    int fd;

    if (nfds <= 0 || rule == NULL || !chaos_net_config_prepare())
    {
        return 0;
    }

    for (fd = 0; fd < nfds; ++fd)
    {
        if ((readfds != NULL && FD_ISSET(fd, readfds)) ||
            (writefds != NULL && FD_ISSET(fd, writefds)) ||
            (exceptfds != NULL && FD_ISSET(fd, exceptfds)))
        {
            if (chaos_net_wait_match_fd_loaded(fd, rule))
            {
                return 1;
            }
        }
    }
    return 0;
}

#ifdef __linux__
/** @brief Bytes of /proc/self/fdinfo read at a time (a `tfd:` line is under 100 bytes). */
#define CHAOS_NET_FDINFO_CHUNK 512U

/** @brief Most fdinfo bytes scanned per wait (256 KiB, about 4000 watched descriptors). */
#define CHAOS_NET_FDINFO_MAX (256U * 1024U)

/**
 * @brief Scans fdinfo text for a `tfd:` line whose descriptor matches a POLL rule.
 *
 * @details Only lines that end in a newline are parsed: fdinfo ends every line with one,
 * so a last line without it was cut by the buffer, and `tfd:  123` cut to `tfd:  12`
 * would name another descriptor.
 *
 * @param buffer  NUL-terminated text; lines are split in place.
 * @param rule    Output: the matching rule copy.
 * @return 1 when a watched descriptor matches; 0 otherwise.
 */
static int chaos_net_wait_scan_fdinfo(char *buffer, chaos_net_rule_t *rule)
{
    char *cursor = buffer;

    while (*cursor != '\0')
    {
        char *line = cursor;

        while (*cursor != '\0' && *cursor != '\n')
        {
            ++cursor;
        }
        if (*cursor != '\n')
        {
            break; /* cut by the buffer: the caller carries it into the next piece */
        }
        *cursor++ = '\0';

        /* A "tfd:" line names one watched descriptor. */
        if (strncmp(line, "tfd:", 4) == 0)
        {
            char *end = NULL;
            long target_fd = strtol(line + 4, &end, 10);

            if (end != line + 4 && target_fd >= 0L &&
                chaos_net_wait_match_fd_loaded((int)target_fd, rule))
            {
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief Scans /proc/self/fdinfo/<epfd> for a watched descriptor that matches a POLL rule.
 *
 * @details The file is read through libc open/read/close with the guard set, so
 * libchaos-net's own read and close wrappers forward these calls without matching (other
 * preloaded libraries still see them). It is read in CHAOS_NET_FDINFO_CHUNK pieces into
 * a stack buffer; a line cut at the end of a piece is moved to the front and completed
 * by the next read, and a line longer than the buffer (never a `tfd:` line) is skipped.
 * Scanning stops at the first match, at EOF or error, or once more than
 * CHAOS_NET_FDINFO_MAX bytes were read; descriptors past that point are not inspected
 * (fail-open).
 *
 * @param epfd  The epoll descriptor.
 * @param rule  Output: the matching rule copy.
 * @return Non-zero if a watched descriptor matched; 0 on no match or any error.
 * @par Stack: about 600 bytes, safe on a small signal stack.
 * @par errno: clobbered; see chaos_net_wait_match_epoll().
 */
static int chaos_net_wait_match_epoll_fdinfo(int epfd, chaos_net_rule_t *rule)
{
    char path[64];
    /* Small, read in pieces: a wait can run in a signal handler on a small alternate
     * stack, and an epoll instance may watch thousands of descriptors. */
    char buffer[CHAOS_NET_FDINFO_CHUNK];
    size_t used = 0U;
    size_t total = 0U;
    int skipping = 0;
    int found = 0;
    int fd;
    int previous;

    if (rule == NULL || !chaos_net_config_prepare())
    {
        return 0;
    }
    if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", epfd) < 0)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        chaos_net_leave_internal(previous);
        return 0;
    }

    while (!found)
    {
        const ssize_t rc = read(fd, buffer + used, sizeof(buffer) - 1U - used);
        char *last;

        if (rc <= 0 || total > CHAOS_NET_FDINFO_MAX)
        {
            break;
        }
        total += (size_t)rc;
        used += (size_t)rc;
        buffer[used] = '\0';
        last = strrchr(buffer, '\n');
        if (last == NULL)
        {
            /* A line longer than the buffer is not a tfd line: skip to its end. */
            if (used == sizeof(buffer) - 1U)
            {
                used = 0U;
                skipping = 1;
            }
            continue;
        }
        {
            char *tail = last + 1;
            const size_t tail_length = used - (size_t)(tail - buffer);
            char *lines = buffer;

            if (skipping)
            {
                lines = strchr(buffer, '\n') + 1;
                skipping = 0;
            }
            const char first = *tail;

            *tail = '\0';
            found = lines < tail && chaos_net_wait_scan_fdinfo(lines, rule);
            /* The cut line continues in the next piece. */
            *tail = first;
            (void)memmove(buffer, tail, tail_length);
            used = tail_length;
        }
    }
    (void)close(fd);
    chaos_net_leave_internal(previous);
    return found;
}

/**
 * @brief chaos_net_wait_match_epoll_fdinfo(), preserving errno.
 *
 * @details The fdinfo open and read are the library's own; they must not change the
 * errno the caller sees.
 */
static int chaos_net_wait_match_epoll(int epfd, chaos_net_rule_t *rule)
{
    const int saved_errno = errno;
    const int result = chaos_net_wait_match_epoll_fdinfo(epfd, rule);

    errno = saved_errno;
    return result;
}
#endif

/**
 * @brief The wait of a firing TIMEOUT: ppoll on no descriptors for @p wait under
 *        @p sigmask (NULL: the thread's own mask), with the kernel's 8-byte signal set.
 *
 * @details A raw system call, so libchaos-time cannot shorten or stretch it. Test seam:
 * unit tests replace it.
 */
#ifndef CHAOS_NET_TIMEOUT_WAIT
#define CHAOS_NET_TIMEOUT_WAIT(wait, sigmask)                                                      \
    syscall(SYS_ppoll, NULL, 0, (wait), (sigmask), (size_t)8U)
#endif

/**
 * @brief Pre-call effects of a wait that runs under @p sigmask (ppoll, pselect,
 *        epoll_pwait); a firing TIMEOUT waits under that mask too.
 *
 * @details LATENCY sleeps and the real call follows. ERRNO returns -1. TIMEOUT, for a
 * call with a timeout (@p timeout_ms >= 0) and when the rule fires, waits out the
 * timeout and sets @p synthetic_timeout, and the caller fakes "nothing ready".
 *
 * @param rule              Matched rule copy; NULL is a no-op.
 * @param timeout_ms        The call's timeout in ms, rounded up; -1 for none (or one the
 *                          kernel would refuse), which TIMEOUT never applies to.
 * @param sigmask           Mask for the TIMEOUT wait; NULL keeps the thread's mask.
 * @param synthetic_timeout Output, may be NULL: 1 when TIMEOUT fired, else 0.
 * @return 0 to proceed (real call, or the synthetic timeout); -1 with errno set when ERRNO
 *         fired, or with EINTR when a signal ended the TIMEOUT wait, as it would end the
 *         real one.
 */
static int chaos_net_wait_pre_call_masked(
    const chaos_net_rule_t *rule,
    int64_t timeout_ms,
    const sigset_t *sigmask,
    int *synthetic_timeout
)
{
    if (synthetic_timeout != NULL)
    {
        *synthetic_timeout = 0;
    }
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(rule);
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(rule))
    {
        return -1;
    }
    if (rule->effect == CHAOS_NET_EFFECT_TIMEOUT && timeout_ms >= 0 &&
        chaos_net_rule_should_trigger(rule))
    {
        struct timespec wait;

        wait.tv_sec = (time_t)(timeout_ms / 1000);
        wait.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        if (CHAOS_NET_TIMEOUT_WAIT(&wait, sigmask) != 0)
        {
            return -1;
        }
        if (synthetic_timeout != NULL)
        {
            *synthetic_timeout = 1;
        }
        return 0;
    }
    return 0;
}

/**
 * @brief chaos_net_wait_pre_call_masked() under the thread's own signal mask (poll,
 *        select, epoll_wait).
 */
static int
chaos_net_wait_pre_call(const chaos_net_rule_t *rule, int64_t timeout_ms, int *synthetic_timeout)
{
    return chaos_net_wait_pre_call_masked(rule, timeout_ms, NULL, synthetic_timeout);
}

/**
 * @brief Timeout of a timespec in ms, rounded up; -1 for none (NULL) and for one the
 *        kernel refuses (negative, or tv_nsec out of range), which TIMEOUT then leaves to
 *        the real call. Values above INT32_MAX / 1000 seconds saturate at INT32_MAX ms.
 */
static int64_t chaos_net_wait_timespec_ms(const struct timespec *timeout)
{
    if (timeout == NULL || timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
        timeout->tv_nsec >= 1000000000L)
    {
        return -1;
    }
    if (timeout->tv_sec > (time_t)(INT32_MAX / 1000))
    {
        return INT32_MAX;
    }
    return (int64_t)timeout->tv_sec * 1000 + (timeout->tv_nsec + 999999L) / 1000000L;
}

/** @brief Timeout of a timeval in ms, rounded up; -1 for none (NULL) or an invalid one. */
static int64_t chaos_net_wait_timeval_ms(const struct timeval *timeout)
{
    struct timespec converted;

    if (timeout == NULL)
    {
        return -1;
    }
    converted.tv_sec = timeout->tv_sec;
    converted.tv_nsec = (long)timeout->tv_usec * 1000L;
    return chaos_net_wait_timespec_ms(&converted);
}

/**
 * @brief Clears every revents of a pollfd array, for a synthetic poll/ppoll timeout.
 *
 * @param fds   Array to clear; NULL is a no-op.
 * @param nfds  Entries to clear.
 */
static void chaos_net_wait_clear_pollfds(struct pollfd *fds, nfds_t nfds)
{
    nfds_t index;

    if (fds == NULL)
    {
        return;
    }

    for (index = 0U; index < nfds; ++index)
    {
        fds[index].revents = 0;
    }
}

/**
 * @brief Clears every given fd_set, for a synthetic select/pselect timeout.
 *
 * @param readfds   Read set; NULL is skipped.
 * @param writefds  Write set; NULL is skipped.
 * @param exceptfds Exception set; NULL is skipped.
 */
static void chaos_net_wait_clear_fdsets(fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
    if (readfds != NULL)
    {
        FD_ZERO(readfds);
    }
    if (writefds != NULL)
    {
        FD_ZERO(writefds);
    }
    if (exceptfds != NULL)
    {
        FD_ZERO(exceptfds);
    }
}

/*---------------------------------------------------------------------------
 * Calls to the real functions: guard set; raw system call before resolution.
 * arm64 has no poll, select or epoll_wait system call: the fallbacks use ppoll,
 * pselect6 and epoll_pwait on both architectures, with the kernel's 8-byte sigset.
 *---------------------------------------------------------------------------*/

/** @brief Calls the real poll(2) with the guard set; SYS_ppoll before resolution. */
static int chaos_net_call_real_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int previous;
    int rc;

    if (g_chaos_net_real_poll == NULL)
    {
        /* Not resolved yet: a call from inside the symbol lookup. arm64 has no poll
         * system call, so both architectures use ppoll. */
        struct timespec wait;

        wait.tv_sec = (time_t)(timeout / 1000);
        wait.tv_nsec = (long)(timeout % 1000) * 1000000L;
        return (int)syscall(SYS_ppoll, fds, nfds, timeout < 0 ? NULL : &wait, NULL, (size_t)8U);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_poll(fds, nfds, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real ppoll(2) with the guard set; SYS_ppoll before resolution. */
static int chaos_net_call_real_ppoll(
    struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask
)
{
    int previous;
    int rc;

    if (g_chaos_net_real_ppoll == NULL)
    {
        /* The kernel writes the time left back, but the caller's timeout is const. */
        struct timespec wait = {0, 0};
        struct timespec *wait_for = NULL;

        if (timeout != NULL)
        {
            wait = *timeout;
            wait_for = &wait;
        }
        return (int)syscall(SYS_ppoll, fds, nfds, wait_for, sigmask, (size_t)8U);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_ppoll(fds, nfds, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real select(2) with the guard set; SYS_pselect6 before resolution. */
static int chaos_net_call_real_select(
    int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
)
{
    int previous;
    int rc;

    if (g_chaos_net_real_select == NULL)
    {
        /* arm64 has no select system call: pselect6, with the time left written back
         * into the timeval as Linux's select does. */
        struct timespec wait = {0, 0};
        struct timespec *wait_for = NULL;

        if (timeout != NULL)
        {
            wait.tv_sec = timeout->tv_sec;
            wait.tv_nsec = (long)timeout->tv_usec * 1000L;
            wait_for = &wait;
        }
        rc = (int)syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, wait_for, NULL);
        if (timeout != NULL)
        {
            timeout->tv_sec = wait.tv_sec;
            timeout->tv_usec = (suseconds_t)(wait.tv_nsec / 1000L);
        }
        return rc;
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_select(nfds, readfds, writefds, exceptfds, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real pselect(2) with the guard set; SYS_pselect6 before resolution. */
static int chaos_net_call_real_pselect(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timespec *timeout,
    const sigset_t *sigmask
)
{
    int previous;
    int rc;

    if (g_chaos_net_real_pselect == NULL)
    {
        /* pselect6 takes the mask together with its size, and writes the time left back
         * into its own copy of the timeout. */
        struct timespec wait = {0, 0};
        struct timespec *wait_for = NULL;
        struct
        {
            const sigset_t *set;
            size_t size;
        } mask;

        if (timeout != NULL)
        {
            wait = *timeout;
            wait_for = &wait;
        }
        mask.set = sigmask;
        mask.size = (size_t)8U;
        return (int)syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, wait_for, &mask);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/** @brief Calls the real epoll_wait(2) with the guard set (Linux). */
static int
chaos_net_call_real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int previous;
    int rc;

    if (g_chaos_net_real_epoll_wait == NULL)
    {
        /* arm64 has no epoll_wait system call: epoll_pwait with no mask. */
        return (int)syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, NULL, (size_t)8U);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_epoll_wait(epfd, events, maxevents, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real epoll_pwait(2) with the guard set (Linux). */
static int chaos_net_call_real_epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    int previous;
    int rc;

    if (g_chaos_net_real_epoll_pwait == NULL)
    {
        return (int)syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, sigmask, (size_t)8U);
    }
    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}
#endif

/*---------------------------------------------------------------------------
 * Wrappers
 *---------------------------------------------------------------------------*/

/**
 * @brief poll(2) wrapper: POLL rules on the first matching descriptor of @p fds.
 *
 * @details LATENCY sleeps before the real poll and leaves its timeout argument as is,
 * so the call can take up to latency + timeout. TIMEOUT waits out @p timeout under the
 * thread's mask, clears every revents and returns 0.
 */
CHAOS_NET_EXPORT int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_wait_match_pollfds(fds, nfds, &rule))
    {
        return chaos_net_call_real_poll(fds, nfds, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, timeout < 0 ? -1 : (int64_t)timeout, &synthetic_timeout) !=
        0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        chaos_net_wait_clear_pollfds(fds, nfds);
        return 0;
    }
    return chaos_net_call_real_poll(fds, nfds, timeout);
}

/**
 * @brief ppoll(2) wrapper: as poll(); a TIMEOUT wait runs under @p sigmask.
 */
CHAOS_NET_EXPORT int
ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_wait_match_pollfds(fds, nfds, &rule))
    {
        return chaos_net_call_real_ppoll(fds, nfds, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call_masked(
            &rule, chaos_net_wait_timespec_ms(timeout), sigmask, &synthetic_timeout
        ) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        chaos_net_wait_clear_pollfds(fds, nfds);
        return 0;
    }
    return chaos_net_call_real_ppoll(fds, nfds, timeout, sigmask);
}

/**
 * @brief select(2) wrapper: POLL rules on the first matching descriptor of the sets.
 *
 * @details A firing TIMEOUT waits out @p timeout, clears all three sets, zeroes
 * @p timeout (the time left, as Linux reports it) and returns 0.
 */
CHAOS_NET_EXPORT int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() ||
        !chaos_net_wait_match_fdsets(nfds, readfds, writefds, exceptfds, &rule))
    {
        return chaos_net_call_real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, chaos_net_wait_timeval_ms(timeout), &synthetic_timeout) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        chaos_net_wait_clear_fdsets(readfds, writefds, exceptfds);
        /* Linux writes the time not slept back into the timeout: none is left. */
        timeout->tv_sec = 0;
        timeout->tv_usec = 0;
        return 0;
    }
    return chaos_net_call_real_select(nfds, readfds, writefds, exceptfds, timeout);
}

/**
 * @brief pselect(2) wrapper: as select(); a TIMEOUT wait runs under @p sigmask, and
 *        @p timeout is const, so nothing is written back.
 */
CHAOS_NET_EXPORT int pselect(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timespec *timeout,
    const sigset_t *sigmask
)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() ||
        !chaos_net_wait_match_fdsets(nfds, readfds, writefds, exceptfds, &rule))
    {
        return chaos_net_call_real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call_masked(
            &rule, chaos_net_wait_timespec_ms(timeout), sigmask, &synthetic_timeout
        ) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        chaos_net_wait_clear_fdsets(readfds, writefds, exceptfds);
        return 0;
    }
    return chaos_net_call_real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

#ifdef __linux__
/**
 * @brief epoll_wait(2) wrapper (Linux): POLL rules on the watched descriptors, listed in
 *        /proc/self/fdinfo/<epfd>.
 *
 * @details A firing TIMEOUT waits out @p timeout and returns 0 without calling the real
 * epoll_wait; the events array is left as is, since a real timeout writes no event.
 */
CHAOS_NET_EXPORT int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_wait_match_epoll(epfd, &rule))
    {
        return chaos_net_call_real_epoll_wait(epfd, events, maxevents, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, timeout < 0 ? -1 : (int64_t)timeout, &synthetic_timeout) !=
        0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        /* No events, no error: what a real epoll timeout returns. */
        return 0;
    }
    return chaos_net_call_real_epoll_wait(epfd, events, maxevents, timeout);
}

/**
 * @brief epoll_pwait(2) wrapper (Linux): as epoll_wait(); a TIMEOUT wait runs under
 *        @p sigmask.
 */
CHAOS_NET_EXPORT int epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_wait_match_epoll(epfd, &rule))
    {
        return chaos_net_call_real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call_masked(
            &rule, timeout < 0 ? -1 : (int64_t)timeout, sigmask, &synthetic_timeout
        ) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        return 0;
    }
    return chaos_net_call_real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}
#endif
