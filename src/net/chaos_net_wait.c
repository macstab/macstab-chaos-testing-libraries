/**
 * @file chaos_net_wait.c
 * @brief LD_PRELOAD interposition wrappers for multiplexed-wait syscalls.
 *
 * @details
 * This file provides the exported interposition symbols for:
 *   - poll(2), ppoll(2)
 *   - select(2), pselect(2)
 *   - epoll_wait(2), epoll_pwait(2)  (Linux only)
 *
 * @par The poll-family matching challenge:
 * Unlike bind/connect/send/recv (which operate on a single known socket fd), the
 * wait family operates on *sets* of fds simultaneously. A single poll() call might
 * wait on 50 fds: some sockets, some pipes, some eventfds. libchaos-net must decide
 * whether to inject a fault without knowing upfront which fd(s) triggered the match.
 *
 * The approach taken is to scan all fds in the set and return at the first fd for
 * which endpoint resolution succeeds and a rule matches. This is a conservative
 * strategy: it injects if *any* fd in the set matches, even if other fds in the
 * same set do not.
 *
 * @par Config preparation amortisation:
 * For poll/ppoll/select/pselect, the scan calls chaos_net_config_prepare() once at
 * the top (via chaos_net_wait_match_pollfds / chaos_net_wait_match_fdsets) and then
 * uses chaos_net_config_match_endpoint_loaded() for each individual fd. This avoids
 * repeated stat(2) calls for every fd in a large poll set, reducing the overhead to
 * one stat per poll invocation regardless of the fd count.
 *
 * @par epoll_wait endpoint resolution (Linux):
 * epoll_wait receives an epoll fd (epfd), not a set of watched fds. The watched fds
 * are not directly available from the epoll fd's arguments. To resolve them,
 * /proc/self/fdinfo/<epfd> is read, which contains lines of the form:
 * @code
 *   tfd: <watched_fd>
 * @endcode
 * for each registered fd. libchaos-net scans these lines and calls
 * chaos_net_wait_match_fd_loaded() on each `tfd` value. This is a best-effort
 * approach: the fdinfo file may not list all fds on non-Linux platforms, and race
 * conditions exist if fds are added/removed from the epoll concurrently. If the
 * fdinfo cannot be read, the call passes through without injection (fail-open).
 *
 * @par TIMEOUT effect:
 * When a TIMEOUT rule fires, the interposed wrapper does NOT call the real wait
 * syscall. Instead it:
 *   - For poll/ppoll: zeroes all revents fields and returns 0 (timeout).
 *   - For select/pselect: zeroes all fd_sets and returns 0 (timeout).
 *   - For epoll_wait/epoll_pwait: returns 0 (no events, not an error).
 * This simulates the OS returning a timeout without waiting, which exercises
 * timeout-handling logic in the application.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Tests whether a single fd's endpoint matches a loaded POLL rule.
 *
 * @details Calls chaos_net_endpoint_from_activity_fd() to resolve the endpoint
 * (trying getsockname first, then getpeername), then
 * chaos_net_config_match_endpoint_loaded() to check the active snapshot without
 * re-triggering a config reload. Assumes chaos_net_config_prepare() has already
 * been called in the current call frame.
 *
 * @param fd    File descriptor to examine.
 * @param rule  Output: populated with the matching rule if found.
 * @return Non-zero if @p fd's endpoint matches a POLL rule; 0 otherwise.
 */
static int chaos_net_wait_match_fd_loaded(int fd, chaos_net_rule_t *rule)
{
    chaos_net_endpoint_t endpoint;

    return chaos_net_endpoint_from_activity_fd(fd, &endpoint) &&
           chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_POLL, &endpoint, rule);
}

/**
 * @brief Scans a pollfd array for the first fd whose endpoint matches a POLL rule.
 *
 * @details Calls chaos_net_config_prepare() once, then iterates over all fds with
 * non-negative fd fields (negative fd values are ignored by the kernel in poll()).
 * Returns on the first match; does not scan all fds.
 *
 * @param fds   Array of pollfds. May be NULL (returns 0).
 * @param nfds  Number of elements in @p fds.
 * @param rule  Output: populated with the first matching rule.
 * @return Non-zero if any fd in the set matched a rule; 0 otherwise.
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
 * @brief Scans select()/pselect() fd_sets for the first fd matching a POLL rule.
 *
 * @details Iterates fds [0, nfds) and checks each that is set in at least one of
 * readfds, writefds, or exceptfds. Returns on the first match.
 *
 * @param nfds      Upper bound on fd values to check (the @p nfds argument to select()).
 * @param readfds   Read set. May be NULL.
 * @param writefds  Write set. May be NULL.
 * @param exceptfds Exception set. May be NULL.
 * @param rule      Output: populated with the first matching rule.
 * @return Non-zero if any watched fd matched a rule; 0 otherwise.
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
/**
 * @brief Reads /proc/self/fdinfo/<epfd> and scans for watched fds matching a POLL rule.
 *
 * @details The fdinfo file for an epoll fd contains one `tfd:` line per registered fd.
 * This function reads the file with the reentrancy guard set (to prevent interposition
 * of open/read/close), then parses each `tfd:` line to extract the watched fd value.
 *
 * The buffer is sized 16 KiB (sizeof(buffer) == 16384), which accommodates epoll
 * instances with approximately 1000 watched fds before truncation. If the file is
 * larger than the buffer, reading stops at the buffer boundary and the fd list is
 * incomplete. This is a best-effort scan: in practice, epoll instances with >1000
 * fds are rare in test scenarios, and truncation only means some fds are not
 * inspected — the call passes through without injection (fail-open).
 *
 * @param epfd  The epoll file descriptor to inspect.
 * @param rule  Output: populated with the first matching rule.
 * @return Non-zero if any watched fd matched a POLL rule; 0 if no match or error.
 * @par Thread-safety: reentrancy guard prevents recursive interposition; safe.
 * @par Blocking: reads from /proc (in-kernel VFS); should not block in practice.
 */
static int chaos_net_wait_match_epoll(int epfd, chaos_net_rule_t *rule)
{
    char path[64];
    char buffer[16384];
    size_t used = 0U;
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

    for (;;)
    {
        ssize_t rc = read(fd, buffer + used, sizeof(buffer) - 1U - used);
        if (rc < 0)
        {
            (void)close(fd);
            chaos_net_leave_internal(previous);
            return 0;
        }
        if (rc == 0)
        {
            break;
        }
        used += (size_t)rc;
        /* Stop at buffer capacity - 1; NUL terminator needs one byte. */
        if (used == sizeof(buffer) - 1U)
        {
            break;
        }
    }
    (void)close(fd);
    chaos_net_leave_internal(previous);
    buffer[used] = '\0';

    {
        char *cursor = buffer;

        while (*cursor != '\0')
        {
            char *line = cursor;

            while (*cursor != '\0' && *cursor != '\n')
            {
                ++cursor;
            }
            if (*cursor == '\n')
            {
                *cursor++ = '\0';
            }

            /* Lines starting with "tfd:" list watched file descriptors. */
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
    }

    return 0;
}
#endif

/**
 * @brief Applies pre-call effects for wait syscalls, with synthetic-timeout support.
 *
 * @details Extends the standard pre-call effect dispatcher with TIMEOUT handling.
 * If a TIMEOUT rule fires, @p synthetic_timeout is set to 1 and the function
 * returns 0 (not -1) because the interposed wrapper should return 0 (no ready fds),
 * not -1 (error). The caller checks synthetic_timeout to decide whether to call
 * the real syscall or synthesise a timeout return.
 *
 * @param rule              Matched rule. May be NULL (no-op).
 * @param synthetic_timeout Output: set to 1 if TIMEOUT effect fires; otherwise 0.
 *                          May be NULL (effect still applied, flag is not stored).
 * @return 0 to indicate the real syscall should proceed or a synthetic timeout
 *         should be returned; -1 if ERRNO injection fired (set errno, skip real call).
 */
static int chaos_net_wait_pre_call(const chaos_net_rule_t *rule, int *synthetic_timeout)
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
    if (rule->effect == CHAOS_NET_EFFECT_TIMEOUT && chaos_net_rule_should_trigger(rule))
    {
        if (synthetic_timeout != NULL)
        {
            *synthetic_timeout = 1;
        }
        return 0;
    }
    return 0;
}

/**
 * @brief Clears all revents fields in a pollfd array.
 *
 * @details Used to build the synthetic timeout return: poll()/ppoll() return 0
 * (no ready fds) with all revents cleared. The caller is responsible for the
 * return value of 0.
 *
 * @param fds   Array to clear. No-op if NULL.
 * @param nfds  Number of elements to clear.
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
 * @brief Clears all fd_sets used for a synthetic select/pselect timeout.
 *
 * @details select()/pselect() returns 0 (no ready fds) with all sets cleared.
 * FD_ZERO is used on each non-NULL set.
 *
 * @param readfds   Read set to zero. May be NULL.
 * @param writefds  Write set to zero. May be NULL.
 * @param exceptfds Exception set to zero. May be NULL.
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
 * Real-symbol call wrappers (reentrancy-guard wrappers)
 *---------------------------------------------------------------------------*/

/** @brief Calls the real poll(2) with reentrancy guard set. */
static int chaos_net_call_real_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_poll(fds, nfds, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real ppoll(2) with reentrancy guard set. */
static int chaos_net_call_real_ppoll(
    struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask
)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_ppoll(fds, nfds, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real select(2) with reentrancy guard set. */
static int chaos_net_call_real_select(
    int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_select(nfds, readfds, writefds, exceptfds, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real pselect(2) with reentrancy guard set. */
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

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}

#ifdef __linux__
/** @brief Calls the real epoll_wait(2) with reentrancy guard set (Linux only). */
static int
chaos_net_call_real_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_epoll_wait(epfd, events, maxevents, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

/** @brief Calls the real epoll_pwait(2) with reentrancy guard set (Linux only). */
static int chaos_net_call_real_epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    chaos_net_leave_internal(previous);
    return rc;
}
#endif

/*---------------------------------------------------------------------------
 * Interposed symbols
 *---------------------------------------------------------------------------*/

/**
 * @brief Interposed poll(2).
 *
 * @details Scans the pollfd array for a matching fd, applies pre-call effects,
 * and either synthesises a timeout (clearing revents, returning 0) or forwards
 * to the real poll. The timeout value passed to the real poll is not modified;
 * LATENCY injection adds sleep before the real call, it does not alter the poll
 * timeout argument.
 */
CHAOS_NET_EXPORT int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    if (chaos_net_in_internal() || !chaos_net_wait_match_pollfds(fds, nfds, &rule))
    {
        return chaos_net_call_real_poll(fds, nfds, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
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
 * @brief Interposed ppoll(2).
 *
 * @details Same logic as poll(); the signal mask argument is forwarded unchanged
 * to the real call when not synthesising a timeout.
 */
CHAOS_NET_EXPORT int
ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    if (chaos_net_in_internal() || !chaos_net_wait_match_pollfds(fds, nfds, &rule))
    {
        return chaos_net_call_real_ppoll(fds, nfds, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
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
 * @brief Interposed select(2).
 *
 * @details Scans all three fd_sets for a matching fd. On synthetic timeout,
 * clears all three sets and returns 0.
 */
CHAOS_NET_EXPORT int
select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    if (chaos_net_in_internal() ||
        !chaos_net_wait_match_fdsets(nfds, readfds, writefds, exceptfds, &rule))
    {
        return chaos_net_call_real_select(nfds, readfds, writefds, exceptfds, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        chaos_net_wait_clear_fdsets(readfds, writefds, exceptfds);
        return 0;
    }
    return chaos_net_call_real_select(nfds, readfds, writefds, exceptfds, timeout);
}

/**
 * @brief Interposed pselect(2).
 *
 * @details Same logic as select(); signal mask and nanosecond timeout are
 * forwarded unchanged to the real call.
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

    if (chaos_net_in_internal() ||
        !chaos_net_wait_match_fdsets(nfds, readfds, writefds, exceptfds, &rule))
    {
        return chaos_net_call_real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
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
 * @brief Interposed epoll_wait(2) (Linux only).
 *
 * @details Uses /proc/self/fdinfo to enumerate the watched fds and find a match.
 * On synthetic timeout, returns 0 without calling the real epoll_wait. The events
 * array is not cleared because epoll_wait returns 0 when no events are ready, and
 * the kernel would not have written any events in that case.
 */
CHAOS_NET_EXPORT int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    if (chaos_net_in_internal() || !chaos_net_wait_match_epoll(epfd, &rule))
    {
        return chaos_net_call_real_epoll_wait(epfd, events, maxevents, timeout);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
    {
        return -1;
    }
    if (synthetic_timeout != 0)
    {
        /* Return 0: no events, no error; consistent with a real epoll timeout. */
        return 0;
    }
    return chaos_net_call_real_epoll_wait(epfd, events, maxevents, timeout);
}

/**
 * @brief Interposed epoll_pwait(2) (Linux only).
 *
 * @details Same logic as epoll_wait(); signal mask is forwarded to the real call.
 */
CHAOS_NET_EXPORT int epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    chaos_net_rule_t rule;
    int synthetic_timeout = 0;

    if (chaos_net_in_internal() || !chaos_net_wait_match_epoll(epfd, &rule))
    {
        return chaos_net_call_real_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
    }
    if (chaos_net_wait_pre_call(&rule, &synthetic_timeout) != 0)
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
