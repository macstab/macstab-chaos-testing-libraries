#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int chaos_net_wait_match_fd_loaded(int fd, chaos_net_rule_t *rule)
{
    chaos_net_endpoint_t endpoint;

    return chaos_net_endpoint_from_activity_fd(fd, &endpoint) &&
           chaos_net_config_match_endpoint_loaded(CHAOS_NET_OP_POLL, &endpoint, rule);
}

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

static int chaos_net_call_real_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int previous;
    int rc;

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_poll(fds, nfds, timeout);
    chaos_net_leave_internal(previous);
    return rc;
}

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
        return 0;
    }
    return chaos_net_call_real_epoll_wait(epfd, events, maxevents, timeout);
}

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
