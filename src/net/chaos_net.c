#include "chaos_net_config.h"
#include "chaos_net_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

chaos_net_bind_fn g_chaos_net_real_bind = NULL;
chaos_net_listen_fn g_chaos_net_real_listen = NULL;
chaos_net_connect_fn g_chaos_net_real_connect = NULL;
chaos_net_accept_fn g_chaos_net_real_accept = NULL;
chaos_net_socket_fn g_chaos_net_real_socket = NULL;
chaos_net_socketpair_fn g_chaos_net_real_socketpair = NULL;
chaos_net_shutdown_fn g_chaos_net_real_shutdown = NULL;
chaos_net_send_fn g_chaos_net_real_send = NULL;
chaos_net_sendto_fn g_chaos_net_real_sendto = NULL;
chaos_net_sendmsg_fn g_chaos_net_real_sendmsg = NULL;
chaos_net_recv_fn g_chaos_net_real_recv = NULL;
chaos_net_recvfrom_fn g_chaos_net_real_recvfrom = NULL;
chaos_net_recvmsg_fn g_chaos_net_real_recvmsg = NULL;
chaos_net_poll_fn g_chaos_net_real_poll = NULL;
chaos_net_ppoll_fn g_chaos_net_real_ppoll = NULL;
chaos_net_select_fn g_chaos_net_real_select = NULL;
chaos_net_pselect_fn g_chaos_net_real_pselect = NULL;
chaos_net_getsockname_fn g_chaos_net_real_getsockname = NULL;
chaos_net_getpeername_fn g_chaos_net_real_getpeername = NULL;
chaos_net_getsockopt_fn g_chaos_net_real_getsockopt = NULL;
#ifdef __linux__
chaos_net_accept4_fn g_chaos_net_real_accept4 = NULL;
chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg = NULL;
chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg = NULL;
chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait = NULL;
chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait = NULL;
#endif

__thread int g_chaos_net_tls_guard = 0;
__thread uint64_t g_chaos_net_tls_prng_state = 0U;
uint64_t g_chaos_net_process_seed = UINT64_C(0x2545f4914f6cdd1d);

#ifndef CHAOS_NET_CONSTRUCTOR
#define CHAOS_NET_CONSTRUCTOR __attribute__((constructor))
#endif

static void chaos_net_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
    {
        abort();
    }

    (void)memcpy(target, &resolved, sizeof(resolved));
}

static uint64_t chaos_net_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    previous = chaos_net_enter_internal();
    fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
    if (fd >= 0)
    {
        ssize_t rc = (ssize_t)syscall(SYS_read, fd, &seed, sizeof(seed));
        (void)syscall(SYS_close, fd);
        chaos_net_leave_internal(previous);
        if (rc == (ssize_t)sizeof(seed))
        {
            return seed;
        }
    }
    else
    {
        chaos_net_leave_internal(previous);
    }
#endif

    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

CHAOS_NET_CONSTRUCTOR
static void chaos_net_init(void)
{
    chaos_net_resolve_symbol(&g_chaos_net_real_bind, "bind");
    chaos_net_resolve_symbol(&g_chaos_net_real_listen, "listen");
    chaos_net_resolve_symbol(&g_chaos_net_real_connect, "connect");
    chaos_net_resolve_symbol(&g_chaos_net_real_accept, "accept");
    chaos_net_resolve_symbol(&g_chaos_net_real_socket, "socket");
    chaos_net_resolve_symbol(&g_chaos_net_real_socketpair, "socketpair");
    chaos_net_resolve_symbol(&g_chaos_net_real_shutdown, "shutdown");
    chaos_net_resolve_symbol(&g_chaos_net_real_send, "send");
    chaos_net_resolve_symbol(&g_chaos_net_real_sendto, "sendto");
    chaos_net_resolve_symbol(&g_chaos_net_real_sendmsg, "sendmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_recv, "recv");
    chaos_net_resolve_symbol(&g_chaos_net_real_recvfrom, "recvfrom");
    chaos_net_resolve_symbol(&g_chaos_net_real_recvmsg, "recvmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_poll, "poll");
    chaos_net_resolve_symbol(&g_chaos_net_real_ppoll, "ppoll");
    chaos_net_resolve_symbol(&g_chaos_net_real_select, "select");
    chaos_net_resolve_symbol(&g_chaos_net_real_pselect, "pselect");
    chaos_net_resolve_symbol(&g_chaos_net_real_getsockname, "getsockname");
    chaos_net_resolve_symbol(&g_chaos_net_real_getpeername, "getpeername");
    chaos_net_resolve_symbol(&g_chaos_net_real_getsockopt, "getsockopt");
#ifdef __linux__
    chaos_net_resolve_symbol(&g_chaos_net_real_accept4, "accept4");
    chaos_net_resolve_symbol(&g_chaos_net_real_sendmmsg, "sendmmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_recvmmsg, "recvmmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_epoll_wait, "epoll_wait");
    chaos_net_resolve_symbol(&g_chaos_net_real_epoll_pwait, "epoll_pwait");
#endif

    g_chaos_net_process_seed = chaos_net_read_seed_material();
    chaos_net_prng_seed_thread(g_chaos_net_process_seed);
    chaos_net_config_init();
}
