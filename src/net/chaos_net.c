/**
 * @file chaos_net.c
 * @brief libchaos-net constructor, real-function resolution and global state.
 *
 * @details
 * Owns:
 *   1. **Global state**: the g_chaos_net_real_* pointers declared in
 *      chaos_net_internal.h, the thread-local guard and PRNG state, the process seed.
 *   2. **Resolution**: chaos_net_ensure_symbols() resolves every real function once
 *      through dlsym(RTLD_NEXT), from whichever wrapper or the constructor runs first.
 *      A symbol that does not resolve aborts the process: a wrapper without a real
 *      function would silently break the program.
 *   3. **Entropy**: 8 bytes from /dev/urandom through raw system calls, else a constant
 *      XOR getpid().
 *   4. **Constructor**: chaos_net_init() resolves, seeds, resets the rule subsystem and
 *      loads the rule file once, so a bad rule file is reported in the status file at
 *      start-up rather than at the first socket call.
 *
 * @par Invariants:
 *   - Every g_chaos_net_real_* pointer is non-NULL once the resolution has completed;
 *     only a call made from inside it, on its own thread, can see NULL.
 *   - g_chaos_net_process_seed is written once, by the constructor.
 *
 * @par Fork and exec:
 *   fork() children inherit the resolved pointers and the seed; the config atfork handler
 *   zeroes the forking thread's PRNG state so the child draws its own sequence. exec()
 *   runs the constructor again in the new image when LD_PRELOAD still names the library.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_once.h"
#include "chaos_net_config.h"
#include "chaos_net_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------------
 * Real-function pointers.
 *
 * NULL until chaos_net_ensure_symbols() fills them; written once, so hot-path reads
 * need no synchronisation. A wrapper that finds one still NULL issues the system call
 * directly.
 *---------------------------------------------------------------------------*/

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
chaos_net_setsockopt_fn g_chaos_net_real_setsockopt = NULL;
chaos_net_read_fn g_chaos_net_real_read = NULL;
chaos_net_write_fn g_chaos_net_real_write = NULL;
chaos_net_readv_fn g_chaos_net_real_readv = NULL;
chaos_net_readv_fn g_chaos_net_real_writev = NULL;
chaos_net_close_fn g_chaos_net_real_close = NULL;

/** @brief Once-control of the resolution (chaos_once.h: no libpthread before glibc 2.34). */
static volatile chaos_once_t g_chaos_net_symbols_once = CHAOS_ONCE_INIT;
#ifdef __linux__
chaos_net_accept4_fn g_chaos_net_real_accept4 = NULL;
chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg = NULL;
chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg = NULL;
chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait = NULL;
chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait = NULL;
#endif

/*---------------------------------------------------------------------------
 * Thread-local and process-wide state.
 *---------------------------------------------------------------------------*/

/** @brief See chaos_net_internal.h. 0 = not inside a library section. */
__thread int g_chaos_net_tls_guard = 0;

/** @brief See chaos_net_internal.h. 0 = not seeded yet. */
__thread uint64_t g_chaos_net_tls_prng_state = 0U;

/**
 * @brief Process-wide PRNG seed; replaced once by chaos_net_init().
 *
 * @details The non-zero initialiser keeps a draw made before the constructor (a wrapper
 * reached from another object's initialiser) away from a degenerate seed.
 */
uint64_t g_chaos_net_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/*---------------------------------------------------------------------------
 * Constructor attribute
 *---------------------------------------------------------------------------*/

/**
 * @brief Constructor attribute of chaos_net_init(); a test seam.
 *
 * @details Unit tests define CHAOS_NET_CONSTRUCTOR as empty before including this file
 * and call chaos_net_init() themselves, to control initialisation order.
 */
#ifndef CHAOS_NET_CONSTRUCTOR
#define CHAOS_NET_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * @brief Resolves @p symbol with dlsym(RTLD_NEXT) into the pointer at @p target, once.
 *
 * @details RTLD_NEXT returns the next definition after this DSO in lookup order: libc, or
 * another preloaded library (libchaos-io for read/write/close), which keeps every library
 * in the chain. A pointer already set (by an earlier call or a test harness) is left
 * alone. dlsym returning NULL with dlerror() set is a genuine lookup failure and aborts:
 * without a real function the wrapper cannot do its job, and passing calls nowhere would
 * corrupt the program. The pointer is copied with memcpy because ISO C does not allow
 * converting between void * and function pointers.
 *
 * @param target  Address of the g_chaos_net_real_* variable; must not be NULL.
 * @param symbol  Symbol name, e.g. "bind"; must not be NULL.
 * @post *target is non-NULL, or the process has aborted.
 */
static void chaos_net_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;
    void *current;

    /* Fill only what is unset: a pointer already wired (an earlier call, a test harness)
     * is never replaced. */
    (void)memcpy(&current, target, sizeof(current));
    if (current != NULL)
    {
        return;
    }

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
    {
        abort();
    }

    /* memcpy: ISO C has no conversion between object and function pointers. */
    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief 8 bytes from /dev/urandom for the process seed; a pid-derived fallback.
 *
 * @details Linux: raw SYS_openat/SYS_read/SYS_close, not the libc functions. libc's open,
 * read and close are wrapped by this library (read, close) and by libchaos-io, whose
 * rules must not decide or delay the seeding, and the wrappers may not be usable yet when
 * the constructor runs. The guard is set anyway, for symmetry with every other library
 * call. A failed open or a short read falls back to a constant XOR getpid(): weaker, but
 * still distinct per process.
 *
 * @return The seed.
 * @par errno: may be clobbered; see chaos_net_read_seed_material().
 */
static uint64_t chaos_net_read_urandom_seed(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    /* Raw system calls are not interposable; the guard is defensive, for symmetry with
     * every other library call. */
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

    /* Fallback: a constant XOR the pid; weak, but non-zero and different per process. */
    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/**
 * @brief chaos_net_read_urandom_seed(), preserving errno.
 *
 * @details Called by the constructor (and by unit tests through chaos_net_init()). The
 * library's own /dev/urandom read must leave errno as the program had it.
 */
static uint64_t chaos_net_read_seed_material(void)
{
    const int saved_errno = errno;
    const uint64_t seed = chaos_net_read_urandom_seed();

    errno = saved_errno;
    return seed;
}

/**
 * @brief Resolves every real function. Runs once, through chaos_net_ensure_symbols().
 *
 * @details Must not call a wrapper: on this thread a re-entry into chaos_once() returns
 * at once with the pointers still unset. dlsym(RTLD_NEXT) walks the loaded link map and
 * does no file I/O; if it allocates, an allocator that reaches a wrapper finds the
 * pointers NULL and is served by the raw system call.
 */
static void chaos_net_resolve_all_symbols(void)
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
    chaos_net_resolve_symbol(&g_chaos_net_real_setsockopt, "setsockopt");
    chaos_net_resolve_symbol(&g_chaos_net_real_read, "read");
    chaos_net_resolve_symbol(&g_chaos_net_real_write, "write");
    chaos_net_resolve_symbol(&g_chaos_net_real_readv, "readv");
    chaos_net_resolve_symbol(&g_chaos_net_real_writev, "writev");
    chaos_net_resolve_symbol(&g_chaos_net_real_close, "close");
#ifdef __linux__
    chaos_net_resolve_symbol(&g_chaos_net_real_accept4, "accept4");
    chaos_net_resolve_symbol(&g_chaos_net_real_sendmmsg, "sendmmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_recvmmsg, "recvmmsg");
    chaos_net_resolve_symbol(&g_chaos_net_real_epoll_wait, "epoll_wait");
    chaos_net_resolve_symbol(&g_chaos_net_real_epoll_pwait, "epoll_pwait");
#endif
}

void chaos_net_ensure_symbols(void)
{
    (void)chaos_once(&g_chaos_net_symbols_once, chaos_net_resolve_all_symbols);
}

/**
 * @brief Library constructor: resolves, seeds, resets the rules, loads the rule file.
 *
 * @details Run by the dynamic linker before main(), but possibly after another object's
 * constructor has already reached a wrapper (which then ran the resolution itself).
 * Order:
 *   1. chaos_net_ensure_symbols(): everything after may call a real function.
 *   2. Seed: the process seed, and this thread's PRNG state. Other threads seed lazily.
 *   3. chaos_net_config_init(): empty snapshots, stamp UNKNOWN, fork handler.
 *   4. chaos_net_config_prepare(): first load, status file written.
 *
 * @post Every g_chaos_net_real_* pointer is non-NULL.
 * @post The rule file, if any, is loaded and reported.
 */
CHAOS_NET_CONSTRUCTOR
static void chaos_net_init(void)
{
    chaos_net_ensure_symbols();
    g_chaos_net_process_seed = chaos_net_read_seed_material();
    chaos_net_prng_seed_thread(g_chaos_net_process_seed);
    chaos_net_config_init();
    /* Load the rules now so a bad rule file is reported at start-up. */
    (void)chaos_net_config_prepare();
}
