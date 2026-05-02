/**
 * @file chaos_net.c
 * @brief Library constructor, real-symbol resolution, and global state definitions.
 *
 * @details
 * This translation unit is the entry point for libchaos-net. It owns:
 *
 *   1. **Global state definitions** — the real-symbol function-pointer instances
 *      (g_chaos_net_real_*) declared as extern in chaos_net_internal.h, the
 *      per-thread TLS guard and PRNG state, and the process-wide PRNG seed.
 *
 *   2. **Symbol resolution** — chaos_net_resolve_symbol() wraps dlsym(RTLD_NEXT)
 *      and aborts if a required symbol cannot be found, because continuing without
 *      a real implementation would silently break the target application.
 *
 *   3. **Entropy collection** — chaos_net_read_seed_material() reads 8 bytes from
 *      /dev/urandom via raw Linux syscalls to avoid going through any interposable
 *      libc symbol during construction. Falls back to a compile-time constant
 *      XORed with getpid() on non-Linux platforms or if the read fails.
 *
 *   4. **Constructor** — chaos_net_init() is tagged __attribute__((constructor))
 *      so the dynamic linker runs it before any application code. It resolves all
 *      symbols, seeds the PRNG, and triggers an initial config load.
 *
 * @par Invariants maintained by this file:
 *   - All g_chaos_net_real_* pointers are non-NULL after chaos_net_init() returns.
 *   - g_chaos_net_process_seed is set once and never written again after init.
 *   - chaos_net_init() is the only writer of these global values; all subsequent
 *     accesses are read-only (except per-thread TLS, which each thread manages
 *     independently).
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_config.h"
#include "chaos_net_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------------
 * Real-symbol pointer definitions.
 *
 * Initialised to NULL; populated by chaos_net_init() before any application
 * code runs. Written exactly once, so reads on the hot interposition path
 * require no synchronisation.
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
#ifdef __linux__
chaos_net_accept4_fn g_chaos_net_real_accept4 = NULL;
chaos_net_sendmmsg_fn g_chaos_net_real_sendmmsg = NULL;
chaos_net_recvmmsg_fn g_chaos_net_real_recvmmsg = NULL;
chaos_net_epoll_wait_fn g_chaos_net_real_epoll_wait = NULL;
chaos_net_epoll_pwait_fn g_chaos_net_real_epoll_pwait = NULL;
#endif

/*---------------------------------------------------------------------------
 * Thread-local and process-global state definitions.
 *---------------------------------------------------------------------------*/

/** @brief See declaration in chaos_net_internal.h. Zero = not in internal call. */
__thread int g_chaos_net_tls_guard = 0;

/** @brief See declaration in chaos_net_internal.h. Zero = not yet seeded. */
__thread uint64_t g_chaos_net_tls_prng_state = 0U;

/**
 * @brief Process-wide PRNG seed; overwritten once by chaos_net_init().
 *
 * The initialiser is a non-zero compile-time constant so that PRNG calls made
 * during (or before) library construction — if they ever happen — do not produce
 * zero-state xorshift output.
 */
uint64_t g_chaos_net_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/*---------------------------------------------------------------------------
 * Constructor tag
 *---------------------------------------------------------------------------*/

/**
 * @brief Allows the constructor attribute to be overridden in unit-test builds.
 *
 * @details Test harnesses can define CHAOS_NET_CONSTRUCTOR to an empty string
 * (or to `static`) to prevent the constructor from firing automatically, and
 * instead call chaos_net_init() explicitly to control initialisation order.
 */
#ifndef CHAOS_NET_CONSTRUCTOR
#define CHAOS_NET_CONSTRUCTOR __attribute__((constructor))
#endif

/**
 * @brief Resolves one interposed symbol via dlsym(RTLD_NEXT) and stores the result.
 *
 * @details RTLD_NEXT skips the current DSO and resolves the symbol in the next
 * matching shared object in the link order, which is the real libc implementation.
 * This is the standard LD_PRELOAD pattern.
 *
 * The function aborts if dlsym returns NULL *and* dlerror() is non-NULL, which
 * indicates a genuine lookup failure rather than a symbol that legitimately resolves
 * to NULL address zero (vanishingly rare, but dlsym's API requires the dlerror check).
 * Aborting is intentional: a missing required symbol means the library cannot
 * function correctly, and silently proceeding would corrupt the target application.
 *
 * The result is written through a void** pointer using memcpy to avoid the
 * function-pointer aliasing UB that a direct assignment would cause under strict
 * ISO C aliasing rules.
 *
 * @param target  Pointer to the function-pointer variable to populate (e.g.,
 *                &g_chaos_net_real_bind). Must not be NULL.
 * @param symbol  Name of the symbol to resolve (e.g., "bind"). Must not be NULL.
 * @pre  dlopen / dynamic linker infrastructure must be available.
 * @post *target is non-NULL on return (or the process has aborted).
 */
static void chaos_net_resolve_symbol(void *target, const char *symbol)
{
    void *resolved;

    (void)dlerror();
    resolved = dlsym(RTLD_NEXT, symbol);
    if (resolved == NULL && dlerror() != NULL)
    {
        abort();
    }

    /* memcpy avoids strict-aliasing UB when copying between incompatible pointer types. */
    (void)memcpy(target, &resolved, sizeof(resolved));
}

/**
 * @brief Reads 8 bytes of cryptographic entropy for PRNG seeding.
 *
 * @details On Linux, opens /dev/urandom and reads 8 bytes using raw syscall
 * numbers (SYS_openat, SYS_read, SYS_close) rather than the libc wrappers.
 * This is necessary because:
 *   1. The constructor runs before application threads start, but libc's
 *      internal stdio buffers may not be initialised yet.
 *   2. The interposition wrappers for open/read/close are not yet safe to call
 *      during construction (real pointers may not all be set).
 *   3. On Linux, using raw syscalls from the constructor is the only way to
 *      guarantee no libc re-entrancy.
 *
 * The reentrancy guard is set around the syscalls to prevent any hypothetical
 * future interposition of SYS_read from recursing back through libchaos-net.
 *
 * Falls back to a compile-time constant XORed with getpid() if the file cannot
 * be opened or the read is short. This is weaker (PID-seeded RNG) but still
 * sufficient to distinguish different processes and prevent deterministic replay.
 *
 * @return 8 bytes of entropy as a uint64_t, or a getpid()-derived fallback.
 */
static uint64_t chaos_net_read_seed_material(void)
{
#ifdef __linux__
    uint64_t seed = 0U;
    int fd;
    int previous;

    /* Guard against reentrancy: the raw syscalls below are not interposed, but
     * set the guard defensively to future-proof against any monitoring hooks. */
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

    /* Fallback: compile-time constant XOR pid. Weak but non-zero and process-unique. */
    return UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();
}

/**
 * @brief Library constructor: resolves all real symbols, seeds the PRNG, and
 *        triggers the initial config load.
 *
 * @details Executed by the dynamic linker before any application code in the
 * process. The order of operations is significant:
 *   1. Resolve all real symbols first, because every subsequent step (including
 *      chaos_net_config_init → stat → getsockname etc.) may indirectly invoke
 *      one of the resolved pointers.
 *   2. Seed the PRNG: both the process seed (from /dev/urandom) and the main
 *      thread's per-thread state are set. Worker threads seed themselves lazily
 *      on first use.
 *   3. Initialise the config subsystem, which sets both snapshots to empty and
 *      marks the mtime as UNKNOWN so the first call to chaos_net_config_prepare()
 *      performs a real stat/load.
 *
 * @post All g_chaos_net_real_* pointers are non-NULL.
 * @post g_chaos_net_process_seed holds entropy from /dev/urandom (or fallback).
 * @post Config subsystem is in a clean state ready for the first reload.
 */
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
