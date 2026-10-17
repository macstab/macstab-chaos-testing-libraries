/**
 * @file test_net_runtime.c
 * @brief Unit tests for the libchaos-net constructor: real-function resolution, seeding, the
 *   start-up rule load, and `chaos_once()` re-entry.
 *
 * @details
 * Unit under test: `src/net/chaos_net.c` and `src/common/chaos_once.h`. The suite proves:
 * - `chaos_net_resolve_symbol()` stores the `dlsym(RTLD_NEXT)` result after clearing a stale
 *   `dlerror()` once, and aborts when dlsym returns NULL with a pending dlerror (no real
 *   function means no way to delegate);
 * - seeding on Linux reads 8 bytes from `/dev/urandom` through raw `SYS_openat`/`SYS_read`/
 *   `SYS_close`, closes the fd on a short read, and falls back to
 *   `0x6a09e667f3bcc909 ^ getpid()` when the open fails or the read is short; on other
 *   platforms only a non-zero seed is asserted;
 * - the constructor wires every real-function pointer it resolves (20 portable socket calls,
 *   plus accept4, sendmmsg, recvmmsg, epoll_wait and epoll_pwait on Linux), seeds the process
 *   and main-thread PRNG, initialises the config module once and loads the rule file once, so
 *   a bad rule file is reported at start-up;
 * - `chaos_once()` called again from inside its own initialiser, on the same thread, returns 0
 *   at once instead of deadlocking, and the initialiser runs exactly once.
 *
 * Seams: the source is compiled into this file with `dlsym`, `dlerror`, `abort` and (Linux)
 * `syscall` macro-redirected to local stubs. The dlsym stub returns a do-nothing stub for each
 * of the 25 socket symbols and NULL otherwise; the six fd calls libchaos-net also resolves
 * (setsockopt, read, write, readv, writev, close) are pre-set by
 * `chaos_net_test_reset_runtime()` to raw-syscall implementations, which resolution never
 * overwrites. The abort stub `longjmp()`s back when an abort is expected; the syscall stub
 * returns fd 9 and the seed `0x1122334455667788`, with flags for the two fallback paths.
 * `chaos_net_config_init()` and `chaos_net_config_prepare()` are replaced by counters.
 *
 * Out of scope: the wrappers (`test_chaos_net.c`), rule loading (`test_net_config.c`) and
 * concurrent library loads.
 */

#include "../support/test_net_support.h"

#include "../../src/net/chaos_net_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Calls of the `chaos_net_config_init()` stub. */
static int g_config_init_calls = 0;

/** @brief Calls of the `chaos_net_config_prepare()` stub (start-up rule loads). */
static int g_config_prepare_calls = 0;
/** @brief Calls of the dlerror stub. */
static int g_dlerror_calls = 0;
/** @brief Returned by the dlerror stub; non-NULL turns a NULL dlsym result into an abort. */
static const char *g_dlerror_text = NULL;
/** @brief Where the abort stub returns to when an abort is expected. */
static jmp_buf g_abort_env;
/** @brief Non-zero while a test expects abort(); otherwise abort() fails the test. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief `SYS_openat` calls seen by the syscall stub. */
static int g_syscall_open_calls = 0;
/** @brief `SYS_read` calls seen by the syscall stub. */
static int g_syscall_read_calls = 0;
/** @brief `SYS_close` calls seen by the syscall stub. */
static int g_syscall_close_calls = 0;
/** @brief Non-zero makes `SYS_openat` fail (no `/dev/urandom`). */
static int g_force_open_fail = 0;
/** @brief Non-zero makes `SYS_read` return 7 of 8 bytes; a partial seed must not be used. */
static int g_force_short_read = 0;
#endif

/**
 * @brief Restores the runtime globals (real functions, PRNG, guard) and clears every counter
 *   and fault flag.
 */
static void reset_test_state(void)
{
    chaos_net_test_reset_runtime();
    g_config_init_calls = 0;
    g_config_prepare_calls = 0;
    g_dlerror_calls = 0;
    g_dlerror_text = NULL;
    g_expect_abort = 0;
#ifdef __linux__
    g_syscall_open_calls = 0;
    g_syscall_read_calls = 0;
    g_syscall_close_calls = 0;
    g_force_open_fail = 0;
    g_force_short_read = 0;
#endif
}

/* -------------------------------------------------------------------------
 * Real-function stand-ins: never called; only their addresses are compared.
 * --------------------------------------------------------------------- */

/** @brief Stand-in for the real bind(). */
static int stub_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real listen(). */
static int stub_listen(int fd, int backlog)
{
    (void)fd;
    (void)backlog;
    return 0;
}

/** @brief Stand-in for the real connect(). */
static int stub_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real accept(). */
static int stub_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real socket(). */
static int stub_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    return 0;
}

/** @brief Stand-in for the real socketpair(). */
static int stub_socketpair(int domain, int type, int protocol, int fds[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    (void)fds;
    return 0;
}

/** @brief Stand-in for the real shutdown(). */
static int stub_shutdown(int fd, int how)
{
    (void)fd;
    (void)how;
    return 0;
}

/** @brief Stand-in for the real send(). */
static ssize_t stub_send(int fd, const void *buffer, size_t size, int flags)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real sendto(). */
static ssize_t stub_sendto(
    int fd,
    const void *buffer,
    size_t size,
    int flags,
    const struct sockaddr *address,
    socklen_t length
)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real sendmsg(). */
static ssize_t stub_sendmsg(int fd, const struct msghdr *message, int flags)
{
    (void)fd;
    (void)message;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real recv(). */
static ssize_t stub_recv(int fd, void *buffer, size_t size, int flags)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real recvfrom(). */
static ssize_t stub_recvfrom(
    int fd, void *buffer, size_t size, int flags, struct sockaddr *address, socklen_t *length
)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real recvmsg(). */
static ssize_t stub_recvmsg(int fd, struct msghdr *message, int flags)
{
    (void)fd;
    (void)message;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real poll(). */
static int stub_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    return 0;
}

/** @brief Stand-in for the real ppoll(). */
static int
stub_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    (void)sigmask;
    return 0;
}

/** @brief Stand-in for the real select(). */
static int
stub_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    return 0;
}

/** @brief Stand-in for the real pselect(). */
static int stub_pselect(
    int nfds,
    fd_set *readfds,
    fd_set *writefds,
    fd_set *exceptfds,
    const struct timespec *timeout,
    const sigset_t *sigmask
)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    (void)sigmask;
    return 0;
}

/** @brief Stand-in for the real getsockname(). */
static int stub_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real getpeername(). */
static int stub_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stand-in for the real getsockopt(). */
static int stub_getsockopt(int fd, int level, int optname, void *value, socklen_t *length)
{
    (void)fd;
    (void)level;
    (void)optname;
    (void)value;
    (void)length;
    return 0;
}

#ifdef __linux__
/** @brief Stand-in for the real accept4() (Linux). */
static int stub_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
    (void)fd;
    (void)address;
    (void)length;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real sendmmsg() (Linux). */
static int
stub_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags)
{
    (void)fd;
    (void)msgvec;
    (void)vlen;
    (void)flags;
    return 0;
}

/** @brief Stand-in for the real recvmmsg() (Linux). */
static int stub_recvmmsg(
    int fd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    (void)fd;
    (void)msgvec;
    (void)vlen;
    (void)flags;
    (void)timeout;
    return 0;
}

/** @brief Stand-in for the real epoll_wait() (Linux). */
static int stub_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    return 0;
}

/** @brief Stand-in for the real epoll_pwait() (Linux). */
static int stub_epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    (void)sigmask;
    return 0;
}
#endif

/** @brief Replaces the config module's initialiser; counts calls. */
void chaos_net_config_init(void)
{
    ++g_config_init_calls;
}

/** @brief Replaces the start-up rule load; counts calls and reports success. */
int chaos_net_config_prepare(void)
{
    ++g_config_prepare_calls;
    return 0;
}

/**
 * @brief dlerror() replacement: counts calls and returns `g_dlerror_text`.
 *
 * The resolver calls dlerror() once before dlsym to clear stale state and a second time only
 * when dlsym returned NULL, so a successful resolution counts exactly 1 call.
 */
static char *chaos_net_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief dlsym() replacement: the stand-in for each of the 20 portable and 5 Linux-only socket
 *   symbols, NULL for any other name.
 *
 * `CHAOS_NET_TEST_DLSYM_RESULT` converts through memcpy, as ISO C has no function-to-object
 * pointer cast. A NULL result aborts only when `g_dlerror_text` is set.
 */
static void *chaos_net_test_dlsym(void *handle, const char *symbol)
{
    (void)handle;

    if (strcmp(symbol, "bind") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_bind_fn, stub_bind);
    if (strcmp(symbol, "listen") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_listen_fn, stub_listen);
    if (strcmp(symbol, "connect") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_connect_fn, stub_connect);
    if (strcmp(symbol, "accept") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_accept_fn, stub_accept);
    if (strcmp(symbol, "socket") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_socket_fn, stub_socket);
    if (strcmp(symbol, "socketpair") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_socketpair_fn, stub_socketpair);
    if (strcmp(symbol, "shutdown") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_shutdown_fn, stub_shutdown);
    if (strcmp(symbol, "send") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_send_fn, stub_send);
    if (strcmp(symbol, "sendto") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_sendto_fn, stub_sendto);
    if (strcmp(symbol, "sendmsg") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_sendmsg_fn, stub_sendmsg);
    if (strcmp(symbol, "recv") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_recv_fn, stub_recv);
    if (strcmp(symbol, "recvfrom") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_recvfrom_fn, stub_recvfrom);
    if (strcmp(symbol, "recvmsg") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_recvmsg_fn, stub_recvmsg);
    if (strcmp(symbol, "poll") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_poll_fn, stub_poll);
    if (strcmp(symbol, "ppoll") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_ppoll_fn, stub_ppoll);
    if (strcmp(symbol, "select") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_select_fn, stub_select);
    if (strcmp(symbol, "pselect") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_pselect_fn, stub_pselect);
    if (strcmp(symbol, "getsockname") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_getsockname_fn, stub_getsockname);
    if (strcmp(symbol, "getpeername") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_getpeername_fn, stub_getpeername);
    if (strcmp(symbol, "getsockopt") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_getsockopt_fn, stub_getsockopt);
#ifdef __linux__
    if (strcmp(symbol, "accept4") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_accept4_fn, stub_accept4);
    if (strcmp(symbol, "sendmmsg") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_sendmmsg_fn, stub_sendmmsg);
    if (strcmp(symbol, "recvmmsg") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_recvmmsg_fn, stub_recvmmsg);
    if (strcmp(symbol, "epoll_wait") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_epoll_wait_fn, stub_epoll_wait);
    if (strcmp(symbol, "epoll_pwait") == 0)
        return CHAOS_NET_TEST_DLSYM_RESULT(chaos_net_epoll_pwait_fn, stub_epoll_pwait);
#endif
    return NULL;
}

#ifdef __linux__
/**
 * @brief syscall() replacement modelling `/dev/urandom` for the seed reader.
 *
 * `SYS_openat` returns fd 9, or -1 under `g_force_open_fail`. `SYS_read` asserts it reads
 * exactly 8 bytes from fd 9, writes `0x1122334455667788`, and reports 7 bytes under
 * `g_force_short_read`. `SYS_close` succeeds. Each is counted; any other number returns -1.
 */
static long chaos_net_test_syscall(long number, ...)
{
    if (number == SYS_openat)
    {
        ++g_syscall_open_calls;
        if (g_force_open_fail != 0)
        {
            return -1;
        }
        return 9;
    }
    if (number == SYS_read)
    {
        va_list args;
        int fd;
        void *buffer;
        size_t size;
        uint64_t seed = UINT64_C(0x1122334455667788);

        ++g_syscall_read_calls;
        va_start(args, number);
        fd = va_arg(args, int);
        buffer = va_arg(args, void *);
        size = va_arg(args, size_t);
        va_end(args);
        assert(fd == 9);
        assert(size == sizeof(seed));
        (void)memcpy(buffer, &seed, sizeof(seed));
        if (g_force_short_read != 0)
        {
            return (long)(sizeof(seed) - 1U);
        }
        return (long)sizeof(seed);
    }
    if (number == SYS_close)
    {
        ++g_syscall_close_calls;
        return 0;
    }

    return -1;
}
#endif

/**
 * @brief abort() replacement: `longjmp()`s to `g_abort_env` when expected, fails the test
 *   otherwise, so the abort path is observable without killing the test process.
 */
static void chaos_net_test_abort(void)
{
    if (g_expect_abort != 0)
    {
        longjmp(g_abort_env, 1);
    }
    assert(!"unexpected abort");
}

/* -------------------------------------------------------------------------
 * Compile the constructor against the stubs above
 * --------------------------------------------------------------------- */

#define dlsym chaos_net_test_dlsym
#define dlerror chaos_net_test_dlerror
#define abort chaos_net_test_abort
#ifdef __linux__
#define syscall chaos_net_test_syscall
#endif
#include "../../src/net/chaos_net.c"
#ifdef __linux__
#undef syscall
#endif
#undef abort
#undef dlerror
#undef dlsym

/* -------------------------------------------------------------------------
 * Test functions
 * --------------------------------------------------------------------- */

/**
 * @brief Re-arms the run-once guard of symbol resolution.
 *
 * @details The real constructor already ran when this binary loaded, so the guard is done
 * and chaos_net_init() would otherwise resolve nothing.
 */
static void reset_symbols_once(void)
{
    g_chaos_net_symbols_once = CHAOS_ONCE_INIT;
}

/**
 * @brief Proves one symbol resolves with exactly one dlerror() call, and the seed comes from
 *   `/dev/urandom`.
 *
 * @details On Linux the seed equals the 8 bytes read, through exactly one open, read and
 * close; elsewhere it is only non-zero.
 */
static void test_resolve_symbol_and_seed_helpers(void)
{
    chaos_net_bind_fn bind_fn = NULL;

    reset_test_state();
    chaos_net_resolve_symbol(&bind_fn, "bind");
    assert(bind_fn == stub_bind);
    assert(g_dlerror_calls == 1);

#ifdef __linux__
    assert(chaos_net_read_seed_material() == UINT64_C(0x1122334455667788));
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
#else
    assert(chaos_net_read_seed_material() != 0U);
#endif
}

/**
 * @brief Proves a failed lookup (dlsym NULL with a pending dlerror) aborts the process.
 *
 * @details libchaos-net fails closed here: without the real function no wrapper could
 * delegate. The abort stub `longjmp()`s back past the call, so reaching the assertion after
 * it means abort() was not called.
 */
static void test_resolve_symbol_abort_path(void)
{
    chaos_net_bind_fn bind_fn = NULL;

    reset_test_state();
    g_dlerror_text = "missing";
    g_expect_abort = 1;
    if (setjmp(g_abort_env) == 0)
    {
        chaos_net_resolve_symbol(&bind_fn, "missing-symbol");
        assert(0 && "expected abort path");
    }
    g_expect_abort = 0;
}

#ifdef __linux__
/**
 * @brief Proves the seed falls back to `0x6a09e667f3bcc909 ^ getpid()` when `/dev/urandom`
 *   cannot be opened or returns a short read (Linux only).
 *
 * @details A failed open performs no read and no close. A short read still closes the fd,
 * so a process without full entropy does not leak a descriptor per seeding.
 */
static void test_seed_fallback_paths(void)
{
    uint64_t fallback = UINT64_C(0x6a09e667f3bcc909) ^ (uint64_t)getpid();

    reset_test_state();
    g_force_open_fail = 1;
    assert(chaos_net_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 0);
    assert(g_syscall_close_calls == 0);

    reset_test_state();
    g_force_short_read = 1;
    assert(chaos_net_read_seed_material() == fallback);
    assert(g_syscall_open_calls == 1);
    assert(g_syscall_read_calls == 1);
    assert(g_syscall_close_calls == 1);
}
#endif

/**
 * @brief Proves the constructor wires every socket real function, seeds both PRNG states, and
 *   initialises and loads the configuration exactly once each.
 */
static void test_constructor_init(void)
{
    int config_calls_before;
    int prepare_calls_before;

    reset_test_state();
    reset_symbols_once();
    config_calls_before = g_config_init_calls;
    prepare_calls_before = g_config_prepare_calls;
    chaos_net_init();
    assert(g_chaos_net_real_bind == stub_bind);
    assert(g_chaos_net_real_listen == stub_listen);
    assert(g_chaos_net_real_connect == stub_connect);
    assert(g_chaos_net_real_accept == stub_accept);
    assert(g_chaos_net_real_socket == stub_socket);
    assert(g_chaos_net_real_socketpair == stub_socketpair);
    assert(g_chaos_net_real_shutdown == stub_shutdown);
    assert(g_chaos_net_real_send == stub_send);
    assert(g_chaos_net_real_sendto == stub_sendto);
    assert(g_chaos_net_real_sendmsg == stub_sendmsg);
    assert(g_chaos_net_real_recv == stub_recv);
    assert(g_chaos_net_real_recvfrom == stub_recvfrom);
    assert(g_chaos_net_real_recvmsg == stub_recvmsg);
    assert(g_chaos_net_real_poll == stub_poll);
    assert(g_chaos_net_real_ppoll == stub_ppoll);
    assert(g_chaos_net_real_select == stub_select);
    assert(g_chaos_net_real_pselect == stub_pselect);
    assert(g_chaos_net_real_getsockname == stub_getsockname);
    assert(g_chaos_net_real_getpeername == stub_getpeername);
    assert(g_chaos_net_real_getsockopt == stub_getsockopt);
#ifdef __linux__
    assert(g_chaos_net_real_accept4 == stub_accept4);
    assert(g_chaos_net_real_sendmmsg == stub_sendmmsg);
    assert(g_chaos_net_real_recvmmsg == stub_recvmmsg);
    assert(g_chaos_net_real_epoll_wait == stub_epoll_wait);
    assert(g_chaos_net_real_epoll_pwait == stub_epoll_pwait);
#endif
    assert(g_config_init_calls == config_calls_before + 1);
    assert(g_config_prepare_calls == prepare_calls_before + 1);
    assert(g_chaos_net_process_seed != 0U);
    assert(g_chaos_net_tls_prng_state != 0U);
}

/** @brief Run-once guard driven by the re-entrant initialiser below. */
static volatile chaos_once_t g_test_once = CHAOS_ONCE_INIT;
/** @brief Result of the nested chaos_once() call (-1 until it runs). */
static int g_test_nested = -1;
/** @brief Times the initialiser ran. */
static int g_test_runs = 0;

/**
 * @brief Initialiser that calls chaos_once() on its own guard, as symbol resolution can when
 *   dlsym() itself calls an interposed function.
 */
static void reentrant_initialiser(void)
{
    ++g_test_runs;
    g_test_nested = chaos_once(&g_test_once, reentrant_initialiser);
}

/**
 * @brief Proves a nested chaos_once() on the initialising thread returns 0 at once instead of
 *   waiting for itself, the outer call returns 1, the guard ends DONE, and a later call does
 *   not run the initialiser again.
 */
static void test_once_reentry_does_not_wait(void)
{
    assert(chaos_once(&g_test_once, reentrant_initialiser) == 1);
    assert(g_test_nested == 0 && g_test_runs == 1);
    assert(g_test_once == CHAOS_ONCE_DONE);
    assert(chaos_once(&g_test_once, reentrant_initialiser) == 1);
    assert(g_test_runs == 1);
}

int main(void)
{
    test_once_reentry_does_not_wait();
    test_resolve_symbol_and_seed_helpers();
    test_resolve_symbol_abort_path();
#ifdef __linux__
    test_seed_fallback_paths();
#endif
    test_constructor_init();
    return 0;
}
