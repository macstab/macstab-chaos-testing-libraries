/**
 * @file test_net_runtime.c
 * @brief Unit tests for the NET-domain constructor: symbol resolution, seed material,
 *   and function-pointer table wiring.
 *
 * Subsystem under test: `src/net/chaos_net.c` (the `chaos_net_init()` constructor).
 *
 * Coverage approach:
 * - All 20 portable socket operation symbols plus 5 Linux-only symbols are mapped to
 *   local stub functions via a test-controlled `dlsym` stub.
 * - `dlerror`, `abort`, and (on Linux) `syscall` are overridden via `#define` before
 *   `chaos_net.c` is included, giving access to the constructor without LD_PRELOAD.
 * - On Linux, a raw-syscall stub intercepts SYS_openat, SYS_read, and SYS_close to
 *   deliver a deterministic 8-byte seed value (0x1122334455667788) so tests can assert
 *   the exact stored seed.
 * - The abort path is intercepted via `setjmp`/`longjmp` to verify that `chaos_net_init`
 *   terminates when a required symbol cannot be resolved.
 *
 * Properties under test:
 * - `chaos_net_resolve_symbol()`: successful resolution calls `dlerror()` once; the
 *   resulting pointer equals the stub function.
 * - `chaos_net_read_seed_material()` (Linux): returns 0x1122334455667788; raw syscalls
 *   issued in order (openat → read → close).
 * - `chaos_net_read_seed_material()` (non-Linux): returns a non-zero value.
 * - Abort path: when `dlsym` returns NULL and `dlerror` returns a non-NULL message,
 *   `chaos_net_resolve_symbol` calls `abort()`.
 * - Linux seed fallback: open failure → PID-based fallback seed; short read → same fallback.
 * - `chaos_net_init()`: all 20 (or 25 on Linux) real-function-pointer globals wired
 *   to their stub counterparts; config_init called once; process_seed and tls_prng_state
 *   are non-zero after construction.
 *
 * What is NOT tested here:
 * - The wrapper interception behaviour (tested in test_chaos_net.c).
 * - Config file loading or rule matching.
 * - Thread-safety of the constructor under concurrent library opens.
 */

#include "../support/test_net_support.h"

#include "../../src/net/chaos_net_config.h"

#include <setjmp.h>
#include <stdarg.h>

/** @brief Number of times `chaos_net_config_init()` stub was called. */
static int g_config_init_calls = 0;
/** @brief Number of times the `dlerror` stub was called. */
static int g_dlerror_calls = 0;
/** @brief Error string to return from the `dlerror` stub; NULL means no error. */
static const char *g_dlerror_text = NULL;
/** @brief `setjmp` buffer used by the `abort` stub to return to the test. */
static jmp_buf g_abort_env;
/** @brief Non-zero when the test expects `abort()` to be called. */
static int g_expect_abort = 0;
#ifdef __linux__
/** @brief Number of times SYS_openat was dispatched through the syscall stub. */
static int g_syscall_open_calls = 0;
/** @brief Number of times SYS_read was dispatched through the syscall stub. */
static int g_syscall_read_calls = 0;
/** @brief Number of times SYS_close was dispatched through the syscall stub. */
static int g_syscall_close_calls = 0;
/** @brief When non-zero, causes SYS_openat to return -1 (simulates /dev/urandom open failure). */
static int g_force_open_fail = 0;
/**
 * @brief When non-zero, causes SYS_read to return sizeof(seed)-1 (simulates short read).
 *
 * A short read of the seed material should trigger the PID-based fallback rather than
 * storing a partial seed value.
 */
static int g_force_short_read = 0;
#endif

/**
 * @brief Reset all runtime globals to their initial state before each test.
 *
 * Resets the NET runtime globals via `chaos_net_test_reset_runtime()` and also
 * zeroes all local stubs counters and flags.
 */
static void reset_test_state(void)
{
    chaos_net_test_reset_runtime();
    g_config_init_calls = 0;
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
 * Stub socket operation implementations
 * --------------------------------------------------------------------- */

/** @brief Stub for `bind(2)`. Returns 0 without touching the OS. */
static int stub_bind(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `listen(2)`. Returns 0. */
static int stub_listen(int fd, int backlog)
{
    (void)fd;
    (void)backlog;
    return 0;
}

/** @brief Stub for `connect(2)`. Returns 0. */
static int stub_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `accept(2)`. Returns 0. */
static int stub_accept(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `socket(2)`. Returns 0. */
static int stub_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    return 0;
}

/** @brief Stub for `socketpair(2)`. Returns 0. */
static int stub_socketpair(int domain, int type, int protocol, int fds[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    (void)fds;
    return 0;
}

/** @brief Stub for `shutdown(2)`. Returns 0. */
static int stub_shutdown(int fd, int how)
{
    (void)fd;
    (void)how;
    return 0;
}

/** @brief Stub for `send(2)`. Returns 0. */
static ssize_t stub_send(int fd, const void *buffer, size_t size, int flags)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    return 0;
}

/** @brief Stub for `sendto(2)`. Returns 0. */
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

/** @brief Stub for `sendmsg(2)`. Returns 0. */
static ssize_t stub_sendmsg(int fd, const struct msghdr *message, int flags)
{
    (void)fd;
    (void)message;
    (void)flags;
    return 0;
}

/** @brief Stub for `recv(2)`. Returns 0. */
static ssize_t stub_recv(int fd, void *buffer, size_t size, int flags)
{
    (void)fd;
    (void)buffer;
    (void)size;
    (void)flags;
    return 0;
}

/** @brief Stub for `recvfrom(2)`. Returns 0. */
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

/** @brief Stub for `recvmsg(2)`. Returns 0. */
static ssize_t stub_recvmsg(int fd, struct msghdr *message, int flags)
{
    (void)fd;
    (void)message;
    (void)flags;
    return 0;
}

/** @brief Stub for `poll(2)`. Returns 0. */
static int stub_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    return 0;
}

/** @brief Stub for `ppoll(2)`. Returns 0. */
static int
stub_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    (void)sigmask;
    return 0;
}

/** @brief Stub for `select(2)`. Returns 0. */
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

/** @brief Stub for `pselect(2)`. Returns 0. */
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

/** @brief Stub for `getsockname(2)`. Returns 0. */
static int stub_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `getpeername(2)`. Returns 0. */
static int stub_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    (void)address;
    (void)length;
    return 0;
}

/** @brief Stub for `getsockopt(2)`. Returns 0. */
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
/** @brief Stub for Linux `accept4(2)`. Returns 0. */
static int stub_accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
    (void)fd;
    (void)address;
    (void)length;
    (void)flags;
    return 0;
}

/** @brief Stub for Linux `sendmmsg(2)`. Returns 0. */
static int
stub_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags)
{
    (void)fd;
    (void)msgvec;
    (void)vlen;
    (void)flags;
    return 0;
}

/** @brief Stub for Linux `recvmmsg(2)`. Returns 0. */
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

/** @brief Stub for Linux `epoll_wait(2)`. Returns 0. */
static int stub_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    return 0;
}

/** @brief Stub for Linux `epoll_pwait(2)`. Returns 0. */
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

/**
 * @brief Stub for `chaos_net_config_init()`.
 *
 * Increments the call counter so tests can verify `chaos_net_init()` invokes it
 * exactly once.
 */
void chaos_net_config_init(void)
{
    ++g_config_init_calls;
}

/**
 * @brief Stub for `dlerror()`.
 *
 * Returns `g_dlerror_text` and increments the call counter. Used to verify that
 * `chaos_net_resolve_symbol()` calls `dlerror()` exactly once per successful resolution.
 */
static char *chaos_net_test_dlerror(void)
{
    ++g_dlerror_calls;
    return (char *)g_dlerror_text;
}

/**
 * @brief Stub for `dlsym(RTLD_NEXT, symbol)`.
 *
 * Maps each of the 20 (or 25 on Linux) expected symbol names to the corresponding
 * stub function via `CHAOS_NET_TEST_DLSYM_RESULT`. Returns NULL for unrecognised
 * symbol names; the production constructor will then call `dlerror()` and `abort()`.
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
 * @brief Stub for `syscall(2)` used by the production constructor to read seed material.
 *
 * Intercepts SYS_openat, SYS_read, and SYS_close. For SYS_read, copies the constant
 * seed `0x1122334455667788` into the caller's buffer when `g_force_short_read == 0`,
 * or returns `sizeof(seed)-1` bytes when `g_force_short_read != 0`. For SYS_openat,
 * returns -1 when `g_force_open_fail != 0`.
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
 * @brief Stub for `abort()`.
 *
 * When `g_expect_abort != 0`, transfers control back to the enclosing `setjmp`
 * frame via `longjmp(g_abort_env, 1)`. When the abort is unexpected, asserts
 * false to produce a diagnostic failure rather than hanging.
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
 * Symbol overrides and production source inclusion
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
 * @brief Invariant: `chaos_net_resolve_symbol()` wires a single symbol and calls dlerror once.
 *
 * Triggering condition: `chaos_net_resolve_symbol(&bind_fn, "bind")` with a clean state.
 *
 * Expected observable behaviour:
 * - `bind_fn` is set to `stub_bind` after the call.
 * - `g_dlerror_calls == 1` (dlerror is called once to clear any pending error string).
 * - On Linux: `chaos_net_read_seed_material()` returns 0x1122334455667788 and issues
 *   exactly one openat, one read, and one close raw syscall.
 * - On non-Linux: `chaos_net_read_seed_material()` returns a non-zero value.
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
 * @brief Invariant: `chaos_net_resolve_symbol()` calls `abort()` when the symbol is missing.
 *
 * Triggering condition: `g_dlerror_text = "missing"` causes the `dlerror` stub to return
 *   a non-NULL string. The `dlsym` stub returns NULL for "missing-symbol". Together these
 *   conditions trigger the fatal-error path in `chaos_net_resolve_symbol`.
 *
 * Expected observable behaviour: `longjmp` transfers control out of the setjmp block;
 *   the "expected abort path" assert is never reached.
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
 * @brief Invariant: `chaos_net_read_seed_material()` falls back to a PID-based seed when
 *   `/dev/urandom` cannot be opened or yields a short read.
 *
 * Triggering conditions:
 * - `g_force_open_fail = 1`: SYS_openat returns -1; no read or close is attempted.
 * - `g_force_short_read = 1`: SYS_read returns `sizeof(seed)-1`; a short read is treated
 *   as a failure and the PID-based fallback is used.
 *
 * Expected observable behaviour: both paths return `0x6a09e667f3bcc909 XOR getpid()`.
 * The fallback constant is the SHA-256 initial hash value for H0, chosen as a non-zero,
 * non-trivial mixing constant.
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
 * @brief Invariant: `chaos_net_init()` wires all function pointers and seeds the PRNG.
 *
 * Triggering condition: `chaos_net_init()` called after `reset_test_state()`.
 *
 * Expected observable behaviour:
 * - All 20 portable `g_chaos_net_real_*` globals equal their corresponding stub functions.
 * - On Linux: the 5 additional Linux-only globals are also wired.
 * - `g_config_init_calls` increments by exactly 1 (config subsystem initialised once).
 * - `g_chaos_net_process_seed != 0` (seed was populated from `chaos_net_read_seed_material()`).
 * - `g_chaos_net_tls_prng_state != 0` (TLS PRNG state was seeded from process seed).
 */
static void test_constructor_init(void)
{
    int config_calls_before;

    reset_test_state();
    config_calls_before = g_config_init_calls;
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
    assert(g_chaos_net_process_seed != 0U);
    assert(g_chaos_net_tls_prng_state != 0U);
}

int main(void)
{
    test_resolve_symbol_and_seed_helpers();
    test_resolve_symbol_abort_path();
#ifdef __linux__
    test_seed_fallback_paths();
#endif
    test_constructor_init();
    return 0;
}
