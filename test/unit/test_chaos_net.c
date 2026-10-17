/**
 * @file test_chaos_net.c
 * @brief Unit tests for every libchaos-net wrapper: socket setup, data transfer, waits,
 *   batches, fd calls on sockets, and the fortified glibc variants.
 *
 * @details
 * Units under test: `src/net/chaos_net_socket.c`, `chaos_net_extra.c` and `chaos_net_wait.c`.
 * The suite proves the wrapper contract, not rule parsing or effect internals:
 * - forwarding: under the TLS guard, with no rules loaded, with no resolvable endpoint, or
 *   with no matching rule, every wrapper calls the real function unchanged and leaves errno
 *   alone; before symbol resolution the `chaos_net_call_real_*()` forwarders reach the kernel
 *   through raw syscalls instead of a NULL pointer (Linux);
 * - endpoints: each wrapper matches on the right endpoint (address argument, local end,
 *   connection with local/peer fallback, socket() arguments, or the descriptors a wait
 *   watches, found for epoll through `/proc/self/fdinfo/<epfd>`);
 * - effects: ERRNO fails before the real call; LATENCY delays, then calls through; CORRUPT
 *   flips a bit only in bytes actually received; TIMEOUT waits out the caller's own timeout
 *   under the caller's signal mask and reports "nothing ready"; TRICKLE shortens stream
 *   receives to the chunk size; DUP replays a socket's last payload once, never on the wrong
 *   socket; RESET arms a zero SO_LINGER before close();
 * - `@size` sees the call's byte count, summed over iovecs and batch messages, and is unknown
 *   where the kernel would reject the vector;
 * - read(), write(), readv(), writev() and close() apply net rules only to sockets;
 *   `__recv_chk()`, `__recvfrom_chk()`, `__read_chk()`, `__poll_chk()` and `__ppoll_chk()`
 *   reach the same wrappers (glibc).
 *
 * Seams:
 * - The config, endpoint and effect entry points the wrappers call are defined here as stubs
 *   driven by flags (`g_stub_*`, `g_errno_trigger`, `g_should_trigger`); the LATENCY stub
 *   never sleeps and the CORRUPT stubs flip a predictable bit.
 * - `reset_wrapper_stubs()` points every socket real function at a counting fake with a
 *   configurable result; `reset_descriptor_stubs()` adds fakes for read, write, readv,
 *   writev, close and setsockopt.
 * - Macros defined before the includes replace the socket-type probe
 *   (`CHAOS_NET_SOCKET_TYPE`), the DUP table mapping, socket identity and close-race hook
 *   (`CHAOS_NET_DUP_*`), and the TIMEOUT wait (`CHAOS_NET_TIMEOUT_WAIT`), so no test waits
 *   for real; in the wait source `open`, `read`, `close` and `snprintf` are redirected so the
 *   fdinfo reader can be fed failures and crafted text.
 * - Real epoll instances on pipes, socketpairs and a loopback TCP listener are used only
 *   where the kernel's behaviour itself is under test.
 *
 * Out of scope: rule loading and selection (`test_net_config.c`), endpoint resolution
 * (`test_net_endpoint.c`), effect internals (`test_net_actions.c`) and the constructor
 * (`test_net_runtime.c`).
 */

#include "../support/test_net_support.h"

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include "../../src/net/chaos_net_config.h"
#include "../../src/net/chaos_net_actions.h"
#include "../../src/net/chaos_net_endpoint.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

/** @brief Rule every match stub returns while `g_stub_match_endpoint` is set. */
static chaos_net_rule_t g_stub_rule;

/** @brief Endpoint every enabled endpoint-resolution stub returns. */
static chaos_net_endpoint_t g_stub_endpoint;

/** @brief Non-zero makes the prepare stub report rules loaded; 0 lets wrappers skip matching. */
static int g_stub_prepare = 0;

/** @brief Length the fake recv was last asked for; shows TRICKLE's shortened request. */
static size_t g_last_receive_size = 0U;
/** @brief iovec count the fake recvmsg was last given. */
static size_t g_last_receive_iovlen = 0U;
/** @brief Total iovec bytes the fake recvmsg was last given. */
static size_t g_last_receive_iov_bytes = 0U;

/** @brief `call_size` of the rule the LATENCY stub last saw; checks what `@size` is fed. */
static uint64_t g_last_call_size = 0U;

/** @brief Non-zero makes every match stub return `g_stub_rule`. */
static int g_stub_match_endpoint = 0;

/** @brief Number of upcoming match calls that miss despite `g_stub_match_endpoint`. */
static int g_stub_match_misses = 0;

/** @brief Non-zero makes the sockaddr endpoint stub resolve. */
static int g_stub_endpoint_from_sockaddr = 0;
/** @brief Calls of the sockaddr endpoint stub, resolved or not. */
static int g_sockaddr_lookups = 0;

/** @brief Non-zero makes the socket()-arguments endpoint stub resolve. */
static int g_stub_endpoint_from_socket_spec = 0;

/** @brief Non-zero makes the activity (local, then peer) endpoint stub resolve. */
static int g_stub_endpoint_from_activity = 0;

/** @brief Non-zero makes the local endpoint stub resolve. */
static int g_stub_endpoint_from_local = 0;

/** @brief Non-zero makes the peer endpoint stub resolve. */
static int g_stub_endpoint_from_peer = 0;

/** @brief Calls of the LATENCY stub (no sleep is performed). */
static int g_latency_calls = 0;

/** @brief Non-zero makes a matched ERRNO rule fire and set its errno. */
static int g_errno_trigger = 0;

/** @brief Result of the should-trigger stub (CORRUPT, TIMEOUT, TRICKLE, DUP, RESET); default 0. */
static int g_should_trigger = 0;

/** @brief Address length the fake recvfrom reports for a too-small buffer, as Linux reports
 *   the full length of a truncated address; 0 disables. */
static socklen_t g_recvfrom_reported_name = 0;

/** @brief Calls of the CORRUPT stubs. */
static int g_corrupt_calls = 0;

/** @brief Length the last CORRUPT call was given; proves only received bytes are corrupted. */
static size_t g_last_corrupt_size = 0U;

/* --- Faults for the epoll fdinfo reader (used on Linux only) --- */

/** @brief Non-zero makes snprintf() in the wait source fail, so the fdinfo path is unbuildable. */
static int g_wait_fail_snprintf = 0;

/** @brief Non-zero makes open() in the wait source return `g_wait_fake_fd`, served by the fake
 *   read and close below. */
static int g_wait_fake_open = 0;

/** @brief Non-zero makes open() in the wait source fail with ENOENT. */
static int g_wait_force_open_fail = 0;

/** @brief Non-zero makes reads of the fake fd fail with EIO. */
static int g_wait_force_read_fail = 0;

/** @brief Non-zero makes every read of the fake fd fill the buffer with 'x' and no newline. */
static int g_wait_fill_buffer = 0;

/** @brief fdinfo text the fake fd serves, in chunks of at most the requested size. */
static const char *g_wait_read_text = NULL;

/** @brief Bytes of `g_wait_read_text` already served. */
static size_t g_wait_read_offset = 0U;

#ifdef __linux__
/** @brief Fake fdinfo descriptor; far above any fd this test binary opens. */
static const int g_wait_fake_fd = 7331;
#endif

/* --- Calls that reached each fake real function --- */

/** @brief Calls of the fake real bind(). */
static int g_bind_calls = 0;
/** @brief Calls of the fake real listen(). */
static int g_listen_calls = 0;
/** @brief Calls of the fake real connect(). */
static int g_connect_calls = 0;
/** @brief Calls of the fake real accept() and accept4(). */
static int g_accept_calls = 0;
/** @brief Calls of the fake real socket(). */
static int g_socket_calls = 0;
/** @brief Calls of the fake real socketpair(). */
static int g_socketpair_calls = 0;
/** @brief Calls of the fake real shutdown(). */
static int g_shutdown_calls = 0;
/** @brief Calls of the fake real send(). */
static int g_send_calls = 0;
/** @brief Calls of the fake real sendto(). */
static int g_sendto_calls = 0;
/** @brief Calls of the fake real sendmsg(). */
static int g_sendmsg_calls = 0;
/** @brief Calls of the fake real recv(). */
static int g_recv_calls = 0;
/** @brief Calls of the fake real recvfrom(). */
static int g_recvfrom_calls = 0;
/** @brief Calls of the fake real recvmsg(). */
static int g_recvmsg_calls = 0;
/** @brief Calls of the fake real poll(). */
static int g_poll_calls = 0;
/** @brief Calls of the fake real ppoll(). */
static int g_ppoll_calls = 0;
/** @brief Calls of the fake real select(). */
static int g_select_calls = 0;
/** @brief Calls of the fake real pselect(). */
static int g_pselect_calls = 0;
#ifdef __linux__
/** @brief Calls of the fake real sendmmsg(). */
static int g_sendmmsg_calls = 0;
/** @brief Calls of the fake real recvmmsg(). */
static int g_recvmmsg_calls = 0;
/** @brief Calls of the fake real epoll_wait(). */
static int g_epoll_wait_calls = 0;
/** @brief Calls of the fake real epoll_pwait(). */
static int g_epoll_pwait_calls = 0;
#endif

/* --- Results of each fake real function (defaults restored by reset_wrapper_stubs()) --- */

/** @brief Result of the fake real bind(); default 0. */
static int g_bind_result = 0;
/** @brief Result of the fake real listen(); default 0. */
static int g_listen_result = 0;
/** @brief Result of the fake real connect(); default 0. */
static int g_connect_result = 0;
/** @brief Result of the fake real accept() and accept4(); default fd 10. */
static int g_accept_result = 10;
/** @brief Result of the fake real socket(); default fd 8. */
static int g_socket_result = 8;
/** @brief Result of the fake real socketpair(); default 0. */
static int g_socketpair_result = 0;
/** @brief Result of the fake real shutdown(); default 0. */
static int g_shutdown_result = 0;
/** @brief Result of the fake real send(); default 4 bytes. */
static ssize_t g_send_result = 4;
/** @brief Result of the fake real sendto(); default 4 bytes. */
static ssize_t g_sendto_result = 4;
/** @brief Result of the fake real sendmsg(); default 4 bytes. */
static ssize_t g_sendmsg_result = 4;
/** @brief Result of the fake real recv(); default 4 bytes. */
static ssize_t g_recv_result = 4;
/** @brief Result of the fake real recvfrom(); default 4 bytes. */
static ssize_t g_recvfrom_result = 4;
/** @brief Result of the fake real recvmsg(); default 4 bytes. */
static ssize_t g_recvmsg_result = 4;
/** @brief Result of the fake real poll(); default 0 (nothing ready). */
static int g_poll_result = 0;
/** @brief Result of the fake real ppoll(); default 0. */
static int g_ppoll_result = 0;
/** @brief Result of the fake real select(); default 0. */
static int g_select_result = 0;
/** @brief Result of the fake real pselect(); default 0. */
static int g_pselect_result = 0;
#ifdef __linux__
/** @brief Result of the fake real sendmmsg(); default 1 message. */
static int g_sendmmsg_result = 1;
/** @brief Result of the fake real recvmmsg(); default 1 message. */
static int g_recvmmsg_result = 1;
/** @brief Result of the fake real epoll_wait(); default 1 event. */
static int g_epoll_wait_result = 1;
/** @brief Result of the fake real epoll_pwait(); default 1 event. */
static int g_epoll_pwait_result = 1;
#endif

/* -------------------------------------------------------------------------
 * Config, endpoint and effect stubs: the wrapper sources link against these instead of
 * chaos_net_config.c, chaos_net_endpoint.c and chaos_net_actions.c
 * --------------------------------------------------------------------- */

/** @brief Prepare stub: rules count as loaded when `g_stub_prepare` is set or a rule matches. */
int chaos_net_config_prepare(void)
{
    return g_stub_prepare || g_stub_match_endpoint;
}

/**
 * @brief Match stub: `g_stub_rule` while matching is enabled, minus `g_stub_match_misses`
 *   initial misses; operation and endpoint are ignored.
 */
int chaos_net_config_match_endpoint(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    (void)operation;
    (void)endpoint;
    if (g_stub_match_endpoint == 0 || rule == NULL)
    {
        return 0;
    }
    if (g_stub_match_misses > 0)
    {
        --g_stub_match_misses;
        return 0;
    }
    *rule = g_stub_rule;
    return 1;
}

/** @brief Match-without-refresh stub: same behaviour as the match stub. */
int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    return chaos_net_config_match_endpoint(operation, endpoint, rule);
}

/**
 * @brief Both-ends match stub: tries @p first, then @p second, through the match stub. Rule
 *   precedence between the ends is proven in test_net_config.c.
 */
int chaos_net_config_match_either_loaded(
    chaos_net_operation_t operation,
    const chaos_net_endpoint_t *first,
    const chaos_net_endpoint_t *second,
    chaos_net_rule_t *rule
)
{
    return (first != NULL && chaos_net_config_match_endpoint(operation, first, rule)) ||
           (second != NULL && chaos_net_config_match_endpoint(operation, second, rule));
}

/** @brief Sockaddr endpoint stub: counts every lookup; resolves while enabled. */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    (void)fd;
    (void)address;
    (void)address_length;
    ++g_sockaddr_lookups;
    if (g_stub_endpoint_from_sockaddr == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/** @brief socket()-arguments endpoint stub: resolves while enabled. */
int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
)
{
    (void)domain;
    (void)type;
    (void)protocol;
    if (g_stub_endpoint_from_socket_spec == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/** @brief When not -1, the only descriptor the activity stub resolves (one watched fd of many). */
static int g_stub_activity_only_fd = -1;

/** @brief Activity endpoint stub: resolves while enabled, optionally for one descriptor only. */
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    if (g_stub_endpoint_from_activity == 0 || endpoint == NULL ||
        (g_stub_activity_only_fd != -1 && fd != g_stub_activity_only_fd))
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/** @brief Local endpoint stub: resolves while enabled. */
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_local == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/** @brief Peer endpoint stub: resolves while enabled. */
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_peer == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/** @brief LATENCY stub: counts calls and records the rule's `call_size`; never sleeps. */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
    g_last_call_size = rule->call_size;
}

/** @brief ERRNO stub: fires an ERRNO rule while `g_errno_trigger` is set, mirroring the real
 *   effect check. */
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}

/** @brief Should-trigger stub: returns `g_should_trigger` for every rule. */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

/** @brief CORRUPT stub: counts calls, records the length, and flips the selected bit like the
 *   real one, so tests can see which bytes changed. */
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;

    ++g_corrupt_calls;
    g_last_corrupt_size = size;
    if (buffer != NULL && size > 0U)
    {
        bytes[index_sample % size] ^= (unsigned char)(1U << (bit_sample & 7U));
    }
}

/** @brief CORRUPT stub without samples: always flips bit 0 of byte 0, a predictable target. */
void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    chaos_net_corrupt_buffer_sample(buffer, size, 0U, 0U);
}

/* -------------------------------------------------------------------------
 * Fake real functions: count the call and return the configured result
 * --------------------------------------------------------------------- */

/** @brief Fake real bind(). */
static int chaos_net_test_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_bind_calls;
    return g_bind_result;
}

/** @brief Fake real listen(). */
static int chaos_net_test_listen(int sockfd, int backlog)
{
    (void)sockfd;
    (void)backlog;
    ++g_listen_calls;
    return g_listen_result;
}

/** @brief Fake real connect(). */
static int
chaos_net_test_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_connect_calls;
    return g_connect_result;
}

/** @brief Fake real accept(); returns fd 10 by default. */
static int chaos_net_test_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_accept_calls;
    return g_accept_result;
}

/** @brief Fake real socket(); returns fd 8 by default. */
static int chaos_net_test_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    ++g_socket_calls;
    return g_socket_result;
}

/** @brief Fake real socketpair(); stores fds 11 and 12 so tests see the pair passed through. */
static int chaos_net_test_socketpair(int domain, int type, int protocol, int sv[2])
{
    (void)domain;
    (void)type;
    (void)protocol;
    ++g_socketpair_calls;
    if (sv != NULL)
    {
        sv[0] = 11;
        sv[1] = 12;
    }
    return g_socketpair_result;
}

/** @brief Fake real shutdown(). */
static int chaos_net_test_shutdown(int sockfd, int how)
{
    (void)sockfd;
    (void)how;
    ++g_shutdown_calls;
    return g_shutdown_result;
}

#ifdef __linux__
/** @brief Fake real accept4() (Linux); shares accept()'s counter and result. */
static int
chaos_net_test_accept4(int sockfd, struct sockaddr *address, socklen_t *address_length, int flags)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    (void)flags;
    ++g_accept_calls;
    return g_accept_result;
}
#endif

/** @brief Fake real send(); reports 4 bytes by default. */
static ssize_t chaos_net_test_send(int sockfd, const void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)buffer;
    (void)size;
    (void)flags;
    ++g_send_calls;
    return g_send_result;
}

/** @brief Fake real sendto(). */
static ssize_t chaos_net_test_sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    const struct sockaddr *address,
    socklen_t address_length
)
{
    (void)sockfd;
    (void)buffer;
    (void)size;
    (void)flags;
    (void)address;
    (void)address_length;
    ++g_sendto_calls;
    return g_sendto_result;
}

/** @brief Fake real sendmsg(). */
static ssize_t chaos_net_test_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)message;
    (void)flags;
    ++g_sendmsg_calls;
    return g_sendmsg_result;
}

/** @brief Fake real recv(): records the requested length and writes "data" when it fits, so
 *   CORRUPT and DUP have known bytes to work on. */
static ssize_t chaos_net_test_recv(int sockfd, void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recv_calls;
    g_last_receive_size = size;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recv_result;
}

/** @brief Fake real recvfrom(): writes "data", and an AF_INET sender address when the buffer
 *   holds one, else the configured truncated-address length. */
static ssize_t chaos_net_test_recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    struct sockaddr *address,
    socklen_t *address_length
)
{
    (void)sockfd;
    (void)flags;
    ++g_recvfrom_calls;
    if (address != NULL && address_length != NULL && *address_length >= sizeof(struct sockaddr_in))
    {
        memset(address, 0, sizeof(struct sockaddr_in));
        address->sa_family = AF_INET;
        *address_length = (socklen_t)sizeof(struct sockaddr_in);
    }
    else if (address != NULL && address_length != NULL && g_recvfrom_reported_name > 0)
    {
        memset(address, 0, *address_length);
        *address_length = g_recvfrom_reported_name;
    }
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recvfrom_result;
}

/** @brief Fake real recvmsg(): records the iovec shape, sets MSG_TRUNC and a 7-byte name, and
 *   writes "data" into the first iovec, so tests see which output fields a wrapper rewrites. */
static ssize_t chaos_net_test_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recvmsg_calls;
    if (message != NULL)
    {
        size_t index;

        g_last_receive_iovlen = (size_t)message->msg_iovlen;
        g_last_receive_iov_bytes = 0U;
        for (index = 0U; index < (size_t)message->msg_iovlen; ++index)
        {
            g_last_receive_iov_bytes += message->msg_iov[index].iov_len;
        }
        message->msg_flags = MSG_TRUNC;
        message->msg_namelen = 7U;
    }
    if (message != NULL && message->msg_iovlen > 0 && message->msg_iov[0].iov_len >= 4U)
    {
        (void)memcpy(message->msg_iov[0].iov_base, "data", 4U);
    }
    return g_recvmsg_result;
}

/** @brief Fake real poll(). */
static int chaos_net_test_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    ++g_poll_calls;
    return g_poll_result;
}

/** @brief Fake real ppoll(). */
static int chaos_net_test_ppoll(
    struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask
)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    (void)sigmask;
    ++g_ppoll_calls;
    return g_ppoll_result;
}

/** @brief Fake real select(). */
static int chaos_net_test_select(
    int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout
)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    ++g_select_calls;
    return g_select_result;
}

/** @brief Fake real pselect(). */
static int chaos_net_test_pselect(
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
    ++g_pselect_calls;
    return g_pselect_result;
}

#ifdef __linux__
/** @brief snprintf() replacement for the wait source: fails while `g_wait_fail_snprintf` is set. */
static int chaos_net_test_wait_snprintf(char *buffer, size_t size, const char *format, ...)
{
    int rc;
    va_list args;

    if (g_wait_fail_snprintf != 0)
    {
        return -1;
    }

    va_start(args, format);
    rc = vsnprintf(buffer, size, format, args);
    va_end(args);
    return rc;
}

/**
 * @brief open() replacement for the wait source: ENOENT, the fake fd, or the real open()
 *   (mode forwarded only with O_CREAT).
 */
static int chaos_net_test_wait_open(const char *path, int flags, ...)
{
    if (g_wait_force_open_fail != 0)
    {
        (void)path;
        (void)flags;
        errno = ENOENT;
        return -1;
    }
    if (g_wait_fake_open != 0)
    {
        (void)path;
        (void)flags;
        return g_wait_fake_fd;
    }
    if ((flags & O_CREAT) != 0)
    {
        va_list args;
        mode_t mode;

        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
        return open(path, flags, mode);
    }
    return open(path, flags);
}

/**
 * @brief read() replacement for the wait source. On the fake fd: EIO, a buffer of 'x' with no
 *   newline, or `g_wait_read_text` in chunks, then EOF. Other fds use the real read().
 */
static ssize_t chaos_net_test_wait_read(int fd, void *buffer, size_t count)
{
    if (fd == g_wait_fake_fd && g_wait_fake_open != 0)
    {
        if (g_wait_force_read_fail != 0)
        {
            errno = EIO;
            return -1;
        }
        if (g_wait_fill_buffer != 0)
        {
            (void)memset(buffer, 'x', count);
            return (ssize_t)count;
        }
        if (g_wait_read_text != NULL)
        {
            size_t remaining = strlen(g_wait_read_text) - g_wait_read_offset;
            size_t chunk = remaining < count ? remaining : count;

            if (chunk == 0U)
            {
                return 0;
            }
            (void)memcpy(buffer, g_wait_read_text + g_wait_read_offset, chunk);
            g_wait_read_offset += chunk;
            return (ssize_t)chunk;
        }
        return 0;
    }
    return read(fd, buffer, count);
}

/** @brief close() replacement for the wait source: the fake fd closes without a syscall. */
static int chaos_net_test_wait_close(int fd)
{
    if (fd == g_wait_fake_fd && g_wait_fake_open != 0)
    {
        return 0;
    }
    return close(fd);
}
#endif

/* -------------------------------------------------------------------------
 * Fake real functions: Linux batch and epoll calls
 * --------------------------------------------------------------------- */

#ifdef __linux__
/** @brief Fake real sendmmsg(); reports 1 message by default. */
static int chaos_net_test_sendmmsg(
    int sockfd, struct mmsghdr *msgvec, unsigned int vlen, CHAOS_NET_MMSG_FLAGS_TYPE flags
)
{
    (void)sockfd;
    (void)msgvec;
    (void)vlen;
    (void)flags;
    ++g_sendmmsg_calls;
    return g_sendmmsg_result;
}

/** @brief Fake real recvmmsg(): writes "data" into the first message's first iovec and sets its
 *   `msg_len` to 4. */
static int chaos_net_test_recvmmsg(
    int sockfd,
    struct mmsghdr *msgvec,
    unsigned int vlen,
    CHAOS_NET_MMSG_FLAGS_TYPE flags,
    struct timespec *timeout
)
{
    (void)sockfd;
    (void)vlen;
    (void)flags;
    (void)timeout;
    ++g_recvmmsg_calls;
    if (msgvec != NULL && vlen > 0U && msgvec[0].msg_hdr.msg_iov != NULL &&
        msgvec[0].msg_hdr.msg_iovlen > 0)
    {
        struct iovec *iov = msgvec[0].msg_hdr.msg_iov;

        if (iov[0].iov_base != NULL && iov[0].iov_len >= 4U)
        {
            (void)memcpy(iov[0].iov_base, "data", 4U);
            msgvec[0].msg_len = 4U;
        }
    }
    return g_recvmmsg_result;
}

/** @brief Fake real epoll_wait(). */
static int
chaos_net_test_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    ++g_epoll_wait_calls;
    return g_epoll_wait_result;
}

/** @brief Fake real epoll_pwait(). */
static int chaos_net_test_epoll_pwait(
    int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask
)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    (void)sigmask;
    ++g_epoll_pwait_calls;
    return g_epoll_pwait_result;
}
#endif

/* -------------------------------------------------------------------------
 * Compile the wrapper sources against the seams above
 * --------------------------------------------------------------------- */

/* SO_TYPE every descriptor reports; TRICKLE, DUP and CORRUPT under MSG_TRUNC depend on it. */
static int g_test_socket_type = SOCK_STREAM;

#define CHAOS_NET_SOCKET_TYPE(fd) ((void)(fd), g_test_socket_type)

/* How the DUP slot table is mapped: 0 normally, 1 fails with ENOMEM, 2 maps but another
 * thread publishes its table first. */
static int g_dup_map_mode = 0;
static void *chaos_net_test_dup_map(size_t size);
static void chaos_net_test_dup_unmap(void *address, size_t size);
/* Non-zero: forget the descriptor between a store's close check and its tag, the window a
 * concurrent close() can hit. */
static int g_dup_close_before_tag = 0;
static void chaos_net_test_dup_before_tag(int fd);
/* Socket identity behind a descriptor (production: inode ^ device << 32). Bumping the epoch
 * models the number being reused for another socket; epoch 0 means "unknown" (fstat failed). */
static uint64_t g_dup_socket_epoch = 1U;
#define CHAOS_NET_DUP_SOCKET(fd)                                                                   \
    (g_dup_socket_epoch == 0U ? 0U : (uint64_t)(fd) + (g_dup_socket_epoch << 32))
#define CHAOS_NET_DUP_BEFORE_TAG(fd) chaos_net_test_dup_before_tag(fd)
#define CHAOS_NET_DUP_MAP(size) chaos_net_test_dup_map(size)
#define CHAOS_NET_DUP_UNMAP(address, size) chaos_net_test_dup_unmap((address), (size))
#include "../../src/net/chaos_net_socket.c"

/** @brief Hook between the DUP close check and the tag: forgets @p fd once when armed. */
static void chaos_net_test_dup_before_tag(int fd)
{
    if (g_dup_close_before_tag)
    {
        g_dup_close_before_tag = 0;
        chaos_net_dup_forget(fd);
    }
}

/** @brief Unmaps of a DUP table that lost the publication race. */
static int g_dup_unmaps = 0;

/**
 * @brief DUP table mapper: fails in mode 1; in mode 2 maps, then publishes a second, empty
 *   table as the competing thread would, so the caller's table must be unmapped.
 */
static void *chaos_net_test_dup_map(size_t size)
{
    void *mapped;

    if (g_dup_map_mode == 1)
    {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(mapped != MAP_FAILED);
    if (g_dup_map_mode == 2)
    {
        chaos_net_dup_slot_t *racer =
            mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        int index;

        assert(racer != MAP_FAILED);
        for (index = 0; index < CHAOS_NET_DUP_SLOTS; ++index)
        {
            racer[index].fd = -1;
        }
        g_chaos_net_dup_slots = racer;
    }
    return mapped;
}

/** @brief DUP table unmapper: counts and unmaps. */
static void chaos_net_test_dup_unmap(void *address, size_t size)
{
    ++g_dup_unmaps;
    assert(munmap(address, size) == 0);
}
#include "../../src/net/chaos_net_extra.c"
#ifdef __linux__
/* Redirect file I/O and snprintf for the wait source only: it reads /proc/self/fdinfo to
 * find the descriptors an epoll instance watches. */
#define open chaos_net_test_wait_open
#define read chaos_net_test_wait_read
#define close chaos_net_test_wait_close
#undef snprintf
#define snprintf chaos_net_test_wait_snprintf
#endif
/* Replaces the raw ppoll a firing TIMEOUT waits with: records duration and signal mask, and
 * fails with EINTR on request, so no test actually waits. */
static int g_timeout_wait_calls = 0;
static int g_timeout_wait_interrupted = 0;
static const sigset_t *g_timeout_wait_mask = NULL;
static struct timespec g_timeout_wait_for;
static long chaos_net_test_timeout_wait(const struct timespec *wait, const sigset_t *sigmask)
{
    ++g_timeout_wait_calls;
    g_timeout_wait_for = *wait;
    g_timeout_wait_mask = sigmask;
    if (g_timeout_wait_interrupted)
    {
        errno = EINTR;
        return -1;
    }
    return 0;
}
#define CHAOS_NET_TIMEOUT_WAIT(wait, sigmask) chaos_net_test_timeout_wait((wait), (sigmask))
#include "../../src/net/chaos_net_wait.c"
#ifdef __linux__
#undef snprintf
#undef close
#undef read
#undef open
#endif

/* -------------------------------------------------------------------------
 * Per-scenario reset
 * --------------------------------------------------------------------- */

/**
 * @brief Points every socket real function at its fake (17 portable, 5 more on Linux),
 *   disables every rule and endpoint stub, and restores counters and default results.
 *
 * @details Called at the start of every scenario so no setting leaks between them. The six
 * fd calls (read, write, readv, writev, close, setsockopt) keep the raw-syscall
 * implementations `chaos_net_test_reset_runtime()` installs.
 */
static void reset_wrapper_stubs(void)
{
    chaos_net_test_reset_runtime();
    g_chaos_net_real_bind = chaos_net_test_bind;
    g_chaos_net_real_listen = chaos_net_test_listen;
    g_chaos_net_real_connect = chaos_net_test_connect;
    g_chaos_net_real_accept = chaos_net_test_accept;
    g_chaos_net_real_socket = chaos_net_test_socket;
    g_chaos_net_real_socketpair = chaos_net_test_socketpair;
    g_chaos_net_real_shutdown = chaos_net_test_shutdown;
    g_chaos_net_real_send = chaos_net_test_send;
    g_chaos_net_real_sendto = chaos_net_test_sendto;
    g_chaos_net_real_sendmsg = chaos_net_test_sendmsg;
    g_chaos_net_real_recv = chaos_net_test_recv;
    g_chaos_net_real_recvfrom = chaos_net_test_recvfrom;
    g_chaos_net_real_recvmsg = chaos_net_test_recvmsg;
    g_chaos_net_real_poll = chaos_net_test_poll;
    g_chaos_net_real_ppoll = chaos_net_test_ppoll;
    g_chaos_net_real_select = chaos_net_test_select;
    g_chaos_net_real_pselect = chaos_net_test_pselect;
#ifdef __linux__
    g_chaos_net_real_accept4 = chaos_net_test_accept4;
    g_chaos_net_real_sendmmsg = chaos_net_test_sendmmsg;
    g_chaos_net_real_recvmmsg = chaos_net_test_recvmmsg;
    g_chaos_net_real_epoll_wait = chaos_net_test_epoll_wait;
    g_chaos_net_real_epoll_pwait = chaos_net_test_epoll_pwait;
#endif
    (void)memset(&g_stub_rule, 0, sizeof(g_stub_rule));
    (void)memset(&g_stub_endpoint, 0, sizeof(g_stub_endpoint));
    g_stub_prepare = 0;
    g_stub_match_endpoint = 0;
    g_stub_match_misses = 0;
    g_stub_endpoint_from_sockaddr = 0;
    g_stub_endpoint_from_socket_spec = 0;
    g_stub_endpoint_from_activity = 0;
    g_stub_endpoint_from_local = 0;
    g_stub_endpoint_from_peer = 0;
    g_latency_calls = 0;
    g_errno_trigger = 0;
    g_should_trigger = 0;
    g_corrupt_calls = 0;
    g_wait_fail_snprintf = 0;
    g_wait_fake_open = 0;
    g_wait_force_open_fail = 0;
    g_wait_force_read_fail = 0;
    g_wait_fill_buffer = 0;
    g_wait_read_text = NULL;
    g_wait_read_offset = 0U;
    g_bind_calls = 0;
    g_listen_calls = 0;
    g_connect_calls = 0;
    g_accept_calls = 0;
    g_socket_calls = 0;
    g_socketpair_calls = 0;
    g_shutdown_calls = 0;
    g_send_calls = 0;
    g_sendto_calls = 0;
    g_sendmsg_calls = 0;
    g_recv_calls = 0;
    g_recvfrom_calls = 0;
    g_recvmsg_calls = 0;
    g_poll_calls = 0;
    g_ppoll_calls = 0;
    g_select_calls = 0;
    g_pselect_calls = 0;
#ifdef __linux__
    g_sendmmsg_calls = 0;
    g_recvmmsg_calls = 0;
    g_epoll_wait_calls = 0;
    g_epoll_pwait_calls = 0;
#endif
    g_bind_result = 0;
    g_listen_result = 0;
    g_connect_result = 0;
    g_accept_result = 10;
    g_socket_result = 8;
    g_socketpair_result = 0;
    g_shutdown_result = 0;
    g_send_result = 4;
    g_sendto_result = 4;
    g_sendmsg_result = 4;
    g_recv_result = 4;
    g_recvfrom_result = 4;
    g_recvmsg_result = 4;
    g_poll_result = 0;
    g_ppoll_result = 0;
    g_select_result = 0;
    g_pselect_result = 0;
#ifdef __linux__
    g_sendmmsg_result = 1;
    g_recvmmsg_result = 1;
    g_epoll_wait_result = 1;
    g_epoll_pwait_result = 1;
#endif
}

/* -------------------------------------------------------------------------
 * Tests
 * --------------------------------------------------------------------- */

/**
 * @brief Proves bind() and connect() forward without a rule, fail before the real call on
 *   ERRNO, and delay then call through on LATENCY.
 *
 * @details Both resolve their endpoint from the address argument. ERRNO returns -1 with
 * EADDRINUSE and the real bind() never runs, so the fault is indistinguishable from the
 * kernel's.
 */
static void test_bind_and_connect_paths(void)
{
    struct sockaddr_in address;

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9000U);
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EADDRINUSE;
    g_errno_trigger = 1;
    errno = 0;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == -1);
    assert(errno == EADDRINUSE);
    assert(g_bind_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_latency_calls == 1);
    assert(g_connect_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_connect_calls == 1);
}

/**
 * @brief Proves the ERRNO, LATENCY and pass-through paths of listen(), accept(), accept4(),
 *   send(), sendto() and sendmsg().
 *
 * @details listen() and accept() match on the local endpoint; send() on the connection;
 * sendto() and sendmsg() with an address on that address. ERRNO (EADDRINUSE, EAGAIN, EINTR,
 * EHOSTUNREACH) returns -1 without the real call; LATENCY delays and calls through; with no
 * rule the real result (fd 10, 4 bytes) is returned unchanged.
 */
static void test_accept_and_send_paths(void)
{
    struct sockaddr_in address;
    struct msghdr message;

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9100U);
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(listen(3, 16) == 0);
    assert(g_listen_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(listen(3, 16) == 0);
    assert(g_listen_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EADDRINUSE;
    g_errno_trigger = 1;
    errno = 0;
    assert(listen(3, 16) == -1);
    assert(errno == EADDRINUSE);
    assert(g_listen_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(accept(3, NULL, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_accept_calls == 0);

    reset_wrapper_stubs();
    assert(accept(3, NULL, NULL) == 10);
    assert(g_accept_calls == 1);

#ifdef __linux__
    reset_wrapper_stubs();
    assert(accept4(3, NULL, NULL, 0) == 10);
    assert(g_accept_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(accept4(3, NULL, NULL, 0) == -1);
    assert(errno == EINTR);
    assert(g_accept_calls == 0);
#endif

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(send(4, "data", 4U, 0) == 4);
    assert(g_send_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(send(4, "data", 4U, 0) == 4);
    assert(g_send_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(
        sendto(4, "data", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) ==
        -1
    );
    assert(errno == EHOSTUNREACH);
    assert(g_sendto_calls == 0);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    assert(sendmsg(4, &message, 0) == 4);
    assert(g_sendmsg_calls == 1);

    reset_wrapper_stubs();
    assert(
        sendto(4, "data", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 4
    );
    assert(g_sendto_calls == 1);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendmsg(4, &message, 0) == 4);
    assert(g_sendmsg_calls == 1);
    assert(g_latency_calls == 1);
}

/**
 * @brief Proves the CORRUPT, LATENCY, ERRNO and pass-through paths of recv(), recvfrom() and
 *   recvmsg().
 *
 * @details CORRUPT runs after the real receive and flips a bit in the received bytes ("data"
 * no longer reads back); ERRNO (EAGAIN) returns -1 without the real call; LATENCY delays and
 * calls through.
 */
static void test_recv_paths(void)
{
    char buffer[8] = "xxxxxxx";
    char msg_buffer[8] = "xxxxxxx";
    struct iovec iov;
    struct msghdr message;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(buffer[0] != 'd');

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recv(5, buffer, sizeof(buffer), 0) == -1);
    assert(errno == EAGAIN);
    assert(g_recv_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_recvfrom_calls == 0);

    reset_wrapper_stubs();
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);
    assert(g_corrupt_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = msg_buffer;
    iov.iov_len = sizeof(msg_buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(memcmp(msg_buffer, "data", 4U) != 0);

    reset_wrapper_stubs();
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = msg_buffer;
    iov.iov_len = sizeof(msg_buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recvmsg(5, &message, 0) == 4);
    assert(g_recvmsg_calls == 1);
    assert(g_latency_calls == 1);
}

/**
 * @brief Proves the ERRNO, LATENCY and pass-through paths of socket(), socketpair() and
 *   shutdown().
 *
 * @details socket() and socketpair() match on the endpoint their arguments describe (no
 * address exists yet); shutdown() on the connection. ERRNO (EAFNOSUPPORT, EMFILE, ENOTCONN)
 * returns -1 without the real call; LATENCY delays and the pair (11, 12) or fd 8 is returned
 * unchanged.
 */
static void test_socket_and_shutdown_paths(void)
{
    int sv[2];

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAFNOSUPPORT;
    g_errno_trigger = 1;
    errno = 0;
    assert(socket(AF_INET, SOCK_STREAM, 0) == -1);
    assert(errno == EAFNOSUPPORT);
    assert(g_socket_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EMFILE;
    g_errno_trigger = 1;
    errno = 0;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1);
    assert(errno == EMFILE);
    assert(g_socketpair_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(g_socketpair_calls == 1);
    assert(g_latency_calls == 1);
    assert(sv[0] == 11);
    assert(sv[1] == 12);

    reset_wrapper_stubs();
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ENOTCONN;
    g_errno_trigger = 1;
    errno = 0;
    assert(shutdown(7, SHUT_RDWR) == -1);
    assert(errno == ENOTCONN);
    assert(g_shutdown_calls == 0);

    reset_wrapper_stubs();
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);

    reset_wrapper_stubs();
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(g_socketpair_calls == 1);

    reset_wrapper_stubs();
    assert(shutdown(7, SHUT_RDWR) == 0);
    assert(g_shutdown_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(shutdown(7, SHUT_RDWR) == 0);
    assert(g_shutdown_calls == 1);
    assert(g_latency_calls == 1);
}

/**
 * @brief Proves TIMEOUT, LATENCY, ERRNO and pass-through for poll(), ppoll(), select() and
 *   pselect().
 *
 * @details
 * - TIMEOUT waits out the caller's timeout and reports "nothing ready": return 0, revents
 *   and fd sets cleared, no real call. select() leaves 0 remaining time in its timeval, as
 *   Linux does after a full timeout. A call without a timeout (-1 or NULL) cannot time out,
 *   so the real call runs.
 * - The TIMEOUT wait uses the call's own duration (1.25 s, or 20 ms rounded from poll's
 *   milliseconds) and the call's signal mask (ppoll), or the thread's mask (poll). A signal
 *   ends it with -1/EINTR, as it would end the real wait, and leaves revents untouched.
 * - On Linux the default wait (raw ppoll with no descriptors and the kernel's 8-byte sigset)
 *   is itself exercised with and without a mask.
 * - ERRNO returns -1 without the real call; LATENCY delays and calls through.
 */
static void test_wait_paths(void)
{
    struct pollfd fds[1];
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timespec ts;
    struct timeval tv;

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(poll(fds, 1U, 1) == 0);
    assert(g_poll_calls == 0);
    assert(fds[0].revents == 0);
    assert(poll(fds, 1U, -1) == 0);
    assert(g_poll_calls == 1);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    tv.tv_sec = 0;
    tv.tv_usec = 1500;
    assert(select(10, &readfds, NULL, NULL, &tv) == 0);
    assert(g_select_calls == 0);
    assert(!FD_ISSET(9, &readfds));
    assert(tv.tv_sec == 0 && tv.tv_usec == 0);
    assert(select(10, &readfds, NULL, NULL, NULL) == 0);
    assert(g_select_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(poll(fds, 1U, 100) == -1);
    assert(errno == EINTR);
    assert(g_poll_calls == 0);

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 0);
    assert(fds[0].revents == 0);

    {
        sigset_t mask;
        struct timespec wait = {1, 250000000L};

        sigemptyset(&mask);
        g_timeout_wait_calls = 0;
        fds[0].revents = POLLIN;
        assert(ppoll(fds, 1U, &wait, &mask) == 0);
        assert(g_timeout_wait_calls == 1 && g_timeout_wait_mask == &mask);
        assert(g_timeout_wait_for.tv_sec == 1 && g_timeout_wait_for.tv_nsec == 250000000L);
        assert(poll(fds, 1U, 20) == 0);
        assert(g_timeout_wait_calls == 2 && g_timeout_wait_mask == NULL);
        assert(g_timeout_wait_for.tv_sec == 0 && g_timeout_wait_for.tv_nsec == 20000000L);
        g_timeout_wait_interrupted = 1;
        fds[0].revents = POLLIN;
        errno = 0;
        assert(ppoll(fds, 1U, &wait, &mask) == -1 && errno == EINTR);
        assert(fds[0].revents == POLLIN && g_ppoll_calls == 0);
        errno = 0;
        assert(poll(fds, 1U, 20) == -1 && errno == EINTR);
        assert(g_poll_calls == 0);
        g_timeout_wait_interrupted = 0;
#ifdef SYS_ppoll
        wait.tv_sec = 0;
        wait.tv_nsec = 1000000L;
        assert(syscall(SYS_ppoll, NULL, 0, &wait, &mask, (size_t)8U) == 0);
        wait.tv_nsec = 1000000L;
        assert(syscall(SYS_ppoll, NULL, 0, &wait, NULL, (size_t)8U) == 0);
#endif
    }

    reset_wrapper_stubs();
    fds[0].fd = 9;
    fds[0].events = POLLIN;
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(ppoll(fds, 1U, &ts, NULL) == -1);
    assert(errno == EINTR);
    assert(g_ppoll_calls == 0);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(9, &readfds);
    FD_SET(8, &writefds);
    FD_SET(7, &exceptfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    tv.tv_sec = 0;
    tv.tv_usec = 1;
    errno = 0;
    assert(select(10, &readfds, &writefds, &exceptfds, &tv) == -1);
    assert(errno == EAGAIN);
    assert(g_select_calls == 0);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(select(10, &readfds, NULL, NULL, &tv) == 0);
    assert(g_select_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 0);
    assert(!FD_ISSET(9, &readfds));

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    errno = 0;
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == -1);
    assert(errno == EINTR);
    assert(g_pselect_calls == 0);

    reset_wrapper_stubs();
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 1);

    reset_wrapper_stubs();
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(g_ppoll_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(select(10, &readfds, NULL, NULL, &tv) == 0);
    assert(g_select_calls == 1);

    reset_wrapper_stubs();
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(pselect(10, &readfds, NULL, NULL, &ts, NULL) == 0);
    assert(g_pselect_calls == 1);
}

#ifdef __linux__
/**
 * @brief Proves the sendmmsg() and recvmmsg() paths (Linux): ERRNO, LATENCY, CORRUPT,
 *   pass-through, the TLS guard, and the `@size` of a batch.
 *
 * @details
 * - ERRNO (EHOSTUNREACH, EAGAIN) returns -1 without the real call; CORRUPT changes the
 *   received bytes; under the TLS guard the call is forwarded untouched.
 * - `@size` sees the sum of the batch (2 x 2 bytes = 4). Messages beyond
 *   `CHAOS_NET_MMSG_MAX` (1024, the kernel's limit) are not inspected, so an address on
 *   message 1024 is never resolved and no rule applies.
 * - The size is unknown (`CHAOS_POLICY_NO_SIZE`) for more than `CHAOS_NET_IOV_MAX` iovecs,
 *   a NULL vector, or a sum that overflows; a NULL batch is forwarded.
 */
static void test_batch_paths(void)
{
    struct sockaddr_in address;
    char buffer[8] = "xxxxxxx";
    struct iovec iov;
    struct mmsghdr messages[1];

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9200U);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_name = &address;
    messages[0].msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(sendmmsg(4, messages, 1U, 0) == -1);
    assert(errno == EHOSTUNREACH);
    assert(g_sendmmsg_calls == 0);

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9200U);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_name = &address;
    messages[0].msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(messages, 0, sizeof(messages));
    messages[0].msg_hdr.msg_iov = &iov;
    messages[0].msg_hdr.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == 1);
    assert(g_recvmmsg_calls == 1);
    assert(g_corrupt_calls == 1);
    assert(memcmp(buffer, "data", 4U) != 0);

    {
        static struct mmsghdr batch[CHAOS_NET_MMSG_MAX + 2U];
        struct iovec two_bytes;

        reset_wrapper_stubs();
        two_bytes.iov_base = buffer;
        two_bytes.iov_len = 2U;
        (void)memset(batch, 0, sizeof(batch));
        batch[0].msg_hdr.msg_iov = &two_bytes;
        batch[0].msg_hdr.msg_iovlen = 1;
        batch[1].msg_hdr.msg_iov = &two_bytes;
        batch[1].msg_hdr.msg_iovlen = 1;
        g_stub_endpoint_from_peer = 1;
        g_stub_match_endpoint = 1;
        g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
        assert(sendmmsg(4, batch, 2U, 0U) == 1);
        assert(g_latency_calls == 1 && g_last_call_size == 4U);
        assert(recvmmsg(5, batch, 2U, 0U, NULL) == 1);
        assert(g_latency_calls == 2 && g_last_call_size == 4U);

        reset_wrapper_stubs();
        batch[CHAOS_NET_MMSG_MAX].msg_hdr.msg_name = &address;
        batch[CHAOS_NET_MMSG_MAX].msg_hdr.msg_namelen = (socklen_t)sizeof(address);
        g_stub_endpoint_from_sockaddr = 1;
        g_stub_match_endpoint = 1;
        g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
        assert(sendmmsg(4, batch, CHAOS_NET_MMSG_MAX + 2U, 0U) == 1);
        assert(g_latency_calls == 0);

        batch[0].msg_hdr.msg_iovlen = (size_t)CHAOS_NET_IOV_MAX + 1U;
        assert(chaos_net_mmsg_size(batch, 2U) == CHAOS_POLICY_NO_SIZE);
        assert(chaos_net_mmsg_size(NULL, 2U) == CHAOS_POLICY_NO_SIZE);
        batch[0].msg_hdr.msg_iovlen = 1;
        two_bytes.iov_len = (size_t)(UINT64_MAX / 2U);
        assert(chaos_net_mmsg_size(batch, 2U) == CHAOS_POLICY_NO_SIZE);
        assert(sendmmsg(4, NULL, 1U, 0U) == 1);
    }

    reset_wrapper_stubs();
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);

    reset_wrapper_stubs();
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == 1);
    assert(g_recvmmsg_calls == 1);

    reset_wrapper_stubs();
    g_chaos_net_tls_guard = 1;
    assert(sendmmsg(4, messages, 1U, 0U) == 1);
    assert(g_sendmmsg_calls == 1);
    g_chaos_net_tls_guard = 0;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvmmsg(5, messages, 1U, 0U, NULL) == -1);
    assert(errno == EAGAIN);
    assert(g_recvmmsg_calls == 0);
}
#endif

/**
 * @brief Proves the internal pre-call, wait, fdinfo-scan, fd-set and iovec helpers directly.
 *
 * @details
 * - The three pre-call helpers ignore NULL, delay on LATENCY, fail with the rule's errno on
 *   ERRNO, and do nothing for an effect applied after the call (CORRUPT).
 * - TIMEOUT sets the synthetic-timeout flag only for a call with a timeout; with none (-1)
 *   the rule is not even consulted.
 * - Timeouts convert to milliseconds rounded up (2 s + 1 ns is 2001 ms; 1 s + 999 us is
 *   1001 ms), saturate at INT32_MAX, and a value the kernel would refuse with EINVAL
 *   (negative, or nanoseconds/microseconds out of range) counts as "no timeout" so the real
 *   call reports the error.
 * - fdinfo scanning uses only complete `tfd:` lines; a line cut off by the buffer, a
 *   non-numeric and a negative descriptor do not match.
 * - Clearing revents and fd sets, every `chaos_net_call_real_*()` forwarder, CORRUPT across
 *   iovecs with a seeded PRNG, and matching over pollfds (skipping fd -1) and fd sets
 *   (skipping descriptors not in the set).
 */
static void test_direct_helper_paths(void)
{
    char second[4] = {'a', 'b', 'c', 'd'};
    struct iovec recv_iov[2];
    char first[1] = {0};
    struct pollfd fds[2];
    fd_set readfds;
    fd_set writefds;
    fd_set exceptfds;
    struct timespec ts;
    struct timeval tv;
    chaos_net_rule_t rule;
    int synthetic_timeout = -1;
    int pipefd[2];

    reset_wrapper_stubs();
    assert(chaos_net_apply_pre_call_rule(NULL) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(NULL) == 0);
    assert(chaos_net_wait_pre_call(NULL, 0, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    assert(chaos_net_wait_pre_call(&rule, 0, &synthetic_timeout) == 0);
    assert(g_latency_calls == 3);

    rule.effect = CHAOS_NET_EFFECT_ERRNO;
    rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(chaos_net_apply_pre_call_rule(&rule) == -1);
    assert(errno == EAGAIN);
    errno = 0;
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == -1);
    assert(errno == EAGAIN);
    errno = 0;
    assert(chaos_net_wait_pre_call(&rule, 0, &synthetic_timeout) == -1);
    assert(errno == EAGAIN);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    synthetic_timeout = 0;
    assert(chaos_net_wait_pre_call(&rule, 0, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 1);
    g_should_trigger = 0;
    assert(chaos_net_wait_pre_call(&rule, -1, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);
    g_should_trigger = 1;
    assert(chaos_net_wait_timespec_ms(NULL) == -1 && chaos_net_wait_timeval_ms(NULL) == -1);
    ts.tv_sec = 2;
    ts.tv_nsec = 1;
    assert(chaos_net_wait_timespec_ms(&ts) == 2001);
    ts.tv_sec = -1;
    assert(chaos_net_wait_timespec_ms(&ts) == -1);
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000000L;
    assert(chaos_net_wait_timespec_ms(&ts) == -1);
    tv.tv_sec = 0;
    tv.tv_usec = 1000000L;
    assert(chaos_net_wait_timeval_ms(&tv) == -1);
    ts.tv_nsec = 1;
    ts.tv_sec = (time_t)INT32_MAX;
    assert(chaos_net_wait_timespec_ms(&ts) == INT32_MAX);
    tv.tv_sec = 1;
    tv.tv_usec = 999;
    assert(chaos_net_wait_timeval_ms(&tv) == 1001);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    synthetic_timeout = -1;
    assert(chaos_net_wait_pre_call(&rule, 0, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

    {
        char text[64];

        reset_wrapper_stubs();
        g_stub_prepare = 1;
        g_stub_endpoint_from_activity = 1;
        g_stub_match_endpoint = 1;
        (void)snprintf(text, sizeof(text), "%s", "pos:\t0\ntfd:  12 events: 19\n");
        assert(chaos_net_wait_scan_fdinfo(text, &rule) == 1);
        (void)snprintf(text, sizeof(text), "%s", "pos:\t0\ntfd:  12");
        assert(chaos_net_wait_scan_fdinfo(text, &rule) == 0);
        (void)snprintf(text, sizeof(text), "%s", "tfd: x\ntfd: -3\n");
        assert(chaos_net_wait_scan_fdinfo(text, &rule) == 0);
        reset_wrapper_stubs();
    }

    chaos_net_wait_clear_pollfds(NULL, 0U);
    fds[0].revents = POLLIN;
    fds[1].revents = POLLOUT;
    chaos_net_wait_clear_pollfds(fds, 2U);
    assert(fds[0].revents == 0);
    assert(fds[1].revents == 0);

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(3, &readfds);
    FD_SET(4, &writefds);
    FD_SET(5, &exceptfds);
    chaos_net_wait_clear_fdsets(&readfds, &writefds, &exceptfds);
    assert(!FD_ISSET(3, &readfds));
    assert(!FD_ISSET(4, &writefds));
    assert(!FD_ISSET(5, &exceptfds));

    assert(chaos_net_call_real_bind(1, NULL, 0) == 0);
    assert(chaos_net_call_real_listen(1, 1) == 0);
    assert(chaos_net_call_real_connect(1, NULL, 0) == 0);
    assert(chaos_net_call_real_accept(1, NULL, NULL) == 10);
#ifdef __linux__
    assert(chaos_net_call_real_accept4(1, NULL, NULL, 0) == 10);
#endif
    assert(chaos_net_call_real_send(1, "x", 1U, 0) == 4);
    assert(chaos_net_call_real_sendto(1, "x", 1U, 0, NULL, 0) == 4);
    assert(chaos_net_call_real_sendmsg(1, NULL, 0) == 4);
    assert(chaos_net_call_real_recv(1, second, sizeof(second), 0) == 4);
    assert(chaos_net_call_real_recvfrom(1, second, sizeof(second), 0, NULL, NULL) == 4);
    assert(chaos_net_call_real_recvmsg(1, NULL, 0) == 4);
    assert(chaos_net_call_real_socket(1, 2, 3) == 8);
    assert(chaos_net_call_real_socketpair(AF_UNIX, SOCK_STREAM, 0, pipefd) == 0);
    assert(chaos_net_call_real_shutdown(1, SHUT_RDWR) == 0);
    assert(chaos_net_call_real_poll(fds, 2U, 0) == 0);
    ts.tv_sec = 0;
    ts.tv_nsec = 1;
    assert(chaos_net_call_real_ppoll(fds, 2U, &ts, NULL) == 0);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    assert(chaos_net_call_real_select(0, NULL, NULL, NULL, &tv) == 0);
    assert(chaos_net_call_real_pselect(0, NULL, NULL, NULL, &ts, NULL) == 0);

    second[0] = 'a';
    second[1] = 'b';
    second[2] = 'c';
    second[3] = 'd';
    chaos_net_corrupt_iovecs(NULL, 0, 0U);
    recv_iov[0].iov_base = first;
    recv_iov[0].iov_len = 1U;
    recv_iov[1].iov_base = second;
    recv_iov[1].iov_len = sizeof(second);
    for (g_chaos_net_tls_prng_state = 1U; chaos_net_prng_next_u32() % 3U == 0U;
         ++g_chaos_net_tls_prng_state)
    {
    }
    chaos_net_corrupt_iovecs(recv_iov, 2, 3U);
    assert(g_corrupt_calls >= 1);

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_pollfds(NULL, 1U, &rule));
    g_stub_prepare = 1;
    fds[0].fd = -1;
    assert(!chaos_net_wait_match_pollfds(fds, 1U, &rule));
    fds[0].fd = 9;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_pollfds(fds, 1U, &rule));

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_fdsets(0, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    assert(!chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    assert(!chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
    g_stub_prepare = 1;
    FD_ZERO(&readfds);
    FD_SET(9, &readfds);
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_fdsets(10, &readfds, NULL, NULL, &rule));
}

#ifdef __linux__
/**
 * @brief Proves the Linux-only forwarders, CORRUPT across a batch, and every failure path of
 *   the epoll fdinfo match.
 *
 * @details CORRUPT of a message whose first iovec is empty lands in the second (one call).
 * The epoll match fails for a NULL rule, an unbuildable fdinfo path, a non-epoll descriptor,
 * a read error and a buffer with no newline; it succeeds on a real epoll instance watching a
 * pipe, reading the real `/proc/self/fdinfo`.
 */
static void test_direct_linux_helper_paths(void)
{
    struct iovec recv_iov[2];
    char first[1] = {0};
    char second[4] = {'a', 'b', 'c', 'd'};
    struct mmsghdr recv_messages[1];
    struct epoll_event events[1];
    struct epoll_event event;
    chaos_net_rule_t rule;
    int pipefd[2];
    int epfd;

    reset_wrapper_stubs();
    assert(chaos_net_call_real_sendmmsg(1, NULL, 0U, 0U) == 1);
    assert(chaos_net_call_real_recvmmsg(1, recv_messages, 0U, 0U, NULL) == 1);
    assert(chaos_net_call_real_epoll_wait(-1, events, 1, 0) == 1);
    assert(chaos_net_call_real_epoll_pwait(-1, events, 1, 0, NULL) == 1);

    recv_iov[0].iov_base = first;
    recv_iov[0].iov_len = 0U;
    recv_iov[1].iov_base = second;
    recv_iov[1].iov_len = sizeof(second);
    (void)memset(recv_messages, 0, sizeof(recv_messages));
    recv_messages[0].msg_hdr.msg_iov = recv_iov;
    recv_messages[0].msg_hdr.msg_iovlen = 2;
    recv_messages[0].msg_len = 4U;
    chaos_net_corrupt_mmsghdrs(NULL, 0U);
    chaos_net_corrupt_mmsghdrs(recv_messages, 1U);
    assert(g_corrupt_calls == 1);

    reset_wrapper_stubs();
    assert(!chaos_net_wait_match_epoll(-1, NULL));
    g_wait_fail_snprintf = 1;
    g_stub_prepare = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    assert(!chaos_net_wait_match_epoll(-1, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_wait_fake_open = 1;
    g_wait_force_read_fail = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_wait_fake_open = 1;
    g_wait_fill_buffer = 1;
    assert(!chaos_net_wait_match_epoll(7, &rule));
    reset_wrapper_stubs();
    assert(pipe(pipefd) == 0);
    epfd = epoll_create1(0);
    assert(epfd >= 0);
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];
    assert(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &event) == 0);
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    assert(chaos_net_wait_match_epoll(epfd, &rule));
    assert(close(pipefd[0]) == 0);
    assert(close(pipefd[1]) == 0);
    assert(close(epfd) == 0);
}
#endif

/**
 * @brief Proves the remaining ERRNO and LATENCY combinations of the connection wrappers, and
 *   that the TLS guard makes socket() forward untouched.
 *
 * @details connect() fails with ECONNREFUSED; accept() and accept4() delay; send() fails with
 * EPIPE; sendto() and sendmsg() without an address match on the connection (LATENCY,
 * EHOSTUNREACH); recvfrom() delays and recvmsg() fails with EAGAIN. Each ERRNO path leaves
 * the real call count at 0.
 */
static void test_wrapper_passthrough_and_additional_branches(void)
{
    struct sockaddr_in address;
    struct msghdr message;
    struct iovec iov;
    char buffer[8] = "xxxxxxx";

    reset_wrapper_stubs();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9001U);
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(g_bind_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNREFUSED;
    g_errno_trigger = 1;
    errno = 0;
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == -1);
    assert(errno == ECONNREFUSED);
    assert(g_connect_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(accept(3, NULL, NULL) == 10);
    assert(g_accept_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
#ifdef __linux__
    assert(accept4(3, NULL, NULL, 0) == 10);
    assert(g_accept_calls == 1);
    assert(g_latency_calls == 1);
#endif

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EPIPE;
    g_errno_trigger = 1;
    errno = 0;
    assert(send(4, "data", 4U, 0) == -1);
    assert(errno == EPIPE);
    assert(g_send_calls == 0);

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(sendto(4, "data", 4U, 0, NULL, 0) == 4);
    assert(g_sendto_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    (void)memset(&message, 0, sizeof(message));
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EHOSTUNREACH;
    g_errno_trigger = 1;
    errno = 0;
    assert(sendmsg(4, &message, 0) == -1);
    assert(errno == EHOSTUNREACH);
    assert(g_sendmsg_calls == 0);

    reset_wrapper_stubs();
    assert(recv(5, buffer, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(recvfrom(5, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EAGAIN;
    g_errno_trigger = 1;
    errno = 0;
    assert(recvmsg(5, &message, 0) == -1);
    assert(errno == EAGAIN);
    assert(g_recvmsg_calls == 0);

    reset_wrapper_stubs();
    g_chaos_net_tls_guard = 1;
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(g_socket_calls == 1);
    g_chaos_net_tls_guard = 0;
}

#ifdef __linux__
/* Fake real read(), defined with the descriptor fakes below: an endless stream without a
 * newline when used as the fdinfo reader. */
static ssize_t chaos_net_test_next_read(int fd, void *buffer, size_t size);

/** @brief fdinfo text the scripted read hands out. */
static const char *g_fdinfo_script = NULL;
/** @brief Bytes of the fdinfo script still to hand out. */
static size_t g_fdinfo_left = 0U;

/** @brief Real read() replacement: hands out the fdinfo script at most 100 bytes at a time, so
 *   lines straddle the reader's chunk boundaries. */
static ssize_t chaos_net_test_script_read(int fd, void *buffer, size_t size)
{
    size_t part = g_fdinfo_left < size ? g_fdinfo_left : size;

    (void)fd;
    part = part < 100U ? part : 100U;
    (void)memcpy(buffer, g_fdinfo_script, part);
    g_fdinfo_script += part;
    g_fdinfo_left -= part;
    return (ssize_t)part;
}

/**
 * @brief Proves the epoll fdinfo reader finds a watched descriptor anywhere in the file, and
 *   bounds its work.
 *
 * @details With 30 watched pipes only the last one resolves to an endpoint, so its `tfd:` line
 * lies past the first 512-byte chunk; TIMEOUT still fires. A descriptor nobody watches matches
 * nothing and the real epoll_wait() runs. A 700-byte line (longer than a chunk) is skipped
 * whole and the `tfd:` line after it is still found. An endless stream without newlines stops
 * at the 256 KiB scan limit with no match.
 */
static void test_epoll_fdinfo_in_pieces(void)
{
    struct epoll_event event;
    struct epoll_event events[1];
    int pipes[30][2];
    int epfd = epoll_create1(0);
    int index;

    assert(epfd >= 0);
    for (index = 0; index < 30; ++index)
    {
        assert(pipe(pipes[index]) == 0);
        (void)memset(&event, 0, sizeof(event));
        event.events = EPOLLIN;
        assert(epoll_ctl(epfd, EPOLL_CTL_ADD, pipes[index][0], &event) == 0);
    }
    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_activity_only_fd = pipes[29][0];
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(epoll_wait(epfd, events, 1, 0) == 0);
    assert(g_epoll_wait_calls == 0);
    g_stub_activity_only_fd = 1000; /* not watched */
    (void)epoll_wait(epfd, events, 1, 0);
    assert(g_epoll_wait_calls == 1);
    g_stub_activity_only_fd = -1;

    {
        static char script[1200];

        (void)memset(script, 'x', 700U);
        (void)snprintf(script + 700, sizeof(script) - 700U, "%s", "\ntfd:  12 events: 19\n");
        g_fdinfo_script = script;
        g_fdinfo_left = strlen(script);
        g_chaos_net_real_read = chaos_net_test_script_read;
        g_stub_activity_only_fd = 12;
        assert(chaos_net_wait_match_epoll(epfd, &g_stub_rule) == 1);
        g_chaos_net_real_read = chaos_net_test_next_read;
        assert(chaos_net_wait_match_epoll(epfd, &g_stub_rule) == 0);
        g_stub_activity_only_fd = -1;
        reset_wrapper_stubs();
    }
    for (index = 0; index < 30; ++index)
    {
        (void)close(pipes[index][0]);
        (void)close(pipes[index][1]);
    }
    (void)close(epfd);
}

/**
 * @brief Proves TIMEOUT, ERRNO, LATENCY and pass-through for epoll_wait() and epoll_pwait()
 *   (Linux).
 *
 * @details A real epoll instance watching a pipe is used because the wrappers find the
 * watched descriptors through `/proc/self/fdinfo/<epfd>`. TIMEOUT returns 0 events without
 * the real call; ERRNO returns -1/ETIMEDOUT without it; LATENCY delays and returns the real
 * result (1).
 */
static void test_epoll_wrapper_paths(void)
{
    int pipefd[2];
    int epfd;
    struct epoll_event event;
    struct epoll_event events[1];

    assert(pipe(pipefd) == 0);
    epfd = epoll_create1(0);
    assert(epfd >= 0);
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = pipefd[0];
    assert(epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd[0], &event) == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(epoll_wait(epfd, events, 1, 0) == 0);
    assert(g_epoll_wait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ETIMEDOUT;
    g_errno_trigger = 1;
    errno = 0;
    assert(epoll_wait(epfd, events, 1, 0) == -1);
    assert(errno == ETIMEDOUT);
    assert(g_epoll_wait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(epoll_wait(epfd, events, 1, 0) == 1);
    assert(g_epoll_wait_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ETIMEDOUT;
    g_errno_trigger = 1;
    errno = 0;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == -1);
    assert(errno == ETIMEDOUT);
    assert(g_epoll_pwait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 0);
    assert(g_epoll_pwait_calls == 0);

    reset_wrapper_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 1);
    assert(g_epoll_pwait_calls == 1);
    assert(g_latency_calls == 1);

    reset_wrapper_stubs();
    assert(epoll_wait(epfd, events, 1, 0) == 1);
    assert(g_epoll_wait_calls == 1);

    reset_wrapper_stubs();
    assert(epoll_pwait(epfd, events, 1, 0, NULL) == 1);
    assert(g_epoll_pwait_calls == 1);

    assert(close(pipefd[0]) == 0);
    assert(close(pipefd[1]) == 0);
    assert(close(epfd) == 0);
}
#endif

#if defined(__GLIBC__)
/** @brief Calls of the `__chk_fail()` replacement. */
static int g_chk_fail_calls = 0;

/** @brief Replaces glibc's `__chk_fail()` (which aborts) so the overflow path is observable. */
static void chaos_net_test_chk_fail(void)
{
    ++g_chk_fail_calls;
}

/**
 * @brief Proves `__recv_chk()` and `__recvfrom_chk()` (glibc _FORTIFY_SOURCE) go through the
 *   receive wrappers, and that a length beyond the declared buffer size calls the overflow
 *   handler without the real call.
 *
 * @details Without these, a program built with _FORTIFY_SOURCE would call glibc's checked
 * variants directly and bypass every recv rule.
 */
static void test_fortified_receive(void)
{
    char buffer[8] = "xxxxxxx";

    g_chaos_net_chk_fail = chaos_net_test_chk_fail;

    reset_wrapper_stubs();
    assert(__recv_chk(5, buffer, 4U, sizeof(buffer), 0) == 4);
    assert(g_recv_calls == 1);
    g_chk_fail_calls = 0;
    /* 4 bytes into a buffer declared as 2: the check trips before anything is written. */
    assert(__recv_chk(5, buffer, 4U, 2U, 0) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_recv_calls == 1);

    reset_wrapper_stubs();
    /* __extension__: NULL converts to glibc's transparent sockaddr union, which -pedantic
     * accepts silently only for prototypes from system headers. */
    assert(__extension__ __recvfrom_chk(5, buffer, 4U, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(g_recvfrom_calls == 1);
    g_chk_fail_calls = 0;
    assert(__extension__ __recvfrom_chk(5, buffer, 4U, 2U, 0, NULL, NULL) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_recvfrom_calls == 1);

    g_chaos_net_chk_fail = __chk_fail;
}
#endif

/** @brief Calls of the fake real read, write, readv, writev and close. */
static int g_descriptor_calls = 0;
/** @brief Calls of the fake real setsockopt. */
static int g_setsockopt_calls = 0;
/** @brief SO_LINGER value the fake setsockopt last received. */
static struct linger g_setsockopt_linger;

/** @brief Fake real read(): records the length and returns "data" (4 bytes) when it fits. */
static ssize_t chaos_net_test_next_read(int fd, void *buffer, size_t size)
{
    (void)fd;
    ++g_descriptor_calls;
    g_last_receive_size = size;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
        return 4;
    }
    return 0;
}

/** @brief Fake real write(): reports everything written. */
static ssize_t chaos_net_test_next_write(int fd, const void *buffer, size_t size)
{
    (void)fd;
    (void)buffer;
    ++g_descriptor_calls;
    return (ssize_t)size;
}

/**
 * @brief Fake real readv() and writev(): records the vector shape and reports the first
 *   iovec's length; more than `CHAOS_NET_IOV_MAX` entries fail with EINVAL as in the kernel.
 */
static ssize_t chaos_net_test_next_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int index;

    (void)fd;
    ++g_descriptor_calls;
    if (iovcnt > CHAOS_NET_IOV_MAX)
    {
        errno = EINVAL; /* before touching the vector, as the kernel */
        return -1;
    }
    g_last_receive_iovlen = (size_t)iovcnt;
    g_last_receive_iov_bytes = 0U;
    for (index = 0; index < iovcnt; ++index)
    {
        g_last_receive_iov_bytes += iov[index].iov_len;
    }
    return (ssize_t)iov[0].iov_len;
}

/** @brief Fake real close(). */
static int chaos_net_test_next_close(int fd)
{
    (void)fd;
    ++g_descriptor_calls;
    return 0;
}

/** @brief Fake real setsockopt(): accepts only SO_LINGER and records the value. */
static int
chaos_net_test_next_setsockopt(int fd, int level, int name, const void *value, socklen_t length)
{
    (void)fd;
    assert(level == SOL_SOCKET && name == SO_LINGER && length == sizeof(struct linger));
    ++g_setsockopt_calls;
    (void)memcpy(&g_setsockopt_linger, value, sizeof(g_setsockopt_linger));
    return 0;
}

/** @brief reset_wrapper_stubs() plus fakes for the six fd calls, with their counters cleared. */
static void reset_descriptor_stubs(void)
{
    reset_wrapper_stubs();
    g_chaos_net_real_read = chaos_net_test_next_read;
    g_chaos_net_real_write = chaos_net_test_next_write;
    g_chaos_net_real_readv = chaos_net_test_next_readv;
    g_chaos_net_real_writev = chaos_net_test_next_readv;
    g_chaos_net_real_close = chaos_net_test_next_close;
    g_chaos_net_real_setsockopt = chaos_net_test_next_setsockopt;
    g_descriptor_calls = 0;
    g_setsockopt_calls = 0;
    (void)memset(&g_setsockopt_linger, 0, sizeof(g_setsockopt_linger));
}

/**
 * @brief Proves read(), write(), readv(), writev() and close() apply net rules to sockets only.
 *
 * @details
 * - Without rules, on a non-socket descriptor, or under the TLS guard the call goes to the
 *   real function unchanged: these wrappers sit in front of every file I/O in the process.
 * - recv rules apply to read() and readv() (LATENCY, ERRNO, CORRUPT); send rules to write()
 *   and writev() (LATENCY, ERRNO).
 * - close(): RESET sets a zero SO_LINGER first so the close sends an RST; LATENCY delays it;
 *   ERRNO reports the error only after the descriptor was really closed, because a close()
 *   that returns -1 must not leak the descriptor.
 */
static void test_descriptor_calls_on_sockets(void)
{
    char buffer[8] = "xxxxxxx";
    struct iovec iov;

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    /* No rules loaded: forwarded before any socket lookup. */
    reset_descriptor_stubs();
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(write(5, buffer, 4U) == 4);
    assert(readv(5, &iov, 1) == (ssize_t)sizeof(buffer));
    assert(writev(5, &iov, 1) == (ssize_t)sizeof(buffer));
    assert(close(5) == 0);
    assert(g_descriptor_calls == 5);

    /* Rules loaded, but no endpoint resolves (not a socket): forwarded. */
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNRESET;
    g_errno_trigger = 1;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(write(5, buffer, 4U) == 4);
    assert(close(5) == 0);
    assert(g_descriptor_calls == 3);

    /* TLS guard set (the library's own I/O): forwarded. */
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_errno_trigger = 1;
    g_chaos_net_tls_guard = 1;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    g_chaos_net_tls_guard = 0;

    /* recv rules apply to read() and readv(). */
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNRESET;
    g_errno_trigger = 1;
    errno = 0;
    assert(read(5, buffer, sizeof(buffer)) == -1);
    assert(errno == ECONNRESET);
    assert(readv(5, &iov, 1) == -1);
    assert(g_descriptor_calls == 0);
    g_errno_trigger = 0;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(readv(5, &iov, 1) == (ssize_t)sizeof(buffer));
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(readv(5, &iov, 1) == (ssize_t)sizeof(buffer));
    assert(g_latency_calls == 2);
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;
    assert(read(5, buffer, sizeof(buffer)) == 4);
    assert(g_corrupt_calls == 1);
    assert(readv(5, &iov, 1) == (ssize_t)sizeof(buffer));

    /* send rules apply to write() and writev(). */
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EPIPE;
    g_errno_trigger = 1;
    assert(write(5, buffer, 4U) == -1);
    assert(errno == EPIPE);
    assert(writev(5, &iov, 1) == -1);
    assert(g_descriptor_calls == 0);
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(write(5, buffer, 4U) == 4);
    assert(writev(5, &iov, 1) == (ssize_t)sizeof(buffer));
    assert(g_latency_calls == 2);

    /* close rules: RESET arms SO_LINGER {1, 0}; ERRNO closes for real, then fails. */
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_RESET;
    g_should_trigger = 1;
    assert(close(5) == 0);
    assert(g_setsockopt_calls == 1);
    assert(g_setsockopt_linger.l_onoff == 1 && g_setsockopt_linger.l_linger == 0);
    assert(g_descriptor_calls == 1);
    g_should_trigger = 0;
    assert(close(5) == 0);
    assert(g_setsockopt_calls == 1);
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(close(5) == 0);
    assert(g_latency_calls == 1);
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = EINTR;
    g_errno_trigger = 1;
    g_descriptor_calls = 0;
    assert(close(5) == -1);
    assert(errno == EINTR);
    assert(g_descriptor_calls == 1);
    g_errno_trigger = 0;
    assert(close(5) == 0);

    reset_wrapper_stubs();
}

#if defined(__GLIBC__)
/**
 * @brief Proves `__read_chk()`, `__poll_chk()` and `__ppoll_chk()` (glibc _FORTIFY_SOURCE) go
 *   through the wrappers, and that a length beyond the declared object size calls the
 *   overflow handler without the real call.
 */
static void test_fortified_read_and_poll(void)
{
    struct pollfd fds[2];
    struct timespec timeout = {0, 0L};
    char buffer[8] = "xxxxxxx";

    g_chaos_net_chk_fail = chaos_net_test_chk_fail;
    (void)memset(fds, 0, sizeof(fds));
    fds[0].fd = -1;
    fds[1].fd = -1;

    reset_descriptor_stubs();
    g_chk_fail_calls = 0;
    assert(__read_chk(5, buffer, 4U, sizeof(buffer)) >= 0);
    assert(g_descriptor_calls == 1);
    assert(__read_chk(5, buffer, 4U, 2U) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_descriptor_calls == 1);

    reset_wrapper_stubs();
    g_chaos_net_real_poll = chaos_net_test_poll;
    g_chaos_net_real_ppoll = chaos_net_test_ppoll;
    g_chk_fail_calls = 0;
    (void)__poll_chk(fds, 2U, 0, sizeof(fds));
    assert(g_poll_calls == 1);
    assert(__poll_chk(fds, 2U, 0, sizeof(fds[0])) == -1);
    assert(g_chk_fail_calls == 1);
    assert(g_poll_calls == 1);

    (void)__ppoll_chk(fds, 2U, &timeout, NULL, sizeof(fds));
    assert(g_ppoll_calls == 1);
    assert(__ppoll_chk(fds, 2U, &timeout, NULL, sizeof(fds[0])) == -1);
    assert(g_chk_fail_calls == 2);
    assert(g_ppoll_calls == 1);

    g_chaos_net_chk_fail = __chk_fail;
}
#endif

/**
 * @brief Proves the `@size` byte count of a vector or message is the sum of all its iovecs,
 *   and unknown (`CHAOS_POLICY_NO_SIZE`) for NULL, a negative count, or more than
 *   `CHAOS_NET_IOV_MAX` entries, which the kernel rejects before reading them.
 */
static void test_size_of_vectors_and_messages(void)
{
    struct iovec iov[2];
    struct msghdr message;

    iov[0].iov_base = NULL;
    iov[0].iov_len = 3U;
    iov[1].iov_base = NULL;
    iov[1].iov_len = 4U;
    memset(&message, 0, sizeof(message));
    message.msg_iov = iov;
    message.msg_iovlen = 2U;
    assert(chaos_net_iovec_size(iov, 2) == 7U);
    assert(chaos_net_iovec_size(NULL, 1) == CHAOS_POLICY_NO_SIZE);
    assert(chaos_net_iovec_size(iov, -1) == CHAOS_POLICY_NO_SIZE);
    assert(chaos_net_message_size(&message) == 7U);
    assert(chaos_net_message_size(NULL) == CHAOS_POLICY_NO_SIZE);
    assert(chaos_net_iovec_size(iov, CHAOS_NET_IOV_MAX + 1) == CHAOS_POLICY_NO_SIZE);
    message.msg_iovlen = (size_t)CHAOS_NET_IOV_MAX + 1U;
    assert(chaos_net_message_size(&message) == CHAOS_POLICY_NO_SIZE);
}

/**
 * @brief Proves send(), recv(), sendmsg() and recvmsg() hand the call's byte count (9, 12,
 *   and 5 + 6 = 11) to the matched rule, so `@size` gates see it.
 */
static void test_wrappers_record_call_size(void)
{
    char buffer[16] = {0};
    long rc;
    struct iovec iov[2];
    struct msghdr message;

    iov[0].iov_base = buffer;
    iov[0].iov_len = 5U;
    iov[1].iov_base = buffer + 5;
    iov[1].iov_len = 6U;
    memset(&message, 0, sizeof(message));
    message.msg_iov = iov;
    message.msg_iovlen = 2U;

    reset_wrapper_stubs();
    g_stub_endpoint_from_peer = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_LATENCY;
    rc = send(4, buffer, 9U, 0);
    assert(g_last_call_size == 9U);
    rc = recv(4, buffer, 12U, 0);
    assert(g_last_call_size == 12U);
    rc = sendmsg(4, &message, 0);
    assert(g_last_call_size == 11U);
    rc = recvmsg(4, &message, 0);
    assert(g_last_call_size == 11U);
    (void)rc;
}

/**
 * @brief Proves TRICKLE shortens every receive form to the rule's chunk size, and leaves
 *   alone what it must not shorten.
 *
 * @details recv(), recvfrom() and read() ask for at most 3 bytes; recvmsg() and readv() pass
 * a vector of at most 3 bytes, cut inside the entry that crosses the limit (2 + 1). recvmsg()
 * runs on a copy of the caller's header: the caller's `msg_iov` and `msg_iovlen` stay as
 * given, and the kernel's `msg_flags` and `msg_namelen` are copied back. Unchanged: a request
 * already within the chunk, MSG_WAITALL (the caller asked for the whole count), a vector of
 * more than `CHAOS_NET_TRICKLE_MAX_IOV` entries, and a rule that does not fire.
 */
static void test_trickle_shortens_receives(void)
{
    char buffer[16] = {0};
    struct iovec iov[3];
    struct iovec many[CHAOS_NET_TRICKLE_MAX_IOV + 1];
    struct msghdr message;
    long rc;
    int index;

    for (index = 0; index < 3; ++index)
    {
        iov[index].iov_base = buffer + index * 4;
        iov[index].iov_len = 2U;
    }
    for (index = 0; index <= CHAOS_NET_TRICKLE_MAX_IOV; ++index)
    {
        many[index].iov_base = buffer;
        many[index].iov_len = 1U;
    }
    memset(&message, 0, sizeof(message));
    message.msg_iov = iov;
    message.msg_iovlen = 3U;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TRICKLE;
    g_stub_rule.chunk_bytes = 3U;
    g_should_trigger = 1;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_last_receive_size == 3U);
    rc = recv(4, buffer, 2U, 0);
    assert(g_last_receive_size == 2U);
    rc = recv(4, buffer, sizeof(buffer), MSG_WAITALL);
    assert(g_last_receive_size == sizeof(buffer));
    rc = recvfrom(4, buffer, sizeof(buffer), 0, NULL, NULL);
    rc = recvmsg(4, &message, 0);
    assert(g_last_receive_iovlen == 2U && g_last_receive_iov_bytes == 3U);
    assert(message.msg_iov == iov && message.msg_iovlen == 3U);
    assert(message.msg_flags == MSG_TRUNC && message.msg_namelen == 7U);
    message.msg_iov = many;
    message.msg_iovlen = CHAOS_NET_TRICKLE_MAX_IOV + 1;
    rc = recvmsg(4, &message, 0);
    assert(g_last_receive_iovlen == (size_t)CHAOS_NET_TRICKLE_MAX_IOV + 1U);
    g_should_trigger = 0;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_last_receive_size == sizeof(buffer));

    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TRICKLE;
    g_stub_rule.chunk_bytes = 3U;
    g_should_trigger = 1;
    rc = read(5, buffer, sizeof(buffer));
    assert(g_last_receive_size == 3U);
    rc = readv(5, iov, 3);
    assert(g_last_receive_iovlen == 2U && g_last_receive_iov_bytes == 3U);
    rc = readv(5, many, CHAOS_NET_TRICKLE_MAX_IOV + 1);
    assert(g_last_receive_iovlen == (size_t)CHAOS_NET_TRICKLE_MAX_IOV + 1U);
    (void)rc;
}

/**
 * @brief Proves DUP keeps each socket's last payload and delivers it once more when the rule
 *   fires, and receives for real whenever a replay could be wrong.
 *
 * @details
 * - Table: a failed mapping disables DUP (every receive real, errno untouched); losing the
 *   publication race uses the winner's table and unmaps ours.
 * - A firing DUP replays the kept bytes without a real receive, exactly once.
 * - Real receives: MSG_PEEK; MSG_WAITALL (a short kept payload would answer short); a rule
 *   that does not fire; a descriptor whose slot (`fd % 64`) another descriptor took; a
 *   descriptor now naming another socket (dup2() or a close libchaos-net did not see); an
 *   unknown socket identity; and the call after a failed receive.
 * - recvfrom() and recvmsg() replay the sender address; a payload without one replays with no
 *   name and no control data.
 * - A kept datagram replayed into a smaller buffer reports MSG_TRUNC, as the kernel does; a
 *   stream payload does not.
 * - A stream payload over `CHAOS_NET_DUP_MAX_BYTES` (4096) is kept truncated; a datagram over
 *   it is not kept, since a truncated datagram would be a different message.
 * - read() and readv() replay too; close() drops the kept payload.
 */
static void test_dup_replays_the_last_payload(void)
{
    static char big[CHAOS_NET_DUP_MAX_BYTES + 100U];
    char buffer[16];
    struct sockaddr_in from;
    socklen_t from_length;
    struct iovec iov[2];
    struct msghdr message;
    long rc;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    g_should_trigger = 1;

    g_chaos_net_dup_slots = NULL;
    g_dup_map_mode = 1;
    errno = 4242;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(errno == 4242);
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 2);

    g_dup_map_mode = 2;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_dup_unmaps == 1);
    g_dup_map_mode = 0;

    memset(buffer, 0, sizeof(buffer));
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(rc == 4 && memcmp(buffer, "data", 4U) == 0);
    assert(g_recv_calls == 3);
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 4);

    rc = recv(4, buffer, sizeof(buffer), MSG_PEEK);
    assert(g_recv_calls == 5);
    rc = recv(4, buffer, sizeof(buffer), MSG_WAITALL);
    assert(g_recv_calls == 6);
    g_recv_calls = 5;
    g_should_trigger = 0;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 6);
    g_should_trigger = 1;

    /* fd 68 shares fd 4's slot: it takes it over, and neither replays the other's payload. */
    rc = recv(4 + CHAOS_NET_DUP_SLOTS, buffer, sizeof(buffer), 0);
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 8);
    rc = recv(4 + CHAOS_NET_DUP_SLOTS, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 9);

    {
        int calls;

        do /* until a real receive has stored a payload for fd 4 */
        {
            calls = g_recv_calls;
            rc = recv(4, buffer, sizeof(buffer), 0);
        } while (g_recv_calls == calls);
        ++g_dup_socket_epoch;
        calls = g_recv_calls;
        rc = recv(4, buffer, sizeof(buffer), 0);
        assert(g_recv_calls == calls + 1);
        g_dup_socket_epoch = 0U;
        rc = recv(4, buffer, sizeof(buffer), 0);
        rc = recv(4, buffer, sizeof(buffer), 0);
        assert(g_recv_calls == calls + 3);
        g_dup_socket_epoch = 1U;
    }

    {
        const int calls = g_recv_calls;

        g_recv_result = -1;
        rc = recv(5, buffer, sizeof(buffer), 0);
        g_recv_result = 4;
        rc = recv(5, buffer, sizeof(buffer), 0);
        assert(g_recv_calls == calls + 2);
    }

    from_length = (socklen_t)sizeof(from);
    rc = recvfrom(6, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_length);
    memset(&from, 0, sizeof(from));
    from_length = (socklen_t)sizeof(from);
    rc = recvfrom(6, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_length);
    assert(rc == 4 && g_recvfrom_calls == 1);
    assert(from.sin_family == AF_INET && from_length == (socklen_t)sizeof(from));
    rc = recvfrom(6, buffer, sizeof(buffer), MSG_PEEK, NULL, NULL);
    assert(g_recvfrom_calls == 2);

    iov[0].iov_base = buffer;
    iov[0].iov_len = 2U;
    iov[1].iov_base = buffer + 2;
    iov[1].iov_len = 14U;
    memset(&message, 0, sizeof(message));
    message.msg_iov = iov;
    message.msg_iovlen = 2U;
    rc = recv(7, buffer, sizeof(buffer), 0);
    message.msg_name = &from;
    message.msg_namelen = (socklen_t)sizeof(from);
    message.msg_controllen = 9U;
    rc = recvmsg(7, &message, 0);
    assert(rc == 4 && g_recvmsg_calls == 0);
    assert(message.msg_namelen == 0 && message.msg_controllen == 0 && message.msg_flags == 0);
    rc = recvmsg(7, &message, 0);
    assert(g_recvmsg_calls == 1);
    message.msg_name = NULL;
    rc = recvmsg(7, &message, 0);
    assert(rc == 4 && g_recvmsg_calls == 1 && message.msg_namelen == 0);
    rc = recvmsg(7, &message, MSG_PEEK);
    assert(g_recvmsg_calls == 2);

    {
        struct iovec small;

        small.iov_base = buffer;
        small.iov_len = 2U;
        message.msg_iov = &small;
        message.msg_iovlen = 1U;
        g_test_socket_type = SOCK_DGRAM;
        rc = recv(12, buffer, sizeof(buffer), 0);
        rc = recvmsg(12, &message, 0);
        assert(rc == 2 && message.msg_flags == MSG_TRUNC);
        g_test_socket_type = SOCK_STREAM;
        rc = recv(13, buffer, sizeof(buffer), 0);
        rc = recvmsg(13, &message, 0);
        assert(rc == 2 && message.msg_flags == 0);
    }

    g_recv_result = (ssize_t)sizeof(big);
    rc = recv(8, big, sizeof(big), 0);
    g_recv_result = 4;
    rc = recv(8, big, sizeof(big), 0);
    assert(rc == (long)CHAOS_NET_DUP_MAX_BYTES);

    {
        const int calls = g_recv_calls;

        g_test_socket_type = SOCK_DGRAM;
        g_recv_result = (ssize_t)sizeof(big);
        rc = recv(11, big, sizeof(big), 0);
        g_recv_result = 4;
        rc = recv(11, big, sizeof(big), 0);
        assert(rc == 4 && g_recv_calls == calls + 2);
        g_test_socket_type = SOCK_STREAM;
    }

    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    g_should_trigger = 1;
    rc = read(9, buffer, sizeof(buffer));
    rc = read(9, buffer, sizeof(buffer));
    assert(rc == 4 && g_descriptor_calls == 1);
    iov[0].iov_len = 8U;
    rc = readv(9, iov, 1);
    rc = readv(9, iov, 1);
    assert(rc == 8 && g_descriptor_calls == 2);
    rc = read(9, buffer, sizeof(buffer));
    g_stub_prepare = 0;
    assert(close(9) == 0);
    g_stub_prepare = 1;
    rc = read(9, buffer, sizeof(buffer));
    assert(g_descriptor_calls == 5);
    chaos_net_dup_forget(-1);
    (void)rc;
}

/**
 * @brief Proves the TRICKLE and DUP edge cases: datagrams, short requests, busy slots, close
 *   of a colliding descriptor, and a truncated sender address.
 *
 * @details TRICKLE leaves datagram sockets alone (shortening would truncate the datagram) and
 * does not even evaluate a rule for a request within the chunk, so no hit is counted. DUP
 * never waits for a busy slot: the call receives for real and the earlier payload is replayed
 * on the next call. Closing another descriptor of the same slot keeps the payload; closing
 * its own drops it. A sender address truncated by the caller's 4-byte buffer is kept only as
 * those 4 bytes, although the kernel reported the full length.
 */
static void test_trickle_and_dup_edges(void)
{
    char buffer[16];
    char small_name[4];
    struct sockaddr_in from;
    socklen_t from_length;
    long rc;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TRICKLE;
    g_stub_rule.chunk_bytes = 3U;
    g_should_trigger = 1;
    g_test_socket_type = SOCK_DGRAM;
    rc = recv(4, buffer, sizeof(buffer), 0);
    assert(g_last_receive_size == sizeof(buffer));
    g_test_socket_type = SOCK_STREAM;
    g_should_trigger = 0; /* a short request must not consult the rule */
    rc = recv(4, buffer, 3U, 0);
    assert(g_last_receive_size == 3U);

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    g_should_trigger = 1;
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_chaos_net_dup_slots != NULL);
    g_chaos_net_dup_slots[10 % CHAOS_NET_DUP_SLOTS].lock = 1;
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 2);
    g_chaos_net_dup_slots[10 % CHAOS_NET_DUP_SLOTS].lock = 0;

    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 2);
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 3);

    chaos_net_dup_forget(10 + CHAOS_NET_DUP_SLOTS);
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 3);
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 4);
    chaos_net_dup_forget(10);
    rc = recv(10, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 5);

    g_recvfrom_reported_name = (socklen_t)sizeof(struct sockaddr_in6);
    from_length = (socklen_t)sizeof(small_name);
    rc = recvfrom(11, buffer, sizeof(buffer), 0, (struct sockaddr *)small_name, &from_length);
    assert(from_length == (socklen_t)sizeof(struct sockaddr_in6));
    g_recvfrom_reported_name = 0;
    from_length = (socklen_t)sizeof(from);
    rc = recvfrom(11, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_length);
    assert(rc == 4 && from_length == (socklen_t)sizeof(small_name));
    (void)rc;
}

/**
 * @brief Proves DUP receives for real when a payload must not be kept or replayed, never
 *   keeps a payload of a descriptor closed during the receive, and that the fork child
 *   handler releases slot locks.
 *
 * @details
 * - Always real: MSG_TRUNC, MSG_OOB, a zero-length or NULL buffer, an empty vector, and a
 *   vector longer than `CHAOS_NET_IOV_MAX`.
 * - A store whose slot generation changed since the receive began (a close in between) is
 *   discarded; the next receive's payload is kept as usual. A close between the store's
 *   generation check and its tag is caught by the re-check after tagging.
 * - Locks held by parent threads, which do not exist in the child, are released.
 */
static void test_dup_skips_and_close_races(void)
{
    char buffer[16];
    struct iovec iov;
    /* volatile: hides the deliberately invalid arguments from compile-time diagnostics. */
    void *volatile no_buffer = NULL;
    volatile int too_many = CHAOS_NET_IOV_MAX + 1;
    unsigned generation;
    long rc;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    g_should_trigger = 1;

    rc = recv(12, buffer, sizeof(buffer), MSG_TRUNC);
    rc = recv(12, buffer, sizeof(buffer), MSG_TRUNC);
    rc = recv(12, buffer, sizeof(buffer), MSG_OOB);
    rc = recv(12, buffer, 0U, 0);
    rc = recv(12, no_buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 5);
    rc = recvfrom(12, no_buffer, sizeof(buffer), 0, NULL, NULL);
    assert(g_recvfrom_calls == 1);

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    memcpy(buffer, "data", 4U);
    generation = chaos_net_dup_generation(13);
    chaos_net_dup_forget(13);
    chaos_net_dup_store(13, &iov, 1, 4, NULL, 0, generation);
    rc = recv(13, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 6);
    rc = recv(13, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 6);
    assert(chaos_net_dup_generation(-1) == 0U);

    g_dup_close_before_tag = 1;
    rc = recv(16, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 7);
    rc = recv(16, buffer, sizeof(buffer), 0);
    assert(g_recv_calls == 8);
    rc = recv(16, buffer, sizeof(buffer), 0); /* replays the previous payload */
    assert(g_recv_calls == 8);

    g_chaos_net_dup_slots[14 % CHAOS_NET_DUP_SLOTS].lock = 1;
    chaos_net_dup_after_fork();
    assert(g_chaos_net_dup_slots[14 % CHAOS_NET_DUP_SLOTS].lock == 0);

    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    g_should_trigger = 1;
    rc = readv(15, &iov, 0);
    rc = readv(15, &iov, too_many); /* kernel rejects with EINVAL */
    rc = read(15, no_buffer, sizeof(buffer));
    assert(g_descriptor_calls == 3);
    (void)rc;
}

/**
 * @brief Proves send and receive rules match either end of a connection: receives try the
 *   local end, then the peer; sends the peer, then the local end.
 *
 * @details With only the peer resolvable a recv rule applies (a client's rule naming its
 * server); with only the local end a send rule applies (a server's rule naming its own port).
 * With neither end, or no rule, the real calls run.
 */
static void test_rules_match_either_end(void)
{
    char buffer[8];

    reset_wrapper_stubs();
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNRESET;
    g_errno_trigger = 1;

    g_stub_endpoint_from_peer = 1;
    errno = 0;
    assert(recv(5, buffer, sizeof(buffer), 0) == -1 && errno == ECONNRESET);
    assert(read(5, buffer, sizeof(buffer)) == -1 && errno == ECONNRESET);
    g_stub_endpoint_from_peer = 0;

    g_stub_endpoint_from_local = 1;
    errno = 0;
    assert(send(5, "x", 1U, 0) == -1 && errno == ECONNRESET);
    assert(write(5, "x", 1U) == -1 && errno == ECONNRESET);
    g_stub_endpoint_from_local = 0;

    assert(recv(5, buffer, sizeof(buffer), 0) == g_recv_result);
    assert(send(5, "x", 1U, 0) == g_send_result);
    g_stub_match_endpoint = 0;
    g_stub_endpoint_from_peer = 1;
    assert(recv(5, buffer, sizeof(buffer), 0) == g_recv_result);
}

/**
 * @brief Proves CORRUPT touches only bytes the receive actually wrote into the buffer.
 *
 * @details With MSG_TRUNC a datagram receive returns the datagram's full length (60000) even
 * when the buffer holds 4 bytes; corruption stays within those 4 bytes (or the 8-byte vector
 * for recvmsg()), never past the caller's buffer. recvmsg() without a message corrupts
 * nothing. A stream receive with MSG_TRUNC discards the data, so nothing is corrupted and the
 * rule is not evaluated.
 */
static void test_corrupt_stays_in_the_buffer(void)
{
    char buffer[16] = "dataXXXXXXXXXXX";
    char vector_bytes[8];
    struct iovec iov;
    struct msghdr message;

    reset_wrapper_stubs();
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 1;

    g_test_socket_type = SOCK_DGRAM;
    g_recv_result = 60000;
    assert(recv(5, buffer, 4U, MSG_TRUNC) == 60000);
    assert(g_corrupt_calls == 1 && g_last_corrupt_size == 4U);
    g_recvfrom_result = 60000;
    assert(recvfrom(5, buffer, 4U, MSG_TRUNC, NULL, NULL) == 60000);
    assert(g_corrupt_calls == 2 && g_last_corrupt_size == 4U);

    iov.iov_base = vector_bytes;
    iov.iov_len = sizeof(vector_bytes);
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;
    g_recvmsg_result = 60000;
    assert(recvmsg(5, &message, MSG_TRUNC) == 60000);
    assert(g_corrupt_calls == 3 && g_last_corrupt_size == sizeof(vector_bytes));
    assert(recvmsg(5, NULL, 0) == 60000); /* no buffer to corrupt */
    assert(g_corrupt_calls == 3);

    g_test_socket_type = SOCK_STREAM;
    g_should_trigger = 0; /* the rule must not be consulted */
    assert(recv(5, buffer, 4U, MSG_TRUNC) == 60000);
    assert(recvfrom(5, buffer, 4U, MSG_TRUNC, NULL, NULL) == 60000);
    assert(recvmsg(5, &message, MSG_TRUNC) == 60000);
    assert(g_corrupt_calls == 3);
    g_recv_result = 4;
    g_recvfrom_result = 4;
    g_recvmsg_result = 4;
}

/**
 * @brief Enables every endpoint lookup and an always-firing ECONNRESET rule, so any wrapper
 *   that consults the rules fails visibly.
 */
static void arm_errno_rule_everywhere(void)
{
    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_sockaddr = 1;
    g_stub_endpoint_from_socket_spec = 1;
    g_stub_endpoint_from_activity = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_endpoint_from_peer = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_ERRNO;
    g_stub_rule.errnum = ECONNRESET;
    g_errno_trigger = 1;
}

/**
 * @brief Proves that under the TLS guard every wrapper forwards unchanged, whatever rule would
 *   match.
 *
 * @details The guard is set while the library makes its own calls (reading the rule file,
 * writing the hits file); applying rules there would recurse or fault the library itself.
 * With the always-firing rule armed, each wrapper returns the real result, each real call
 * runs once, errno stays 0, no delay is applied, and no destination address is even resolved.
 */
static void test_wrappers_forward_inside_library(void)
{
    struct sockaddr_in address;
    struct msghdr message;
    struct pollfd fds[1];
    struct timeval tv = {0, 0};
    struct timespec ts = {0, 0};
    fd_set readfds;
    char buffer[8];
    int sv[2];
#ifdef __linux__
    struct mmsghdr mmsg;
    struct epoll_event events[1];
#endif

    arm_errno_rule_everywhere();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9300U);
    (void)memset(&message, 0, sizeof(message));
    fds[0].fd = 3;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    FD_ZERO(&readfds);
    FD_SET(3, &readfds);

    g_chaos_net_tls_guard = 1;
    g_sockaddr_lookups = 0;
    errno = 0;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(listen(3, 1) == 0);
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(accept(3, NULL, NULL) == 10);
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(shutdown(3, SHUT_RDWR) == 0);
    assert(send(3, "x", 1U, 0) == 4);
    assert(
        sendto(3, "x", 1U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 4
    );
    assert(sendmsg(3, &message, 0) == 4);
    assert(recv(3, buffer, sizeof(buffer), 0) == 4);
    assert(recvfrom(3, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(recvmsg(3, &message, 0) == 4);
    assert(poll(fds, 1U, 0) == 0);
    assert(ppoll(fds, 1U, &ts, NULL) == 0);
    assert(select(4, &readfds, NULL, NULL, &tv) == 0);
    assert(pselect(4, &readfds, NULL, NULL, &ts, NULL) == 0);
#ifdef __linux__
    assert(accept4(3, NULL, NULL, 0) == 10);
    (void)memset(&mmsg, 0, sizeof(mmsg));
    assert(sendmmsg(3, &mmsg, 1U, 0) == 1);
    assert(recvmmsg(3, &mmsg, 1U, 0, NULL) == 1);
    assert(epoll_wait(3, events, 1, 0) == 1);
    assert(epoll_pwait(3, events, 1, 0, NULL) == 1);
#endif
    g_chaos_net_tls_guard = 0;

    assert(errno == 0);
    assert(g_bind_calls == 1 && g_listen_calls == 1 && g_connect_calls == 1);
    assert(g_socket_calls == 1 && g_socketpair_calls == 1 && g_shutdown_calls == 1);
    assert(g_send_calls == 1 && g_sendto_calls == 1 && g_sendmsg_calls == 1);
    assert(g_recv_calls == 1 && g_recvfrom_calls == 1 && g_recvmsg_calls == 1);
    assert(g_poll_calls == 1 && g_ppoll_calls == 1);
    assert(g_select_calls == 1 && g_pselect_calls == 1);
#ifdef __linux__
    assert(g_accept_calls == 2);
    assert(g_sendmmsg_calls == 1 && g_recvmmsg_calls == 1);
    assert(g_epoll_wait_calls == 1 && g_epoll_pwait_calls == 1);
#else
    assert(g_accept_calls == 1);
#endif
    assert(g_latency_calls == 0);
    assert(g_sockaddr_lookups == 0);
    reset_wrapper_stubs();
}

/**
 * @brief Proves a resolvable endpoint that matches no rule is forwarded, and a connection is
 *   matched on its other end when the first matches nothing.
 *
 * @details
 * - With the match stub missing every call, every wrapper forwards, including sendto(),
 *   sendmsg() and sendmmsg() with an explicit destination, and close().
 * - A destination whose endpoint cannot be resolved is forwarded; sendmsg() without a header
 *   falls back to the connection's endpoints and the rule applies.
 * - recv() matches its peer after its local end misses, send() its local end after its peer;
 *   with both missing the real calls run.
 */
static void test_unmatched_endpoints_are_forwarded(void)
{
    struct sockaddr_in address;
    struct msghdr message;
    char buffer[8];
    int sv[2];
#ifdef __linux__
    struct mmsghdr mmsg;
#endif

    arm_errno_rule_everywhere();
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 9301U);
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    g_stub_match_misses = 1000;

    errno = 0;
    assert(bind(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(listen(3, 1) == 0);
    assert(connect(3, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 0);
    assert(accept(3, NULL, NULL) == 10);
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    assert(shutdown(3, SHUT_RDWR) == 0);
    assert(
        sendto(3, "x", 1U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 4
    );
    assert(sendmsg(3, &message, 0) == 4);
    assert(close(3) == 0);
#ifdef __linux__
    assert(accept4(3, NULL, NULL, 0) == 10);
    (void)memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg_hdr.msg_name = &address;
    mmsg.msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    assert(sendmmsg(3, &mmsg, 1U, 0) == 1);
    assert(g_sendmmsg_calls == 1);
#endif
    assert(errno == 0);
    assert(g_bind_calls == 1 && g_listen_calls == 1 && g_connect_calls == 1);
    assert(g_socket_calls == 1 && g_socketpair_calls == 1 && g_shutdown_calls == 1);
    assert(g_sendto_calls == 1 && g_sendmsg_calls == 1 && g_descriptor_calls == 1);

    g_stub_match_misses = 0;
    g_stub_endpoint_from_sockaddr = 0;
    assert(
        sendto(3, "x", 1U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) == 4
    );
    assert(sendmsg(3, &message, 0) == 4);
#ifdef __linux__
    assert(sendmmsg(3, &mmsg, 1U, 0) == 1);
    assert(g_sendmmsg_calls == 2);
#endif
    assert(g_sendto_calls == 2 && g_sendmsg_calls == 2);
    assert(errno == 0);

    errno = 0;
    assert(sendmsg(3, NULL, 0) == -1 && errno == ECONNRESET);
    assert(g_sendmsg_calls == 2);

    g_stub_match_misses = 1;
    assert(recv(3, buffer, sizeof(buffer), 0) == -1 && errno == ECONNRESET);
    g_stub_match_misses = 1;
    errno = 0;
    assert(send(3, "x", 1U, 0) == -1 && errno == ECONNRESET);
    g_stub_match_misses = 2;
    errno = 0;
    assert(recv(3, buffer, sizeof(buffer), 0) == 4);
    g_stub_match_misses = 2;
    assert(send(3, "x", 1U, 0) == 4);
    assert(errno == 0);
    assert(g_recv_calls == 1 && g_send_calls == 1);
    reset_wrapper_stubs();
}

/**
 * @brief Proves a matched rule that does not fire leaves the call exactly as the real
 *   function returned it.
 *
 * @details ERRNO not firing: the real receive's result and data are returned and errno stays
 * 0; the pre-call helpers report nothing. CORRUPT not firing: every receive form returns the
 * bytes as received. A failed (-1) or empty (0) recvmmsg() batch is not corrupted and the
 * rule is not evaluated, even when it would fire. TIMEOUT not firing: the real poll() runs.
 * A firing TIMEOUT with a NULL flag pointer still returns 0, and LATENCY ignores the flag.
 */
static void test_rules_that_do_not_fire(void)
{
    char buffer[8];
    struct iovec iov;
    struct msghdr message;
    struct pollfd fds[1];
    chaos_net_rule_t rule;
    int synthetic_timeout = -1;
#ifdef __linux__
    struct mmsghdr mmsg;
    char mmsg_bytes[8];
    struct iovec mmsg_iov;
#endif

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1U;

    arm_errno_rule_everywhere();
    g_errno_trigger = 0;
    errno = 0;
    (void)memset(buffer, 0, sizeof(buffer));
    assert(recv(3, buffer, sizeof(buffer), 0) == 4 && memcmp(buffer, "data", 4U) == 0);
    (void)memset(buffer, 0, sizeof(buffer));
    assert(recvfrom(3, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(memcmp(buffer, "data", 4U) == 0);
    (void)memset(buffer, 0, sizeof(buffer));
    assert(recvmsg(3, &message, 0) == 4 && memcmp(buffer, "data", 4U) == 0);
    assert(socket(AF_INET, SOCK_STREAM, 0) == 8);
    assert(errno == 0);
    rule = g_stub_rule;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    assert(chaos_net_wait_pre_call(&rule, 0, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0 && errno == 0);

    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    g_should_trigger = 0;
    (void)memset(buffer, 0, sizeof(buffer));
    assert(recv(3, buffer, sizeof(buffer), 0) == 4 && memcmp(buffer, "data", 4U) == 0);
    assert(recvfrom(3, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(memcmp(buffer, "data", 4U) == 0);
    assert(recvmsg(3, &message, 0) == 4 && memcmp(buffer, "data", 4U) == 0);
    assert(read(3, buffer, sizeof(buffer)) == 4 && memcmp(buffer, "data", 4U) == 0);
    assert(readv(3, &iov, 1) == (ssize_t)sizeof(buffer));
#ifdef __linux__
    mmsg_iov.iov_base = mmsg_bytes;
    mmsg_iov.iov_len = sizeof(mmsg_bytes);
    (void)memset(&mmsg, 0, sizeof(mmsg));
    mmsg.msg_hdr.msg_iov = &mmsg_iov;
    mmsg.msg_hdr.msg_iovlen = 1U;
    assert(recvmmsg(3, &mmsg, 1U, 0, NULL) == 1);
    assert(memcmp(mmsg_bytes, "data", 4U) == 0);
    g_should_trigger = 1;
    g_recvmmsg_result = -1;
    assert(recvmmsg(3, &mmsg, 1U, 0, NULL) == -1);
    g_recvmmsg_result = 0;
    assert(recvmmsg(3, &mmsg, 1U, 0, NULL) == 0);
    g_should_trigger = 0;
#endif
    assert(g_corrupt_calls == 0);

    g_stub_rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    fds[0].fd = 3;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    g_poll_result = 1;
    assert(poll(fds, 1U, 0) == 1);
    assert(g_poll_calls == 1);

    g_should_trigger = 1;
    rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    assert(chaos_net_wait_pre_call(&rule, 0, NULL) == 0);
    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(chaos_net_wait_pre_call(&rule, 0, NULL) == 0);
    assert(g_latency_calls == 1);
    reset_wrapper_stubs();
}

/**
 * @brief Proves select() finds a rule through whichever fd set names the descriptor, and the
 *   wait wrappers forward when no watched descriptor matches or no rules are loaded.
 *
 * @details A socket watched only for exceptions, or only for writes, still gets its rule.
 * pollfd entries with fd -1 are skipped. A negative `tv_nsec` is invalid and counts as "no
 * timeout", leaving the error to the real call. Clearing fd sets skips NULL sets.
 */
static void test_wait_sets_and_unmatched_descriptors(void)
{
    struct pollfd fds[2];
    struct timespec ts;
    fd_set exceptfds;
    fd_set writefds;
    chaos_net_rule_t rule;

    arm_errno_rule_everywhere();
    FD_ZERO(&exceptfds);
    FD_SET(3, &exceptfds);
    errno = 0;
    assert(select(4, NULL, NULL, &exceptfds, NULL) == -1 && errno == ECONNRESET);
    FD_ZERO(&writefds);
    FD_SET(3, &writefds);
    errno = 0;
    assert(select(4, NULL, &writefds, NULL, NULL) == -1 && errno == ECONNRESET);
    assert(g_select_calls == 0);

    g_stub_match_endpoint = 0;
    fds[0].fd = -1;
    fds[0].events = POLLIN;
    fds[1].fd = 3;
    fds[1].events = POLLIN;
    assert(poll(fds, 2U, 0) == 0);
    assert(!chaos_net_wait_match_pollfds(fds, 2U, &rule));
    assert(!chaos_net_wait_match_fd_loaded(3, &rule));
    assert(select(4, NULL, NULL, &exceptfds, NULL) == 0);
    g_stub_prepare = 0;
    assert(!chaos_net_wait_match_pollfds(fds, 2U, &rule));
    assert(!chaos_net_wait_match_fdsets(4, NULL, NULL, &exceptfds, &rule));
    assert(poll(fds, 2U, 0) == 0);
    assert(g_poll_calls == 2 && g_select_calls == 1);
    assert(errno == ECONNRESET);

    ts.tv_sec = 1;
    ts.tv_nsec = -1L;
    assert(chaos_net_wait_timespec_ms(&ts) == -1);
    FD_ZERO(&writefds);
    FD_SET(4, &writefds);
    chaos_net_wait_clear_fdsets(NULL, &writefds, NULL);
    assert(!FD_ISSET(4, &writefds));
    reset_wrapper_stubs();
}

/** @brief Fake real readv() that accepts a NULL vector and reads nothing. */
static ssize_t chaos_net_test_empty_readv(int fd, const struct iovec *iov, int iovcnt)
{
    (void)fd;
    (void)iov;
    ++g_descriptor_calls;
    g_last_receive_iovlen = (size_t)iovcnt;
    return 0;
}

/**
 * @brief Proves the receive helpers stay within the bytes a call delivered, skip empty iovec
 *   entries, and keep and replay DUP payloads across any vector shape.
 *
 * @details
 * - CORRUPT across a vector skips a leading empty entry; nothing is corrupted for a zero
 *   count or zero bytes. recvmmsg() corruption skips messages with no length, no vector, no
 *   entries, or only empty entries.
 * - A datagram received with MSG_TRUNC counts at most its buffer; errors and 0 count nothing.
 * - TRICKLE does not apply to a receive of unknown size; a limit beyond the vector keeps every
 *   entry whole.
 * - DUP keeps a payload received through an empty first entry and replays it across buffers
 *   of 2 + 2 bytes, leaving the fourth untouched. A sender address longer than
 *   `sockaddr_storage` is not kept (length 0); a replay with an address buffer but no length
 *   leaves the address alone; recvfrom() and recvmsg() without an address keep and replay.
 * - CORRUPT on a vector over `CHAOS_NET_IOV_MAX` (unknown size) corrupts nothing.
 * - readv() with TRICKLE and a NULL vector is forwarded as given.
 * - Forgetting a descriptor before the DUP table exists is a no-op.
 */
static void test_receive_helpers_and_vector_shapes(void)
{
    static struct iovec too_many[CHAOS_NET_IOV_MAX + 1];
    char first[4] = "aaa";
    char second[8] = "data";
    char third[8];
    char name[sizeof(struct sockaddr_storage) + 1U];
    struct sockaddr_in from;
    socklen_t from_length;
    struct iovec iov[4];
    struct iovec limited[3];
    struct msghdr message;
    socklen_t name_length;
    chaos_net_rule_t rule;
    unsigned generation;
    char buffer[16];
#ifdef __linux__
    struct mmsghdr mmsg[1];
#endif

    reset_wrapper_stubs();
    iov[0].iov_base = first;
    iov[0].iov_len = 0U;
    iov[1].iov_base = second;
    iov[1].iov_len = 4U;
    chaos_net_corrupt_iovecs(iov, 0, 4U);
    chaos_net_corrupt_iovecs(iov, 2, 0U);
    assert(g_corrupt_calls == 0);
    chaos_net_corrupt_iovecs(iov, 2, 4U);
    assert(g_corrupt_calls == 1 && g_last_corrupt_size == 4U);
    assert(memcmp(second, "data", 4U) != 0 && strcmp(first, "aaa") == 0);

#ifdef __linux__
    (void)memcpy(second, "data", 4U);
    (void)memset(mmsg, 0, sizeof(mmsg));
    chaos_net_corrupt_mmsghdrs(mmsg, 0U);
    chaos_net_corrupt_mmsghdrs(mmsg, 1U); /* msg_len 0: skipped */
    mmsg[0].msg_len = 4U;
    chaos_net_corrupt_mmsghdrs(mmsg, 1U); /* no vector: skipped */
    mmsg[0].msg_hdr.msg_iov = iov;
    chaos_net_corrupt_mmsghdrs(mmsg, 1U); /* msg_iovlen 0: skipped */
    mmsg[0].msg_hdr.msg_iovlen = 1U;
    chaos_net_corrupt_mmsghdrs(mmsg, 1U); /* only an empty entry: skipped */
    assert(g_corrupt_calls == 1);
    mmsg[0].msg_hdr.msg_iovlen = 2U;
    chaos_net_corrupt_mmsghdrs(mmsg, 1U);
    assert(g_corrupt_calls == 2 && g_last_corrupt_size == 4U);
    assert(memcmp(second, "data", 4U) != 0);
#endif

    g_test_socket_type = SOCK_DGRAM;
    assert(chaos_net_received_bytes(3, 60000, 4U, MSG_TRUNC) == 4U);
    assert(chaos_net_received_bytes(3, 3, 4U, MSG_TRUNC) == 3U);
    assert(chaos_net_received_bytes(3, -1, 4U, 0) == 0U);
    assert(chaos_net_received_bytes(3, 0, 4U, 0) == 0U);
    g_test_socket_type = SOCK_STREAM;

    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_NET_EFFECT_TRICKLE;
    rule.chunk_bytes = 2U;
    g_should_trigger = 1;
    assert(chaos_net_trickles(&rule, 3, 16U, 0));
    assert(!chaos_net_trickles(&rule, 3, CHAOS_POLICY_NO_SIZE, 0));
    iov[0].iov_len = 3U;
    iov[1].iov_len = 4U;
    assert(chaos_net_limit_iovecs(iov, 2, 100U, limited) == 2);
    assert(limited[0].iov_len == 3U && limited[1].iov_len == 4U);

    (void)memcpy(second, "data", 4U);
    iov[0].iov_len = 0U;
    iov[1].iov_len = sizeof(second);
    iov[2].iov_base = third;
    iov[2].iov_len = sizeof(third);
    generation = chaos_net_dup_generation(30);
    (void)memset(name, 0, sizeof(name));
    chaos_net_dup_store(
        30, iov, 3, 4, (const struct sockaddr *)name, (socklen_t)sizeof(name), generation
    );
    iov[0].iov_base = first;
    iov[0].iov_len = 0U;
    iov[1].iov_base = buffer;
    iov[1].iov_len = 2U;
    iov[2].iov_base = third;
    iov[2].iov_len = 2U;
    iov[3].iov_base = first;
    iov[3].iov_len = sizeof(first);
    (void)memset(buffer, 0, sizeof(buffer));
    (void)memset(third, 0, sizeof(third));
    name_length = (socklen_t)sizeof(name);
    assert(
        chaos_net_dup_replay(&rule, 30, iov, 4, (struct sockaddr *)name, &name_length, NULL) == 4
    );
    assert(memcmp(buffer, "da", 2U) == 0 && memcmp(third, "ta", 2U) == 0);
    assert(strcmp(first, "aaa") == 0); /* payload ended before buffer 4 */
    assert(chaos_net_dup_replay(&rule, -1, iov, 4, NULL, NULL, NULL) == -1);
    assert(name_length == 0); /* address too long to keep */

    iov[1].iov_len = sizeof(buffer);
    generation = chaos_net_dup_generation(31);
    chaos_net_dup_store(31, &iov[1], 1, 4, NULL, 0, generation);
    assert(chaos_net_dup_replay(&rule, 31, &iov[1], 1, (struct sockaddr *)name, NULL, NULL) == 4);

    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_DUP;
    assert(recvfrom(32, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    (void)memset(buffer, 0, sizeof(buffer));
    assert(recvfrom(32, buffer, sizeof(buffer), 0, NULL, NULL) == 4);
    assert(memcmp(buffer, "data", 4U) == 0 && g_recvfrom_calls == 1);
    (void)memset(&from, 0, sizeof(from));
    assert(recvfrom(35, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, NULL) == 4);
    assert(recvfrom(35, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, NULL) == 4);
    assert(g_recvfrom_calls == 2 && from.sin_family == 0);
    from_length = (socklen_t)sizeof(from);
    assert(recvfrom(35, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_length) == 4);
    assert(g_recvfrom_calls == 3);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov[1];
    message.msg_iovlen = 1U;
    assert(recvmsg(33, &message, 0) == 4);
    assert(recvmsg(33, &message, 0) == 4);
    assert(g_recvmsg_calls == 1 && message.msg_namelen == 0);

    g_stub_rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    too_many[0].iov_base = buffer;
    too_many[0].iov_len = sizeof(buffer);
    message.msg_iov = too_many;
    message.msg_iovlen = CHAOS_NET_IOV_MAX + 1;
    g_corrupt_calls = 0;
    assert(recvmsg(33, &message, 0) == 4);
    assert(g_corrupt_calls == 0);

    reset_descriptor_stubs();
    g_stub_prepare = 1;
    g_stub_endpoint_from_local = 1;
    g_stub_match_endpoint = 1;
    g_stub_rule.effect = CHAOS_NET_EFFECT_TRICKLE;
    g_stub_rule.chunk_bytes = 1U;
    g_should_trigger = 1;
    g_chaos_net_real_readv = chaos_net_test_empty_readv;
    assert(readv(34, NULL, 0) == 0);
    assert(g_descriptor_calls == 1 && g_last_receive_iovlen == 0U);

    {
        chaos_net_dup_slot_t *const table = g_chaos_net_dup_slots;

        g_chaos_net_dup_slots = NULL;
        chaos_net_dup_forget(30);
        g_chaos_net_dup_slots = table;
    }
    reset_wrapper_stubs();
}

#ifdef __linux__
/** @brief CLOCK_MONOTONIC in ms, to check that a real wait really waited. */
static long long unresolved_now_ms(void)
{
    struct timespec now;

    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (long long)now.tv_sec * 1000LL + (long long)(now.tv_nsec / 1000000L);
}

/**
 * @brief Proves that with every real-function pointer NULL (a call before symbol resolution
 *   finished) each `chaos_net_call_real_*()` forwarder reaches the kernel through a raw
 *   syscall instead of calling through NULL (Linux).
 *
 * @details Everything runs on real descriptors so the kernel's behaviour is observed, not
 * assumed: stream I/O over a socketpair (send/recv, sendto/recvfrom, read/write,
 * readv/writev, sendmsg/recvmsg); poll() and select() with a 20 ms timeout really wait at
 * least 15 ms and select() leaves 0 remaining time; ppoll() and pselect() leave their
 * timespec unchanged; epoll_wait() and epoll_pwait() report readiness; shutdown(SHUT_WR)
 * gives the peer EOF; a second close() fails with EBADF; sendmmsg()/recvmmsg() move two
 * datagrams; and a loopback TCP listener accepts through accept() and accept4(), with
 * setsockopt(SO_LINGER) verified through getsockopt().
 */
static void test_unresolved_symbols_reach_the_kernel(void)
{
    struct sockaddr_in address;
    socklen_t address_length;
    struct linger linger;
    socklen_t linger_length;
    struct pollfd watched;
    struct timespec ts;
    struct timeval tv;
    fd_set readable;
    sigset_t mask;
    struct epoll_event event;
    struct epoll_event events[1];
    struct iovec iov[2];
    struct msghdr message;
    struct mmsghdr messages[2];
    struct iovec message_iov[2];
    char one[2] = {'p', 'q'};
    char two[2] = {'r', 's'};
    char buffer[8];
    char other[8];
    long long started;
    int pair[2];
    int datagrams[2];
    int listener;
    int client;
    int second_client;
    int accepted;
    int accepted4;
    int epfd;

    reset_wrapper_stubs();
    chaos_net_test_reset_runtime();
    g_chaos_net_real_setsockopt = NULL;
    g_chaos_net_real_read = NULL;
    g_chaos_net_real_write = NULL;
    g_chaos_net_real_readv = NULL;
    g_chaos_net_real_writev = NULL;
    g_chaos_net_real_close = NULL;

    assert(chaos_net_call_real_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(chaos_net_call_real_send(pair[0], "ab", 2U, 0) == 2);
    (void)memset(buffer, 0, sizeof(buffer));
    assert(chaos_net_call_real_recv(pair[1], buffer, sizeof(buffer), 0) == 2);
    assert(memcmp(buffer, "ab", 2U) == 0);
    assert(chaos_net_call_real_sendto(pair[0], "c", 1U, 0, NULL, 0) == 1);
    assert(chaos_net_call_real_recvfrom(pair[1], buffer, sizeof(buffer), 0, NULL, NULL) == 1);
    assert(buffer[0] == 'c');
    assert(chaos_net_call_real_write(pair[0], "de", 2U) == 2);
    assert(chaos_net_call_real_read(pair[1], buffer, sizeof(buffer)) == 2);
    assert(memcmp(buffer, "de", 2U) == 0);
    iov[0].iov_base = one;
    iov[0].iov_len = sizeof(one);
    iov[1].iov_base = two;
    iov[1].iov_len = sizeof(two);
    assert(chaos_net_call_real_writev(pair[0], iov, 2) == 4);
    (void)memset(buffer, 0, sizeof(buffer));
    (void)memset(other, 0, sizeof(other));
    iov[0].iov_base = buffer;
    iov[0].iov_len = 1U;
    iov[1].iov_base = other;
    iov[1].iov_len = 3U;
    assert(chaos_net_call_real_readv(pair[1], iov, 2) == 4);
    assert(buffer[0] == 'p' && memcmp(other, "qrs", 3U) == 0);
    iov[0].iov_base = one;
    iov[0].iov_len = sizeof(one);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = iov;
    message.msg_iovlen = 1U;
    assert(chaos_net_call_real_sendmsg(pair[0], &message, 0) == 2);
    iov[0].iov_base = buffer;
    iov[0].iov_len = sizeof(buffer);
    assert(chaos_net_call_real_recvmsg(pair[1], &message, 0) == 2);
    assert(memcmp(buffer, "pq", 2U) == 0);

    watched.fd = pair[1];
    watched.events = POLLIN;
    watched.revents = 0;
    started = unresolved_now_ms();
    assert(chaos_net_call_real_poll(&watched, 1U, 20) == 0);
    assert(unresolved_now_ms() - started >= 15);
    FD_ZERO(&readable);
    FD_SET(pair[1], &readable);
    tv.tv_sec = 0;
    tv.tv_usec = 20000;
    started = unresolved_now_ms();
    assert(chaos_net_call_real_select(pair[1] + 1, &readable, NULL, NULL, &tv) == 0);
    assert(unresolved_now_ms() - started >= 15);
    assert(tv.tv_sec == 0 && tv.tv_usec == 0);
    assert(chaos_net_call_real_send(pair[0], "x", 1U, 0) == 1);
    assert(chaos_net_call_real_poll(&watched, 1U, -1) == 1);
    assert(watched.revents == POLLIN);
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    watched.revents = 0;
    assert(chaos_net_call_real_ppoll(&watched, 1U, &ts, NULL) == 1);
    assert(watched.revents == POLLIN && ts.tv_sec == 1 && ts.tv_nsec == 0);
    watched.revents = 0;
    assert(chaos_net_call_real_ppoll(&watched, 1U, NULL, NULL) == 1);
    FD_ZERO(&readable);
    FD_SET(pair[1], &readable);
    assert(chaos_net_call_real_select(pair[1] + 1, &readable, NULL, NULL, NULL) == 1);
    assert(FD_ISSET(pair[1], &readable));
    FD_ZERO(&readable);
    FD_SET(pair[1], &readable);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    assert(chaos_net_call_real_select(pair[1] + 1, &readable, NULL, NULL, &tv) == 1);
    FD_ZERO(&readable);
    FD_SET(pair[1], &readable);
    (void)sigemptyset(&mask);
    assert(chaos_net_call_real_pselect(pair[1] + 1, &readable, NULL, NULL, &ts, &mask) == 1);
    assert(FD_ISSET(pair[1], &readable) && ts.tv_sec == 1 && ts.tv_nsec == 0);
    FD_ZERO(&readable);
    FD_SET(pair[1], &readable);
    assert(chaos_net_call_real_pselect(pair[1] + 1, &readable, NULL, NULL, NULL, NULL) == 1);
    epfd = (int)syscall(SYS_epoll_create1, 0);
    assert(epfd >= 0);
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = pair[1];
    assert(syscall(SYS_epoll_ctl, epfd, EPOLL_CTL_ADD, pair[1], &event) == 0);
    assert(chaos_net_call_real_epoll_wait(epfd, events, 1, 1000) == 1);
    assert(events[0].data.fd == pair[1]);
    assert(chaos_net_call_real_epoll_pwait(epfd, events, 1, 1000, &mask) == 1);
    assert(chaos_net_call_real_close(epfd) == 0);

    assert(chaos_net_call_real_recv(pair[1], buffer, sizeof(buffer), 0) == 1);
    assert(chaos_net_call_real_shutdown(pair[0], SHUT_WR) == 0);
    assert(chaos_net_call_real_recv(pair[1], buffer, sizeof(buffer), 0) == 0);
    assert(chaos_net_call_real_close(pair[0]) == 0);
    assert(chaos_net_call_real_close(pair[1]) == 0);
    errno = 0;
    assert(chaos_net_call_real_close(pair[1]) == -1 && errno == EBADF);

    assert(chaos_net_call_real_socketpair(AF_UNIX, SOCK_DGRAM, 0, datagrams) == 0);
    (void)memset(messages, 0, sizeof(messages));
    message_iov[0].iov_base = one;
    message_iov[0].iov_len = sizeof(one);
    message_iov[1].iov_base = two;
    message_iov[1].iov_len = sizeof(two);
    messages[0].msg_hdr.msg_iov = &message_iov[0];
    messages[0].msg_hdr.msg_iovlen = 1U;
    messages[1].msg_hdr.msg_iov = &message_iov[1];
    messages[1].msg_hdr.msg_iovlen = 1U;
    assert(chaos_net_call_real_sendmmsg(datagrams[0], messages, 2U, 0U) == 2);
    (void)memset(buffer, 0, sizeof(buffer));
    (void)memset(other, 0, sizeof(other));
    message_iov[0].iov_base = buffer;
    message_iov[0].iov_len = sizeof(buffer);
    message_iov[1].iov_base = other;
    message_iov[1].iov_len = sizeof(other);
    assert(chaos_net_call_real_recvmmsg(datagrams[1], messages, 2U, 0U, NULL) == 2);
    assert(memcmp(buffer, "pq", 2U) == 0 && memcmp(other, "rs", 2U) == 0);
    assert(chaos_net_call_real_close(datagrams[0]) == 0);
    assert(chaos_net_call_real_close(datagrams[1]) == 0);

    listener = chaos_net_call_real_socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    chaos_net_test_set_ipv4(&address, "127.0.0.1", 0U);
    assert(chaos_net_call_real_bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(chaos_net_call_real_listen(listener, 4) == 0);
    address_length = (socklen_t)sizeof(address);
    assert(syscall(SYS_getsockname, listener, (struct sockaddr *)&address, &address_length) == 0);
    client = chaos_net_call_real_socket(AF_INET, SOCK_STREAM, 0);
    second_client = chaos_net_call_real_socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0 && second_client >= 0);
    assert(chaos_net_call_real_connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(
        chaos_net_call_real_connect(second_client, (struct sockaddr *)&address, sizeof(address)) ==
        0
    );
    accepted = chaos_net_call_real_accept(listener, NULL, NULL);
    assert(accepted >= 0);
    accepted4 = chaos_net_call_real_accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    assert(accepted4 >= 0);
    assert(chaos_net_call_real_send(client, "z", 1U, 0) == 1);
    assert(chaos_net_call_real_recv(accepted, buffer, sizeof(buffer), 0) == 1 && buffer[0] == 'z');
    linger.l_onoff = 1;
    linger.l_linger = 0;
    assert(
        chaos_net_call_real_setsockopt(
            client, SOL_SOCKET, SO_LINGER, &linger, (socklen_t)sizeof(linger)
        ) == 0
    );
    (void)memset(&linger, 0, sizeof(linger));
    linger_length = (socklen_t)sizeof(linger);
    assert(syscall(SYS_getsockopt, client, SOL_SOCKET, SO_LINGER, &linger, &linger_length) == 0);
    assert(linger.l_onoff != 0 && linger.l_linger == 0);
    assert(chaos_net_call_real_close(accepted4) == 0);
    assert(chaos_net_call_real_close(accepted) == 0);
    assert(chaos_net_call_real_close(second_client) == 0);
    assert(chaos_net_call_real_close(client) == 0);
    assert(chaos_net_call_real_close(listener) == 0);

    reset_wrapper_stubs();
}
#endif

int main(void)
{
    test_wrappers_forward_inside_library();
    test_unmatched_endpoints_are_forwarded();
    test_rules_that_do_not_fire();
    test_wait_sets_and_unmatched_descriptors();
    test_receive_helpers_and_vector_shapes();
    test_corrupt_stays_in_the_buffer();
    test_rules_match_either_end();
    test_dup_skips_and_close_races();
    test_trickle_and_dup_edges();
    test_dup_replays_the_last_payload();
    test_trickle_shortens_receives();
    test_wrappers_record_call_size();
    test_size_of_vectors_and_messages();
    test_bind_and_connect_paths();
    test_accept_and_send_paths();
    test_recv_paths();
    test_descriptor_calls_on_sockets();
#if defined(__GLIBC__)
    test_fortified_receive();
    test_fortified_read_and_poll();
#endif
    test_socket_and_shutdown_paths();
    test_wait_paths();
    test_direct_helper_paths();
    test_wrapper_passthrough_and_additional_branches();
#ifdef __linux__
    test_batch_paths();
    test_direct_linux_helper_paths();
    test_epoll_wrapper_paths();
    test_epoll_fdinfo_in_pieces();
    test_unresolved_symbols_reach_the_kernel();
#endif
    return 0;
}
