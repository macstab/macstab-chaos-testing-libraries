/**
 * @file test_chaos_net.c
 * @brief Integration-style unit tests for all NET-domain wrapper call paths.
 *
 * Subsystem under test: `src/net/chaos_net_socket.c`, `src/net/chaos_net_extra.c`,
 *   and `src/net/chaos_net_wait.c`.
 *
 * Coverage approach:
 * - All three production source files are included directly. Endpoint resolution,
 *   config matching, action helpers (latency, errno, corrupt, should_trigger), and
 *   the real-function-pointer globals are replaced with test-local stubs declared in
 *   this file. This allows each test to exercise a specific effect path without LD_PRELOAD.
 * - On Linux the wait path reads `/proc/<pid>/fd/<fd>` to resolve FD paths. The
 *   `open`, `read`, `close`, and `snprintf` symbols inside `chaos_net_wait.c` are
 *   overridden via `#define` before inclusion so that fake-FD injection and all
 *   failure modes are exercised without touching the real filesystem.
 * - `CHAOS_NET_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals.
 * - `reset_wrapper_stubs()` resets all state between sub-tests.
 *
 * Properties under test (portable):
 * - `bind`: passthrough; ERRNO injection returns -1 with errno set; LATENCY calls latency stub.
 * - `listen`: passthrough; ERRNO + LATENCY paths; endpoint resolved via `from_local_fd`.
 * - `accept` / `accept4` (Linux): passthrough; ERRNO injection; LATENCY; ERRNO=EINTR.
 * - `send` / `sendto` / `sendmsg`: passthrough; ERRNO; LATENCY; endpoint via `from_peer_fd` /
 *   `from_sockaddr_fd`.
 * - `recv` / `recvfrom` / `recvmsg`: passthrough; ERRNO; LATENCY; CORRUPT (corrupt stub
 *   increments `g_corrupt_calls` and actually flips byte[0] so assert `buffer[0] != 'd'`).
 * - `socket` / `socketpair`: passthrough; ERRNO; LATENCY; TLS guard bypass.
 * - `shutdown`: passthrough; ERRNO; LATENCY; endpoint via `from_activity_fd`.
 * - `poll` / `ppoll` / `select` / `pselect`: TIMEOUT clears revents/fd-sets and bypasses real
 *   call; ERRNO; LATENCY; passthrough.
 * - Direct helper functions: `chaos_net_apply_pre_call_rule`, `chaos_net_apply_simple_pre_call_rule`,
 *   `chaos_net_wait_pre_call`, `chaos_net_wait_clear_pollfds`, `chaos_net_wait_clear_fdsets`,
 *   all `chaos_net_call_real_*` wrappers, `chaos_net_corrupt_iovecs`,
 *   `chaos_net_wait_match_pollfds`, `chaos_net_wait_match_fdsets`.
 * - Passthrough and additional branches: connect ERRNO=ECONNREFUSED; send ERRNO=EPIPE;
 *   sendmsg ERRNO=EHOSTUNREACH; TLS guard on `socket`.
 *
 * Properties under test (Linux-only):
 * - `sendmmsg`: ERRNO=EHOSTUNREACH; LATENCY; passthrough.
 * - `recvmmsg`: CORRUPT (buffer verified modified); ERRNO=EAGAIN; passthrough; TLS guard bypass.
 * - `epoll_wait` / `epoll_pwait`: real epoll instance with pipe; TIMEOUT zeroes event count;
 *   ERRNO; LATENCY; passthrough.
 * - `chaos_net_corrupt_mmsghdrs`: NULL guard; single mmsg with 2 iovecs; corrupt_calls verified.
 * - `chaos_net_wait_match_epoll`: snprintf-fail path; invalid epfd; read-fail; fill-buffer
 *   overflow; real epfd with endpoint match.
 *
 * What is NOT tested here:
 * - Config file loading, rule persistence, or mtime-based reload.
 * - Constructor symbol resolution or PRNG seeding.
 */

#include "../support/test_net_support.h"

#include <fcntl.h>
#include <stdarg.h>
#include "../../src/net/chaos_net_config.h"
#include "../../src/net/chaos_net_actions.h"
#include "../../src/net/chaos_net_endpoint.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

/**
 * @brief Rule returned by the config-match stub when `g_stub_match_endpoint != 0`.
 *
 * Tests set `g_stub_rule.effect` and `g_stub_rule.errnum` before calling a wrapper
 * to control which effect path is exercised.
 */
static chaos_net_rule_t g_stub_rule;

/** @brief Endpoint returned by all endpoint-resolution stubs when their flag is non-zero. */
static chaos_net_endpoint_t g_stub_endpoint;

/**
 * @brief Return value for `chaos_net_config_prepare()`.
 *
 * When 0 the wrapper bypasses matching entirely; when 1 matching proceeds.
 */
static int g_stub_prepare = 0;

/** @brief When non-zero, `chaos_net_config_match_endpoint*` fills @p rule and returns 1. */
static int g_stub_match_endpoint = 0;

/** @brief When non-zero, `chaos_net_endpoint_from_sockaddr_fd` fills @p endpoint and returns 1. */
static int g_stub_endpoint_from_sockaddr = 0;

/** @brief When non-zero, `chaos_net_endpoint_from_socket_spec` fills @p endpoint and returns 1. */
static int g_stub_endpoint_from_socket_spec = 0;

/** @brief When non-zero, `chaos_net_endpoint_from_activity_fd` fills @p endpoint and returns 1. */
static int g_stub_endpoint_from_activity = 0;

/** @brief When non-zero, `chaos_net_endpoint_from_local_fd` fills @p endpoint and returns 1. */
static int g_stub_endpoint_from_local = 0;

/** @brief When non-zero, `chaos_net_endpoint_from_peer_fd` fills @p endpoint and returns 1. */
static int g_stub_endpoint_from_peer = 0;

/** @brief Cumulative count of `chaos_net_rule_apply_latency` stub invocations. */
static int g_latency_calls = 0;

/**
 * @brief Controls whether the errno stub fires.
 *
 * When 0, `chaos_net_rule_apply_errno` always returns 0 even if effect==ERRNO.
 * When 1, it sets errno to `rule->errnum` and returns 1.
 */
static int g_errno_trigger = 0;

/**
 * @brief Return value for `chaos_net_rule_should_trigger`.
 *
 * Tests that exercise CORRUPT or TIMEOUT set this to 1 before calling the wrapper.
 */
static int g_should_trigger = 0;

/** @brief Cumulative count of `chaos_net_corrupt_buffer*` stub invocations. */
static int g_corrupt_calls = 0;

/* --- Wait-path injection flags (Linux-only when guarded) --- */

/**
 * @brief When non-zero, the `snprintf` stub inside `chaos_net_wait.c` returns -1.
 *
 * Used to exercise the FD-path formatting failure branch of `chaos_net_wait_match_epoll`.
 */
static int g_wait_fail_snprintf = 0;

/**
 * @brief When non-zero, `chaos_net_test_wait_open` returns `g_wait_fake_fd` instead of
 *   opening a real file, and `chaos_net_test_wait_read` / `chaos_net_test_wait_close`
 *   intercept that descriptor.
 */
static int g_wait_fake_open = 0;

/** @brief When non-zero, `chaos_net_test_wait_open` returns ENOENT=-1. */
static int g_wait_force_open_fail = 0;

/** @brief When non-zero and `g_wait_fake_open != 0`, `chaos_net_test_wait_read` returns EIO=-1. */
static int g_wait_force_read_fail = 0;

/**
 * @brief When non-zero and `g_wait_fake_open != 0`, `chaos_net_test_wait_read` fills the
 *   entire output buffer with `'x'`, triggering the path-too-long detection.
 */
static int g_wait_fill_buffer = 0;

/**
 * @brief When non-NULL and `g_wait_fake_open != 0`, `chaos_net_test_wait_read` delivers
 *   the contents of this string in streaming chunks.
 */
static const char *g_wait_read_text = NULL;

/** @brief Byte offset into `g_wait_read_text` for the next streaming chunk. */
static size_t g_wait_read_offset = 0U;

#ifdef __linux__
/** @brief Sentinel file descriptor returned by `chaos_net_test_wait_open` for fake opens. */
static const int g_wait_fake_fd = 7331;
#endif

/* --- Per-function real-call counters --- */

/** @brief Number of times the `bind` stub was called. */
static int g_bind_calls = 0;
/** @brief Number of times the `listen` stub was called. */
static int g_listen_calls = 0;
/** @brief Number of times the `connect` stub was called. */
static int g_connect_calls = 0;
/** @brief Number of times the `accept` / `accept4` stub was called. */
static int g_accept_calls = 0;
/** @brief Number of times the `socket` stub was called. */
static int g_socket_calls = 0;
/** @brief Number of times the `socketpair` stub was called. */
static int g_socketpair_calls = 0;
/** @brief Number of times the `shutdown` stub was called. */
static int g_shutdown_calls = 0;
/** @brief Number of times the `send` stub was called. */
static int g_send_calls = 0;
/** @brief Number of times the `sendto` stub was called. */
static int g_sendto_calls = 0;
/** @brief Number of times the `sendmsg` stub was called. */
static int g_sendmsg_calls = 0;
/** @brief Number of times the `recv` stub was called. */
static int g_recv_calls = 0;
/** @brief Number of times the `recvfrom` stub was called. */
static int g_recvfrom_calls = 0;
/** @brief Number of times the `recvmsg` stub was called. */
static int g_recvmsg_calls = 0;
/** @brief Number of times the `poll` stub was called. */
static int g_poll_calls = 0;
/** @brief Number of times the `ppoll` stub was called. */
static int g_ppoll_calls = 0;
/** @brief Number of times the `select` stub was called. */
static int g_select_calls = 0;
/** @brief Number of times the `pselect` stub was called. */
static int g_pselect_calls = 0;
#ifdef __linux__
/** @brief Number of times the `sendmmsg` stub was called. */
static int g_sendmmsg_calls = 0;
/** @brief Number of times the `recvmmsg` stub was called. */
static int g_recvmmsg_calls = 0;
/** @brief Number of times the `epoll_wait` stub was called. */
static int g_epoll_wait_calls = 0;
/** @brief Number of times the `epoll_pwait` stub was called. */
static int g_epoll_pwait_calls = 0;
#endif

/* --- Per-function real-call results --- */

/** @brief Value returned by the `bind` stub. Default 0 (success). */
static int g_bind_result = 0;
/** @brief Value returned by the `listen` stub. Default 0 (success). */
static int g_listen_result = 0;
/** @brief Value returned by the `connect` stub. Default 0 (success). */
static int g_connect_result = 0;
/** @brief Value returned by the `accept` / `accept4` stub. Default 10 (synthetic fd). */
static int g_accept_result = 10;
/** @brief Value returned by the `socket` stub. Default 8 (synthetic fd). */
static int g_socket_result = 8;
/** @brief Value returned by the `socketpair` stub. Default 0 (success). */
static int g_socketpair_result = 0;
/** @brief Value returned by the `shutdown` stub. Default 0 (success). */
static int g_shutdown_result = 0;
/** @brief Byte count returned by the `send` stub. Default 4. */
static ssize_t g_send_result = 4;
/** @brief Byte count returned by the `sendto` stub. Default 4. */
static ssize_t g_sendto_result = 4;
/** @brief Byte count returned by the `sendmsg` stub. Default 4. */
static ssize_t g_sendmsg_result = 4;
/** @brief Byte count returned by the `recv` stub; it also fills the buffer with "data". */
static ssize_t g_recv_result = 4;
/** @brief Byte count returned by the `recvfrom` stub; fills buffer with "data". */
static ssize_t g_recvfrom_result = 4;
/** @brief Byte count returned by the `recvmsg` stub; fills iov[0] with "data". */
static ssize_t g_recvmsg_result = 4;
/** @brief Value returned by the `poll` stub. Default 0. */
static int g_poll_result = 0;
/** @brief Value returned by the `ppoll` stub. Default 0. */
static int g_ppoll_result = 0;
/** @brief Value returned by the `select` stub. Default 0. */
static int g_select_result = 0;
/** @brief Value returned by the `pselect` stub. Default 0. */
static int g_pselect_result = 0;
#ifdef __linux__
/** @brief Message-batch count returned by the `sendmmsg` stub. Default 1. */
static int g_sendmmsg_result = 1;
/** @brief Message-batch count returned by the `recvmmsg` stub. Default 1. */
static int g_recvmmsg_result = 1;
/** @brief Event count returned by the `epoll_wait` stub. Default 1. */
static int g_epoll_wait_result = 1;
/** @brief Event count returned by the `epoll_pwait` stub. Default 1. */
static int g_epoll_pwait_result = 1;
#endif

/* -------------------------------------------------------------------------
 * Config and action stubs (replace compiled-in config/action modules)
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for `chaos_net_config_prepare()`.
 *
 * Returns `g_stub_prepare`. When 0, wrappers skip rule matching entirely.
 */
int chaos_net_config_prepare(void)
{
    return g_stub_prepare;
}

/**
 * @brief Stub for `chaos_net_config_match_endpoint()`.
 *
 * When `g_stub_match_endpoint != 0` and @p rule is non-NULL, copies `g_stub_rule`
 * into @p rule and returns 1. Returns 0 otherwise.
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
    *rule = g_stub_rule;
    return 1;
}

/**
 * @brief Stub for `chaos_net_config_match_endpoint_loaded()`.
 *
 * Delegates to `chaos_net_config_match_endpoint` using the same flags, so tests
 * that call the "loaded" variant are covered by the same setup.
 */
int chaos_net_config_match_endpoint_loaded(
    chaos_net_operation_t operation, const chaos_net_endpoint_t *endpoint, chaos_net_rule_t *rule
)
{
    return chaos_net_config_match_endpoint(operation, endpoint, rule);
}

/**
 * @brief Stub for `chaos_net_endpoint_from_sockaddr_fd()`.
 *
 * Used by `bind`, `connect`, `sendto`, and `sendmsg` to obtain the remote endpoint.
 * Returns 1 and fills @p endpoint with `g_stub_endpoint` when `g_stub_endpoint_from_sockaddr != 0`.
 */
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    (void)fd;
    (void)address;
    (void)address_length;
    if (g_stub_endpoint_from_sockaddr == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/**
 * @brief Stub for `chaos_net_endpoint_from_socket_spec()`.
 *
 * Used by `socket` and `socketpair` to describe the created socket kind.
 * Returns 1 and fills @p endpoint when `g_stub_endpoint_from_socket_spec != 0`.
 */
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

/**
 * @brief Stub for `chaos_net_endpoint_from_activity_fd()`.
 *
 * Used by `shutdown`, `poll`, `ppoll`, `select`, `pselect`, and epoll paths.
 * Returns 1 and fills @p endpoint when `g_stub_endpoint_from_activity != 0`.
 */
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    (void)fd;
    if (g_stub_endpoint_from_activity == 0 || endpoint == NULL)
    {
        return 0;
    }
    *endpoint = g_stub_endpoint;
    return 1;
}

/**
 * @brief Stub for `chaos_net_endpoint_from_local_fd()`.
 *
 * Used by `listen` and `accept` to identify the local socket endpoint.
 * Returns 1 and fills @p endpoint when `g_stub_endpoint_from_local != 0`.
 */
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

/**
 * @brief Stub for `chaos_net_endpoint_from_peer_fd()`.
 *
 * Used by `send`, `sendto`, and `sendmsg` (NULL-address form) to identify the
 * connected peer endpoint. Returns 1 and fills @p endpoint when
 * `g_stub_endpoint_from_peer != 0`.
 */
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

/**
 * @brief Stub for `chaos_net_rule_apply_latency()`.
 *
 * Increments `g_latency_calls`. The assert ensures the rule pointer is non-NULL,
 * matching the production contract.
 */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    assert(rule != NULL);
    ++g_latency_calls;
}

/**
 * @brief Stub for `chaos_net_rule_apply_errno()`.
 *
 * Sets `errno` to `rule->errnum` and returns 1 only when all three conditions hold:
 * rule is non-NULL, effect is ERRNO, and `g_errno_trigger != 0`. This allows tests
 * to arm the errno path independently from rule matching.
 */
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_ERRNO || g_errno_trigger == 0)
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}

/**
 * @brief Stub for `chaos_net_rule_should_trigger()`.
 *
 * Returns `g_should_trigger` unconditionally. Tests that exercise CORRUPT or TIMEOUT
 * set this to 1 before calling the wrapper under test.
 */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    (void)rule;
    return g_should_trigger;
}

/**
 * @brief Stub for `chaos_net_corrupt_buffer_sample()`.
 *
 * Increments `g_corrupt_calls` and actually flips `bytes[index_sample % size]` bit
 * `(bit_sample & 7)`, so assertions like `buffer[0] != 'd'` after recv are valid.
 */
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;

    ++g_corrupt_calls;
    if (buffer != NULL && size > 0U)
    {
        bytes[index_sample % size] ^= (unsigned char)(1U << (bit_sample & 7U));
    }
}

/**
 * @brief Stub for `chaos_net_corrupt_buffer()`.
 *
 * Delegates to `chaos_net_corrupt_buffer_sample` with fixed indices 0/0, ensuring
 * byte[0] is always the corrupted position in tests that use this entry-point.
 */
void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    chaos_net_corrupt_buffer_sample(buffer, size, 0U, 0U);
}

/* -------------------------------------------------------------------------
 * Real-function stubs: portable socket calls
 * --------------------------------------------------------------------- */

/**
 * @brief Stub for the real `bind(2)`.
 *
 * Increments `g_bind_calls` and returns `g_bind_result`. The default result is 0
 * (success).
 */
static int chaos_net_test_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_bind_calls;
    return g_bind_result;
}

/**
 * @brief Stub for the real `listen(2)`.
 *
 * Increments `g_listen_calls` and returns `g_listen_result`.
 */
static int chaos_net_test_listen(int sockfd, int backlog)
{
    (void)sockfd;
    (void)backlog;
    ++g_listen_calls;
    return g_listen_result;
}

/**
 * @brief Stub for the real `connect(2)`.
 *
 * Increments `g_connect_calls` and returns `g_connect_result`.
 */
static int
chaos_net_test_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_connect_calls;
    return g_connect_result;
}

/**
 * @brief Stub for the real `accept(2)`.
 *
 * Increments `g_accept_calls` and returns `g_accept_result`. Default result is 10,
 * a synthetic accepted-socket fd.
 */
static int chaos_net_test_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    (void)sockfd;
    (void)address;
    (void)address_length;
    ++g_accept_calls;
    return g_accept_result;
}

/**
 * @brief Stub for the real `socket(2)`.
 *
 * Increments `g_socket_calls` and returns `g_socket_result`. Default result is 8,
 * a synthetic socket fd.
 */
static int chaos_net_test_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    ++g_socket_calls;
    return g_socket_result;
}

/**
 * @brief Stub for the real `socketpair(2)`.
 *
 * Increments `g_socketpair_calls`, populates `sv[0]=11, sv[1]=12` when non-NULL,
 * and returns `g_socketpair_result`. The fixed fd values let tests assert the
 * pair was delivered through the wrapper without modification.
 */
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

/**
 * @brief Stub for the real `shutdown(2)`.
 *
 * Increments `g_shutdown_calls` and returns `g_shutdown_result`.
 */
static int chaos_net_test_shutdown(int sockfd, int how)
{
    (void)sockfd;
    (void)how;
    ++g_shutdown_calls;
    return g_shutdown_result;
}

#ifdef __linux__
/**
 * @brief Linux-only stub for the real `accept4(2)`.
 *
 * Shares `g_accept_calls` and `g_accept_result` with the portable `accept` stub,
 * so both are counted by the same counter and tested with the same expected value.
 */
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

/**
 * @brief Stub for the real `send(2)`.
 *
 * Increments `g_send_calls` and returns `g_send_result`. Default is 4 bytes sent.
 */
static ssize_t chaos_net_test_send(int sockfd, const void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)buffer;
    (void)size;
    (void)flags;
    ++g_send_calls;
    return g_send_result;
}

/**
 * @brief Stub for the real `sendto(2)`.
 *
 * Increments `g_sendto_calls` and returns `g_sendto_result`.
 */
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

/**
 * @brief Stub for the real `sendmsg(2)`.
 *
 * Increments `g_sendmsg_calls` and returns `g_sendmsg_result`.
 */
static ssize_t chaos_net_test_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)message;
    (void)flags;
    ++g_sendmsg_calls;
    return g_sendmsg_result;
}

/**
 * @brief Stub for the real `recv(2)`.
 *
 * Increments `g_recv_calls`. When @p buffer is non-NULL and `size >= 4`, fills the
 * first 4 bytes with `"data"` so post-recv corruption tests can detect the change.
 * Returns `g_recv_result`.
 */
static ssize_t chaos_net_test_recv(int sockfd, void *buffer, size_t size, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recv_calls;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recv_result;
}

/**
 * @brief Stub for the real `recvfrom(2)`.
 *
 * Increments `g_recvfrom_calls` and fills buffer with `"data"` when possible.
 * Returns `g_recvfrom_result`.
 */
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
    (void)address;
    (void)address_length;
    ++g_recvfrom_calls;
    if (buffer != NULL && size >= 4U)
    {
        (void)memcpy(buffer, "data", 4U);
    }
    return g_recvfrom_result;
}

/**
 * @brief Stub for the real `recvmsg(2)`.
 *
 * Increments `g_recvmsg_calls`. When `message->msg_iov[0].iov_len >= 4`, fills
 * `iov[0].iov_base` with `"data"` so corruption tests can assert modification.
 * Returns `g_recvmsg_result`.
 */
static ssize_t chaos_net_test_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    (void)sockfd;
    (void)flags;
    ++g_recvmsg_calls;
    if (message != NULL && message->msg_iovlen > 0 && message->msg_iov[0].iov_len >= 4U)
    {
        (void)memcpy(message->msg_iov[0].iov_base, "data", 4U);
    }
    return g_recvmsg_result;
}

/**
 * @brief Stub for the real `poll(2)`.
 *
 * Increments `g_poll_calls` and returns `g_poll_result`.
 */
static int chaos_net_test_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    (void)fds;
    (void)nfds;
    (void)timeout;
    ++g_poll_calls;
    return g_poll_result;
}

/**
 * @brief Stub for the real `ppoll(2)`.
 *
 * Increments `g_ppoll_calls` and returns `g_ppoll_result`.
 */
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

/**
 * @brief Stub for the real `select(2)`.
 *
 * Increments `g_select_calls` and returns `g_select_result`.
 */
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

/**
 * @brief Stub for the real `pselect(2)`.
 *
 * Increments `g_pselect_calls` and returns `g_pselect_result`.
 */
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
/**
 * @brief Linux-only stub for `snprintf` inside `chaos_net_wait.c`.
 *
 * When `g_wait_fail_snprintf != 0`, returns -1 to exercise the formatting-failure
 * branch of `chaos_net_wait_match_epoll`. Otherwise delegates to `vsnprintf`.
 */
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
 * @brief Linux-only stub for `open(2)` inside `chaos_net_wait.c`.
 *
 * Three operating modes:
 * - `g_wait_force_open_fail != 0` — returns -1 / ENOENT unconditionally.
 * - `g_wait_fake_open != 0` — returns the sentinel `g_wait_fake_fd` without
 *   opening a real file; the path and flags arguments are ignored.
 * - Otherwise — forwards to the real `open(2)`, handling `O_CREAT` va_args correctly.
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
 * @brief Linux-only stub for `read(2)` inside `chaos_net_wait.c`.
 *
 * When `fd == g_wait_fake_fd` and `g_wait_fake_open != 0`, four modes are available:
 * - `g_wait_force_read_fail != 0` — returns EIO=-1 to exercise the read-error path.
 * - `g_wait_fill_buffer != 0` — fills the entire buffer with `'x'`, triggering the
 *   path-too-long detection in the caller.
 * - `g_wait_read_text != NULL` — delivers the text in streaming chunks up to @p count bytes
 *   per call, advancing `g_wait_read_offset`; returns 0 at end-of-string.
 * - Otherwise returns 0 (empty read).
 * For any other fd, delegates to the real `read(2)`.
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

/**
 * @brief Linux-only stub for `close(2)` inside `chaos_net_wait.c`.
 *
 * When `fd == g_wait_fake_fd` and `g_wait_fake_open != 0`, returns 0 without
 * calling the real `close`. Otherwise delegates to the real `close(2)`.
 */
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
 * Linux-only batch and epoll real-function stubs
 * --------------------------------------------------------------------- */

#ifdef __linux__
/**
 * @brief Stub for the real `sendmmsg(2)`.
 *
 * Increments `g_sendmmsg_calls` and returns `g_sendmmsg_result`. Default is 1
 * message sent.
 */
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

/**
 * @brief Stub for the real `recvmmsg(2)`.
 *
 * Increments `g_recvmmsg_calls`. When `msgvec[0].msg_hdr.msg_iov[0].iov_len >= 4`,
 * fills it with `"data"` and sets `msgvec[0].msg_len = 4` so corruption tests
 * can detect the modification. Returns `g_recvmmsg_result`.
 */
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

/**
 * @brief Stub for the real `epoll_wait(2)`.
 *
 * Increments `g_epoll_wait_calls` and returns `g_epoll_wait_result`.
 */
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

/**
 * @brief Stub for the real `epoll_pwait(2)`.
 *
 * Increments `g_epoll_pwait_calls` and returns `g_epoll_pwait_result`.
 */
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
 * Production source inclusion with symbol overrides
 * --------------------------------------------------------------------- */

#include "../../src/net/chaos_net_socket.c"
#include "../../src/net/chaos_net_extra.c"
#ifdef __linux__
/* Override the three syscall-like I/O symbols and snprintf only for the wait module. */
#define open chaos_net_test_wait_open
#define read chaos_net_test_wait_read
#define close chaos_net_test_wait_close
#undef snprintf
#define snprintf chaos_net_test_wait_snprintf
#endif
#include "../../src/net/chaos_net_wait.c"
#ifdef __linux__
#undef snprintf
#undef close
#undef read
#undef open
#endif

/* -------------------------------------------------------------------------
 * State reset
 * --------------------------------------------------------------------- */

/**
 * @brief Reset all runtime globals and test-local state before each test function.
 *
 * Wires all 17 (21 on Linux) `g_chaos_net_real_*` function pointers to the
 * corresponding test stubs, then zeroes all flag, counter, and result variables to
 * their default values. Default results are: accept=10, socket=8, send/recv family=4.
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
 * Test functions
 * --------------------------------------------------------------------- */

/**
 * @brief Invariant: `bind` and `connect` passthrough and ERRNO/LATENCY paths.
 *
 * Triggering conditions:
 * - `bind` with no matching endpoint → passthrough, `g_bind_calls == 1`.
 * - `bind` with ERRNO=EADDRINUSE → returns -1, errno set, real bind not called.
 * - `connect` with LATENCY rule → latency stub called, real connect called.
 * - `bind` with LATENCY rule → latency stub called, real bind called.
 * - `connect` with no endpoint match → passthrough.
 *
 * Expected observable behaviour:
 * - Passthrough: wrapper returns the stub result and increments the call counter.
 * - ERRNO injection: wrapper returns -1, errno==EADDRINUSE, real bind call count==0.
 * - LATENCY: `g_latency_calls == 1` and real function was still called.
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
 * @brief Invariant: `listen`, `accept`, `send`, `sendto`, `sendmsg` effect paths.
 *
 * Triggering conditions:
 * - `listen` LATENCY via `from_local_fd`; ERRNO=EADDRINUSE.
 * - `accept` ERRNO=EAGAIN (no accept call); passthrough; accept4 passthrough (Linux).
 * - `accept4` ERRNO=EINTR (Linux).
 * - `send` LATENCY via `from_peer_fd`; passthrough.
 * - `sendto` ERRNO=EHOSTUNREACH via `from_sockaddr_fd`; passthrough.
 * - `sendmsg` passthrough (NULL msg_name → from_sockaddr returns 0); LATENCY.
 *
 * Expected observable behaviour:
 * - ERRNO before real call: counter==0, errno set correctly.
 * - LATENCY before real call: latency counter==1, real call counter==1.
 * - Passthrough: wrapper result equals stub result; counter==1.
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
 * @brief Invariant: `recv`, `recvfrom`, `recvmsg` effect paths.
 *
 * Triggering conditions:
 * - `recv` CORRUPT → `g_corrupt_calls == 1`; `buffer[0] != 'd'` (byte flipped by stub).
 * - `recv` LATENCY; ERRNO=EAGAIN.
 * - `recvfrom` ERRNO=EAGAIN; passthrough; CORRUPT.
 * - `recvmsg` CORRUPT (msg_buffer verified not equal to "data"); passthrough; LATENCY.
 *
 * Expected observable behaviour:
 * - CORRUPT: real receive still called, then corruption stub fires; byte is modified.
 * - ERRNO: real receive not called (counter==0), errno set.
 * - LATENCY: latency stub called, real receive called.
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
 * @brief Invariant: `socket`, `socketpair`, `shutdown` effect paths.
 *
 * Triggering conditions:
 * - `socket` ERRNO=EAFNOSUPPORT; LATENCY; passthrough.
 * - `socketpair` ERRNO=EMFILE; LATENCY with sv[0]==11 and sv[1]==12.
 * - `shutdown` ERRNO=ENOTCONN; passthrough; LATENCY.
 *
 * Expected observable behaviour:
 * - ERRNO: real function not called, errno set.
 * - LATENCY: real function called, latency counter incremented.
 * - socketpair passthrough: pair descriptors delivered unchanged.
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
 * @brief Invariant: `poll`, `ppoll`, `select`, `pselect` TIMEOUT/LATENCY/ERRNO paths.
 *
 * Triggering conditions (poll and ppoll):
 * - TIMEOUT: `g_should_trigger=1` → `revents` zeroed, real call bypassed.
 * - LATENCY: real call reached, latency stub fires.
 * - ERRNO=EINTR: returns -1, real call bypassed.
 *
 * Triggering conditions (select and pselect):
 * - TIMEOUT: fd-sets cleared, real call bypassed.
 * - LATENCY: real call reached.
 * - ERRNO: returns -1 with errno set.
 *
 * Expected observable behaviour:
 * - TIMEOUT: return 0; revents/fd-set bits cleared; real call counter==0.
 * - ERRNO: return -1; errno set; real call counter==0.
 * - LATENCY: return 0 (stub result); latency counter==1; real call counter==1.
 * - Passthrough: return 0; real call counter==1.
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
    assert(poll(fds, 1U, 100) == 0);
    assert(g_poll_calls == 0);
    assert(fds[0].revents == 0);

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
    assert(select(10, &readfds, NULL, NULL, NULL) == 0);
    assert(g_select_calls == 0);
    assert(!FD_ISSET(9, &readfds));

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
 * @brief Invariant: `sendmmsg` and `recvmmsg` batch effect paths (Linux-only).
 *
 * Triggering conditions:
 * - `sendmmsg` ERRNO=EHOSTUNREACH: returns -1, real call bypassed.
 * - `sendmmsg` LATENCY: latency counter incremented, real call reached.
 * - `recvmmsg` CORRUPT: corruption stub fires, `buffer` is not equal to "data".
 * - `sendmmsg` passthrough; `recvmmsg` passthrough.
 * - `sendmmsg` with TLS guard active: passthrough (guard bypasses matching).
 * - `recvmmsg` ERRNO=EAGAIN: returns -1, errno set, real call bypassed.
 *
 * Expected observable behaviour:
 * - CORRUPT: `g_corrupt_calls == 1` and `buffer[0:4] != "data"`.
 * - TLS guard: `sendmmsg` passes through even with no explicit passthrough setup.
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
 * @brief Invariant: direct helper functions exercise all branches.
 *
 * Triggering conditions:
 * - `chaos_net_apply_pre_call_rule(NULL)` → 0.
 * - `chaos_net_apply_simple_pre_call_rule(NULL)` → 0.
 * - `chaos_net_wait_pre_call(NULL, &timeout)` → 0, `timeout == 0`.
 * - LATENCY rule → `g_latency_calls == 3` across all three helpers.
 * - ERRNO rule with `g_errno_trigger=1` → returns -1 across all three.
 * - TIMEOUT rule with `g_should_trigger=1` → `synthetic_timeout == 1`.
 * - CORRUPT rule → all three return 0, `synthetic_timeout == 0`.
 * - `chaos_net_wait_clear_pollfds(NULL, 0)` → no crash.
 * - `chaos_net_wait_clear_pollfds` with 2 entries → revents zeroed.
 * - `chaos_net_wait_clear_fdsets` with three non-empty sets → all cleared.
 * - All `chaos_net_call_real_*` functions forwarded to test stubs.
 * - `chaos_net_corrupt_iovecs(NULL, …)` → no crash; non-NULL 2-iov vector with
 *   seeded PRNG that produces odd result → corruption on second iov.
 * - `chaos_net_wait_match_pollfds`: NULL fds; fd==-1; valid fd with match.
 * - `chaos_net_wait_match_fdsets`: NULL readfds; empty set; fd not in set; valid match.
 *
 * Expected observable behaviour:
 * - NULL guards: return 0/false without accessing any globals.
 * - All `call_real_*` wrappers invoke the corresponding stub exactly once.
 * - Iov corruption: `g_corrupt_calls >= 1` after seeded PRNG produces odd.
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
    assert(chaos_net_wait_pre_call(NULL, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

    rule.effect = CHAOS_NET_EFFECT_LATENCY;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
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
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == -1);
    assert(errno == EAGAIN);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_TIMEOUT;
    g_should_trigger = 1;
    synthetic_timeout = 0;
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 1);

    reset_wrapper_stubs();
    rule.effect = CHAOS_NET_EFFECT_CORRUPT;
    assert(chaos_net_apply_pre_call_rule(&rule) == 0);
    assert(chaos_net_apply_simple_pre_call_rule(&rule) == 0);
    synthetic_timeout = -1;
    assert(chaos_net_wait_pre_call(&rule, &synthetic_timeout) == 0);
    assert(synthetic_timeout == 0);

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
 * @brief Invariant: Linux-only direct helper paths for batch and epoll operations.
 *
 * Triggering conditions:
 * - `chaos_net_call_real_sendmmsg`, `chaos_net_call_real_recvmmsg`,
 *   `chaos_net_call_real_epoll_wait`, `chaos_net_call_real_epoll_pwait` — each
 *   calls the corresponding stub exactly once and returns the stub result.
 * - `chaos_net_corrupt_mmsghdrs(NULL, 0)` → no crash.
 * - `chaos_net_corrupt_mmsghdrs(recv_messages, 1)` with iov[0].iov_len==0 and
 *   iov[1].iov_len==4 → corruption lands in iov[1]; `g_corrupt_calls == 1`.
 * - `chaos_net_wait_match_epoll(-1, NULL)` → false (NULL rule pointer).
 * - `chaos_net_wait_match_epoll` with snprintf failure → false.
 * - `chaos_net_wait_match_epoll` with invalid epfd → false.
 * - `chaos_net_wait_match_epoll` with read failure → false.
 * - `chaos_net_wait_match_epoll` with fill-buffer overflow → false.
 * - `chaos_net_wait_match_epoll` with real epfd, endpoint match → true.
 *
 * Expected observable behaviour:
 * - `call_real_*`: stub call counters each increment by 1.
 * - `corrupt_mmsghdrs`: `g_corrupt_calls == 1` for the single message.
 * - `wait_match_epoll`: false for all error paths; true for successful match.
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
 * @brief Invariant: additional wrapper branches not covered by primary tests.
 *
 * Triggering conditions:
 * - `bind` passthrough with explicit reset.
 * - `connect` ERRNO=ECONNREFUSED.
 * - `accept` LATENCY via `from_local_fd`.
 * - `accept4` LATENCY via `from_local_fd` (Linux).
 * - `send` ERRNO=EPIPE via `from_peer_fd`.
 * - `sendto` LATENCY with NULL address via `from_peer_fd`.
 * - `sendmsg` ERRNO=EHOSTUNREACH via `from_peer_fd` (NULL msg_name).
 * - `recv` passthrough.
 * - `recvfrom` LATENCY.
 * - `recvmsg` ERRNO=EAGAIN.
 * - `socket` with TLS guard active → real call, guard reset.
 *
 * Expected observable behaviour:
 * - ECONNREFUSED: `connect` returns -1, errno==ECONNREFUSED, real call count==0.
 * - EPIPE: `send` returns -1, errno==EPIPE, real call count==0.
 * - TLS guard on socket: wrapper passes through regardless of config state.
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
/**
 * @brief Invariant: `epoll_wait` and `epoll_pwait` effect paths (Linux-only).
 *
 * Triggering conditions:
 * - `epoll_wait` TIMEOUT: real call bypassed, returns 0.
 * - `epoll_wait` ERRNO=ETIMEDOUT: returns -1.
 * - `epoll_wait` LATENCY: real call reached, returns 1 (stub result).
 * - `epoll_pwait` ERRNO=ETIMEDOUT; TIMEOUT; LATENCY.
 * - Both `epoll_wait` and `epoll_pwait` passthrough.
 *
 * All tests use a real epoll instance created from a pipe so that
 * `chaos_net_wait_match_epoll` can read `/proc/self/fd/<epfd>` entries.
 * The real fds are closed in all paths to avoid leaks.
 *
 * Expected observable behaviour:
 * - TIMEOUT: call count==0, return 0.
 * - ERRNO: call count==0, return -1, errno==ETIMEDOUT.
 * - LATENCY: call count==1, `g_latency_calls==1`, return 1.
 * - Passthrough: call count==1, return 1.
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

int main(void)
{
    test_bind_and_connect_paths();
    test_accept_and_send_paths();
    test_recv_paths();
    test_socket_and_shutdown_paths();
    test_wait_paths();
    test_direct_helper_paths();
    test_wrapper_passthrough_and_additional_branches();
#ifdef __linux__
    test_batch_paths();
    test_direct_linux_helper_paths();
    test_epoll_wrapper_paths();
#endif
    return 0;
}
