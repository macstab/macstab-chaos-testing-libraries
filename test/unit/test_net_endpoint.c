/**
 * @file test_net_endpoint.c
 * @brief Unit tests for network-endpoint parsing, matching, and socket-address resolution.
 *
 * Subsystem under test: `src/net/chaos_net_endpoint.c`
 *
 * Coverage approach:
 * - The production source file is included directly. Three real-function-pointer globals
 *   (`g_chaos_net_real_getsockopt`, `g_chaos_net_real_getsockname`,
 *   `g_chaos_net_real_getpeername`) are assigned to test stubs in `reset_endpoint_stubs()`
 *   before each test that needs them. This mirrors how the production library wires the
 *   function pointers at constructor time.
 * - `CHAOS_NET_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals.
 * - Three stubs control the syscall-level responses:
 *   - `chaos_net_test_getsockopt`: asserts SOL_SOCKET/SO_TYPE parameters; writes
 *     `g_stub_socket_type` into the value buffer; returns `g_stub_getsockopt_result`.
 *   - `chaos_net_test_getsockname`: copies `g_stub_sockname_storage` (truncated to
 *     `g_stub_sockname_length`) into the output; returns `g_stub_getsockname_result`.
 *   - `chaos_net_test_getpeername`: copies `g_stub_peer_storage` into the output;
 *     returns `g_stub_getpeername_result`.
 * - Helper `chaos_net_test_set_ipv4` / `chaos_net_test_set_ipv6` from `test_net_support.h`
 *   constructs properly-initialised sockaddr_in / sockaddr_in6 values for use in tests.
 *
 * Properties under test:
 * - `chaos_net_endpoint_parse_selector`: all 7 scheme prefixes (tcp4, tcp6, udp4, udp6,
 *   unix, wildcard *); wildcard-host variants (`*:port`); exact-host variants; NULL, empty,
 *   unknown scheme, missing port → false.
 * - `chaos_net_parse_port`: NULL, empty, NULL output, out-of-range, trailing char → false.
 * - `chaos_net_parse_ipv4_selector`: bare IP without port → false; wildcard with port → true;
 *   oversized host, invalid IP → false.
 * - `chaos_net_parse_ipv6_selector`: bracketed IPv6 with port → true; wildcard → true;
 *   missing port separator, empty brackets, invalid address → false.
 * - `chaos_net_endpoint_matches`: exact TCP4 match → rank 3; wildcard-host match → rank 2;
 *   wildcard `*` match → rank 1; UNIX exact match → rank 4; UNIX wildcard → rank 2;
 *   NULL selector or endpoint → false; kind/address/port mismatches → false;
 *   INVALID kind → false, rank reset to 0; NULL rank pointer → no crash.
 * - `chaos_net_endpoint_from_sockaddr_fd`: AF_INET TCP → TCP4; AF_INET UDP → UDP4;
 *   AF_INET6 TCP → TCP6; AF_INET6 UDP → UDP6; AF_UNIX with path → UNIX; empty sun_path →
 *   false; oversized unix path → false; truncated sockaddr (too small) → false;
 *   getsockopt failure → false; unknown socket type → false; NULL address → false;
 *   address length < `sizeof(sa_family_t)` → false; AF_UNSPEC → false.
 * - `chaos_net_endpoint_from_sockaddr`: oversized unix path → false.
 * - `chaos_net_endpoint_from_local_fd`: populates endpoint from getsockname; getsockname
 *   failure → false; NULL output → false.
 * - `chaos_net_endpoint_from_peer_fd`: populates endpoint from getpeername; getpeername
 *   failure → false; NULL output → false.
 * - `chaos_net_endpoint_from_socket_spec`: all valid AF/type combinations; SOCK_NONBLOCK
 *   masked on Linux; SOCK_RAW → false; AF_UNSPEC → false; NULL output → false.
 * - `chaos_net_endpoint_from_activity_fd`: tries getpeername first, falls back to
 *   getsockname; both failing → false; NULL output → false.
 * - `chaos_net_endpoint_kind_from_socket`: NULL output → false; NULL getsockopt → false;
 *   AF_UNSPEC → false; valid AF/type pairs produce correct kinds.
 *
 * What is NOT tested here:
 * - Network wrapper call paths (tested in `test_chaos_net.c`).
 * - Config file parsing and rule selection (tested in the net-config test).
 */

#include "../support/test_net_support.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

/** @brief Return value for `chaos_net_test_getsockopt`; 0 → success. */
static int g_stub_getsockopt_result = 0;

/**
 * @brief Socket type written into the getsockopt value buffer.
 *
 * Defaults to SOCK_STREAM. Set to SOCK_DGRAM or an invalid value to exercise UDP and
 * unknown-socket-type paths.
 */
static int g_stub_socket_type = SOCK_STREAM;

/** @brief Return value for `chaos_net_test_getsockname`; 0 → success, -1 → failure. */
static int g_stub_getsockname_result = 0;

/** @brief Return value for `chaos_net_test_getpeername`; 0 → success, -1 → failure. */
static int g_stub_getpeername_result = 0;

/**
 * @brief Storage for the sockaddr copied by `chaos_net_test_getsockname`.
 *
 * Populated via `memcpy` from a real `sockaddr_in` or `sockaddr_in6` before a test that
 * exercises `chaos_net_endpoint_from_local_fd`.
 */
static struct sockaddr_storage g_stub_sockname_storage;

/**
 * @brief Byte length of the valid data in `g_stub_sockname_storage`.
 *
 * Set to `sizeof(sockaddr_in)` or `sizeof(sockaddr_in6)` as appropriate.
 */
static socklen_t g_stub_sockname_length = 0U;

/**
 * @brief Storage for the sockaddr copied by `chaos_net_test_getpeername`.
 *
 * Populated and used identically to `g_stub_sockname_storage` for peer-address tests.
 */
static struct sockaddr_storage g_stub_peer_storage;

/** @brief Byte length of valid data in `g_stub_peer_storage`. */
static socklen_t g_stub_peer_length = 0U;

/**
 * @brief Stub getsockopt that validates parameters and writes `g_stub_socket_type`.
 *
 * Asserts that level is SOL_SOCKET and optname is SO_TYPE. When `g_stub_getsockopt_result`
 * is non-zero, returns that value without writing. Otherwise writes `g_stub_socket_type`
 * into `*(int *)value` and sets `*length = sizeof(int)`.
 *
 * @param fd      Ignored.
 * @param level   Asserted to be SOL_SOCKET.
 * @param optname Asserted to be SO_TYPE.
 * @param value   Destination for the socket type integer.
 * @param length  Set to `sizeof(int)` on success.
 * @return `g_stub_getsockopt_result` (0 = success).
 */
static int chaos_net_test_getsockopt(int fd, int level, int optname, void *value, socklen_t *length)
{
    (void)fd;
    assert(level == SOL_SOCKET);
    assert(optname == SO_TYPE);
    assert(value != NULL);
    assert(length != NULL);

    if (g_stub_getsockopt_result != 0)
    {
        return g_stub_getsockopt_result;
    }

    *(int *)value = g_stub_socket_type;
    *length = (socklen_t)sizeof(int);
    return 0;
}

/**
 * @brief Stub getsockname that copies `g_stub_sockname_storage` into the output buffer.
 *
 * Returns `g_stub_getsockname_result` without writing when non-zero. Otherwise asserts that
 * `*length >= g_stub_sockname_length` and copies exactly `g_stub_sockname_length` bytes.
 *
 * @param fd       Ignored.
 * @param address  Destination buffer.
 * @param length   In: caller buffer size. Out: set to `g_stub_sockname_length`.
 * @return `g_stub_getsockname_result` (0 = success).
 */
static int chaos_net_test_getsockname(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    if (g_stub_getsockname_result != 0)
    {
        return g_stub_getsockname_result;
    }

    assert(address != NULL);
    assert(length != NULL);
    assert(*length >= g_stub_sockname_length);
    (void)memcpy(address, &g_stub_sockname_storage, g_stub_sockname_length);
    *length = g_stub_sockname_length;
    return 0;
}

/**
 * @brief Stub getpeername that copies `g_stub_peer_storage` into the output buffer.
 *
 * Behaves identically to `chaos_net_test_getsockname` but uses the peer storage variables.
 *
 * @param fd       Ignored.
 * @param address  Destination buffer.
 * @param length   In: caller buffer size. Out: set to `g_stub_peer_length`.
 * @return `g_stub_getpeername_result` (0 = success).
 */
static int chaos_net_test_getpeername(int fd, struct sockaddr *address, socklen_t *length)
{
    (void)fd;
    if (g_stub_getpeername_result != 0)
    {
        return g_stub_getpeername_result;
    }

    assert(address != NULL);
    assert(length != NULL);
    assert(*length >= g_stub_peer_length);
    (void)memcpy(address, &g_stub_peer_storage, g_stub_peer_length);
    *length = g_stub_peer_length;
    return 0;
}

#include "../../src/net/chaos_net_endpoint.c"

/**
 * @brief Reset all stub variables and function-pointer globals to well-known defaults.
 *
 * Calls `chaos_net_test_reset_runtime()` to clear PRNG and function-pointer globals, then
 * installs the three test stubs and zeroes all storage buffers and result codes.
 */
static void reset_endpoint_stubs(void)
{
    chaos_net_test_reset_runtime();
    g_chaos_net_real_getsockopt = chaos_net_test_getsockopt;
    g_chaos_net_real_getsockname = chaos_net_test_getsockname;
    g_chaos_net_real_getpeername = chaos_net_test_getpeername;
    g_stub_getsockopt_result = 0;
    g_stub_socket_type = SOCK_STREAM;
    g_stub_getsockname_result = 0;
    g_stub_getpeername_result = 0;
    (void)memset(&g_stub_sockname_storage, 0, sizeof(g_stub_sockname_storage));
    g_stub_sockname_length = 0U;
    (void)memset(&g_stub_peer_storage, 0, sizeof(g_stub_peer_storage));
    g_stub_peer_length = 0U;
}

/**
 * @brief Invariant: selector parsing accepts all scheme/host/port combinations and
 *   rejects all malformed inputs; matching assigns the correct rank for each selector kind.
 *
 * Triggering condition: `chaos_net_endpoint_parse_selector` with all valid and invalid
 *   selector strings; `chaos_net_parse_port`, `chaos_net_parse_ipv4_selector`, and
 *   `chaos_net_parse_ipv6_selector` with boundary inputs; `chaos_net_endpoint_matches`
 *   with matching and non-matching endpoint pairs.
 *
 * Expected observable behaviour:
 * - `"*"` → ANY kind.
 * - `"tcp4://127.0.0.1:5432"` → TCP4, port=5432, wildcard_host=0.
 * - `"tcp4://\*:5432"` → TCP4, port=5432, wildcard_host=1.
 * - `"tcp6://[::1]:443"` → TCP6, port=443.
 * - `"tcp6://\*:8443"` → TCP6, port=8443, wildcard_host=1.
 * - `"udp4://127.0.0.1:53"` → UDP4, port=53.
 * - `"udp6://\*:53"` → UDP6, port=53, wildcard_host=1.
 * - `"udp6://[::1]:53"` → UDP6, port=53.
 * - `"unix:///tmp/socket"` → UNIX, text="/tmp/socket".
 * - `"unix://\*"` → UNIX, text="*".
 * - `parse_port(NULL)`, `("")`, `(80, NULL)`, `("70000")`, `("10x")` → false.
 * - `parse_ipv4_selector("127.0.0.1", ...)` (no port) → false; `("*:25", ...)` → true,
 *   wildcard=1, port=25; oversized host → false; invalid IP → false.
 * - `parse_ipv6_selector("[::1]:443", ...)` → true, port=443; `("*:443", ...)` →
 *   wildcard=1; missing port sep, empty brackets, invalid address → false.
 * - NULL, empty, unknown scheme, missing port, unbracketed IPv6 → false.
 * - Exact TCP4 match (same ip+port) → rank 3; wildcard-host match → rank 2; `*` → rank 1.
 * - UNIX exact match → rank 4; UNIX wildcard → rank 2; path mismatch → false.
 * - NULL selector or endpoint → false; kind/address/port/family mismatches → false.
 * - INVALID kind on both sides → false and rank reset to 0.
 * - NULL rank pointer in matching call does not crash.
 */
static void test_selector_parsing_and_matching(void)
{
    chaos_net_endpoint_t selector;
    chaos_net_endpoint_t endpoint;
    unsigned int rank = 0U;
    char long_host[INET_ADDRSTRLEN + 16U];

    assert(chaos_net_endpoint_parse_selector("*", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_ANY);

    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5432", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_TCP4);
    assert(selector.port == 5432U);
    assert(selector.wildcard_host == 0);

    assert(chaos_net_endpoint_parse_selector("tcp4://*:5432", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_TCP4);
    assert(selector.port == 5432U);
    assert(selector.wildcard_host == 1);

    assert(chaos_net_endpoint_parse_selector("tcp6://[::1]:443", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_TCP6);
    assert(selector.port == 443U);
    assert(chaos_net_endpoint_parse_selector("tcp6://*:8443", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_TCP6);
    assert(selector.port == 8443U);
    assert(selector.wildcard_host == 1);

    assert(chaos_net_endpoint_parse_selector("udp4://127.0.0.1:53", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_UDP4);
    assert(selector.port == 53U);

    assert(chaos_net_endpoint_parse_selector("udp6://*:53", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_UDP6);
    assert(selector.port == 53U);
    assert(selector.wildcard_host == 1);
    assert(chaos_net_endpoint_parse_selector("udp6://[::1]:53", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_UDP6);
    assert(selector.port == 53U);

    assert(chaos_net_endpoint_parse_selector("unix:///tmp/socket", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strcmp(selector.value.text, "/tmp/socket") == 0);
    assert(chaos_net_endpoint_parse_selector("unix://*", &selector));
    assert(selector.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strcmp(selector.value.text, "*") == 0);
    assert(!chaos_net_parse_port(NULL, &endpoint.port));
    assert(!chaos_net_parse_port("", &endpoint.port));
    assert(!chaos_net_parse_port("80", NULL));
    assert(!chaos_net_parse_port("70000", &endpoint.port));
    assert(!chaos_net_parse_port("10x", &endpoint.port));
    assert(!chaos_net_parse_ipv4_selector("127.0.0.1", CHAOS_NET_ENDPOINT_TCP4, &selector));
    assert(chaos_net_parse_ipv4_selector("*:25", CHAOS_NET_ENDPOINT_TCP4, &selector));
    assert(selector.wildcard_host == 1);
    assert(selector.port == 25U);
    assert(chaos_net_parse_ipv6_selector("[::1]:443", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(selector.port == 443U);
    assert(chaos_net_parse_ipv6_selector("*:443", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(selector.wildcard_host == 1);

    (void)memset(long_host, '1', sizeof(long_host) - 4U);
    long_host[sizeof(long_host) - 4U] = ':';
    long_host[sizeof(long_host) - 3U] = '8';
    long_host[sizeof(long_host) - 2U] = '0';
    long_host[sizeof(long_host) - 1U] = '\0';
    assert(!chaos_net_parse_ipv4_selector(long_host, CHAOS_NET_ENDPOINT_TCP4, &selector));
    assert(!chaos_net_parse_ipv4_selector("999.0.0.1:80", CHAOS_NET_ENDPOINT_TCP4, &selector));
    assert(!chaos_net_parse_ipv6_selector("*", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(!chaos_net_parse_ipv6_selector("*443", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(!chaos_net_parse_ipv6_selector("[::1]443", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(!chaos_net_parse_ipv6_selector("[]:443", CHAOS_NET_ENDPOINT_TCP6, &selector));
    assert(!chaos_net_parse_ipv6_selector("[nope]:443", CHAOS_NET_ENDPOINT_TCP6, &selector));

    assert(!chaos_net_endpoint_parse_selector(NULL, &selector));
    assert(!chaos_net_endpoint_parse_selector("", &selector));
    assert(!chaos_net_endpoint_parse_selector("bogus://x", &selector));
    assert(!chaos_net_endpoint_parse_selector("tcp4://127.0.0.1", &selector));
    assert(!chaos_net_endpoint_parse_selector("tcp6://::1:443", &selector));
    assert(!chaos_net_endpoint_parse_selector("unix://", &selector));

    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5432", &selector));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:5432", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 3U);

    assert(chaos_net_endpoint_parse_selector("tcp4://*:5432", &selector));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 2U);

    assert(chaos_net_endpoint_parse_selector("*", &selector));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 1U);

    assert(chaos_net_endpoint_parse_selector("unix:///tmp/socket", &selector));
    assert(chaos_net_endpoint_parse_selector("unix:///tmp/socket", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 4U);
    assert(chaos_net_endpoint_parse_selector("unix://*", &selector));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 2U);
    assert(chaos_net_endpoint_parse_selector("unix:///tmp/socket", &selector));
    endpoint.value.text[0] = 'x';
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));

    assert(!chaos_net_endpoint_matches(NULL, &endpoint, &rank));
    assert(!chaos_net_endpoint_matches(&selector, NULL, &rank));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:1234", &selector));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.2:1234", &endpoint));
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:1234", &selector));
    assert(chaos_net_endpoint_parse_selector("tcp4://127.0.0.1:9999", &endpoint));
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(chaos_net_endpoint_parse_selector("tcp6://*:443", &selector));
    assert(chaos_net_endpoint_parse_selector("tcp6://[::1]:443", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 2U);
    assert(chaos_net_endpoint_parse_selector("udp4://127.0.0.1:53", &selector));
    assert(chaos_net_endpoint_parse_selector("udp4://127.0.0.1:53", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 3U);
    assert(chaos_net_endpoint_parse_selector("udp6://*:53", &selector));
    assert(chaos_net_endpoint_parse_selector("udp6://[::1]:53", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 2U);
    assert(chaos_net_endpoint_parse_selector("tcp6://[::1]:443", &selector));
    assert(chaos_net_endpoint_parse_selector("tcp6://[::1]:443", &endpoint));
    assert(chaos_net_endpoint_matches(&selector, &endpoint, NULL));
    endpoint.port = 444U;
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    endpoint.port = 443U;
    endpoint.value.ipv6 = in6addr_any;
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(chaos_net_endpoint_parse_selector("tcp6://[::1]:443", &selector));
    endpoint.kind = CHAOS_NET_ENDPOINT_ANY;
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    endpoint.kind = CHAOS_NET_ENDPOINT_UNIX;
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));

    (void)memset(&selector, 0, sizeof(selector));
    (void)memset(&endpoint, 0, sizeof(endpoint));
    rank = 99U;
    selector.kind = CHAOS_NET_ENDPOINT_INVALID;
    endpoint.kind = CHAOS_NET_ENDPOINT_INVALID;
    assert(!chaos_net_endpoint_matches(&selector, &endpoint, &rank));
    assert(rank == 0U);
}

/**
 * @brief Invariant: endpoint resolution from sockaddr structures and file descriptors
 *   produces the correct endpoint kind and handles all failure modes.
 *
 * Triggering condition: `chaos_net_endpoint_from_sockaddr_fd`, `chaos_net_endpoint_from_sockaddr`,
 *   `chaos_net_endpoint_from_local_fd`, `chaos_net_endpoint_from_peer_fd`,
 *   `chaos_net_endpoint_from_socket_spec`, `chaos_net_endpoint_from_activity_fd`, and
 *   `chaos_net_endpoint_kind_from_socket` called with various valid and invalid inputs.
 *
 * Expected observable behaviour:
 * - IPv4 address + SOCK_STREAM → TCP4, port matches; truncated sockaddr (size-1) → false.
 * - IPv4 address + SOCK_DGRAM → UDP4.
 * - IPv6 address + SOCK_STREAM → TCP6, port matches; truncated → false.
 * - IPv6 address + SOCK_DGRAM → UDP6.
 * - AF_UNIX with "/tmp/chaos.sock" → UNIX, path matches; empty sun_path → false;
 *   oversized unix path (beyond `CHAOS_NET_MAX_TEXT`) → false.
 * - Local fd resolution via getsockname with IPv4/TCP4: endpoint.kind=TCP4.
 * - Peer fd resolution via getpeername with IPv4/TCP4: endpoint.kind=TCP4.
 * - `getsockopt_result=-1` → false for sockaddr_fd.
 * - Unknown socket type (12345) → false.
 * - NULL address → false; address length < sizeof(sa_family_t) → false.
 * - `from_socket_spec(AF_INET, SOCK_STREAM, ...)` → TCP4, port=0, wildcard=1.
 * - `from_socket_spec(AF_INET, SOCK_DGRAM, ...)` → UDP4.
 * - `from_socket_spec(AF_INET6, SOCK_STREAM, ...)` → TCP6.
 * - `from_socket_spec(AF_INET6, SOCK_DGRAM[|SOCK_NONBLOCK], ...)` → UDP6, wildcard=1.
 * - `from_socket_spec(AF_INET6, SOCK_RAW, ...)` → false.
 * - `from_socket_spec(AF_UNIX, SOCK_STREAM, ...)` → UNIX, text="*".
 * - `from_socket_spec(AF_UNSPEC, ...)` and `(AF_INET, SOCK_RAW, ...)` → false.
 * - NULL output → false.
 * - `from_activity_fd`: getpeername fails → falls back to getsockname (TCP4 from local);
 *   getsockname fails → falls back to getpeername; both fail → false; NULL output → false.
 * - `endpoint_kind_from_socket`: NULL output → false; NULL getsockopt → false;
 *   AF_UNSPEC → false; valid AF/SOCK_DGRAM pairs → UDP4, UDP6, UNIX.
 */
static void test_endpoint_resolution_from_sockaddr_and_fd(void)
{
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
    struct sockaddr_un unix_address;
    struct
    {
        struct sockaddr_un base;
        char extra[CHAOS_NET_MAX_TEXT + 8U];
    } long_unix;
    chaos_net_endpoint_t endpoint;

    reset_endpoint_stubs();

    chaos_net_test_set_ipv4(&ipv4, "127.0.0.1", 8080U);
    g_stub_socket_type = SOCK_STREAM;
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);
    assert(endpoint.port == 8080U);
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4) - 1U, &endpoint
    ));

    g_stub_socket_type = SOCK_DGRAM;
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP4);

    chaos_net_test_set_ipv6(&ipv6, "::1", 8443U);
    g_stub_socket_type = SOCK_STREAM;
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP6);
    assert(endpoint.port == 8443U);
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6) - 1U, &endpoint
    ));
    g_stub_socket_type = SOCK_DGRAM;
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP6);

    (void)memset(&unix_address, 0, sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    (void)snprintf(unix_address.sun_path, sizeof(unix_address.sun_path), "%s", "/tmp/chaos.sock");
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&unix_address, (socklen_t)sizeof(unix_address), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strcmp(endpoint.value.text, "/tmp/chaos.sock") == 0);
    unix_address.sun_path[0] = '\0';
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&unix_address, (socklen_t)sizeof(unix_address), &endpoint
    ));
    (void)memset(&long_unix, 0, sizeof(long_unix));
    long_unix.base.sun_family = AF_UNIX;
    (void)memset(long_unix.base.sun_path, 'x', sizeof(long_unix.base.sun_path));
    (void)memset(long_unix.extra, 'x', sizeof(long_unix.extra) - 1U);
    long_unix.extra[sizeof(long_unix.extra) - 1U] = '\0';
    assert(!chaos_net_endpoint_from_sockaddr(
        7, (const struct sockaddr *)&long_unix, (socklen_t)sizeof(long_unix), &endpoint
    ));

    (void)memcpy(&g_stub_sockname_storage, &ipv4, sizeof(ipv4));
    g_stub_sockname_length = (socklen_t)sizeof(ipv4);
    g_stub_socket_type = SOCK_STREAM;
    assert(chaos_net_endpoint_from_local_fd(7, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);

    (void)memcpy(&g_stub_peer_storage, &ipv4, sizeof(ipv4));
    g_stub_peer_length = (socklen_t)sizeof(ipv4);
    assert(chaos_net_endpoint_from_peer_fd(7, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);

    g_stub_getsockopt_result = -1;
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), &endpoint
    ));
    g_stub_getsockopt_result = 0;
    g_stub_socket_type = 12345;
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), &endpoint
    ));

    assert(!chaos_net_endpoint_from_sockaddr_fd(7, NULL, (socklen_t)sizeof(ipv4), &endpoint));
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(sa_family_t) - 1U, &endpoint
    ));

    g_stub_socket_type = SOCK_STREAM;
    assert(!chaos_net_endpoint_kind_from_socket(7, AF_UNSPEC, &endpoint.kind));
    assert(!chaos_net_endpoint_kind_from_socket(7, AF_INET, NULL));
    g_stub_socket_type = SOCK_DGRAM;
    assert(chaos_net_endpoint_kind_from_socket(7, AF_INET, &endpoint.kind));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP4);
    assert(chaos_net_endpoint_kind_from_socket(7, AF_INET6, &endpoint.kind));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP6);
    assert(chaos_net_endpoint_kind_from_socket(7, AF_UNIX, &endpoint.kind));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
    g_stub_socket_type = 12345;
    assert(!chaos_net_endpoint_kind_from_socket(7, AF_INET6, &endpoint.kind));
    g_chaos_net_real_getsockopt = NULL;
    assert(!chaos_net_endpoint_kind_from_socket(7, AF_INET, &endpoint.kind));
    g_chaos_net_real_getsockopt = chaos_net_test_getsockopt;

    g_stub_socket_type = SOCK_STREAM;
    ipv4.sin_family = AF_UNSPEC;
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv4, (socklen_t)sizeof(ipv4), &endpoint
    ));
    chaos_net_test_set_ipv4(&ipv4, "127.0.0.1", 8080U);
    g_stub_getsockopt_result = -1;
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
    ));
    (void)memset(&unix_address, 0, sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    (void)snprintf(unix_address.sun_path, sizeof(unix_address.sun_path), "%s", "/tmp/chaos.sock");
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&unix_address, (socklen_t)sizeof(unix_address), &endpoint
    ));
    g_stub_getsockopt_result = 0;

    g_stub_getsockname_result = -1;
    assert(!chaos_net_endpoint_from_local_fd(7, &endpoint));
    g_stub_getsockname_result = 0;
    assert(!chaos_net_endpoint_from_local_fd(7, NULL));

    g_stub_getpeername_result = -1;
    assert(!chaos_net_endpoint_from_peer_fd(7, &endpoint));
    g_stub_getpeername_result = 0;
    assert(!chaos_net_endpoint_from_peer_fd(7, NULL));

    assert(chaos_net_endpoint_from_socket_spec(AF_INET, SOCK_STREAM, 0, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);
    assert(endpoint.port == 0U);
    assert(endpoint.wildcard_host == 1);
    assert(chaos_net_endpoint_from_socket_spec(AF_INET, SOCK_DGRAM, 0, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP4);
    assert(chaos_net_endpoint_from_socket_spec(AF_INET6, SOCK_STREAM, 0, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP6);
#ifdef SOCK_NONBLOCK
    assert(chaos_net_endpoint_from_socket_spec(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0, &endpoint));
#else
    assert(chaos_net_endpoint_from_socket_spec(AF_INET6, SOCK_DGRAM, 0, &endpoint));
#endif
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP6);
    assert(endpoint.wildcard_host == 1);
    assert(!chaos_net_endpoint_from_socket_spec(AF_INET6, SOCK_RAW, 0, &endpoint));
    assert(chaos_net_endpoint_from_socket_spec(AF_UNIX, SOCK_STREAM, 0, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strcmp(endpoint.value.text, "*") == 0);
    assert(!chaos_net_endpoint_from_socket_spec(AF_UNSPEC, SOCK_STREAM, 0, &endpoint));
    assert(!chaos_net_endpoint_from_socket_spec(AF_INET, SOCK_RAW, 0, &endpoint));
    assert(!chaos_net_endpoint_from_socket_spec(AF_INET, SOCK_STREAM, 0, NULL));

    g_stub_getpeername_result = -1;
    g_stub_socket_type = SOCK_STREAM;
    (void)memcpy(&g_stub_sockname_storage, &ipv4, sizeof(ipv4));
    g_stub_sockname_length = (socklen_t)sizeof(ipv4);
    assert(chaos_net_endpoint_from_activity_fd(7, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);
    g_stub_getsockname_result = -1;
    g_stub_getpeername_result = 0;
    assert(chaos_net_endpoint_from_activity_fd(7, &endpoint));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);
    g_stub_getpeername_result = -1;
    assert(!chaos_net_endpoint_from_activity_fd(7, &endpoint));
    g_stub_getsockname_result = 0;
    assert(!chaos_net_endpoint_from_activity_fd(7, NULL));
}

int main(void)
{
    test_selector_parsing_and_matching();
    test_endpoint_resolution_from_sockaddr_and_fd();
    return 0;
}
