/**
 * @file test_net_endpoint.c
 * @brief Unit tests for libchaos-net selectors and endpoints: parsing, rank matching, and
 *   endpoint resolution from sockaddrs, descriptors and socket() arguments.
 *
 * @details
 * Unit under test: `src/net/chaos_net_endpoint.c`. The suite proves:
 * - selectors: `*`, `tcp4://`/`udp4://` `HOST:PORT`, `tcp6://`/`udp6://` `[V6]:PORT`,
 *   `*:PORT` for any host, and `unix://PATH` or `unix://\*`; a port must be 0-65535 with
 *   nothing after the digits; any malformed field, a missing port, an unbracketed IPv6 address
 *   and a UNIX path longer than `CHAOS_NET_MAX_TEXT - 1` (255) bytes are rejected;
 * - ranks: UNIX path 4, exact address and port 3, wildcard host with port (or `unix://\*`) 2,
 *   `*` 1; kinds must be equal unless the selector is `*`; no match resets the rank to 0;
 * - endpoints from a sockaddr take the protocol from `getsockopt(SO_TYPE)`; an IPv4-mapped
 *   IPv6 address (`::ffff:0:0/96` only) is IPv4 traffic and matches `tcp4`/`udp4` rules;
 *   a UNIX path is bounded by both `address_len` and `sizeof(sun_path)`, never by a NUL
 *   found past the field; abstract names are shown with `@` for each NUL, as Linux does;
 *   an unnamed socket has an empty name that only wildcards match;
 * - descriptor lookups use the real getsockname/getpeername; the activity endpoint takes the
 *   local address first and the peer only when that fails; without the real functions
 *   (symbols not yet resolved) nothing resolves;
 * - an endpoint from socket() arguments has a wildcard host and port 0 (UNIX: `*`), masks
 *   SOCK_NONBLOCK/SOCK_CLOEXEC, and rejects SOCK_RAW and unknown families.
 *
 * Seams: the source is compiled into this file. `reset_endpoint_stubs()` points the real
 * getsockopt, getsockname and getpeername at local fakes: getsockopt asserts it is asked for
 * `SOL_SOCKET`/`SO_TYPE` and reports `g_stub_socket_type`; getsockname and getpeername copy a
 * prepared sockaddr. Each fake fails with its configured result. No real socket is opened.
 *
 * Out of scope: the wrappers (`test_chaos_net.c`) and rule parsing (`test_net_config.c`).
 */

#include "../support/test_net_support.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

/** @brief Non-zero makes the fake getsockopt fail with this value. */
static int g_stub_getsockopt_result = 0;

/** @brief SO_TYPE the fake getsockopt reports; SOCK_STREAM by default. */
static int g_stub_socket_type = SOCK_STREAM;

/** @brief Non-zero makes the fake getsockname fail with this value. */
static int g_stub_getsockname_result = 0;

/** @brief Non-zero makes the fake getpeername fail with this value. */
static int g_stub_getpeername_result = 0;

/** @brief Local address the fake getsockname reports. */
static struct sockaddr_storage g_stub_sockname_storage;

/** @brief Length of the local address the fake getsockname reports. */
static socklen_t g_stub_sockname_length = 0U;

/** @brief Peer address the fake getpeername reports. */
static struct sockaddr_storage g_stub_peer_storage;

/** @brief Length of the peer address the fake getpeername reports. */
static socklen_t g_stub_peer_length = 0U;

/**
 * @brief Fake real getsockopt: asserts the query is `SOL_SOCKET`/`SO_TYPE`, then reports
 *   `g_stub_socket_type` or fails with `g_stub_getsockopt_result`.
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
 * @brief Fake real getsockname: copies the prepared local address, asserting the caller's
 *   buffer is large enough, or fails with `g_stub_getsockname_result`.
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

/** @brief Fake real getpeername: as the getsockname fake, with the peer address. */
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
 * @brief Restores the runtime globals, points the three real functions at the fakes, and
 *   clears every prepared address and failure.
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
 * @brief Proves every selector form parses, malformed ones are rejected, and matching
 *   returns the documented rank.
 *
 * @details
 * - Each scheme with an exact host and with `*` as host; `unix://PATH` and `unix://\*`.
 * - Ports: NULL, empty, a NULL output, 70000 and "10x" are rejected.
 * - IPv4 bodies need a port and a valid address no longer than `INET_ADDRSTRLEN`; IPv6 bodies
 *   need brackets, a non-empty valid address and `:` before the port.
 * - Matching: 3 for an exact TCP4 or UDP4 endpoint, 2 for a wildcard host (v4 and v6), 1 for
 *   `*`, 4 for an equal UNIX path and 2 for `unix://\*`.
 * - No match: a different path, address, port or kind (ANY and UNIX endpoints against a TCP6
 *   selector), a NULL selector or endpoint, and INVALID kinds, which also reset the rank to 0.
 *   The rank output is optional.
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
 * @brief Proves endpoint resolution from sockaddrs and descriptors, including IPv4-mapped
 *   addresses and every UNIX naming form.
 *
 * @details
 * - The SO_TYPE answer picks TCP or UDP for AF_INET and AF_INET6; a sockaddr one byte short
 *   of its family's size, an unknown family, an unknown socket type and a failing getsockopt
 *   yield no endpoint.
 * - `::ffff:10.1.2.3` becomes TCP4/UDP4 10.1.2.3 so `tcp4://` rules match a dual-stack
 *   socket's IPv4 peers and a `tcp6://` rule on the mapped form does not; the deprecated
 *   IPv4-compatible `::10.1.2.3` stays IPv6.
 * - UNIX: a path, an abstract name (`\0bus\0x` becomes `@bus@x`), a full unterminated
 *   `sun_path` followed in memory by more non-NUL bytes (exactly `sizeof(sun_path)`
 *   characters, no overread), an unnamed socket (`address_len == sizeof(sa_family_t)`, empty
 *   name, only `unix://\*` matches), and an unterminated path bounded by `address_len`.
 * - Local and peer lookups resolve through the fakes, and fail with them or a NULL output.
 * - socket() arguments: wildcard host and port 0, UDP6 with SOCK_NONBLOCK masked off, UNIX as
 *   `*`; SOCK_RAW, AF_UNSPEC and a NULL output are rejected.
 * - The activity lookup falls back between local and peer, failing only when both fail.
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

    {
        chaos_net_endpoint_t selector;

        chaos_net_test_set_ipv6(&ipv6, "::ffff:10.1.2.3", 5432U);
        g_stub_socket_type = SOCK_STREAM;
        assert(chaos_net_endpoint_from_sockaddr_fd(
            7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP4);
        assert(endpoint.port == 5432U);
        assert(endpoint.value.ipv4.s_addr == inet_addr("10.1.2.3"));
        assert(chaos_net_endpoint_parse_selector("tcp4://10.1.2.3:5432", &selector));
        assert(chaos_net_endpoint_matches(&selector, &endpoint, NULL));
        assert(chaos_net_endpoint_parse_selector("tcp6://[::ffff:10.1.2.3]:5432", &selector));
        assert(!chaos_net_endpoint_matches(&selector, &endpoint, NULL));
        g_stub_socket_type = SOCK_DGRAM;
        assert(chaos_net_endpoint_from_sockaddr_fd(
            7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP4);
        chaos_net_test_set_ipv6(&ipv6, "::10.1.2.3", 5432U);
        assert(chaos_net_endpoint_from_sockaddr_fd(
            7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_UDP6);
    }

    (void)memset(&unix_address, 0, sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    (void)snprintf(unix_address.sun_path, sizeof(unix_address.sun_path), "%s", "/tmp/chaos.sock");
    assert(chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&unix_address, (socklen_t)sizeof(unix_address), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strcmp(endpoint.value.text, "/tmp/chaos.sock") == 0);
    {
        chaos_net_endpoint_t selector;

        (void)memset(&unix_address, 0, sizeof(unix_address));
        unix_address.sun_family = AF_UNIX;
        (void)memcpy(unix_address.sun_path, "\0bus\0x", 6U);
        assert(chaos_net_endpoint_from_sockaddr_fd(
            7,
            (const struct sockaddr *)&unix_address,
            (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 6U),
            &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
        assert(strcmp(endpoint.value.text, "@bus@x") == 0);
        assert(chaos_net_endpoint_parse_selector("unix://@bus@x", &selector));
        assert(chaos_net_endpoint_matches(&selector, &endpoint, NULL));
        assert(chaos_net_endpoint_parse_selector("unix://*", &selector));
        assert(chaos_net_endpoint_matches(&selector, &endpoint, NULL));
    }
    /* The bytes after sun_path are non-NUL too: a scan to the first NUL would read past the
     * field and return an oversized path. */
    (void)memset(&long_unix, 0, sizeof(long_unix));
    long_unix.base.sun_family = AF_UNIX;
    (void)memset(long_unix.base.sun_path, 'x', sizeof(long_unix.base.sun_path));
    (void)memset(long_unix.extra, 'x', sizeof(long_unix.extra) - 1U);
    long_unix.extra[sizeof(long_unix.extra) - 1U] = '\0';
    assert(chaos_net_endpoint_from_sockaddr(
        7, (const struct sockaddr *)&long_unix, (socklen_t)sizeof(long_unix), &endpoint
    ));
    assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX);
    assert(strlen(endpoint.value.text) == sizeof(long_unix.base.sun_path));

    /* Unnamed (socketpair(), never bound): every byte past the family is 'x', so reading
     * past address_len would produce a non-empty name. */
    {
        chaos_net_endpoint_t selector;

        (void)memset(&unix_address, 'x', sizeof(unix_address));
        unix_address.sun_family = AF_UNIX;
        assert(chaos_net_endpoint_from_sockaddr(
            7, (const struct sockaddr *)&unix_address, (socklen_t)sizeof(sa_family_t), &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_UNIX && endpoint.value.text[0] == '\0');
        assert(chaos_net_endpoint_parse_selector("unix://*", &selector));
        assert(chaos_net_endpoint_matches(&selector, &endpoint, NULL));
        assert(chaos_net_endpoint_parse_selector("unix:///tmp/a.sock", &selector));
        assert(!chaos_net_endpoint_matches(&selector, &endpoint, NULL));
    }

    /* No terminator, trailing 'x' bytes: address_len alone ends the path. */
    (void)memset(&unix_address, 'x', sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    (void)memcpy(unix_address.sun_path, "/tmp/a.sock", 11U);
    assert(chaos_net_endpoint_from_sockaddr(
        7,
        (const struct sockaddr *)&unix_address,
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 11U),
        &endpoint
    ));
    assert(strcmp(endpoint.value.text, "/tmp/a.sock") == 0);

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

/**
 * @brief Proves the remaining selector rejections, that only `::ffff:0:0/96` is treated as
 *   IPv4, and that descriptor lookups fail before the real functions are resolved.
 *
 * @details Rejected: an empty IPv4 host, a one-character host other than `*`, an unterminated
 * bracket, an IPv6 host longer than its buffer, and a NULL output. A UNIX path of
 * `CHAOS_NET_MAX_TEXT` (256) bytes is rejected and one of 255 accepted (room for the NUL).
 * `2001:db8::1` and `0:0:1::1` stay TCP6 with the address unchanged. A 1-byte sockaddr yields
 * nothing.
 */
static void test_selector_rejections_and_unresolved_lookups(void)
{
    static const char *const not_mapped[] = {"2001:db8::1", "0:0:1::1"};
    chaos_net_endpoint_t selector;
    chaos_net_endpoint_t endpoint;
    struct sockaddr_in6 ipv6;
    char long_selector[7U + CHAOS_NET_MAX_TEXT + 1U];
    char long_ipv6[64];
    size_t index;

    reset_endpoint_stubs();
    assert(!chaos_net_endpoint_parse_selector("tcp4://:80", &selector));
    assert(!chaos_net_endpoint_parse_selector("tcp4://1:80", &selector));
    assert(!chaos_net_endpoint_parse_selector("tcp6://[::1:443", &selector));
    (void)memset(long_ipv6, '1', sizeof(long_ipv6));
    (void)memcpy(long_ipv6, "tcp6://[", 8U);
    (void)memcpy(long_ipv6 + sizeof(long_ipv6) - 5U, "]:80", 5U);
    assert(!chaos_net_endpoint_parse_selector(long_ipv6, &selector));
    assert(!chaos_net_endpoint_parse_selector("tcp4://*:80", NULL));

    (void)memcpy(long_selector, "unix://", 7U);
    (void)memset(long_selector + 7U, 'p', CHAOS_NET_MAX_TEXT);
    long_selector[sizeof(long_selector) - 1U] = '\0';
    assert(!chaos_net_endpoint_parse_selector(long_selector, &selector));
    long_selector[sizeof(long_selector) - 2U] = '\0';
    assert(chaos_net_endpoint_parse_selector(long_selector, &selector));
    assert(strlen(selector.value.text) == CHAOS_NET_MAX_TEXT - 1U);

    g_stub_socket_type = SOCK_STREAM;
    for (index = 0U; index < sizeof(not_mapped) / sizeof(not_mapped[0]); ++index)
    {
        chaos_net_test_set_ipv6(&ipv6, not_mapped[index], 443U);
        assert(chaos_net_endpoint_from_sockaddr_fd(
            7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), &endpoint
        ));
        assert(endpoint.kind == CHAOS_NET_ENDPOINT_TCP6);
        assert(memcmp(&endpoint.value.ipv6, &ipv6.sin6_addr, sizeof(ipv6.sin6_addr)) == 0);
    }
    assert(!chaos_net_endpoint_from_sockaddr_fd(
        7, (const struct sockaddr *)&ipv6, (socklen_t)sizeof(ipv6), NULL
    ));
    assert(!chaos_net_endpoint_from_sockaddr_fd(7, (const struct sockaddr *)&ipv6, 1U, &endpoint));

    g_chaos_net_real_getsockname = NULL;
    g_chaos_net_real_getpeername = NULL;
    assert(!chaos_net_endpoint_from_local_fd(7, &endpoint));
    assert(!chaos_net_endpoint_from_peer_fd(7, &endpoint));
    reset_endpoint_stubs();
}

int main(void)
{
    test_selector_parsing_and_matching();
    test_endpoint_resolution_from_sockaddr_and_fd();
    test_selector_rejections_and_unresolved_lookups();
    return 0;
}
