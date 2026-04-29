#include "../support/test_net_support.h"

CHAOS_NET_DEFINE_TEST_GLOBALS();

static int g_stub_getsockopt_result = 0;
static int g_stub_socket_type = SOCK_STREAM;
static int g_stub_getsockname_result = 0;
static int g_stub_getpeername_result = 0;
static struct sockaddr_storage g_stub_sockname_storage;
static socklen_t g_stub_sockname_length = 0U;
static struct sockaddr_storage g_stub_peer_storage;
static socklen_t g_stub_peer_length = 0U;

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
