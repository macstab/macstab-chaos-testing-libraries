#include "chaos_net_endpoint.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

static int chaos_net_parse_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || port == NULL || *text == '\0')
    {
        return 0;
    }

    value = strtoul(text, &end, 10);
    if (*end != '\0' || value > 65535UL)
    {
        return 0;
    }

    *port = (uint16_t)value;
    return 1;
}

static int chaos_net_parse_ipv4_selector(
    const char *body, chaos_net_endpoint_kind_t kind, chaos_net_endpoint_t *endpoint
)
{
    const char *port_text;
    size_t host_len;
    char host[INET_ADDRSTRLEN];

    port_text = strrchr(body, ':');
    if (port_text == NULL || port_text == body)
    {
        return 0;
    }

    host_len = (size_t)(port_text - body);
    if (host_len == 1U && body[0] == '*')
    {
        endpoint->wildcard_host = 1;
    }
    else
    {
        if (host_len >= sizeof(host))
        {
            return 0;
        }
        (void)memcpy(host, body, host_len);
        host[host_len] = '\0';
        if (inet_pton(AF_INET, host, &endpoint->value.ipv4) != 1)
        {
            return 0;
        }
    }

    endpoint->kind = kind;
    return chaos_net_parse_port(port_text + 1, &endpoint->port);
}

static int chaos_net_parse_ipv6_selector(
    const char *body, chaos_net_endpoint_kind_t kind, chaos_net_endpoint_t *endpoint
)
{
    const char *port_text;
    char host[INET6_ADDRSTRLEN];
    size_t host_len;

    endpoint->kind = kind;
    if (strcmp(body, "*") == 0)
    {
        return 0;
    }
    if (body[0] == '*')
    {
        if (body[1] != ':')
        {
            return 0;
        }
        endpoint->wildcard_host = 1;
        return chaos_net_parse_port(body + 2, &endpoint->port);
    }
    if (body[0] != '[')
    {
        return 0;
    }

    port_text = strchr(body, ']');
    if (port_text == NULL || port_text[1] != ':')
    {
        return 0;
    }

    host_len = (size_t)(port_text - (body + 1));
    if (host_len == 0U || host_len >= sizeof(host))
    {
        return 0;
    }

    (void)memcpy(host, body + 1, host_len);
    host[host_len] = '\0';
    if (inet_pton(AF_INET6, host, &endpoint->value.ipv6) != 1)
    {
        return 0;
    }

    return chaos_net_parse_port(port_text + 2, &endpoint->port);
}

int chaos_net_endpoint_parse_selector(const char *text, chaos_net_endpoint_t *endpoint)
{
    const char *body;

    if (text == NULL || endpoint == NULL || *text == '\0')
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
    endpoint->selector_len = strlen(text);

    if (strcmp(text, "*") == 0)
    {
        endpoint->kind = CHAOS_NET_ENDPOINT_ANY;
        return 1;
    }
    if (strncmp(text, "tcp4://", 7) == 0)
    {
        return chaos_net_parse_ipv4_selector(text + 7, CHAOS_NET_ENDPOINT_TCP4, endpoint);
    }
    if (strncmp(text, "tcp6://", 7) == 0)
    {
        return chaos_net_parse_ipv6_selector(text + 7, CHAOS_NET_ENDPOINT_TCP6, endpoint);
    }
    if (strncmp(text, "udp4://", 7) == 0)
    {
        return chaos_net_parse_ipv4_selector(text + 7, CHAOS_NET_ENDPOINT_UDP4, endpoint);
    }
    if (strncmp(text, "udp6://", 7) == 0)
    {
        return chaos_net_parse_ipv6_selector(text + 7, CHAOS_NET_ENDPOINT_UDP6, endpoint);
    }
    if (strncmp(text, "unix://", 7) == 0)
    {
        body = text + 7;
        if (*body == '\0' || strlen(body) >= sizeof(endpoint->value.text))
        {
            return 0;
        }
        endpoint->kind = CHAOS_NET_ENDPOINT_UNIX;
        (void)memcpy(endpoint->value.text, body, strlen(body) + 1U);
        return 1;
    }
    return 0;
}

int chaos_net_endpoint_matches(
    const chaos_net_endpoint_t *selector,
    const chaos_net_endpoint_t *endpoint,
    unsigned int *rank_out
)
{
    unsigned int rank = 0U;

    if (rank_out != NULL)
    {
        *rank_out = 0U;
    }
    if (selector == NULL || endpoint == NULL)
    {
        return 0;
    }
    if (selector->kind == CHAOS_NET_ENDPOINT_ANY)
    {
        rank = 1U;
    }
    else if (selector->kind == CHAOS_NET_ENDPOINT_UNIX && endpoint->kind == CHAOS_NET_ENDPOINT_UNIX)
    {
        if (strcmp(selector->value.text, "*") == 0)
        {
            rank = 2U;
        }
        else
        {
            if (strcmp(selector->value.text, endpoint->value.text) != 0)
            {
                return 0;
            }
            rank = 4U;
        }
    }
    else if (selector->kind == endpoint->kind)
    {
        switch (selector->kind)
        {
        case CHAOS_NET_ENDPOINT_TCP4:
        case CHAOS_NET_ENDPOINT_UDP4:
            if (selector->port != endpoint->port)
            {
                return 0;
            }
            if (selector->wildcard_host != 0)
            {
                rank = 2U;
                break;
            }
            if (memcmp(
                    &selector->value.ipv4, &endpoint->value.ipv4, sizeof(selector->value.ipv4)
                ) != 0)
            {
                return 0;
            }
            rank = 3U;
            break;
        case CHAOS_NET_ENDPOINT_TCP6:
        case CHAOS_NET_ENDPOINT_UDP6:
            if (selector->port != endpoint->port)
            {
                return 0;
            }
            if (selector->wildcard_host != 0)
            {
                rank = 2U;
                break;
            }
            if (memcmp(
                    &selector->value.ipv6, &endpoint->value.ipv6, sizeof(selector->value.ipv6)
                ) != 0)
            {
                return 0;
            }
            rank = 3U;
            break;
        default:
            return 0;
        }
    }
    else
    {
        return 0;
    }

    if (rank_out != NULL)
    {
        *rank_out = rank;
    }
    return rank != 0U;
}

int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
)
{
    (void)protocol;

    if (endpoint == NULL)
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
#ifdef SOCK_CLOEXEC
    type &= ~SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    type &= ~SOCK_NONBLOCK;
#endif
    if (domain == AF_INET)
    {
        if (type == SOCK_STREAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_TCP4;
            endpoint->wildcard_host = 1;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_UDP4;
            endpoint->wildcard_host = 1;
            return 1;
        }
        return 0;
    }
    if (domain == AF_INET6)
    {
        if (type == SOCK_STREAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_TCP6;
            endpoint->wildcard_host = 1;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            endpoint->kind = CHAOS_NET_ENDPOINT_UDP6;
            endpoint->wildcard_host = 1;
            return 1;
        }
        return 0;
    }
    if (domain == AF_UNIX)
    {
        endpoint->kind = CHAOS_NET_ENDPOINT_UNIX;
        (void)memcpy(endpoint->value.text, "*", 2U);
        return 1;
    }

    return 0;
}

int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    if (endpoint == NULL)
    {
        return 0;
    }

    if (chaos_net_endpoint_from_local_fd(fd, endpoint))
    {
        return 1;
    }
    return chaos_net_endpoint_from_peer_fd(fd, endpoint);
}

static int
chaos_net_endpoint_kind_from_socket(int fd, sa_family_t family, chaos_net_endpoint_kind_t *kind)
{
    int type = 0;
    socklen_t type_len = (socklen_t)sizeof(type);
    int previous;

    if (kind == NULL || g_chaos_net_real_getsockopt == NULL)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    if (g_chaos_net_real_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) != 0)
    {
        chaos_net_leave_internal(previous);
        return 0;
    }
    chaos_net_leave_internal(previous);

#ifdef SOCK_CLOEXEC
    type &= ~SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
    type &= ~SOCK_NONBLOCK;
#endif
    if (family == AF_INET)
    {
        if (type == SOCK_STREAM)
        {
            *kind = CHAOS_NET_ENDPOINT_TCP4;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            *kind = CHAOS_NET_ENDPOINT_UDP4;
            return 1;
        }
        return 0;
    }
    if (family == AF_INET6)
    {
        if (type == SOCK_STREAM)
        {
            *kind = CHAOS_NET_ENDPOINT_TCP6;
            return 1;
        }
        if (type == SOCK_DGRAM)
        {
            *kind = CHAOS_NET_ENDPOINT_UDP6;
            return 1;
        }
        return 0;
    }
    if (family == AF_UNIX)
    {
        *kind = CHAOS_NET_ENDPOINT_UNIX;
        return 1;
    }

    return 0;
}

static int chaos_net_endpoint_from_sockaddr(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    const struct sockaddr_in *ipv4;
    const struct sockaddr_in6 *ipv6;
    const struct sockaddr_un *unix_address;

    if (address == NULL || endpoint == NULL || address_length < (socklen_t)sizeof(sa_family_t))
    {
        return 0;
    }

    (void)memset(endpoint, 0, sizeof(*endpoint));
    switch (address->sa_family)
    {
    case AF_INET:
        if (address_length < (socklen_t)sizeof(*ipv4))
        {
            return 0;
        }
        ipv4 = (const struct sockaddr_in *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_INET, &endpoint->kind))
        {
            return 0;
        }
        endpoint->port = ntohs(ipv4->sin_port);
        endpoint->value.ipv4 = ipv4->sin_addr;
        return 1;
    case AF_INET6:
        if (address_length < (socklen_t)sizeof(*ipv6))
        {
            return 0;
        }
        ipv6 = (const struct sockaddr_in6 *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_INET6, &endpoint->kind))
        {
            return 0;
        }
        endpoint->port = ntohs(ipv6->sin6_port);
        endpoint->value.ipv6 = ipv6->sin6_addr;
        return 1;
    case AF_UNIX:
        unix_address = (const struct sockaddr_un *)address;
        if (!chaos_net_endpoint_kind_from_socket(fd, AF_UNIX, &endpoint->kind))
        {
            return 0;
        }
        if (unix_address->sun_path[0] == '\0')
        {
            return 0;
        }
        if (strlen(unix_address->sun_path) >= sizeof(endpoint->value.text))
        {
            return 0;
        }
        (void
        )memcpy(endpoint->value.text, unix_address->sun_path, strlen(unix_address->sun_path) + 1U);
        return 1;
    default:
        return 0;
    }
}

int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
)
{
    return chaos_net_endpoint_from_sockaddr(fd, address, address_length, endpoint);
}

int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;

    if (endpoint == NULL || g_chaos_net_real_getsockname == NULL)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getsockname(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint
    );
}

int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint)
{
    struct sockaddr_storage storage;
    socklen_t address_length = (socklen_t)sizeof(storage);
    int previous;
    int rc;

    if (endpoint == NULL || g_chaos_net_real_getpeername == NULL)
    {
        return 0;
    }

    previous = chaos_net_enter_internal();
    rc = g_chaos_net_real_getpeername(fd, (struct sockaddr *)&storage, &address_length);
    chaos_net_leave_internal(previous);
    if (rc != 0)
    {
        return 0;
    }

    return chaos_net_endpoint_from_sockaddr(
        fd, (const struct sockaddr *)&storage, address_length, endpoint
    );
}
