#ifndef CHAOS_NET_ENDPOINT_H
#define CHAOS_NET_ENDPOINT_H

#include "chaos_net_config.h"

int chaos_net_endpoint_parse_selector(const char *text, chaos_net_endpoint_t *endpoint);
int chaos_net_endpoint_matches(
    const chaos_net_endpoint_t *selector,
    const chaos_net_endpoint_t *endpoint,
    unsigned int *rank_out
);
int chaos_net_endpoint_from_sockaddr_fd(
    int fd, const struct sockaddr *address, socklen_t address_length, chaos_net_endpoint_t *endpoint
);
int chaos_net_endpoint_from_socket_spec(
    int domain, int type, int protocol, chaos_net_endpoint_t *endpoint
);
int chaos_net_endpoint_from_activity_fd(int fd, chaos_net_endpoint_t *endpoint);
int chaos_net_endpoint_from_local_fd(int fd, chaos_net_endpoint_t *endpoint);
int chaos_net_endpoint_from_peer_fd(int fd, chaos_net_endpoint_t *endpoint);

#endif
