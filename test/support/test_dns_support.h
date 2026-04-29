#ifndef CHAOS_DNS_TEST_SUPPORT_H
#define CHAOS_DNS_TEST_SUPPORT_H

#include "../../src/dns/chaos_dns_internal.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHAOS_DNS_DEFINE_TEST_GLOBALS()                                                            \
    chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;                                  \
    chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;                                  \
    chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;                                \
    __thread int g_chaos_dns_tls_guard = 0;                                                        \
    __thread uint64_t g_chaos_dns_tls_prng_state = 0U;                                             \
    uint64_t g_chaos_dns_process_seed = 1U

static inline void chaos_dns_test_reset_runtime(void)
{
    g_chaos_dns_real_getaddrinfo = NULL;
    g_chaos_dns_real_getnameinfo = NULL;
    g_chaos_dns_real_freeaddrinfo = NULL;
    g_chaos_dns_tls_guard = 0;
    g_chaos_dns_tls_prng_state = 0U;
    g_chaos_dns_process_seed = 1U;
}

static inline void *chaos_dns_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_DNS_TEST_DLSYM_RESULT(type, function)                                                \
    chaos_dns_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
