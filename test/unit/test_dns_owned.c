/**
 * @file test_dns_owned.c
 * @brief Unit tests for the registry of addrinfo lists libchaos-dns allocates itself.
 *
 * @details
 * Unit under test: `src/dns/chaos_dns_owned.c`. An OVERRIDE result is one allocation of ours
 * holding the nodes of several real getaddrinfo() calls; the interposed freeaddrinfo() must
 * recognise it through whichever node the caller holds (SHUFFLE may have moved any node to the
 * head) and free() it instead of passing it to the real function. The suite proves:
 * - a copy concatenates every node of every input list in order, each node owning its own
 *   `sockaddr_storage`; the canonical name sits on the first node only; an `ai_addrlen` above
 *   `sizeof(struct sockaddr_storage)` is clamped to it and a NULL `ai_addr` stays NULL;
 * - membership is an exact address-range test over the single allocation: every node of the
 *   copy is recognised, the byte before node 0 and the slot after the last node are not, and
 *   caller-owned (real) nodes never are;
 * - freeing through any node releases the whole block exactly once (a second free returns 0);
 * - zero nodes, a failed `malloc()`, or a registry holding `CHAOS_DNS_MAX_OWNED` (256) blocks
 *   yield NULL (the OVERRIDE path then returns EAI_MEMORY).
 *
 * Seams: the source is compiled into this file with `malloc` macro-redirected to
 * `test_malloc()`, which returns NULL while `g_fail_malloc` is set. The input lists are stack
 * arrays, so no real resolver runs.
 */

#include <stddef.h>
#include <stdlib.h>

static int g_fail_malloc = 0;
static void *test_malloc(size_t size)
{
    return g_fail_malloc ? NULL : malloc(size);
}
#define malloc test_malloc
#include "../../src/dns/chaos_dns_owned.c"
#undef malloc

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>

int main(void)
{
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    struct sockaddr_storage oversized;
    struct addrinfo first[2];
    struct addrinfo second[2];
    struct addrinfo *lists[2];
    struct addrinfo *copy;
    struct addrinfo *copies[CHAOS_DNS_MAX_OWNED];
    size_t index;

    memset(&v4, 0, sizeof(v4));
    v4.sin_family = AF_INET;
    v4.sin_addr.s_addr = htonl(0x7f000001U);
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    memset(first, 0, sizeof(first));
    memset(second, 0, sizeof(second));
    first[0].ai_family = AF_INET;
    first[0].ai_addr = (struct sockaddr *)&v4;
    first[0].ai_addrlen = sizeof(v4);
    first[0].ai_canonname = (char *)"real";
    first[0].ai_next = &first[1];
    first[1].ai_family = AF_INET;
    first[1].ai_addr = NULL; /* must stay NULL in the copy */
    second[0].ai_family = AF_INET6;
    second[0].ai_addr = (struct sockaddr *)&v6;
    second[0].ai_addrlen = sizeof(v6);
    second[0].ai_next = &second[1];
    second[1].ai_family = AF_INET6;
    second[1].ai_addr = (struct sockaddr *)&oversized;
    second[1].ai_addrlen = (socklen_t)(sizeof(oversized) + 16U); /* must clamp to storage */
    memset(&oversized, 0, sizeof(oversized));
    lists[0] = first;
    lists[1] = second;

    copy = chaos_dns_owned_copy(lists, 2U, "name.test");
    assert(copy != NULL);
    assert(strcmp(copy->ai_canonname, "name.test") == 0);
    assert(
        copy->ai_addr != first[0].ai_addr &&
        ((struct sockaddr_in *)copy->ai_addr)->sin_addr.s_addr == v4.sin_addr.s_addr
    );
    assert(copy->ai_next->ai_canonname == NULL && copy->ai_next->ai_addr == NULL);
    assert(copy->ai_next->ai_next->ai_family == AF_INET6);
    assert(copy->ai_next->ai_next->ai_next->ai_addrlen == sizeof(struct sockaddr_storage));
    assert(copy->ai_next->ai_next->ai_next->ai_next == NULL);
    assert(chaos_dns_owned_contains(copy->ai_next->ai_next));
    assert(!chaos_dns_owned_contains(first));
    /* Membership is a half-open range [first, first + count): an off-by-one either way would
     * make freeaddrinfo() free a caller's neighbouring allocation or leak ours. */
    assert(!chaos_dns_owned_contains((const struct addrinfo *)((uintptr_t)copy - 1U)));
    assert(chaos_dns_owned_contains(copy + 3));
    assert(!chaos_dns_owned_contains(copy + 4));
    assert(chaos_dns_owned_free(copy->ai_next) == 1); /* interior node frees all */
    assert(!chaos_dns_owned_contains(copy) && chaos_dns_owned_free(copy) == 0);

    /* No canonical name allocates no name bytes; an empty input and a failed malloc() both
     * return NULL rather than an empty or partial list. */
    copy = chaos_dns_owned_copy(lists, 1U, NULL);
    assert(copy != NULL && copy->ai_canonname == NULL && chaos_dns_owned_free(copy) == 1);
    lists[0] = NULL;
    assert(chaos_dns_owned_copy(lists, 1U, NULL) == NULL);
    lists[0] = first;
    g_fail_malloc = 1;
    assert(chaos_dns_owned_copy(lists, 1U, NULL) == NULL);
    g_fail_malloc = 0;

    /* With all CHAOS_DNS_MAX_OWNED slots taken the copy is freed and NULL returned: an
     * unregistered block could never be recognised by freeaddrinfo() and would leak. */
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        copies[index] = chaos_dns_owned_copy(lists, 1U, NULL);
        assert(copies[index] != NULL);
    }
    assert(chaos_dns_owned_copy(lists, 1U, NULL) == NULL);
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        assert(chaos_dns_owned_free(copies[index]) == 1);
    }
    return 0;
}
