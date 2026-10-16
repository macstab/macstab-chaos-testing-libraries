/**
 * @file chaos_dns_owned.c
 * @brief Address lists libchaos-dns builds itself, and their release.
 */

#include "chaos_dns_owned.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/** @brief One allocation: the nodes, then their addresses, then the canonical name. */
typedef struct chaos_dns_owned_block
{
    size_t count;
    struct addrinfo *first; /**< nodes[0]: the block holds nodes [first, first + count). */
} chaos_dns_owned_block_t;

/** @brief Blocks alive, guarded by a spin lock held only for a scan of the table. */
static chaos_dns_owned_block_t *g_chaos_dns_owned[CHAOS_DNS_MAX_OWNED];
static volatile int g_chaos_dns_owned_lock = 0;

static void chaos_dns_owned_acquire(void)
{
    while (__sync_lock_test_and_set(&g_chaos_dns_owned_lock, 1) != 0)
    {
    }
}

static void chaos_dns_owned_release(void)
{
    __sync_lock_release(&g_chaos_dns_owned_lock);
}

/** @brief Index of the block @p node lies in; -1. Call with the lock held. */
static int chaos_dns_owned_find(const struct addrinfo *node)
{
    size_t index;

    for (index = 0U; index < CHAOS_DNS_MAX_OWNED; ++index)
    {
        const chaos_dns_owned_block_t *block = g_chaos_dns_owned[index];

        if (block != NULL && (uintptr_t)node >= (uintptr_t)block->first &&
            (uintptr_t)node < (uintptr_t)(block->first + block->count))
        {
            return (int)index;
        }
    }
    return -1;
}

struct addrinfo *
chaos_dns_owned_copy(struct addrinfo *const *lists, size_t count, const char *canonname)
{
    const size_t name_size = canonname != NULL ? strlen(canonname) + 1U : 0U;
    chaos_dns_owned_block_t *block;
    struct addrinfo *nodes;
    struct sockaddr_storage *addresses;
    const struct addrinfo *node;
    size_t total = 0U;
    size_t index;
    size_t list;

    for (list = 0U; list < count; ++list)
    {
        for (node = lists[list]; node != NULL; node = node->ai_next)
        {
            ++total;
        }
    }
    if (total == 0U)
    {
        return NULL;
    }
    block = malloc(sizeof(*block) + total * (sizeof(*nodes) + sizeof(*addresses)) + name_size);
    if (block == NULL)
    {
        return NULL;
    }
    /* struct addrinfo and sockaddr_storage keep the alignment malloc() gave. */
    nodes = (struct addrinfo *)(block + 1);
    addresses = (struct sockaddr_storage *)(nodes + total);
    block->count = total;
    block->first = nodes;

    index = 0U;
    for (list = 0U; list < count; ++list)
    {
        for (node = lists[list]; node != NULL; node = node->ai_next)
        {
            const size_t length = node->ai_addrlen <= sizeof(addresses[index])
                                      ? (size_t)node->ai_addrlen
                                      : sizeof(addresses[index]);

            nodes[index] = *node;
            memset(&addresses[index], 0, sizeof(addresses[index]));
            if (node->ai_addr != NULL)
            {
                memcpy(&addresses[index], node->ai_addr, length);
            }
            nodes[index].ai_addr =
                node->ai_addr != NULL ? (struct sockaddr *)&addresses[index] : NULL;
            nodes[index].ai_addrlen = (socklen_t)length;
            nodes[index].ai_canonname = NULL;
            nodes[index].ai_next = index + 1U < total ? &nodes[index + 1U] : NULL;
            ++index;
        }
    }
    if (canonname != NULL)
    {
        nodes[0].ai_canonname = memcpy((char *)(addresses + total), canonname, name_size);
    }

    chaos_dns_owned_acquire();
    for (index = 0U; index < CHAOS_DNS_MAX_OWNED && g_chaos_dns_owned[index] != NULL; ++index)
    {
    }
    if (index == CHAOS_DNS_MAX_OWNED)
    {
        chaos_dns_owned_release();
        free(block);
        return NULL;
    }
    g_chaos_dns_owned[index] = block;
    chaos_dns_owned_release();
    return nodes;
}

int chaos_dns_owned_contains(const struct addrinfo *node)
{
    int found;

    chaos_dns_owned_acquire();
    found = chaos_dns_owned_find(node) >= 0;
    chaos_dns_owned_release();
    return found;
}

int chaos_dns_owned_free(const struct addrinfo *node)
{
    chaos_dns_owned_block_t *block = NULL;
    int index;

    chaos_dns_owned_acquire();
    index = chaos_dns_owned_find(node);
    if (index >= 0)
    {
        block = g_chaos_dns_owned[index];
        g_chaos_dns_owned[index] = NULL;
    }
    chaos_dns_owned_release();
    free(block);
    return block != NULL;
}
