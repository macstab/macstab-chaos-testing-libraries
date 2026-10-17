/**
 * @file chaos_dns_owned.c
 * @brief Registry of the address lists libchaos-dns allocates itself (OVERRIDE).
 *
 * @details Each list is one malloc() block: a header, the nodes, one sockaddr_storage
 * per node, then the canonical name. Up to CHAOS_DNS_MAX_OWNED (256) blocks are alive at
 * once, kept in a fixed table guarded by a spin lock that is held only for a table scan
 * (at most 256 entries, no allocation, no system call). A node belongs to a block when
 * its address lies inside the block's node array, so any node of a shuffled list finds
 * its block.
 *
 * Thread-safety: all three functions may run concurrently. The spin lock is not
 * async-signal-safe: a signal handler that calls getaddrinfo or freeaddrinfo while its
 * thread holds the lock would spin forever (POSIX does not make getaddrinfo or
 * freeaddrinfo async-signal-safe either).
 */

#include "chaos_dns_owned.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/** @brief Header of one allocation: the nodes, then their addresses, then the name. */
typedef struct chaos_dns_owned_block
{
    size_t count;
    struct addrinfo *first; /**< nodes[0]: the block holds nodes [first, first + count). */
} chaos_dns_owned_block_t;

/** @brief Blocks alive; slots are NULL when free. Guarded by g_chaos_dns_owned_lock. */
static chaos_dns_owned_block_t *g_chaos_dns_owned[CHAOS_DNS_MAX_OWNED];
static volatile int g_chaos_dns_owned_lock = 0;

/** @brief Takes the table lock; spins without yielding, since holders only scan. */
static void chaos_dns_owned_acquire(void)
{
    while (__sync_lock_test_and_set(&g_chaos_dns_owned_lock, 1) != 0)
    {
    }
}

/** @brief Releases the table lock (release barrier). */
static void chaos_dns_owned_release(void)
{
    __sync_lock_release(&g_chaos_dns_owned_lock);
}

/** @brief Index of the block whose node array contains @p node; -1. Lock held. */
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

/**
 * @brief Copies the nodes of @p lists into one registered block (contract in the header).
 *
 * @details Each node keeps its family, socket type, protocol and flags; its address is
 * copied into the block (truncated to sizeof(struct sockaddr_storage)), ai_canonname is
 * cleared except on the first node, and ai_next links the copies in order. The block is
 * registered last; a full table frees it and returns NULL.
 */
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

/** @brief Whether @p node lies in a registered block (contract in the header). */
int chaos_dns_owned_contains(const struct addrinfo *node)
{
    int found;

    chaos_dns_owned_acquire();
    found = chaos_dns_owned_find(node) >= 0;
    chaos_dns_owned_release();
    return found;
}

/**
 * @brief Unregisters and frees the block holding @p node (contract in the header).
 *
 * @details free() runs after the lock is released. NULL, or a node of a real result,
 * returns 0 and frees nothing.
 */
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
