/**
 * @file chaos_dns_owned.h
 * @brief Address lists libchaos-dns builds itself (OVERRIDE), and their release.
 *
 * @details musl allocates each getaddrinfo() result as one reference-counted block
 * and its freeaddrinfo() charges the whole chain to the block of the chain's last
 * node. A list spliced together from several real results (one per OVERRIDE
 * literal) is therefore released wrongly: a leak on every lookup, and a
 * use-after-free once SHUFFLE or LIMIT reorders or cuts it.
 *
 * OVERRIDE instead copies the nodes of its real results into one allocation of its
 * own and releases those results at once. The allocation is registered here, and
 * the interposed freeaddrinfo() frees it when given any of its nodes (SHUFFLE may
 * have made any of them the head). Nodes FILTER or LIMIT drop from such a list are
 * only unlinked; the allocation goes when the list does.
 */

#ifndef CHAOS_DNS_OWNED_H
#define CHAOS_DNS_OWNED_H

#include <netdb.h>
#include <stddef.h>

/** @brief Lists of our own alive at once; OVERRIDE fails with EAI_MEMORY beyond. */
#define CHAOS_DNS_MAX_OWNED 256U

/**
 * @brief Copies the nodes of @p lists into one registered allocation.
 *
 * @param lists      Real getaddrinfo() results, @p count of them; not modified.
 * @param canonname  Name for the first node's ai_canonname, or NULL for none.
 * @return The copy's first node, or NULL (out of memory, or too many alive).
 */
struct addrinfo *
chaos_dns_owned_copy(struct addrinfo *const *lists, size_t count, const char *canonname);

/** @brief Whether @p node belongs to a list of ours. */
int chaos_dns_owned_contains(const struct addrinfo *node);

/**
 * @brief Frees the list of ours @p node belongs to.
 * @return 1 when it was ours and is freed, 0 when it is a real result.
 */
int chaos_dns_owned_free(const struct addrinfo *node);

#endif
