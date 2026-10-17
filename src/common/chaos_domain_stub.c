/**
 * @file chaos_domain_stub.c
 * @brief Records the identity of a domain library from its constructor.
 *
 * @details
 * Not compiled into any target: no Makefile rule builds this file and no library calls
 * chaos_domain_stub_init(). All six libraries (`libchaos-io`, `-net`, `-dns`, `-time`,
 * `-memory`, `-process`) have their own runtime and constructor. The file is kept as the
 * original scaffold; see chaos_domain_stub.h.
 *
 * The two globals are `volatile` because they are written and never read: without the
 * qualifier the compiler may drop both stores as dead, and the constructor would leave
 * no trace in an optimised binary.
 */

#include "chaos_domain_stub.h"

#include <stddef.h>

/**
 * @brief Library name of the last chaos_domain_stub_init() call; NULL before the first.
 *
 * `volatile` keeps the write-only store from being eliminated. The pointer is stored,
 * not copied, so it must point to storage that lives as long as the process.
 */
static volatile const char *g_chaos_stub_last_library = NULL;

/**
 * @brief Rule-file path of the last chaos_domain_stub_init() call; NULL before the first.
 *
 * Same lifetime and `volatile` contract as g_chaos_stub_last_library.
 */
static volatile const char *g_chaos_stub_last_config = NULL;

/**
 * @brief Stores the library name and rule-file path of @p descriptor.
 *
 * Intended caller: a domain's `__attribute__((constructor))` function, at load time
 * and therefore on one thread. The globals are written without synchronisation and
 * are not safe to update from several threads at once.
 *
 * @param descriptor  Descriptor whose two string pointers are stored, not copied; they
 *                    must stay valid for the life of the process. NULL is a no-op and
 *                    leaves the previous values in place.
 */
void chaos_domain_stub_init(const chaos_domain_stub_descriptor_t *descriptor)
{
    if (descriptor == NULL)
    {
        return;
    }

    g_chaos_stub_last_library = descriptor->library_name;
    g_chaos_stub_last_config = descriptor->config_path;
}
