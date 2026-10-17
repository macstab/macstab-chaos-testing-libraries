/**
 * @file chaos_domain_stub.h
 * @brief Constructor scaffold for a domain library that has no interception logic yet.
 *
 * @details
 * The suite builds one shared object per fault domain. Before a domain had a runtime of
 * its own, this scaffold gave it a constructor that recorded the library name and rule
 * file path, so the library linked and loaded with a real constructor path.
 *
 * Current status: unused. All six libraries (`libchaos-io`, `-net`, `-dns`, `-time`,
 * `-memory`, `-process`) are implemented, none includes this header, and
 * chaos_domain_stub.c is not part of any Makefile target.
 *
 * Contract, should a new domain use it:
 * - The descriptor is a value type; the strings it points to stay owned by the caller
 *   and must have static storage duration, because only the pointers are kept.
 * - chaos_domain_stub_init() with NULL is a no-op.
 * - The scaffold provides no PRNG, re-entrancy guard, rule parser or real-function
 *   table; those belong to the domain's own runtime.
 * - The header includes no system headers.
 */

#ifndef CHAOS_DOMAIN_STUB_H
#define CHAOS_DOMAIN_STUB_H

/**
 * @brief Identity of a domain library, passed from its constructor to
 *        chaos_domain_stub_init().
 *
 * @var chaos_domain_stub_descriptor_t::library_name
 *      Library name for diagnostics, e.g. "libchaos-net". Must be a string literal or
 *      other static storage.
 * @var chaos_domain_stub_descriptor_t::config_path
 *      Rule-file path the domain will read once it has a runtime, e.g.
 *      "/tmp/.chaos-net.conf". Must be a string literal or other static storage.
 */
typedef struct chaos_domain_stub_descriptor
{
    const char *library_name;
    const char *config_path;
} chaos_domain_stub_descriptor_t;

/**
 * @brief Stores the identity in @p descriptor in module-level `volatile` globals.
 *
 * Call it from the domain's `__attribute__((constructor))`. The globals are written
 * without synchronisation, so concurrent calls are not supported.
 *
 * @param descriptor  Descriptor with static-lifetime strings; the pointers are stored,
 *                    not copied. NULL returns at once and changes nothing.
 *
 * Misuse: strings in automatic storage leave dangling pointers once the caller's frame
 * is gone; use string literals or `static` arrays.
 */
void chaos_domain_stub_init(const chaos_domain_stub_descriptor_t *descriptor);

#endif
