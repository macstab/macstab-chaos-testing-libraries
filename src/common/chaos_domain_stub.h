#ifndef CHAOS_DOMAIN_STUB_H
#define CHAOS_DOMAIN_STUB_H

/*
 * Shared scaffold for future domain-specific preload libraries.
 *
 * The repository builds multiple dedicated `.so` files, but only `libchaos-io`
 * currently owns real interception logic. The other libraries reuse this tiny
 * constructor scaffold until their domain-specific wrappers land.
 */

typedef struct chaos_domain_stub_descriptor
{
    const char *library_name;
    const char *config_path;
} chaos_domain_stub_descriptor_t;

void chaos_domain_stub_init(const chaos_domain_stub_descriptor_t *descriptor);

#endif
