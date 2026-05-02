/**
 * @file chaos_domain_stub.h
 * @brief Lightweight constructor scaffold for not-yet-implemented domain preload libraries.
 *
 * The fault-injection suite builds one `.so` per fault domain (IO, NET, DNS, MEMORY,
 * PROCESS, TIME). Each library must register a `__attribute__((constructor))` function
 * that resolves real function pointers via `dlsym(RTLD_NEXT, ...)` before any caller
 * can reach the wrappers. Domains that do not yet have their own interception logic use
 * this common scaffold so the constructor path is always present and the build remains
 * valid even for stub-only libraries.
 *
 * Scope and invariants:
 * - The descriptor struct is a value type; ownership of the pointed-to strings remains
 *   with the caller. The strings must have static or program lifetime (they are stored
 *   in `volatile` globals).
 * - A NULL descriptor passed to `chaos_domain_stub_init()` is a deliberate no-op; the
 *   globals retain their previous (typically NULL) values.
 * - This header does not pull in any system headers itself; callers are responsible for
 *   including what they need.
 *
 * What is NOT provided here:
 * - Any PRNG, TLS guard, config subsystem, or real-function-pointer table. Those belong
 *   to the per-domain runtime headers once a domain is fully implemented.
 */

#ifndef CHAOS_DOMAIN_STUB_H
#define CHAOS_DOMAIN_STUB_H

/**
 * @brief Descriptor carrying the identity of a stub domain preload library.
 *
 * Populated by a domain's constructor and passed to `chaos_domain_stub_init()`.
 * Both fields are expected to point to string literals with static storage duration.
 *
 * @var chaos_domain_stub_descriptor_t::library_name
 *      Human-readable name of the preload library (e.g. "libchaos-net"). Used for
 *      diagnostic purposes and to identify which constructor ran.
 * @var chaos_domain_stub_descriptor_t::config_path
 *      Path at which the domain's configuration file will be searched when the real
 *      interception logic is implemented. Stored now so the eventual runtime can read
 *      it from the same global rather than re-specifying the path.
 */
typedef struct chaos_domain_stub_descriptor
{
    const char *library_name;
    const char *config_path;
} chaos_domain_stub_descriptor_t;

/**
 * @brief Store domain identity metadata during library constructor execution.
 *
 * Called from the domain's `__attribute__((constructor))` function. Copies the
 * string pointers from @p descriptor into `volatile` module-level globals so the
 * information survives potential reordering by the optimizer.
 *
 * @param descriptor  Pointer to a descriptor with static-lifetime string members.
 *                    If NULL, the function returns immediately without modifying state.
 *
 * Misuse risk: passing a descriptor whose string members point into stack-allocated
 * storage causes undefined behaviour once that stack frame is released. Always use
 * string literals or `static` arrays.
 */
void chaos_domain_stub_init(const chaos_domain_stub_descriptor_t *descriptor);

#endif
