/**
 * @file chaos_domain_stub.c
 * @brief Implementation of the domain-stub constructor scaffold.
 *
 * Stores the library identity metadata supplied by a domain constructor into
 * `volatile` module-level globals. The `volatile` qualifier is intentional: it
 * prevents the compiler from treating these write-only assignments as dead stores
 * and eliding them, which would make the constructor path invisible in a stripped
 * binary even though it still ran.
 *
 * The stub libraries intentionally do almost nothing today. Keeping the domain
 * metadata in volatile storage makes the constructor path explicit and gives the
 * future real runtimes a stable place to grow from.
 *
 * Coverage note: the two storage globals are written once per process via the
 * domain constructor and are never read back in production code. Tests that verify
 * constructor execution check them indirectly through the public API.
 */

#include "chaos_domain_stub.h"

#include <stddef.h>

/**
 * @brief Last library name written by a call to `chaos_domain_stub_init()`.
 *
 * Declared `volatile` so the assignment is not optimised away by the compiler even
 * when the value is never read in the same compilation unit. Initialised to NULL;
 * updated to a static string literal on the first constructor call.
 */
static volatile const char *g_chaos_stub_last_library = NULL;

/**
 * @brief Last config path written by a call to `chaos_domain_stub_init()`.
 *
 * Same lifetime and volatility contract as `g_chaos_stub_last_library`.
 */
static volatile const char *g_chaos_stub_last_config = NULL;

/**
 * @brief Store domain identity metadata from a library constructor.
 *
 * Records @p descriptor->library_name and @p descriptor->config_path in the
 * module-level volatile globals. A NULL @p descriptor is silently ignored so
 * that callers do not need to guard against the degenerate case.
 *
 * Triggering condition: called from a domain's `__attribute__((constructor))`
 * function during `dlopen` / process startup.
 *
 * Observable behaviour: after a non-NULL call, `g_chaos_stub_last_library` and
 * `g_chaos_stub_last_config` hold the corresponding pointer values from the
 * descriptor. Because both fields are `volatile`, the writes are not dead-store
 * eliminated even in optimised builds.
 *
 * @param descriptor  Filled-in descriptor provided by the domain constructor.
 *                    Must remain valid for the lifetime of the process; the pointers
 *                    are stored, not copied.
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
