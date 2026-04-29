#include "chaos_domain_stub.h"

#include <stddef.h>

/*
 * The stub libraries intentionally do almost nothing today. Keeping the domain
 * metadata in volatile storage makes the constructor path explicit and gives
 * the future real runtimes a stable place to grow from.
 */
static volatile const char *g_chaos_stub_last_library = NULL;
static volatile const char *g_chaos_stub_last_config = NULL;

void chaos_domain_stub_init(const chaos_domain_stub_descriptor_t *descriptor)
{
    if (descriptor == NULL)
    {
        return;
    }

    g_chaos_stub_last_library = descriptor->library_name;
    g_chaos_stub_last_config = descriptor->config_path;
}
