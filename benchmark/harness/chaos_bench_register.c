/**
 * @file chaos_bench_register.c
 * @brief Global descriptor registry: filled by per-benchmark ELF constructors, queried by
 *        the runner.
 *
 * @details
 * A singly-linked list of descriptors with head insertion. Every @ref CHAOS_BENCH expansion
 * emits an `__attribute__((constructor))` function that calls @ref chaos_bench_register.
 * Constructors run in unspecified order but all complete before `main`, so the list is
 * complete when the runner queries it.
 *
 * **Why a linked list, not a linker section.**
 *  - The `__attribute__((section))` + `__start_<sec>`/`__stop_<sec>` idiom needs the linker
 *    to synthesise the bound symbols and to keep the section under `--gc-sections`; GNU ld
 *    and lld do, but behaviour differs across linkers (the macOS linker in particular). The
 *    list depends only on constructors, which every supported toolchain implements.
 *  - The cost is one constructor call per benchmark at load time and one linear scan per
 *    process, both outside any timed region.
 *
 * **Thread-safety.** No locking. Constructors run on the main thread before any other thread
 * can exist, and the list is only read after `main` starts.
 */

#include "chaos_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Most recently registered descriptor; written only by `chaos_bench_register`.
 */
static chaos_bench_descriptor_t *g_chaos_bench_registry_head = NULL;

/**
 * @brief Number of registered descriptors; never exceeds @ref CHAOS_BENCH_MAX_REGISTERED.
 */
static size_t g_chaos_bench_registry_count = 0U;

void chaos_bench_register(chaos_bench_descriptor_t *desc)
{
    if (desc == NULL)
    {
        /* A NULL descriptor, a NULL iter or an overflow is a build defect; abort before
         * main so a binary that would silently skip or crash in a benchmark never runs. */
        fprintf(stderr, "chaos_bench: NULL descriptor registration\n");
        abort();
    }
    if (desc->iter == NULL)
    {
        fprintf(stderr,
                "chaos_bench: descriptor '%s' has NULL iter callback\n",
                desc->name != NULL ? desc->name : "<unnamed>");
        abort();
    }
    if (g_chaos_bench_registry_count >= CHAOS_BENCH_MAX_REGISTERED)
    {
        fprintf(stderr,
                "chaos_bench: registry full (%u entries) — rejecting '%s'\n",
                CHAOS_BENCH_MAX_REGISTERED,
                desc->name != NULL ? desc->name : "<unnamed>");
        abort();
    }

    desc->next                     = g_chaos_bench_registry_head;
    g_chaos_bench_registry_head    = desc;
    ++g_chaos_bench_registry_count;
}

chaos_bench_descriptor_t *chaos_bench_registry_find(const char *name)
{
    chaos_bench_descriptor_t *cur;

    if (name == NULL)
    {
        return NULL;
    }
    for (cur = g_chaos_bench_registry_head; cur != NULL; cur = cur->next)
    {
        if (cur->name != NULL && strcmp(cur->name, name) == 0)
        {
            return cur;
        }
    }
    return NULL;
}

/**
 * @brief Prints one `<category>\t<name>` line per registered benchmark to @p out.
 *
 * @details Backs `--list`. Order is reverse registration order, which is unspecified; "?"
 * stands in for a NULL category or name.
 */
void chaos_bench_registry_list(FILE *out)
{
    chaos_bench_descriptor_t *cur;

    for (cur = g_chaos_bench_registry_head; cur != NULL; cur = cur->next)
    {
        fprintf(out, "%s\t%s\n",
                cur->category != NULL ? cur->category : "?",
                cur->name     != NULL ? cur->name     : "?");
    }
}
