/**
 * @file chaos_bench_register.c
 * @brief Global descriptor registry — populated by per-benchmark
 *        constructors, walked once by the runner.
 *
 * @details
 * The registry is a singly-linked list of `chaos_bench_descriptor_t *`,
 * with insertion at the head.  Each `CHAOS_BENCH(...)` macro emits a
 * `__attribute__((constructor))` function that calls
 * @ref chaos_bench_register; constructors execute in unspecified order
 * but always before `main`, so by the time the runner queries the list
 * every benchmark in the binary is registered.
 *
 * **Why a linked list and not a `__attribute__((section))` set?**
 *  - Section-based registration (the GCC `__start_<sec> / __stop_<sec>`
 *    idiom) is slightly more elegant but depends on the host linker
 *    producing the section-bound symbols.  The Make/Ld combo we ship
 *    with covers GNU ld and lld, but the linker on a Mac dev box
 *    produces results that diverge under `--gc-sections`.  A linked
 *    list is portable across every linker we'll ever care about and
 *    incurs one constructor call per benchmark — negligible.
 *  - The registry is consulted exactly once per process (in `main`),
 *    so list-vs-array scan cost is irrelevant.
 *
 * **Thread-safety.** Not thread-safe.  Constructors run before any
 * thread other than the implicit main thread exists, and the registry
 * is read-only after `main` begins.  No locking is needed.
 */

#include "chaos_bench_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Registry head pointer; modified only by `chaos_bench_register`.
 */
static chaos_bench_descriptor_t *g_chaos_bench_registry_head = NULL;

/**
 * @brief Registered descriptor count; bounded by
 *        @ref CHAOS_BENCH_MAX_REGISTERED.
 */
static size_t g_chaos_bench_registry_count = 0U;

void chaos_bench_register(chaos_bench_descriptor_t *desc)
{
    if (desc == NULL)
    {
        /* Defensive: a benchmark binary that registers a NULL descriptor
         * is a build-system bug; abort loudly so it surfaces immediately. */
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
 * @brief Internal: prints all registered names, one per line.  Used by
 *        the runner's `--list` flag.
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
