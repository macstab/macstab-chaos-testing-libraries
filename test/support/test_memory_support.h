/**
 * @file test_memory_support.h
 * @brief Memory-domain test globals, reset helper, and dlsym cast utility.
 *
 * Subsystem under test: chaos-memory (LD_PRELOAD memory fault injection via
 *   mmap / munmap / mprotect / madvise interception).
 *
 * This header is included by every unit test that exercises the memory domain.
 * It provides:
 *
 *   1. `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` -- a macro that instantiates all
 *      translation-unit-scoped globals declared `extern` in the production
 *      memory internal header. Must be expanded exactly once per test binary.
 *
 *   2. `chaos_memory_test_reset_runtime()` -- resets all memory runtime globals
 *      to their initial (NULL/zero) state. Call at the start of every test
 *      function that modifies runtime state.
 *
 *   3. `CHAOS_MEMORY_TEST_DLSYM_RESULT(type, function)` -- type-safe conversion
 *      of a typed function pointer to `void *` via `memcpy`, used in dlsym
 *      stubs to map symbol names to test stub functions.
 *
 * The memory domain intercepts six functions: mmap, munmap, mprotect, madvise,
 * nanosleep, and usleep. The last two are intercepted so the latency injection
 * path can be tested without real sleeps.
 *
 * Coverage approach:
 * - Tests directly `#include` production `.c` files after `#define`-overriding
 *   `dlsym`, `dlerror`, `abort`, and (on Linux) `syscall`. The constructor and
 *   config paths are tested without LD_PRELOAD.
 *
 * What is NOT tested via this header:
 * - Actual mmap/mprotect/madvise system call semantics.
 * - Thread-safety of the TLS guard under concurrent mmap calls.
 * - OS-level memory fault behaviour triggered by mprotect.
 */

#ifndef CHAOS_MEMORY_TEST_SUPPORT_H
#define CHAOS_MEMORY_TEST_SUPPORT_H

#include "../../src/memory/chaos_memory_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Instantiate all memory-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope. Defines:
 * - `g_chaos_memory_real_mmap`, `g_chaos_memory_real_munmap`,
 *   `g_chaos_memory_real_mprotect`, `g_chaos_memory_real_madvise`,
 *   `g_chaos_memory_real_nanosleep`, `g_chaos_memory_real_usleep` -- all NULL.
 * - `__thread int g_chaos_memory_tls_guard` -- per-thread re-entrancy guard.
 * - `__thread uint64_t g_chaos_memory_tls_prng_state` -- per-thread PRNG state.
 * - `uint64_t g_chaos_memory_process_seed` -- process-wide PRNG seed (1).
 */
#define CHAOS_MEMORY_DEFINE_TEST_GLOBALS()                                                         \
    chaos_memory_mmap_fn g_chaos_memory_real_mmap = NULL;                                          \
    chaos_memory_munmap_fn g_chaos_memory_real_munmap = NULL;                                      \
    chaos_memory_mprotect_fn g_chaos_memory_real_mprotect = NULL;                                  \
    chaos_memory_madvise_fn g_chaos_memory_real_madvise = NULL;                                    \
    chaos_memory_nanosleep_fn g_chaos_memory_real_nanosleep = NULL;                                \
    chaos_memory_usleep_fn g_chaos_memory_real_usleep = NULL;                                      \
    __thread int g_chaos_memory_tls_guard = 0;                                                     \
    __thread uint64_t g_chaos_memory_tls_prng_state = 0U;                                          \
    uint64_t g_chaos_memory_process_seed = 1U

/**
 * @brief Reset all memory-domain runtime globals to their initial state.
 *
 * Sets all six real-function-pointer globals to NULL, zeroes the TLS guard, TLS
 * PRNG state, and resets the process seed to 1. Call at the start of each test
 * function to prevent cross-test contamination.
 */
static inline void chaos_memory_test_reset_runtime(void)
{
    g_chaos_memory_real_mmap = NULL;
    g_chaos_memory_real_munmap = NULL;
    g_chaos_memory_real_mprotect = NULL;
    g_chaos_memory_real_madvise = NULL;
    g_chaos_memory_real_nanosleep = NULL;
    g_chaos_memory_real_usleep = NULL;
    g_chaos_memory_tls_guard = 0;
    g_chaos_memory_tls_prng_state = 0U;
    g_chaos_memory_process_seed = 1U;
}

/**
 * @brief Convert a typed function pointer to `void *` using `memcpy`.
 *
 * Direct casts between function pointers and `void *` are undefined behaviour
 * in C99. This helper copies the pointer bits through a `void *` local.
 *
 * @param function_bytes  Address of a function-pointer-typed value.
 * @param function_size   `sizeof` the function pointer type; must be <= sizeof(void *).
 * @return `void *` carrying the same bit pattern as the function pointer.
 */
static inline void *
chaos_memory_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

/**
 * @brief Produce the `void *` return value for a `dlsym` stub entry.
 *
 * @param type      Function pointer typedef (e.g. `chaos_memory_mmap_fn`).
 * @param function  Stub function to map to this symbol.
 *
 * Usage:
 * @code
 * if (strcmp(symbol, "mmap") == 0)
 *     return CHAOS_MEMORY_TEST_DLSYM_RESULT(chaos_memory_mmap_fn, stub_mmap);
 * @endcode
 */
#define CHAOS_MEMORY_TEST_DLSYM_RESULT(type, function)                                             \
    chaos_memory_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
