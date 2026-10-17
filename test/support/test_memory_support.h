/**
 * @file test_memory_support.h
 * @brief Unit-test scaffolding for libchaos-memory: runtime globals, reset helper, dlsym cast.
 *
 * @details Unit tests compile the libchaos-memory sources directly into the test binary
 * instead of loading the shared object, so the globals libchaos-memory defines in its own
 * translation units must be supplied by the test. This header provides:
 *
 *   1. CHAOS_MEMORY_DEFINE_TEST_GLOBALS(): defines every runtime global declared `extern` in
 *      chaos_memory_internal.h, plus an empty chaos_memory_ensure_symbols() so no wrapper
 *      calls dlsym(RTLD_NEXT). Expand exactly once per test binary, at file scope.
 *   2. chaos_memory_test_reset_runtime(): returns those globals to their initial state; call
 *      at the start of every test that touches runtime state.
 *   3. CHAOS_MEMORY_TEST_DLSYM_RESULT(type, function): converts a typed function pointer to
 *      the `void *` a stub dlsym() returns, via memcpy (ISO C forbids the direct cast).
 *
 * libchaos-memory holds five real functions: mmap, munmap, mprotect, madvise and
 * posix_madvise. Its LATENCY effect sleeps through chaos_sleep_ms(); include
 * test_sleep_support.h first to record those sleeps instead of performing them.
 *
 * Runtime tests (test_memory_runtime.c) additionally `#define` dlsym, dlerror, abort and, on
 * Linux, syscall before including the production sources, which lets them drive the
 * constructor and the config path without LD_PRELOAD.
 *
 * Not covered by tests built on this header: real mmap/mprotect/madvise semantics, faults
 * raised by a real mprotect, and the reentrancy guard under concurrent calls.
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
 * @brief Defines the libchaos-memory runtime globals for one test binary.
 *
 * Expand exactly once at file scope (a second expansion is a duplicate definition). Defines:
 * - chaos_memory_ensure_symbols() as a no-op, so real functions stay what the test assigns.
 * - The five `g_chaos_memory_real_*` real-function pointers, all NULL.
 * - `__thread int g_chaos_memory_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_memory_tls_prng_state` = 0, which makes the per-thread PRNG
 *   seed itself on first use.
 * - `uint64_t g_chaos_memory_process_seed` = 1 in place of the /dev/urandom seed.
 */
#define CHAOS_MEMORY_DEFINE_TEST_GLOBALS()                                                         \
    void chaos_memory_ensure_symbols(void) {}                                                      \
    chaos_memory_mmap_fn g_chaos_memory_real_mmap = NULL;                                          \
    chaos_memory_munmap_fn g_chaos_memory_real_munmap = NULL;                                      \
    chaos_memory_mprotect_fn g_chaos_memory_real_mprotect = NULL;                                  \
    chaos_memory_madvise_fn g_chaos_memory_real_madvise = NULL;                                    \
    chaos_memory_posix_madvise_fn g_chaos_memory_real_posix_madvise = NULL;                        \
    __thread int g_chaos_memory_tls_guard = 0;                                                     \
    __thread uint64_t g_chaos_memory_tls_prng_state = 0U;                                          \
    uint64_t g_chaos_memory_process_seed = 1U

/**
 * @brief Restores every global defined by CHAOS_MEMORY_DEFINE_TEST_GLOBALS() to its initial
 *        value.
 *
 * Sets the five real-function pointers to NULL, zeroes the calling thread's reentrancy guard
 * and PRNG state, and resets the process seed to 1. Only the calling thread's TLS is reset.
 */
static inline void chaos_memory_test_reset_runtime(void)
{
    g_chaos_memory_real_mmap = NULL;
    g_chaos_memory_real_munmap = NULL;
    g_chaos_memory_real_mprotect = NULL;
    g_chaos_memory_real_madvise = NULL;
    g_chaos_memory_real_posix_madvise = NULL;
    g_chaos_memory_tls_guard = 0;
    g_chaos_memory_tls_prng_state = 0U;
    g_chaos_memory_process_seed = 1U;
}

/**
 * @brief Copies a function pointer's bytes into a `void *`.
 *
 * ISO C leaves function-pointer to object-pointer casts undefined; POSIX guarantees the
 * representations match, so a byte copy is the portable way to build a dlsym() result.
 *
 * @param function_bytes  Address of a function-pointer object; must not be NULL (asserted).
 * @param function_size   Size of that object; must be <= sizeof(void *) (asserted).
 * @return A `void *` with the same bit pattern as the function pointer.
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
 * @brief Yields the `void *` a stub dlsym() returns for @p function.
 *
 * @param type      Function-pointer typedef, e.g. `chaos_memory_mmap_fn`; a mismatch
 *                  with @p function draws a compiler diagnostic via the compound literal.
 * @param function  Stub to hand back for the requested symbol name.
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
