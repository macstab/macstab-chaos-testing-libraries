/**
 * @file test_time_support.h
 * @brief TIME-domain test globals, reset helper, and dlsym cast utility.
 *
 * Subsystem under test: chaos-time (LD_PRELOAD time fault injection via
 *   clock_gettime / nanosleep / usleep interception).
 *
 * This header is included by every unit test that exercises the TIME domain.
 * It provides:
 *
 *   1. `CHAOS_TIME_DEFINE_TEST_GLOBALS()` -- instantiates all TIME-domain
 *      runtime globals. Must be expanded exactly once per test binary.
 *
 *   2. `chaos_time_test_reset_runtime()` -- resets all TIME runtime globals to
 *      their initial (NULL/zero) state. Call at the start of every test function.
 *
 *   3. `CHAOS_TIME_TEST_DLSYM_RESULT(type, function)` -- type-safe function
 *      pointer to `void *` conversion for dlsym stubs.
 *
 * The TIME domain intercepts three functions: clock_gettime (for the OFFSET and
 * ERRNO/LATENCY effects), nanosleep, and usleep (for LATENCY and ERRNO effects).
 * The OFFSET effect skews `tv_sec`/`tv_nsec` returned by clock_gettime by
 * `rule.offset_ms` milliseconds, either forward (positive) or backward (negative).
 *
 * Coverage approach:
 * - Tests directly `#include` production `.c` files after symbol overrides.
 * - The LD_PRELOAD interposition path is NOT tested here.
 *
 * What is NOT tested via this header:
 * - Actual clock resolution or monotonicity guarantees.
 * - Thread-safety of the TLS guard under concurrent clock_gettime calls.
 * - nanosleep EINTR behaviour with real signal delivery.
 */

#ifndef CHAOS_TIME_TEST_SUPPORT_H
#define CHAOS_TIME_TEST_SUPPORT_H

#include "../../src/time/chaos_time_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Instantiate all TIME-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope. Defines:
 * - `g_chaos_time_real_clock_gettime`, `g_chaos_time_real_nanosleep`,
 *   `g_chaos_time_real_usleep` -- all NULL.
 * - `__thread int g_chaos_time_tls_guard` -- per-thread re-entrancy guard.
 * - `__thread uint64_t g_chaos_time_tls_prng_state` -- per-thread PRNG state.
 * - `uint64_t g_chaos_time_process_seed` -- process-wide PRNG seed (1).
 */
#define CHAOS_TIME_DEFINE_TEST_GLOBALS()                                                           \
    chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;                            \
    chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;                                    \
    chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;                                          \
    __thread int g_chaos_time_tls_guard = 0;                                                       \
    __thread uint64_t g_chaos_time_tls_prng_state = 0U;                                            \
    uint64_t g_chaos_time_process_seed = 1U

/**
 * @brief Reset all TIME-domain runtime globals to their initial state.
 *
 * Sets all three real-function-pointer globals to NULL, zeroes the TLS guard and
 * TLS PRNG state, and resets the process seed to 1. Call at the start of each
 * test function to prevent cross-test contamination.
 */
static inline void chaos_time_test_reset_runtime(void)
{
    g_chaos_time_real_clock_gettime = NULL;
    g_chaos_time_real_nanosleep = NULL;
    g_chaos_time_real_usleep = NULL;
    g_chaos_time_tls_guard = 0;
    g_chaos_time_tls_prng_state = 0U;
    g_chaos_time_process_seed = 1U;
}

/**
 * @brief Convert a typed function pointer to `void *` using `memcpy`.
 *
 * @param function_bytes  Address of a function-pointer-typed value.
 * @param function_size   `sizeof` the function pointer type; must be <= sizeof(void *).
 * @return `void *` carrying the same bit pattern as the function pointer.
 */
static inline void *chaos_time_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

/**
 * @brief Produce the `void *` return value for a TIME `dlsym` stub entry.
 *
 * @param type      Function pointer typedef (e.g. `chaos_time_clock_gettime_fn`).
 * @param function  Stub function to associate with this symbol name.
 */
#define CHAOS_TIME_TEST_DLSYM_RESULT(type, function)                                               \
    chaos_time_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
