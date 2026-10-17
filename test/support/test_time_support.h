/**
 * @file test_time_support.h
 * @brief Unit-test scaffolding for libchaos-time: runtime globals, reset helper, dlsym cast.
 *
 * @details Unit tests compile the libchaos-time sources directly into the test binary
 * (`#include "…/chaos_time_*.c"`) instead of loading the shared object, so the globals that
 * libchaos-time defines in its own translation units must be supplied by the test. This
 * header provides:
 *
 *   1. CHAOS_TIME_DEFINE_TEST_GLOBALS(): defines every runtime global declared `extern` in
 *      chaos_time_internal.h, plus an empty chaos_time_ensure_symbols() so no wrapper ever
 *      calls dlsym(RTLD_NEXT). Expand exactly once per test binary, at file scope.
 *   2. chaos_time_test_reset_runtime(): returns those globals to their initial state; call
 *      at the start of every test so state cannot leak between tests.
 *   3. CHAOS_TIME_TEST_DLSYM_RESULT(type, function): converts a typed function pointer to
 *      the `void *` a stub dlsym() returns, via memcpy (ISO C forbids the direct cast).
 *
 * libchaos-time holds eight real functions: clock_gettime, nanosleep, usleep, gettimeofday,
 * time, clock_nanosleep, sleep and timespec_get. Rule selectors name three operations
 * (clock_gettime, nanosleep, usleep); the other wrappers map onto those.
 *
 * Not covered by tests built on this header: LD_PRELOAD interposition itself, real clock
 * resolution or monotonicity, the per-thread reentrancy guard under concurrency, and EINTR
 * from real signal delivery. The runtime suites (test/runtime) cover interposition.
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
 * @brief Defines the libchaos-time runtime globals for one test binary.
 *
 * Expand exactly once at file scope (a second expansion is a duplicate definition). Defines:
 * - chaos_time_ensure_symbols() as a no-op, so real functions stay what the test assigns.
 * - The eight `g_chaos_time_real_*` real-function pointers, all NULL.
 * - `__thread int g_chaos_time_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_time_tls_prng_state` (per-thread PRNG state) = 0; 0 makes the
 *   PRNG reseed from the process seed on first use.
 * - `uint64_t g_chaos_time_process_seed` = 1 instead of the /dev/urandom seed of
 *   chaos_time_init(); per-thread streams still mix in the TID and a stack address.
 */
#define CHAOS_TIME_DEFINE_TEST_GLOBALS()                                                           \
    void chaos_time_ensure_symbols(void) {}                                                        \
    chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;                            \
    chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;                                    \
    chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;                                          \
    chaos_time_gettimeofday_fn g_chaos_time_real_gettimeofday = NULL;                              \
    chaos_time_time_fn g_chaos_time_real_time = NULL;                                              \
    chaos_time_clock_nanosleep_fn g_chaos_time_real_clock_nanosleep = NULL;                        \
    chaos_time_sleep_fn g_chaos_time_real_sleep = NULL;                                            \
    chaos_time_timespec_get_fn g_chaos_time_real_timespec_get = NULL;                              \
    __thread int g_chaos_time_tls_guard = 0;                                                       \
    __thread uint64_t g_chaos_time_tls_prng_state = 0U;                                            \
    uint64_t g_chaos_time_process_seed = 1U

/**
 * @brief Restores every global defined by CHAOS_TIME_DEFINE_TEST_GLOBALS() to its initial value.
 *
 * Sets the eight real-function pointers to NULL, zeroes the calling thread's reentrancy guard
 * and PRNG state, and resets the process seed to 1. Only the calling thread's TLS is reset.
 */
static inline void chaos_time_test_reset_runtime(void)
{
    g_chaos_time_real_clock_gettime = NULL;
    g_chaos_time_real_nanosleep = NULL;
    g_chaos_time_real_usleep = NULL;
    g_chaos_time_real_gettimeofday = NULL;
    g_chaos_time_real_time = NULL;
    g_chaos_time_real_clock_nanosleep = NULL;
    g_chaos_time_real_sleep = NULL;
    g_chaos_time_real_timespec_get = NULL;
    g_chaos_time_tls_guard = 0;
    g_chaos_time_tls_prng_state = 0U;
    g_chaos_time_process_seed = 1U;
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
static inline void *chaos_time_test_dlsym_pointer(const void *function_bytes, size_t function_size)
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
 * @param type      Function-pointer typedef, e.g. `chaos_time_clock_gettime_fn`; a mismatch
 *                  with @p function draws a compiler diagnostic via the compound literal.
 * @param function  Stub to hand back for the requested symbol name.
 */
#define CHAOS_TIME_TEST_DLSYM_RESULT(type, function)                                               \
    chaos_time_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
