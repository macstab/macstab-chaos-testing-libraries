/**
 * @file test_process_support.h
 * @brief PROCESS-domain test globals, reset helper, and dlsym cast utility.
 *
 * Subsystem under test: chaos-process (LD_PRELOAD process lifecycle fault injection
 *   via pthread_create / fork / posix_spawn / execve / waitpid interception).
 *
 * This header is included by every unit test that exercises the PROCESS domain.
 * It provides:
 *
 *   1. `CHAOS_PROCESS_DEFINE_TEST_GLOBALS()` -- instantiates all process-domain
 *      runtime globals. Notably includes the `fail_after_counters` volatile array
 *      (one `uint64_t` per operation kind) used by the FAIL_AFTER countdown effect.
 *
 *   2. `chaos_process_test_reset_runtime()` -- resets all process runtime globals
 *      to their initial state. Zeroes the fail_after_counters array via `memset`
 *      in addition to the standard pointer/seed resets.
 *
 *   3. `CHAOS_PROCESS_TEST_DLSYM_RESULT(type, function)` -- type-safe function
 *      pointer to `void *` conversion for dlsym stubs.
 *
 * The PROCESS domain intercepts nine functions: pthread_create, fork, posix_spawn,
 * posix_spawnp, execve, execveat (Linux only), waitpid, nanosleep, and usleep.
 * The nanosleep/usleep interceptions support the LATENCY effect.
 *
 * Coverage approach:
 * - Tests directly `#include` production `.c` files after symbol overrides.
 * - The LD_PRELOAD interposition path is NOT tested here.
 *
 * What is NOT tested via this header:
 * - Real fork/exec semantics, child process creation, or process table effects.
 * - Thread-safety of the fail_after_counters under concurrent pthread_create calls.
 * - Signal handling across fork.
 */

#ifndef CHAOS_PROCESS_TEST_SUPPORT_H
#define CHAOS_PROCESS_TEST_SUPPORT_H

#include "../../src/process/chaos_process_config.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * @brief Instantiate all PROCESS-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope. Defines:
 * - All nine real-function-pointer globals (NULL-initialised).
 * - `__thread int g_chaos_process_tls_guard` -- per-thread re-entrancy guard.
 * - `__thread uint64_t g_chaos_process_tls_prng_state` -- per-thread PRNG state.
 * - `uint64_t g_chaos_process_process_seed` -- process-wide PRNG seed (1).
 * - `volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT]`
 *   -- per-operation countdown counters for the FAIL_AFTER effect. Initialised to
 *   all-zeros; each element counts down from `rule.fail_after_count` and triggers
 *   the error once it reaches zero.
 */
#define CHAOS_PROCESS_DEFINE_TEST_GLOBALS()                                                        \
    chaos_process_pthread_create_fn g_chaos_process_real_pthread_create = NULL;                    \
    chaos_process_fork_fn g_chaos_process_real_fork = NULL;                                        \
    chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn = NULL;                          \
    chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp = NULL;                        \
    chaos_process_execve_fn g_chaos_process_real_execve = NULL;                                    \
    chaos_process_execveat_fn g_chaos_process_real_execveat = NULL;                                \
    chaos_process_waitpid_fn g_chaos_process_real_waitpid = NULL;                                  \
    chaos_process_nanosleep_fn g_chaos_process_real_nanosleep = NULL;                              \
    chaos_process_usleep_fn g_chaos_process_real_usleep = NULL;                                    \
    __thread int g_chaos_process_tls_guard = 0;                                                    \
    __thread uint64_t g_chaos_process_tls_prng_state = 0U;                                         \
    uint64_t g_chaos_process_process_seed = 1U;                                                    \
    volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U}

/**
 * @brief Reset all PROCESS-domain runtime globals to their initial state.
 *
 * Sets all real-function-pointer globals to NULL, zeroes the TLS guard and PRNG
 * state, resets the process seed to 1, and zeroes all elements of the
 * `g_chaos_process_fail_after_counters` array. The `memset` cast to `void *` is
 * required because the array is `volatile`.
 *
 * Call at the start of each test function to prevent cross-test contamination,
 * especially important for FAIL_AFTER tests where counter state from a previous
 * test could cause spurious failures in the next.
 */
static inline void chaos_process_test_reset_runtime(void)
{
    g_chaos_process_real_pthread_create = NULL;
    g_chaos_process_real_fork = NULL;
    g_chaos_process_real_posix_spawn = NULL;
    g_chaos_process_real_posix_spawnp = NULL;
    g_chaos_process_real_execve = NULL;
    g_chaos_process_real_execveat = NULL;
    g_chaos_process_real_waitpid = NULL;
    g_chaos_process_real_nanosleep = NULL;
    g_chaos_process_real_usleep = NULL;
    g_chaos_process_tls_guard = 0;
    g_chaos_process_tls_prng_state = 0U;
    g_chaos_process_process_seed = 1U;
    (void)memset(
        (void *)g_chaos_process_fail_after_counters,
        0,
        sizeof(uint64_t) * (size_t)CHAOS_PROCESS_OP_COUNT
    );
}

/**
 * @brief Convert a typed function pointer to `void *` using `memcpy`.
 *
 * @param function_bytes  Address of a function-pointer-typed value.
 * @param function_size   `sizeof` the function pointer type; must be <= sizeof(void *).
 * @return `void *` carrying the same bit pattern as the function pointer.
 */
static inline void *
chaos_process_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

/**
 * @brief Produce the `void *` return value for a PROCESS `dlsym` stub entry.
 *
 * @param type      Function pointer typedef (e.g. `chaos_process_fork_fn`).
 * @param function  Stub function to associate with this symbol name.
 */
#define CHAOS_PROCESS_TEST_DLSYM_RESULT(type, function)                                            \
    chaos_process_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
