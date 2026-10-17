/**
 * @file test_process_support.h
 * @brief Unit-test scaffolding for libchaos-process: runtime globals, reset helper, dlsym cast.
 *
 * @details Unit tests compile the libchaos-process sources directly into the test binary
 * instead of loading the shared object, so the globals libchaos-process defines in its own
 * translation units must be supplied by the test. This header provides:
 *
 *   1. CHAOS_PROCESS_DEFINE_TEST_GLOBALS(): defines every runtime global declared `extern`
 *      for libchaos-process, including the FAIL_AFTER counter array, plus test versions of
 *      chaos_process_ensure_symbols() (no-op) and chaos_process_resolve_pthread_create().
 *      Expand exactly once per test binary, at file scope.
 *   2. chaos_process_test_reset_runtime(): returns those globals to their initial state,
 *      FAIL_AFTER counters included; call at the start of every test.
 *   3. CHAOS_PROCESS_TEST_DLSYM_RESULT(type, function): converts a typed function pointer to
 *      the `void *` a stub dlsym() returns, via memcpy (ISO C forbids the direct cast).
 *
 * libchaos-process holds thirteen real functions: pthread_create, fork, posix_spawn,
 * posix_spawnp, execve, execveat (Linux only), execvpe, fexecve, system, popen, waitpid,
 * wait4 and waitid. Its LATENCY effect sleeps through chaos_sleep_ms(); include
 * test_sleep_support.h first to record those sleeps instead of performing them.
 *
 * Not covered by tests built on this header: real fork/exec/spawn semantics, signals across
 * fork, LD_PRELOAD interposition, and the FAIL_AFTER counters under concurrent callers. The
 * runtime suites (test/runtime) cover interposition.
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
 * @brief Defines the libchaos-process runtime globals for one test binary.
 *
 * Expand exactly once at file scope (a second expansion is a duplicate definition). Defines:
 * - chaos_process_ensure_symbols() as a no-op, so real functions stay what the test assigns.
 * - chaos_process_resolve_pthread_create(), which installs `g_test_late_pthread_create` only
 *   while the real pthread_create is still NULL. It models the production lazy resolution,
 *   where pthread_create can appear later (libpthread brought in by dlopen()), so tests can
 *   prove the wrapper retries resolution instead of failing for good.
 * - The thirteen `g_chaos_process_real_*` real-function pointers, all NULL.
 * - `__thread int g_chaos_process_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_process_tls_prng_state` = 0, which makes the per-thread PRNG
 *   seed itself on first use.
 * - `uint64_t g_chaos_process_process_seed` = 1 in place of the /dev/urandom seed.
 * - `volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT]` = 0:
 *   one call counter per operation, counting up from 0. The FAIL_AFTER effect increments it
 *   on every matching call and injects the error once the pre-increment value reaches
 *   `rule.fail_after_count` (and the probability draw hits). In production the counters are
 *   also zeroed on every reload and, by the pthread_atfork child handler, in a fork child, so
 *   FAIL_AFTER counts per process.
 */
#define CHAOS_PROCESS_DEFINE_TEST_GLOBALS()                                                        \
    void chaos_process_ensure_symbols(void) {}                                                     \
    chaos_process_pthread_create_fn g_test_late_pthread_create = NULL;                             \
    void chaos_process_resolve_pthread_create(void)                                                \
    {                                                                                              \
        if (g_chaos_process_real_pthread_create == NULL)                                           \
        {                                                                                          \
            g_chaos_process_real_pthread_create = g_test_late_pthread_create;                      \
        }                                                                                          \
    }                                                                                              \
    chaos_process_pthread_create_fn g_chaos_process_real_pthread_create = NULL;                    \
    chaos_process_fork_fn g_chaos_process_real_fork = NULL;                                        \
    chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn = NULL;                          \
    chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp = NULL;                        \
    chaos_process_execve_fn g_chaos_process_real_execve = NULL;                                    \
    chaos_process_execveat_fn g_chaos_process_real_execveat = NULL;                                \
    chaos_process_waitpid_fn g_chaos_process_real_waitpid = NULL;                                  \
    chaos_process_wait4_fn g_chaos_process_real_wait4 = NULL;                                      \
    chaos_process_execvpe_fn g_chaos_process_real_execvpe = NULL;                                  \
    chaos_process_fexecve_fn g_chaos_process_real_fexecve = NULL;                                  \
    chaos_process_system_fn g_chaos_process_real_system = NULL;                                    \
    chaos_process_popen_fn g_chaos_process_real_popen = NULL;                                      \
    chaos_process_waitid_fn g_chaos_process_real_waitid = NULL;                                    \
    __thread int g_chaos_process_tls_guard = 0;                                                    \
    __thread uint64_t g_chaos_process_tls_prng_state = 0U;                                         \
    uint64_t g_chaos_process_process_seed = 1U;                                                    \
    volatile uint64_t g_chaos_process_fail_after_counters[CHAOS_PROCESS_OP_COUNT] = {0U}

/**
 * @brief Restores every global defined by CHAOS_PROCESS_DEFINE_TEST_GLOBALS() to its initial
 *        value.
 *
 * Sets the thirteen real-function pointers to NULL, zeroes the calling thread's reentrancy
 * guard and PRNG state, resets the process seed to 1 and zeroes every FAIL_AFTER counter. A
 * counter left over from an earlier test would shift the call on which FAIL_AFTER fires.
 * `g_test_late_pthread_create` is not reset. The memset() argument is cast to `void *`
 * because passing a pointer to volatile discards the qualifier.
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
    g_chaos_process_real_wait4 = NULL;
    g_chaos_process_real_execvpe = NULL;
    g_chaos_process_real_fexecve = NULL;
    g_chaos_process_real_system = NULL;
    g_chaos_process_real_popen = NULL;
    g_chaos_process_real_waitid = NULL;
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
chaos_process_test_dlsym_pointer(const void *function_bytes, size_t function_size)
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
 * @param type      Function-pointer typedef, e.g. `chaos_process_fork_fn`; a mismatch
 *                  with @p function draws a compiler diagnostic via the compound literal.
 * @param function  Stub to hand back for the requested symbol name.
 */
#define CHAOS_PROCESS_TEST_DLSYM_RESULT(type, function)                                            \
    chaos_process_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
