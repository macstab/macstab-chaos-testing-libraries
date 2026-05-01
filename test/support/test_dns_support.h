/**
 * @file test_dns_support.h
 * @brief DNS-domain test globals, reset helper, and dlsym cast utility.
 *
 * Subsystem under test: chaos-dns (LD_PRELOAD DNS fault injection via
 *   getaddrinfo / getnameinfo interception).
 *
 * This header is included by every unit test that exercises the DNS domain.
 * It provides two categories of support:
 *
 *   1. `CHAOS_DNS_DEFINE_TEST_GLOBALS()` -- a macro that instantiates all
 *      translation-unit-scoped globals declared `extern` in the production
 *      DNS internal header. Each test `.c` file must expand this macro exactly
 *      once at file scope.
 *
 *   2. `chaos_dns_test_reset_runtime()` -- resets all DNS runtime globals to
 *      their initial (NULL/zero) state. Call at the start of every test
 *      function that modifies runtime state.
 *
 *   3. `CHAOS_DNS_TEST_DLSYM_RESULT(type, function)` -- a type-safe macro that
 *      converts a typed function pointer to `void *` via `memcpy`, avoiding
 *      strict-aliasing UB in the dlsym stub. Required when building a stub
 *      `dlsym` that maps symbol names to test functions.
 *
 * Coverage approach:
 * - Tests directly `#include` production `.c` files after overriding `dlsym`,
 *   `dlerror`, `abort`, and (on Linux) `syscall` via `#define`. This exercises
 *   the constructor and config subsystem without requiring LD_PRELOAD.
 * - The actual DNS interposition path (RTLD_NEXT-based interception in a live
 *   process) is NOT tested here.
 *
 * What is NOT tested via this header:
 * - Thread-safety of the TLS PRNG state under concurrent getaddrinfo calls.
 * - OS-level DNS resolver behaviour or network availability.
 */

#ifndef CHAOS_DNS_TEST_SUPPORT_H
#define CHAOS_DNS_TEST_SUPPORT_H

#include "../../src/dns/chaos_dns_internal.h"

#include <assert.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Instantiate all DNS-domain runtime globals for one test translation unit.
 *
 * Must be expanded exactly once at file scope. Defines:
 * - `g_chaos_dns_real_getaddrinfo`, `g_chaos_dns_real_getnameinfo`,
 *   `g_chaos_dns_real_freeaddrinfo` -- real-function-pointer globals, all NULL.
 * - `__thread int g_chaos_dns_tls_guard` -- per-thread re-entrancy guard.
 * - `__thread uint64_t g_chaos_dns_tls_prng_state` -- per-thread PRNG state.
 * - `uint64_t g_chaos_dns_process_seed` -- process-wide PRNG seed, initialised
 *   to 1 (non-zero) so PRNG operations are defined without calling the constructor.
 */
#define CHAOS_DNS_DEFINE_TEST_GLOBALS()                                                            \
    chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;                                  \
    chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;                                  \
    chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;                                \
    __thread int g_chaos_dns_tls_guard = 0;                                                        \
    __thread uint64_t g_chaos_dns_tls_prng_state = 0U;                                             \
    uint64_t g_chaos_dns_process_seed = 1U

/**
 * @brief Reset all DNS-domain runtime globals to their initial state.
 *
 * Sets all three real-function-pointer globals to NULL, zeroes the TLS guard,
 * TLS PRNG state, and resets the process seed to 1. Call at the start of each
 * test function to prevent cross-test state contamination.
 */
static inline void chaos_dns_test_reset_runtime(void)
{
    g_chaos_dns_real_getaddrinfo = NULL;
    g_chaos_dns_real_getnameinfo = NULL;
    g_chaos_dns_real_freeaddrinfo = NULL;
    g_chaos_dns_tls_guard = 0;
    g_chaos_dns_tls_prng_state = 0U;
    g_chaos_dns_process_seed = 1U;
}

/**
 * @brief Convert a typed function pointer to `void *` using `memcpy`.
 *
 * Direct casts between function pointers and `void *` are undefined behaviour
 * in C99. This helper copies the pointer bits through a `void *` local so the
 * conversion is well-defined.
 *
 * @param function_bytes  Address of a function-pointer-typed value.
 * @param function_size   `sizeof` the function pointer type; must be <= sizeof(void *).
 * @return `void *` carrying the same bit pattern as the function pointer.
 */
static inline void *chaos_dns_test_dlsym_pointer(const void *function_bytes, size_t function_size)
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
 * @param type      The function pointer typedef (e.g. `chaos_dns_getaddrinfo_fn`).
 * @param function  The stub function to map to this symbol.
 *
 * Usage in a dlsym stub:
 * @code
 * if (strcmp(symbol, "getaddrinfo") == 0)
 *     return CHAOS_DNS_TEST_DLSYM_RESULT(chaos_dns_getaddrinfo_fn, stub_getaddrinfo);
 * @endcode
 */
#define CHAOS_DNS_TEST_DLSYM_RESULT(type, function)                                                \
    chaos_dns_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
