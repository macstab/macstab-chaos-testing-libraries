/**
 * @file test_dns_support.h
 * @brief Unit-test scaffolding for libchaos-dns: runtime globals, reset helper, dlsym cast.
 *
 * @details Unit tests compile the libchaos-dns sources directly into the test binary
 * instead of loading the shared object, so the globals libchaos-dns defines in its own
 * translation units must be supplied by the test. This header provides:
 *
 *   1. CHAOS_DNS_DEFINE_TEST_GLOBALS(): defines every runtime global declared `extern` in
 *      chaos_dns_internal.h, plus an empty chaos_dns_ensure_symbols() so no wrapper calls
 *      dlsym(RTLD_NEXT). Expand exactly once per test binary, at file scope.
 *   2. chaos_dns_test_reset_runtime(): returns those globals to their initial state; call at
 *      the start of every test that touches runtime state.
 *   3. CHAOS_DNS_TEST_DLSYM_RESULT(type, function): converts a typed function pointer to the
 *      `void *` a stub dlsym() returns, via memcpy (ISO C forbids the direct cast).
 *
 * libchaos-dns holds seven real functions: getaddrinfo, getnameinfo, freeaddrinfo,
 * gethostbyname2, gethostbyname2_r, gethostbyaddr and gethostbyaddr_r.
 *
 * Runtime tests (test_dns_runtime.c) additionally `#define` dlsym, dlerror, abort and, on
 * Linux, syscall before including the production sources, which lets them drive the
 * constructor and the config path without LD_PRELOAD.
 *
 * Not covered by tests built on this header: interposition through RTLD_NEXT in a live
 * process (the runtime suites cover it), the system resolver and the network, and the
 * per-thread PRNG under concurrent lookups.
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
 * @brief Defines the libchaos-dns runtime globals for one test binary.
 *
 * Expand exactly once at file scope (a second expansion is a duplicate definition). Defines:
 * - chaos_dns_ensure_symbols() as a no-op, so real functions stay what the test assigns.
 * - The seven `g_chaos_dns_real_*` real-function pointers, all NULL.
 * - `__thread int g_chaos_dns_tls_guard` (reentrancy guard) = 0.
 * - `__thread uint64_t g_chaos_dns_tls_prng_state` = 0, which makes the per-thread PRNG seed
 *   itself on first use.
 * - `uint64_t g_chaos_dns_process_seed` = 1 in place of the /dev/urandom seed, so probability
 *   draws work without running the constructor.
 */
#define CHAOS_DNS_DEFINE_TEST_GLOBALS()                                                            \
    void chaos_dns_ensure_symbols(void) {}                                                         \
    chaos_dns_getaddrinfo_fn g_chaos_dns_real_getaddrinfo = NULL;                                  \
    chaos_dns_getnameinfo_fn g_chaos_dns_real_getnameinfo = NULL;                                  \
    chaos_dns_freeaddrinfo_fn g_chaos_dns_real_freeaddrinfo = NULL;                                \
    chaos_dns_gethostbyname2_fn g_chaos_dns_real_gethostbyname2 = NULL;                            \
    chaos_dns_gethostbyname2_r_fn g_chaos_dns_real_gethostbyname2_r = NULL;                        \
    chaos_dns_gethostbyaddr_fn g_chaos_dns_real_gethostbyaddr = NULL;                              \
    chaos_dns_gethostbyaddr_r_fn g_chaos_dns_real_gethostbyaddr_r = NULL;                          \
    __thread int g_chaos_dns_tls_guard = 0;                                                        \
    __thread uint64_t g_chaos_dns_tls_prng_state = 0U;                                             \
    uint64_t g_chaos_dns_process_seed = 1U

/**
 * @brief Restores every global defined by CHAOS_DNS_DEFINE_TEST_GLOBALS() to its initial value.
 *
 * Sets the seven real-function pointers to NULL, zeroes the calling thread's reentrancy guard
 * and PRNG state, and resets the process seed to 1. Only the calling thread's TLS is reset.
 */
static inline void chaos_dns_test_reset_runtime(void)
{
    g_chaos_dns_real_getaddrinfo = NULL;
    g_chaos_dns_real_getnameinfo = NULL;
    g_chaos_dns_real_freeaddrinfo = NULL;
    g_chaos_dns_real_gethostbyname2 = NULL;
    g_chaos_dns_real_gethostbyname2_r = NULL;
    g_chaos_dns_real_gethostbyaddr = NULL;
    g_chaos_dns_real_gethostbyaddr_r = NULL;
    g_chaos_dns_tls_guard = 0;
    g_chaos_dns_tls_prng_state = 0U;
    g_chaos_dns_process_seed = 1U;
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
static inline void *chaos_dns_test_dlsym_pointer(const void *function_bytes, size_t function_size)
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
 * @param type      Function-pointer typedef, e.g. `chaos_dns_getaddrinfo_fn`; a mismatch
 *                  with @p function draws a compiler diagnostic via the compound literal.
 * @param function  Stub to hand back for the requested symbol name.
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
