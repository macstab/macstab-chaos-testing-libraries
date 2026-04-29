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

#define CHAOS_TIME_DEFINE_TEST_GLOBALS()                                                           \
    chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime = NULL;                            \
    chaos_time_nanosleep_fn g_chaos_time_real_nanosleep = NULL;                                    \
    chaos_time_usleep_fn g_chaos_time_real_usleep = NULL;                                          \
    __thread int g_chaos_time_tls_guard = 0;                                                       \
    __thread uint64_t g_chaos_time_tls_prng_state = 0U;                                            \
    uint64_t g_chaos_time_process_seed = 1U

static inline void chaos_time_test_reset_runtime(void)
{
    g_chaos_time_real_clock_gettime = NULL;
    g_chaos_time_real_nanosleep = NULL;
    g_chaos_time_real_usleep = NULL;
    g_chaos_time_tls_guard = 0;
    g_chaos_time_tls_prng_state = 0U;
    g_chaos_time_process_seed = 1U;
}

static inline void *chaos_time_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_TIME_TEST_DLSYM_RESULT(type, function)                                               \
    chaos_time_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
