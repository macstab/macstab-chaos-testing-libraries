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

static inline void *
chaos_memory_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_MEMORY_TEST_DLSYM_RESULT(type, function)                                             \
    chaos_memory_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
