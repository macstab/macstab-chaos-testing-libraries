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

static inline void *
chaos_process_test_dlsym_pointer(const void *function_bytes, size_t function_size)
{
    void *resolved = NULL;

    assert(function_bytes != NULL);
    assert(function_size <= sizeof(resolved));
    (void)memcpy(&resolved, function_bytes, function_size);
    return resolved;
}

#define CHAOS_PROCESS_TEST_DLSYM_RESULT(type, function)                                            \
    chaos_process_test_dlsym_pointer(&(type){function}, sizeof(type))

#endif
