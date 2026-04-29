#ifndef CHAOS_TIME_INTERNAL_H
#define CHAOS_TIME_INTERNAL_H

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define CHAOS_TIME_CONFIG_PATH "/tmp/.chaos-time.conf"
#define CHAOS_TIME_MAX_RULES 256U
#define CHAOS_TIME_MAX_LINE_LENGTH 1024U
#define CHAOS_TIME_MAX_CONFIG_BYTES (CHAOS_TIME_MAX_RULES * CHAOS_TIME_MAX_LINE_LENGTH)
#define CHAOS_TIME_MAX_TEXT 128U
#define CHAOS_TIME_MAX_VALUE 256U

#define CHAOS_TIME_EXPORT __attribute__((visibility("default")))

#define CHAOS_TIME_MTIME_MISSING UINT64_C(0)
#define CHAOS_TIME_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_TIME_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

typedef int (*chaos_time_clock_gettime_fn)(clockid_t, struct timespec *);
typedef int (*chaos_time_nanosleep_fn)(const struct timespec *, struct timespec *);
typedef int (*chaos_time_usleep_fn)(useconds_t);

extern chaos_time_clock_gettime_fn g_chaos_time_real_clock_gettime;
extern chaos_time_nanosleep_fn g_chaos_time_real_nanosleep;
extern chaos_time_usleep_fn g_chaos_time_real_usleep;

extern __thread int g_chaos_time_tls_guard;
extern __thread uint64_t g_chaos_time_tls_prng_state;
extern uint64_t g_chaos_time_process_seed;

static inline int chaos_time_in_internal(void)
{
    return g_chaos_time_tls_guard != 0;
}

static inline int chaos_time_enter_internal(void)
{
    int previous = g_chaos_time_tls_guard;
    g_chaos_time_tls_guard = 1;
    return previous;
}

static inline void chaos_time_leave_internal(int previous)
{
    g_chaos_time_tls_guard = previous;
}

static inline uint64_t chaos_time_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

static inline int
chaos_time_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

static inline uint64_t chaos_time_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static inline uint64_t chaos_time_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static inline void chaos_time_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_time_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_time_process_seed;
    seed ^= chaos_time_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed);
    if (g_chaos_time_tls_prng_state == 0U)
    {
        g_chaos_time_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

static inline void chaos_time_prng_seed_thread(uint64_t seed)
{
    g_chaos_time_tls_prng_state = chaos_time_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

static inline uint32_t chaos_time_prng_next_u32(void)
{
    uint64_t state;

    chaos_time_prng_ensure_seeded();
    state = g_chaos_time_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_time_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
