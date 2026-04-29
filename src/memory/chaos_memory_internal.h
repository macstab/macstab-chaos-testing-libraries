#ifndef CHAOS_MEMORY_INTERNAL_H
#define CHAOS_MEMORY_INTERNAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif

#define CHAOS_MEMORY_CONFIG_PATH "/tmp/.chaos-memory.conf"
#define CHAOS_MEMORY_MAX_RULES 256U
#define CHAOS_MEMORY_MAX_LINE_LENGTH 1024U
#define CHAOS_MEMORY_MAX_CONFIG_BYTES (CHAOS_MEMORY_MAX_RULES * CHAOS_MEMORY_MAX_LINE_LENGTH)
#define CHAOS_MEMORY_MAX_VALUE 256U

#define CHAOS_MEMORY_EXPORT __attribute__((visibility("default")))

#define CHAOS_MEMORY_MTIME_MISSING UINT64_C(0)
#define CHAOS_MEMORY_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_MEMORY_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

typedef void *(*chaos_memory_mmap_fn)(void *, size_t, int, int, int, off_t);
typedef int (*chaos_memory_munmap_fn)(void *, size_t);
typedef int (*chaos_memory_mprotect_fn)(void *, size_t, int);
typedef int (*chaos_memory_madvise_fn)(void *, size_t, int);
typedef int (*chaos_memory_nanosleep_fn)(const struct timespec *, struct timespec *);
typedef int (*chaos_memory_usleep_fn)(useconds_t);

extern chaos_memory_mmap_fn g_chaos_memory_real_mmap;
extern chaos_memory_munmap_fn g_chaos_memory_real_munmap;
extern chaos_memory_mprotect_fn g_chaos_memory_real_mprotect;
extern chaos_memory_madvise_fn g_chaos_memory_real_madvise;
extern chaos_memory_nanosleep_fn g_chaos_memory_real_nanosleep;
extern chaos_memory_usleep_fn g_chaos_memory_real_usleep;

extern __thread int g_chaos_memory_tls_guard;
extern __thread uint64_t g_chaos_memory_tls_prng_state;
extern uint64_t g_chaos_memory_process_seed;

static inline int chaos_memory_in_internal(void)
{
    return g_chaos_memory_tls_guard != 0;
}

static inline int chaos_memory_enter_internal(void)
{
    int previous = g_chaos_memory_tls_guard;
    g_chaos_memory_tls_guard = 1;
    return previous;
}

static inline void chaos_memory_leave_internal(int previous)
{
    g_chaos_memory_tls_guard = previous;
}

static inline uint64_t chaos_memory_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

static inline int
chaos_memory_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

static inline uint64_t chaos_memory_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static inline uint64_t chaos_memory_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static inline void chaos_memory_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_memory_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_memory_process_seed;
    seed ^= chaos_memory_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed);
    if (g_chaos_memory_tls_prng_state == 0U)
    {
        g_chaos_memory_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

static inline void chaos_memory_prng_seed_thread(uint64_t seed)
{
    g_chaos_memory_tls_prng_state = chaos_memory_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

static inline uint32_t chaos_memory_prng_next_u32(void)
{
    uint64_t state;

    chaos_memory_prng_ensure_seeded();
    state = g_chaos_memory_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_memory_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

static inline int chaos_memory_mmap_is_anonymous(int flags)
{
    return (flags & MAP_ANONYMOUS) != 0;
}

#endif
