#ifndef CHAOS_PROCESS_INTERNAL_H
#define CHAOS_PROCESS_INTERNAL_H

#include <errno.h>
#include <pthread.h>
#include <spawn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#define CHAOS_PROCESS_CONFIG_PATH "/tmp/.chaos-process.conf"
#define CHAOS_PROCESS_MAX_RULES 256U
#define CHAOS_PROCESS_MAX_LINE_LENGTH 1024U
#define CHAOS_PROCESS_MAX_CONFIG_BYTES (CHAOS_PROCESS_MAX_RULES * CHAOS_PROCESS_MAX_LINE_LENGTH)
#define CHAOS_PROCESS_MAX_VALUE 256U

#define CHAOS_PROCESS_EXPORT __attribute__((visibility("default")))

#define CHAOS_PROCESS_MTIME_MISSING UINT64_C(0)
#define CHAOS_PROCESS_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)
#define CHAOS_PROCESS_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

typedef int (*chaos_process_pthread_create_fn)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
typedef pid_t (*chaos_process_fork_fn)(void);
typedef int (*chaos_process_posix_spawn_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);
typedef int (*chaos_process_posix_spawnp_fn)(
    pid_t *,
    const char *,
    const posix_spawn_file_actions_t *,
    const posix_spawnattr_t *,
    char *const[],
    char *const[]
);
typedef int (*chaos_process_execve_fn)(const char *, char *const[], char *const[]);
typedef int (*chaos_process_execveat_fn)(int, const char *, char *const[], char *const[], int);
typedef pid_t (*chaos_process_waitpid_fn)(pid_t, int *, int);
typedef int (*chaos_process_nanosleep_fn)(const struct timespec *, struct timespec *);
typedef int (*chaos_process_usleep_fn)(useconds_t);

extern chaos_process_pthread_create_fn g_chaos_process_real_pthread_create;
extern chaos_process_fork_fn g_chaos_process_real_fork;
extern chaos_process_posix_spawn_fn g_chaos_process_real_posix_spawn;
extern chaos_process_posix_spawnp_fn g_chaos_process_real_posix_spawnp;
extern chaos_process_execve_fn g_chaos_process_real_execve;
extern chaos_process_execveat_fn g_chaos_process_real_execveat;
extern chaos_process_waitpid_fn g_chaos_process_real_waitpid;
extern chaos_process_nanosleep_fn g_chaos_process_real_nanosleep;
extern chaos_process_usleep_fn g_chaos_process_real_usleep;

extern __thread int g_chaos_process_tls_guard;
extern __thread uint64_t g_chaos_process_tls_prng_state;
extern uint64_t g_chaos_process_process_seed;
extern volatile uint64_t g_chaos_process_fail_after_counters[];

static inline int chaos_process_in_internal(void)
{
    return g_chaos_process_tls_guard != 0;
}

static inline int chaos_process_enter_internal(void)
{
    int previous = g_chaos_process_tls_guard;
    g_chaos_process_tls_guard = 1;
    return previous;
}

static inline void chaos_process_leave_internal(int previous)
{
    g_chaos_process_tls_guard = previous;
}

static inline uint64_t chaos_process_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

static inline int
chaos_process_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

static inline uint64_t chaos_process_atomic_fetch_add_u64(volatile uint64_t *value, uint64_t delta)
{
    return (uint64_t)__sync_fetch_and_add(value, delta);
}

static inline uint64_t chaos_process_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

static inline uint64_t chaos_process_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static inline void chaos_process_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_process_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_process_process_seed;
    seed ^= chaos_process_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed);
    if (g_chaos_process_tls_prng_state == 0U)
    {
        g_chaos_process_tls_prng_state = UINT64_C(0x2545f4914f6cdd1d);
    }
}

static inline void chaos_process_prng_seed_thread(uint64_t seed)
{
    g_chaos_process_tls_prng_state = chaos_process_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

static inline uint32_t chaos_process_prng_next_u32(void)
{
    uint64_t state;

    chaos_process_prng_ensure_seeded();
    state = g_chaos_process_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_process_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

#endif
