/**
 * @file chaos_once.h
 * @brief One-time initialisation that needs nothing beyond the C library itself.
 *
 * Every library resolves its downstream symbols on the first wrapper call, from
 * whichever thread gets there first. `pthread_once()` would be the obvious tool,
 * but before glibc 2.34 it lives in libpthread, not libc: a preloaded library that
 * calls it fails with "undefined symbol: pthread_once" in every program that does
 * not load libpthread -- `cat`, `sh`, most command-line tools on Debian 11,
 * Ubuntu 20.04, RHEL 8 and Amazon Linux 2. This header provides the same guarantee
 * with compiler atomics and `sched_yield()`, which every libc exports.
 *
 * States: 0 not started, 1 running, 2 done. The first caller runs the
 * initialiser; other threads yield until it is done.
 *
 * Unlike `pthread_once()`, a call from inside the initialiser, on the thread
 * running it, does not wait for itself forever: it returns 0 at once, and the
 * caller goes on without what the initialiser has not set up yet. That happens
 * when symbol lookup allocates and a preloaded allocator maps memory through the
 * same library (dlsym -> calloc -> jemalloc -> mmap -> libchaos-memory).
 */

#ifndef CHAOS_ONCE_H
#define CHAOS_ONCE_H

#include <sched.h>

/** @brief One-time initialisation state; initialise with CHAOS_ONCE_INIT. */
typedef int chaos_once_t;

/** @brief Initial value of a chaos_once_t. */
#define CHAOS_ONCE_INIT 0

/** @brief A chaos_once_t whose initialiser has completed. */
#define CHAOS_ONCE_DONE 2

/**
 * @brief Set while the calling thread runs an initialiser of this translation
 *        unit (each library has one once-control per unit).
 */
static __thread int g_chaos_once_running = 0;

/**
 * @brief Runs @p initialise exactly once per @p once, whichever thread calls first.
 *
 * @details Returns after the initialiser has completed, in every caller but one
 * that the initialiser itself causes on its own thread.
 *
 * @param once        State shared by all callers.
 * @param initialise  Function to run once.
 * @return 1 when the initialiser has completed, 0 when it is still running on the
 *         calling thread (a call from inside it).
 */
static inline int chaos_once(volatile chaos_once_t *once, void (*initialise)(void))
{
    int expected = CHAOS_ONCE_INIT;

    if (__atomic_load_n(once, __ATOMIC_ACQUIRE) == CHAOS_ONCE_DONE)
    {
        return 1;
    }
    if (__atomic_compare_exchange_n(once, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        g_chaos_once_running = 1;
        initialise();
        g_chaos_once_running = 0;
        __atomic_store_n(once, CHAOS_ONCE_DONE, __ATOMIC_RELEASE);
        return 1;
    }
    if (g_chaos_once_running)
    {
        return 0;
    }
    while (__atomic_load_n(once, __ATOMIC_ACQUIRE) != CHAOS_ONCE_DONE)
    {
        (void)sched_yield();
    }
    return 1;
}

#endif /* CHAOS_ONCE_H */
