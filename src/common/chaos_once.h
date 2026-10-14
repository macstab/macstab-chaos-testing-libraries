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
 * States: 0 not started, 1 running, 2 done. The first caller runs the initialiser;
 * concurrent callers yield until it is done. Like `pthread_once()`, an initialiser
 * must not call back into a wrapper of the same library.
 */

#ifndef CHAOS_ONCE_H
#define CHAOS_ONCE_H

#include <sched.h>

/** @brief One-time initialisation state; initialise with CHAOS_ONCE_INIT. */
typedef int chaos_once_t;

/** @brief Initial value of a chaos_once_t. */
#define CHAOS_ONCE_INIT 0

/**
 * @brief Runs @p initialise exactly once per @p once, whichever thread calls first.
 *
 * @details Returns only after the initialiser has completed, in every caller.
 *
 * @param once        State shared by all callers.
 * @param initialise  Function to run once.
 */
static inline void chaos_once(volatile chaos_once_t *once, void (*initialise)(void))
{
    int expected = CHAOS_ONCE_INIT;

    if (__atomic_load_n(once, __ATOMIC_ACQUIRE) == 2)
    {
        return;
    }
    if (__atomic_compare_exchange_n(once, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
    {
        initialise();
        __atomic_store_n(once, 2, __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(once, __ATOMIC_ACQUIRE) != 2)
    {
        (void)sched_yield();
    }
}

#endif /* CHAOS_ONCE_H */
