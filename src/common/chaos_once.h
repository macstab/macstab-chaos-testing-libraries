/**
 * @file chaos_once.h
 * @brief Run-once initialisation built only on compiler atomics and `sched_yield()`.
 *
 * @details
 * Every library resolves its real functions on the first wrapper call, from whichever
 * thread arrives first. `pthread_once()` is not usable: before glibc 2.34 it lives in
 * libpthread, not libc, and a preloaded library that references it fails with
 * "undefined symbol: pthread_once" in every program that does not load libpthread
 * (`cat`, `sh` and most command-line tools on Debian 11, Ubuntu 20.04, RHEL 8 and
 * Amazon Linux 2). `sched_yield()` and the `__atomic` builtins need nothing beyond libc.
 *
 * State machine of a chaos_once_t: 0 (not started) -> 1 (running) -> 2 (done). The CAS
 * 0 -> 1 elects one initialiser; every other thread spins on `sched_yield()` until it
 * reads 2. The release store of 2 pairs with the acquire loads, so whatever the
 * initialiser wrote is visible to every caller that returns 1.
 *
 * Re-entry differs from `pthread_once()` on purpose. A call made from inside the
 * initialiser on the thread running it returns 0 at once instead of deadlocking, and
 * the caller must proceed without the state the initialiser has not set up yet (the
 * libraries then call through to the real function). This happens when symbol lookup
 * allocates and a preloaded allocator maps memory through the same library:
 * `dlsym` -> `calloc` -> jemalloc -> `mmap` -> libchaos-memory.
 *
 * Limits:
 * - The re-entry flag is one thread-local per translation unit, not per once-control: a
 *   thread running any initialiser of the unit gets 0 from every chaos_once() of that
 *   unit that is not done. Each library has one once-control per unit, so the two
 *   coincide.
 * - An initialiser that never returns blocks every other caller forever.
 * - Not async-signal-safe while state is 1: a signal handler on another thread spins
 *   until the initialiser finishes; on the initialising thread it gets 0.
 * - fork() during an initialisation leaves state 1 in the child with no thread to
 *   finish it; a caller in the child would spin forever.
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
 * @brief Non-zero while the calling thread runs an initialiser of this translation unit;
 *        what lets a re-entrant call return 0 instead of waiting for itself.
 */
static __thread int g_chaos_once_running = 0;

/**
 * @brief Runs @p initialise exactly once per @p once; the first caller runs it, the
 *        others wait for it to finish.
 *
 * @details The fast path, once done, is one acquire load. A caller other than the
 * initialising thread spins with `sched_yield()` until the state reads 2.
 *
 * @param once        Shared state, statically initialised to CHAOS_ONCE_INIT.
 * @param initialise  Initialiser; must return, and may itself call chaos_once() on @p once
 *                    (that nested call returns 0).
 * @return 1 when the initialiser has completed and its writes are visible; 0 when it is
 *         still running on the calling thread (a re-entrant call).
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
