/**
 * @file chaos_memory_actions.c
 * @brief The two effects of libchaos-memory (LATENCY, ERRNO) and the decision
 *        whether a matched rule fires.
 *
 * @details
 * A rule fires when, in this order: its `@from`/`@until` window is open, its
 * `@size` gate passes for the call's length, a draw from the per-thread PRNG falls
 * below its probability, and chaos_policy_fire() grants an `@first` slot (which
 * also counts the hit). Only then is the effect applied:
 *  - LATENCY sleeps latency_ms with chaos_sleep_ms() (a raw clock_nanosleep on
 *    CLOCK_MONOTONIC, restarted on EINTR, invisible to libchaos-time); the real
 *    function runs afterwards.
 *  - ERRNO stores the errno and tells the wrapper to return its failure value
 *    (MAP_FAILED, -1, or for posix_madvise() the error number) without calling the
 *    real function.
 *
 * @par Why there is no CORRUPT/OFFSET effect on mmap()
 * The only thing to corrupt is the returned address. One that maps nothing turns
 * the first access into SIGSEGV; one inside another mapping corrupts live data;
 * writing into the new mapping corrupts application data. None exercises an error
 * path, so mmap() faults are injected before the call, as ERRNO.
 *
 * @par Thread and signal safety
 * Lock-free and allocation-free; the PRNG is thread-local.
 */

#include "chaos_memory_actions.h"
#include "chaos_sleep.h"

#include <errno.h>
#include <stdint.h>

/**
 * @brief Bernoulli trial of @p probability with a given 32-bit sample.
 *
 * @details Fires when sample < probability * 2^32 (compared as doubles: the 53-bit
 * mantissa holds the 32-bit threshold exactly). Probabilities <= 0 and >= 1 are
 * decided before the arithmetic.
 */
int chaos_memory_probability_hit_sample(double probability, uint32_t sample)
{
    double threshold;

    if (probability <= 0.0)
    {
        return 0;
    }
    if (probability >= 1.0)
    {
        return 1;
    }

    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

/** @brief Bernoulli trial of @p probability with the next value of this thread's PRNG. */
int chaos_memory_probability_hit(double probability)
{
    return chaos_memory_probability_hit_sample(probability, chaos_memory_prng_next_u32());
}

/**
 * @brief Decides whether @p rule fires on this call, and counts the hit if so.
 *
 * @details Checks are ordered cheapest and side-effect-free first: the window and
 * the size gate consume no PRNG value, so a gated-out call does not shift the
 * random sequence; chaos_policy_fire() comes last because it claims an `@first`
 * slot and increments the hit counter.
 */
int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }

    if (!chaos_memory_probability_hit(rule->probability))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/**
 * @brief Sleeps latency_ms if @p rule is a LATENCY rule that fires.
 *
 * @details chaos_sleep_ms() is a raw system call: libchaos-time cannot shorten or
 * lengthen the delay, and no wrapper is entered, so no reentrancy guard is
 * needed. One decision per call: the whole delay or none.
 */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_LATENCY ||
        !chaos_memory_rule_should_trigger(rule))
    {
        return;
    }
    chaos_sleep_ms((uint64_t)rule->latency_ms);
}

/**
 * @brief Sets errno to rule->errnum if @p rule is an ERRNO rule that fires.
 *
 * @details Returns 1 so the wrapper returns its failure value without calling the
 * real function; errno is untouched when it returns 0.
 */
int chaos_memory_rule_apply_errno(const chaos_memory_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_ERRNO ||
        !chaos_memory_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
