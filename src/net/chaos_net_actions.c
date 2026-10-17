/**
 * @file chaos_net_actions.c
 * @brief Effect primitives of libchaos-net (contracts in chaos_net_actions.h).
 *
 * @details
 * The layer between rule matching and the real call. Only caller state (rule copy,
 * buffers) and the thread's PRNG are touched; there is no file-scope mutable state.
 *
 * @par Probability:
 * `probability * 2^32` maps [0.0, 1.0] onto [0, 2^32); the 32-bit sample is compared as
 * a double. A double holds every uint32_t exactly, and the 2^-32 (about 2.3e-10) step of
 * the sample is far above double rounding (about 1.1e-16 relative), so the comparison
 * adds no bias of its own.
 *
 * @par Corruption:
 * One bit per firing. The byte and the bit come from two separate PRNG draws.
 *
 * @par Latency:
 * chaos_sleep_ms(): raw clock_nanosleep on CLOCK_MONOTONIC, restarted on EINTR, so the
 * delay is exactly latency_ms and no other preloaded library can change it.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_sleep.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

/**
 * @brief Fire/no-fire decision for a pre-drawn sample (contract in the header).
 */
int chaos_net_probability_hit_sample(double probability, uint32_t sample)
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

    /* Scale [0.0, 1.0) onto [0, 2^32); converting a uint32_t to double is exact. */
    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

int chaos_net_probability_hit(double probability)
{
    return chaos_net_probability_hit_sample(probability, chaos_net_prng_next_u32());
}

/**
 * @brief Flips one bit chosen by caller-supplied samples (contract in the header).
 *
 * @details `index_sample % size` is always in [0, size), so no further bounds check is
 * needed once NULL and size 0 are excluded.
 */
void chaos_net_corrupt_buffer_sample(
    void *buffer, size_t size, uint32_t index_sample, uint32_t bit_sample
)
{
    unsigned char *bytes = (unsigned char *)buffer;
    size_t index;
    unsigned int bit;

    if (buffer == NULL || size == 0U)
    {
        return;
    }

    index = (size_t)(index_sample % size);
    bit = (unsigned int)(bit_sample & 7U);
    bytes[index] ^= (unsigned char)(1U << bit);
}

/**
 * @brief Flips one bit, with the byte and the bit from two PRNG draws.
 */
void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    uint32_t index_sample = chaos_net_prng_next_u32();
    uint32_t bit_sample = chaos_net_prng_next_u32();

    chaos_net_corrupt_buffer_sample(buffer, size, index_sample, bit_sample);
}

/**
 * @brief Sleeps for a firing LATENCY rule (contract in the header).
 */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    /* The qualifiers (@first, @from, @until, @size) and the hit count apply to a delay
     * as to any other effect. */
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_LATENCY ||
        !chaos_net_rule_should_trigger(rule))
    {
        return;
    }
    chaos_sleep_ms((uint64_t)rule->latency_ms);
}

/**
 * @brief Firing decision for a rule copy (contract in the header).
 *
 * @details Cheap gates first (window, size), then the PRNG draw, then the hit slot: a
 * call the window or the size gate rejects neither consumes a random number nor claims
 * an `@first` slot.
 */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
    }
    if (!chaos_net_probability_hit(rule->probability))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/**
 * @brief Applies an ERRNO rule (contract in the header).
 *
 * @details Safe to call unconditionally: a NULL or non-ERRNO rule returns 0 with errno
 * untouched, so the errno a wrapper reports after forwarding stays the real function's.
 */
int chaos_net_rule_apply_errno(const chaos_net_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_ERRNO)
    {
        return 0;
    }
    if (!chaos_net_rule_should_trigger(rule))
    {
        return 0;
    }

    errno = rule->errnum;
    return 1;
}
