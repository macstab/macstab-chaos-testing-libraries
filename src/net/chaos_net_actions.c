/**
 * @file chaos_net_actions.c
 * @brief Implementation of fault-injection primitives for libchaos-net.
 *
 * @details
 * This file implements the action layer that sits between rule matching and the
 * real syscall. All functions operate on caller-supplied state (rule structs, buffers)
 * and per-thread PRNG state; there is no shared mutable state in this file.
 *
 * @par Probability sampling:
 * The probability threshold is computed as `probability * 2^32`, which maps the
 * [0.0, 1.0] range onto [0, 2^32). A uint32_t sample drawn from the PRNG is
 * compared as a double against this threshold. Double precision is sufficient for
 * this comparison: the smallest representable probability step at uint32 resolution
 * is approximately 2.3e-10, which is well above double's relative error (~2.2e-16).
 *
 * @par Buffer corruption:
 * Exactly one bit is flipped per call using uniform selection. Two independent
 * PRNG draws are used: one for the byte index and one for the bit position within
 * that byte. Drawing them separately avoids any correlation between index and bit
 * that would exist if a single 64-bit value were split.
 *
 * @par Latency injection:
 * usleep() is called in chunks of at most 1,000,000 µs. POSIX states that usleep()
 * with an argument >= 1,000,000 has undefined behaviour on some implementations.
 * The loop does not account for EINTR reducing the actual sleep; on EINTR, the
 * remaining time equals the full chunk. This is intentional: injected latency should
 * be approximately rule->latency_ms regardless of signal delivery.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

/**
 * @brief Converts a probability and a pre-drawn sample into a fire/no-fire decision.
 *
 * @details See chaos_net_actions.h for the full contract and the threshold arithmetic.
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

    /* Scale [0.0, 1.0] onto the uint32 range. The cast to double of the uint32_t
     * sample is exact for all values <= 2^53, so no precision is lost here. */
    threshold = probability * 4294967296.0;
    return (double)sample < threshold;
}

int chaos_net_probability_hit(double probability)
{
    return chaos_net_probability_hit_sample(probability, chaos_net_prng_next_u32());
}

/**
 * @brief Flips one bit in a buffer using caller-supplied samples.
 *
 * @details The byte is selected as `index_sample % size`. The bit within that byte
 * is selected as `bit_sample & 7` (lower 3 bits only). The XOR mask is `1 << bit`
 * which flips exactly the selected bit.
 *
 * No bounds checks beyond NULL/size=0 are needed: `index_sample % size` is always
 * in [0, size-1] by the definition of the modulo operator for positive operands.
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
 * @brief Draws two PRNG samples and flips one bit in the buffer.
 *
 * @details Two separate calls to chaos_net_prng_next_u32() ensure that the byte
 * index and bit position are drawn from independent parts of the PRNG stream.
 * Using a single 64-bit draw and splitting it would introduce correlation between
 * the high 32 bits (index) and the low 32 bits (bit), biasing which bytes get
 * corrupted for small buffers.
 */
void chaos_net_corrupt_buffer(void *buffer, size_t size)
{
    uint32_t index_sample = chaos_net_prng_next_u32();
    uint32_t bit_sample = chaos_net_prng_next_u32();

    chaos_net_corrupt_buffer_sample(buffer, size, index_sample, bit_sample);
}

/**
 * @brief Sleeps for rule->latency_ms milliseconds using usleep() in 1-second chunks.
 *
 * @details The chunk limit of 1,000,000 µs avoids the undefined behaviour of
 * usleep(n) with n >= 1,000,000 on non-POSIX-compliant implementations (some
 * BSDs document this restriction). The loop condition `remaining_us > 0ULL`
 * terminates naturally when the full duration has elapsed. EINTR is not handled
 * explicitly; usleep() may return early on signal delivery, and the remaining
 * time calculation still yields the correct value because `remaining_us` is
 * decremented by the requested chunk, not the actual sleep.
 */
void chaos_net_rule_apply_latency(const chaos_net_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_NET_EFFECT_LATENCY)
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;
        (void)usleep(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/**
 * @brief Returns non-zero if a rule should fire on this invocation.
 *
 * @details LATENCY rules always fire because they represent a deterministic delay,
 * not a probabilistic failure. All other effect types carry a probability field and
 * must pass the PRNG sample check.
 */
int chaos_net_rule_should_trigger(const chaos_net_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        return 1;
    }
    return chaos_net_probability_hit(rule->probability);
}

/**
 * @brief Applies an ERRNO rule by sampling probability and setting errno if it fires.
 *
 * @details The early return on NULL/wrong-effect ensures this function is safe to
 * call unconditionally from interposition wrappers that test the return value:
 * @code
 *   if (chaos_net_rule_apply_errno(&rule)) return -1;
 * @endcode
 * If the rule does not fire, errno is left unchanged, preserving whatever value
 * the libc machinery had set before this call. This matters for interposed wrappers
 * that check errno after calling helper functions before applying a rule.
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
