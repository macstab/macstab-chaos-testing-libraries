/**
 * @file chaos_process_actions.c
 * @brief Implementation of probability sampling, latency injection, and
 *        error-code dispatch for the libchaos-process fault-injection subsystem.
 *
 * @details
 * This translation unit implements the action layer declared in
 * `chaos_process_actions.h`.  It bridges the parsed rule model (from
 * `chaos_process_config.h`) with the concrete side effects applied by each
 * interposition hook in `chaos_process_hooks.c`.
 *
 * ## Probability model
 *
 * Probability decisions use a fixed-point comparison: `probability` in
 * [0.0, 1.0] is scaled to [0, 2^32) and compared against a uniform 32-bit
 * PRNG sample.  The PRNG is per-thread (no lock required) and advances as a
 * side effect of sampling.
 *
 * ## Latency injection
 *
 * The sleep is chaos_sleep_ms(): a direct clock_nanosleep system call,
 * restarted on EINTR with the remaining time, which no other preloaded library
 * can intercept and which enters no wrapper of this one.
 *
 * ## FAIL_AFTER counter
 *
 * The per-operation counter in `g_chaos_process_fail_after_counters[operation]`
 * is incremented with `__sync_fetch_and_add`, which emits a full memory
 * barrier on all supported architectures.  The returned *pre-increment* value
 * is compared against `rule->fail_after_count` to decide whether to inject
 * a fault.  The probability check is an additional gate applied after the
 * threshold check: even calls beyond the threshold only fail with probability
 * `rule->probability`.
 *
 * ## Stability
 * Private implementation — not part of the public API.
 */

#include "chaos_process_actions.h"
#include "chaos_sleep.h"

#include <errno.h>
#include <stdint.h>

/**
 * @brief Determines whether a probability threshold is met given an explicit
 *        32-bit PRNG sample.
 *
 * Threshold computation: `threshold = probability * 2^32`.  The shot fires
 * iff `(double)sample < threshold`.  Because `sample` is uniformly
 * distributed in [0, 2^32) and `threshold` is in [0, 2^32], this fires with
 * probability exactly equal to `probability` (ignoring double precision
 * rounding, which is < 1 ULP at these magnitudes).
 *
 * Special cases short-circuit before the floating-point multiply to avoid
 * any rounding edge cases at the extremes of the probability range.
 */
int chaos_process_probability_hit_sample(double probability, uint32_t sample)
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

/**
 * @brief Determines whether a probability threshold is met using the
 *        per-thread PRNG.
 *
 * Advances the per-thread PRNG by one step and delegates to
 * `chaos_process_probability_hit_sample()`.
 */
int chaos_process_probability_hit(double probability)
{
    return chaos_process_probability_hit_sample(probability, chaos_process_prng_next_u32());
}

/**
 * @brief Samples the probability of a rule and returns whether it should
 *        trigger on this call.
 */
int chaos_process_rule_should_trigger(const chaos_process_rule_t *rule)
{
    if (rule == NULL || !chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size))
    {
        return 0;
    }

    if (!chaos_process_probability_hit(rule->probability))
    {
        return 0;
    }
    return chaos_policy_fire(&rule->policy, rule->hit);
}

/**
 * @brief Applies the LATENCY effect of a rule if the probability fires.
 *
 * @details Sleeps with chaos_sleep_ms(), a direct system call: no other
 * preloaded library (libchaos-time in particular) can shorten or lengthen the
 * delay, and no interposed symbol is entered, so no reentrancy guard is needed.
 * The probability is sampled once; the full delay is either applied or not.
 */
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule)
{
    if (rule == NULL || rule->effect != CHAOS_PROCESS_EFFECT_LATENCY ||
        !chaos_process_rule_should_trigger(rule))
    {
        return;
    }
    chaos_sleep_ms((uint64_t)rule->latency_ms);
}

/**
 * @brief Evaluates an ERRNO rule and, if it fires, returns the error number.
 *
 * Samples the rule's probability; if the shot fires, writes `rule->errnum`
 * into `*errnum` and returns non-zero.  Returns 0 on any no-op path.
 */
int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum)
{
    if (rule == NULL || errnum == NULL || rule->effect != CHAOS_PROCESS_EFFECT_ERRNO ||
        !chaos_process_rule_should_trigger(rule))
    {
        return 0;
    }

    *errnum = rule->errnum;
    return 1;
}

/**
 * @brief Evaluates a FAIL_AFTER rule and, once the threshold is crossed,
 *        returns the error number.
 *
 * Atomically increments `g_chaos_process_fail_after_counters[operation]`
 * using `__sync_fetch_and_add` (full barrier) and captures the
 * *pre-increment* value in `observed`.
 *
 * The fault is injected when both conditions hold:
 *   1. `observed >= rule->fail_after_count` (the N-call grace window has
 *      been exhausted).
 *   2. The per-rule probability sample fires.
 *
 * By incrementing unconditionally before the threshold check, the counter
 * advances on every call — including those where the probability sample
 * fails.  This means probability < 1.0 causes only intermittent failures
 * after the threshold is crossed, but the counter always advances monotonically.
 *
 * Counter overflow (uint64_t wrapping at 2^64) is not guarded; at any
 * realistic call rate wrapping is not achievable in a process lifetime.
 */
int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
)
{
    uint64_t observed;

    if (rule == NULL || errnum == NULL || operation < 0 || operation >= CHAOS_PROCESS_OP_COUNT ||
        rule->effect != CHAOS_PROCESS_EFFECT_FAIL_AFTER)
    {
        return 0;
    }

    observed =
        chaos_process_atomic_fetch_add_u64(&g_chaos_process_fail_after_counters[operation], 1U);
    if (observed < rule->fail_after_count || !chaos_process_probability_hit(rule->probability))
    {
        return 0;
    }

    if (!chaos_policy_window_open(&rule->policy) ||
        !chaos_policy_size_ok(&rule->policy, rule->call_size) ||
        !chaos_policy_fire(&rule->policy, rule->hit))
    {
        return 0;
    }
    *errnum = rule->errnum;
    return 1;
}
