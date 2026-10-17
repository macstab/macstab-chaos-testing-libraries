/**
 * @file chaos_process_actions.c
 * @brief Effects of libchaos-process (see chaos_process_actions.h for the contracts).
 *
 * @details
 * - **Probability:** `probability` is scaled to [0, 2^32] and compared with one draw
 *   from the calling thread's PRNG.
 * - **LATENCY:** chaos_sleep_ms(), a direct clock_nanosleep system call restarted on
 *   EINTR with the remaining time; no other preloaded library can intercept it and it
 *   enters no wrapper of this one, so no guard is needed.
 * - **FAIL_AFTER:** the per-operation counter is incremented before anything else is
 *   decided, so it counts every call that reaches the rule; the threshold, probability
 *   and qualifiers are checked afterwards.
 */

#include "chaos_process_actions.h"
#include "chaos_sleep.h"

#include <errno.h>
#include <stdint.h>

/**
 * @copydoc chaos_process_probability_hit_sample
 *
 * Implementation notes: the hit rate is probability rounded to a multiple of 2^-32;
 * the extremes return before the multiply so 0 and 1 are exact.
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

/** @copydoc chaos_process_probability_hit */
int chaos_process_probability_hit(double probability)
{
    return chaos_process_probability_hit_sample(probability, chaos_process_prng_next_u32());
}

/**
 * @copydoc chaos_process_rule_should_trigger
 *
 * Implementation notes: the cheap window and size checks come before the draw; the
 * `@first` claim comes last so a call that loses the draw consumes no budget.
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
    return chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation);
}

/**
 * @copydoc chaos_process_rule_apply_latency
 *
 * Implementation notes: one decision per call; the full delay is applied or none.
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

/** @copydoc chaos_process_rule_error_number */
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
 * @copydoc chaos_process_rule_fail_after_error
 *
 * Implementation notes: the probability is drawn only past the threshold, and the
 * window, size gate and `@first` claim are checked after the draw, so calls inside the
 * first N consume neither draws nor budget. Wraparound at 2^64 is not guarded.
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
        !chaos_policy_fire(&rule->policy, rule->hit, rule->hit_generation))
    {
        return 0;
    }
    *errnum = rule->errnum;
    return 1;
}
