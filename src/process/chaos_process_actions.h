/**
 * @file chaos_process_actions.h
 * @brief Probability evaluation, latency injection, and error-code dispatch
 *        for the libchaos-process fault-injection subsystem.
 *
 * @details
 * This header declares the action layer — the functions that translate a
 * matched `chaos_process_rule_t` into concrete runtime effects:
 *
 *  - **ERRNO**: sample the probability, and if the shot fires, return the
 *    configured error number to the caller.
 *  - **LATENCY**: sample the probability, and if the shot fires, sleep for
 *    the configured number of milliseconds before returning to the hook.
 *  - **FAIL_AFTER**: increment the per-operation atomic counter and, once the
 *    threshold is crossed, return the configured error number.
 *
 * All probability decisions use the per-thread xorshift64* PRNG maintained
 * in `g_chaos_process_tls_prng_state`.  The PRNG state is not shared across
 * threads, so probability sampling is lock-free.
 *
 * ## Stability
 * Private — not part of the public API.
 */

#ifndef CHAOS_PROCESS_ACTIONS_H
#define CHAOS_PROCESS_ACTIONS_H

#include "chaos_process_config.h"

/**
 * @brief Determines whether a probability threshold is met given an explicit
 *        PRNG sample.
 *
 * Maps `probability` onto the range [0, 2^32) and compares against `sample`.
 * A sample value uniformly distributed in [0, 2^32) hits the threshold with
 * probability exactly equal to `probability`.
 *
 * Short-circuits at the extremes:
 *   - `probability <= 0.0`: always returns 0 (never fires).
 *   - `probability >= 1.0`: always returns 1 (always fires).
 *
 * This overload exists for testability: test code can inject a specific
 * sample value rather than relying on the PRNG.
 *
 * @param probability Probability in [0.0, 1.0].
 * @param sample      A 32-bit uniform random value to compare against.
 * @return Non-zero if the probability threshold is met; 0 otherwise.
 */
int chaos_process_probability_hit_sample(double probability, uint32_t sample);

/**
 * @brief Determines whether a probability threshold is met using the
 *        per-thread PRNG.
 *
 * Draws one 32-bit value from `chaos_process_prng_next_u32()` and delegates
 * to `chaos_process_probability_hit_sample()`.  The PRNG is advanced as a
 * side effect; callers must not rely on the state remaining unchanged after
 * this call.
 *
 * @param probability Probability in [0.0, 1.0].
 * @return Non-zero if the probability threshold is met; 0 otherwise.
 */
int chaos_process_probability_hit(double probability);

/**
 * @brief Samples the probability of a rule and returns whether it should
 *        trigger on this call.
 *
 * Thin wrapper around `chaos_process_probability_hit(rule->probability)`.
 * Returns 0 if `rule` is NULL.
 *
 * @param rule The rule whose `probability` field is to be sampled.
 * @return Non-zero if the rule should fire on this call; 0 otherwise.
 */
int chaos_process_rule_should_trigger(const chaos_process_rule_t *rule);

/**
 * @brief Applies the LATENCY effect of a rule if the probability fires.
 *
 * Sleeps for `rule->latency_ms` milliseconds by calling the real `usleep`
 * (preferred) or `nanosleep` (fallback) via the re-entrancy guard.  The
 * delay is broken into 1-second chunks to stay within `usleep`'s POSIX
 * limit of 1,000,000 microseconds per call.
 *
 * This function is a no-op if:
 *   - `rule` is NULL.
 *   - `rule->effect != CHAOS_PROCESS_EFFECT_LATENCY`.
 *   - The probability sampling returns 0.
 *
 * @warning Callers in the `vfork` path must NOT call this function.  The
 *          vfork window (between `vfork()` return in the child and the
 *          child's `exec`/`_exit`) requires strictly async-signal-safe
 *          functions.  `usleep` and `nanosleep` are not async-signal-safe
 *          and must not be called while sharing the parent's address space.
 *          See `chaos_process_hooks.c` for how the `vfork` wrapper handles
 *          this constraint.
 *
 * @param rule The LATENCY rule to apply.
 */
void chaos_process_rule_apply_latency(const chaos_process_rule_t *rule);

/**
 * @brief Evaluates an ERRNO rule and, if it fires, returns the error number.
 *
 * Samples the probability and, if the shot fires, writes the rule's `errnum`
 * into `*errnum` and returns non-zero.
 *
 * This function is a no-op (returns 0) if:
 *   - `rule` or `errnum` is NULL.
 *   - `rule->effect != CHAOS_PROCESS_EFFECT_ERRNO`.
 *   - The probability sampling returns 0.
 *
 * @param rule   The ERRNO rule to evaluate.
 * @param errnum Output: set to `rule->errnum` if the rule fires.
 * @return Non-zero if the rule fired and `*errnum` was set; 0 otherwise.
 */
int chaos_process_rule_error_number(const chaos_process_rule_t *rule, int *errnum);

/**
 * @brief Evaluates a FAIL_AFTER rule and, once the threshold is crossed,
 *        returns the error number.
 *
 * Atomically increments `g_chaos_process_fail_after_counters[operation]`
 * using `__sync_fetch_and_add` (full barrier) and compares the
 * *pre-increment* value against `rule->fail_after_count`:
 *
 *   - If pre-increment < `fail_after_count`: this call is within the allowed
 *     window; returns 0 (do not inject a fault).
 *   - If pre-increment >= `fail_after_count`: the threshold has been crossed;
 *     additionally samples the probability.  If the probability shot also
 *     fires, writes `rule->errnum` into `*errnum` and returns non-zero.
 *
 * Counter semantics:
 *   - Counter starts at 0 (all elements of `g_chaos_process_fail_after_counters`
 *     are zero-initialised and reset to zero on every config reload).
 *   - The first call returns pre-increment value 0.
 *   - With `fail_after_count = N`: calls 1..N succeed (pre-increment 0..N-1),
 *     call N+1 fails (pre-increment N >= N).  With N=0, every call fails.
 *   - Counter is shared across all threads for the operation (intentional:
 *     models system-wide resource exhaustion rather than per-thread limits).
 *   - On uint64_t wraparound (after ~1.8 * 10^19 calls), the counter
 *     restarts at 0, effectively re-arming the FAIL_AFTER trigger.
 *
 * @param rule      The FAIL_AFTER rule to evaluate.
 * @param operation The operation index (determines which counter to use).
 * @param errnum    Output: set to `rule->errnum` if the rule fires.
 * @return Non-zero if the rule fired and `*errnum` was set; 0 otherwise.
 */
int chaos_process_rule_fail_after_error(
    const chaos_process_rule_t *rule, chaos_process_operation_t operation, int *errnum
);

#endif
