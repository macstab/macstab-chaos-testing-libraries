/**
 * @file chaos_time_actions.h
 * @brief Rule execution API — probability gating, LATENCY sleep, ERRNO
 *        injection, and OFFSET application for libchaos-time.
 *
 * This header declares the six functions that translate a matched
 * chaos_time_rule_t into an observable side effect.  They form a clean
 * boundary between the config/selection layer (chaos_time_config.h) and the
 * hook wrappers (chaos_time_hooks.c): the hooks call these functions without
 * knowing how probability sampling, real-function dispatch, or nanosecond
 * arithmetic work.
 *
 * ### Execution model
 *
 * For each intercepted call, the hook wrapper may call up to three of these
 * functions in a fixed order:
 *
 *  1. **LATENCY** (chaos_time_rule_apply_latency) — pre-call sleep.
 *  2. **ERRNO**   (chaos_time_rule_apply_errno)   — pre-call fault injection;
 *     if triggered, the hook returns -1 without calling the real function.
 *  3. **OFFSET**  (chaos_time_rule_apply_offset)  — post-call time shift;
 *     applied to the struct timespec written by the real function.
 *
 * Each function performs its own probability gate internally via
 * chaos_time_rule_should_trigger(), so callers do not need to sample
 * probability themselves.
 *
 * @module chaos-time
 * @stability Internal.
 */

#ifndef CHAOS_TIME_ACTIONS_H
#define CHAOS_TIME_ACTIONS_H

#include "chaos_time_config.h"

/**
 * Tests whether a probability value is hit given a pre-drawn PRNG sample.
 *
 * The sample (a uint32_t in [0, 2^32)) is compared against the threshold
 * @c probability * 2^32.  Using a pre-drawn sample allows callers to reuse
 * a single draw for multiple comparisons, though in practice callers use the
 * single-call variant chaos_time_probability_hit().
 *
 * Special cases:
 *  - probability ≤ 0.0 → always returns 0 (never trigger).
 *  - probability ≥ 1.0 → always returns 1 (always trigger).
 *
 * @param probability  Desired trigger probability in [0.0, 1.0].
 * @param sample       Pre-drawn uniform random uint32_t.
 * @return             Non-zero if the sample falls below the threshold.
 */
int chaos_time_probability_hit_sample(double probability, uint32_t sample);

/**
 * Draws a PRNG sample and tests it against a probability threshold.
 *
 * Convenience wrapper around chaos_time_probability_hit_sample() that calls
 * chaos_time_prng_next_u32() for the sample.  Advances the per-thread PRNG
 * state as a side effect.
 *
 * @param probability  Desired trigger probability in [0.0, 1.0].
 * @return             Non-zero if the rule should trigger on this call.
 */
int chaos_time_probability_hit(double probability);

/**
 * Evaluates the probability gate for a rule.
 *
 * Thin wrapper that extracts the probability field and calls
 * chaos_time_probability_hit().  Centralises the NULL guard so that action
 * functions do not each need to repeat it.
 *
 * @param rule  Rule to evaluate.  May be NULL (returns 0).
 * @return      Non-zero if the rule's probability gate fires on this call.
 */
int chaos_time_rule_should_trigger(const chaos_time_rule_t *rule);

/**
 * Applies a LATENCY effect: sleeps for rule->latency_ms milliseconds before
 * the real function call.
 *
 * ### Reentrancy contract
 *
 * The sleep is performed via the real usleep or nanosleep implementation
 * (g_chaos_time_real_usleep / g_chaos_time_real_nanosleep), not through the
 * wrapper symbols.  The reentrancy guard is raised (via
 * chaos_time_enter_internal()) inside chaos_time_sleep_chunk() before
 * calling the real sleep function.  This is mandatory when the intercepted
 * symbol is nanosleep itself:
 *
 * @code
 *   Application calls nanosleep()
 *     → nanosleep wrapper (guard = 0)
 *       LATENCY matched; chaos_time_rule_apply_latency() called
 *         → chaos_time_sleep_chunk()
 *           → chaos_time_enter_internal()  [saves previous=0, sets guard=1]
 *           → g_chaos_time_real_nanosleep()  [real kernel call, no wrapper]
 *           → chaos_time_leave_internal(0)  [restores guard=0]
 *         ← returns
 *       ← latency applied
 *     real nanosleep called by wrapper
 *   ← returns to application
 * @endcode
 *
 * Without the guard, if g_chaos_time_real_nanosleep somehow resolved back to
 * the wrapper (which must not happen with correct RTLD_NEXT resolution but is
 * a useful invariant to maintain), or if a future code path calls the wrapped
 * symbol, the result would be infinite recursion.  The guard also prevents
 * any clock_gettime call made by the C runtime's sleep implementation from
 * being intercepted during the LATENCY sleep, which would otherwise inject
 * chaos inside the chaos injection.
 *
 * The latency is broken into chunks of at most 1,000,000 µs (1 second) so
 * that large values do not exceed useconds_t's maximum on any platform.
 *
 * No-ops if rule is NULL, effect is not CHAOS_TIME_EFFECT_LATENCY, or the
 * probability gate does not fire.
 *
 * @param rule  Rule to apply.  May be NULL.
 */
void chaos_time_rule_apply_latency(const chaos_time_rule_t *rule);

/**
 * Applies an ERRNO effect: sets errno and signals the hook to return -1.
 *
 * Called before the real function.  If the probability gate fires, sets the
 * global errno to rule->errnum and returns non-zero, indicating to the hook
 * wrapper that it should return -1 immediately without calling the real
 * function.
 *
 * No-ops (returns 0) if rule is NULL, effect is not CHAOS_TIME_EFFECT_ERRNO,
 * or the probability gate does not fire.
 *
 * @param rule  Rule to apply.  May be NULL.
 * @return      Non-zero if errno was set and the caller should return -1;
 *              zero if the real function should proceed normally.
 */
int chaos_time_rule_apply_errno(const chaos_time_rule_t *rule);

/**
 * Applies an OFFSET effect: adds a signed millisecond delta to a struct
 * timespec after the real clock_gettime call returns.
 *
 * ### Semantics
 *
 * The delta is added to the value in @p value (which was populated by
 * g_chaos_time_real_clock_gettime).  The kernel clock is not modified; only
 * the value visible to the application at the ABI boundary changes.
 *
 * For CLOCK_MONOTONIC, this deliberately and intentionally breaks the
 * monotonicity guarantee: two calls separated by a config change, or two
 * calls where one fires the probability gate and one does not, will return
 * timestamps that go backwards.  This is the intended behaviour — the library
 * is testing whether applications handle such conditions gracefully.
 *
 * Thread-safety: the offset is stateless.  Two threads calling clock_gettime
 * concurrently both receive the same delta applied independently to their
 * respective real return values.  There is no per-thread accumulation.
 *
 * ### Arithmetic
 *
 * The millisecond delta is split into a whole-second part and a sub-second
 * nanosecond residual, each added to the corresponding field of @p value.
 * Carry propagation between the nanosecond and second fields is handled by
 * iterative normalisation: if tv_nsec ≥ 1,000,000,000 it is reduced and
 * tv_sec is incremented; if tv_nsec < 0 it is corrected by subtracting one
 * second's worth of nanoseconds and decrementing tv_sec.  If the resulting
 * tv_sec is negative (the offset is larger in magnitude than the current
 * time), the result is clamped to {0, 0} rather than returning a negative
 * timespec, which would violate the POSIX requirement that tv_nsec ∈
 * [0, 999,999,999].
 *
 * No-ops if rule is NULL, value is NULL, effect is not CHAOS_TIME_EFFECT_OFFSET,
 * or the probability gate does not fire.
 *
 * @param rule   Rule to apply.  May be NULL.
 * @param value  struct timespec to modify in-place.  May be NULL (no-op).
 */
void chaos_time_rule_apply_offset(const chaos_time_rule_t *rule, struct timespec *value);

#endif
