/**
 * @file test_memory_actions.c
 * @brief Unit tests for memory-domain probability sampling, latency application, and
 *   errno injection helpers.
 *
 * Subsystem under test: `src/memory/chaos_memory_actions.c`
 *
 * Coverage approach:
 * - The production source file is included directly without symbol replacement.
 *   Latency and nanosleep behaviour is controlled at runtime by assigning test stubs to
 *   `g_chaos_memory_real_usleep` and `g_chaos_memory_real_nanosleep` before each sub-test.
 * - The usleep stub records each call duration in `g_sleep_chunks`; the nanosleep stub counts
 *   calls, captures the last request timespec, and supports a configurable EINTR injection
 *   via `g_nanosleep_eintr_count`.
 * - `CHAOS_MEMORY_DEFINE_TEST_GLOBALS()` instantiates all real-function-pointer globals
 *   required by the production action helpers.
 * - `reset_action_state()` resets the PRNG and function-pointer globals (via
 *   `chaos_memory_test_reset_runtime()`) and clears all sleep tracking state.
 *
 * Properties under test:
 * - `chaos_memory_probability_hit_sample`: boundary values 0.0 and 1.0; midpoint 0.5 with
 *   sample=0 (hit) and sample=UINT32_MAX (miss).
 * - `chaos_memory_rule_should_trigger(NULL)` → false.
 * - Latency with usleep: 2500 ms → exactly 3 usleep calls with durations 1 000 000,
 *   1 000 000, and 500 000 µs.
 * - Latency with nanosleep (sub-millisecond threshold): 1 ms → exactly 1 nanosleep call
 *   with `tv_nsec == 1 000 000` and `tv_sec == 0`.
 * - Latency with EINTR retry: `g_nanosleep_eintr_count = 1` causes nanosleep to be called
 *   twice (once returning EINTR with remaining=request, once succeeding).
 * - Latency with probability=0.0: no sleep calls made even when `latency_ms > 0`.
 * - `chaos_memory_rule_apply_errno`: probability=1.0 sets errno to ENOMEM and returns true;
 *   NULL rule → false.
 *
 * What is NOT tested here:
 * - Memory wrapper call paths that invoke action helpers at interception time.
 * - Config file parsing and rule selection (tested in `test_memory_config.c`).
 */

#include "../support/test_memory_support.h"

#include "../../src/memory/chaos_memory_config.h"

CHAOS_MEMORY_DEFINE_TEST_GLOBALS();

/**
 * @brief Captured usleep durations, recorded in call order by `chaos_memory_test_usleep`.
 *
 * Array size 8 is deliberately small relative to any realistic worst case; the assert
 * inside the stub will catch overflows if the production code emits more chunks than expected.
 */
static useconds_t g_sleep_chunks[8];

/** @brief Number of usleep calls recorded since the last reset. */
static size_t g_sleep_count = 0U;

/** @brief Number of nanosleep calls made since the last reset. */
static int g_nanosleep_calls = 0;

/**
 * @brief Number of remaining EINTR injections in `chaos_memory_test_nanosleep`.
 *
 * When positive, the stub returns -1 with errno EINTR and decrements the counter.
 * Set to 1 before a test that expects a retry loop.
 */
static int g_nanosleep_eintr_count = 0;

/**
 * @brief Last `struct timespec` passed to `chaos_memory_test_nanosleep` as `request`.
 *
 * Cleared in `reset_action_state()`; compared in tests to verify the correct duration
 * is passed when nanosleep is used for sub-millisecond latency.
 */
static struct timespec g_last_nanosleep_request;

/**
 * @brief Test-local usleep stub that records call durations instead of sleeping.
 *
 * Asserts that `g_sleep_count` has not exceeded the array bounds before recording. Always
 * returns 0 (success).
 *
 * @param usec  Duration in microseconds, stored at `g_sleep_chunks[g_sleep_count]`.
 * @return 0.
 */
static int chaos_memory_test_usleep(useconds_t usec)
{
    assert(g_sleep_count < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]));
    g_sleep_chunks[g_sleep_count++] = usec;
    return 0;
}

/**
 * @brief Test-local nanosleep stub that records calls and optionally injects EINTR.
 *
 * Increments `g_nanosleep_calls` and copies `*request` into `g_last_nanosleep_request`.
 * When `g_nanosleep_eintr_count > 0`: decrements the counter, fills `*remaining` with
 * `*request` (mimicking the kernel's remaining-time behaviour), sets errno to EINTR, and
 * returns -1. On the next call (counter now 0): fills `remaining` with zeros and returns 0.
 *
 * @param request    Requested sleep duration.
 * @param remaining  Output for time not yet slept when interrupted; may be NULL.
 * @return 0 on success, -1 with errno EINTR when injecting an interruption.
 */
static int chaos_memory_test_nanosleep(const struct timespec *request, struct timespec *remaining)
{
    ++g_nanosleep_calls;
    assert(request != NULL);
    g_last_nanosleep_request = *request;
    if (g_nanosleep_eintr_count > 0)
    {
        --g_nanosleep_eintr_count;
        if (remaining != NULL)
        {
            remaining->tv_sec = request->tv_sec;
            remaining->tv_nsec = request->tv_nsec;
        }
        errno = EINTR;
        return -1;
    }
    if (remaining != NULL)
    {
        remaining->tv_sec = 0;
        remaining->tv_nsec = 0L;
    }
    return 0;
}

#include "../../src/memory/chaos_memory_actions.c"

/**
 * @brief Reset all per-test action state to well-known defaults.
 *
 * Calls `chaos_memory_test_reset_runtime()` to zero PRNG and function-pointer globals,
 * then clears sleep count, nanosleep counters, and the sleep chunk array.
 */
static void reset_action_state(void)
{
    size_t index;

    chaos_memory_test_reset_runtime();
    g_sleep_count = 0U;
    g_nanosleep_calls = 0;
    g_nanosleep_eintr_count = 0;
    g_last_nanosleep_request.tv_sec = 0;
    g_last_nanosleep_request.tv_nsec = 0L;
    for (index = 0U; index < sizeof(g_sleep_chunks) / sizeof(g_sleep_chunks[0]); ++index)
    {
        g_sleep_chunks[index] = 0U;
    }
}

/**
 * @brief Invariant: probability sampling produces the correct binary decision at all
 *   boundary values; `should_trigger(NULL)` is safe.
 *
 * Triggering condition: `chaos_memory_probability_hit_sample` with p=0.0/1.0/0.5 and
 *   sample=0/UINT32_MAX; `chaos_memory_rule_should_trigger(NULL)`.
 *
 * Expected observable behaviour:
 * - `probability_hit_sample(0.0, 0)` → false.
 * - `probability_hit_sample(1.0, UINT32_MAX)` → true.
 * - `probability_hit_sample(0.5, 0)` → true (0 < threshold).
 * - `probability_hit_sample(0.5, UINT32_MAX)` → false (UINT32_MAX ≥ threshold).
 * - `rule_should_trigger(NULL)` → false (NULL guard).
 */
static void test_probability_helpers(void)
{
    assert(!chaos_memory_probability_hit_sample(0.0, 0U));
    assert(chaos_memory_probability_hit_sample(1.0, 0xffffffffU));
    assert(chaos_memory_probability_hit_sample(0.5, 0U));
    assert(!chaos_memory_probability_hit_sample(0.5, 0xffffffffU));
    assert(!chaos_memory_rule_should_trigger(NULL));
}

/**
 * @brief Invariant: latency application decomposes correctly into usleep and nanosleep
 *   calls, retries on EINTR, and skips sleep when probability is 0.
 *
 * Triggering condition: four sub-tests, each calling `reset_action_state()` and then
 *   `chaos_memory_rule_apply_latency` with a distinct rule configuration.
 *
 * Expected observable behaviour:
 * - Rule with LATENCY effect, probability=1.0, latency_ms=2500: `g_sleep_count == 3`,
 *   `g_sleep_chunks[0] == 1 000 000`, `[1] == 1 000 000`, `[2] == 500 000` µs.
 * - Rule with LATENCY effect, probability=1.0, latency_ms=1 (sub-millisecond path via
 *   nanosleep): `g_sleep_count == 0`; `g_nanosleep_calls == 1`;
 *   `g_last_nanosleep_request.tv_sec == 0` and `tv_nsec == 1 000 000`.
 * - Same rule with `g_nanosleep_eintr_count = 1`: `g_nanosleep_calls == 2` (one EINTR
 *   retry loop iteration before the final successful call).
 * - Rule with probability=0.0, latency_ms=100: no sleep calls made (`g_sleep_count == 0`).
 */
static void test_latency_helper(void)
{
    chaos_memory_rule_t rule;

    reset_action_state();
    g_chaos_memory_real_usleep = chaos_memory_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 2500U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 3U);
    assert(g_sleep_chunks[0] == 1000000U);
    assert(g_sleep_chunks[1] == 1000000U);
    assert(g_sleep_chunks[2] == 500000U);

    reset_action_state();
    g_chaos_memory_real_nanosleep = chaos_memory_test_nanosleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
    assert(g_nanosleep_calls == 1);
    assert(g_last_nanosleep_request.tv_sec == 0);
    assert(g_last_nanosleep_request.tv_nsec == 1000000L);

    reset_action_state();
    g_chaos_memory_real_nanosleep = chaos_memory_test_nanosleep;
    g_nanosleep_eintr_count = 1;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 1.0;
    rule.latency_ms = 1U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_nanosleep_calls == 2);

    reset_action_state();
    g_chaos_memory_real_usleep = chaos_memory_test_usleep;
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_LATENCY;
    rule.probability = 0.0;
    rule.latency_ms = 100U;
    chaos_memory_rule_apply_latency(&rule);
    assert(g_sleep_count == 0U);
}

/**
 * @brief Invariant: `chaos_memory_rule_apply_errno` sets errno and returns true with
 *   probability=1.0, and returns false for a NULL rule.
 *
 * Triggering condition: a rule with ERRNO effect, errnum=ENOMEM, probability=1.0; then
 *   `apply_errno(NULL)`.
 *
 * Expected observable behaviour:
 * - `apply_errno(&rule)` with probability=1.0: returns true; `errno == ENOMEM`.
 *   ENOMEM is the canonical allocation-failure code for memory interceptors and is used here
 *   to verify that the specific error code from the rule is what actually gets injected.
 * - `apply_errno(NULL)` → false (NULL guard).
 */
static void test_errno_helper(void)
{
    chaos_memory_rule_t rule;

    reset_action_state();
    (void)memset(&rule, 0, sizeof(rule));
    rule.effect = CHAOS_MEMORY_EFFECT_ERRNO;
    rule.probability = 1.0;
    rule.errnum = ENOMEM;
    errno = 0;
    assert(chaos_memory_rule_apply_errno(&rule));
    assert(errno == ENOMEM);
    assert(!chaos_memory_rule_apply_errno(NULL));
}

int main(void)
{
    test_probability_helpers();
    test_latency_helper();
    test_errno_helper();
    return 0;
}
