/**
 * @file chaos_memory_actions.c
 * @brief Implementation of fault-injection actions for libchaos-memory.
 *
 * @details
 * This translation unit implements the two injectable effects (LATENCY and
 * ERRNO) and the shared probability gate that guards both.
 *
 * @par LATENCY action
 * chaos_memory_rule_apply_latency() sleeps for rule->latency_ms milliseconds
 * before the intercepted syscall returns.  The sleep is chunked into at most
 * 1-second increments to remain within useconds_t range and to limit the
 * granularity of each reentrancy-guarded frame.  The real usleep(3) is
 * preferred over nanosleep(2) for simplicity; nanosleep is the fallback and
 * handles EINTR by restarting with the remaining time.
 *
 * @par ERRNO action
 * chaos_memory_rule_apply_errno() sets the calling thread's errno to the
 * configured value and returns 1 to signal that the hook should return the
 * error sentinel.  The calling hook in chaos_memory_hooks.c is responsible for
 * knowing whether the sentinel is MAP_FAILED ((void*)-1) for mmap(2) or -1 for
 * munmap(2)/mprotect(2)/madvise(2).
 *
 * @par Why no CORRUPT or OFFSET effect on mmap
 * mmap(2) returns a pointer to a newly-established virtual memory region.
 * Mutating the pointer after a successful mapping would mean returning a value
 * that either:
 *  a) Does not correspond to any mapping: the first load or store at that
 *     address causes SIGSEGV, which is not a testable error path — it is an
 *     uncatchable crash.
 *  b) Points into an existing mapping (e.g., offset by a known constant):
 *     this corrupts live data or code, causing undefined behaviour in the
 *     application rather than exercising its error handling.
 *  c) Points into the newly-created mapping itself: writing the sentinel
 *     requires touching potentially uninitialized anonymous pages or
 *     overwriting the first bytes of a file-backed mapping, which corrupts
 *     application data.
 * None of these is a useful fault simulation.  Pre-call ERRNO injection is
 * the only safe and semantically meaningful way to test allocator and mmap
 * error paths.
 *
 * @par Thread safety
 * All functions are safe to call concurrently from multiple threads.
 * Probability sampling uses the per-thread TLS PRNG state exclusively; no
 * synchronisation is required.
 *
 * @par Stability
 * Internal — do not depend on the symbols in this file from outside the
 * memory chaos module.
 */

#include "chaos_memory_actions.h"

#include <stdint.h>

/**
 * @brief Test whether a probability value fires for a given 32-bit PRNG sample.
 *
 * @details
 * Scales @p probability into the integer range [0, 2^32) by multiplication
 * with 4294967296.0 and compares @p sample against the threshold as a double.
 * IEEE 754 double has 53 significant bits, which is sufficient to represent
 * the threshold for any probability value with at least 5 significant decimal
 * digits without rounding error larger than 1 ULP of the threshold.
 *
 * The fast-path boundary checks for probability <= 0.0 and >= 1.0 ensure
 * correct clamping without relying on double arithmetic edge cases at the
 * extremes.
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

/**
 * @brief Test whether a probability value fires, drawing from the per-thread PRNG.
 *
 * @details
 * Draws a 32-bit value from the per-thread xorshift64* PRNG and passes it to
 * chaos_memory_probability_hit_sample().  The PRNG is lazily seeded on first
 * use by chaos_memory_prng_ensure_seeded(); that seeding path performs no I/O
 * and no heap allocation, so it is safe inside the reentrancy guard.
 */
int chaos_memory_probability_hit(double probability)
{
    return chaos_memory_probability_hit_sample(probability, chaos_memory_prng_next_u32());
}

/**
 * @brief Sleep for @p usec microseconds using the real usleep or nanosleep.
 *
 * @details
 * Sets the TLS reentrancy guard for the duration of the sleep call so that
 * any mmap call internally triggered by usleep/nanosleep (e.g., from thread
 * signal delivery, timer management in glibc, or kernel VDSO mapping) bypasses
 * fault injection.
 *
 * The guard save/restore pattern (previous/leave) is used rather than a
 * simple set/clear so that the function is safe to call from any depth of
 * already-guarded code, though in practice it is only called from
 * chaos_memory_rule_apply_latency() which is not itself guarded.
 *
 * Prefers g_chaos_memory_real_usleep if non-NULL; falls back to
 * g_chaos_memory_real_nanosleep with an EINTR-restart loop.  If both are
 * NULL (should not occur after a successful constructor run), the sleep
 * is silently skipped.
 *
 * @param usec  Number of microseconds to sleep.  Must be <= 1,000,000
 *              (callers enforce this; useconds_t on Linux is at most
 *              999999 per POSIX).
 */
static void chaos_memory_sleep_chunk(useconds_t usec)
{
    int previous;

    previous = chaos_memory_enter_internal();
    if (g_chaos_memory_real_usleep != NULL)
    {
        (void)g_chaos_memory_real_usleep(usec);
    }
    else if (g_chaos_memory_real_nanosleep != NULL)
    {
        struct timespec request;

        request.tv_sec = (time_t)(usec / 1000000U);
        request.tv_nsec = (long)((usec % 1000000U) * 1000U);
        while (g_chaos_memory_real_nanosleep(&request, &request) != 0 && errno == EINTR)
        {
        }
    }
    chaos_memory_leave_internal(previous);
}

/**
 * @brief Probabilistic trigger gate: returns non-zero if the rule should fire.
 *
 * @details
 * A NULL rule always returns 0.  Otherwise delegates to
 * chaos_memory_probability_hit(rule->probability).  Separated from the apply
 * functions so that the same gate is used for both LATENCY and ERRNO effects,
 * and so it can be exercised in isolation by unit tests with a deterministic
 * PRNG seed.
 */
int chaos_memory_rule_should_trigger(const chaos_memory_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }

    return chaos_memory_probability_hit(rule->probability);
}

/**
 * @brief Apply a LATENCY rule: sleep before the intercepted syscall.
 *
 * @details
 * Validates preconditions (non-NULL rule, correct effect, probability fires)
 * and then sleeps for exactly rule->latency_ms milliseconds by issuing
 * successive 1-second (or shorter for the last chunk) sleep calls through
 * chaos_memory_sleep_chunk().
 *
 * Chunking to 1,000,000 us per call keeps each chunk within POSIX usleep's
 * guaranteed-valid range and bounds the duration of each reentrancy-guarded
 * frame.  The total latency may be slightly larger than requested if the
 * process is descheduled between chunks, but this is acceptable for chaos
 * testing purposes.
 *
 * The loop uses uint64_t arithmetic (latency_ms * 1000ULL) to avoid overflow
 * for latency values near UINT_MAX.
 */
void chaos_memory_rule_apply_latency(const chaos_memory_rule_t *rule)
{
    uint64_t remaining_us;

    if (rule == NULL || rule->effect != CHAOS_MEMORY_EFFECT_LATENCY ||
        !chaos_memory_rule_should_trigger(rule))
    {
        return;
    }

    remaining_us = (uint64_t)rule->latency_ms * 1000ULL;
    while (remaining_us > 0ULL)
    {
        useconds_t chunk = remaining_us > 1000000ULL ? 1000000U : (useconds_t)remaining_us;

        chaos_memory_sleep_chunk(chunk);
        remaining_us -= (uint64_t)chunk;
    }
}

/**
 * @brief Apply an ERRNO rule: set errno and signal short-circuit.
 *
 * @details
 * Validates preconditions (non-NULL rule, effect == ERRNO, probability fires)
 * and if all pass, writes rule->errnum to the calling thread's errno and
 * returns 1.  The caller in chaos_memory_hooks.c translates this return value
 * into the correct error sentinel for the intercepted syscall:
 *  - mmap(2):    MAP_FAILED ((void*)-1)
 *  - munmap(2):  -1
 *  - mprotect(2): -1
 *  - madvise(2): -1
 *
 * Returns 0 without touching errno if any precondition fails.
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
