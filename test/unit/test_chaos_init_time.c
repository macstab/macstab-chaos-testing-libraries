/**
 * @file test_chaos_init_time.c
 * @brief Proves chaos-init turns a tracee's clock reads and sleeps into libchaos-time
 *        verdicts, and produces the value a changed clock read returns.
 *
 * @details Unit under test: `chaos_init_time_decide()`, `chaos_init_time_commit()` and the
 * two filter inputs in `src/init/chaos_init_time.c`, compiled in by `#include` together
 * with the libchaos-time rule core it embeds, `chaos_init_proc.c` (the write into the
 * tracee) and `chaos_init_tracee.c` (per-process hit slots).
 *
 * Isolation: no supervisor, no seccomp filter and no tracee. Each call is a
 * `chaos_init_call_t` filled the way a seccomp notification fills it, with this test
 * process as the caller (`tid = getpid()`), so the value is written into this process's
 * own memory through the real process_vm_writev(). The rule file is replaced by an atomic
 * rename(2), and `g_chaos_time_check_interval_ns = 0` makes every decision re-check it.
 *
 * Seam: `CHAOS_INIT_TIME_CLOCK` replaces the supervisor's own clock read, which makes a
 * clock it cannot read testable and lets the test state what the clock says.
 *
 * Properties proven:
 * - clock_gettime, gettimeofday and the two sleeps reach their operation; any other
 *   system call returns 0 (not time's);
 * - LATENCY gives DELAY and ERRNO gives FAIL, on a read and on a sleep, and both on one
 *   call give DELAY carrying the errno;
 * - a read a value-changing rule matches does not run: the verdict returns 0 and the
 *   value is written at commit, with OFFSET shifting it, FREEZE holding it and REGRESS
 *   stepping it back;
 * - gettimeofday gets a timeval, clock_gettime a timespec;
 * - a read without a buffer, a clock the supervisor cannot read, and a call whose rule
 *   file changed between decision and commit are left to the kernel;
 * - the filter is asked for exactly what the rules need: the sleeps alone, the wall clock
 *   calls only for a wall clock rule, and the clock list is empty when a rule names no
 *   clock (which means every clock);
 * - a `usleep` rule rejects the whole file, because libc sleeps through nanosleep and the
 *   supervisor cannot tell the two apart.
 */

#include <time.h>

/* The clock the supervisor reads; the test answers for it. */
static int g_clock_fails = 0;
static struct timespec g_now;
static clockid_t g_asked = 0;
static int test_clock(clockid_t clock, struct timespec *value)
{
    g_asked = clock;
    if (g_clock_fails)
    {
        return -1;
    }
    *value = g_now;
    return 0;
}
#define CHAOS_INIT_TIME_CLOCK(clock, value) test_clock((clock), (value))

#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_time.c"
#include "../../src/init/chaos_init_tracee.c"

/* The seed source lives in chaos_init_core.c, which this test does not include; the
 * declaration comes from chaos_init_core.h, so the definition may follow the include. A
 * fixed value keeps the rules' draw keys the same in every run. */
uint64_t chaos_init_seed(void)
{
    return UINT64_C(0x5eed5eed5eed5eed);
}

#include <assert.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/** @brief Replaces the rule file by rename(2), so a reload never sees a partial file. */
static void write_rules(const char *rules)
{
    FILE *file = fopen("/tmp/.chaos-time.conf.new", "w");

    assert(file != NULL && fputs(rules, file) >= 0 && fclose(file) == 0);
    assert(rename("/tmp/.chaos-time.conf.new", "/tmp/.chaos-time.conf") == 0);
}

/**
 * @brief Decides a time call of this process and asserts time owns it.
 *
 * @details The verdict is pre-set to FAIL so that a PASS result proves the decision wrote
 * the verdict rather than leaving stale state.
 */
static chaos_init_verdict_t decide(int nr, uint64_t first, uint64_t second)
{
    chaos_init_call_t call;
    chaos_init_verdict_t verdict;

    memset(&call, 0, sizeof(call));
    memset(&verdict, 0, sizeof(verdict));
    call.tid = getpid();
    call.nr = nr;
    call.args[0] = first;
    call.args[1] = second;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_time_decide(&call, &verdict) == 1);
    return verdict;
}

/** @brief decide() followed by the commit, which is how the supervisor answers a read. */
static chaos_init_verdict_t serve(int nr, uint64_t first, uint64_t second)
{
    const chaos_init_verdict_t verdict = decide(nr, first, second);
    chaos_init_call_t call;

    memset(&call, 0, sizeof(call));
    call.tid = getpid();
    call.nr = nr;
    call.args[0] = first;
    call.args[1] = second;
    chaos_init_time_commit(&call, &verdict);
    return verdict;
}

/** @brief Address of @p pointer as a call argument. */
#define P(pointer) ((uint64_t)(uintptr_t)(pointer))

int main(void)
{
    struct timespec value;
    struct timeval day;
    chaos_init_call_t other;
    chaos_init_verdict_t verdict;
    long calls[8];
    long clocks[8];
    char hits[256];
    char path[64];
    FILE *file;

    (void)unlink("/tmp/.chaos-time.conf");
    chaos_init_time_start();
    g_chaos_time_check_interval_ns = 0U;
    g_now.tv_sec = 1000;
    g_now.tv_nsec = 500;

    /* A non-time system call is not time's: decide returns 0 so another library may own
     * it, and the verdict is left as it was. */
    memset(&other, 0, sizeof(other));
    memset(&verdict, 0, sizeof(verdict));
    other.tid = getpid();
    other.nr = __NR_getpid;
    verdict.action = CHAOS_INIT_FAIL;
    assert(chaos_init_time_decide(&other, &verdict) == 0);
    assert(verdict.action == CHAOS_INIT_FAIL);

    /* No rule file: every time call passes. */
    assert(decide(__NR_clock_gettime, CLOCK_REALTIME, P(&value)).action == CHAOS_INIT_PASS);
    assert(chaos_init_time_calls(calls, sizeof(calls) / sizeof(calls[0])) == 0U);
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 0U);

    /* LATENCY and ERRNO on a clock read and on a sleep, as in the library: a delay, a
     * failure, and both together as a delay that fails when it is due. */
    write_rules("clock_gettime:LATENCY:25\n");
    verdict = decide(__NR_clock_gettime, CLOCK_REALTIME, P(&value));
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.delay_ms == 25U);
    write_rules("clock_gettime:ERRNO:EINVAL\n");
    verdict = decide(__NR_clock_gettime, CLOCK_REALTIME, P(&value));
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EINVAL);
    write_rules("clock_gettime:LATENCY:5\nclock_gettime:ERRNO:EPERM\n");
    verdict = decide(__NR_clock_gettime, CLOCK_REALTIME, P(&value));
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.error == EPERM);
    write_rules("nanosleep:ERRNO:EINTR\n");
    assert(decide(__NR_nanosleep, 0, 0).action == CHAOS_INIT_FAIL);
    assert(decide(__NR_clock_nanosleep, 0, 0).action == CHAOS_INIT_FAIL);
    /* A sleep carries no value, so nothing is written for it and the call still runs. */
    write_rules("nanosleep:LATENCY:5\n");
    verdict = decide(__NR_nanosleep, 0, 0);
    assert(verdict.action == CHAOS_INIT_DELAY && verdict.writes_time == 0);

    /* OFFSET: the read does not run. The verdict returns 0 and the value is written at
     * commit, shifted by the rule, into the caller's own buffer. */
    write_rules("clock_gettime/realtime:OFFSET:1500\n");
    value.tv_sec = 0;
    value.tv_nsec = 0;
    verdict = serve(__NR_clock_gettime, CLOCK_REALTIME, P(&value));
    assert(verdict.action == CHAOS_INIT_RETURN && verdict.value == 0 && verdict.returns == 1);
    assert(verdict.writes_time == 1);
    assert(g_asked == CLOCK_REALTIME);
    assert(value.tv_sec == 1001 && value.tv_nsec == 500000500L);
    /* Another clock is not this rule's business. */
    value.tv_sec = 0;
    assert(serve(__NR_clock_gettime, CLOCK_MONOTONIC, P(&value)).action == CHAOS_INIT_PASS);
    assert(value.tv_sec == 0);

    /* A read that fails produces no value: the ERRNO rule is the whole answer, as in the
     * library, where the failing wrapper never calls the clock. */
    write_rules("clock_gettime:ERRNO:EPERM\nclock_gettime/realtime:OFFSET:1500\n");
    value.tv_sec = 42;
    verdict = serve(__NR_clock_gettime, CLOCK_REALTIME, P(&value));
    assert(verdict.action == CHAOS_INIT_FAIL && verdict.error == EPERM);
    assert(verdict.writes_time == 0 && value.tv_sec == 42);

    /* gettimeofday reads the wall clock and reports microseconds. */
    write_rules("clock_gettime:OFFSET:1000\n");
    day.tv_sec = 0;
    day.tv_usec = 0;
    assert(serve(__NR_gettimeofday, P(&day), 0).action == CHAOS_INIT_RETURN);
    assert(day.tv_sec == 1001 && day.tv_usec == 0);

    /* FREEZE holds the clock at the reading of the call that started it: the second read
     * gets the same value although the clock has moved on. */
    write_rules("clock_gettime/realtime:FREEZE:1.0\n");
    assert(serve(__NR_clock_gettime, CLOCK_REALTIME, P(&value)).action == CHAOS_INIT_RETURN);
    assert(value.tv_sec == 1000 && value.tv_nsec == 500);
    g_now.tv_sec = 2000;
    assert(serve(__NR_clock_gettime, CLOCK_REALTIME, P(&value)).action == CHAOS_INIT_RETURN);
    assert(value.tv_sec == 1000 && value.tv_nsec == 500);

    /* REGRESS steps the clock back once the rule is armed, so a later read is earlier
     * than the one before it. */
    write_rules("clock_gettime/monotonic:REGRESS:5000\n");
    assert(serve(__NR_clock_gettime, CLOCK_MONOTONIC, P(&value)).action == CHAOS_INIT_RETURN);
    assert(value.tv_sec == 2000);
    assert(serve(__NR_clock_gettime, CLOCK_MONOTONIC, P(&value)).action == CHAOS_INIT_RETURN);
    assert(value.tv_sec == 1995);

    /* What the supervisor cannot serve is left to the kernel: a read without a buffer,
     * and a clock it cannot read itself. */
    write_rules("clock_gettime:OFFSET:1000\n");
    assert(decide(__NR_clock_gettime, CLOCK_REALTIME, 0).action == CHAOS_INIT_PASS);
    g_clock_fails = 1;
    assert(decide(__NR_clock_gettime, CLOCK_REALTIME, P(&value)).action == CHAOS_INIT_PASS);
    g_clock_fails = 0;

    /* The commit does nothing for a verdict that did not ask for a value, and nothing
     * when the clock has become unreadable since the decision. */
    value.tv_sec = 7;
    memset(&other, 0, sizeof(other));
    other.tid = getpid();
    other.nr = __NR_clock_gettime;
    other.args[0] = CLOCK_REALTIME;
    other.args[1] = P(&value);
    memset(&verdict, 0, sizeof(verdict));
    chaos_init_time_commit(&other, &verdict);
    assert(value.tv_sec == 7);
    verdict.writes_time = 1;
    g_clock_fails = 1;
    chaos_init_time_commit(&other, &verdict);
    assert(value.tv_sec == 7);
    g_clock_fails = 0;
    /* A rule file that lost its value rule between decision and commit: the real reading
     * is what the caller gets, because that is what the call would have produced. */
    write_rules("nanosleep:LATENCY:5\n");
    chaos_init_time_commit(&other, &verdict);
    assert(value.tv_sec == 2000 && value.tv_nsec == 500);

    /* The filter is asked for what the rules need, and nothing else. */
    write_rules("nanosleep:LATENCY:5\n");
    assert(chaos_init_time_calls(calls, sizeof(calls) / sizeof(calls[0])) == 2U);
    assert(calls[0] == __NR_nanosleep && calls[1] == __NR_clock_nanosleep);
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 0U);
    /* A rule on another clock leaves gettimeofday and time alone: they read the wall
     * clock and nothing else. */
    write_rules("clock_gettime/monotonic:OFFSET:1000\n");
    assert(chaos_init_time_calls(calls, sizeof(calls) / sizeof(calls[0])) == 1U);
    assert(calls[0] == __NR_clock_gettime);
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 1U);
    assert(clocks[0] == CLOCK_MONOTONIC);
    /* Two rules on the same clock name it once; a rule that names no clock means every
     * clock, which is the empty list. */
    write_rules("clock_gettime/monotonic:OFFSET:1000\nclock_gettime/monotonic:FREEZE:0.5\n");
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 1U);
    write_rules("clock_gettime/realtime:OFFSET:1000\nclock_gettime:FREEZE:0.5\n");
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 0U);
    write_rules("*:LATENCY:5\n");
    assert(chaos_init_time_clocks(clocks, sizeof(clocks) / sizeof(clocks[0])) == 0U);
    {
        const size_t count = chaos_init_time_calls(calls, sizeof(calls) / sizeof(calls[0]));

        /* clock_gettime, gettimeofday, the two sleeps, and `time` where it exists. */
        assert(count >= 4U);
    }
    /* Neither list writes past its capacity, and neither needs a buffer at all. */
    write_rules("clock_gettime/realtime:OFFSET:1000\nclock_gettime/monotonic:FREEZE:0.5\n");
    assert(chaos_init_time_clocks(clocks, 1U) == 1U);
    assert(chaos_init_time_clocks(clocks, 0U) == 0U);
    assert(chaos_init_time_clocks(NULL, 4U) == 0U);
    assert(chaos_init_time_calls(calls, 1U) == 1U);
    assert(chaos_init_time_calls(calls, 0U) == 0U);
    assert(chaos_init_time_calls(NULL, 4U) == 0U);
    /* The sleeps are cut by the same bound: one read call and two sleeps, so a capacity
     * of one stops before the sleeps and two stops inside them. */
    write_rules("clock_gettime/monotonic:OFFSET:1000\nnanosleep:LATENCY:5\n");
    assert(chaos_init_time_calls(calls, 4U) == 3U);
    assert(chaos_init_time_calls(calls, 2U) == 2U);
    assert(chaos_init_time_calls(calls, 1U) == 1U);

    /* A usleep rule rejects the whole file: libc sleeps through nanosleep, so the
     * supervisor cannot tell which entry point the program used and the rule would load
     * and never fire. The valid LATENCY on the first line goes with it. */
    write_rules("nanosleep:LATENCY:5\nusleep:ERRNO:EINTR\n");
    assert(decide(__NR_nanosleep, 0, 0).action == CHAOS_INIT_PASS);
    file = fopen("/tmp/.chaos-time.status", "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(strstr(hits, "line=2\nreason=unsupported in seccomp mode\n") != NULL);

    /* A hit writes the caller's hits file, as under LD_PRELOAD. */
    write_rules("clock_gettime/realtime:OFFSET:1000\n");
    assert(serve(__NR_clock_gettime, CLOCK_REALTIME, P(&value)).action == CHAOS_INIT_RETURN);
    (void)snprintf(path, sizeof(path), "/tmp/.chaos-time.hits.%ld", (long)getpid());
    file = fopen(path, "r");
    assert(file != NULL);
    hits[fread(hits, 1U, sizeof(hits) - 1U, file)] = '\0';
    (void)fclose(file);
    assert(strstr(hits, "1\tclock_gettime/realtime:OFFSET:1000\n") != NULL);

    (void)unlink("/tmp/.chaos-time.conf");
    (void)unlink(path);
    /* A reload without a call: what the inotify watch of chaos_init.c asks for when a
     * rule file is put in place, so that the status file reports the rules before anything
     * has called into them. Two rules, because every file loaded above has one or none: a
     * status that said anything else would mean the reload did nothing. */
    write_rules("clock_gettime/realtime:OFFSET:1000\nclock_gettime/monotonic:LATENCY:5\n");
    chaos_init_time_reload();
    {
        FILE *reloaded = fopen("/tmp/.chaos-time.status", "r");
        char text[256] = {0};

        assert(reloaded != NULL);
        text[fread(text, 1U, sizeof(text) - 1U, reloaded)] = '\0';
        (void)fclose(reloaded);
        assert(strncmp(text, "state=ok\nrules=2\n", strlen("state=ok\nrules=2\n")) == 0);
    }

    return 0;
}
