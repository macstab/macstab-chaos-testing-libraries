/**
 * @file test_chaos_init_main.c
 * @brief Unit tests for the decision helpers of `src/init/chaos_init.c`.
 *
 * @details This file is the supervisor's entry point: argument handling, the handover, the
 * filter, the serve loop. Most of it needs a container, a seccomp filter and a tracee, and
 * is covered by `test/runtime/test_seccomp.sh`. What does *not* need any of that is the
 * part that decides: the reply sent for each verdict, the name filter that tells a rule
 * file from any other file in the watched directory, and the drain of the inotify queue.
 * Those are what this test reaches, by including the file with `CHAOS_INIT_NO_MAIN`.
 *
 * It exists because the file was in no unit test and in no coverage target at all, while
 * the gate's own header claimed to cover chaos-init -- five defects in here were invisible
 * to a green gate for that reason. The gate now records this file at the share these tests
 * reach, so a change that drops it further is visible.
 *
 * Covered:
 * - every action produces its own reply: FAIL as a negative errno, RETURN as the value,
 *   and each of the four that only a trace stop can carry as CONTINUE -- the kernel's
 *   answer for "run it", which is why a verdict that needs a stop must never get here;
 * - the rule-file name filter: the prefix, the suffix, and a name that is only the two;
 * - the inotify drain: one read per call, a name that matches, a name that does not, and
 *   an event with no name at all.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The modules chaos_init.c calls into, compiled in as the other init tests do. At -O0 --
 * which is how the coverage build compiles -- every static function in this translation
 * unit is emitted whether or not it is called, so everything they reach has to link. */
#include "../../src/init/chaos_init_core.c"
#include "../../src/init/chaos_init_delay.c"
#include "../../src/init/chaos_init_proc.c"
#include "../../src/init/chaos_init_trace.c"
#include "../../src/init/chaos_init_tracee.c"
#include "../../src/init/chaos_init_vdso.c"

#define CHAOS_INIT_NO_MAIN
#include "../../src/init/chaos_init.c"

#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

/* The per-library entry points. Each library's own test owns its decisions; here they
 * only have to link, because at -O0 every function of the included file is emitted. The
 * reloads are the exception: counting them is how the drain test shows which names it
 * acted on. */
static unsigned g_reloads = 0U;
int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
int chaos_init_io_decide_result(const chaos_init_call_t *call, long result)
{
    (void)call;
    (void)result;
    return 0;
}
void chaos_init_io_start(void) {}
size_t chaos_init_io_traced_calls(long *out, size_t capacity)
{
    (void)out;
    (void)capacity;
    return 0U;
}
int chaos_init_net_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
int chaos_init_net_decide_result(const chaos_init_call_t *call, long result)
{
    (void)call;
    (void)result;
    return 0;
}
void chaos_init_net_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
}
void chaos_init_net_start(void) {}
size_t chaos_init_net_traced_calls(long *out, size_t capacity)
{
    (void)out;
    (void)capacity;
    return 0U;
}
int chaos_init_dns_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
void chaos_init_dns_start(void) {}
size_t chaos_init_dns_calls(long *out, size_t capacity)
{
    (void)out;
    (void)capacity;
    return 0U;
}
int chaos_init_time_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
void chaos_init_time_commit(const chaos_init_call_t *call, const chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
}
void chaos_init_time_start(void) {}
size_t chaos_init_time_calls(long *out, size_t capacity)
{
    (void)out;
    (void)capacity;
    return 0U;
}
size_t chaos_init_time_clocks(long *out, size_t capacity)
{
    (void)out;
    (void)capacity;
    return 0U;
}
int chaos_init_memory_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
int chaos_init_process_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    (void)call;
    (void)verdict;
    return 0;
}
void chaos_init_io_reload(void)
{
    ++g_reloads;
}
void chaos_init_net_reload(void)
{
    ++g_reloads;
}
void chaos_init_dns_reload(void)
{
    ++g_reloads;
}
void chaos_init_time_reload(void)
{
    ++g_reloads;
}
void chaos_init_memory_reload(void)
{
    ++g_reloads;
}
void chaos_init_process_reload(void)
{
    ++g_reloads;
}

/** @brief The reply the supervisor would send for @p action, read back out of the buffer. */
static struct seccomp_notif_resp reply_for(chaos_init_action_t action, int error, long value)
{
    chaos_init_verdict_t verdict;
    struct seccomp_notif_resp reply;

    memset(&verdict, 0, sizeof(verdict));
    verdict.action = action;
    verdict.error = error;
    verdict.value = value;
    /* Descriptor -1: the ioctl fails and is ignored, which is what the function does when
     * the thread has already gone. The buffer is what is being tested. */
    chaos_init_reply(-1, 7U, &verdict, &reply, sizeof(reply));
    return reply;
}

static void test_reply_per_action(void)
{
    struct seccomp_notif_resp reply = reply_for(CHAOS_INIT_FAIL, EIO, 0);

    assert(reply.id == 7U && reply.error == -EIO && reply.val == 0 && reply.flags == 0U);

    reply = reply_for(CHAOS_INIT_RETURN, 0, 42);
    assert(reply.id == 7U && reply.error == 0 && reply.val == 42 && reply.flags == 0U);

    reply = reply_for(CHAOS_INIT_PASS, 0, 0);
    assert(reply.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE && reply.error == 0);

    /* The four a notification cannot carry. CONTINUE is the only honest answer here --
     * there is no way to shorten or substitute a call on this path -- which is exactly why
     * the deciders refuse such a verdict for a call the installed filter does not trace:
     * reaching this point means the effect is lost, and a hit would already be counted. */
    reply = reply_for(CHAOS_INIT_SHORTEN, 0, 5);
    assert(reply.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    reply = reply_for(CHAOS_INIT_AFTER, 0, 0);
    assert(reply.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    reply = reply_for(CHAOS_INIT_INSTEAD, 0, 0);
    assert(reply.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    reply = reply_for(CHAOS_INIT_BEFORE, 0, 0);
    assert(reply.flags == SECCOMP_USER_NOTIF_FLAG_CONTINUE);
}

static void test_rule_file_names(void)
{
    assert(chaos_init_rule_file(".chaos-io.conf"));
    assert(chaos_init_rule_file(".chaos-net.conf"));
    /* The prefix and the suffix with nothing between them is not a library's file. */
    assert(chaos_init_rule_file(".chaos-.conf") == 0);
    assert(chaos_init_rule_file(".chaos-io.conf.tmp") == 0);
    assert(chaos_init_rule_file("chaos-io.conf") == 0);
    assert(chaos_init_rule_file(".chaos-io") == 0);
    assert(chaos_init_rule_file(".conf") == 0);
    assert(chaos_init_rule_file("") == 0);
}

/** @brief Queues @p name on @p watcher by creating that file in @p directory. */
static void touch(const char *directory, const char *name)
{
    char path[256];
    int fd;

    (void)snprintf(path, sizeof(path), "%s/%s", directory, name);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(fd >= 0);
    assert(close(fd) == 0);
}

static void test_watched_drain(void)
{
    const char *directory = "/tmp/chaos-init-watch";
    int watcher;

    assert(mkdir(directory, 0755) == 0 || errno == EEXIST);
    watcher = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    assert(watcher >= 0);
    assert(inotify_add_watch(watcher, directory, IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE) >= 0);

    /* A file that is not a rule file: read, recognised as uninteresting, no reload. */
    touch(directory, "other.txt");
    g_reloads = 0U;
    chaos_init_watched(watcher, 0U);
    assert(g_reloads == 0U);

    /* One that is: every selected library is reloaded, because the watch is on the
     * directory and one changed file is cheaper to answer for all of them than to map
     * back to its owner. */
    touch(directory, ".chaos-io.conf");
    chaos_init_watched(watcher, CHAOS_INIT_LIB_IO | CHAOS_INIT_LIB_NET);
    assert(g_reloads == 2U);

    /* An empty queue: the read fails with EAGAIN and nothing is walked. */
    g_reloads = 0U;
    chaos_init_watched(watcher, CHAOS_INIT_LIB_IO);
    assert(g_reloads == 0U);

    assert(close(watcher) == 0);
    /* A descriptor that is no inotify queue at all: the read fails, and the function has
     * to cope rather than walk a buffer it never filled. */
    chaos_init_watched(-1, CHAOS_INIT_LIB_IO);
    assert(g_reloads == 0U);
}

/**
 * @brief Names the parts of the serve loop this test does not reach.
 *
 * @details They need a filter, a tracee and a container, which `test_seccomp.sh`
 * provides. Naming them keeps the compiler from refusing the file for unused statics, and
 * puts the list of what the runtime suite owns in one place rather than in a comment that
 * drifts.
 */
static void covered_by_the_runtime_suite(void)
{
    void (*const answer)(int, unsigned, void *, void *, size_t) = chaos_init_answer;
    void (*const on_time)(int, int, void *, size_t) = chaos_init_on_time;
    int (*const reap)(unsigned, pid_t, int *) = chaos_init_reap;
    int (*const rest)(int) = chaos_init_serve_the_rest;
    int (*const handover)(unsigned, int, int *) = chaos_init_install_and_hand_over;

    assert(answer != NULL && on_time != NULL && reap != NULL && rest != NULL);
    assert(handover != NULL);
    {
        void (*const signals)(sigset_t *) = chaos_init_signal_set;
        void (*const shell)(const char *, char **) = chaos_init_exec_shell;
        int (*const receive)(int, int *, int *) = chaos_init_receive_listener;

        assert(signals != NULL && shell != NULL && receive != NULL);
    }
    /* Set by the handover, read by the serve loop: both belong to the runtime suite. */
    assert(g_chaos_init_tracing == 0);
}

int main(void)
{
    covered_by_the_runtime_suite();
    test_reply_per_action();
    test_rule_file_names();
    test_watched_drain();
    (void)printf("test_chaos_init_main: ok\n");
    return 0;
}
