/**
 * @file chaos_init_io.c
 * @brief `chaos-init`: libchaos-io rules applied to tracee system calls.
 *
 * @details The libchaos-io rule core (parsing, reload, status file, matching,
 * qualifiers) is compiled in by `#include` of its .c files, unchanged, as the unit tests
 * do. This file only translates a notified system call into the (operation, path, size)
 * the wrappers would pass to that core, following the wrappers exactly:
 *
 * | System call | Operation | Target |
 * |---|---|---|
 * | open, creat, openat, openat2 | open | path (dirfd-relative for *at) |
 * | read, readv / write, writev | read / write | fd |
 * | pread64, preadv, preadv2 / pwrite64, pwritev, pwritev2 | pread / pwrite | fd |
 * | sendfile, copy_file_range | write | the output fd |
 * | close, fsync, fdatasync, ftruncate, fallocate | as named (truncate, allocate) | fd |
 * | truncate | truncate | path |
 * | unlink, unlinkat, rmdir | unlink | path |
 * | rename, renameat, renameat2 | rename_from / rename_to | both paths (see below) |
 *
 * Paths are the strings the wrappers match: absolute, or joined lexically to
 * `/proc/<tid>/cwd` or to the dirfd's `/proc/<tid>/fd/<n>` target, then normalised
 * (no symlink resolution). fds 0-2, non-file descriptors (pipes, sockets) and paths under
 * /proc, /sys and /dev are never faulted. read/write/close on sockets never reach this
 * file: the net decider claims them first.
 *
 * @par Supported effects
 * ERRNO (not on close) and LATENCY. TORN and CORRUPT change data the kernel moves, which a
 * seccomp reply cannot do; ERRNO on close would have to close and fail at once (the
 * wrapper closes, then reports the error), while a notified call either runs or fails. A
 * rule file containing any of them is rejected at parse time through the
 * CHAOS_IO_RULE_SUPPORTED hook, so its status file reports `unsupported in seccomp mode`
 * and none of its rules apply.
 *
 * @par Failure behaviour
 * Fail-open: any argument or /proc entry that cannot be read means no match, and the
 * call passes.
 *
 * Test seam: CHAOS_INIT_IO_PROC_LINK replaces the /proc link reader.
 */

#include "chaos_init_io.h"

/* Parser hook, defined before the core is included: rules this mode cannot apply reject
 * their file at load time. */
struct chaos_io_rule;
static int chaos_init_io_supported(const struct chaos_io_rule *rule);
#define CHAOS_IO_RULE_SUPPORTED(rule) chaos_init_io_supported(rule)

#include "../config/chaos_io_config.c"
#include "../effects/chaos_io_actions.c"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* Symbols the rule core expects from the preload library. The "real functions" are
 * plain libc here: the supervisor is under no filter and wraps nothing. The TLS guard
 * and PRNG state are thread-local by contract but the supervisor has one thread. The
 * seed constant is replaced from getrandom() in chaos_init_io_start(). */
chaos_io_open_fn g_chaos_io_real_open = open;
chaos_io_read_fn g_chaos_io_real_read = read;
chaos_io_close_fn g_chaos_io_real_close = close;
__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/* CHAOS_IO_RULE_SUPPORTED: ERRNO on anything but close, and LATENCY. */
static int chaos_init_io_supported(const struct chaos_io_rule *rule)
{
    return (rule->effect == CHAOS_IO_EFFECT_ERRNO && rule->operation != CHAOS_IO_OP_CLOSE) ||
           rule->effect == CHAOS_IO_EFFECT_LATENCY;
}

/** @brief Test seam: how /proc links are read; unit tests make one unreadable. */
#ifndef CHAOS_INIT_IO_PROC_LINK
#define CHAOS_INIT_IO_PROC_LINK chaos_init_proc_link
#endif

/** @brief How a system call names what it acts on, i.e. how its target path is derived. */
typedef enum chaos_init_io_kind
{
    CHAOS_INIT_IO_FD,      /**< args[target] is a descriptor. */
    CHAOS_INIT_IO_PATH,    /**< args[target] is a path, relative to the cwd. */
    CHAOS_INIT_IO_PATH_AT, /**< args[target - 1] a directory fd, args[target] a path. */
#ifdef __NR_rename
    CHAOS_INIT_IO_RENAME, /**< args[0] and args[1] are paths (x86_64 rename). */
#endif
    CHAOS_INIT_IO_RENAME_AT /**< dirfd, path, dirfd, path in args[0..3]. */
} chaos_init_io_kind_t;

/** @brief One row of the io decode table: system call number to wrapper semantics. */
typedef struct chaos_init_io_call
{
    long nr;
    chaos_io_operation_t operation;
    chaos_init_io_kind_t kind;
    int target; /**< Argument index of the descriptor or path. */
    int size;   /**< Argument index of the byte count; -1 none, -2 an iovec array. */
} chaos_init_io_call_t;

/* Must list exactly the numbers of g_chaos_init_io_calls in chaos_init_core.c. */
static const chaos_init_io_call_t g_chaos_init_io_calls[] = {
    {__NR_openat, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH_AT, 1, -1},
    {__NR_read, CHAOS_IO_OP_READ, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_readv, CHAOS_IO_OP_READ, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_write, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_writev, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pread64, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_preadv, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_preadv2, CHAOS_IO_OP_PREAD, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pwrite64, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, 2},
    {__NR_pwritev, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_pwritev2, CHAOS_IO_OP_PWRITE, CHAOS_INIT_IO_FD, 0, -2},
    {__NR_sendfile, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 0, 3},
    {__NR_copy_file_range, CHAOS_IO_OP_WRITE, CHAOS_INIT_IO_FD, 2, 4},
    {__NR_close, CHAOS_IO_OP_CLOSE, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_fsync, CHAOS_IO_OP_FSYNC, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_fdatasync, CHAOS_IO_OP_FDATASYNC, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_ftruncate, CHAOS_IO_OP_TRUNCATE, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_truncate, CHAOS_IO_OP_TRUNCATE, CHAOS_INIT_IO_PATH, 0, -1},
    {__NR_fallocate, CHAOS_IO_OP_ALLOCATE, CHAOS_INIT_IO_FD, 0, -1},
    {__NR_unlinkat, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH_AT, 1, -1},
    {__NR_renameat2, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME_AT, 0, -1},
#ifdef __NR_openat2
    {__NR_openat2, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH_AT, 1, -1},
#endif
#ifdef __NR_open
    {__NR_open, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_creat
    {__NR_creat, CHAOS_IO_OP_OPEN, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_unlink
    {__NR_unlink, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_rmdir
    {__NR_rmdir, CHAOS_IO_OP_UNLINK, CHAOS_INIT_IO_PATH, 0, -1},
#endif
#ifdef __NR_rename
    {__NR_rename, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME, 0, -1},
#endif
#ifdef __NR_renameat
    {__NR_renameat, CHAOS_IO_OP_RENAME_FROM, CHAOS_INIT_IO_RENAME_AT, 0, -1},
#endif
};

/* Per-process hit slots of the io rules. */
CHAOS_INIT_RULES_STORAGE(g_chaos_init_io, CHAOS_IO_MAX_RULES);

/** @brief Load counter of the active snapshot (see chaos_init_rules_t::snapshot). */
static uint64_t g_chaos_init_io_load = 0U;
static const chaos_io_config_state_t *g_chaos_init_io_seen_state = NULL;
static uint64_t g_chaos_init_io_seen_stamp = 0U;

/* chaos_init_rules_t::snapshot for io. A reload is detected by the active state pointer
 * (the core alternates two snapshots) or the cached rule file mtime changing; either bumps
 * the load counter, which makes every process re-sync its slots by rule text. */
static size_t chaos_init_io_snapshot(const chaos_init_text_t **texts, uint64_t *generation)
{
    const chaos_io_config_state_t *state = chaos_io_config_active_state();

    if (g_chaos_init_io_load == 0U || state != g_chaos_init_io_seen_state ||
        g_chaos_io_cached_mtime != g_chaos_init_io_seen_stamp)
    {
        g_chaos_init_io_seen_state = state;
        g_chaos_init_io_seen_stamp = g_chaos_io_cached_mtime;
        ++g_chaos_init_io_load;
    }
    *texts = (const chaos_init_text_t *)state->text;
    *generation = g_chaos_init_io_load;
    return state->rule_count;
}

static chaos_init_rules_t g_chaos_init_io_rules = {
    CHAOS_IO_HITS_PREFIX,
    CHAOS_IO_MAX_RULES,
    chaos_init_io_snapshot,
    g_chaos_init_io_slots,
    g_chaos_init_io_hashes,
    g_chaos_init_io_generation,
    g_chaos_init_io_count,
    g_chaos_init_io_total,
    g_chaos_init_io_pending,
    g_chaos_init_io_buffer,
    g_chaos_init_io_file,
};

void chaos_init_io_start(void)
{
    uint64_t seed;

    chaos_io_config_init();
    if (getrandom(&seed, sizeof(seed), 0) == (ssize_t)sizeof(seed))
    {
        g_chaos_io_process_seed = seed;
    }
    (void)chaos_init_tracee_register(&g_chaos_init_io_rules);
}

/**
 * @brief Resolves descriptor @p fd of thread @p tid to its file path via
 *        `/proc/<tid>/fd/<fd>`. @p fd is sign-extended from 32 bits, so negative values
 *        and fds 0-2 are rejected, as are non-path targets (`pipe:[..]`, `socket:[..]`).
 * @return 1 with an absolute path in @p out, else 0.
 */
static int chaos_init_io_fd_path(pid_t tid, uint64_t fd, char *out, size_t size)
{
    char name[32];

    if ((int64_t)(int32_t)fd <= 2)
    {
        return 0;
    }
    (void)snprintf(name, sizeof(name), "fd/%d", (int)fd);
    return CHAOS_INIT_IO_PROC_LINK(tid, name, out, size) > 0 && out[0] == '/';
}

/**
 * @brief Builds the path string the wrappers match for (dirfd, path) of thread @p tid.
 *
 * @details The path is read from tracee memory. An absolute path is used as is; a
 * relative one is joined to `/proc/<tid>/cwd` (no dirfd, or AT_FDCWD) or to the dirfd's
 * path. The result is normalised lexically (chaos_io_normalize_path()), as the wrappers
 * do; symlinks are not resolved.
 *
 * @param has_dirfd  Whether @p dirfd is meaningful (the *at variants).
 * @return 1 with the path in @p out; 0 when any part is unreadable or does not fit.
 */
static int chaos_init_io_at_path(
    pid_t tid, int has_dirfd, uint64_t dirfd, uint64_t address, char *out, size_t size
)
{
    char path[CHAOS_IO_MAX_PATH];
    char base[CHAOS_IO_MAX_PATH];
    int at_cwd;

    if (chaos_init_read_string(tid, address, path, sizeof(path)) < 0)
    {
        return 0;
    }
    at_cwd = !has_dirfd || (int)(int32_t)dirfd == AT_FDCWD;
    if (path[0] == '/' ? !chaos_io_copy_path(out, size, path)
                       : (at_cwd ? CHAOS_INIT_IO_PROC_LINK(tid, "cwd", base, sizeof(base)) <= 0
                                 : !chaos_init_io_fd_path(tid, dirfd, base, sizeof(base))) ||
                             !chaos_io_join_paths(out, size, base, path))
    {
        return 0;
    }
    chaos_io_normalize_path(out);
    return 1;
}

/**
 * @brief Total bytes of an iovec array of thread @p tid, for `@size`. Read in batches of
 *        64 entries; more than 1024 entries (the kernel's UIO_MAXIOV, which fails such a
 *        call with EINVAL anyway) or an unreadable array yields CHAOS_POLICY_NO_SIZE.
 */
static uint64_t chaos_init_io_iov_size(pid_t tid, uint64_t address, uint64_t count)
{
    struct iovec vector[64];
    uint64_t total = 0U;
    uint64_t done = 0U;

    if (count > 1024U)
    {
        return CHAOS_POLICY_NO_SIZE;
    }
    while (done < count)
    {
        const uint64_t chunk = count - done < 64U ? count - done : 64U;
        uint64_t index;

        if (chaos_init_read_memory(
                tid, address + done * sizeof(struct iovec), vector, chunk * sizeof(struct iovec)
            ) != 0)
        {
            return CHAOS_POLICY_NO_SIZE;
        }
        for (index = 0U; index < chunk; ++index)
        {
            total += (uint64_t)vector[index].iov_len;
        }
        done += chunk;
    }
    return total;
}

/**
 * @brief Matches @p path for @p operation against the loaded rules, excluding /proc, /sys
 *        and /dev. Precondition: chaos_io_config_prepare() succeeded.
 */
static int
chaos_init_io_match(chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule)
{
    return !chaos_io_is_excluded_path(path) && chaos_io_config_match_loaded(operation, path, rule);
}

/**
 * @brief Selects the rule a rename is decided by, as the wrapper does: rename_to on the
 *        destination wins when it matches and its path prefix is at least as long as a
 *        rename_from match on the source; otherwise the source's rule.
 *
 * @param at  1 for renameat/renameat2 (dirfd, path, dirfd, path), 0 for rename (path, path).
 * @return 1 with the rule in @p rule, 0 when neither side matches or both are unreadable.
 */
static int chaos_init_io_rename(const chaos_init_call_t *call, int at, chaos_io_rule_t *rule)
{
    char from[CHAOS_IO_MAX_PATH];
    char to[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t from_rule;
    chaos_io_rule_t to_rule;
    const int from_ok = chaos_init_io_at_path(
        call->tid, at, call->args[0], call->args[at ? 1 : 0], from, sizeof(from)
    );
    const int to_ok =
        chaos_init_io_at_path(call->tid, at, call->args[2], call->args[at ? 3 : 1], to, sizeof(to));
    int have_from;
    int have_to;

    if ((!from_ok && !to_ok) || !chaos_io_config_prepare())
    {
        return 0;
    }
    have_from = from_ok && chaos_init_io_match(CHAOS_IO_OP_RENAME_FROM, from, &from_rule);
    have_to = to_ok && chaos_init_io_match(CHAOS_IO_OP_RENAME_TO, to, &to_rule);
    if (have_to && (!have_from || to_rule.path_len >= from_rule.path_len))
    {
        *rule = to_rule;
        return 1;
    }
    if (have_from)
    {
        *rule = from_rule;
        return 1;
    }
    return 0;
}

/* Decode by table, build the path, match, then let the core's trigger decide (probability,
 * qualifiers, hit counting) on the per-process slot. */
int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_init_io_call_t *entry = NULL;
    const chaos_io_config_state_t *state;
    char path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    size_t index;
    int matched = 0;

    for (index = 0U; index < sizeof(g_chaos_init_io_calls) / sizeof(g_chaos_init_io_calls[0]);
         ++index)
    {
        if (g_chaos_init_io_calls[index].nr == call->nr)
        {
            entry = &g_chaos_init_io_calls[index];
            break;
        }
    }
    if (entry == NULL)
    {
        return 0;
    }
    verdict->action = CHAOS_INIT_PASS;

    switch (entry->kind)
    {
    case CHAOS_INIT_IO_FD:
        matched = chaos_init_io_fd_path(call->tid, call->args[entry->target], path, sizeof(path)) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
    case CHAOS_INIT_IO_PATH:
        matched = chaos_init_io_at_path(
                      call->tid, 0, 0U, call->args[entry->target], path, sizeof(path)
                  ) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
    case CHAOS_INIT_IO_PATH_AT:
        matched = chaos_init_io_at_path(
                      call->tid,
                      1,
                      call->args[entry->target - 1],
                      call->args[entry->target],
                      path,
                      sizeof(path)
                  ) &&
                  chaos_io_config_match_path(entry->operation, path, &rule);
        break;
#ifdef __NR_rename
    case CHAOS_INIT_IO_RENAME:
        matched = chaos_init_io_rename(call, 0, &rule);
        break;
#endif
    case CHAOS_INIT_IO_RENAME_AT:
        matched = chaos_init_io_rename(call, 1, &rule);
        break;
    }
    /* A loaded rule is ERRNO or LATENCY only (chaos_init_io_supported() rejected the
     * rest at parse time). */
    if (!matched)
    {
        return 1;
    }

    /* `@size` input, measured only after a match: the iovec case costs tracee reads. */
    if (entry->size >= 0)
    {
        rule.call_size = call->args[entry->size];
    }
    else if (entry->size == -2)
    {
        rule.call_size = chaos_init_io_iov_size(call->tid, call->args[1], call->args[2]);
    }
    /* Swap the snapshot's shared slot for the calling process's, so probability,
     * `@first` and windows count per process as under LD_PRELOAD. No slot (the process
     * ended): do not fire. */
    state = chaos_io_config_active_state();
    rule.hit = chaos_init_tracee_hit(
        &g_chaos_init_io_rules, call->tid, state->hits, state->rule_count, rule.hit
    );
    rule.hit_generation = rule.hit != NULL ? rule.hit->generation : 0U;
    if (rule.hit == NULL || !chaos_io_rule_should_trigger(&rule))
    {
        return 1;
    }
    if (rule.effect == CHAOS_IO_EFFECT_ERRNO)
    {
        verdict->action = CHAOS_INIT_FAIL;
        verdict->error = rule.errnum;
    }
    else
    {
        verdict->action = CHAOS_INIT_DELAY;
        verdict->delay_ms = rule.latency_ms;
    }
    return 1;
}
