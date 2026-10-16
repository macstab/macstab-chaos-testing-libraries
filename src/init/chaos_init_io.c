/**
 * @file chaos_init_io.c
 * @brief chaos-init: libchaos-io rules for system calls of supervised processes.
 *
 * @details The rule core of libchaos-io (parsing, reload, status file, matching,
 * qualifiers) is compiled in unchanged, as the unit tests do; this file only
 * turns a notified system call into what the wrappers pass to it. The mapping
 * follows the wrappers: the same operations, the same path strings (absolute, or
 * joined lexically to the working directory or the directory descriptor), fds 0-2
 * and /proc, /sys, /dev never faulted, sendfile and copy_file_range as writes to
 * their output, renames decided like renameat().
 *
 * SECCOMP mode applies ERRNO and LATENCY; TORN and CORRUPT change data the kernel
 * moves, and ERRNO on close would have to close and fail at once (the wrapper
 * closes, then reports the error): none of these is applied here.
 */

#include "chaos_init_io.h"

#include "../config/chaos_io_config.c"
#include "../effects/chaos_io_actions.c"
#include "chaos_init_proc.h"
#include "chaos_init_tracee.h"

#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/uio.h>

/* What the rule core expects the preload library to provide. The rule file is
 * read with the C library: the supervisor is not under any filter. */
chaos_io_open_fn g_chaos_io_real_open = open;
chaos_io_read_fn g_chaos_io_real_read = read;
chaos_io_close_fn g_chaos_io_real_close = close;
__thread int g_chaos_io_tls_guard = 0;
__thread uint64_t g_chaos_io_tls_prng_state = 0U;
uint64_t g_chaos_io_process_seed = UINT64_C(0x2545f4914f6cdd1d);

/** @brief How /proc links are read; unit tests replace it to make one unreadable. */
#ifndef CHAOS_INIT_IO_PROC_LINK
#define CHAOS_INIT_IO_PROC_LINK chaos_init_proc_link
#endif

/** @brief How a system call names what it acts on. */
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

typedef struct chaos_init_io_call
{
    long nr;
    chaos_io_operation_t operation;
    chaos_init_io_kind_t kind;
    int target; /**< Argument index of the descriptor or path. */
    int size;   /**< Argument index of the byte count; -1 none, -2 an iovec array. */
} chaos_init_io_call_t;

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

/** @brief The path open file @p fd of thread @p tid refers to; 0 for none (pipe, socket, 0-2). */
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
 * @brief The string the wrappers match for (dirfd, path) of thread @p tid:
 *        absolute, or joined to the working directory or the directory.
 */
static int chaos_init_io_at_path(
    pid_t tid, int has_dirfd, uint64_t dirfd, uint64_t address, char *out, size_t size
)
{
    char path[CHAOS_IO_MAX_PATH];
    char base[CHAOS_IO_MAX_PATH];

    if (chaos_init_read_string(tid, address, path, sizeof(path)) < 0)
    {
        return 0;
    }
    if (path[0] == '/')
    {
        return chaos_io_copy_path(out, size, path);
    }
    if (!has_dirfd || (int)(int32_t)dirfd == AT_FDCWD)
    {
        if (CHAOS_INIT_IO_PROC_LINK(tid, "cwd", base, sizeof(base)) <= 0)
        {
            return 0;
        }
    }
    else if (!chaos_init_io_fd_path(tid, dirfd, base, sizeof(base)))
    {
        return 0;
    }
    return chaos_io_join_paths(out, size, base, path);
}

/** @brief Bytes an iovec array of thread @p tid describes; CHAOS_POLICY_NO_SIZE if unknown. */
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

/** @brief Matches @p path for @p operation against the loaded rules (already prepared). */
static int
chaos_init_io_match(chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule)
{
    return !chaos_io_is_excluded_path(path) && chaos_io_config_match_loaded(operation, path, rule);
}

/**
 * @brief The rule a rename is decided by: like the wrapper, the destination's when
 *        both sides match with the destination's prefix at least as long.
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

int chaos_init_io_decide(const chaos_init_call_t *call, chaos_init_verdict_t *verdict)
{
    const chaos_init_io_call_t *entry = NULL;
    const chaos_io_config_state_t *state;
    char path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    size_t index;
    int matched = 0;
    int tracee;

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
    if (!matched ||
        (rule.effect != CHAOS_IO_EFFECT_ERRNO && rule.effect != CHAOS_IO_EFFECT_LATENCY) ||
        (entry->operation == CHAOS_IO_OP_CLOSE && rule.effect == CHAOS_IO_EFFECT_ERRNO))
    {
        return 1;
    }

    /* The rule's counters are the calling process's, not the snapshot's. */
    state = chaos_io_config_active_state();
    if (rule.hit < state->hits || rule.hit >= state->hits + state->rule_count ||
        (tracee = chaos_init_tracee_of(call->tid)) < 0)
    {
        return 1;
    }
    if (entry->size >= 0)
    {
        rule.call_size = call->args[entry->size];
    }
    else if (entry->size == -2)
    {
        rule.call_size = chaos_init_io_iov_size(call->tid, call->args[1], call->args[2]);
    }
    rule.hit =
        chaos_init_tracee_slot(&g_chaos_init_io_rules, tracee, (size_t)(rule.hit - state->hits));
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
