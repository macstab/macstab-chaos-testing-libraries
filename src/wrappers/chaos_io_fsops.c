/**
 * @file chaos_io_fsops.c
 * @brief File-system operation wrappers: ftruncate, truncate, fallocate, posix_fallocate,
 *        unlinkat, unlink, rmdir, remove, renameat, renameat2, rename (and glibc `64`
 *        aliases).
 *
 * @details
 * | Wrapper | Operation | Matched by |
 * |---------|-----------|------------|
 * | ftruncate | `truncate` | descriptor |
 * | truncate | `truncate` | path |
 * | fallocate, posix_fallocate | `allocate` | descriptor (`@size` = length) |
 * | unlinkat, unlink, rmdir, remove | `unlink` | path |
 * | renameat, renameat2, rename | `rename_from` (source), `rename_to` (target) | paths |
 *
 * All apply only ERRNO and LATENCY (the parser rejects TORN and CORRUPT here). The path
 * forms exist because libc implements unlink, rmdir, rename and truncate with its own
 * system calls, not through the *at functions or ftruncate.
 *
 * @par fd-cache reset after unlink and rename
 * A successful unlink or rename, with or without a matching rule, resets the whole fd
 * cache. Both change the kernel's name of descriptors already open on the file
 * (`<path> (deleted)` after unlink, the new name after rename, the replaced target's
 * descriptors too), and the cache keeps no reverse index from path to descriptor, so a
 * selective invalidation is impossible. An injected failure changes nothing on disk and
 * keeps the cache.
 *
 * @par Rename rule selection
 * A rename has two paths: the source is matched against `rename_from` rules, the target
 * against `rename_to` rules, and the longer written prefix wins; on a tie the
 * `rename_to` rule wins. The usual commit pattern (write a temp file, rename it over the
 * final name) makes the target the name operators care about.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"
#include "chaos_io_wrappers.h"

#include <errno.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* --- Real-call trampolines ------------------------------------------------------- */

/*
 * Each trampoline calls the real function inside a library section and issues the system
 * call itself while its `g_chaos_io_real_*` pointer is still NULL (a call during symbol
 * resolution).
 */

/** @brief Real ftruncate() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_ftruncate(int fd, off_t length)
{
    int previous;
    int result;

    if (g_chaos_io_real_ftruncate == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_ftruncate, fd, length);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_ftruncate(fd, length);
    chaos_io_leave_internal(previous);
    return result;
}

#ifdef __linux__
/** @brief Real fallocate() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_fallocate(int fd, int mode, off_t offset, off_t length)
{
    int previous;
    int result;

    if (g_chaos_io_real_fallocate == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_fallocate, fd, mode, offset, length);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_fallocate(fd, mode, offset, length);
    chaos_io_leave_internal(previous);
    return result;
}
#endif

/** @brief Real truncate() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_truncate(const char *path, off_t length)
{
    int previous;
    int result;

    if (g_chaos_io_real_truncate == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_truncate, path, length);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_truncate(path, length);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Real posix_fallocate() inside a library section; before resolution the fallocate
 *        system call with mode 0 (no write-zeros fallback).
 */
static int chaos_io_call_real_posix_fallocate(int fd, off_t offset, off_t length)
{
    int previous;
    int result;

    if (g_chaos_io_real_posix_fallocate == NULL)
    {
        /* posix_fallocate returns the error number and leaves errno alone. */
        const int saved_errno = errno;

        result = CHAOS_IO_SYSCALL(SYS_fallocate, fd, 0, offset, length) == 0 ? 0 : errno;
        errno = saved_errno;
        return result;
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_posix_fallocate(fd, offset, length);
    chaos_io_leave_internal(previous);
    return result;
}

/**
 * @brief Real renameat2() inside a library section; the renameat2 system call where libc
 *        lacks the function (musl, glibc before 2.28) or before resolution.
 *
 * @details libchaos-io exports renameat2 everywhere, so a program that looks it up at run
 * time (dlsym, a weak symbol) gets a working function rather than one that always fails.
 * ENOSYS only where the headers lack the system call number.
 */
static int chaos_io_call_real_renameat2(
    int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags
)
{
    int previous;
    int result;

    if (g_chaos_io_real_renameat2 == NULL)
    {
#ifdef SYS_renameat2
        return (int)syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real unlinkat() inside a library section; raw system call before resolution. */
static int chaos_io_call_real_unlinkat(int dirfd, const char *path, int flags)
{
    int previous;
    int result;

    if (g_chaos_io_real_unlinkat == NULL)
    {
        return (int)CHAOS_IO_SYSCALL(SYS_unlinkat, dirfd, path, flags);
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_unlinkat(dirfd, path, flags);
    chaos_io_leave_internal(previous);
    return result;
}

/** @brief Real renameat() inside a library section; raw system call before resolution. */
static int
chaos_io_call_real_renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    int previous;
    int result;

    if (g_chaos_io_real_renameat == NULL)
    {
#ifdef SYS_renameat
        return (int)CHAOS_IO_SYSCALL(SYS_renameat, olddirfd, oldpath, newdirfd, newpath);
#else
        /* aarch64 has only renameat2; with flags 0 it is renameat. */
        return (int)CHAOS_IO_SYSCALL(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, 0U);
#endif
    }
    previous = chaos_io_enter_internal();
    result = g_chaos_io_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    chaos_io_leave_internal(previous);
    return result;
}

/* --- Path-based rule matching helpers ------------------------------------------- */

/**
 * @brief Exclusion check plus chaos_io_config_match_loaded(), without a reload; the caller
 *        has called chaos_io_config_prepare() (once for both paths of a rename).
 *
 * @param[in]  operation  Operation to match.
 * @param[in]  path       Normalised absolute path; NULL returns 0.
 * @param[out] rule       Receives the rule; NULL returns 0.
 * @return Non-zero when a rule matched.
 */
static int chaos_io_match_loaded_path_rule(
    chaos_io_operation_t operation, const char *path, chaos_io_rule_t *rule
)
{
    if (path == NULL || rule == NULL || chaos_io_is_excluded_path(path))
    {
        return 0;
    }
    return chaos_io_config_match_loaded(operation, path, rule);
}

/**
 * @brief Selects the one rule a rename applies: the best `rename_from` rule for the source
 *        or the best `rename_to` rule for the target, whichever has the longer written
 *        prefix; `rename_to` on a tie.
 *
 * @details Each side is resolved with chaos_io_resolve_at_path(); a side that cannot be
 * resolved, or is excluded, simply has no rule. The rule file is checked once for both.
 * The tie goes to the target because the usual commit pattern (temp file renamed over the
 * final name) makes the target the significant name; the longer prefix still wins first,
 * so a more specific rule beats a broader one on either side.
 *
 * @param[in]  olddirfd  Directory descriptor or AT_FDCWD for @p oldpath.
 * @param[in]  oldpath   Source path; NULL means no source rule.
 * @param[in]  newdirfd  Directory descriptor or AT_FDCWD for @p newpath.
 * @param[in]  newpath   Target path; NULL means no target rule.
 * @param[out] rule      Receives the winning rule; NULL returns 0.
 * @return Non-zero when a rule was selected; 0 to pass the call through.
 */
static int chaos_io_match_rename_rule(
    int olddirfd, const char *oldpath, int newdirfd, const char *newpath, chaos_io_rule_t *rule
)
{
    char old_resolved[CHAOS_IO_MAX_PATH];
    char new_resolved[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t from_rule;
    chaos_io_rule_t to_rule;
    int old_ok;
    int new_ok;
    int have_from = 0;
    int have_to = 0;

    if (rule == NULL)
    {
        return 0;
    }

    old_ok = chaos_io_resolve_at_path(olddirfd, oldpath, old_resolved, sizeof(old_resolved));
    new_ok = chaos_io_resolve_at_path(newdirfd, newpath, new_resolved, sizeof(new_resolved));
    if (!old_ok && !new_ok)
    {
        return 0;
    }
    if (!chaos_io_config_prepare())
    {
        return 0;
    }

    if (old_ok)
    {
        have_from =
            chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_FROM, old_resolved, &from_rule);
    }
    if (new_ok)
    {
        have_to = chaos_io_match_loaded_path_rule(CHAOS_IO_OP_RENAME_TO, new_resolved, &to_rule);
    }

    if (!have_from && !have_to)
    {
        return 0;
    }
    /* Target wins on equal path_len: the final name of a temp-then-rename commit. */
    if (have_to && (!have_from || to_rule.path_len >= from_rule.path_len))
    {
        *rule = to_rule;
        return 1;
    }

    *rule = from_rule;
    return 1;
}

/* --- Exported interposed symbols ------------------------------------------------- */

/**
 * @brief Interposed ftruncate(2): `truncate` rules on the descriptor; ERRNO fails without
 *        truncating, LATENCY delays.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int ftruncate(int fd, off_t length)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() || !chaos_io_match_fd_rule(fd, CHAOS_IO_OP_TRUNCATE, &rule))
    {
        return chaos_io_call_real_ftruncate(fd, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_ftruncate(fd, length);
}

#ifdef __linux__
/**
 * @brief Interposed fallocate(2): `allocate` rules on the descriptor, `@size` = @p length;
 *        ERRNO (ENOSPC, EDQUOT, ...) fails without allocating, LATENCY delays.
 *
 * @details @p mode (punch hole, collapse range, ...) does not take part in matching: an
 * `allocate` rule faults every fallocate on the file.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int fallocate(int fd, int mode, off_t offset, off_t length)
{
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_ALLOCATE, (uint64_t)length, &rule))
    {
        return chaos_io_call_real_fallocate(fd, mode, offset, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }

    return chaos_io_call_real_fallocate(fd, mode, offset, length);
}
#endif

/**
 * @brief Interposed unlinkat(2): `unlink` rules on the path; ERRNO fails without removing,
 *        LATENCY delays.
 *
 * @details Files and directories (AT_REMOVEDIR) alike. When the path cannot be resolved,
 * is excluded, or matches no rule, the real call runs unchanged. Every successful real
 * unlink, also inside a library section, resets the whole fd cache (file header); an
 * injected failure removes nothing and keeps it.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int unlinkat(int dirfd, const char *path, int flags)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(dirfd, path, resolved_path, sizeof(resolved_path)) ||
        chaos_io_is_excluded_path(resolved_path) || !chaos_io_config_prepare() ||
        !chaos_io_match_loaded_path_rule(CHAOS_IO_OP_UNLINK, resolved_path, &rule))
    {
        rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
        if (rc == 0)
        {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        /* Injected failure: nothing was removed, so the cache stays valid. */
        return -1;
    }

    rc = chaos_io_call_real_unlinkat(dirfd, path, flags);
    if (rc == 0)
    {
        chaos_io_fdcache_reset();
    }
    return rc;
}

/**
 * @brief Interposed renameat(2): one `rename_from`/`rename_to` rule
 *        (chaos_io_match_rename_rule()); ERRNO fails without renaming, LATENCY delays.
 *
 * @details Every successful real rename, also inside a library section, resets the whole
 * fd cache: descriptors open on the source now resolve to the new name, and those open on
 * a replaced target to `<target> (deleted)`. An injected failure renames nothing and
 * keeps the cache.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_rename_rule(olddirfd, oldpath, newdirfd, newpath, &rule))
    {
        rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
        if (rc == 0)
        {
            chaos_io_fdcache_reset();
        }
        return rc;
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        /* Injected failure: nothing was renamed, so the cache stays valid. */
        return -1;
    }

    rc = chaos_io_call_real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (rc == 0)
    {
        chaos_io_fdcache_reset();
    }
    return rc;
}

/* ---------------------------------------------------------------------------
 * Path forms of the same operations
 *
 * glibc and musl implement unlink(), rmdir(), rename() and truncate() with their own
 * system calls, not through unlinkat(), renameat() or ftruncate(), so rules would
 * otherwise never see them, and they are the forms most programs use: the JDK's
 * File.delete() and Files.delete() call unlink(), Files.move() calls rename(). The kernel
 * defines unlink(p) as unlinkat(AT_FDCWD, p, 0), rmdir(p) as
 * unlinkat(AT_FDCWD, p, AT_REMOVEDIR) and rename(a, b) as
 * renameat(AT_FDCWD, a, AT_FDCWD, b), so these forward to the *at wrappers with identical
 * semantics. truncate() matches `truncate` rules by path.
 * ------------------------------------------------------------------------- */

/** @brief Interposed unlink(2): unlinkat(AT_FDCWD, @p path, 0). */
CHAOS_IO_EXPORT int unlink(const char *path)
{
    return unlinkat(AT_FDCWD, path, 0);
}

/** @brief Interposed rmdir(2): unlinkat(AT_FDCWD, @p path, AT_REMOVEDIR); `unlink` rules. */
CHAOS_IO_EXPORT int rmdir(const char *path)
{
    return unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
}

/**
 * @brief Interposed remove(3): `unlink` rules.
 *
 * @details Same algorithm as glibc and musl: unlink, and rmdir only when that fails with
 * EISDIR. Both steps go through unlinkat(), so an injected failure of the first step
 * ends the call (unless the rule's errno is EISDIR, which is not in the ERRNO list).
 */
CHAOS_IO_EXPORT int remove(const char *path)
{
    int rc = unlinkat(AT_FDCWD, path, 0);

    if (rc != 0 && errno == EISDIR)
    {
        rc = unlinkat(AT_FDCWD, path, AT_REMOVEDIR);
    }
    return rc;
}

/** @brief Interposed rename(2): renameat(AT_FDCWD, @p oldpath, AT_FDCWD, @p newpath). */
CHAOS_IO_EXPORT int rename(const char *oldpath, const char *newpath)
{
    return renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

int renameat2(
    int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags
);

/**
 * @brief Interposed renameat2(2): renameat() with flags (RENAME_NOREPLACE,
 *        RENAME_EXCHANGE, RENAME_WHITEOUT), used by `mv` and systemd.
 *
 * @details glibc's renameat() does not call it, so it needs its own wrapper. Rule
 * selection and fd-cache reset are those of renameat(); @p flags do not take part in
 * matching (for RENAME_EXCHANGE the "target" is the second path).
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int
renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
    chaos_io_rule_t rule;
    int rc;

    chaos_io_ensure_symbols();
    if (!chaos_io_in_internal() &&
        chaos_io_match_rename_rule(olddirfd, oldpath, newdirfd, newpath, &rule))
    {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
        {
            chaos_io_rule_apply_latency(&rule);
        }
        else if (chaos_io_rule_apply_errno(&rule))
        {
            return -1;
        }
    }

    rc = chaos_io_call_real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    if (rc == 0)
    {
        chaos_io_fdcache_reset();
    }
    return rc;
}

/**
 * @brief Interposed posix_fallocate(3): `allocate` rules, `@size` = @p length.
 *
 * @details libc implements it with the fallocate system call (glibc falls back to
 * writing zeros), never through fallocate(). Unlike fallocate() it reports failure as the
 * returned error number and leaves errno alone, injected failures included.
 *
 * @return 0 on success; an error number on a real or injected failure.
 */
CHAOS_IO_EXPORT int posix_fallocate(int fd, off_t offset, off_t length)
{
    chaos_io_rule_t rule;
    int saved_errno;
    int injected;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_match_fd_rule_sized(fd, CHAOS_IO_OP_ALLOCATE, (uint64_t)length, &rule))
    {
        return chaos_io_call_real_posix_fallocate(fd, offset, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else
    {
        saved_errno = errno;
        if (chaos_io_rule_apply_errno(&rule))
        {
            injected = errno;
            errno = saved_errno;
            return injected;
        }
    }
    return chaos_io_call_real_posix_fallocate(fd, offset, length);
}

/**
 * @brief Interposed truncate(2): `truncate` rules matched by path; ERRNO fails without
 *        truncating, LATENCY delays.
 *
 * @return 0 on success; -1 with errno on a real or injected failure.
 */
CHAOS_IO_EXPORT int truncate(const char *path, off_t length)
{
    char resolved_path[CHAOS_IO_MAX_PATH];
    chaos_io_rule_t rule;

    chaos_io_ensure_symbols();
    if (chaos_io_in_internal() ||
        !chaos_io_resolve_at_path(AT_FDCWD, path, resolved_path, sizeof(resolved_path)) ||
        chaos_io_is_excluded_path(resolved_path) ||
        !chaos_io_config_match_path(CHAOS_IO_OP_TRUNCATE, resolved_path, &rule))
    {
        return chaos_io_call_real_truncate(path, length);
    }

    if (rule.effect == CHAOS_IO_EFFECT_LATENCY)
    {
        chaos_io_rule_apply_latency(&rule);
    }
    else if (chaos_io_rule_apply_errno(&rule))
    {
        return -1;
    }
    return chaos_io_call_real_truncate(path, length);
}

/* ---------------------------------------------------------------------------
 * glibc alternate entry points
 *
 * On 64-bit glibc the large-file names (`ftruncate64`, `fallocate64`, ...) are separate
 * symbols with the same signature as the base functions, and binaries built with
 * large-file support, or the JDK, bind to them; without these aliases such calls would
 * bypass the library. musl has no large-file names, so this is glibc-only (LP64).
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__) && defined(__LP64__)

CHAOS_IO_EXPORT int ftruncate64(int fd, off_t length) __attribute__((alias("ftruncate")));
CHAOS_IO_EXPORT int truncate64(const char *path, off_t length) __attribute__((alias("truncate")));
CHAOS_IO_EXPORT int posix_fallocate64(int fd, off_t offset, off_t length)
    __attribute__((alias("posix_fallocate")));
CHAOS_IO_EXPORT int fallocate64(int fd, int mode, off_t offset, off_t length)
    __attribute__((alias("fallocate")));

#endif
