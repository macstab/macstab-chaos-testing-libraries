/*
 * Path-first wrappers for libchaos-io.
 *
 * `open()` and `openat()` are grouped together because they share the same
 * varargs ABI handling, path-resolution semantics, and fd-cache seeding rules.
 */

#include "chaos_io_actions.h"
#include "chaos_io_config.h"
#include "chaos_io_fdcache.h"
#include "chaos_io_internal.h"

#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

/*
 * Call the real `open()` with the exact ABI shape expected by libc.
 *
 * Parameters:
 * - `path`
 *   Pathname forwarded to the downstream libc `open()`.
 * - `flags`
 *   Original open flags. These are forwarded unchanged.
 * - `has_mode`
 *   Non-zero when the wrapper decoded a trailing mode argument from the caller
 *   and therefore must pass three arguments to the real symbol.
 * - `mode`
 *   Decoded file mode. Meaningful only when `has_mode` is non-zero.
 *
 * Returns:
 * - the return value of the real libc `open()`
 *
 * Why this helper exists:
 * - `open()` is varargs and therefore awkward to delegate correctly in multiple
 *   places
 * - the recursion-guard boundary should be identical across all `open()` paths
 *
 * System interaction:
 * - does not touch config or cache state
 * - enters internal mode
 * - calls the resolved downstream libc `open()` symbol
 * - restores the prior recursion-guard state
 *
 * The subtle point here is argument promotion: by the time the caller reaches
 * this helper, any optional `mode_t` has already been decoded from varargs with
 * default integer promotion rules. This helper only decides whether the real
 * call is made with two or three arguments.
 */
static int chaos_io_call_real_open(const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    if (has_mode != 0) {
        result = g_chaos_io_real_open(path, flags, mode);
    } else {
        result = g_chaos_io_real_open(path, flags);
    }
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Returns non-zero when an open-style call must forward a trailing mode.
 *
 * `open()` and `openat()` share the same varargs contract. Keeping the flag
 * check in one helper avoids subtle divergence between the two wrappers.
 */
static int chaos_io_open_needs_mode(int flags)
{
#ifdef O_TMPFILE
    return ((flags & O_CREAT) != 0) || ((flags & O_TMPFILE) == O_TMPFILE);
#else
    return ((flags & O_CREAT) != 0);
#endif
}

/*
 * Call the real `openat()` with the ABI shape expected by libc.
 *
 * This mirrors `chaos_io_call_real_open()` exactly, but keeps the directory-fd
 * argument in place for relative-path callers.
 */
static int chaos_io_call_real_openat(int dirfd, const char *path, int flags, int has_mode, mode_t mode)
{
    int previous;
    int result;

    previous = chaos_io_enter_internal();
    if (has_mode != 0) {
        result = g_chaos_io_real_openat(dirfd, path, flags, mode);
    } else {
        result = g_chaos_io_real_openat(dirfd, path, flags);
    }
    chaos_io_leave_internal(previous);
    return result;
}

/*
 * Copy one path string into caller storage if it fits.
 *
 * Open-style wrappers resolve a match path up front and then reuse it for rule
 * selection and fd-cache seeding. This helper keeps the bounds check uniform.
 */
static int chaos_io_copy_path(char *destination, size_t destination_size, const char *path)
{
    size_t length;

    if (destination == NULL || destination_size == 0U || path == NULL) {
        return 0;
    }

    length = strlen(path);
    if (length + 1U > destination_size) {
        return 0;
    }

    (void)memcpy(destination, path, length + 1U);
    return 1;
}

/*
 * Join a resolved base directory and a relative child path.
 *
 * `openat()` needs a stable absolute-ish string for config matching. The join
 * is intentionally lexical; it does not normalize `.` or `..` segments.
 */
static int chaos_io_join_paths(char *destination, size_t destination_size, const char *base, const char *path)
{
    size_t base_length;
    size_t path_length;
    size_t needs_separator;

    if (destination == NULL || destination_size == 0U || base == NULL || path == NULL) {
        return 0;
    }
    if (*base == '\0' || *path == '\0') {
        return 0;
    }

    base_length = strlen(base);
    path_length = strlen(path);
    needs_separator = (base[base_length - 1U] == '/') ? 0U : 1U;
    if (base_length + needs_separator + path_length + 1U > destination_size) {
        return 0;
    }

    (void)memcpy(destination, base, base_length);
    if (needs_separator != 0U) {
        destination[base_length] = '/';
        ++base_length;
    }
    (void)memcpy(destination + base_length, path, path_length + 1U);
    return 1;
}

/*
 * Resolve the current working directory without leaving the preload layer.
 *
 * Relative `open()` and `openat(AT_FDCWD, ...)` calls need a matchable path
 * before any rule can fire. The library does not interpose `getcwd()`, but it
 * still enters internal mode so any libc work it performs stays out of scope.
 */
static int chaos_io_getcwd_path(char *path, size_t path_size)
{
    int previous;
    int ok;

    if (path == NULL || path_size == 0U) {
        return 0;
    }

    previous = chaos_io_enter_internal();
    ok = getcwd(path, path_size) != NULL;
    chaos_io_leave_internal(previous);
    return ok;
}

/*
 * Resolve an open-style pathname into the string used for matching.
 *
 * Resolution rules:
 * - absolute paths are used as-is
 * - relative paths under `AT_FDCWD` are joined with the current working
 *   directory
 * - other relative paths are joined with the directory-fd path resolved through
 *   the fd cache or `/proc/self/fd`
 *
 * If resolution fails, the caller must bypass pre-open path injection and rely
 * on post-open fd resolution only.
 */
static int chaos_io_resolve_open_path(int dirfd, const char *path, char *resolved_path, size_t resolved_path_size)
{
    char base_path[CHAOS_IO_MAX_PATH];

    if (path == NULL || resolved_path == NULL || resolved_path_size == 0U) {
        return 0;
    }
    if (path[0] == '/') {
        return chaos_io_copy_path(resolved_path, resolved_path_size, path);
    }
    if (dirfd == AT_FDCWD) {
        return chaos_io_getcwd_path(base_path, sizeof(base_path))
            && chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path);
    }
    if (!chaos_io_fdcache_resolve(dirfd, base_path, sizeof(base_path))) {
        return 0;
    }
    return chaos_io_join_paths(resolved_path, resolved_path_size, base_path, path);
}

/*
 * Seed the fd cache after a successful open-style call.
 *
 * When the wrapper already resolved a stable path, store it directly. When it
 * could not resolve the path up front, ask the fd cache module to resolve the
 * new descriptor through `/proc/self/fd` instead.
 */
static void chaos_io_cache_open_result(int fd, const char *path)
{
    char resolved_path[CHAOS_IO_MAX_PATH];

    if (fd < 0) {
        return;
    }
    if (path != NULL) {
        if (!chaos_io_is_excluded_path(path)) {
            chaos_io_fdcache_store(fd, path);
        }
        return;
    }

    (void)chaos_io_fdcache_resolve(fd, resolved_path, sizeof(resolved_path));
}

/*
 * Interposed `open(2)` entry point.
 *
 * Parameters:
 * - `path`
 *   User-supplied pathname. It is both the object of the real open operation
 *   and the key used for rule matching and later fd-cache seeding.
 * - `flags`
 *   Original open flags. These are inspected to determine whether a trailing
 *   mode argument exists and are then forwarded unchanged to libc.
 * - `...`
 *   Optional `mode_t`, present when `flags` requires it. Because varargs use
 *   default argument promotions, the wrapper decodes it as `int` and casts back
 *   to `mode_t`.
 */
CHAOS_IO_EXPORT int open(const char *path, int flags, ...)
{
    chaos_io_rule_t rule;
    char resolved_path[CHAOS_IO_MAX_PATH];
    const char *match_path = NULL;
    mode_t mode = 0;
    int has_mode;
    int fd;

    has_mode = chaos_io_open_needs_mode(flags);

    if (has_mode != 0) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (chaos_io_in_internal()) {
        return chaos_io_call_real_open(path, flags, has_mode, mode);
    }

    if (chaos_io_resolve_open_path(AT_FDCWD, path, resolved_path, sizeof(resolved_path))) {
        match_path = resolved_path;
    }

    if (match_path != NULL
        && !chaos_io_is_excluded_path(match_path)
        && chaos_io_config_match_path(CHAOS_IO_OP_OPEN, match_path, &rule)) {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
            chaos_io_rule_apply_latency(&rule);
        } else if (chaos_io_rule_apply_errno(&rule)) {
            return -1;
        }
    }

    fd = chaos_io_call_real_open(path, flags, has_mode, mode);
    chaos_io_cache_open_result(fd, match_path);
    return fd;
}

/*
 * Interposed `openat(2)` entry point.
 *
 * `openat()` reuses the logical `open` rule class. The only extra work here is
 * resolving relative paths into the string used for matching and cache seeding.
 */
CHAOS_IO_EXPORT int openat(int dirfd, const char *path, int flags, ...)
{
    chaos_io_rule_t rule;
    char resolved_path[CHAOS_IO_MAX_PATH];
    const char *match_path = NULL;
    mode_t mode = 0;
    int has_mode;
    int fd;

    has_mode = chaos_io_open_needs_mode(flags);
    if (has_mode != 0) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    if (chaos_io_in_internal()) {
        return chaos_io_call_real_openat(dirfd, path, flags, has_mode, mode);
    }

    if (chaos_io_resolve_open_path(dirfd, path, resolved_path, sizeof(resolved_path))) {
        match_path = resolved_path;
    }

    if (match_path != NULL
        && !chaos_io_is_excluded_path(match_path)
        && chaos_io_config_match_path(CHAOS_IO_OP_OPEN, match_path, &rule)) {
        if (rule.effect == CHAOS_IO_EFFECT_LATENCY) {
            chaos_io_rule_apply_latency(&rule);
        } else if (chaos_io_rule_apply_errno(&rule)) {
            return -1;
        }
    }

    fd = chaos_io_call_real_openat(dirfd, path, flags, has_mode, mode);
    chaos_io_cache_open_result(fd, match_path);
    return fd;
}
