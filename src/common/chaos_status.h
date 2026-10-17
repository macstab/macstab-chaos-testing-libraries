/**
 * @file chaos_status.h
 * @brief The status file (`/tmp/.chaos-<lib>.status`) every library writes after a reload,
 *        and the raw-syscall file I/O shared with the hits file and rule-file reads.
 *
 * @details
 * Rule parsing is all-or-nothing: one bad line leaves the library with no rules, which
 * from the outside is indistinguishable from a rule that never fires. After every reload
 * each library therefore replaces its status file with the outcome:
 *
 * @code
 * state=ok|error
 * rules=<number of active rules; 0 for an error>
 * line=<1-based line of the first rejected rule; 0 when no line is named>  (error only)
 * reason=<one of the reasons below>                                        (error only)
 * text=<that line as written, at most 200 bytes>                           (error only)
 * pid=<process that wrote the file>
 * @endcode
 *
 * | reason | line |
 * |--------|------|
 * | `invalid rule` | the rejected line |
 * | `too many rules` | the first line beyond the rule limit |
 * | `unsupported in seccomp mode` | the rule chaos-init cannot apply |
 * | `file too large` | 0, text empty |
 * | `file unreadable` | 0, text empty |
 * | `file contains a NUL byte` | 0, text empty |
 *
 * Without a rule file there is nothing to report and the status file is removed, so a
 * status file always describes the rule file beside it.
 *
 * @par Atomic publication
 * The report is written to `<dir>/.chaos-staging-<pid>-<nonce>-<name>` and renamed over
 * the target, so a reader sees the old or the new report, never a mix
 * (chaos_status_publish()).
 *
 * @par Why raw system calls
 * Like the injected sleep (chaos_sleep.h), every file operation here is a `syscall(2)`:
 * libchaos-io interposes open, write and rename, and a user's io rule must not fail or
 * delay a report or a rule-file read. All writes are best effort; failures are ignored
 * and errno is preserved.
 *
 * @par Test seams
 * CHAOS_STATUS_OPEN and its siblings, CHAOS_CONFIG_FILE_OPEN/READ/CLOSE and
 * CHAOS_STATUS_NONCE may be predefined by unit tests.
 */

#ifndef CHAOS_STATUS_H
#define CHAOS_STATUS_H

#include "chaos_clock.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/** @brief Maximum bytes of a rule text kept for the status and hits files (excluding NUL). */
#define CHAOS_STATUS_TEXT_MAX 200U

/** @brief Report buffer size: six keys, a 200-byte text and three numbers fit with room. */
#define CHAOS_STATUS_BUFFER_SIZE 512U

/** @brief Outcome of a reload, written as the `state=` key. */
typedef enum chaos_status_state
{
    CHAOS_STATUS_OK = 0,
    CHAOS_STATUS_ERROR = 1
} chaos_status_state_t;

/**
 * @brief Parser error record: the line being parsed and, once rejected, the reason.
 *
 * @details `reason == NULL` means no line was rejected. `line == 0` with a reason means a
 * whole-file rejection that names no line.
 */
typedef struct chaos_status_error
{
    size_t line;
    const char *reason;
    char text[CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_status_error_t;

/** @brief Reason: the line does not parse (selector, effect, probability or qualifier). */
#define CHAOS_STATUS_REASON_INVALID "invalid rule"

/** @brief Reason: the first rule beyond the library's rule limit. */
#define CHAOS_STATUS_REASON_TOO_MANY "too many rules"

/** @brief Reason: the rule file is at or over the library's size limit (no line named). */
#define CHAOS_STATUS_REASON_TOO_LARGE "file too large"

/** @brief Reason: this process may not open or read the rule file (no line named). */
#define CHAOS_STATUS_REASON_UNREADABLE "file unreadable"

/**
 * @brief Reason: the rule file contains a NUL byte (no line named). A string parser would
 *        stop there and drop every later rule silently, so the file is rejected instead.
 */
#define CHAOS_STATUS_REASON_NUL "file contains a NUL byte"

/**
 * @brief Reason: a valid rule that SECCOMP mode cannot apply (data effects, ERRNO on
 *        close); emitted when a parser is built for chaos-init.
 */
#define CHAOS_STATUS_REASON_UNSUPPORTED "unsupported in seccomp mode"

/** @brief Resets @p error to "nothing rejected". */
static inline void chaos_status_clear(chaos_status_error_t *error)
{
    error->line = 0U;
    error->reason = NULL;
    error->text[0] = '\0';
}

/**
 * @brief Snapshots line @p number into @p error before the parser modifies it in place.
 *
 * @details Called for every line, so the record always holds the line under parse;
 * the copy also serves as the rule text in the hits file. Copies up to
 * CHAOS_STATUS_TEXT_MAX bytes, stopping at NUL or LF; control characters and DEL become
 * spaces so each report key stays on one line. Clears any earlier reason.
 */
static inline void
chaos_status_keep_line(chaos_status_error_t *error, size_t number, const char *line)
{
    size_t index = 0U;

    while (index < CHAOS_STATUS_TEXT_MAX && line[index] != '\0' && line[index] != '\n')
    {
        const unsigned char ch = (unsigned char)line[index];

        error->text[index] = (ch < 0x20U || ch == 0x7fU) ? ' ' : (char)ch;
        ++index;
    }
    error->text[index] = '\0';
    error->line = number;
    error->reason = NULL;
}

/** @brief Marks the line kept by chaos_status_keep_line() as rejected for @p reason. */
static inline void chaos_status_reject(chaos_status_error_t *error, const char *reason)
{
    error->reason = reason;
}

/**
 * @brief Formats a status report into @p buffer.
 *
 * @details The error layout is used only when @p state is CHAOS_STATUS_ERROR and
 * @p error carries a reason; otherwise the short `state`/`rules`/`pid` layout is written.
 * The output is truncated, not overflowed, when @p size is too small.
 *
 * @return Bytes written, excluding the NUL; 0 when formatting failed or @p size is 0.
 */
static inline size_t chaos_status_format(
    char *buffer,
    size_t size,
    chaos_status_state_t state,
    size_t rules,
    const chaos_status_error_t *error,
    long pid
)
{
    static const char *const names[] = {"ok", "error"};
    int length;

    if (state == CHAOS_STATUS_ERROR && error != NULL && error->reason != NULL)
    {
        length = snprintf(
            buffer,
            size,
            "state=error\nrules=0\nline=%lu\nreason=%s\ntext=%s\npid=%ld\n",
            (unsigned long)error->line,
            error->reason,
            error->text,
            pid
        );
    }
    else
    {
        length = snprintf(
            buffer, size, "state=%s\nrules=%lu\npid=%ld\n", names[state], (unsigned long)rules, pid
        );
    }
    if (length < 0 || size == 0U)
    {
        return 0U;
    }
    return (size_t)length < size ? (size_t)length : size - 1U;
}

/*
 * File operations of status and hits files as raw system calls (see the file header).
 * New files: O_EXCL | O_NOFOLLOW, because /tmp is shared and a planted symlink must not
 * redirect the write. Existing files: no O_CREAT, which fs.protected_regular would refuse
 * for another user's file in a sticky directory. renameat2 covers architectures without
 * SYS_renameat (aarch64). Unit tests replace them all.
 */
#ifndef CHAOS_STATUS_OPEN
#ifdef __linux__
#define CHAOS_STATUS_OPEN(path)                                                                    \
    (int)syscall(                                                                                  \
        SYS_openat, AT_FDCWD, (path), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644   \
    )
#define CHAOS_STATUS_OPEN_EXISTING(path)                                                           \
    (int)syscall(SYS_openat, AT_FDCWD, (path), O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
#define CHAOS_STATUS_SHARE(fd) syscall(SYS_fchmod, (fd), 0666)
#define CHAOS_STATUS_WRITE(fd, data, length) syscall(SYS_write, (fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) syscall(SYS_close, (fd))
#define CHAOS_STATUS_UNLINK(path) syscall(SYS_unlinkat, AT_FDCWD, (path), 0)
#define CHAOS_STATUS_LINK(from, to) syscall(SYS_linkat, AT_FDCWD, (from), AT_FDCWD, (to), 0)
#define CHAOS_STATUS_EXISTS(path) (syscall(SYS_faccessat, AT_FDCWD, (path), F_OK, 0) == 0)
#ifdef SYS_renameat
#define CHAOS_STATUS_RENAME(from, to) syscall(SYS_renameat, AT_FDCWD, (from), AT_FDCWD, (to))
#else
#define CHAOS_STATUS_RENAME(from, to) syscall(SYS_renameat2, AT_FDCWD, (from), AT_FDCWD, (to), 0)
#endif
#else
#define CHAOS_STATUS_OPEN(path)                                                                    \
    open((path), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644)
#define CHAOS_STATUS_OPEN_EXISTING(path) open((path), O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC)
#define CHAOS_STATUS_SHARE(fd) fchmod((fd), 0666)
#define CHAOS_STATUS_WRITE(fd, data, length) write((fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) close(fd)
#define CHAOS_STATUS_UNLINK(path) unlink(path)
#define CHAOS_STATUS_LINK(from, to) link((from), (to))
#define CHAOS_STATUS_EXISTS(path) (access((path), F_OK) == 0)
#define CHAOS_STATUS_RENAME(from, to) rename((from), (to))
#endif
#endif

/*
 * Rule-file reads as raw system calls: through libc, libchaos-io preloaded into the same
 * process would intercept another library reading its rules, and an io rule could fail or
 * delay that read. O_CLOEXEC: a descriptor open while another thread execs must not leak
 * into the new program. Unit tests replace these with stubs.
 */
#ifndef CHAOS_CONFIG_FILE_OPEN
#ifdef __linux__
#define CHAOS_CONFIG_FILE_OPEN(path)                                                               \
    (int)syscall(SYS_openat, AT_FDCWD, (path), O_RDONLY | O_CLOEXEC)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) (ssize_t) syscall(SYS_read, (fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)syscall(SYS_close, (fd))
#else
#define CHAOS_CONFIG_FILE_OPEN(path) open((path), O_RDONLY | O_CLOEXEC)
#define CHAOS_CONFIG_FILE_READ(fd, buffer, size) read((fd), (buffer), (size))
#define CHAOS_CONFIG_FILE_CLOSE(fd) (void)close(fd)
#endif
#endif

/**
 * @brief 64-bit FNV-1a hash of a rule file's bytes.
 *
 * @details A provisional load (chaos_clock_stamp_is_recent()) re-reads the file on every
 * check; comparing hashes lets that re-read skip the reparse when the bytes are unchanged.
 * Not collision-resistant, which is acceptable for change detection of trusted input.
 */
static inline uint64_t chaos_config_content_hash(const char *data, size_t size)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    size_t index;

    for (index = 0U; index < size; ++index)
    {
        hash ^= (unsigned char)data[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

/**
 * @brief Staging-name nonce: monotonic ns XOR a stack address, so writers with the same pid
 *        (one per container sharing /tmp) pick different names. Unit tests fix it.
 */
#ifndef CHAOS_STATUS_NONCE
#define CHAOS_STATUS_NONCE(staging) (chaos_clock_now_ns() ^ (uint64_t)(uintptr_t)(staging))
#endif

/**
 * @brief Writes all @p length bytes of @p data to @p fd, retrying short writes and EINTR.
 *
 * @return 1 when every byte was written; 0 on any other error or a zero-byte write
 *         (errno then describes the failure).
 */
static inline int chaos_status_write_all(int fd, const char *data, size_t length)
{
    size_t written = 0U;

    while (written < length)
    {
        const long rc = (long)CHAOS_STATUS_WRITE(fd, data + written, length - written);

        if (rc <= 0)
        {
            if (rc < 0 && errno == EINTR)
            {
                continue;
            }
            return 0;
        }
        written += (size_t)rc;
    }
    return 1;
}

/**
 * @brief Atomically replaces (or, with @p exclusive, only creates) the file at @p path
 *        with @p length bytes of @p data.
 *
 * @details Writes `<dir>/.chaos-staging-<pid>-<nonce>-<name>` (a leading '.' of the name
 * dropped) and renames it over @p path, so a reader sees the old or the new file, never a
 * mix. The staging prefix differs from every status and hits file name, so a reader that
 * globs `.chaos-<lib>.hits.*` never picks up a half-written file. The nonce separates
 * writers with the same pid (containers sharing /tmp each run their own pid 1); an
 * existing staging name (EEXIST) is another writer's, and up to 4 nonces are tried.
 *
 * Files are made mode 0666 with fchmod (bypassing the umask): in a sticky /tmp another
 * user may not rename over a file it does not own, e.g. when an image starts as root and
 * the application runs as another user. A rename refused with EPERM or EACCES falls back
 * to rewriting @p path in place (O_TRUNC, no O_CREAT); a reader may then briefly see a
 * short file.
 *
 * With @p exclusive, the staging file is hard-linked to @p path, which fails with EEXIST
 * when @p path exists; nothing is replaced. When linking fails for another reason (a file
 * system without hard links), the function falls through to the rename and replaces
 * @p path after all.
 *
 * Failure behaviour: best effort. On any failure the staging file is removed and @p path
 * keeps its previous content; a staging path longer than 191 bytes writes nothing.
 * errno is preserved.
 *
 * @param path       Target file; its directory must be writable.
 * @param data       Content; need not be NUL-terminated.
 * @param length     Bytes of @p data.
 * @param exclusive  Non-zero to create only, never replace.
 * @return 1 when @p exclusive and @p path already existed (nothing written); 0 otherwise,
 *         including on failure.
 */
static inline int
chaos_status_publish(const char *path, const char *data, size_t length, int exclusive)
{
    const int saved_errno = errno;
    const char *slash = strrchr(path, '/');
    const char *name = slash == NULL ? path : slash + 1;
    const int dir_length = (int)(name - path);
    char staging[192];
    const uint64_t nonce = CHAOS_STATUS_NONCE(staging);
    unsigned attempt;
    int complete;
    int fd = -1;

    if (name[0] == '.')
    {
        ++name;
    }
    /* O_EXCL | O_NOFOLLOW (CHAOS_STATUS_OPEN): /tmp is shared, so never write through a
     * pre-existing file or a planted symlink. */
    for (attempt = 0U; attempt < 4U; ++attempt)
    {
        if ((size_t)snprintf(
                staging,
                sizeof(staging),
                "%.*s.chaos-staging-%ld-%llx-%s",
                dir_length,
                path,
                (long)getpid(),
                (unsigned long long)(nonce + attempt),
                name
            ) >= sizeof(staging))
        {
            errno = saved_errno;
            return 0;
        }
        fd = CHAOS_STATUS_OPEN(staging);
        if (fd >= 0 || errno != EEXIST)
        {
            break;
        }
    }
    if (fd < 0)
    {
        errno = saved_errno;
        return 0;
    }
    (void)CHAOS_STATUS_SHARE(fd);
    complete = chaos_status_write_all(fd, data, length);
    (void)CHAOS_STATUS_CLOSE(fd);
    if (complete && exclusive)
    {
        const int taken = CHAOS_STATUS_LINK(staging, path) != 0;

        if (!taken || errno == EEXIST)
        {
            (void)CHAOS_STATUS_UNLINK(staging);
            errno = saved_errno;
            return taken;
        }
    }
    if (complete && CHAOS_STATUS_RENAME(staging, path) == 0)
    {
        errno = saved_errno;
        return 0;
    }
    if (complete && (errno == EPERM || errno == EACCES))
    {
        /* Another user's file in a sticky directory cannot be renamed over; rewrite it in
         * place instead (the 0666 mode set at creation makes that possible). */
        fd = CHAOS_STATUS_OPEN_EXISTING(path);
        if (fd >= 0)
        {
            (void)chaos_status_write_all(fd, data, length);
            (void)CHAOS_STATUS_CLOSE(fd);
        }
    }
    (void)CHAOS_STATUS_UNLINK(staging);
    errno = saved_errno;
    return 0;
}

/** @brief chaos_status_publish() in replace mode; best effort, errno preserved. */
static inline void chaos_status_replace_file(const char *path, const char *data, size_t length)
{
    (void)chaos_status_publish(path, data, length, 0);
}

/**
 * @brief Atomically replaces the status file at @p path with the outcome of a reload.
 *
 * @details Best effort; errno is preserved. The report carries the caller's pid.
 *
 * @param path   Status file, e.g. `/tmp/.chaos-net.status`.
 * @param state  Outcome of the reload.
 * @param rules  Number of active rules; written as 0 for an error with a reason.
 * @param error  The rejection record for CHAOS_STATUS_ERROR, otherwise NULL.
 */
static inline void chaos_status_write(
    const char *path, chaos_status_state_t state, size_t rules, const chaos_status_error_t *error
)
{
    char report[CHAOS_STATUS_BUFFER_SIZE];
    const size_t length =
        chaos_status_format(report, sizeof(report), state, rules, error, (long)getpid());

    chaos_status_replace_file(path, report, length);
}

/** @brief Removes the status file at @p path (no rule file); best effort, errno preserved. */
static inline void chaos_status_remove(const char *path)
{
    const int saved_errno = errno;

    (void)CHAOS_STATUS_UNLINK(path);
    errno = saved_errno;
}

#endif
