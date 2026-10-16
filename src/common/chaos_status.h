/**
 * @file chaos_status.h
 * @brief The status file every library writes after loading its rule file.
 *
 * @details
 * Rule parsing is all-or-nothing: one bad line leaves the library with no rules.
 * Without a report that looks exactly like a rule that never fires. After every
 * load each library therefore replaces `/tmp/.chaos-<lib>.status` with what it
 * found:
 *
 * @code
 * state=ok|error
 * rules=<number of active rules>
 * line=<1-based line of the first rejected rule>      (error only)
 * reason=invalid rule|too many rules|file too large|file unreadable|file contains a NUL byte
 *                                                      (error only; line=0 for the last two)
 * text=<that line as written, at most 200 bytes>       (error only)
 * pid=<process that wrote the file>
 * @endcode
 *
 * Without a rule file there is nothing to report and the status file is removed,
 * so a status file always describes the rule file next to it.
 *
 * The file is written to `<path>.<pid>` and renamed over the old one, so a reader
 * never sees half a report. Like the injected sleep (chaos_sleep.h) the write
 * issues system calls directly: libchaos-io interposes open, write and rename,
 * and a user's io rule must not be able to fail the report. Writing is best
 * effort; any failure is ignored and errno is left as it was.
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

/** @brief Longest rejected line kept in the report. */
#define CHAOS_STATUS_TEXT_MAX 200U

/** @brief Largest report: six keys, a 200-byte line and a few numbers. */
#define CHAOS_STATUS_BUFFER_SIZE 512U

/** @brief Outcome of a load, as written to the `state=` key. */
typedef enum chaos_status_state
{
    CHAOS_STATUS_OK = 0,
    CHAOS_STATUS_ERROR = 1
} chaos_status_state_t;

/** @brief The first line a parse rejected; `line == 0` when none was rejected. */
typedef struct chaos_status_error
{
    size_t line;
    const char *reason;
    char text[CHAOS_STATUS_TEXT_MAX + 1U];
} chaos_status_error_t;

/** @brief Reason for a line the parser rejected. */
#define CHAOS_STATUS_REASON_INVALID "invalid rule"

/** @brief Reason for the first line beyond the rule limit. */
#define CHAOS_STATUS_REASON_TOO_MANY "too many rules"

/** @brief Reason for a rule file at or over the size limit (no line is named). */
#define CHAOS_STATUS_REASON_TOO_LARGE "file too large"

/** @brief Reason for a rule file this process may not open or read (no line is named). */
#define CHAOS_STATUS_REASON_UNREADABLE "file unreadable"

/**
 * @brief Reason for a rule file holding a NUL byte (no line is named): the parser
 *        would stop there and drop every rule after it without a word.
 */
#define CHAOS_STATUS_REASON_NUL "file contains a NUL byte"

/** @brief Reason for a valid rule chaos-init cannot apply (data effects, ERRNO on close). */
#define CHAOS_STATUS_REASON_UNSUPPORTED "unsupported in seccomp mode"

/** @brief Forgets any recorded error. */
static inline void chaos_status_clear(chaos_status_error_t *error)
{
    error->line = 0U;
    error->reason = NULL;
    error->text[0] = '\0';
}

/**
 * @brief Keeps a copy of line @p number before the parser modifies it in place.
 *
 * @details Called for every line; only the copy of the line that fails is reported.
 * Control characters become spaces so the report stays one line per key.
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

/** @brief Marks the kept line as the rejected one. */
static inline void chaos_status_reject(chaos_status_error_t *error, const char *reason)
{
    error->reason = reason;
}

/** @brief Formats the report into @p buffer; returns its length. */
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

/* The system calls of status and hits files; unit tests replace them all. */
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
#define CHAOS_STATUS_EXISTS(path) (access((path), F_OK) == 0)
#define CHAOS_STATUS_RENAME(from, to) rename((from), (to))
#endif
#endif

/*
 * Rule files are read with raw system calls too. Through libc, another library
 * preloaded into the same process (libchaos-io) would see one library reading its
 * rules, and its rules could fail or delay that read. O_CLOEXEC: a descriptor open
 * while another thread execs must not leak into the new program. Unit tests
 * replace these with stubs.
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
 * @brief FNV-1a hash of a rule file's bytes: lets a provisional load that reads the
 *        file again (chaos_clock_stamp_is_recent) see that nothing changed.
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

/** @brief Varies the staging name between writers with the same pid; unit tests fix it. */
#ifndef CHAOS_STATUS_NONCE
#define CHAOS_STATUS_NONCE(staging) (chaos_clock_now_ns() ^ (uint64_t)(uintptr_t)(staging))
#endif

/** @brief Writes @p length bytes of @p data to @p fd; 1 when all were written. */
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
 * @brief Replaces the file at @p path with @p length bytes of @p data.
 *
 * @details Writes `<dir>/.chaos-staging-<pid>-<nonce>-<name>` and renames it over
 * @p path, so a reader sees the old file or the new one, never a mix. The staging
 * name starts differently from every status and hits file, so nothing that lists
 * those (`.chaos-net.hits.*`) picks up a half-written one. The nonce keeps apart
 * writers with the same pid: containers that share /tmp each run their own PID 1.
 * A name that exists is another writer's; the next nonce is tried instead.
 *
 * Files are created readable and writable by everyone (0666): in a shared, sticky
 * /tmp another user may not rename over a file it does not own, as when an image
 * starts as root and the application runs as another user. Such a refused rename
 * falls back to rewriting @p path in place; a reader may then briefly see it
 * short. It is opened without O_CREAT, which fs.protected_regular would refuse.
 *
 * Best effort: on any other failure the staging file is removed and @p path is
 * left as it was. errno is left untouched.
 */
static inline void chaos_status_replace_file(const char *path, const char *data, size_t length)
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
    /* A new file only, never through a link: /tmp is shared. */
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
            return;
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
        return;
    }
    (void)CHAOS_STATUS_SHARE(fd);
    complete = chaos_status_write_all(fd, data, length);
    (void)CHAOS_STATUS_CLOSE(fd);
    if (complete && CHAOS_STATUS_RENAME(staging, path) == 0)
    {
        errno = saved_errno;
        return;
    }
    if (complete && (errno == EPERM || errno == EACCES))
    {
        /* Another user's file in a sticky directory: rewrite it in place. */
        fd = CHAOS_STATUS_OPEN_EXISTING(path);
        if (fd >= 0)
        {
            (void)chaos_status_write_all(fd, data, length);
            (void)CHAOS_STATUS_CLOSE(fd);
        }
    }
    (void)CHAOS_STATUS_UNLINK(staging);
    errno = saved_errno;
}

/**
 * @brief Replaces the status file at @p path with the outcome of a load.
 *
 * @param path   Status file, e.g. `/tmp/.chaos-net.status`.
 * @param state  Outcome of the load.
 * @param rules  Number of active rules (ignored for an error).
 * @param error  The rejected line for CHAOS_STATUS_ERROR, otherwise NULL.
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

/** @brief Removes the status file at @p path, leaving errno untouched. */
static inline void chaos_status_remove(const char *path)
{
    const int saved_errno = errno;

    (void)CHAOS_STATUS_UNLINK(path);
    errno = saved_errno;
}

#endif
