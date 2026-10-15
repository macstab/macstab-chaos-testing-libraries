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
 * reason=invalid rule|too many rules                   (error only)
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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
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
    if (length < 0)
    {
        return 0U;
    }
    return (size_t)length < size ? (size_t)length : size - 1U;
}

#ifdef __linux__
#define CHAOS_STATUS_OPEN(path)                                                                    \
    (int)syscall(SYS_openat, AT_FDCWD, (path), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)
#define CHAOS_STATUS_WRITE(fd, data, length) syscall(SYS_write, (fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) syscall(SYS_close, (fd))
#define CHAOS_STATUS_UNLINK(path) syscall(SYS_unlinkat, AT_FDCWD, (path), 0)
#ifdef SYS_renameat
#define CHAOS_STATUS_RENAME(from, to) syscall(SYS_renameat, AT_FDCWD, (from), AT_FDCWD, (to))
#else
#define CHAOS_STATUS_RENAME(from, to) syscall(SYS_renameat2, AT_FDCWD, (from), AT_FDCWD, (to), 0)
#endif
#else
#define CHAOS_STATUS_OPEN(path) open((path), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)
#define CHAOS_STATUS_WRITE(fd, data, length) write((fd), (data), (length))
#define CHAOS_STATUS_CLOSE(fd) close(fd)
#define CHAOS_STATUS_UNLINK(path) unlink(path)
#define CHAOS_STATUS_RENAME(from, to) rename((from), (to))
#endif

/**
 * @brief Replaces the file at @p path with @p length bytes of @p data.
 *
 * @details Writes `<path>.<pid>` and renames it over @p path, so a reader sees the
 * old file or the new one, never a mix. Best effort: on any failure the staging
 * file is removed and @p path is left as it was. errno is left untouched.
 */
static inline void chaos_status_replace_file(const char *path, const char *data, size_t length)
{
    const int saved_errno = errno;
    char staging[128];
    size_t written = 0U;
    int fd;

    if ((size_t)snprintf(staging, sizeof(staging), "%s.%ld", path, (long)getpid()) >=
        sizeof(staging))
    {
        return;
    }
    fd = CHAOS_STATUS_OPEN(staging);
    if (fd < 0)
    {
        errno = saved_errno;
        return;
    }
    while (written < length)
    {
        const long rc = (long)CHAOS_STATUS_WRITE(fd, data + written, length - written);

        if (rc <= 0)
        {
            if (rc < 0 && errno == EINTR)
            {
                continue;
            }
            break;
        }
        written += (size_t)rc;
    }
    (void)CHAOS_STATUS_CLOSE(fd);
    if (written != length || CHAOS_STATUS_RENAME(staging, path) != 0)
    {
        (void)CHAOS_STATUS_UNLINK(staging);
    }
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
