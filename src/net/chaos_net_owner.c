/**
 * @file chaos_net_owner.c
 * @brief Whether a socket is held by more descriptors than the one being closed.
 *
 * @details RESET works by setting `SO_LINGER {1, 0}` and closing, so the kernel aborts the
 * connection and the peer receives an RST. The option belongs to the open file
 * description, not to the descriptor: when another descriptor still refers to it, the
 * close frees nothing, no RST leaves, and the option stays behind until some later close
 * -- in another process, at another time, for no rule. A pre-forking server hits this
 * every time, because the parent closes its copy after handing the connection to a child.
 *
 * The kernel knows how many references an open file description has and does not say. It
 * is reconstructed here by reading the state rather than by tracking its history: every
 * `/proc/<pid>/fd` entry is a symbolic link that reads `socket:[<inode>]`, so a socket
 * held twice is visible as two links to the same inode. That observes the result, so it
 * covers `fork`, `vfork`, `dup`, `posix_spawn`, `SCM_RIGHTS` and any future way of
 * sharing one alike, and needs no bookkeeping on the hot path.
 *
 * The scan runs only for a close on which a RESET rule matched -- once per connection
 * teardown in a chaos test, never on a throughput path -- and only over the processes of a
 * container, which are tens, not thousands.
 *
 * @par Answer
 * `SOLE` only when every process was read and no other link was found. Anything that
 * could not be read answers `UNKNOWN`, on which the caller leaves the connection alone and
 * says so, because a wrong `SOLE` is what leaves the option behind.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/** @brief Bytes read from a directory per getdents64 call; two pages hold many entries. */
#define CHAOS_NET_OWNER_DIRENT_BYTES 8192U

/** @brief Longest `socket:[<inode>]` a 64-bit inode can produce, plus the NUL. */
#define CHAOS_NET_OWNER_TARGET_MAX 40U

/** @brief Longest `/proc/<pid>/fd` path, plus the NUL. */
#define CHAOS_NET_OWNER_PATH_MAX 64U

/**
 * @brief The kernel's getdents64 entry.
 *
 * @details Declared here because no C library on the build matrix exposes it: glibc hides
 * it behind readdir(), which allocates. The layout is kernel ABI and does not change.
 */
struct chaos_net_owner_dirent
{
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

/*
 * Test seams. The scan reads /proc, so a unit test cannot provoke an unreadable directory
 * or a vanished entry from outside; it replaces these three instead.
 */
#ifndef CHAOS_NET_OWNER_OPEN
#define CHAOS_NET_OWNER_OPEN(path) open((path), O_RDONLY | O_DIRECTORY | O_CLOEXEC)
#endif
#ifndef CHAOS_NET_OWNER_READLINK
#define CHAOS_NET_OWNER_READLINK(dir_fd, name, out, size)                                          \
    readlinkat((dir_fd), (name), (out), (size))
#endif
#ifndef CHAOS_NET_OWNER_GETDENTS
#define CHAOS_NET_OWNER_GETDENTS(fd, buffer, size) syscall(SYS_getdents64, (fd), (buffer), (size))
#endif

/**
 * @brief Whether @p name in directory @p dir_fd is a symbolic link reading @p target.
 *
 * @details readlinkat does not terminate, so the length it reports does. A name that is
 * not a link, or a target longer than the buffer, cannot be the socket and answers 0.
 *
 * @param dir_fd Directory holding @p name.
 * @param name   Entry to resolve.
 * @param target The `socket:[<inode>]` text to match.
 * @return Non-zero when the link reads exactly @p target.
 */
static int chaos_net_owner_link_is(int dir_fd, const char *name, const char *target)
{
    char link[CHAOS_NET_OWNER_TARGET_MAX];
    const ssize_t length = (ssize_t)CHAOS_NET_OWNER_READLINK(dir_fd, name, link, sizeof(link) - 1U);

    if (length <= 0)
    {
        return 0;
    }
    link[length] = '\0';
    return strcmp(link, target) == 0;
}

/**
 * @brief Counts the links to @p target in the descriptor directory @p path.
 *
 * @details `.` and `..` are skipped; every other entry is a descriptor number whose link
 * is resolved. Counting rather than stopping at the first match lets the caller tell its
 * own descriptor from a second one in the same process.
 *
 * @param path    A `/proc/<pid>/fd` directory.
 * @param target  The `socket:[<inode>]` text to match.
 * @param matches Output: how many entries resolve to @p target.
 * @return 0 when the whole directory was read; -1 when it could not be, with errno set.
 */
static int chaos_net_owner_count(const char *path, const char *target, size_t *matches)
{
    char buffer[CHAOS_NET_OWNER_DIRENT_BYTES];
    const int dir_fd = CHAOS_NET_OWNER_OPEN(path);
    long bytes;

    *matches = 0U;
    if (dir_fd < 0)
    {
        return -1;
    }
    while ((bytes = (long)CHAOS_NET_OWNER_GETDENTS(dir_fd, buffer, sizeof(buffer))) > 0)
    {
        long offset = 0;

        while (offset < bytes)
        {
            const struct chaos_net_owner_dirent *entry =
                (const struct chaos_net_owner_dirent *)(const void *)(buffer + offset);

            if (entry->d_name[0] != '.' && chaos_net_owner_link_is(dir_fd, entry->d_name, target))
            {
                ++*matches;
            }
            offset += (long)entry->d_reclen;
        }
    }
    (void)close(dir_fd);
    return bytes < 0 ? -1 : 0;
}

/**
 * @brief Whether @p name is a process directory, i.e. all digits.
 *
 * @param name Entry of `/proc`.
 * @return Non-zero for a process id.
 */
static int chaos_net_owner_is_pid(const char *name)
{
    size_t index = 0U;

    while (name[index] >= '0' && name[index] <= '9')
    {
        ++index;
    }
    return index > 0U && name[index] == '\0';
}

/**
 * @brief Looks for the socket in every process but this one.
 *
 * @details A process that ended between the listing and the open is not a holder, so
 * ENOENT is skipped; anything else unreadable makes the answer unknown, since a holder
 * could be hiding behind it.
 *
 * @param target The `socket:[<inode>]` text to match.
 * @param self   Decimal id of this process, already counted by the caller.
 * @return 1 found, 0 none, -1 a process could not be read.
 */
static int chaos_net_owner_other_holder(const char *target, const char *self)
{
    char buffer[CHAOS_NET_OWNER_DIRENT_BYTES];
    const int proc_fd = CHAOS_NET_OWNER_OPEN("/proc");
    int unreadable = 0;
    long bytes;

    if (proc_fd < 0)
    {
        return -1;
    }
    while ((bytes = (long)CHAOS_NET_OWNER_GETDENTS(proc_fd, buffer, sizeof(buffer))) > 0)
    {
        long offset = 0;

        while (offset < bytes)
        {
            const struct chaos_net_owner_dirent *entry =
                (const struct chaos_net_owner_dirent *)(const void *)(buffer + offset);
            char path[CHAOS_NET_OWNER_PATH_MAX];
            size_t matches = 0U;

            offset += (long)entry->d_reclen;
            if (!chaos_net_owner_is_pid(entry->d_name) || strcmp(entry->d_name, self) == 0)
            {
                continue;
            }
            /* No length check: a pid is at most ten digits, so the path always fits. */
            (void)snprintf(path, sizeof(path), "/proc/%s/fd", entry->d_name);
            if (chaos_net_owner_count(path, target, &matches) != 0)
            {
                unreadable = unreadable || errno != ENOENT;
                continue;
            }
            if (matches > 0U)
            {
                (void)close(proc_fd);
                return 1;
            }
        }
    }
    (void)close(proc_fd);
    if (bytes < 0)
    {
        return -1;
    }
    return unreadable ? -1 : 0;
}

/**
 * @copydoc chaos_net_socket_ownership
 */
chaos_net_ownership_t chaos_net_socket_ownership(int fd)
{
    const int saved_errno = errno;
    char target[CHAOS_NET_OWNER_TARGET_MAX];
    char self[16];
    struct stat info;
    size_t own = 0U;
    chaos_net_ownership_t answer = CHAOS_NET_OWNER_UNKNOWN;
    int previous;
    int other;

    previous = chaos_net_enter_internal();
    if (fstat(fd, &info) == 0 &&
        snprintf(target, sizeof(target), "socket:[%llu]", (unsigned long long)info.st_ino) > 0 &&
        chaos_net_owner_count("/proc/self/fd", target, &own) == 0)
    {
        /* This descriptor is one of the links, so a second one in this process is a dup.
         * None at all means the scan did not see what must be there -- the descriptor is
         * no socket, or /proc does not show this process -- and nothing may be concluded. */
        if (own > 1U)
        {
            answer = CHAOS_NET_OWNER_SHARED;
        }
        else if (own == 1U)
        {
            other = snprintf(self, sizeof(self), "%ld", (long)getpid()) > 0
                        ? chaos_net_owner_other_holder(target, self)
                        : -1;
            answer = other > 0 ? CHAOS_NET_OWNER_SHARED
                               : (other == 0 ? CHAOS_NET_OWNER_SOLE : CHAOS_NET_OWNER_UNKNOWN);
        }
    }
    chaos_net_leave_internal(previous);
    errno = saved_errno;
    return answer;
}
