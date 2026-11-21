/**
 * @file test_net_owner.c
 * @brief Unit tests for the ownership scan of libchaos-net.
 *
 * @details Units under test: `src/net/chaos_net_owner.c`. The scan reads `/proc`, so these
 * tests use real descriptors and real processes rather than stubs: a socket this process
 * alone holds, the same socket after a dup, and the same socket while a child holds it.
 *
 * Covered:
 * - a socket held by one descriptor is SOLE;
 * - a dup of it in this process is SHARED, and SOLE again once the dup is closed;
 * - a socket a forked child holds is SHARED, and SOLE again once the child is gone;
 * - a descriptor that is no socket is UNKNOWN, because the scan cannot find its own link
 *   among the sockets and must not conclude from that;
 * - a closed descriptor is UNKNOWN, since fstat fails.
 */

#include "../support/test_net_support.h"

#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>

CHAOS_NET_DEFINE_TEST_GLOBALS();

/* Seams: a failing open, a vanished entry and a failing getdents cannot be provoked from
 * outside, so the test forces each in turn. */
static int g_fail_open_for = 0;        /**< 1: /proc/self/fd, 2: /proc, 3: a process. */
static int g_fail_readlink = 0;        /**< Non-zero: every link read fails. */
static int g_fail_getdents_after = -1; /**< >= 0: fail a directory read after this many. */
static int chaos_net_test_owner_open(const char *path);
static ssize_t chaos_net_test_owner_readlink(int dir_fd, const char *name, char *out, size_t size);
static long chaos_net_test_owner_getdents(int fd, void *buffer, size_t size);
#define CHAOS_NET_OWNER_OPEN(path) chaos_net_test_owner_open(path)
#define CHAOS_NET_OWNER_READLINK(dir_fd, name, out, size)                                          \
    chaos_net_test_owner_readlink((dir_fd), (name), (out), (size))
#define CHAOS_NET_OWNER_GETDENTS(fd, buffer, size)                                                 \
    chaos_net_test_owner_getdents((fd), (buffer), (size))

#include "../../src/net/chaos_net_owner.c"

/** @brief Opens @p path unless this kind of directory is armed to fail. */
static int chaos_net_test_owner_open(const char *path)
{
    const int kind = strcmp(path, "/proc/self/fd") == 0 ? 1 : (strcmp(path, "/proc") == 0 ? 2 : 3);

    if (g_fail_open_for == kind)
    {
        errno = kind == 3 ? EACCES : ENOTDIR;
        return -1;
    }
    return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

/** @brief Reads the link unless armed to fail, which models an entry that vanished. */
static ssize_t chaos_net_test_owner_readlink(int dir_fd, const char *name, char *out, size_t size)
{
    if (g_fail_readlink != 0)
    {
        errno = ENOENT;
        return -1;
    }
    return readlinkat(dir_fd, name, out, size);
}

/** @brief Reads directory entries unless armed to fail once. */
static long chaos_net_test_owner_getdents(int fd, void *buffer, size_t size)
{
    if (g_fail_getdents_after == 0)
    {
        g_fail_getdents_after = -1;
        errno = EIO;
        return -1;
    }
    if (g_fail_getdents_after > 0)
    {
        --g_fail_getdents_after;
    }
    return (long)syscall(SYS_getdents64, fd, buffer, size);
}

/** @brief A datagram socket, or -1. */
static int open_socket(void)
{
    return socket(AF_INET, SOCK_DGRAM, 0);
}

/** @brief Proves the scan tells a sole owner from a shared one. */
static void test_ownership_of_a_socket(void)
{
    const int sock = open_socket();
    int copy;

    assert(sock >= 0);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SOLE);

    /* A dup in this process is a second link to the same inode. */
    copy = dup(sock);
    assert(copy >= 0);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SHARED);
    assert(chaos_net_socket_ownership(copy) == CHAOS_NET_OWNER_SHARED);
    assert(close(copy) == 0);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SOLE);

    assert(close(sock) == 0);
}

/** @brief Proves a holder in another process is found, and forgotten once it ends. */
static void test_ownership_across_a_fork(void)
{
    const int sock = open_socket();
    int ready[2];
    pid_t child;
    char token = 0;

    assert(sock >= 0);
    assert(pipe(ready) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0)
    {
        /* The child inherits the socket; it reports itself and then waits to be killed. */
        if (write(ready[1], "x", 1U) != 1)
        {
            _exit(1);
        }
        for (;;)
        {
            (void)pause();
        }
    }
    assert(close(ready[1]) == 0);
    assert(read(ready[0], &token, 1U) == 1);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SHARED);

    assert(kill(child, SIGKILL) == 0);
    assert(waitpid(child, NULL, 0) == child);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SOLE);

    assert(close(ready[0]) == 0);
    assert(close(sock) == 0);
}

/** @brief Proves anything the scan cannot account for answers UNKNOWN, never SOLE. */
static void test_ownership_of_a_non_socket(void)
{
    const int file = open("/dev/null", O_RDONLY);
    const int sock = open_socket();

    assert(file >= 0 && sock >= 0);
    /* Its link does not read socket:[...], so the scan never finds its own descriptor. */
    assert(chaos_net_socket_ownership(file) == CHAOS_NET_OWNER_UNKNOWN);
    assert(close(file) == 0);

    /* A closed descriptor cannot be stat'ed. */
    assert(close(sock) == 0);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    assert(chaos_net_socket_ownership(-1) == CHAOS_NET_OWNER_UNKNOWN);
}

/**
 * @brief Proves every way the scan can fail answers UNKNOWN rather than SOLE.
 *
 * @details A wrong "sole owner" is what leaves SO_LINGER behind on a socket that outlives
 * the close, so each failure has to be conservative: an unreadable descriptor directory,
 * an unreadable /proc, a process that cannot be read, a link that cannot be resolved and a
 * directory read that breaks off. A process that ended between the listing and the open is
 * the one exception: it holds nothing, so it is skipped rather than counted.
 */
static void test_unreadable_answers_unknown(void)
{
    const int sock = open_socket();

    assert(sock >= 0);
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SOLE);

    g_fail_open_for = 1; /* /proc/self/fd */
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_open_for = 2; /* /proc */
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_open_for = 3; /* another process, EACCES rather than ENOENT */
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_open_for = 0;

    /* Links that cannot be read leave the own descriptor unaccounted for. */
    g_fail_readlink = 1;
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_readlink = 0;

    /* A directory read that breaks off mid-way is not a complete answer: once while
     * reading this process's descriptors, once while walking /proc. The descriptor scan
     * takes two reads (entries, then the end), so the second failure comes later. */
    g_fail_getdents_after = 0;
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_getdents_after = 2;
    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_UNKNOWN);
    g_fail_getdents_after = -1;

    assert(chaos_net_socket_ownership(sock) == CHAOS_NET_OWNER_SOLE);
    assert(close(sock) == 0);
}

int main(void)
{
    test_ownership_of_a_socket();
    test_unreadable_answers_unknown();
    test_ownership_across_a_fork();
    test_ownership_of_a_non_socket();
    return 0;
}
