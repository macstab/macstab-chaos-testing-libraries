/**
 * @file chaos_net_socket.c
 * @brief Wrappers for the connection lifecycle, send, receive and the generic descriptor
 *        calls on sockets (read, write, readv, writev, close).
 *
 * @details
 * Exported wrappers: bind, listen, connect, accept, accept4 (Linux); send, sendto,
 * sendmsg; recv, recvfrom, recvmsg; read, readv, write, writev, close; and on glibc the
 * fortified __recv_chk, __recvfrom_chk, __read_chk, __poll_chk, __ppoll_chk.
 *
 * Every wrapper follows the same shape:
 *   1. chaos_net_ensure_symbols(), then the guard: a call from inside the library goes
 *      straight to the real function.
 *   2. Resolve the endpoint (sockaddr argument, getsockname, getpeername). A call whose
 *      endpoint does not resolve (not a socket, unsupported family or type) is forwarded
 *      untouched.
 *   3. Match the active snapshot; apply pre-call effects (LATENCY, ERRNO), make the real
 *      call, apply post-call effects (CORRUPT; DUP and TRICKLE reshape the receive).
 * While no rule is active, step 2 is skipped for the connected-socket and descriptor
 * paths, so an idle library costs one throttled check per call.
 *
 * @par Which end a rule names:
 *   A rule names an address. On a connected socket a client's rule names its server (the
 *   peer), a server's rule its own port (the local end), so send and receive rules match
 *   either end (chaos_net_match_connected()); on equal specificity receives prefer the
 *   local end, sends the peer. sendto/sendmsg with a destination match that address only.
 *
 * @par accept / accept4:
 *   Their sockaddr is an output, uninitialised before the call; the endpoint is the
 *   listening socket's local address, i.e. the server's port.
 *
 * @par read, write and close:
 *   Also wrapped by libchaos-io. Each library acts only on its own kind of descriptor
 *   (here: sockets, recognised by a successful endpoint lookup) and always forwards to
 *   the next definition (RTLD_NEXT), so every library sees every call in either preload
 *   order. read/readv count as `recv`, write/writev as `send`.
 *
 * @par Post-call bounds:
 *   CORRUPT touches only bytes the kernel actually wrote: chaos_net_received_bytes() caps
 *   a MSG_TRUNC datagram length at the buffer and treats a MSG_TRUNC stream receive (which
 *   discards data) as writing nothing. DUP bypasses MSG_TRUNC receives altogether.
 *
 * @par Fork:
 *   The DUP slot table survives fork(); an atfork handler releases slot locks held by
 *   parent threads. vfork() children share the table and run no handler.
 *
 * @par Test seams:
 *   CHAOS_NET_DUP_MAP/UNMAP, CHAOS_NET_DUP_BEFORE_TAG, CHAOS_NET_DUP_SOCKET,
 *   CHAOS_NET_SOCKET_TYPE, g_chaos_net_chk_fail.
 *
 * @par Module: chaos-net
 * @par Stability: private / internal
 */

#include "chaos_net_actions.h"
#include "chaos_net_config.h"
#include "chaos_net_endpoint.h"
#include "chaos_net_internal.h"

#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/**
 * @brief Flips one bit of a scatter list, treating its first @p size bytes as one buffer.
 *
 * @details The byte is `index_sample % size` over the concatenated segments, the bit
 * `bit_sample & 7`; the segment holding that byte is found by walking the list. The
 * vector counterpart of chaos_net_corrupt_buffer(), for recvmsg and readv.
 *
 * @param iov     Scatter list the kernel filled; NULL is a no-op.
 * @param iovcnt  Entries in @p iov; <= 0 is a no-op.
 * @param size    Bytes received, already capped at the vector's capacity; 0 is a no-op.
 * @par Thread-safety: advances the calling thread's PRNG by two steps.
 */
static void chaos_net_corrupt_iovecs(const struct iovec *iov, int iovcnt, size_t size)
{
    uint32_t index_sample;
    uint32_t bit_sample;
    size_t remaining = size;
    size_t index;
    int entry;

    if (iov == NULL || iovcnt <= 0 || size == 0U)
    {
        return;
    }

    index_sample = chaos_net_prng_next_u32();
    bit_sample = chaos_net_prng_next_u32();
    index = (size_t)(index_sample % size);
    for (entry = 0; entry < iovcnt && remaining > 0U; ++entry)
    {
        size_t segment_len = iov[entry].iov_len;

        if (segment_len > remaining)
        {
            segment_len = remaining;
        }
        if (index < segment_len)
        {
            /* The target byte is in this segment. */
            chaos_net_corrupt_buffer_sample(
                iov[entry].iov_base, segment_len, (uint32_t)index, bit_sample
            );
            return;
        }

        if (segment_len > 0U)
        {
            /* Step past this segment. */
            index -= segment_len;
            remaining -= segment_len;
        }
    }
}

/*---------------------------------------------------------------------------
 * Calls to the real functions
 *
 * Each helper sets the reentrancy guard, calls the real function and restores the
 * guard, so the wrappers stay free of guard boilerplate. A pointer still NULL (a call
 * that arrives during symbol resolution: a signal handler, or an allocator doing I/O
 * inside dlsym) is served by the system call itself. amd64 and arm64 lack send, recv
 * and (arm64) several wait calls, so those fall back to their general forms.
 *---------------------------------------------------------------------------*/

/**
 * @brief Calls the real bind(2) with the guard set; SYS_bind before resolution.
 */
static int
chaos_net_call_real_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    if (g_chaos_net_real_bind == NULL)
    {
        /* Not resolved yet: a call from inside the symbol lookup (a signal handler, or
         * an allocator that does I/O while dlsym runs). The system call does what libc
         * would. */
        return (int)syscall(SYS_bind, sockfd, address, address_length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_bind(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real listen(2) with the guard set; SYS_listen before resolution.
 */
static int chaos_net_call_real_listen(int sockfd, int backlog)
{
    int previous;
    int result;

    if (g_chaos_net_real_listen == NULL)
    {
        return (int)syscall(SYS_listen, sockfd, backlog);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_listen(sockfd, backlog);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real connect(2) with the guard set; SYS_connect before resolution.
 */
static int
chaos_net_call_real_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    if (g_chaos_net_real_connect == NULL)
    {
        return (int)syscall(SYS_connect, sockfd, address, address_length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_connect(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real accept(2) with the guard set; SYS_accept before resolution.
 */
static int
chaos_net_call_real_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    int previous;
    int result;

    if (g_chaos_net_real_accept == NULL)
    {
        return (int)syscall(SYS_accept, sockfd, address, address_length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

#ifdef __linux__
/**
 * @brief Calls the real accept4(2) with the guard set; SYS_accept4 before resolution.
 */
static int chaos_net_call_real_accept4(
    int sockfd, struct sockaddr *address, socklen_t *address_length, int flags
)
{
    int previous;
    int result;

    if (g_chaos_net_real_accept4 == NULL)
    {
        return (int)syscall(SYS_accept4, sockfd, address, address_length, flags);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept4(sockfd, address, address_length, flags);
    chaos_net_leave_internal(previous);
    return result;
}
#endif

/**
 * @brief Calls the real send(2) with the guard set; SYS_sendto before resolution.
 */
static ssize_t chaos_net_call_real_send(int sockfd, const void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_send == NULL)
    {
        /* Neither amd64 nor arm64 has a send system call: sendto without an address. */
        return (ssize_t)syscall(SYS_sendto, sockfd, buffer, size, flags, NULL, (socklen_t)0);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_send(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendto(2) with the guard set; SYS_sendto before resolution.
 */
static ssize_t chaos_net_call_real_sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    const struct sockaddr *address,
    socklen_t address_length
)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_sendto == NULL)
    {
        return (ssize_t)syscall(SYS_sendto, sockfd, buffer, size, flags, address, address_length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendto(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendmsg(2) with the guard set; SYS_sendmsg before resolution.
 */
static ssize_t chaos_net_call_real_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_sendmsg == NULL)
    {
        return (ssize_t)syscall(SYS_sendmsg, sockfd, message, flags);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recv(2) with the guard set; SYS_recvfrom before resolution.
 */
static ssize_t chaos_net_call_real_recv(int sockfd, void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_recv == NULL)
    {
        /* Neither amd64 nor arm64 has a recv system call: recvfrom without an address. */
        return (ssize_t)syscall(SYS_recvfrom, sockfd, buffer, size, flags, NULL, NULL);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recv(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvfrom(2) with the guard set; SYS_recvfrom before resolution.
 */
static ssize_t chaos_net_call_real_recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    struct sockaddr *address,
    socklen_t *address_length
)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_recvfrom == NULL)
    {
        return (ssize_t)syscall(SYS_recvfrom, sockfd, buffer, size, flags, address, address_length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvfrom(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvmsg(2) with the guard set; SYS_recvmsg before resolution.
 */
static ssize_t chaos_net_call_real_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_recvmsg == NULL)
    {
        return (ssize_t)syscall(SYS_recvmsg, sockfd, message, flags);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/*---------------------------------------------------------------------------
 * Pre-call effects
 *---------------------------------------------------------------------------*/

/**
 * @brief Applies the pre-call effects LATENCY and ERRNO.
 *
 * @details Used by every wrapper whose operation has no post-call effect: bind, listen,
 * connect, accept, accept4, send, sendto, sendmsg, write, writev. Any other effect is
 * ignored here.
 *
 * @param rule  Matched rule copy; NULL yields 0.
 * @return 0 to make the real call (after any delay); -1 to return -1 at once, errno set.
 */
static int chaos_net_apply_pre_call_rule(const chaos_net_rule_t *rule)
{
    if (rule == NULL)
    {
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(rule);
        return 0;
    }
    if (rule->effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(rule))
    {
        return -1;
    }
    return 0;
}

/*---------------------------------------------------------------------------
 * Wrappers: connection lifecycle and send
 *---------------------------------------------------------------------------*/

/**
 * @brief bind(2) wrapper: BIND rules on the address being bound.
 *
 * @details Endpoint from the sockaddr argument plus SO_TYPE. Unresolvable endpoint or no
 * matching rule: forwarded unchanged. The CHAOS_NET_*SOCKADDR* macros absorb glibc's
 * transparent-union parameter.
 */
CHAOS_NET_EXPORT int
bind(int sockfd, CHAOS_NET_CONST_SOCKADDR_PARAM address, socklen_t address_length)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_BIND, &endpoint, &rule))
    {
        return chaos_net_call_real_bind(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_bind(sockfd, address_ptr, address_length);
}

/**
 * @brief listen(2) wrapper: LISTEN rules on the socket's bound address.
 *
 * @details listen() has no address argument; getsockname reports what bind() set, which
 * is what a rule for "the server on port 8080" names.
 */
CHAOS_NET_EXPORT int listen(int sockfd, int backlog)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_LISTEN, &endpoint, &rule))
    {
        return chaos_net_call_real_listen(sockfd, backlog);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_listen(sockfd, backlog);
}

/**
 * @brief connect(2) wrapper: CONNECT rules on the destination address.
 *
 * @details Endpoint from the destination sockaddr plus SO_TYPE, e.g.
 * `tcp4://10.0.0.1:6379 : connect : ECONNREFUSED : 1.0`. An ERRNO firing never reaches
 * the kernel: no SYN is sent and the socket stays unconnected.
 */
CHAOS_NET_EXPORT int
connect(int sockfd, CHAOS_NET_CONST_SOCKADDR_PARAM address, socklen_t address_length)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() ||
        !chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_CONNECT, &endpoint, &rule))
    {
        return chaos_net_call_real_connect(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_connect(sockfd, address_ptr, address_length);
}

/**
 * @brief accept(2) wrapper: ACCEPT rules on the listening socket's local address.
 *
 * @details The sockaddr argument is an output, uninitialised on entry; the listening
 * port is what a rule names. An ERRNO firing leaves the pending connection queued.
 */
CHAOS_NET_EXPORT int accept(int sockfd, CHAOS_NET_SOCKADDR_PARAM address, socklen_t *address_length)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_ACCEPT, &endpoint, &rule))
    {
        return chaos_net_call_real_accept(sockfd, address_ptr, address_length);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_accept(sockfd, address_ptr, address_length);
}

#ifdef __linux__
/**
 * @brief accept4(2) wrapper (Linux): as accept(); @p flags is forwarded unchanged.
 */
CHAOS_NET_EXPORT int
accept4(int sockfd, CHAOS_NET_SOCKADDR_PARAM address, socklen_t *address_length, int flags)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_endpoint_from_local_fd(sockfd, &endpoint) ||
        !chaos_net_config_match_endpoint(CHAOS_NET_OP_ACCEPT, &endpoint, &rule))
    {
        return chaos_net_call_real_accept4(sockfd, address_ptr, address_length, flags);
    }

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_accept4(sockfd, address_ptr, address_length, flags);
}
#endif

/*---------------------------------------------------------------------------
 * DUP: deliver a socket's previous payload once more
 *---------------------------------------------------------------------------*/

/** @brief Sockets whose last payload can be kept at once (slots indexed by fd % 64). */
#define CHAOS_NET_DUP_SLOTS 64

/** @brief Longest kept payload in bytes; a longer stream payload is kept truncated. */
#define CHAOS_NET_DUP_MAX_BYTES 4096U

/**
 * @brief The last payload received on one socket, kept for a DUP rule.
 *
 * @details Slot `fd % CHAOS_NET_DUP_SLOTS`, tagged with the descriptor and the socket's
 * identity (inode, device). A colliding descriptor overwrites the slot, so the older
 * payload is lost rather than replayed on the wrong socket. `lock` is a try-lock: nobody
 * waits for a slot.
 */
typedef struct chaos_net_dup_slot
{
    volatile int lock;
    volatile int fd;          /**< Owner of the stored payload; -1 when empty. */
    volatile unsigned closes; /**< Closes of descriptors in this slot, see dup_store(). */
    uint64_t socket;          /**< Identity of the socket the payload came from. */
    size_t length;
    socklen_t name_length; /**< Sender address length (datagrams); 0 when none. */
    struct sockaddr_storage name;
    unsigned char data[CHAOS_NET_DUP_MAX_BYTES];
} chaos_net_dup_slot_t;

/**
 * @brief Maps and unmaps the slot table with raw system calls, so libchaos-memory rules
 *        on mmap cannot decide whether libchaos-net keeps a payload.
 *
 * @details Test seam: unit tests define these before including this file to make the
 * mapping fail or lose the publication race to another thread.
 */
#ifndef CHAOS_NET_DUP_MAP
#ifdef __linux__
#define CHAOS_NET_DUP_MAP(size)                                                                    \
    ((void *)syscall(                                                                              \
        SYS_mmap, NULL, (size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0         \
    ))
#define CHAOS_NET_DUP_UNMAP(address, size) ((void)syscall(SYS_munmap, (address), (size)))
#else
#define CHAOS_NET_DUP_MAP(size)                                                                    \
    mmap(NULL, (size), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
#define CHAOS_NET_DUP_UNMAP(address, size) ((void)munmap((address), (size)))
#endif
#endif

/**
 * @brief Hook between a store's close check and its tag; a no-op in the library.
 *
 * @details Test seam: unit tests define it to close the descriptor exactly there, the
 * window a concurrent close() can hit.
 */
#ifndef CHAOS_NET_DUP_BEFORE_TAG
#define CHAOS_NET_DUP_BEFORE_TAG(fd) ((void)(fd))
#endif

/**
 * @brief Identity of the socket behind @p fd: inode XOR (device << 32); 0 if unknown.
 *
 * @details A descriptor number outlives its socket when it is closed or replaced where
 * libchaos-net does not see it (dup2(), fclose() of an fdopen() stream, a raw close
 * system call); the identity keeps a payload from replaying on a different socket that
 * reuses the number. errno is preserved. Test seam: CHAOS_NET_DUP_SOCKET.
 */
#ifndef CHAOS_NET_DUP_SOCKET
static uint64_t chaos_net_dup_socket(int fd)
{
    const int saved_errno = errno;
    struct stat info;
    uint64_t identity = 0U;

    if (fstat(fd, &info) == 0)
    {
        identity = (uint64_t)info.st_ino ^ ((uint64_t)info.st_dev << 32);
    }
    errno = saved_errno;
    return identity;
}
#define CHAOS_NET_DUP_SOCKET(fd) chaos_net_dup_socket(fd)
#endif

static int chaos_net_is_stream(int fd);

/** @brief The slot table, mapped at the first DUP receive; NULL before, or if mmap failed. */
static chaos_net_dup_slot_t *volatile g_chaos_net_dup_slots = NULL;

/**
 * @brief fork() child handler: releases slot locks held by parent threads.
 *
 * @details Those threads do not exist in the child; a lock they held would make its slot
 * skip DUP forever there. A vfork() child shares the table and runs no handler.
 */
static void chaos_net_dup_after_fork(void)
{
    chaos_net_dup_slot_t *table = g_chaos_net_dup_slots;
    int index;

    /* One slot spans more than a page: an unconditional store would fault every slot's
     * page in every child. */
    for (index = 0; index < CHAOS_NET_DUP_SLOTS; ++index)
    {
        CHAOS_STORE_IF_CHANGED(table[index].lock, 0);
    }
}

/**
 * @brief The slot table, mapped on first use: 64 slots of about 4.2 KiB, about 267 KiB.
 *
 * @details Raw mmap for the same reason as the libchaos-io fd cache: libchaos-memory
 * wraps mmap, and its rules must not decide whether libchaos-net can keep a payload.
 * Racing threads each map; the CAS loser unmaps its copy. The winner registers the
 * atfork handler. errno is preserved.
 *
 * @return The table, or NULL if mmap failed (DUP then never replays).
 */
static chaos_net_dup_slot_t *chaos_net_dup_table(void)
{
    const size_t size = sizeof(chaos_net_dup_slot_t) * (size_t)CHAOS_NET_DUP_SLOTS;
    chaos_net_dup_slot_t *table = g_chaos_net_dup_slots;
    void *mapped;
    int index;

    if (table != NULL)
    {
        return table;
    }
    {
        /* The library's own allocation: a failure must not show in the caller's errno. */
        const int saved_errno = errno;

        mapped = CHAOS_NET_DUP_MAP(size);
        errno = saved_errno;
    }
    if (mapped == MAP_FAILED)
    {
        return NULL;
    }
    table = (chaos_net_dup_slot_t *)mapped;
    for (index = 0; index < CHAOS_NET_DUP_SLOTS; ++index)
    {
        table[index].fd = -1;
    }
    if (!__sync_bool_compare_and_swap(&g_chaos_net_dup_slots, NULL, table))
    {
        CHAOS_NET_DUP_UNMAP(mapped, size);
    }
    else
    {
        /* Registered once, by the thread whose table was published. */
        (void)pthread_atfork(NULL, NULL, chaos_net_dup_after_fork);
    }
    return g_chaos_net_dup_slots;
}

/**
 * @brief Try-locks the slot of @p fd; NULL if the table is absent or the slot is busy.
 *
 * @param create  Non-zero maps the table if needed (store path); 0 only uses an existing
 *                one (replay path).
 */
static chaos_net_dup_slot_t *chaos_net_dup_lock(int fd, int create)
{
    chaos_net_dup_slot_t *table = create ? chaos_net_dup_table() : g_chaos_net_dup_slots;
    chaos_net_dup_slot_t *slot;

    if (table == NULL || fd < 0)
    {
        return NULL;
    }
    slot = &table[fd % CHAOS_NET_DUP_SLOTS];
    /* Never wait: the holder may be this very thread, interrupted by a signal handler
     * that receives or closes. A busy slot skips DUP for this call. */
    if (__sync_lock_test_and_set(&slot->lock, 1) != 0)
    {
        return NULL;
    }
    return slot;
}

/** @brief Releases a slot taken with chaos_net_dup_lock(). */
static void chaos_net_dup_unlock(chaos_net_dup_slot_t *slot)
{
    __sync_lock_release(&slot->lock);
}

/**
 * @brief Close count of @p fd's slot, read before a receive whose payload is kept.
 *
 * @details Maps the table if needed; 0 without one (nothing is kept then). Compared
 * again by chaos_net_dup_store() to detect a close during the receive.
 */
static unsigned chaos_net_dup_generation(int fd)
{
    chaos_net_dup_slot_t *table = chaos_net_dup_table();

    if (table == NULL || fd < 0)
    {
        return 0U;
    }
    __sync_synchronize();
    return table[fd % CHAOS_NET_DUP_SLOTS].closes;
}

/**
 * @brief Keeps the @p received bytes the receive wrote into @p iov as @p fd's last payload.
 *
 * @details @p generation is the slot's close count from before the receive. If a
 * descriptor in this slot was closed since (another thread, while this one received), the
 * number may already name a new socket, and the payload is dropped instead of being
 * replayed there. A datagram longer than CHAOS_NET_DUP_MAX_BYTES is not kept: replayed
 * cut, it would be a different message. A stream payload is kept up to that size. The
 * datagram sender address is kept for recvfrom/recvmsg replays.
 */
static void chaos_net_dup_store(
    int fd,
    const struct iovec *iov,
    int iovcnt,
    ssize_t received,
    const struct sockaddr *name,
    socklen_t name_length,
    unsigned generation
)
{
    chaos_net_dup_slot_t *slot;
    uint64_t socket;
    size_t remaining;
    int index;

    if (received <= 0 || (socket = CHAOS_NET_DUP_SOCKET(fd)) == 0U)
    {
        return;
    }
    /* A datagram is one message: kept cut, it would replay as a different one. */
    if ((size_t)received > CHAOS_NET_DUP_MAX_BYTES && !chaos_net_is_stream(fd))
    {
        return;
    }
    slot = chaos_net_dup_lock(fd, 1);
    if (slot == NULL)
    {
        return;
    }
    if (slot->closes != generation)
    {
        chaos_net_dup_unlock(slot);
        return;
    }
    remaining =
        (size_t)received < CHAOS_NET_DUP_MAX_BYTES ? (size_t)received : CHAOS_NET_DUP_MAX_BYTES;
    slot->length = 0U;
    for (index = 0; index < iovcnt && remaining > 0U; ++index)
    {
        const size_t part = iov[index].iov_len < remaining ? iov[index].iov_len : remaining;

        if (part > 0U)
        {
            memcpy(slot->data + slot->length, iov[index].iov_base, part);
        }
        slot->length += part;
        remaining -= part;
    }
    slot->socket = socket;
    slot->name_length = 0;
    if (name != NULL && name_length > 0 && (size_t)name_length <= sizeof(slot->name))
    {
        memcpy(&slot->name, name, (size_t)name_length);
        slot->name_length = name_length;
    }
    CHAOS_NET_DUP_BEFORE_TAG(fd);
    slot->fd = fd;
    /* A close since the check above either saw the tag (and cleared it) or bumped the
     * count before this re-check, which then drops the payload. The slot lock is held, so
     * only a close can write the tag meanwhile, and it writes -1. */
    __sync_synchronize();
    if (slot->closes != generation)
    {
        slot->fd = -1;
    }
    chaos_net_dup_unlock(slot);
}

/**
 * @brief Delivers @p fd's kept payload again if the DUP rule fires.
 *
 * @details The payload must belong to this descriptor and to the same socket identity;
 * a stale one is discarded. The rule is asked only when a payload exists, so a hit means
 * a real duplicate. Each payload replays at most once (the slot is emptied), so the next
 * receive reads the socket again. The sender address is copied into @p name, truncated
 * to the caller's capacity, with the full length reported, as the kernel does.
 *
 * @param truncated  Output, may be NULL: 1 when the buffers held less than the payload
 *                   (recvmsg reports MSG_TRUNC for a datagram).
 * @return Bytes delivered, or -1 when nothing was replayed (no payload, busy slot, rule
 *         did not fire): the caller then receives normally.
 */
static ssize_t chaos_net_dup_replay(
    const chaos_net_rule_t *rule,
    int fd,
    const struct iovec *iov,
    int iovcnt,
    struct sockaddr *name,
    socklen_t *name_length,
    int *truncated
)
{
    chaos_net_dup_slot_t *slot = chaos_net_dup_lock(fd, 0);
    size_t delivered = 0U;
    int index;

    if (slot == NULL)
    {
        return -1;
    }
    if (slot->fd != fd)
    {
        chaos_net_dup_unlock(slot);
        return -1;
    }
    if (slot->socket != CHAOS_NET_DUP_SOCKET(fd))
    {
        /* The number names another socket now: its payload is not this one's. */
        slot->fd = -1;
        chaos_net_dup_unlock(slot);
        return -1;
    }
    if (!chaos_net_rule_should_trigger(rule))
    {
        chaos_net_dup_unlock(slot);
        return -1;
    }
    for (index = 0; index < iovcnt && delivered < slot->length; ++index)
    {
        const size_t left = slot->length - delivered;
        const size_t part = iov[index].iov_len < left ? iov[index].iov_len : left;

        if (part > 0U)
        {
            memcpy(iov[index].iov_base, slot->data + delivered, part);
        }
        delivered += part;
    }
    if (name != NULL && name_length != NULL)
    {
        const socklen_t copied =
            *name_length < slot->name_length ? *name_length : slot->name_length;

        memcpy(name, &slot->name, (size_t)copied);
        *name_length = slot->name_length;
    }
    if (truncated != NULL)
    {
        *truncated = delivered < slot->length;
    }
    slot->fd = -1;
    chaos_net_dup_unlock(slot);
    return (ssize_t)delivered;
}

/** @brief Drops @p fd's kept payload; called by close() before the real close. */
static void chaos_net_dup_forget(int fd)
{
    chaos_net_dup_slot_t *table = g_chaos_net_dup_slots;

    if (table == NULL || fd < 0)
    {
        return;
    }
    /* Lock-free: close() must not wait. The count goes first, so a store for this
     * descriptor in progress right now drops its payload itself. */
    (void)__sync_fetch_and_add(&table[fd % CHAOS_NET_DUP_SLOTS].closes, 1U);
    (void)__sync_bool_compare_and_swap(&table[fd % CHAOS_NET_DUP_SLOTS].fd, fd, -1);
}

/** @brief Receive flags that bypass DUP (the call is made for real, nothing is kept). */
#ifdef MSG_ERRQUEUE
#define CHAOS_NET_DUP_SKIP_FLAGS (MSG_PEEK | MSG_TRUNC | MSG_OOB | MSG_WAITALL | MSG_ERRQUEUE)
#else
#define CHAOS_NET_DUP_SKIP_FLAGS (MSG_PEEK | MSG_TRUNC | MSG_OOB | MSG_WAITALL)
#endif

/**
 * @brief Whether a receive of @p requested bytes with @p flags goes through DUP.
 *
 * @details Bypassed: MSG_PEEK (consumes nothing), MSG_TRUNC (may report more than the
 * buffer holds), MSG_OOB and MSG_ERRQUEUE (not the data stream), MSG_WAITALL (asks for
 * the whole buffer, which a shorter kept payload would not give). An empty or unknown-size
 * request is bypassed too: a replay into it would return 0, which reads as EOF.
 */
static int chaos_net_dups(const chaos_net_rule_t *rule, int flags, uint64_t requested)
{
    return rule->effect == CHAOS_NET_EFFECT_DUP && (flags & CHAOS_NET_DUP_SKIP_FLAGS) == 0 &&
           requested != 0U && requested != CHAOS_POLICY_NO_SIZE;
}

/** @brief Longest iovec array TRICKLE reshapes (stack copy); longer arrays are left alone. */
#define CHAOS_NET_TRICKLE_MAX_IOV 64

/**
 * @brief SO_TYPE of @p fd via a raw getsockopt system call; -1 when unknown.
 *
 * @details Raw so that no wrapper sees it; errno is preserved. Test seam:
 * CHAOS_NET_SOCKET_TYPE.
 */
#ifndef CHAOS_NET_SOCKET_TYPE
static int chaos_net_socket_type(int fd)
{
    const int saved_errno = errno;
    int type = -1;
    socklen_t length = (socklen_t)sizeof(type);

#ifdef __linux__
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0)
#else
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0)
#endif
    {
        type = -1;
    }
    errno = saved_errno;
    return type;
}
#define CHAOS_NET_SOCKET_TYPE(fd) chaos_net_socket_type(fd)
#endif

/**
 * @brief Whether @p fd is a stream socket.
 *
 * @details TRICKLE shortens only stream receives: on a datagram socket a shorter buffer
 * truncates the datagram and the kernel discards the rest.
 */
static int chaos_net_is_stream(int fd)
{
    return CHAOS_NET_SOCKET_TYPE(fd) == SOCK_STREAM;
}

/**
 * @brief Bytes of a @p size-byte buffer that a receive returning @p rc actually filled.
 *
 * @details With MSG_TRUNC, a datagram receive returns the full datagram length, which can
 * exceed the buffer, and a stream receive discards the data without writing the buffer.
 * CORRUPT must stay inside what was written.
 */
static size_t chaos_net_received_bytes(int fd, ssize_t rc, size_t size, int flags)
{
    if (rc <= 0 || ((flags & MSG_TRUNC) != 0 && chaos_net_is_stream(fd)))
    {
        return 0U;
    }
    return (size_t)rc < size ? (size_t)rc : size;
}

/**
 * @brief Whether a TRICKLE rule fires for a receive of @p requested bytes on @p fd.
 *
 * @details Only a stream socket and a request larger than the chunk are shortened, and
 * the rule is asked last, so a call TRICKLE leaves alone is not counted as a hit.
 * MSG_WAITALL asks for the whole count, which the kernel shortens only on a signal, an
 * error or end of stream; such a receive is left alone too.
 */
static int chaos_net_trickles(const chaos_net_rule_t *rule, int fd, uint64_t requested, int flags)
{
    return rule->effect == CHAOS_NET_EFFECT_TRICKLE && (flags & MSG_WAITALL) == 0 &&
           requested > rule->chunk_bytes && requested != CHAOS_POLICY_NO_SIZE &&
           chaos_net_is_stream(fd) && chaos_net_rule_should_trigger(rule);
}

/**
 * @brief Copies @p iov into @p out, cut to at most @p limit bytes; returns the entry count.
 *
 * @details TRICKLE for vectored receives: the kernel fills the shortened vector, so the
 * caller's buffers receive the first bytes exactly as a short read would deliver them.
 */
static int
chaos_net_limit_iovecs(const struct iovec *iov, int iovcnt, size_t limit, struct iovec *out)
{
    int count = 0;
    int index;

    for (index = 0; index < iovcnt && limit > 0U; ++index)
    {
        out[count] = iov[index];
        if (out[count].iov_len > limit)
        {
            out[count].iov_len = limit;
        }
        limit -= out[count].iov_len;
        ++count;
    }
    return count;
}

int chaos_net_match_connected(
    int fd, chaos_net_operation_t operation, int peer_first, chaos_net_rule_t *rule
)
{
    chaos_net_endpoint_t local;
    chaos_net_endpoint_t peer;
    int have_local;
    int have_peer;
    int not_socket;

    /* No rule for this operation: nothing can match, so no endpoint is looked up. */
    if (!chaos_net_config_prepare() || !chaos_net_config_targets_loaded(operation))
    {
        return 0;
    }
    /* The preferred end first; the other end costs another system call and is resolved
     * only when a rule could still outrank the preferred end's match there, and never for
     * a descriptor the first lookup showed is not a socket (read and write on files). */
    if (peer_first)
    {
        have_peer = chaos_net_endpoint_from_end_fd(fd, 1, &peer, &not_socket);
        if (not_socket ||
            (have_peer && chaos_net_config_match_final_loaded(operation, &peer, rule)))
        {
            return !not_socket;
        }
        have_local = chaos_net_endpoint_from_local_fd(fd, &local);
    }
    else
    {
        have_local = chaos_net_endpoint_from_end_fd(fd, 0, &local, &not_socket);
        if (not_socket ||
            (have_local && chaos_net_config_match_final_loaded(operation, &local, rule)))
        {
            return !not_socket;
        }
        have_peer = chaos_net_endpoint_from_peer_fd(fd, &peer);
    }
    return peer_first ? chaos_net_config_match_either_loaded(
                            operation, have_peer ? &peer : NULL, have_local ? &local : NULL, rule
                        )
                      : chaos_net_config_match_either_loaded(
                            operation, have_local ? &local : NULL, have_peer ? &peer : NULL, rule
                        );
}

/**
 * @brief send(2) wrapper: SEND rules on either end of the connection.
 *
 * @details send() has no destination argument; chaos_net_match_connected() searches both
 * ends of the connection, the peer winning ties. `@size` sees @p size.
 */
CHAOS_NET_EXPORT ssize_t send(int sockfd, const void *buffer, size_t size, int flags)
{
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule))
    {
        return chaos_net_call_real_send(sockfd, buffer, size, flags);
    }
    rule.call_size = (uint64_t)size;

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_send(sockfd, buffer, size, flags);
}

/**
 * @brief sendto(2) wrapper: SEND rules on the destination, or on the connection.
 *
 * @details With a destination (typical for UDP), that address alone is matched. Without
 * one (connected mode, sendto used as send), chaos_net_match_connected() searches both
 * ends, the peer winning ties. `@size` sees @p size.
 */
CHAOS_NET_EXPORT ssize_t sendto(
    int sockfd,
    const void *buffer,
    size_t size,
    int flags,
    CHAOS_NET_CONST_SOCKADDR_PARAM address,
    socklen_t address_length
)
{
    const struct sockaddr *address_ptr = CHAOS_NET_CONST_SOCKADDR_VALUE(address);
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int matched;

    chaos_net_ensure_symbols();

    /* Match the explicit destination if there is one, else the connection. A call from
     * inside the library is not looked at. */
    matched = !chaos_net_in_internal() &&
              (address_ptr != NULL
                   ? chaos_net_endpoint_from_sockaddr_fd(
                         sockfd, address_ptr, address_length, &endpoint
                     ) && chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule)
                   : chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule));
    if (!matched)
    {
        return chaos_net_call_real_sendto(sockfd, buffer, size, flags, address_ptr, address_length);
    }
    rule.call_size = (uint64_t)size;

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_sendto(sockfd, buffer, size, flags, address_ptr, address_length);
}

/**
 * @brief sendmsg(2) wrapper: SEND rules on msg_name, or on the connection.
 *
 * @details As sendto(): msg_name when present, else chaos_net_match_connected(). `@size`
 * sees the iovec total, or no size for an invalid vector.
 */
CHAOS_NET_EXPORT ssize_t sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int matched;

    chaos_net_ensure_symbols();

    matched = !chaos_net_in_internal() &&
              (message != NULL && message->msg_name != NULL
                   ? chaos_net_endpoint_from_sockaddr_fd(
                         sockfd,
                         (const struct sockaddr *)message->msg_name,
                         (socklen_t)message->msg_namelen,
                         &endpoint
                     ) && chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule)
                   : chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule));
    if (!matched)
    {
        return chaos_net_call_real_sendmsg(sockfd, message, flags);
    }
    rule.call_size = chaos_net_message_size(message);

    if (chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_sendmsg(sockfd, message, flags);
}

/**
 * @brief recv(2) wrapper: RECV rules on either end of the connection.
 *
 * @details chaos_net_match_connected() searches both ends, the local end winning ties.
 * Order of effects: LATENCY or ERRNO before the call; then DUP (replay, or receive and keep);
 * else TRICKLE (shorten the request); then the real call; then CORRUPT within the bytes
 * the buffer actually holds. EOF (0) and errors (-1) are never corrupted.
 */
CHAOS_NET_EXPORT ssize_t recv(int sockfd, void *buffer, size_t size, int flags)
{
    chaos_net_rule_t rule;
    ssize_t rc;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_match_connected(sockfd, CHAOS_NET_OP_RECV, 0, &rule))
    {
        return chaos_net_call_real_recv(sockfd, buffer, size, flags);
    }
    rule.call_size = (uint64_t)size;

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    if (buffer != NULL && chaos_net_dups(&rule, flags, (uint64_t)size))
    {
        struct iovec target;

        target.iov_base = buffer;
        target.iov_len = size;
        rc = chaos_net_dup_replay(&rule, sockfd, &target, 1, NULL, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(sockfd);

            rc = chaos_net_call_real_recv(sockfd, buffer, size, flags);
            chaos_net_dup_store(sockfd, &target, 1, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (chaos_net_trickles(&rule, sockfd, (uint64_t)size, flags))
    {
        size = rule.chunk_bytes;
    }
    rc = chaos_net_call_real_recv(sockfd, buffer, size, flags);
    /* Corrupt only received bytes that are inside the buffer. */
    if (rule.effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        const size_t filled = chaos_net_received_bytes(sockfd, rc, size, flags);

        if (filled > 0U && chaos_net_rule_should_trigger(&rule))
        {
            chaos_net_corrupt_buffer(buffer, filled);
        }
    }
    return rc;
}

/**
 * @brief recvfrom(2) wrapper: as recv(); the sender address is passed through, and kept
 *        and replayed by DUP.
 *
 * @details A DUP replay copies the kept sender address into @p address, truncated to the
 * caller's capacity, and reports its full length, as the kernel does.
 */
CHAOS_NET_EXPORT ssize_t recvfrom(
    int sockfd,
    void *buffer,
    size_t size,
    int flags,
    CHAOS_NET_SOCKADDR_PARAM address,
    socklen_t *address_length
)
{
    struct sockaddr *address_ptr = CHAOS_NET_SOCKADDR_VALUE(address);
    chaos_net_rule_t rule;
    ssize_t rc;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_match_connected(sockfd, CHAOS_NET_OP_RECV, 0, &rule))
    {
        return chaos_net_call_real_recvfrom(
            sockfd, buffer, size, flags, address_ptr, address_length
        );
    }
    rule.call_size = (uint64_t)size;

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    if (chaos_net_trickles(&rule, sockfd, (uint64_t)size, flags))
    {
        size = rule.chunk_bytes;
    }
    if (buffer != NULL && chaos_net_dups(&rule, flags, (uint64_t)size))
    {
        struct iovec target;

        const socklen_t capacity = address_length != NULL ? *address_length : 0;

        target.iov_base = buffer;
        target.iov_len = size;
        rc = chaos_net_dup_replay(&rule, sockfd, &target, 1, address_ptr, address_length, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(sockfd);

            rc = chaos_net_call_real_recvfrom(
                sockfd, buffer, size, flags, address_ptr, address_length
            );
            chaos_net_dup_store(
                sockfd,
                &target,
                1,
                rc,
                address_ptr,
                /* The kernel reports the full address length even when it cut the address
                 * to fit the caller's buffer: keep only what was written. */
                address_ptr != NULL && address_length != NULL
                    ? (*address_length < capacity ? *address_length : capacity)
                    : 0,
                generation
            );
        }
        return rc;
    }
    rc = chaos_net_call_real_recvfrom(sockfd, buffer, size, flags, address_ptr, address_length);
    if (rule.effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        const size_t filled = chaos_net_received_bytes(sockfd, rc, size, flags);

        if (filled > 0U && chaos_net_rule_should_trigger(&rule))
        {
            chaos_net_corrupt_buffer(buffer, filled);
        }
    }
    return rc;
}

/**
 * @brief recvmsg(2) wrapper: as recv(), on a scatter list.
 *
 * @details CORRUPT uses chaos_net_corrupt_iovecs() within the bytes the vector holds.
 * TRICKLE copies at most CHAOS_NET_TRICKLE_MAX_IOV entries into a shortened vector and
 * copies the kernel's msg_namelen, msg_controllen and msg_flags back. A DUP replay sets
 * msg_controllen to 0 (no ancillary data is kept) and MSG_TRUNC for a datagram that did
 * not fit.
 */
CHAOS_NET_EXPORT ssize_t recvmsg(int sockfd, struct msghdr *message, int flags)
{
    chaos_net_rule_t rule;
    ssize_t rc;

    chaos_net_ensure_symbols();

    if (chaos_net_in_internal() || !chaos_net_match_connected(sockfd, CHAOS_NET_OP_RECV, 0, &rule))
    {
        return chaos_net_call_real_recvmsg(sockfd, message, flags);
    }
    rule.call_size = chaos_net_message_size(message);

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    if (message != NULL && chaos_net_dups(&rule, flags, chaos_net_message_size(message)))
    {
        const socklen_t capacity = message->msg_namelen;
        socklen_t name_length = message->msg_namelen;
        int truncated = 0;

        rc = chaos_net_dup_replay(
            &rule,
            sockfd,
            message->msg_iov,
            (int)message->msg_iovlen,
            (struct sockaddr *)message->msg_name,
            &name_length,
            &truncated
        );
        if (rc >= 0)
        {
            message->msg_namelen = message->msg_name != NULL ? name_length : 0;
            message->msg_controllen = 0;
            /* A datagram that did not fit is reported cut, as the kernel does. */
            message->msg_flags = truncated && !chaos_net_is_stream(sockfd) ? MSG_TRUNC : 0;
            return rc;
        }
        {
            const unsigned generation = chaos_net_dup_generation(sockfd);
            socklen_t kept;

            rc = chaos_net_call_real_recvmsg(sockfd, message, flags);
            kept = message->msg_name == NULL         ? 0
                   : message->msg_namelen < capacity ? message->msg_namelen
                                                     : capacity;
            chaos_net_dup_store(
                sockfd,
                message->msg_iov,
                (int)message->msg_iovlen,
                rc,
                (const struct sockaddr *)message->msg_name,
                kept,
                generation
            );
        }
        return rc;
    }
    if (message != NULL && (size_t)message->msg_iovlen <= (size_t)CHAOS_NET_TRICKLE_MAX_IOV &&
        chaos_net_trickles(&rule, sockfd, chaos_net_message_size(message), flags))
    {
        struct iovec limited[CHAOS_NET_TRICKLE_MAX_IOV];
        struct msghdr shortened = *message;

        shortened.msg_iov = limited;
        /* msg_iovlen is size_t on glibc and int on musl. */
        shortened.msg_iovlen = chaos_net_limit_iovecs(
            message->msg_iov, (int)message->msg_iovlen, rule.chunk_bytes, limited
        );
        rc = chaos_net_call_real_recvmsg(sockfd, &shortened, flags);
        /* The kernel reported these through the header it was given. */
        message->msg_namelen = shortened.msg_namelen;
        message->msg_controllen = shortened.msg_controllen;
        message->msg_flags = shortened.msg_flags;
        return rc;
    }
    rc = chaos_net_call_real_recvmsg(sockfd, message, flags);
    if (message != NULL && rule.effect == CHAOS_NET_EFFECT_CORRUPT)
    {
        /* With MSG_TRUNC rc can exceed the vector: aim inside what it holds. */
        const uint64_t capacity = chaos_net_message_size(message);
        const size_t filled = chaos_net_received_bytes(
            sockfd, rc, capacity == CHAOS_POLICY_NO_SIZE ? 0U : (size_t)capacity, flags
        );

        if (filled > 0U && chaos_net_rule_should_trigger(&rule))
        {
            chaos_net_corrupt_iovecs(message->msg_iov, (int)message->msg_iovlen, filled);
        }
    }
    return rc;
}

/* ---------------------------------------------------------------------------
 * glibc fortified entry points
 *
 * `_FORTIFY_SOURCE` builds call __recv_chk(), __recvfrom_chk(), __read_chk(),
 * __poll_chk() and __ppoll_chk() instead of the base functions when the buffer size is
 * known at compile time. Without these exports such calls would bypass the wrappers.
 * Each checks the size the way glibc does (__chk_fail() on overflow) and then calls the
 * wrapper. libchaos-io also exports __read_chk() for files; both forward to read(),
 * which reaches both libraries in either preload order. musl has no fortified variants.
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__)

extern void __chk_fail(void) __attribute__((__noreturn__));

/** @brief Overflow handler of the fortified variants; a test seam (tests observe it). */
static void (*g_chaos_net_chk_fail)(void) = __chk_fail;

/** @brief Fortified recv(): __chk_fail() when @p size exceeds @p buffer_size. */
CHAOS_NET_EXPORT ssize_t
__recv_chk(int sockfd, void *buffer, size_t size, size_t buffer_size, int flags)
{
    chaos_net_ensure_symbols();
    if (size > buffer_size)
    {
        g_chaos_net_chk_fail();
        return -1;
    }
    return recv(sockfd, buffer, size, flags);
}

/** @brief Fortified recvfrom(): __chk_fail() when @p size exceeds @p buffer_size. */
CHAOS_NET_EXPORT ssize_t __recvfrom_chk(
    int sockfd,
    void *buffer,
    size_t size,
    size_t buffer_size,
    int flags,
    CHAOS_NET_SOCKADDR_PARAM address,
    socklen_t *address_length
)
{
    chaos_net_ensure_symbols();
    if (size > buffer_size)
    {
        g_chaos_net_chk_fail();
        return -1;
    }
    return recvfrom(sockfd, buffer, size, flags, address, address_length);
}

/** @brief Fortified read(): __chk_fail() when @p size exceeds @p buffer_size. */
CHAOS_NET_EXPORT ssize_t __read_chk(int fd, void *buffer, size_t size, size_t buffer_size)
{
    chaos_net_ensure_symbols();
    if (size > buffer_size)
    {
        g_chaos_net_chk_fail();
        return -1;
    }
    return read(fd, buffer, size);
}

/** @brief Fortified poll(): __chk_fail() when @p nfds exceeds the array. */
CHAOS_NET_EXPORT int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fds_size)
{
    chaos_net_ensure_symbols();
    if (fds_size / sizeof(*fds) < nfds)
    {
        g_chaos_net_chk_fail();
        return -1;
    }
    return poll(fds, nfds, timeout);
}

/** @brief Fortified ppoll(): __chk_fail() when @p nfds exceeds the array. */
CHAOS_NET_EXPORT int __ppoll_chk(
    struct pollfd *fds,
    nfds_t nfds,
    const struct timespec *timeout,
    const sigset_t *mask,
    size_t fds_size
)
{
    chaos_net_ensure_symbols();
    if (fds_size / sizeof(*fds) < nfds)
    {
        g_chaos_net_chk_fail();
        return -1;
    }
    return ppoll(fds, nfds, timeout, mask);
}

#endif

/*---------------------------------------------------------------------------
 * Generic descriptor calls on sockets: read, write, readv, writev, close
 *
 * libchaos-io wraps the same symbols for files. Each library acts only on its own
 * kind of descriptor -- here sockets, recognised by an endpoint lookup that fails with
 * ENOTSOCK for anything else -- and always forwards to the next definition in the chain
 * (RTLD_NEXT), never straight to libc. Whichever library is preloaded first, a file
 * reaches libchaos-io's rules, a socket reaches these, and every library sees every
 * call.
 *
 * read/readv on a socket count as `recv`, write/writev as `send`, so
 * `tcp4://10.0.0.5:6379:recv:ECONNRESET:1.0` applies whichever call the program uses.
 * With no active rule the wrappers forward without any socket lookup.
 *---------------------------------------------------------------------------*/

/** @brief Calls the next read(2) in the chain with the guard set; SYS_read before resolution. */
static ssize_t chaos_net_call_real_read(int fd, void *buffer, size_t size)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_read == NULL)
    {
        return (ssize_t)syscall(SYS_read, fd, buffer, size);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_read(fd, buffer, size);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next write(2) with the guard set; SYS_write before resolution. */
static ssize_t chaos_net_call_real_write(int fd, const void *buffer, size_t size)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_write == NULL)
    {
        return (ssize_t)syscall(SYS_write, fd, buffer, size);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_write(fd, buffer, size);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next readv(2) with the guard set; SYS_readv before resolution. */
static ssize_t chaos_net_call_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_readv == NULL)
    {
        return (ssize_t)syscall(SYS_readv, fd, iov, iovcnt);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_readv(fd, iov, iovcnt);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next writev(2) with the guard set; SYS_writev before resolution. */
static ssize_t chaos_net_call_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    if (g_chaos_net_real_writev == NULL)
    {
        return (ssize_t)syscall(SYS_writev, fd, iov, iovcnt);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_writev(fd, iov, iovcnt);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next close(2) with the guard set; SYS_close before resolution. */
static int chaos_net_call_real_close(int fd)
{
    int previous;
    int result;

    if (g_chaos_net_real_close == NULL)
    {
        return (int)syscall(SYS_close, fd);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_close(fd);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the real setsockopt(2) with the guard set; used by RESET (not a wrapper). */
static int
chaos_net_call_real_setsockopt(int fd, int level, int name, const void *value, socklen_t length)
{
    int previous;
    int result;

    if (g_chaos_net_real_setsockopt == NULL)
    {
        return (int)syscall(SYS_setsockopt, fd, level, name, value, length);
    }
    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_setsockopt(fd, level, name, value, length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief The rule for a generic descriptor call, if @p fd is a socket.
 *
 * @details The snapshot is checked first, so with no active rule no socket lookup is
 * made. SEND and RECV match both ends of the connection (peer first for SEND); CLOSE
 * matches the local address, else the peer. A non-socket fails the lookup (ENOTSOCK,
 * errno preserved) and the call is not libchaos-net's.
 *
 * @param fd         Descriptor of the call.
 * @param operation  CHAOS_NET_OP_RECV, _SEND or _CLOSE.
 * @param size       Byte count for `@size`; CHAOS_POLICY_NO_SIZE when there is none.
 * @param rule       Output: the matching rule copy, with call_size set.
 * @return Non-zero when @p fd is a socket with a matching rule.
 */
static int chaos_net_match_descriptor_rule(
    int fd, chaos_net_operation_t operation, uint64_t size, chaos_net_rule_t *rule
)
{
    chaos_net_endpoint_t endpoint;
    int found;

    if (chaos_net_in_internal() || !chaos_net_config_prepare())
    {
        return 0;
    }
    if (operation == CHAOS_NET_OP_SEND || operation == CHAOS_NET_OP_RECV)
    {
        found = chaos_net_match_connected(fd, operation, operation == CHAOS_NET_OP_SEND, rule);
    }
    else
    {
        found = chaos_net_endpoint_from_activity_fd(fd, &endpoint) &&
                chaos_net_config_match_endpoint_loaded(operation, &endpoint, rule);
    }
    if (!found)
    {
        return 0;
    }
    rule->call_size = size;
    return 1;
}

/**
 * @brief read(2) wrapper: `recv` rules on sockets (with DUP, TRICKLE, CORRUPT); every
 *        other descriptor is forwarded.
 */
CHAOS_NET_EXPORT ssize_t read(int fd, void *buffer, size_t size)
{
    chaos_net_rule_t rule;
    ssize_t rc;

    chaos_net_ensure_symbols();
    if (!chaos_net_match_descriptor_rule(fd, CHAOS_NET_OP_RECV, (uint64_t)size, &rule))
    {
        return chaos_net_call_real_read(fd, buffer, size);
    }

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    if (buffer != NULL && chaos_net_dups(&rule, 0, (uint64_t)size))
    {
        struct iovec target;

        target.iov_base = buffer;
        target.iov_len = size;
        rc = chaos_net_dup_replay(&rule, fd, &target, 1, NULL, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(fd);

            rc = chaos_net_call_real_read(fd, buffer, size);
            chaos_net_dup_store(fd, &target, 1, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (chaos_net_trickles(&rule, fd, (uint64_t)size, 0))
    {
        size = rule.chunk_bytes;
    }
    rc = chaos_net_call_real_read(fd, buffer, size);
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_buffer(buffer, (size_t)rc);
    }
    return rc;
}

/**
 * @brief readv(2) wrapper: `recv` rules on sockets (with DUP, TRICKLE, CORRUPT); every
 *        other descriptor is forwarded.
 */
CHAOS_NET_EXPORT ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_net_rule_t rule;
    ssize_t rc;

    chaos_net_ensure_symbols();
    if (!chaos_net_match_descriptor_rule(
            fd, CHAOS_NET_OP_RECV, chaos_net_iovec_size(iov, iovcnt), &rule
        ))
    {
        return chaos_net_call_real_readv(fd, iov, iovcnt);
    }

    if (rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }

    if (chaos_net_dups(&rule, 0, chaos_net_iovec_size(iov, iovcnt)))
    {
        rc = chaos_net_dup_replay(&rule, fd, iov, iovcnt, NULL, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(fd);

            rc = chaos_net_call_real_readv(fd, iov, iovcnt);
            chaos_net_dup_store(fd, iov, iovcnt, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (iov != NULL && iovcnt > 0 && iovcnt <= CHAOS_NET_TRICKLE_MAX_IOV &&
        chaos_net_trickles(&rule, fd, chaos_net_iovec_size(iov, iovcnt), 0))
    {
        struct iovec limited[CHAOS_NET_TRICKLE_MAX_IOV];

        return chaos_net_call_real_readv(
            fd, limited, chaos_net_limit_iovecs(iov, iovcnt, rule.chunk_bytes, limited)
        );
    }
    rc = chaos_net_call_real_readv(fd, iov, iovcnt);
    if (rc > 0 && rule.effect == CHAOS_NET_EFFECT_CORRUPT && chaos_net_rule_should_trigger(&rule))
    {
        chaos_net_corrupt_iovecs(iov, iovcnt, (size_t)rc);
    }
    return rc;
}

/**
 * @brief write(2) wrapper: `send` rules (LATENCY, ERRNO) on sockets; everything else
 *        forwarded.
 */
CHAOS_NET_EXPORT ssize_t write(int fd, const void *buffer, size_t size)
{
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();
    if (chaos_net_match_descriptor_rule(fd, CHAOS_NET_OP_SEND, (uint64_t)size, &rule) &&
        chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_write(fd, buffer, size);
}

/**
 * @brief writev(2) wrapper: `send` rules (LATENCY, ERRNO) on sockets; everything else
 *        forwarded.
 */
CHAOS_NET_EXPORT ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    chaos_net_rule_t rule;

    chaos_net_ensure_symbols();
    if (chaos_net_match_descriptor_rule(
            fd, CHAOS_NET_OP_SEND, chaos_net_iovec_size(iov, iovcnt), &rule
        ) &&
        chaos_net_apply_pre_call_rule(&rule) != 0)
    {
        return -1;
    }
    return chaos_net_call_real_writev(fd, iov, iovcnt);
}

/**
 * @brief close(2) wrapper: `close` rules on sockets; every other descriptor forwarded.
 *
 * @details The endpoint is resolved before the descriptor goes away. Effects:
 *   - RESET: SO_LINGER {l_onoff 1, l_linger 0} before the close, so the kernel aborts the
 *     connection and the peer receives an RST (ECONNRESET) instead of a FIN: what a
 *     crashed or killed process, or a load balancer dropping a connection, looks like
 *     from the other side. A setsockopt failure is ignored, errno preserved.
 *   - LATENCY: delays the close.
 *   - ERRNO: closes first, then reports the error. Linux releases the descriptor even
 *     when close reports an error and programs never retry it, so a synthetic error that
 *     kept the descriptor open would leak it.
 * The close itself always goes through the chain, so a library that also wraps close
 * (libchaos-io keeps an fd cache) sees every call, and the DUP slot is forgotten first.
 */
CHAOS_NET_EXPORT int close(int fd)
{
    chaos_net_rule_t rule;
    struct linger abort_linger;
    int matched;
    int saved_errno;
    int rc;

    chaos_net_ensure_symbols();
    matched = chaos_net_match_descriptor_rule(fd, CHAOS_NET_OP_CLOSE, CHAOS_POLICY_NO_SIZE, &rule);
    if (matched && rule.effect == CHAOS_NET_EFFECT_LATENCY)
    {
        chaos_net_rule_apply_latency(&rule);
    }
    else if (matched && rule.effect == CHAOS_NET_EFFECT_RESET &&
             chaos_net_rule_should_trigger(&rule))
    {
        abort_linger.l_onoff = 1;
        abort_linger.l_linger = 0;
        saved_errno = errno;
        (void)chaos_net_call_real_setsockopt(
            fd, SOL_SOCKET, SO_LINGER, &abort_linger, (socklen_t)sizeof(abort_linger)
        );
        errno = saved_errno;
    }

    chaos_net_dup_forget(fd);
    rc = chaos_net_call_real_close(fd);
    if (matched && rule.effect == CHAOS_NET_EFFECT_ERRNO && chaos_net_rule_apply_errno(&rule))
    {
        return -1;
    }
    return rc;
}
