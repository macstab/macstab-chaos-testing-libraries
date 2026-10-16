/**
 * @file chaos_net_socket.c
 * @brief LD_PRELOAD interposition wrappers for connection-lifecycle and I/O socket syscalls.
 *
 * @details
 * This file provides the exported interposition symbols for:
 *   - Connection lifecycle: bind, listen, connect, accept, accept4 (Linux).
 *   - Send path: send, sendto, sendmsg.
 *   - Receive path: recv, recvfrom, recvmsg.
 *
 * Each wrapper follows an identical three-phase pattern:
 *   1. **Guard check**: if chaos_net_in_internal() is non-zero, the call originated
 *      from within libchaos-net itself (e.g., getsockname called during endpoint
 *      resolution). Fast-path directly to the real symbol.
 *   2. **Endpoint resolution**: translate the syscall arguments (sockaddr parameter
 *      or fd-based getsockname/getpeername) into a chaos_net_endpoint_t. If
 *      resolution fails (unsupported socket type, abstract UNIX path, etc.), the
 *      call is passed through without injection.
 *   3. **Rule matching and effect application**: look up the config rule for
 *      (operation, endpoint). Apply pre-call effects (latency, errno-injection)
 *      before the real call; apply post-call effects (corruption) after.
 *
 * @par accept / accept4 endpoint direction:
 * For accept and accept4, the sockaddr parameter is an *output* — it is filled in
 * by the kernel after the call and is uninitialised before it. Using the sockaddr
 * from the argument as a selector would read uninitialised memory. Instead, the
 * listening socket's local address (obtained via getsockname on @p sockfd) is used
 * as the matching endpoint. This is consistent with user intent: a rule saying
 * "inject on accept for port 8080" refers to the listening port, not the ephemeral
 * client port that only becomes known after the call.
 *
 * @par read() and write():
 * read, write, readv, writev and close are interposed too, and follow the recv,
 * send and close rules on sockets only; on anything else they are forwarded. On a
 * socket libchaos-io leaves them alone (its `*` rule matches files only).
 *
 * @par Which end a rule names:
 * A rule names an address. On a connected socket a client's rule names its server
 * (the peer), a server's rule its own port (the local end), so send and receive
 * rules are matched on either end (chaos_net_match_connected()): receives try the
 * local end first, sends the peer.
 *
 * @par Receive-side CORRUPT application:
 * Corruption is applied only when:
 *   - The real recv call returned a positive byte count (rc > 0).
 *   - The matched rule has effect == CORRUPT.
 *   - chaos_net_rule_should_trigger() fires (probability check).
 * Applying corruption to a return value of 0 (EOF) or -1 (error) is meaningless
 * and could write past the actual data in the buffer.
 *
 * @par sendto / sendmsg endpoint resolution:
 * These functions carry an optional explicit destination address. When present
 * (address_ptr != NULL for sendto, message->msg_name != NULL for sendmsg), the
 * destination address is used as the endpoint. When absent (connected-mode send),
 * getpeername is used to resolve the peer address. This matches how applications
 * use these calls: datagram sends include the destination; stream sends do not.
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
#ifdef __linux__
#include <sys/syscall.h>
#endif

/**
 * @brief Flips one bit in a scattered I/O vector using pre-drawn PRNG samples.
 *
 * @details Treats the iovec array as a logically contiguous buffer of @p size bytes
 * and selects the target byte by walking through segments until the cumulative
 * offset equals `index_sample % size`. The bit within the byte is selected by
 * `bit_sample & 7`. This is the recvmsg counterpart of chaos_net_corrupt_buffer():
 * the caller's data lives in multiple disjoint segments and cannot be corrupted
 * with a single pointer + offset.
 *
 * Only one bit is flipped across the entire scatter, consistent with the flat-buffer
 * contract in chaos_net_actions.h. After the bit is flipped, the function returns
 * immediately without examining further segments.
 *
 * @param iov     Scatter array describing the receive buffers.
 * @param iovcnt  Number of entries in @p iov. Must be > 0.
 * @param size    Total byte count to consider (typically the recvmsg return value).
 *                Must be > 0 and <= the sum of iov_len values.
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
            /* The target byte falls within this segment. */
            chaos_net_corrupt_buffer_sample(
                iov[entry].iov_base, segment_len, (uint32_t)index, bit_sample
            );
            return;
        }

        if (segment_len > 0U)
        {
            /* Advance past this segment and continue searching. */
            index -= segment_len;
            remaining -= segment_len;
        }
    }
}

/*---------------------------------------------------------------------------
 * Real-symbol call wrappers
 *
 * These wrappers set the reentrancy guard, invoke the real symbol, and restore
 * the guard. They exist to centralise the guard management so that the interposition
 * wrappers themselves read clearly without guard boilerplate on every call site.
 *---------------------------------------------------------------------------*/

/**
 * @brief Calls the real bind(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_bind(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_bind(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real listen(2) with reentrancy guard set.
 */
static int chaos_net_call_real_listen(int sockfd, int backlog)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_listen(sockfd, backlog);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real connect(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_connect(int sockfd, const struct sockaddr *address, socklen_t address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_connect(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real accept(2) with reentrancy guard set.
 */
static int
chaos_net_call_real_accept(int sockfd, struct sockaddr *address, socklen_t *address_length)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept(sockfd, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

#ifdef __linux__
/**
 * @brief Calls the real accept4(2) with reentrancy guard set (Linux only).
 */
static int chaos_net_call_real_accept4(
    int sockfd, struct sockaddr *address, socklen_t *address_length, int flags
)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_accept4(sockfd, address, address_length, flags);
    chaos_net_leave_internal(previous);
    return result;
}
#endif

/**
 * @brief Calls the real send(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_send(int sockfd, const void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_send(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendto(2) with reentrancy guard set.
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

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendto(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real sendmsg(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_sendmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recv(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_recv(int sockfd, void *buffer, size_t size, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recv(sockfd, buffer, size, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvfrom(2) with reentrancy guard set.
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

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvfrom(sockfd, buffer, size, flags, address, address_length);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Calls the real recvmsg(2) with reentrancy guard set.
 */
static ssize_t chaos_net_call_real_recvmsg(int sockfd, struct msghdr *message, int flags)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_recvmsg(sockfd, message, flags);
    chaos_net_leave_internal(previous);
    return result;
}

/*---------------------------------------------------------------------------
 * Pre-call effect dispatcher
 *---------------------------------------------------------------------------*/

/**
 * @brief Applies pre-call effects (latency or errno injection) for connection-lifecycle
 *        and send operations.
 *
 * @details Returns -1 if the call should be intercepted and the real syscall skipped
 * (errno injection fired). Returns 0 if the real syscall should proceed (either a
 * latency was applied and we continue, or the errno injection did not fire).
 *
 * This dispatcher is used by bind, listen, connect, accept, accept4, send, sendto,
 * sendmsg. It does NOT handle CORRUPT (post-call only) or TIMEOUT (poll-family only).
 *
 * @param rule  Matched rule; may be NULL (returns 0 immediately).
 * @return 0 to proceed with the real call; -1 to return immediately (errno set).
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
 * Interposed symbols
 *---------------------------------------------------------------------------*/

/**
 * @brief Interposed bind(2).
 *
 * @details Endpoint is derived from the caller-provided sockaddr + socket type.
 * If the endpoint cannot be resolved (e.g., unsupported address family) or no
 * rule matches, the call is forwarded to the real bind without modification.
 * The CHAOS_NET_CONST_SOCKADDR_PARAM / CHAOS_NET_CONST_SOCKADDR_VALUE macros
 * handle the glibc sockaddr union ABI on the parameter.
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
 * @brief Interposed listen(2).
 *
 * @details Endpoint is derived from the local address of the listening socket
 * (getsockname). The sockaddr is an input parameter to listen() only implicitly:
 * it was set by a prior bind(). Using getsockname here is consistent with how
 * users write config rules: "listen on port 8080" refers to the bound address.
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
 * @brief Interposed connect(2).
 *
 * @details Endpoint is derived from the caller-provided destination address and
 * the socket's type (SO_TYPE). This allows rules to target connects to a specific
 * remote endpoint: `tcp4://10.0.0.1:6379 : connect : ECONNREFUSED : 1.0`.
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
 * @brief Interposed accept(2).
 *
 * @details The sockaddr output parameter is an OUTPUT filled by the kernel post-call;
 * it is uninitialised at entry. Endpoint is therefore derived from the listening
 * socket's local address (getsockname on sockfd), not from the sockaddr argument.
 * See the file-level comment for the full rationale.
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
 * @brief Interposed accept4(2) (Linux only).
 *
 * @details Same endpoint-direction rationale as accept(): the sockaddr is an output
 * parameter. The endpoint is resolved from getsockname on the listening socket.
 * The flags parameter (SOCK_CLOEXEC, SOCK_NONBLOCK) is forwarded to the real call
 * unchanged; fault injection does not affect the semantics of the returned fd.
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
 * DUP: duplicate delivery
 *---------------------------------------------------------------------------*/

/** @brief Sockets whose last payload is kept at the same time (by descriptor). */
#define CHAOS_NET_DUP_SLOTS 64

/** @brief Longest payload kept for replay; a longer one is replayed truncated. */
#define CHAOS_NET_DUP_MAX_BYTES 4096U

/**
 * @brief The last payload received on one socket, kept for a DUP rule.
 *
 * @details Slots are indexed by descriptor modulo CHAOS_NET_DUP_SLOTS and tagged
 * with the descriptor, so a collision drops the older socket's payload instead of
 * replaying it on the wrong socket.
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
 * @brief How the slot table is mapped and unmapped: raw system calls, so that
 *        libchaos-memory rules on mmap cannot decide whether net keeps a payload.
 *
 * @details Unit tests define these before including this file to make the mapping
 * fail or lose the race to another thread.
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
 * @brief Runs between a store's close check and its tag; does nothing in the library.
 *
 * @details Unit tests define it before including this file to close the descriptor
 * exactly there, the window a concurrent close() can hit.
 */
#ifndef CHAOS_NET_DUP_BEFORE_TAG
#define CHAOS_NET_DUP_BEFORE_TAG(fd) ((void)(fd))
#endif

/**
 * @brief Identity of the socket behind @p fd (its inode and device); 0 when unknown.
 *
 * @details A descriptor number outlives its socket when it is closed or replaced
 * where net does not see it (dup2(), fclose() of an fdopen() stream, a raw close):
 * a payload is replayed only on the socket it came from. Unit tests define
 * CHAOS_NET_DUP_SOCKET before including this file.
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

/** @brief The slot table, mapped on the first DUP rule; NULL before (or if mapping failed). */
static chaos_net_dup_slot_t *volatile g_chaos_net_dup_slots = NULL;

/**
 * @brief Releases, in a fork() child, the slot locks other threads held at the fork.
 *
 * @details Those threads do not exist in the child: without this their slots would
 * never replay there. A vfork child shares the table and runs no atfork handler.
 */
static void chaos_net_dup_after_fork(void)
{
    chaos_net_dup_slot_t *table = g_chaos_net_dup_slots;
    int index;

    for (index = 0; index < CHAOS_NET_DUP_SLOTS; ++index)
    {
        table[index].lock = 0;
    }
}

/**
 * @brief Maps the slot table on first use with a raw system call.
 *
 * @details A raw mmap, like the io fd cache: libchaos-memory interposes mmap and
 * its rules must not decide whether net can keep a payload.
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
        /* Registered once, by the thread whose table is published. */
        (void)pthread_atfork(NULL, NULL, chaos_net_dup_after_fork);
    }
    return g_chaos_net_dup_slots;
}

/** @brief Locks and returns the slot of @p fd, or NULL without a table. */
static chaos_net_dup_slot_t *chaos_net_dup_lock(int fd, int create)
{
    chaos_net_dup_slot_t *table = create ? chaos_net_dup_table() : g_chaos_net_dup_slots;
    chaos_net_dup_slot_t *slot;

    if (table == NULL || fd < 0)
    {
        return NULL;
    }
    slot = &table[fd % CHAOS_NET_DUP_SLOTS];
    /* Never wait: the holder may be this very thread, interrupted by a signal
     * handler that receives or closes. A busy slot just skips DUP for this call. */
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
 * @brief The close count of @p fd's slot, taken before a receive whose payload is kept.
 *
 * @details Maps the table if needed; 0 without one (nothing is kept then).
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
 * @brief Keeps the @p received bytes just read into @p iov as @p fd's last payload.
 *
 * @details @p generation is the slot's close count from before the receive. If a
 * descriptor in the slot was closed since (by another thread, while this one was
 * receiving), the number may already name a new socket: the payload is dropped
 * rather than replayed there.
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
    /* A close since the check above either saw the tag (and cleared it) or bumped
     * the count before this re-check: then the payload is dropped. The slot lock is
     * held, so only a close can write the tag meanwhile, and it writes -1 too. */
    __sync_synchronize();
    if (slot->closes != generation)
    {
        slot->fd = -1;
    }
    chaos_net_dup_unlock(slot);
}

/**
 * @brief Delivers @p fd's last payload again when a DUP rule fires.
 *
 * @details Each payload is replayed at most once: the slot is emptied, so the next
 * receive reads the socket again. The sender address is copied to @p name when the
 * caller asked for one.
 *
 * @return Bytes delivered, or -1 when nothing was replayed (no payload kept, or the
 *         rule did not fire) and the caller must receive normally.
 */
static ssize_t chaos_net_dup_replay(
    const chaos_net_rule_t *rule,
    int fd,
    const struct iovec *iov,
    int iovcnt,
    struct sockaddr *name,
    socklen_t *name_length
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
    slot->fd = -1;
    chaos_net_dup_unlock(slot);
    return (ssize_t)delivered;
}

/** @brief Drops @p fd's kept payload; called when the descriptor is closed. */
static void chaos_net_dup_forget(int fd)
{
    chaos_net_dup_slot_t *table = g_chaos_net_dup_slots;

    if (table == NULL || fd < 0)
    {
        return;
    }
    /* Without the lock: close() must not wait. The count goes first, so a payload
     * being stored for the closed descriptor right now is dropped by its writer. */
    (void)__sync_fetch_and_add(&table[fd % CHAOS_NET_DUP_SLOTS].closes, 1U);
    (void)__sync_bool_compare_and_swap(&table[fd % CHAOS_NET_DUP_SLOTS].fd, fd, -1);
}

/** @brief Receive flags under which DUP receives for real (nothing is consumed or kept). */
#ifdef MSG_ERRQUEUE
#define CHAOS_NET_DUP_SKIP_FLAGS (MSG_PEEK | MSG_TRUNC | MSG_OOB | MSG_ERRQUEUE)
#else
#define CHAOS_NET_DUP_SKIP_FLAGS (MSG_PEEK | MSG_TRUNC | MSG_OOB)
#endif

/**
 * @brief Whether a receive of @p requested bytes with @p flags goes through DUP.
 *
 * @details Peeks consume nothing; MSG_TRUNC may report more than the buffer
 * holds; out-of-band and error-queue data is not the stream. An empty buffer
 * is left alone too: a replay into it would return 0, which reads as EOF.
 */
static int chaos_net_dups(const chaos_net_rule_t *rule, int flags, uint64_t requested)
{
    return rule->effect == CHAOS_NET_EFFECT_DUP && (flags & CHAOS_NET_DUP_SKIP_FLAGS) == 0 &&
           requested != 0U && requested != CHAOS_POLICY_NO_SIZE;
}

/** @brief Largest iovec array a TRICKLE rule reshapes; longer ones are left alone. */
#define CHAOS_NET_TRICKLE_MAX_IOV 64

/**
 * @brief The socket type of @p fd, asked with a raw system call; -1 when unknown.
 *
 * @details Unit tests define CHAOS_NET_SOCKET_TYPE before including this file.
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
 * @details TRICKLE only shortens receives on streams: on a datagram socket a
 * shorter buffer truncates the datagram and the kernel drops the rest.
 */
static int chaos_net_is_stream(int fd)
{
    return CHAOS_NET_SOCKET_TYPE(fd) == SOCK_STREAM;
}

/**
 * @brief Bytes of a @p size-byte buffer that a receive returning @p rc filled.
 *
 * @details With MSG_TRUNC a datagram receive returns the datagram's full length,
 * which can exceed the buffer, and a stream receive discards the data without
 * writing the buffer at all. CORRUPT must stay inside what was written.
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
 * @details Only a stream socket and a request larger than the chunk are shortened,
 * so a call TRICKLE leaves alone is not counted as a hit.
 */
static int chaos_net_trickles(const chaos_net_rule_t *rule, int fd, uint64_t requested)
{
    return rule->effect == CHAOS_NET_EFFECT_TRICKLE && requested > rule->chunk_bytes &&
           requested != CHAOS_POLICY_NO_SIZE && chaos_net_is_stream(fd) &&
           chaos_net_rule_should_trigger(rule);
}

/**
 * @brief Copies @p iov into @p out keeping at most @p limit bytes; returns the entry count.
 *
 * @details TRICKLE on vectored receives: the kernel fills the shortened vector, so
 * the caller's buffers receive the first bytes exactly as a short read would.
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
    chaos_net_endpoint_t endpoint;

    if (!chaos_net_config_prepare())
    {
        return 0;
    }
    if ((peer_first ? chaos_net_endpoint_from_peer_fd(fd, &endpoint)
                    : chaos_net_endpoint_from_local_fd(fd, &endpoint)) &&
        chaos_net_config_match_endpoint_loaded(operation, &endpoint, rule))
    {
        return 1;
    }
    return (peer_first ? chaos_net_endpoint_from_local_fd(fd, &endpoint)
                       : chaos_net_endpoint_from_peer_fd(fd, &endpoint)) &&
           chaos_net_config_match_endpoint_loaded(operation, &endpoint, rule);
}

/**
 * @brief Interposed send(2).
 *
 * @details send() is a connected-mode operation; there is no explicit destination
 * address. The endpoint is resolved via getpeername on the socket. If the socket is
 * not connected (getpeername fails), the call is passed through without injection.
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
 * @brief Interposed sendto(2).
 *
 * @details sendto() may be called in two modes:
 *   - With an explicit destination (address_ptr != NULL): typical for UDP datagrams.
 *     The destination sockaddr is used for endpoint resolution.
 *   - Without a destination (address_ptr == NULL): connected-mode send on a socket
 *     for which sendto is used as an alias for send(). The peer address from
 *     getpeername is used.
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

    /* Use the explicit destination if provided; fall back to getpeername for connected mode. */
    matched =
        address_ptr != NULL
            ? chaos_net_endpoint_from_sockaddr_fd(sockfd, address_ptr, address_length, &endpoint) &&
                  chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule)
            : chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule);
    if (chaos_net_in_internal() || !matched)
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
 * @brief Interposed sendmsg(2).
 *
 * @details sendmsg() may carry an explicit destination address in msg_name (non-NULL
 * for datagram sends) or may rely on the socket being connected (msg_name == NULL).
 * Endpoint resolution mirrors sendto(): use msg_name if present, otherwise getpeername.
 */
CHAOS_NET_EXPORT ssize_t sendmsg(int sockfd, const struct msghdr *message, int flags)
{
    chaos_net_endpoint_t endpoint;
    chaos_net_rule_t rule;
    int matched;

    chaos_net_ensure_symbols();

    matched = message != NULL && message->msg_name != NULL
                  ? chaos_net_endpoint_from_sockaddr_fd(
                        sockfd,
                        (const struct sockaddr *)message->msg_name,
                        (socklen_t)message->msg_namelen,
                        &endpoint
                    ) && chaos_net_config_match_endpoint(CHAOS_NET_OP_SEND, &endpoint, &rule)
                  : chaos_net_match_connected(sockfd, CHAOS_NET_OP_SEND, 1, &rule);
    if (chaos_net_in_internal() || !matched)
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
 * @brief Interposed recv(2).
 *
 * @details The endpoint is derived from the local address (getsockname) because:
 *   - For connected TCP sockets, the local port identifies the service.
 *   - For UDP sockets, the local port identifies the listening endpoint.
 *   Using the peer address would require the socket to be connected, which excludes
 *   UDP servers calling recvfrom without a prior connect.
 *
 * CORRUPT is applied post-call only on rc > 0. If rc == 0 (EOF) or rc < 0 (error),
 * there is no receive buffer content to corrupt and the buffer may be uninitialised.
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
        rc = chaos_net_dup_replay(&rule, sockfd, &target, 1, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(sockfd);

            rc = chaos_net_call_real_recv(sockfd, buffer, size, flags);
            chaos_net_dup_store(sockfd, &target, 1, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (chaos_net_trickles(&rule, sockfd, (uint64_t)size))
    {
        size = rule.chunk_bytes;
    }
    rc = chaos_net_call_real_recv(sockfd, buffer, size, flags);
    /* Apply corruption only to the received bytes the buffer holds. */
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
 * @brief Interposed recvfrom(2).
 *
 * @details Same endpoint resolution and CORRUPT application logic as recv(). The
 * caller-supplied address parameter (output) is forwarded to the real call unchanged;
 * libchaos-net does not modify the sender address.
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

    if (chaos_net_trickles(&rule, sockfd, (uint64_t)size))
    {
        size = rule.chunk_bytes;
    }
    if (buffer != NULL && chaos_net_dups(&rule, flags, (uint64_t)size))
    {
        struct iovec target;

        const socklen_t capacity = address_length != NULL ? *address_length : 0;

        target.iov_base = buffer;
        target.iov_len = size;
        rc = chaos_net_dup_replay(&rule, sockfd, &target, 1, address_ptr, address_length);
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
                /* The kernel reports the full address length even when it had to
                 * cut the address to fit the caller's buffer. */
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
 * @brief Interposed recvmsg(2).
 *
 * @details Same endpoint and pre-call logic as recv(). Post-call CORRUPT uses
 * chaos_net_corrupt_iovecs() because the receive buffer is described by the iovec
 * array in message->msg_iov, not a single flat buffer. The total received byte
 * count (rc) bounds the corruption to the actually-written portion of the scatter.
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

        rc = chaos_net_dup_replay(
            &rule,
            sockfd,
            message->msg_iov,
            (int)message->msg_iovlen,
            (struct sockaddr *)message->msg_name,
            &name_length
        );
        if (rc >= 0)
        {
            message->msg_namelen = message->msg_name != NULL ? name_length : 0;
            message->msg_controllen = 0;
            message->msg_flags = 0;
            return rc;
        }
        {
            const unsigned generation = chaos_net_dup_generation(sockfd);

            rc = chaos_net_call_real_recvmsg(sockfd, message, flags);
            chaos_net_dup_store(
                sockfd,
                message->msg_iov,
                (int)message->msg_iovlen,
                rc,
                (const struct sockaddr *)message->msg_name,
                message->msg_name != NULL
                    ? (message->msg_namelen < capacity ? message->msg_namelen : capacity)
                    : 0,
                generation
            );
        }
        return rc;
    }
    if (message != NULL && (size_t)message->msg_iovlen <= (size_t)CHAOS_NET_TRICKLE_MAX_IOV &&
        chaos_net_trickles(&rule, sockfd, chaos_net_message_size(message)))
    {
        struct iovec limited[CHAOS_NET_TRICKLE_MAX_IOV];
        struct msghdr shortened = *message;

        shortened.msg_iov = limited;
        /* msg_iovlen is size_t on glibc and int on musl. */
        shortened.msg_iovlen = chaos_net_limit_iovecs(
            message->msg_iov, (int)message->msg_iovlen, rule.chunk_bytes, limited
        );
        rc = chaos_net_call_real_recvmsg(sockfd, &shortened, flags);
        /* The kernel reports these through the header it was given. */
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
 * `_FORTIFY_SOURCE` builds call `__recv_chk()`, `__recvfrom_chk()`, `__read_chk()`,
 * `__poll_chk()` and `__ppoll_chk()` instead of the base functions when the buffer
 * size is known. They check the buffer the way glibc does and then run the
 * wrapper. libchaos-io also exports `__read_chk()` for files; both forward to
 * `read()`, which reaches both libraries in either preload order. musl has no
 * fortified variants.
 * ------------------------------------------------------------------------- */
#if defined(__GLIBC__)

extern void __chk_fail(void) __attribute__((__noreturn__));

/** Overflow handler of the fortified variants; replaceable so tests can observe it. */
static void (*g_chaos_net_chk_fail)(void) = __chk_fail;

/** @brief Fortified `recv()`: aborts like glibc when @p size exceeds the buffer. */
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

/** @brief Fortified `recvfrom()`: aborts like glibc when @p size exceeds the buffer. */
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

/** @brief Fortified `read()`: aborts like glibc when @p size exceeds the buffer. */
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

/** @brief Fortified `poll()`: aborts like glibc when @p nfds exceeds the array. */
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

/** @brief Fortified `ppoll()`: aborts like glibc when @p nfds exceeds the array. */
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
 * libchaos-io interposes the same symbols for files. Each library acts only on
 * its own kind of descriptor -- here sockets, recognised by the endpoint lookup
 * that fails with ENOTSOCK for anything else -- and always forwards the call to
 * the next definition in the chain (`RTLD_NEXT`), never straight to libc. So
 * whichever library is preloaded first, a file reaches libchaos-io's rules, a
 * socket reaches these, and every library sees every call.
 *
 * read/readv on a socket count as `recv`, write/writev as `send`, so a rule such
 * as `tcp4://10.0.0.5:6379:recv:ECONNRESET:1.0` applies whichever call the
 * program uses. Without any net rule the wrappers forward without a socket
 * lookup.
 *---------------------------------------------------------------------------*/

/** @brief Calls the next read(2) in the chain with the reentrancy guard set. */
static ssize_t chaos_net_call_real_read(int fd, void *buffer, size_t size)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_read(fd, buffer, size);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next write(2) in the chain with the reentrancy guard set. */
static ssize_t chaos_net_call_real_write(int fd, const void *buffer, size_t size)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_write(fd, buffer, size);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next readv(2) in the chain with the reentrancy guard set. */
static ssize_t chaos_net_call_real_readv(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_readv(fd, iov, iovcnt);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next writev(2) in the chain with the reentrancy guard set. */
static ssize_t chaos_net_call_real_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int previous;
    ssize_t result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_writev(fd, iov, iovcnt);
    chaos_net_leave_internal(previous);
    return result;
}

/** @brief Calls the next close(2) in the chain with the reentrancy guard set. */
static int chaos_net_call_real_close(int fd)
{
    int previous;
    int result;

    previous = chaos_net_enter_internal();
    result = g_chaos_net_real_close(fd);
    chaos_net_leave_internal(previous);
    return result;
}

/**
 * @brief Finds the rule for a generic descriptor call, if @p fd is a socket.
 *
 * @details The config is consulted first, so without rules no socket lookup is
 * made. For a file, the endpoint lookup fails (ENOTSOCK) and the call is not
 * ours; errno is preserved by the lookup.
 *
 * @param fd         Descriptor of the call.
 * @param operation  RECV, SEND or CLOSE.
 * @param rule       Output: the matching rule.
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
 * @brief Interposed read(2): `recv` rules for sockets, anything else forwarded.
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
        rc = chaos_net_dup_replay(&rule, fd, &target, 1, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(fd);

            rc = chaos_net_call_real_read(fd, buffer, size);
            chaos_net_dup_store(fd, &target, 1, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (chaos_net_trickles(&rule, fd, (uint64_t)size))
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
 * @brief Interposed readv(2): `recv` rules for sockets, anything else forwarded.
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
        rc = chaos_net_dup_replay(&rule, fd, iov, iovcnt, NULL, NULL);
        if (rc < 0)
        {
            const unsigned generation = chaos_net_dup_generation(fd);

            rc = chaos_net_call_real_readv(fd, iov, iovcnt);
            chaos_net_dup_store(fd, iov, iovcnt, rc, NULL, 0, generation);
        }
        return rc;
    }
    if (iov != NULL && iovcnt > 0 && iovcnt <= CHAOS_NET_TRICKLE_MAX_IOV &&
        chaos_net_trickles(&rule, fd, chaos_net_iovec_size(iov, iovcnt)))
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
 * @brief Interposed write(2): `send` rules for sockets, anything else forwarded.
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
 * @brief Interposed writev(2): `send` rules for sockets, anything else forwarded.
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
 * @brief Interposed close(2): `close` rules for sockets, anything else forwarded.
 *
 * @details The endpoint is resolved before the descriptor goes away. Effects:
 *   - RESET: arms SO_LINGER with a zero timeout, so the close aborts the
 *     connection and the peer receives an RST (ECONNRESET) instead of a FIN.
 *     This is how a crashed or killed process, or a load balancer dropping a
 *     connection, looks from the other side.
 *   - LATENCY: delays the close.
 *   - ERRNO: closes, then reports the error. Linux releases the descriptor even
 *     when close reports an error, and programs never retry it, so a synthetic
 *     error that kept the descriptor open would leak it.
 * The close itself always runs through the chain, so a library that shares
 * `close` (libchaos-io keeps an fd cache) sees every call.
 */
CHAOS_NET_EXPORT int close(int fd)
{
    chaos_net_rule_t rule;
    struct linger abort_linger;
    int matched;
    int previous;
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
        previous = chaos_net_enter_internal();
        (void)g_chaos_net_real_setsockopt(
            fd, SOL_SOCKET, SO_LINGER, &abort_linger, (socklen_t)sizeof(abort_linger)
        );
        chaos_net_leave_internal(previous);
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
