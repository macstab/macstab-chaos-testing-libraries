/**
 * @file chaos_io_internal.h
 * @brief libchaos-io primitives shared by every translation unit: limits, control-file
 *        paths, real-function types and pointers, re-entrancy guard, PRNG, path filters.
 *
 * @details
 * Included by the wrappers, the rule cache, the fd cache, the effects and by chaos-init
 * (which reuses the path helpers). Everything defined inline here is allocation-free and
 * lock-free.
 *
 * @par Thread safety
 * - Real-function pointers are written once, during symbol resolution under chaos_once(),
 *   and only read afterwards.
 * - g_chaos_io_process_seed is written once in the constructor.
 * - The re-entrancy guard and the PRNG state are thread-local (`__thread`): each thread
 *   has its own, so they need no synchronisation. Together they are 12 bytes of TLS;
 *   larger objects are kept out of TLS on purpose (see g_chaos_io_config_buffer in
 *   chaos_io_config.c).
 * - The atomic helpers order the shared rule-cache fields.
 */

#ifndef CHAOS_IO_INTERNAL_H
#define CHAOS_IO_INTERNAL_H

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/sendfile.h>
#include <sys/syscall.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * @brief System-call entry used by a wrapper whose real function is not resolved yet.
 *
 * @details A wrapper can run while the real-function table is still being filled: a
 * signal handler during the constructor's dlsym, or an allocator whose first allocation
 * inside dlsym does file I/O. Its `g_chaos_io_real_*` pointer is NULL then, and the
 * wrapper issues the system call itself. Test seam: unit tests stub `syscall` and point
 * this macro at the real one.
 */
#ifndef CHAOS_IO_SYSCALL
#define CHAOS_IO_SYSCALL syscall
#endif

/**
 * @defgroup chaos_io_limits Capacity and path limits
 * @{
 */

/**
 * @brief Rule file of libchaos-io.
 *
 * @details Re-read when its change stamp changes (chaos_io_config_prepare()). Excluded
 * from matching, together with every other `/tmp/.chaos-*` control file
 * (chaos_io_is_control_path()), so no rule can fault the control plane.
 */
#define CHAOS_IO_CONFIG_PATH "/tmp/.chaos-io.conf"

/** @brief Status file: outcome of the last reload (chaos_status.h). */
#define CHAOS_IO_STATUS_PATH "/tmp/.chaos-io.status"

/** @brief Hits-file name without the `.<n>` suffix (chaos_hits.h). */
#define CHAOS_IO_HITS_PREFIX "/tmp/.chaos-io.hits"

/**
 * @brief Most rules one rule file may hold; rule 257 rejects the file ("too many rules").
 *
 * @details Sizes the two static snapshots, the hit-slot pool (twice this) and the
 * hits-file buffer; BSS grows linearly with it.
 */
#define CHAOS_IO_MAX_RULES 256U

/**
 * @brief Size of a path buffer, NUL included: `PATH_MAX` (4096 on Linux), the kernel's
 *        own limit for a path argument. Wrappers keep one or two on the stack.
 */
#define CHAOS_IO_MAX_PATH ((size_t)PATH_MAX)

/**
 * @brief Size of a rule's path-prefix buffer, NUL included; a prefix of 1024 bytes or more
 *        rejects the line.
 *
 * @details Smaller than CHAOS_IO_MAX_PATH because it is stored three times per rule slot
 * (prefix, resolved form, both snapshots), and operator-written prefixes are short.
 */
#define CHAOS_IO_MAX_RULE_PATH 1024U

/**
 * @brief Line length used only to size CHAOS_IO_MAX_CONFIG_BYTES; no per-line limit is
 *        enforced beyond the rule-prefix limit.
 */
#define CHAOS_IO_MAX_LINE_LENGTH 1024U

/**
 * @brief Rule-file size limit: 256 * 1024 = 262144 bytes (256 KiB). A file of this size
 *        or larger is rejected ("file too large") instead of being parsed truncated.
 */
#define CHAOS_IO_MAX_CONFIG_BYTES (CHAOS_IO_MAX_RULES * CHAOS_IO_MAX_LINE_LENGTH)

/**
 * @brief Slots of the process-wide direct-mapped fd-to-path cache.
 *
 * @details Indexed by `fd % CHAOS_IO_FD_CACHE_SLOTS`: descriptors that differ by a
 * multiple of 32 share a slot, and the later store evicts the earlier entry. The table
 * is mapped once per process on first store, 32 * (4096 + 12) bytes, about 128 KiB; no
 * thread carries any of it.
 */
#define CHAOS_IO_FD_CACHE_SLOTS 32U

/** @} */

/**
 * @defgroup chaos_io_visibility Symbol visibility
 * @{
 */

/**
 * @brief Exports a wrapper into the dynamic symbol table.
 *
 * @details Only the interposed functions carry it; the shared object is built with
 * `-fvisibility=hidden`, so no internal helper can interpose on, or collide with, a
 * symbol of the host process.
 *
 * @note The shared object is also built with `-fno-stack-protector`, so it imports no
 * `__stack_chk_fail`: that handler writes a message through libc, which would re-enter
 * these wrappers on a corrupted stack.
 */
#define CHAOS_IO_EXPORT __attribute__((visibility("default")))

/** @} */

/**
 * @defgroup chaos_io_mtime Change-stamp sentinels
 * @{
 *
 * @details The rule cache keeps the rule file's change stamp (a 64-bit hash of mtime,
 * size, inode and device) in one shared word that is also the reload claim's CAS target.
 * Three values are reserved; chaos_io_config_normalize_mtime_hash() moves a real stamp
 * that hashes to one of them off it.
 */

/**
 * @brief Sentinel: the rule file does not exist or stat() failed; the active snapshot
 *        then holds no rules.
 */
#define CHAOS_IO_MTIME_MISSING UINT64_C(0)

/**
 * @brief Sentinel: the reload claim; one thread of this process is reloading.
 *
 * @details Other threads keep using the active snapshot instead of waiting, so at most
 * one thread reads and parses the rule file at a time.
 */
#define CHAOS_IO_MTIME_RELOADING UINT64_C(0xfffffffffffffffe)

/**
 * @brief Sentinel: no load yet (set by chaos_io_config_init(), and by the atfork handler
 *        when it releases a claim). Every observed stamp differs from it, so the next
 *        check reloads, and the throttle is bypassed while it is set.
 */
#define CHAOS_IO_MTIME_UNKNOWN UINT64_C(0xffffffffffffffff)

/** @} */

/**
 * @defgroup chaos_io_fn_types Real-function pointer types
 * @{
 *
 * @details Each typedef mirrors the libc prototype exactly, so calls through the
 * pointers are type-checked and well defined. The pointers are filled by
 * `dlsym(RTLD_NEXT, ...)` (chaos_io_ensure_symbols()); wrappers handle a NULL pointer
 * themselves (raw system call or ENOSYS).
 */

/** @brief Type of the real `read(2)` libc symbol. */
typedef ssize_t (*chaos_io_read_fn)(int, void *, size_t);

/** @brief Type of the real `write(2)` libc symbol. */
typedef ssize_t (*chaos_io_write_fn)(int, const void *, size_t);

/** @brief Type of the real `readv(2)` libc symbol. */
typedef ssize_t (*chaos_io_readv_fn)(int, const struct iovec *, int);

/** @brief Type of the real `writev(2)` libc symbol. */
typedef ssize_t (*chaos_io_writev_fn)(int, const struct iovec *, int);

/** @brief Type of the real `open(2)` libc symbol (varargs). */
typedef int (*chaos_io_open_fn)(const char *, int, ...);

/** @brief Type of the real `openat(2)` libc symbol (varargs). */
typedef int (*chaos_io_openat_fn)(int, const char *, int, ...);

/** @brief Type of the real `close(2)` libc symbol. */
typedef int (*chaos_io_close_fn)(int);

/** @brief Type of the real `dup2(2)` libc symbol. */
typedef int (*chaos_io_dup2_fn)(int, int);

/** @brief Type of the real `close_range(2)` libc symbol (glibc 2.34+; may be absent). */
typedef int (*chaos_io_close_range_fn)(unsigned int, unsigned int, int);
/** @brief Signature of `closedir`. */
typedef int (*chaos_io_closedir_fn)(DIR *);
/** @brief Signature of `pclose`. */
typedef int (*chaos_io_pclose_fn)(FILE *);
/** @brief Signature of `closefrom` (glibc 2.34; absent from musl). */
typedef void (*chaos_io_closefrom_fn)(int);

/**
 * @brief Type shared by the real `fsync(2)` and `fdatasync(2)` libc symbols.
 *
 * @details Both functions have the same signature `int f(int fd)` so a
 * single typedef covers both stored pointers.
 */
typedef int (*chaos_io_sync_fn)(int);

/** @brief Type of the real `pread(2)` libc symbol. */
typedef ssize_t (*chaos_io_pread_fn)(int, void *, size_t, off_t);

/** @brief Type of the real `pwrite(2)` libc symbol. */
typedef ssize_t (*chaos_io_pwrite_fn)(int, const void *, size_t, off_t);

/** @brief Type of the real `preadv(2)` libc symbol. */
typedef ssize_t (*chaos_io_preadv_fn)(int, const struct iovec *, int, off_t);

/** @brief Type of the real `pwritev(2)` libc symbol. */
typedef ssize_t (*chaos_io_pwritev_fn)(int, const struct iovec *, int, off_t);

/** @brief Type of the real `ftruncate(2)` libc symbol. */
typedef int (*chaos_io_ftruncate_fn)(int, off_t);

/** @brief Type of the real `truncate(2)` libc symbol. */
typedef int (*chaos_io_truncate_fn)(const char *, off_t);

/** @brief Type of the real `fread` libc symbol. */
typedef size_t (*chaos_io_fread_fn)(void *, size_t, size_t, FILE *);

/** @brief Type of the real `fwrite` libc symbol. */
typedef size_t (*chaos_io_fwrite_fn)(const void *, size_t, size_t, FILE *);

/** @brief Type of the real `fgets` libc symbol. */
typedef char *(*chaos_io_fgets_fn)(char *, int, FILE *);

/** @brief Type of the real `fputs` libc symbol. */
typedef int (*chaos_io_fputs_fn)(const char *, FILE *);

/** @brief Type of the real `fgetc` libc symbol. */
typedef int (*chaos_io_fgetc_fn)(FILE *);

/** @brief Type of the real `fputc` libc symbol. */
typedef int (*chaos_io_fputc_fn)(int, FILE *);

/** @brief Type of the real `getdelim` libc symbol. */
typedef ssize_t (*chaos_io_getdelim_fn)(char **, size_t *, int, FILE *);

/** @brief Type of the real `vfprintf` libc symbol. */
typedef int (*chaos_io_vfprintf_fn)(FILE *, const char *, va_list);

/** @brief Type of the real `fflush` libc symbol. */
typedef int (*chaos_io_fflush_fn)(FILE *);

/** @brief Type of the real `__vfprintf_chk` libc symbol. */
typedef int (*chaos_io_vfprintf_chk_fn)(FILE *, int, const char *, va_list);

/** @brief Type of the real `__fread_chk` libc symbol. */
typedef size_t (*chaos_io_fread_chk_fn)(void *, size_t, size_t, size_t, FILE *);

/** @brief Type of the real `__fgets_chk` libc symbol. */
typedef char *(*chaos_io_fgets_chk_fn)(char *, size_t, int, FILE *);

/** @brief Type of the real `fclose` libc symbol. */
typedef int (*chaos_io_fclose_fn)(FILE *);

/** @brief Type of the real `fopen(3)` libc symbol. */
typedef FILE *(*chaos_io_fopen_fn)(const char *, const char *);

/** @brief Type of the real `freopen(3)` libc symbol. */
typedef FILE *(*chaos_io_freopen_fn)(const char *, const char *, FILE *);

/** @brief Type of the real `renameat2(2)` libc symbol (glibc 2.28+; absent on musl). */
typedef int (*chaos_io_renameat2_fn)(int, const char *, int, const char *, unsigned int);

/** @brief Type of the real `posix_fallocate(3)` libc symbol. */
typedef int (*chaos_io_posix_fallocate_fn)(int, off_t, off_t);

/** @brief Type of the real `unlinkat(2)` libc symbol. */
typedef int (*chaos_io_unlinkat_fn)(int, const char *, int);

/** @brief Type of the real `renameat(2)` libc symbol. */
typedef int (*chaos_io_renameat_fn)(int, const char *, int, const char *);

#ifdef __linux__
/** @brief Type of the real Linux `fallocate(2)` libc symbol. */
typedef int (*chaos_io_fallocate_fn)(int, int, off_t, off_t);

/** @brief Type of the real Linux `sendfile(2)` libc symbol. */
typedef ssize_t (*chaos_io_sendfile_fn)(int, int, off_t *, size_t);

/** @brief Type of the real Linux `dup3(2)` libc symbol. */
typedef int (*chaos_io_dup3_fn)(int, int, int);

/** @brief Type of the real Linux `copy_file_range(2)` libc symbol. */
typedef ssize_t (*chaos_io_copy_file_range_fn)(int, off_t *, int, off_t *, size_t, unsigned int);
#endif

/** @} */

/**
 * @defgroup chaos_io_real_symbols Real functions
 * @{
 *
 * @details The next definition of each symbol after libchaos-io, found with
 * `dlsym(RTLD_NEXT, name)`: libc, or another preloaded library later in `LD_PRELOAD`.
 * Written once by chaos_io_ensure_symbols() and read without synchronisation afterwards;
 * chaos_once()'s release/acquire pairing makes the complete table visible.
 *
 * All start NULL. The constructor alone does not guarantee they are set: ELF initialisers
 * run in dependency order, so another object's constructor can reach a wrapper before
 * chaos_io_init(). Every wrapper therefore calls chaos_io_ensure_symbols() first, and
 * still copes with NULL (re-entry during resolution, or an optional symbol libc lacks).
 */

extern chaos_io_read_fn g_chaos_io_real_read;     /**< Downstream `read`. */
extern chaos_io_write_fn g_chaos_io_real_write;   /**< Downstream `write`. */
extern chaos_io_readv_fn g_chaos_io_real_readv;   /**< Downstream `readv`. */
extern chaos_io_writev_fn g_chaos_io_real_writev; /**< Downstream `writev`. */
extern chaos_io_open_fn g_chaos_io_real_open;     /**< Downstream `open`. */
extern chaos_io_openat_fn g_chaos_io_real_openat; /**< Downstream `openat`. */
extern chaos_io_close_fn g_chaos_io_real_close;   /**< Downstream `close`. */
extern chaos_io_dup2_fn g_chaos_io_real_dup2;     /**< Downstream `dup2`. */
extern chaos_io_close_range_fn
    g_chaos_io_real_close_range; /**< Downstream `close_range`; NULL when libc lacks it. */
extern chaos_io_closedir_fn g_chaos_io_real_closedir; /**< Downstream `closedir`. */
extern chaos_io_pclose_fn g_chaos_io_real_pclose;     /**< Downstream `pclose`. */
extern chaos_io_closefrom_fn
    g_chaos_io_real_closefrom; /**< Downstream `closefrom`; NULL when libc lacks it. */
extern chaos_io_sync_fn g_chaos_io_real_fsync;          /**< Downstream `fsync`. */
extern chaos_io_sync_fn g_chaos_io_real_fdatasync;      /**< Downstream `fdatasync`. */
extern chaos_io_pread_fn g_chaos_io_real_pread;         /**< Downstream `pread`. */
extern chaos_io_pwrite_fn g_chaos_io_real_pwrite;       /**< Downstream `pwrite`. */
extern chaos_io_preadv_fn g_chaos_io_real_preadv;       /**< Downstream `preadv`. */
extern chaos_io_pwritev_fn g_chaos_io_real_pwritev;     /**< Downstream `pwritev`. */
extern chaos_io_ftruncate_fn g_chaos_io_real_ftruncate; /**< Downstream `ftruncate`. */
extern chaos_io_unlinkat_fn g_chaos_io_real_unlinkat;   /**< Downstream `unlinkat`. */
extern chaos_io_truncate_fn g_chaos_io_real_truncate;   /**< Downstream `truncate`. */
extern chaos_io_fopen_fn g_chaos_io_real_fopen;         /**< Downstream `fopen`. */
extern chaos_io_fclose_fn g_chaos_io_real_fclose;       /**< Downstream `fclose`. */
extern chaos_io_fread_fn g_chaos_io_real_fread;         /**< Downstream `fread`. */
extern chaos_io_fwrite_fn g_chaos_io_real_fwrite;       /**< Downstream `fwrite`. */
extern chaos_io_fgets_fn g_chaos_io_real_fgets;         /**< Downstream `fgets`. */
extern chaos_io_fputs_fn g_chaos_io_real_fputs;         /**< Downstream `fputs`. */
extern chaos_io_fgetc_fn g_chaos_io_real_fgetc;         /**< Downstream `fgetc`. */
extern chaos_io_fgetc_fn g_chaos_io_real_getc;          /**< Downstream `getc`. */
extern chaos_io_fputc_fn g_chaos_io_real_fputc;         /**< Downstream `fputc`. */
extern chaos_io_fputc_fn g_chaos_io_real_putc;          /**< Downstream `putc`. */
extern chaos_io_getdelim_fn g_chaos_io_real_getdelim;   /**< Downstream `getdelim`. */
extern chaos_io_vfprintf_fn g_chaos_io_real_vfprintf;   /**< Downstream `vfprintf`. */
extern chaos_io_fflush_fn g_chaos_io_real_fflush;       /**< Downstream `fflush`. */
extern chaos_io_vfprintf_chk_fn
    g_chaos_io_real_vfprintf_chk; /**< Downstream `__vfprintf_chk` (optional). */
extern chaos_io_fread_chk_fn g_chaos_io_real_fread_chk; /**< Downstream `__fread_chk` (optional). */
extern chaos_io_fgets_chk_fn g_chaos_io_real_fgets_chk; /**< Downstream `__fgets_chk` (optional). */
extern chaos_io_freopen_fn g_chaos_io_real_freopen;     /**< Downstream `freopen`. */
extern chaos_io_renameat2_fn
    g_chaos_io_real_renameat2; /**< Downstream `renameat2`; NULL when libc lacks it. */
extern chaos_io_posix_fallocate_fn
    g_chaos_io_real_posix_fallocate;                  /**< Downstream `posix_fallocate`. */
extern chaos_io_renameat_fn g_chaos_io_real_renameat; /**< Downstream `renameat`. */
#ifdef __linux__
extern chaos_io_fallocate_fn g_chaos_io_real_fallocate; /**< Downstream `fallocate` (Linux). */
extern chaos_io_sendfile_fn g_chaos_io_real_sendfile;   /**< Downstream `sendfile` (Linux). */
extern chaos_io_dup3_fn g_chaos_io_real_dup3;           /**< Downstream `dup3` (Linux). */
extern chaos_io_copy_file_range_fn
    g_chaos_io_real_copy_file_range; /**< Downstream `copy_file_range` (Linux). */

/**
 * @brief Resolves every real function on first use; idempotent and thread-safe.
 *
 * @details The first statement of every wrapper. The constructor is not enough on its
 * own: ELF initialisers run in dependency order, so another object's constructor can
 * reach a wrapper before chaos_io_init(). `libcap-ng` does exactly that (its initialiser
 * performs file I/O), which made every `setpriv`, `su` and `runuser` under this preload
 * jump through a NULL pointer and die with SIGSEGV. After the first call the cost is one
 * acquire load and a predictable branch. A call re-entered from inside resolution on the
 * same thread returns without waiting (chaos_once.h).
 */
void chaos_io_ensure_symbols(void);
#endif

/** @} */

/**
 * @defgroup chaos_io_tls Thread-local state
 * @{
 */

/**
 * @brief Per-thread re-entrancy guard: non-zero while this thread runs library code that
 *        may call an interposed function (rule-file read, `/proc/self/fd` readlink,
 *        getcwd, a real-function call).
 *
 * @details A wrapper that finds it set calls straight through to the real function, so
 * the library's own I/O, and libc's I/O made from inside a real call (fopen opening a
 * file, fclose flushing), is never faulted or re-matched. Saved and restored, not
 * counted, so nested sections restore the caller's state. Zero-initialised TLS, so every
 * new thread starts outside.
 */
extern __thread int g_chaos_io_tls_guard;

/**
 * @brief Per-thread xorshift64* state; 0 means "not seeded yet".
 *
 * @details Seeded on first draw (chaos_io_prng_ensure_seeded()) from the process seed,
 * the kernel tid and a stack address, so threads, and forked children (whose state the
 * atfork handler zeroes), draw independent sequences.
 */
extern __thread uint64_t g_chaos_io_tls_prng_state;

/**
 * @brief Process-wide seed base for the per-thread PRNGs.
 *
 * @details Set once in chaos_io_init() from `/dev/urandom`, or from a pid-derived value
 * when that fails. A thread created later sees it through pthread_create()'s
 * happens-before. A wrapper that runs before the constructor seeds from the built-in
 * placeholder instead; that only affects which faults fire, not correctness.
 */
extern uint64_t g_chaos_io_process_seed;

/** @} */

/**
 * @defgroup chaos_io_guard_inlines Reentrancy guard inline helpers
 * @{
 */

/**
 * @brief Non-zero when this thread is inside a library section (g_chaos_io_tls_guard).
 *
 * @details A wrapper that sees non-zero must call straight through without touching rules
 * or caches. Async-signal-safe: one TLS load.
 */
static inline int chaos_io_in_internal(void)
{
    return g_chaos_io_tls_guard != 0;
}

/**
 * @brief Enters a library section: sets the guard and returns its previous value.
 *
 * @details Pass the result to chaos_io_leave_internal() on every exit path; restoring the
 * previous value (instead of clearing) keeps an enclosing section intact. A signal handler
 * that interrupts a section sees the guard set and passes its own I/O straight through.
 *
 * @return The previous guard value.
 */
static inline int chaos_io_enter_internal(void)
{
    int previous = g_chaos_io_tls_guard;
    g_chaos_io_tls_guard = 1;
    return previous;
}

/**
 * @brief Leaves a library section: restores the guard to @p previous, the value the
 *        matching chaos_io_enter_internal() returned. A missed call leaves the thread in
 *        permanent pass-through.
 */
static inline void chaos_io_leave_internal(int previous)
{
    g_chaos_io_tls_guard = previous;
}

/** @} */

/**
 * @defgroup chaos_io_atomic Lock-free atomic helpers
 * @{
 */

/**
 * @brief Full barrier, then a load of @p value.
 *
 * @details Used for the cached change stamp, which is published lock-free: the barrier
 * keeps the load from being satisfied before earlier memory operations of this thread.
 * A 64-bit aligned load is single-copy atomic on x86_64 and aarch64, the supported
 * targets.
 *
 * @param[in] value  Shared word; must not be NULL.
 */
static inline uint64_t chaos_io_atomic_load_u64(volatile uint64_t *value)
{
    __sync_synchronize();
    return *value;
}

/**
 * @brief Full-barrier compare-and-swap on a shared 64-bit word.
 *
 * @details Decides the reload claim: the thread that swaps the cached stamp to
 * CHAOS_IO_MTIME_RELOADING reloads; the others keep serving from the active snapshot
 * instead of spinning.
 *
 * @return Non-zero when `*value` was @p expected and is now @p desired; 0 otherwise.
 */
static inline int
chaos_io_atomic_cas_u64(volatile uint64_t *value, uint64_t expected, uint64_t desired)
{
    return __sync_bool_compare_and_swap(value, expected, desired);
}

/** @} */

/**
 * @defgroup chaos_io_prng PRNG helpers
 * @{
 */

/**
 * @brief Kernel thread id (Linux), or the pid on other hosts; PRNG seed material.
 *
 * @details `syscall(SYS_gettid)` rather than gettid(): the libc wrapper exists only since
 * glibc 2.30, and musl added it later still.
 */
static inline uint64_t chaos_io_current_tid(void)
{
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    return (uint64_t)getpid();
#endif
}

/**
 * @brief SplitMix64 step (Steele, Lea, Flood 2014): turns structured seed material (pid,
 *        tid, addresses) into well-mixed PRNG state; every input bit affects every
 *        output bit.
 */
static inline uint64_t chaos_io_prng_mix(uint64_t value)
{
    value += UINT64_C(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)) * UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

/**
 * @brief Seeds this thread's PRNG on its first draw.
 *
 * @details Lazy, so threads that never draw pay nothing. Seed = process seed XOR tid XOR
 * a stack address (ASLR- and thread-dependent), mixed with SplitMix64 and forced odd, so
 * the state is never 0, the one state xorshift64* cannot leave. One extra gettid system
 * call per thread, once.
 */
static inline void chaos_io_prng_ensure_seeded(void)
{
    uint64_t seed;

    if (g_chaos_io_tls_prng_state != 0U)
    {
        return;
    }

    seed = g_chaos_io_process_seed;
    seed ^= chaos_io_current_tid();
    seed ^= (uint64_t)(uintptr_t)&seed;
    /* Odd: never 0, the one state xorshift64* cannot leave. */
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed) | 1U;
}

/**
 * @brief Seeds this thread's PRNG from @p seed (mixed with SplitMix64); the constructor
 *        seeds its own thread with it, tests use it for reproducible draws.
 *
 * @param[in] seed  Seed; 0 is replaced by 1 before mixing. The mixed state is not forced
 *                  odd here; a zero result would be reseeded lazily on the next draw.
 */
static inline void chaos_io_prng_seed_thread(uint64_t seed)
{
    g_chaos_io_tls_prng_state = chaos_io_prng_mix(seed == 0U ? UINT64_C(1) : seed);
}

/**
 * @brief Next 32-bit sample of this thread's xorshift64* generator (shifts 12, 25, 27;
 *        output = high 32 bits of state * 0x2545f4914f6cdd1d).
 *
 * @details A few cycles, no system call after seeding. The multiplied high half has far
 * better low-order statistics than the raw state, which matters for the modulo in torn
 * counts and corruption offsets. Not a cryptographic generator.
 *
 * Signal handlers: a handler that interrupts the update and draws itself may make both
 * draws return related values; the state stays valid. Harmless for fault sampling.
 */
static inline uint32_t chaos_io_prng_next_u32(void)
{
    uint64_t state;

    chaos_io_prng_ensure_seeded();
    state = g_chaos_io_tls_prng_state;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    g_chaos_io_tls_prng_state = state;
    return (uint32_t)((state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}

/** @} */

/**
 * @defgroup chaos_io_path_filter Path exclusion helpers
 * @{
 */

/** @brief Name prefix of every libchaos library's control files (rule, status, hits, staging). */
#define CHAOS_IO_CONTROL_PREFIX "/tmp/.chaos-"

/**
 * @brief Non-zero when @p path is a control file of any libchaos library.
 *
 * @details The rule, status and hits files of every library (`/tmp/.chaos-<lib>.conf`,
 * `.status`, `.hits.<n>`) are never faulted, including when a tool under the same preload
 * writes them (a shell redirecting into a rule file). Also covers status staging files
 * in /tmp, whose names start with `.chaos-staging-`.
 *
 * @param[in] path  Path; NULL returns 0.
 */
static inline int chaos_io_is_control_path(const char *path)
{
    return path != NULL &&
           (strcmp(path, CHAOS_IO_CONFIG_PATH) == 0 ||
            strncmp(path, CHAOS_IO_CONTROL_PREFIX, sizeof(CHAOS_IO_CONTROL_PREFIX) - 1U) == 0);
}

/**
 * @brief Non-zero when @p path equals @p prefix or lies below it at a component boundary
 *        (`/proc` covers `/proc/self/status`, not `/process`).
 *
 * @param[in] path    Path; NULL returns 0.
 * @param[in] prefix  Prefix without a trailing `/`; NULL returns 0.
 */
static inline int chaos_io_has_reserved_prefix(const char *path, const char *prefix)
{
    size_t prefix_len;

    if (path == NULL || prefix == NULL)
    {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0)
    {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

/**
 * @brief Non-zero when @p path is never faulted, whatever the rules say.
 *
 * @details Applied before rule matching and before an fd-cache store:
 * - NULL or empty (unresolved);
 * - control files of every libchaos library (`/tmp/.chaos-*`);
 * - `/proc`, `/sys`, `/dev` and everything below them.
 *
 * `/proc` and `/sys` are kernel interfaces the libraries and runtimes depend on
 * (`/proc/self/fd`, `/proc/self/maps`, cgroup files); `/dev` holds devices, terminals and
 * `/dev/urandom`, where a file fault would break terminals and entropy reads.
 * Excluded descriptors are not cached, so they are re-resolved on every call.
 *
 * @param[in] path  Path; NULL allowed.
 * @return Non-zero to pass the call through.
 */
static inline int chaos_io_is_excluded_path(const char *path)
{
    if (path == NULL || *path == '\0')
    {
        return 1;
    }
    if (chaos_io_is_control_path(path))
    {
        return 1;
    }
    if (chaos_io_has_reserved_prefix(path, "/proc") || chaos_io_has_reserved_prefix(path, "/sys") ||
        chaos_io_has_reserved_prefix(path, "/dev"))
    {
        return 1;
    }
    return 0;
}

/** @} */

/** @name Path strings matched against rules (wrappers and chaos-init) */
/** @{ */

/**
 * @brief Copies @p path into @p destination when it fits, NUL included.
 *
 * @param[out] destination       Buffer; NULL returns 0.
 * @param[in]  destination_size  Capacity in bytes; 0 returns 0.
 * @param[in]  path              Source; NULL returns 0.
 * @return Non-zero on success; 0 when it does not fit (@p destination untouched).
 */
static inline int chaos_io_copy_path(char *destination, size_t destination_size, const char *path)
{
    size_t length;

    if (destination == NULL || destination_size == 0U || path == NULL)
    {
        return 0;
    }

    length = strlen(path);
    if (length + 1U > destination_size)
    {
        return 0;
    }

    (void)memcpy(destination, path, length + 1U);
    return 1;
}

/**
 * @brief Normalises an absolute path in place, lexically.
 *
 * @details Repeated slashes collapse, `.` components go, `..` removes the previous
 * component (and stops at `/`), and a trailing slash goes; `/` stays `/`. So
 * `/tmp/pd/./data//f` and `/tmp/pd/x/../data/f` both match a rule for `/tmp/pd/data`.
 * Symbolic links are not followed: `..` after a link may differ from what the kernel
 * resolves, but a descriptor's cached path comes from the kernel (`/proc/self/fd`)
 * anyway. The result is never longer than the input; no allocation.
 *
 * @param[in,out] path  NUL-terminated path; NULL or a relative path is left unchanged.
 */
static inline void chaos_io_normalize_path(char *path)
{
    size_t read_at = 1U;
    size_t write_at = 1U;

    if (path == NULL || path[0] != '/')
    {
        return;
    }
    while (path[read_at] != '\0')
    {
        size_t start;
        size_t length;

        while (path[read_at] == '/')
        {
            ++read_at;
        }
        start = read_at;
        while (path[read_at] != '\0' && path[read_at] != '/')
        {
            ++read_at;
        }
        length = read_at - start;
        if (length == 0U || (length == 1U && path[start] == '.'))
        {
            continue;
        }
        if (length == 2U && path[start] == '.' && path[start + 1U] == '.')
        {
            while (write_at > 1U && path[write_at - 1U] != '/')
            {
                --write_at;
            }
            if (write_at > 1U)
            {
                --write_at;
            }
            continue;
        }
        if (write_at > 1U)
        {
            path[write_at++] = '/';
        }
        (void)memmove(path + write_at, path + start, length);
        write_at += length;
    }
    path[write_at] = '\0';
}

/**
 * @brief Writes `base + "/" + path` into @p destination (no separator when @p base already
 *        ends with `/`).
 *
 * @details Purely lexical; callers normalise the result with chaos_io_normalize_path().
 * Used for matching only, never for file-system access.
 *
 * @param[out] destination       Buffer; NULL returns 0.
 * @param[in]  destination_size  Capacity in bytes; 0 returns 0.
 * @param[in]  base              Directory path; NULL or empty returns 0.
 * @param[in]  path              Relative path; NULL or empty returns 0.
 * @return Non-zero on success; 0 when the result does not fit.
 */
static inline int
chaos_io_join_paths(char *destination, size_t destination_size, const char *base, const char *path)
{
    size_t base_length;
    size_t path_length;
    size_t needs_separator;

    if (destination == NULL || destination_size == 0U || base == NULL || path == NULL)
    {
        return 0;
    }
    if (*base == '\0' || *path == '\0')
    {
        return 0;
    }

    base_length = strlen(base);
    path_length = strlen(path);
    needs_separator = (base[base_length - 1U] == '/') ? 0U : 1U;
    if (base_length + needs_separator + path_length + 1U > destination_size)
    {
        return 0;
    }

    (void)memcpy(destination, base, base_length);
    if (needs_separator != 0U)
    {
        destination[base_length] = '/';
        ++base_length;
    }
    (void)memcpy(destination + base_length, path, path_length + 1U);
    return 1;
}

/** @} */

#endif
