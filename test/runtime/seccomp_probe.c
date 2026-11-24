/**
 * @file seccomp_probe.c
 * @brief Static C tracee for test_seccomp.sh: performs one intercepted operation per mode and
 *        prints the outcome for the script to compare.
 *
 * @details
 * Built -static, so no dynamic loader exists and LD_PRELOAD mode cannot reach it; every fault
 * it observes comes from chaos-init answering seccomp user notifications (SECCOMP mode). It
 * prints errno names (EIO, EACCES, ECONNREFUSED, ECONNRESET, ENOMEM; strerror() text
 * otherwise).
 *
 * Usage: seccomp_probe <mode> [arg]
 * - open <path>         open(O_RDONLY|O_CREAT): "ok" or the errno name.
 * - openms <path>       the same, printing the elapsed ms instead (LATENCY checks).
 * - read <path>         open, then read 1 byte: "ok" or the errno name of the failing call.
 * - signalled <path>    openms with SIGALRM (SA_RESTART) every 20 ms: a delayed open must
 *                       be neither cut short nor restarted and delayed again per signal.
 * - first <path>        opens twice, then once in a forked child:
 *                       "parent=<1st>,<2nd> child=<1st>" (@first is per process).
 * - connect <port>      listens on 127.0.0.1:<port> and connects to it.
 * - mmap <bytes>        anonymous mapping of that size (@size gates).
 * - waits <port>        with one byte pending, select and poll with 200 ms, then select with
 *                       no timeout: "select=<rc>,<isset>,<waited|early> poll=<rc>,<revents>
 *                       forever=<rc>"; "waited" means >= 150 ms elapsed.
 * - orphan <path> <out> exits 3 at once, leaving a child that opens <path> 300 ms later and
 *                       writes "ok" or the errno name to <out>.
 *   torn <path>         - writes ten bytes to <path> and prints the returned count and the
 *                       file's resulting size, for TORN under a trace stop.
 *   trickle <port>      - sends ten bytes over a loopback stream pair and prints what the
 *                       first recv returned and how much was left, for TRICKLE.
 *   corrupt <path>      - writes eight known bytes to <path>, reads them back and prints
 *                       how many differ and whether exactly one bit changed, for CORRUPT.
 *   netcorrupt <port>   - the same count over a loopback stream pair, for net CORRUPT.
 *   dup <port>          - sends "one", receives it, sends "two", then reads twice and
 *                       prints the three payloads, for net DUP.
 *   drop <path>         - writes ten bytes to <path>, then four, and prints what the two
 *                       writes returned and where the four landed, for write DROP.
 *   reset <port>        - closes the server end of a loopback pair and prints what the
 *                       client's next read sees, for close RESET.
 *   shared <port>       - the same with a forked child holding the server end too, which
 *                       is the case a RESET must not act on.
 *   dnsquery <name>     - sends a DNS question for <name> to 127.0.0.1:53 and prints the
 *                       elapsed ms, for the dns LATENCY rules.
 *   atwait <path>       - opens <path>, waits 600 ms, opens it again: "before=<r>
 *                       after=<r>", for the `@at=+N` delay.
 *   throttle <path>     - writes 512 KiB to <path> in two rounds and prints the elapsed ms
 *                       and whether any write came back short, for THROTTLE.
 *   late <path>         - waits three seconds, then opens <path>: a process that makes no
 *                       intercepted call while a rule file is being put in place.
 *   setuid <path>       - drops to uid 65534, then opens <path> and maps 4 MiB:
 *                       "open=<r> mmap=<r>", for what a rule can still match after a
 *                       user switch.
 *   clock <name>        - reads the clock twice (`realtime` or `monotonic`) two
 *                       milliseconds apart and prints the wall second, whether both reads
 *                       agree and whether the second one is earlier, for the time effects.
 * - fork                fork + waitpid: "ok" or the errno name.
 * - exec                execl("/bin/true"); prints the errno name only when it fails.
 *
 * Exit: 0 after printing (orphan: 3); 1 on a setup failure; 2 on bad usage.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/** @brief Symbolic name for the errnos the script compares, strerror() text otherwise. */
static const char *try_open_errno_name(int error)
{
    switch (error)
    {
    case EIO:
        return "EIO";
    case EACCES:
        return "EACCES";
    case ECONNREFUSED:
        return "ECONNREFUSED";
    case ECONNRESET:
        return "ECONNRESET";
    case ENOMEM:
        return "ENOMEM";
    default:
        return strerror(error);
    }
}

/** @brief open(O_RDONLY|O_CREAT, 0644) and close: "ok" or the errno name. */
static const char *try_open(const char *path)
{
    const int fd = open(path, O_RDONLY | O_CREAT, 0644);

    if (fd >= 0)
    {
        (void)close(fd);
        return "ok";
    }
    return try_open_errno_name(errno);
}

/** @brief Empty SIGALRM handler: the signal exists only to interrupt the delayed call. */
static void on_alarm(int signal_number)
{
    (void)signal_number;
}

/** @brief Prints how long opening @p path takes, in ms (CLOCK_MONOTONIC). */
static void print_open_ms(const char *path)
{
    struct timespec start;
    struct timespec end;

    (void)clock_gettime(CLOCK_MONOTONIC, &start);
    (void)try_open(path);
    (void)clock_gettime(CLOCK_MONOTONIC, &end);
    (void)printf(
        "%ld\n",
        (long)((end.tv_sec - start.tv_sec) * 1000L + (end.tv_nsec - start.tv_nsec) / 1000000L)
    );
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "open") == 0)
    {
        (void)printf("%s\n", try_open(argv[2]));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "read") == 0)
    {
        char byte;
        const int fd = open(argv[2], O_RDONLY);

        if (fd < 0)
        {
            (void)printf("%s\n", try_open_errno_name(errno));
            return 0;
        }
        (void)printf("%s\n", read(fd, &byte, 1U) >= 0 ? "ok" : try_open_errno_name(errno));
        (void)close(fd);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "corrupt") == 0)
    {
        /* Writes eight known bytes to <path>, reads them back and prints how many of them
         * came back different and whether exactly one bit changed. A CORRUPT rule flips
         * one bit of what the read delivered, which only the stop after the call can do. */
        const int fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0644);
        unsigned char got[8];
        int differences = 0;
        int single_bit = 1;
        size_t index;

        if (fd < 0 || write(fd, "AAAAAAAA", (size_t)8) != 8 || lseek(fd, 0, SEEK_SET) != 0)
        {
            (void)printf("setup=failed\n");
            return 0;
        }
        if (read(fd, got, sizeof(got)) != 8)
        {
            (void)printf("read=%s\n", try_open_errno_name(errno));
            (void)close(fd);
            return 0;
        }
        (void)close(fd);
        for (index = 0U; index < sizeof(got); ++index)
        {
            const unsigned char changed = (unsigned char)(got[index] ^ 'A');

            if (changed != 0U)
            {
                ++differences;
                single_bit = single_bit && (changed & (unsigned char)(changed - 1U)) == 0U;
            }
        }
        (void)printf("changed=%d onebit=%d\n", differences, differences > 0 && single_bit);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "torn") == 0)
    {
        /* Writes ten bytes to <path> and prints what write() returned, plus the bytes the
         * file ended up holding. A TORN rule shortens the count in the register before the
         * kernel reads it, so both numbers drop together -- a count the supervisor faked
         * without the call being shortened would show as a mismatch. */
        const int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        ssize_t written;
        struct stat info;

        if (fd < 0)
        {
            (void)printf("open=%s\n", try_open_errno_name(errno));
            return 0;
        }
        written = write(fd, "0123456789", (size_t)10);
        (void)close(fd);
        if (written < 0)
        {
            (void)printf("write=%s\n", try_open_errno_name(errno));
            return 0;
        }
        (void)printf(
            "wrote=%ld file=%ld\n",
            (long)written,
            stat(argv[2], &info) == 0 ? (long)info.st_size : -1L
        );
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "openms") == 0)
    {
        print_open_ms(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "signalled") == 0)
    {
        struct sigaction action;
        struct itimerval every = {{0, 20000}, {0, 20000}};

        memset(&action, 0, sizeof(action));
        action.sa_handler = on_alarm;
        action.sa_flags = SA_RESTART;
        if (sigaction(SIGALRM, &action, NULL) != 0 || setitimer(ITIMER_REAL, &every, NULL) != 0)
        {
            return 1;
        }
        print_open_ms(argv[2]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "first") == 0)
    {
        char child_result[32] = "";
        int pipe_fds[2];
        const char *first = try_open(argv[2]);
        const char *second = try_open(argv[2]);
        pid_t child;

        if (pipe(pipe_fds) != 0)
        {
            return 1;
        }
        child = fork();
        if (child == 0)
        {
            const char *result = try_open(argv[2]);

            (void)write(pipe_fds[1], result, strlen(result));
            _exit(0);
        }
        (void)close(pipe_fds[1]);
        (void)waitpid(child, NULL, 0);
        (void)read(pipe_fds[0], child_result, sizeof(child_result) - 1U);
        (void)printf("parent=%s,%s child=%s\n", first, second, child_result);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "orphan") == 0)
    {
        const pid_t child = fork();

        if (child == 0)
        {
            const struct timespec wait = {0, 300000000L};
            const char *result;
            int out;

            (void)nanosleep(&wait, NULL);
            result = try_open(argv[2]);
            out = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out >= 0)
            {
                (void)write(out, result, strlen(result));
                (void)close(out);
            }
            _exit(0);
        }
        return child > 0 ? 3 : 1;
    }
    if (argc == 3 && strcmp(argv[1], "trickle") == 0)
    {
        /* A loopback stream pair: ten bytes are sent, one recv asks for all ten, and the
         * count it returns is printed. A TRICKLE rule shortens the request in the register
         * before the kernel reads it, so the count drops below ten while the rest stays in
         * the socket -- which the second recv shows, cut to the chunk as well. */
        struct sockaddr_in address;
        char buffer[16];
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        ssize_t first;
        ssize_t second;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0 ||
            write(client, "0123456789", (size_t)10) != 10)
        {
            return 1;
        }
        first = recv(server, buffer, sizeof(buffer) > 10U ? 10U : sizeof(buffer), 0);
        second = first > 0 && first < 10 ? recv(server, buffer, (size_t)(10 - first), 0) : 0;
        (void)printf("first=%ld rest=%ld\n", (long)first, (long)second);
        (void)close(server);
        (void)close(client);
        (void)close(listener);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "netcorrupt") == 0)
    {
        /* Eight known bytes travel over a loopback stream pair and one recv takes them
         * all; printed is how many came back different and whether exactly one bit
         * changed. A net CORRUPT rule flips one bit of what the receive delivered, so only
         * the stop after the call can apply it -- at the entry stop the count is unknown. */
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        unsigned char got[8];
        int differences = 0;
        int single_bit = 1;
        size_t index;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0 ||
            write(client, "AAAAAAAA", (size_t)8) != 8)
        {
            (void)printf("setup=failed\n");
            return 0;
        }
        if (recv(server, got, sizeof(got), 0) != 8)
        {
            (void)printf("recv=%s\n", try_open_errno_name(errno));
            return 0;
        }
        for (index = 0U; index < sizeof(got); ++index)
        {
            const unsigned char changed = (unsigned char)(got[index] ^ 'A');

            if (changed != 0U)
            {
                ++differences;
                single_bit = single_bit && (changed & (unsigned char)(changed - 1U)) == 0U;
            }
        }
        (void)printf("changed=%d onebit=%d\n", differences, differences > 0 && single_bit);
        (void)close(server);
        (void)close(client);
        (void)close(listener);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "dup") == 0)
    {
        /* "one" is sent and received, "two" is sent, and the next read is the one a DUP
         * rule answers with the kept payload: it prints "one" again without the call
         * running, and "two" is still pending for the read after it. The last read asks
         * with MSG_DONTWAIT so a rule that did not replay cannot block the suite. */
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        char first[8] = {0};
        char second[8] = {0};
        char third[8] = {0};

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0 || send(client, "one", (size_t)3, 0) != 3 ||
            recv(server, first, (size_t)3, 0) != 3 || send(client, "two", (size_t)3, 0) != 3)
        {
            (void)printf("setup=failed\n");
            return 0;
        }
        if (read(server, second, (size_t)3) != 3 ||
            recv(server, third, (size_t)3, MSG_DONTWAIT) != 3)
        {
            (void)printf("first=%s short=%s\n", first, try_open_errno_name(errno));
            return 0;
        }
        (void)printf("first=%s second=%s third=%s\n", first, second, third);
        (void)close(server);
        (void)close(client);
        (void)close(listener);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "drop") == 0)
    {
        /* Ten bytes, then four. A DROP rule with `@first=1` drops the first write and has
         * to move the file offset on all the same, so the four bytes land at offset ten
         * with a hole in front of them -- which is what a lost write looks like. A
         * supervisor that reported the count without moving the offset would put the four
         * bytes at offset zero. */
        const int fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0644);
        unsigned char got[16];
        ssize_t first;
        ssize_t second;
        int zeros = 1;
        size_t index;

        if (fd < 0)
        {
            (void)printf("setup=%s\n", try_open_errno_name(errno));
            return 0;
        }
        first = write(fd, "AAAAAAAAAA", (size_t)10);
        second = write(fd, "BBBB", (size_t)4);
        (void)memset(got, 0xff, sizeof(got));
        if (lseek(fd, 0, SEEK_SET) != 0 || read(fd, got, sizeof(got)) != 14)
        {
            (void)printf(
                "wrote=%ld,%ld read=%s\n", (long)first, (long)second, try_open_errno_name(errno)
            );
            (void)close(fd);
            return 0;
        }
        (void)close(fd);
        for (index = 0U; index < 10U; ++index)
        {
            zeros = zeros && got[index] == 0U;
        }
        (void
        )printf("wrote=%ld,%ld zeros=%d tenth=%c\n", (long)first, (long)second, zeros, got[10]);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "late") == 0)
    {
        /* Nothing intercepted for three seconds: whatever the supervisor does with a rule
         * file that appears meanwhile, it does without being asked by a call. */
        const struct timespec wait = {3, 0};

        (void)nanosleep(&wait, NULL);
        (void)printf("%s\n", try_open(argv[2]));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "throttle") == 0)
    {
        /* Two rounds of 256 KiB against a rate of 256 KiB per second. The bucket starts
         * full, so the first round goes at once and the second takes about a second,
         * arriving in short writes -- whether the supervisor shortens the call in the
         * register or holds it in its delay queue, the rate is what shows. */
        static char block[262144];
        const int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        struct timespec start;
        struct timespec end;
        int shortened = 0;
        int round;

        if (fd < 0)
        {
            (void)printf("setup=%s\n", try_open_errno_name(errno));
            return 0;
        }
        (void)memset(block, 'x', sizeof(block));
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        for (round = 0; round < 2; ++round)
        {
            size_t done = 0U;

            while (done < sizeof(block))
            {
                const ssize_t wrote = write(fd, block + done, sizeof(block) - done);

                if (wrote <= 0)
                {
                    (void)printf("write=%s\n", try_open_errno_name(errno));
                    (void)close(fd);
                    return 0;
                }
                if ((size_t)wrote < sizeof(block) - done)
                {
                    shortened = 1;
                }
                done += (size_t)wrote;
            }
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        (void)close(fd);
        (void)printf(
            "ms=%ld short=%d\n",
            (long)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000),
            shortened
        );
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "atwait") == 0)
    {
        /* Two opens in one run, 600 ms apart. A rule with `@at=+N` starts counting when it
         * becomes active for this process, so only the second open is past a delay below
         * that -- and both have to be in the same run, because the next one arms the rule
         * afresh. */
        const struct timespec wait = {0, 600000000L};
        const char *before = try_open(argv[2]);

        (void)nanosleep(&wait, NULL);
        (void)printf("before=%s after=%s\n", before, try_open(argv[2]));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "dnsquery") == 0)
    {
        /* The question a resolver would send, built here so the probe needs no name
         * server: nothing listens on the port, and a UDP send succeeds all the same. The
         * supervisor reads the name out of the payload and holds the send, which is the
         * whole mechanism -- the elapsed time is what shows it. */
        unsigned char query[512];
        struct sockaddr_in server;
        struct timespec start;
        struct timespec end;
        const char *label = argv[2];
        size_t at = 12U;
        const int fd = socket(AF_INET, SOCK_DGRAM, 0);

        memset(query, 0, sizeof(query));
        query[0] = 0x12;
        query[1] = 0x34;
        query[5] = 1U; /* one question */
        while (*label != '\0')
        {
            const char *dot = strchr(label, '.');
            const size_t length = dot != NULL ? (size_t)(dot - label) : strlen(label);

            query[at++] = (unsigned char)length;
            memcpy(query + at, label, length);
            at += length;
            label = dot != NULL ? dot + 1 : label + length;
        }
        query[at++] = 0U; /* the root label */
        query[at++] = 0U;
        query[at++] = 1U; /* QTYPE A */
        query[at++] = 0U;
        query[at++] = 1U; /* QCLASS IN */

        memset(&server, 0, sizeof(server));
        server.sin_family = AF_INET;
        server.sin_port = htons(53);
        server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        if (fd < 0 ||
            sendto(fd, query, at, 0, (struct sockaddr *)&server, sizeof(server)) != (ssize_t)at)
        {
            (void)printf("send=%s\n", try_open_errno_name(errno));
            return 0;
        }
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        (void)printf(
            "%lld\n",
            (long long)((end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000
            )
        );
        (void)close(fd);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "setuid") == 0)
    {
        /* A server that drops privileges (Postgres, MySQL, Redis) becomes non-dumpable,
         * after which the kernel refuses every look into it without CAP_SYS_PTRACE: the
         * path of this open cannot be read, so a path rule does not match it. With the
         * capability it does. The supervisor says which of the two happened in its status
         * file (`unreadable=yes`). */
        void *mapping;

        if (setgid(65534) != 0 || setuid(65534) != 0)
        {
            (void)printf("setuid=%s\n", try_open_errno_name(errno));
            return 0;
        }
        /* The open names a path, which the supervisor has to read out of this process; the
         * mapping names none, so a memory rule reaches it either way. */
        (void)printf("open=%s ", try_open(argv[2]));
        mapping =
            mmap(NULL, (size_t)4 * 1024 * 1024, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        (void)printf("mmap=%s\n", mapping != MAP_FAILED ? "ok" : try_open_errno_name(errno));
        if (mapping != MAP_FAILED)
        {
            (void)munmap(mapping, (size_t)4 * 1024 * 1024);
        }
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "clock") == 0)
    {
        /* Two reads of one clock. A time rule is answered by the supervisor, which reads
         * the same clock and applies the effect: OFFSET shows in the wall second, FREEZE
         * makes both reads agree and REGRESS makes the second one earlier. Without a rule
         * the clock behaves, which is the reference the script compares against.
         *
         * The reads go through the C library, which calls the vDSO unless the supervisor
         * made its lookups fail -- so this also proves that step. */
        const int monotonic = strcmp(argv[2], "monotonic") == 0;
        const struct timespec gap = {0, 2000000L};
        struct timespec first;
        struct timespec second;

        /* Two milliseconds between the reads: a clock that runs has moved on by then, so
         * "the two agree" means the supervisor held it rather than that the host's clock
         * has a coarse tick. */
        if (clock_gettime(monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &first) != 0 ||
            nanosleep(&gap, NULL) != 0 ||
            clock_gettime(monotonic ? CLOCK_MONOTONIC : CLOCK_REALTIME, &second) != 0)
        {
            (void)printf("clock=%s\n", try_open_errno_name(errno));
            return 0;
        }
        (void)printf(
            "sec=%lld same=%d back=%d\n",
            (long long)first.tv_sec,
            first.tv_sec == second.tv_sec && first.tv_nsec == second.tv_nsec,
            second.tv_sec < first.tv_sec ||
                (second.tv_sec == first.tv_sec && second.tv_nsec < first.tv_nsec)
        );
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "shared") == 0)
    {
        /* A forked child holds the accepted end as well, so SO_LINGER set here would
         * reset the connection at the child's close instead -- out of any rule's reach.
         * The supervisor finds the second holder in /proc and leaves the close alone, so
         * the client reads end of file. The child exits only after that read. */
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int keeper[2];
        int server;
        pid_t child;
        char byte;
        ssize_t got;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (pipe(keeper) != 0 ||
            bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0)
        {
            (void)printf("setup=failed\n");
            return 0;
        }
        child = fork();
        if (child < 0)
        {
            (void)printf("fork=failed\n");
            return 0;
        }
        if (child == 0)
        {
            /* Holds the socket until the parent is done, then closes it on exit. */
            (void)close(keeper[1]);
            (void)read(keeper[0], &byte, (size_t)1);
            _exit(0);
        }
        (void)close(keeper[0]);
        if (close(server) != 0)
        {
            (void)printf("close=%s\n", try_open_errno_name(errno));
            return 0;
        }
        /* The connection is not finished while the child still holds its end, so the
         * child is let go first; what the client then reads is the answer. A RESET the
         * supervisor had set up here would arrive at that close, not at this one. */
        (void)close(keeper[1]);
        (void)waitpid(child, NULL, 0);
        got = recv(client, &byte, (size_t)1, 0);
        (void)printf("peer=%s\n", got == 0 ? "eof" : try_open_errno_name(errno));
        (void)close(client);
        (void)close(listener);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "reset") == 0)
    {
        /* The accepted end is closed while the client still holds its end. A plain close
         * sends a FIN and the client reads end of file; a RESET rule puts
         * SO_LINGER{1,0} on the socket first, so the kernel aborts the connection and the
         * client reads ECONNRESET. Only the one descriptor holds the socket, so the
         * ownership check lets the rule through. */
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        char byte;
        ssize_t got;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0)
        {
            (void)printf("setup=failed\n");
            return 0;
        }
        if (close(server) != 0)
        {
            (void)printf("close=%s\n", try_open_errno_name(errno));
            return 0;
        }
        got = recv(client, &byte, (size_t)1, 0);
        (void)printf("peer=%s\n", got == 0 ? "eof" : try_open_errno_name(errno));
        (void)close(client);
        (void)close(listener);
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "waits") == 0)
    {
        struct sockaddr_in address;
        struct timespec start;
        struct timespec end;
        struct timeval wait = {0, 200000};
        struct pollfd polled;
        fd_set readable;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);
        int server;
        int selected;
        int polled_rc;

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0 ||
            connect(client, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            (server = accept(listener, NULL, NULL)) < 0 || write(client, "x", 1U) != 1)
        {
            return 1;
        }
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
        selected = select(server + 1, &readable, NULL, NULL, &wait);
        (void)clock_gettime(CLOCK_MONOTONIC, &end);
        polled.fd = server;
        polled.events = POLLIN;
        polled.revents = POLLIN;
        polled_rc = poll(&polled, 1U, 200);
        (void)printf(
            "select=%d,%d,%s poll=%d,%d ",
            selected,
            FD_ISSET(server, &readable) ? 1 : 0,
            (end.tv_sec - start.tv_sec) * 1000L + (end.tv_nsec - start.tv_nsec) / 1000000L >= 150L
                ? "waited"
                : "early",
            polled_rc,
            (int)polled.revents
        );
        FD_ZERO(&readable);
        FD_SET(server, &readable);
        (void)printf("forever=%d\n", select(server + 1, &readable, NULL, NULL, NULL));
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "connect") == 0)
    {
        struct sockaddr_in address;
        const int listener = socket(AF_INET, SOCK_STREAM, 0);
        const int client = socket(AF_INET, SOCK_STREAM, 0);

        memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons((uint16_t)atoi(argv[2]));
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
            listen(listener, 1) != 0)
        {
            return 1;
        }
        (void)printf(
            "%s\n",
            connect(client, (struct sockaddr *)&address, sizeof(address)) == 0
                ? "ok"
                : try_open_errno_name(errno)
        );
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "mmap") == 0)
    {
        const size_t length = (size_t)strtoul(argv[2], NULL, 10);
        void *mapping =
            mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        (void)printf("%s\n", mapping != MAP_FAILED ? "ok" : try_open_errno_name(errno));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "fork") == 0)
    {
        const pid_t child = fork();

        if (child == 0)
        {
            _exit(0);
        }
        if (child > 0)
        {
            (void)waitpid(child, NULL, 0);
        }
        (void)printf("%s\n", child > 0 ? "ok" : try_open_errno_name(errno));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "exec") == 0)
    {
        (void)execl("/bin/true", "true", (char *)NULL);
        (void)printf("%s\n", try_open_errno_name(errno));
        return 0;
    }
    (void)fprintf(
        stderr,
        "usage: %s open|openms|first <path> | connect <port> | mmap <bytes> | "
        "fork | exec\n",
        argv[0]
    );
    return 2;
}
