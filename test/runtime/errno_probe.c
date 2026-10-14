/**
 * @file errno_probe.c
 * @brief Runtime probe: an idle libchaos library never changes errno on success.
 *
 * Every successful call below starts with errno set to a sentinel and checks it is
 * still the sentinel afterwards. POSIX lets a successful call leave errno alone, and
 * applications rely on that (for example `errno = 0; ...; if (errno)`). A library
 * that runs its own stat(2), open(2) or getsockname(2) before forwarding the call
 * would leak ENOENT or ENOTCONN into errno even though the caller's call succeeded.
 *
 * Run once without a config file and once with a config file whose rules match
 * nothing here, under LD_PRELOAD of each libchaos library in turn.
 *
 * Exit code 0 on success, 1 on the first leaked errno.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SENTINEL 4242

static int g_failures = 0;

static void check(const char *what, int ok)
{
    if (!ok)
    {
        (void)fprintf(stderr, "FAIL %s: call failed (errno %d)\n", what, errno);
        g_failures++;
        return;
    }
    if (errno != SENTINEL)
    {
        (void)fprintf(stderr, "FAIL %s: errno changed to %d (%s)\n", what, errno, strerror(errno));
        g_failures++;
    }
}

int main(void)
{
    struct sockaddr_in address;
    socklen_t length = (socklen_t)sizeof(address);
    struct timespec now;
    struct timespec nap = {0, 1000000L};
    struct addrinfo *result = NULL;
    char buffer[16];
    void *mapping;
    pid_t child;
    int status;
    int listener;
    int client;
    int fd;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0)
    {
        perror("setup");
        return 2;
    }
    client = socket(AF_INET, SOCK_STREAM, 0);

    errno = SENTINEL;
    check("connect", connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    errno = SENTINEL;
    check("send", send(client, "x", 1U, 0) == 1);

    errno = SENTINEL;
    fd = open("/tmp/errno-probe.dat", O_CREAT | O_TRUNC | O_RDWR, 0600);
    check("open", fd >= 0);
    errno = SENTINEL;
    check("write", write(fd, "data", 4U) == 4);
    errno = SENTINEL;
    check("fsync", fsync(fd) == 0);
    errno = SENTINEL;
    check("pread", pread(fd, buffer, 4U, 0) == 4);
    (void)close(fd);
    (void)unlink("/tmp/errno-probe.dat");

    errno = SENTINEL;
    mapping = mmap(NULL, 1U << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap", mapping != MAP_FAILED);
    errno = SENTINEL;
    check("munmap", munmap(mapping, 1U << 20) == 0);

    errno = SENTINEL;
    check("clock_gettime", clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    errno = SENTINEL;
    check("nanosleep", nanosleep(&nap, NULL) == 0);

    errno = SENTINEL;
    child = fork();
    if (child == 0)
    {
        _exit(0);
    }
    check("fork", child > 0);
    errno = SENTINEL;
    check("waitpid", waitpid(child, &status, 0) == child);

    /* glibc's getaddrinfo() itself resets errno to 0 on success, with or without a
     * preloaded library, so only success is checked; the call still drives the dns
     * library through its config refresh. */
    if (getaddrinfo("localhost", NULL, NULL, &result) != 0)
    {
        (void)fprintf(stderr, "FAIL getaddrinfo: call failed\n");
        g_failures++;
    }
    if (result != NULL)
    {
        freeaddrinfo(result);
    }

    (void)close(client);
    (void)close(listener);
    if (g_failures == 0)
    {
        (void)printf("errno untouched by every successful call\n");
    }
    return g_failures == 0 ? 0 : 1;
}
