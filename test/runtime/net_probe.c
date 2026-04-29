#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static time_t g_config_stamp = 1000;

static long long elapsed_ms(const struct timespec *start, const struct timespec *end)
{
    long long seconds = (long long)(end->tv_sec - start->tv_sec);
    long long nanos = (long long)(end->tv_nsec - start->tv_nsec);

    return seconds * 1000LL + nanos / 1000000LL;
}

static int write_config(const char *line)
{
    struct timespec times[2];
    FILE *config = fopen("/tmp/.chaos-net.conf", "w");

    if (config == NULL)
    {
        return 200;
    }
    if (fprintf(config, "%s\n", line) < 0)
    {
        fclose(config);
        return 201;
    }
    if (fflush(config) != 0)
    {
        fclose(config);
        return 202;
    }

    times[0].tv_sec = g_config_stamp++;
    times[0].tv_nsec = 0L;
    times[1] = times[0];
    if (futimens(fileno(config), times) != 0)
    {
        fclose(config);
        return 203;
    }
    if (fclose(config) != 0)
    {
        return 204;
    }

    return 0;
}

static int set_reuseaddr(int fd)
{
    int enabled = 1;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, (socklen_t)sizeof(enabled)) != 0)
    {
        return 1;
    }
    return 0;
}

static void set_loopback_v4(struct sockaddr_in *address, unsigned short port)
{
    (void)memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &address->sin_addr) != 1)
    {
        abort();
    }
}

static int create_tcp_listener(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return -1;
    }
    set_loopback_v4(&address, port);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_tcp(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    set_loopback_v4(&address, port);
    if (connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_tcp_pair(unsigned short port, int *server_fd, int *client_fd)
{
    int listener = create_tcp_listener(port);
    int client;
    int server;

    if (listener < 0 || server_fd == NULL || client_fd == NULL)
    {
        if (listener >= 0)
        {
            close(listener);
        }
        return -1;
    }

    client = connect_tcp(port);
    if (client < 0)
    {
        close(listener);
        return -1;
    }

    server = accept(listener, NULL, NULL);
    close(listener);
    if (server < 0)
    {
        close(client);
        return -1;
    }

    *server_fd = server;
    *client_fd = client;
    return 0;
}

static int create_udp_bound(unsigned short port)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
    {
        return -1;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return -1;
    }
    set_loopback_v4(&address, port);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int wait_child_ok(pid_t pid, int failure_code)
{
    int status;

    if (waitpid(pid, &status, 0) < 0)
    {
        return failure_code;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return failure_code + 1;
    }
    return 0;
}

static int probe_bind_errno(void)
{
    struct sockaddr_in address;
    int rc;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        return 10;
    }
    rc = write_config("tcp4://127.0.0.1:41001:bind:EMFILE:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41001U);
    errno = 0;
    rc = bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    if (rc != -1 || errno != EMFILE)
    {
        return 11;
    }
    return 0;
}

static int probe_listen_latency(void)
{
    struct sockaddr_in address;
    struct timespec start;
    struct timespec end;
    long long duration_ms;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int rc;

    if (fd < 0)
    {
        return 20;
    }
    if (set_reuseaddr(fd) != 0)
    {
        close(fd);
        return 21;
    }
    set_loopback_v4(&address, 41002U);
    if (bind(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return 22;
    }
    rc = write_config("tcp4://127.0.0.1:41002:listen:LATENCY:200");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    {
        close(fd);
        return 23;
    }
    if (listen(fd, 16) != 0)
    {
        close(fd);
        return 24;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
    {
        close(fd);
        return 25;
    }
    close(fd);
    duration_ms = elapsed_ms(&start, &end);
    return duration_ms >= 150LL ? 0 : 26;
}

static int probe_connect_errno(void)
{
    struct sockaddr_in address;
    int listener = create_tcp_listener(41003U);
    int fd;
    int rc;

    if (listener < 0)
    {
        return 30;
    }
    rc = write_config("tcp4://127.0.0.1:41003:connect:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        close(listener);
        return 31;
    }
    set_loopback_v4(&address, 41003U);
    errno = 0;
    rc = connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    close(listener);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 32;
    }
    return 0;
}

static int probe_accept_errno(void)
{
    int listener = create_tcp_listener(41004U);
    int rc;

    if (listener < 0)
    {
        return 40;
    }
    rc = write_config("tcp4://127.0.0.1:41004:accept:EAGAIN:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    errno = 0;
    rc = accept(listener, NULL, NULL);
    close(listener);
    if (rc != -1 || errno != EAGAIN)
    {
        return 41;
    }
    return 0;
}

static int probe_accept4_errno(void)
{
    int listener = create_tcp_listener(41011U);
    int rc;

    if (listener < 0)
    {
        return 50;
    }
    rc = write_config("tcp4://127.0.0.1:41011:accept:EAGAIN:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    errno = 0;
    rc = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    close(listener);
    if (rc != -1 || errno != EAGAIN)
    {
        return 51;
    }
    return 0;
}

static int probe_send_latency(void)
{
    int listener = create_tcp_listener(41005U);
    pid_t child;
    int accepted;
    char buffer[8];
    int rc;

    if (listener < 0)
    {
        return 60;
    }
    rc = write_config("tcp4://127.0.0.1:41005:send:LATENCY:200");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(listener);
        return 61;
    }
    if (child == 0)
    {
        struct timespec start;
        struct timespec end;
        long long duration_ms;
        int fd = connect_tcp(41005U);

        if (fd < 0)
        {
            _exit(1);
        }
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        {
            _exit(2);
        }
        if (send(fd, "ping", 4U, 0) != 4)
        {
            _exit(3);
        }
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0)
        {
            _exit(4);
        }
        close(fd);
        duration_ms = elapsed_ms(&start, &end);
        _exit(duration_ms >= 150LL ? 0 : 5);
    }

    accepted = accept(listener, NULL, NULL);
    if (accepted < 0)
    {
        close(listener);
        (void)wait_child_ok(child, 62);
        return 62;
    }
    if (recv(accepted, buffer, sizeof(buffer), 0) != 4)
    {
        close(accepted);
        close(listener);
        (void)wait_child_ok(child, 63);
        return 63;
    }
    close(accepted);
    close(listener);
    return wait_child_ok(child, 64);
}

static int probe_recv_corrupt(void)
{
    int listener = create_tcp_listener(41006U);
    pid_t child;
    int accepted;
    char buffer[8];
    int rc;

    if (listener < 0)
    {
        return 70;
    }
    rc = write_config("tcp4://127.0.0.1:41006:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(listener);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(listener);
        return 71;
    }
    if (child == 0)
    {
        int fd = connect_tcp(41006U);

        if (fd < 0)
        {
            _exit(1);
        }
        if (send(fd, "ABCD", 4U, 0) != 4)
        {
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    accepted = accept(listener, NULL, NULL);
    if (accepted < 0)
    {
        close(listener);
        (void)wait_child_ok(child, 72);
        return 72;
    }
    if (recv(accepted, buffer, sizeof(buffer), 0) != 4)
    {
        close(accepted);
        close(listener);
        (void)wait_child_ok(child, 73);
        return 73;
    }
    close(accepted);
    close(listener);
    if (memcmp(buffer, "ABCD", 4U) == 0)
    {
        (void)wait_child_ok(child, 74);
        return 74;
    }
    return wait_child_ok(child, 75);
}

static int probe_sendto_errno(void)
{
    struct sockaddr_in address;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 80;
    }
    rc = write_config("udp4://127.0.0.1:41007:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41007U);
    errno = 0;
    rc = (int
    )sendto(fd, "udp", 3U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address));
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 81;
    }
    return 0;
}

static int probe_recvfrom_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41008U);
    pid_t child;
    char buffer[8];
    int rc;

    if (receiver < 0)
    {
        return 90;
    }
    rc = write_config("udp4://127.0.0.1:41008:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(receiver);
        return 91;
    }
    if (child == 0)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0)
        {
            _exit(1);
        }
        set_loopback_v4(&address, 41008U);
        if (sendto(
                fd, "WXYZ", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
            ) != 4)
        {
            close(fd);
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    if (recvfrom(receiver, buffer, sizeof(buffer), 0, NULL, NULL) != 4)
    {
        close(receiver);
        (void)wait_child_ok(child, 92);
        return 92;
    }
    close(receiver);
    if (memcmp(buffer, "WXYZ", 4U) == 0)
    {
        (void)wait_child_ok(child, 93);
        return 93;
    }
    return wait_child_ok(child, 94);
}

static int probe_sendmsg_errno(void)
{
    struct sockaddr_in address;
    struct iovec iov;
    struct msghdr message;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 100;
    }
    rc = write_config("udp4://127.0.0.1:41009:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41009U);
    iov.iov_base = (void *)"msg";
    iov.iov_len = 3U;
    (void)memset(&message, 0, sizeof(message));
    message.msg_name = &address;
    message.msg_namelen = (socklen_t)sizeof(address);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    errno = 0;
    rc = (int)sendmsg(fd, &message, 0);
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 101;
    }
    return 0;
}

static int probe_recvmsg_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41010U);
    pid_t child;
    char buffer[8];
    struct iovec iov;
    struct msghdr message;
    int rc;

    if (receiver < 0)
    {
        return 110;
    }
    rc = write_config("udp4://127.0.0.1:41010:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    child = fork();
    if (child < 0)
    {
        close(receiver);
        return 111;
    }
    if (child == 0)
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);

        if (fd < 0)
        {
            _exit(1);
        }
        set_loopback_v4(&address, 41010U);
        if (sendto(
                fd, "LMNO", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
            ) != 4)
        {
            close(fd);
            _exit(2);
        }
        close(fd);
        _exit(0);
    }

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    if (recvmsg(receiver, &message, 0) != 4)
    {
        close(receiver);
        (void)wait_child_ok(child, 112);
        return 112;
    }
    close(receiver);
    if (memcmp(buffer, "LMNO", 4U) == 0)
    {
        (void)wait_child_ok(child, 113);
        return 113;
    }
    return wait_child_ok(child, 114);
}

static int probe_socket_errno(void)
{
    int fd;
    int rc = write_config("tcp4://*:0:socket:EAFNOSUPPORT:1.0");

    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd != -1 || errno != EAFNOSUPPORT)
    {
        if (fd >= 0)
        {
            close(fd);
        }
        return 140;
    }
    return 0;
}

static int probe_socketpair_errno(void)
{
    int sv[2];
    int rc = write_config("unix://*:socket:EMFILE:1.0");

    if (rc != 0)
    {
        return rc;
    }
    errno = 0;
    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (rc != -1 || errno != EMFILE)
    {
        if (rc == 0)
        {
            close(sv[0]);
            close(sv[1]);
        }
        return 141;
    }
    return 0;
}

static int probe_shutdown_errno(void)
{
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41012U, &server_fd, &client_fd) != 0)
    {
        return 142;
    }
    rc = write_config("tcp4://127.0.0.1:41012:shutdown:ENOTCONN:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    errno = 0;
    rc = shutdown(server_fd, SHUT_RDWR);
    close(server_fd);
    close(client_fd);
    if (rc != -1 || errno != ENOTCONN)
    {
        return 143;
    }
    return 0;
}

static int probe_poll_timeout(void)
{
    struct pollfd pfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41013U, &server_fd, &client_fd) != 0)
    {
        return 144;
    }
    rc = write_config("tcp4://127.0.0.1:41013:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "poll", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 145;
    }

    pfd.fd = server_fd;
    pfd.events = POLLIN;
    pfd.revents = POLLIN;
    rc = poll(&pfd, 1U, 1000);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || pfd.revents != 0)
    {
        return 146;
    }
    return 0;
}

static int probe_ppoll_timeout(void)
{
    struct pollfd pfd;
    struct timespec timeout;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41014U, &server_fd, &client_fd) != 0)
    {
        return 147;
    }
    rc = write_config("tcp4://127.0.0.1:41014:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "ppol", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 148;
    }

    pfd.fd = server_fd;
    pfd.events = POLLIN;
    pfd.revents = POLLIN;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0L;
    rc = ppoll(&pfd, 1U, &timeout, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || pfd.revents != 0)
    {
        return 149;
    }
    return 0;
}

static int probe_select_timeout(void)
{
    fd_set readfds;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41015U, &server_fd, &client_fd) != 0)
    {
        return 150;
    }
    rc = write_config("tcp4://127.0.0.1:41015:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "sele", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 151;
    }

    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    rc = select(server_fd + 1, &readfds, NULL, NULL, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || FD_ISSET(server_fd, &readfds))
    {
        return 152;
    }
    return 0;
}

static int probe_pselect_timeout(void)
{
    fd_set readfds;
    struct timespec timeout;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41016U, &server_fd, &client_fd) != 0)
    {
        return 153;
    }
    rc = write_config("tcp4://127.0.0.1:41016:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }
    if (send(client_fd, "psel", 4U, 0) != 4)
    {
        close(server_fd);
        close(client_fd);
        return 154;
    }

    FD_ZERO(&readfds);
    FD_SET(server_fd, &readfds);
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0L;
    rc = pselect(server_fd + 1, &readfds, NULL, NULL, &timeout, NULL);
    close(server_fd);
    close(client_fd);
    if (rc != 0 || FD_ISSET(server_fd, &readfds))
    {
        return 155;
    }
    return 0;
}

static int probe_epoll_wait_timeout(void)
{
    struct epoll_event event;
    struct epoll_event events[1];
    int epfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41017U, &server_fd, &client_fd) != 0)
    {
        return 156;
    }
    rc = write_config("tcp4://127.0.0.1:41017:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    epfd = epoll_create1(0);
    if (epfd < 0)
    {
        close(server_fd);
        close(client_fd);
        return 157;
    }
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &event) != 0)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 158;
    }
    if (send(client_fd, "epol", 4U, 0) != 4)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 159;
    }

    rc = epoll_wait(epfd, events, 1, 1000);
    close(epfd);
    close(server_fd);
    close(client_fd);
    return rc == 0 ? 0 : 160;
}

static int probe_epoll_pwait_timeout(void)
{
    struct epoll_event event;
    struct epoll_event events[1];
    int epfd;
    int server_fd;
    int client_fd;
    int rc;

    if (create_tcp_pair(41018U, &server_fd, &client_fd) != 0)
    {
        return 161;
    }
    rc = write_config("tcp4://127.0.0.1:41018:poll:TIMEOUT:1.0");
    if (rc != 0)
    {
        close(server_fd);
        close(client_fd);
        return rc;
    }

    epfd = epoll_create1(0);
    if (epfd < 0)
    {
        close(server_fd);
        close(client_fd);
        return 162;
    }
    (void)memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = server_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, server_fd, &event) != 0)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 163;
    }
    if (send(client_fd, "epwt", 4U, 0) != 4)
    {
        close(epfd);
        close(server_fd);
        close(client_fd);
        return 164;
    }

    rc = epoll_pwait(epfd, events, 1, 1000, NULL);
    close(epfd);
    close(server_fd);
    close(client_fd);
    return rc == 0 ? 0 : 165;
}

static int probe_sendmmsg_errno(void)
{
    struct sockaddr_in address;
    struct iovec iov;
    struct mmsghdr message;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int rc;

    if (fd < 0)
    {
        return 166;
    }
    rc = write_config("udp4://127.0.0.1:41019:send:EHOSTUNREACH:1.0");
    if (rc != 0)
    {
        close(fd);
        return rc;
    }

    set_loopback_v4(&address, 41019U);
    iov.iov_base = (void *)"bat";
    iov.iov_len = 3U;
    (void)memset(&message, 0, sizeof(message));
    message.msg_hdr.msg_name = &address;
    message.msg_hdr.msg_namelen = (socklen_t)sizeof(address);
    message.msg_hdr.msg_iov = &iov;
    message.msg_hdr.msg_iovlen = 1;

    errno = 0;
    rc = sendmmsg(fd, &message, 1U, 0U);
    close(fd);
    if (rc != -1 || errno != EHOSTUNREACH)
    {
        return 167;
    }
    return 0;
}

static int probe_recvmmsg_corrupt(void)
{
    struct sockaddr_in address;
    int receiver = create_udp_bound(41020U);
    int sender;
    char buffer[8];
    struct iovec iov;
    struct mmsghdr message;
    int rc;

    if (receiver < 0)
    {
        return 168;
    }
    rc = write_config("udp4://127.0.0.1:41020:recv:CORRUPT:1.0");
    if (rc != 0)
    {
        close(receiver);
        return rc;
    }

    sender = socket(AF_INET, SOCK_DGRAM, 0);
    if (sender < 0)
    {
        close(receiver);
        return 169;
    }
    set_loopback_v4(&address, 41020U);
    if (sendto(
            sender, "BULK", 4U, 0, (const struct sockaddr *)&address, (socklen_t)sizeof(address)
        ) != 4)
    {
        close(sender);
        close(receiver);
        return 170;
    }
    close(sender);

    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    (void)memset(&message, 0, sizeof(message));
    message.msg_hdr.msg_iov = &iov;
    message.msg_hdr.msg_iovlen = 1;
    rc = recvmmsg(receiver, &message, 1U, 0U, NULL);
    close(receiver);
    if (rc != 1)
    {
        return 171;
    }
    if (memcmp(buffer, "BULK", 4U) == 0)
    {
        return 172;
    }
    return 0;
}

int main(void)
{
    int rc;

    signal(SIGPIPE, SIG_IGN);

    rc = probe_bind_errno();
    if (rc != 0)
        return rc;
    rc = probe_listen_latency();
    if (rc != 0)
        return rc;
    rc = probe_connect_errno();
    if (rc != 0)
        return rc;
    rc = probe_accept_errno();
    if (rc != 0)
        return rc;
    rc = probe_accept4_errno();
    if (rc != 0)
        return rc;
    rc = probe_send_latency();
    if (rc != 0)
        return rc;
    rc = probe_recv_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_sendto_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvfrom_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_sendmsg_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvmsg_corrupt();
    if (rc != 0)
        return rc;
    rc = probe_socket_errno();
    if (rc != 0)
        return rc;
    rc = probe_socketpair_errno();
    if (rc != 0)
        return rc;
    rc = probe_shutdown_errno();
    if (rc != 0)
        return rc;
    rc = probe_poll_timeout();
    if (rc != 0)
        return rc;
    rc = probe_ppoll_timeout();
    if (rc != 0)
        return rc;
    rc = probe_select_timeout();
    if (rc != 0)
        return rc;
    rc = probe_pselect_timeout();
    if (rc != 0)
        return rc;
    rc = probe_epoll_wait_timeout();
    if (rc != 0)
        return rc;
    rc = probe_epoll_pwait_timeout();
    if (rc != 0)
        return rc;
    rc = probe_sendmmsg_errno();
    if (rc != 0)
        return rc;
    rc = probe_recvmmsg_corrupt();
    if (rc != 0)
        return rc;

    return 0;
}
