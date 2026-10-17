/* Demo net3: a reset on an established connection. connect() to <ip> <port> (default
 * 127.0.0.1 9092) succeeds against net_server, then one 100-byte send() returns ECONNRESET
 * under `tcp4://<any>:9092:send:ECONNRESET:1.0` (host `*`). libchaos-net matches a send
 * on a connected socket against the peer address first, so a rule naming the server port
 * selects the client's sends. Exit 9 if the connect itself fails. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    const char *ip = argc > 1 ? argv[1] : "127.0.0.1";
    int port = argc > 2 ? atoi(argv[2]) : 9092;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, ip, &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        printf("connect failed [errno %d] %s\n", errno, strerror(errno));
        return 9;
    }
    char buf[100];
    memset(buf, 'z', sizeof buf);
    ssize_t r = send(s, buf, sizeof buf, 0);
    if (r < 0) printf("send -> [errno %d] %s\n", errno, strerror(errno));
    else       printf("send -> %zd bytes (no fault)\n", r);
    close(s);
    return 0;
}
