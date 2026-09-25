/* net use-case (blog fault 2) — a mid-stream reset. The connection establishes,
 * then ONE send() returns ECONNRESET. libchaos-net matches send() on the PEER
 * endpoint, so tcp4://*:<port>:send:ECONNRESET:p fires for a client sending to
 * a peer on <port>. */
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
