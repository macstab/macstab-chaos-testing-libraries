/* Minimal loopback TCP server for the net send:ECONNRESET demo. Runs WITHOUT
 * the chaos lib preloaded, so only the client's send() is faulted. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 9092;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); return 1; }
    listen(s, 16);
    for (;;) {
        int c = accept(s, 0, 0);
        if (c < 0) continue;
        char b[1024];
        while (recv(c, b, sizeof b, 0) > 0) { }
        close(c);
    }
}
