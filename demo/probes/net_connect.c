/* net use-case 1 — connect() to a peer, report the errno. With
 * tcp4://<ip>:<port>:connect:ECONNREFUSED:p the call is refused before the syscall. */
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
    int port = argc > 2 ? atoi(argv[2]) : 6379;
    for (int i = 0; i < 5; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        inet_pton(AF_INET, ip, &a.sin_addr);
        int r = connect(s, (struct sockaddr *)&a, sizeof a);
        if (r == 0) printf("try %d: connected\n", i);
        else        printf("try %d: connect -> [errno %d] %s\n", i, errno, strerror(errno));
        close(s);
    }
    return 0;
}
