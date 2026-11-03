/* Minimal epoll HTTP backend for benchmarking: answers every request with a tiny 200.
   Fast enough that it never limits the proxy under test.   gcc -O2 -o fast_backend fast_backend.c */
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
static const char RESP[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 8081;
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 4096)) { perror("bind"); return 1; }
    fcntl(ls, F_SETFL, O_NONBLOCK);
    int ep = epoll_create1(0); struct epoll_event ev = {.events = EPOLLIN, .data.fd = ls}; epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
    struct epoll_event evs[256]; char buf[65536];
    for (;;) {
        int n = epoll_wait(ep, evs, 256, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == ls) { int c; while ((c = accept(ls, 0, 0)) >= 0) { fcntl(c, F_SETFL, O_NONBLOCK); setsockopt(c, IPPROTO_TCP, 1, &one, sizeof one);
                struct epoll_event e = {.events = EPOLLIN, .data.fd = c}; epoll_ctl(ep, EPOLL_CTL_ADD, c, &e); } continue; }
            ssize_t r = read(fd, buf, sizeof buf);
            if (r <= 0) { close(fd); continue; }
            int reqs = 0; for (char *p = buf; (p = memmem(p, buf + r - p, "\r\n\r\n", 4)); p += 4) reqs++;
            for (int k = 0; k < reqs; k++) if (write(fd, RESP, sizeof RESP - 1) < 0) break;
        }
    }
}
