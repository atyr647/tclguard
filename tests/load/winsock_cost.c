/* What do the raw Winsock calls cost on this machine, without Tcl?  Cross-compile: x86_64-w64-mingw32-gcc -O2 -o winsock_cost.exe winsock_cost.c -lws2_32
 *
 *   winsock_cost.exe select     per-socket cost of WSAAsyncSelect (register, unregister) next to plain socket()/closesocket()
 *   winsock_cost.exe accept 0   accepts per second for connections opened and dropped by 8 client threads: plain blocking accept + close
 *   winsock_cost.exe accept 1   the same, plus what Tcl does per connection: WSAAsyncSelect(FD_READ|FD_WRITE|FD_CLOSE) on the new socket, then WSAAsyncSelect(0)
 *   (a thread pumping the window's messages, like Tcl's socket thread, runs in every mode)
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOTIFY_MSG (WM_USER + 1)
static HWND hwnd;
static volatile LONG stop_pump, stop_clients, accepted;
static int port = 19090;

static double now(void) { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double) c.QuadPart / (double) f.QuadPart; }

static DWORD WINAPI pump(LPVOID a) {
    MSG m; (void) a;
    hwnd = CreateWindowExA(0, "STATIC", "x", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, NULL);
    while (!stop_pump) { while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) { /* discard */ } MsgWaitForMultipleObjects(0, NULL, FALSE, 50, QS_ALLINPUT); }
    return 0;
}

static DWORD WINAPI client(LPVOID a) {
    struct sockaddr_in sa; (void) a;
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((u_short) port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while (!stop_clients) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *) &sa, sizeof sa) == 0) { /* dropped at once */ }
        closesocket(s);
    }
    return 0;
}

int main(int argc, char **argv) {
    WSADATA w; int mode = argc > 2 ? atoi(argv[2]) : 0, i; HANDLE th;
    WSAStartup(MAKEWORD(2, 2), &w);
    th = CreateThread(NULL, 0, pump, NULL, 0, NULL); Sleep(300);
    if (argc > 1 && strcmp(argv[1], "select") == 0) {
        int n = 3000; double t0, t1, t2, t3;
        t0 = now(); for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); closesocket(s); } t1 = now();
        for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); WSAAsyncSelect(s, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); closesocket(s); } t2 = now();
        for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); WSAAsyncSelect(s, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); WSAAsyncSelect(s, hwnd, 0, 0); closesocket(s); } t3 = now();
        printf("socket+closesocket            %7.1f us\n", (t1 - t0) * 1e6 / n);
        printf("... + WSAAsyncSelect          %7.1f us\n", (t2 - t1) * 1e6 / n);
        printf("... + WSAAsyncSelect + undo   %7.1f us\n", (t3 - t2) * 1e6 / n);
        stop_pump = 1; return 0;
    } else {
        SOCKET ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in sa; HANDLE cl[8]; double t0; int secs = 10;
        memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((u_short) port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(ls, (struct sockaddr *) &sa, sizeof sa); listen(ls, SOMAXCONN);
        for (i = 0; i < 8; i++) cl[i] = CreateThread(NULL, 0, client, NULL, 0, NULL);
        t0 = now();
        while (now() - t0 < secs) {
            fd_set r; struct timeval tv = { 0, 100000 }; FD_ZERO(&r); FD_SET(ls, &r);
            if (select(0, &r, NULL, NULL, &tv) > 0) {
                SOCKET c = accept(ls, NULL, NULL);
                if (c == INVALID_SOCKET) continue;
                if (mode >= 1) { WSAAsyncSelect(c, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); WSAAsyncSelect(c, hwnd, 0, 0); }
                closesocket(c); accepted++;
            }
        }
        printf("accept mode %d: %.0f connections accepted and closed per second\n", mode, accepted / (now() - t0));
        stop_clients = 1; stop_pump = 1; return 0;
    }
}
