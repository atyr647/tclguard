/* What do the raw Winsock calls cost on this machine, without Tcl?  Cross-compile: x86_64-w64-mingw32-gcc -O2 -o winsock_cost.exe winsock_cost.c -lws2_32
 *
 *   winsock_cost.exe select       per-socket cost of WSAAsyncSelect (register, unregister) next to plain socket()/closesocket()
 *   winsock_cost.exe accept N     accepts per second for connections opened and dropped by 96 client threads, N =
 *      0  a blocking accept() loop (what Python does)
 *      1  Tcl's design: the listener is registered with WSAAsyncSelect(FD_ACCEPT) to a window owned by a message-pumping thread, which
 *         wakes the main thread, which accepts ONE connection and closes it, then waits again
 *      2  the same, but the main thread accepts until accept() says "would block" before waiting again
 *      3  as 2, plus a registration of every accepted socket done directly (WSAAsyncSelect on, then off)
 *      4  as 3 but the registrations are synchronous messages to the pump thread, three per connection (on, on, off), as in Tcl's driver
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NOTIFY_MSG (WM_USER + 1)
static HWND hwnd; static HANDLE hAcc, hReady;
static volatile LONG stop_pump, stop_clients;
static int port = 19090;

static double now(void) { LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c); return (double) c.QuadPart / (double) f.QuadPart; }

#define SELECT_MSG (WM_USER + 2)
static LRESULT CALLBACK wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == NOTIFY_MSG) { if (WSAGETSELECTEVENT(l) == FD_ACCEPT) SetEvent(hAcc); return 0; }
    if (m == SELECT_MSG) { if (w) WSAAsyncSelect((SOCKET) l, h, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); else WSAAsyncSelect((SOCKET) l, h, 0, 0); return 0; }
    return DefWindowProcA(h, m, w, l);
}

static DWORD WINAPI pump(LPVOID a) {
    MSG m; WNDCLASSA wc; (void) a;
    memset(&wc, 0, sizeof wc); wc.lpfnWndProc = wndproc; wc.hInstance = GetModuleHandle(NULL); wc.lpszClassName = "wsc";
    RegisterClassA(&wc);
    hwnd = CreateWindowExA(0, "wsc", "x", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    SetEvent(hReady);
    while (GetMessage(&m, NULL, 0, 0) > 0) { TranslateMessage(&m); DispatchMessage(&m); }
    return 0;
}

static DWORD WINAPI client(LPVOID a) {
    struct sockaddr_in sa; (void) a;
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((u_short) port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    while (!stop_clients) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        connect(s, (struct sockaddr *) &sa, sizeof sa);
        closesocket(s);
    }
    return 0;
}

int main(int argc, char **argv) {
    WSADATA w; int mode = argc > 2 ? atoi(argv[2]) : 0, i; HANDLE th;
    hAcc = CreateEventA(NULL, FALSE, FALSE, NULL); hReady = CreateEventA(NULL, TRUE, FALSE, NULL);
    WSAStartup(MAKEWORD(2, 2), &w);
    th = CreateThread(NULL, 0, pump, NULL, 0, NULL); WaitForSingleObject(hReady, 5000);
    if (argc > 1 && strcmp(argv[1], "select") == 0) {
        int n = 3000; double t0, t1, t2, t3;
        t0 = now(); for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); closesocket(s); } t1 = now();
        for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); WSAAsyncSelect(s, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); closesocket(s); } t2 = now();
        for (i = 0; i < n; i++) { SOCKET s = socket(AF_INET, SOCK_STREAM, 0); WSAAsyncSelect(s, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); WSAAsyncSelect(s, hwnd, 0, 0); closesocket(s); } t3 = now();
        printf("socket+closesocket            %7.1f us\n", (t1 - t0) * 1e6 / n);
        printf("... + WSAAsyncSelect          %7.1f us\n", (t2 - t1) * 1e6 / n);
        printf("... + WSAAsyncSelect + undo   %7.1f us\n", (t3 - t2) * 1e6 / n);
        return 0;
    } else {
        SOCKET ls = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in sa; HANDLE cl[96]; double t0; int secs = 10; long accepted = 0, wakes = 0;
        memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((u_short) port); sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(ls, (struct sockaddr *) &sa, sizeof sa); listen(ls, SOMAXCONN);
        if (mode >= 1) WSAAsyncSelect(ls, hwnd, NOTIFY_MSG, FD_ACCEPT);
        int ext = argc > 3 && strcmp(argv[3], "ext") == 0; double tw = 0, acc_us = 0; long wacc = 0, nacc = 0;
        if (ext) secs = 28; else for (i = 0; i < 96; i++) cl[i] = CreateThread(NULL, 0, client, NULL, 0, NULL);
        t0 = now(); tw = t0;
        while (now() - t0 < secs) {
            if (ext && now() - tw >= 4.0) { printf("  window: %.0f accepts/s\n", (accepted - wacc) / (now() - tw)); fflush(stdout); wacc = accepted; tw = now(); }
            if (mode == 0) {
                double ta = now(); SOCKET c = accept(ls, NULL, NULL);
                if (c != INVALID_SOCKET) { acc_us += (now() - ta) * 1e6; nacc++; closesocket(c); accepted++; }
            } else {
                if (WaitForSingleObject(hAcc, 200) != WAIT_OBJECT_0) continue;
                wakes++;
                for (;;) {
                    double ta = now(); SOCKET c = accept(ls, NULL, NULL);
                    if (c == INVALID_SOCKET) break;
                    acc_us += (now() - ta) * 1e6; nacc++;
                    if (mode == 3) { WSAAsyncSelect(c, hwnd, NOTIFY_MSG, FD_READ | FD_WRITE | FD_CLOSE); WSAAsyncSelect(c, hwnd, 0, 0); }
                    if (mode >= 4) { SendMessage(hwnd, SELECT_MSG, 1, (LPARAM) c); SendMessage(hwnd, SELECT_MSG, 1, (LPARAM) c); SendMessage(hwnd, SELECT_MSG, 0, (LPARAM) c); }
                    closesocket(c); accepted++;
                    if (mode == 1) break;
                }
            }
        }
        printf("accept mode %d: %.0f connections accepted and closed per second (%ld wake-ups); one accept() call takes %.0f us on average\n", mode, accepted / (now() - t0), wakes, nacc ? acc_us / nacc : 0.0);
        stop_clients = 1; (void) th; (void) cl; return 0;
    }
}
