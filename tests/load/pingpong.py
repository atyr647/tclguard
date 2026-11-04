"""The same loopback ping-pong in Python, to tell what the OS can do from what Tcl's event loop does. python pingpong.py [seconds]"""
import socket, sys, threading, time
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 5
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
def serve():
    c, _ = srv.accept()
    f = c.makefile("rwb", buffering=0)
    while True:
        d = c.recv(64)
        if not d: break
        c.sendall(d)
threading.Thread(target=serve, daemon=True).start()
c = socket.create_connection(srv.getsockname()); c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
n = 0; end = time.time() + secs
while time.time() < end:
    c.sendall(b"ping\n"); c.recv(64); n += 1
print("python    blocking sockets, 2 threads    : %8.0f round trips/s" % (n / secs))
