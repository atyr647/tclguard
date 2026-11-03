#!/usr/bin/env python3
"""When strangers fill the global connection cap (a slow-drip attack from many addresses), the last quarter of it
is still available to visitors the guard already knows. Measured before this existed: 1500 slow connections from 300
addresses made thousands of an ordinary visitor's attempts fail. Unix only (needs 127.x source addresses)."""
import sys, os, re, socket, time
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

if sys.platform != "linux":
    print("SKIP reserve test: needs the whole 127/8 range as source addresses (Linux)"); sys.exit(0)

def conn(src, port, timeout=3):
    s = socket.socket(); s.settimeout(timeout); s.bind((src, 0)); s.connect(("127.0.0.1", port)); return s

def get_from(src, port, path="/"):
    s = conn(src, port)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except OSError: pass
    s.close(); return out

def become_known(src, port):
    """Four requests on one keep-alive connection: what the guard counts as a visitor that behaves (3+ completed requests)."""
    s = conn(src, port); ok = 0
    for i in range(4):
        s.sendall(b"GET /hello%d HTTP/1.1\r\nHost: x\r\n\r\n" % i)
        buf = b""
        while b"\r\n\r\n" not in buf: buf += s.recv(65536)
        head, _, rest = buf.partition(b"\r\n\r\n")
        m = re.search(rb"Content-Length: (\d+)", head, re.I)
        n = int(m.group(1)) if m else 0
        while len(rest) < n: rest += s.recv(65536)
        ok += status(head) == 200
    s.close(); return ok == 4

def refused(s):
    """The guard closes a refused connection at once; an admitted one sits waiting for its request."""
    s.settimeout(0.4)
    try: return s.recv(1) == b""
    except socket.timeout: return False
    except OSError: return True

CAP = 200
be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "maxConns": 100000, "maxConnsPerIP": 50, "connRate": 1000000,
                   "reqRate": 100000, "headerTimeout": 120, "idleTimeout": 300}}, {"maxConnections": CAP, "strikeThreshold": 1000000})
socks = []
try:
    g.start(); assert wait_port(port)
    check("a visitor makes four ordinary requests and becomes known", become_known("127.0.9.9", port))
    # strangers: 20 per address until the guard starts refusing
    admitted = 0; i = 0; refusedAt = None
    while refusedAt is None and i < 400:
        src = "127.0.5.%d" % (1 + i // 20)
        try: s = conn(src, port)
        except OSError: refusedAt = admitted; break
        i += 1
        if refused(s): s.close(); refusedAt = admitted; break
        socks.append(s); admitted += 1
    print("INFO strangers admitted before the first refusal:", admitted, "of cap", CAP)
    check("strangers are admitted up to about three quarters of the cap, then refused", 0.6 * CAP <= admitted <= 0.9 * CAP, admitted)
    time.sleep(0.5)
    r = get_from("127.0.6.2", port)
    check("a new stranger is turned away while they hold that", status(r) != 200, r[:80])
    r = get_from("127.0.9.9", port, "/known")
    check("...but the visitor the guard already knows is still served", status(r) == 200, r[:80])
    check("the guard is alive and logged no Tcl errors", g.proc.poll() is None and "background error" not in g.stderr(), g.stderr()[-300:])
    for s in socks: s.close()
    socks = []
    time.sleep(1.0)
    check("after the strangers leave, new visitors are served again", status(get_from("127.0.6.3", port)) == 200)
finally:
    for s in socks:
        try: s.close()
        except Exception: pass
    g.cleanup(); be.stop()
sys.exit(summary())
