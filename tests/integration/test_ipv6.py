#!/usr/bin/env python3
"""IPv6 end to end: listeners on '::', clients on ::1, backends on ::1, real sockets, per-/64 bans.
Skipped when the machine has no IPv6 loopback. The /64 part needs extra loopback addresses, which only Linux
(with `ip` and root) lets us add; elsewhere that part is skipped with a message."""
import sys, time, socket, os, re, subprocess, shutil
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

if not have_ipv6():
    print("SKIP IPv6 tests: no IPv6 loopback on this machine"); sys.exit(0)

def get6(port, path="/", host="x", src=None, extra="", timeout=5):
    s = socket.socket(socket.AF_INET6)
    s.settimeout(timeout)
    if src: s.bind((src, 0))
    s.connect(("::1" if not src else "::1", port))
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n".encode())
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d: break
            out += d
    except (socket.timeout, OSError): pass
    s.close()
    return out

# ============================================================ HTTP listener on ::, backend on ::1
be = HttpBackend(host="::1"); port = free_port()
g = Guard({"web6": {"type": "http", "port": port, "bind": "::", "backendHost": "::1", "backendPort": be.port,
                    "connRate": 1000, "maxConnsPerIP": 400, "reqRate": 5000}}, {"strikeThreshold": 50})
try:
    g.start()
    check("listener on '::' accepts IPv6 connections", wait_port(port, 10, host="::1"))
    r = get6(port, "/v6")
    check("an IPv6 visitor is proxied to an IPv6 backend", status(r) == 200 and b"ok:GET /v6" in r, r[:100])
    q = be.requests[-1][1] if be.requests else {}
    check("the backend sees the real IPv6 address (::1) in X-Real-IP", q.get("x-real-ip") == "::1", q)
    check("X-Forwarded-For carries the IPv6 address", q.get("x-forwarded-for", "").startswith("::1"), q)
    r = get6(port, "/x", extra="X-Forwarded-For: 2001:db8::99\r\n")
    check("a spoofed X-Forwarded-For is replaced (untrusted source)", be.requests[-1][1].get("x-forwarded-for", "").startswith("::1")
          and "2001:db8::99" not in be.requests[-1][1].get("x-forwarded-for", ""), be.requests[-1][1])
    rc, out = g.ctl("status")
    check("status reports the listener as running", "web6" in out, out[:200])
    bad = [l for l in g.stderr().splitlines() if "background error" in l or "invalid command" in l or "can't read" in l]
    check("no Tcl errors in the guard log (IPv6 HTTP)", not bad, bad[:3])
finally:
    g.cleanup(); be.stop()

# ============================================================ raw TCP relay over IPv6
echo = TcpEcho(host="::1"); port = free_port()
g = Guard({"t6": {"type": "tcp", "port": port, "bind": "::", "backendHost": "::1", "backendPort": echo.port, "connRate": 1000, "maxConnsPerIP": 400}}, {})
try:
    g.start(); assert wait_port(port, 10, host="::1")
    s = socket.socket(socket.AF_INET6); s.settimeout(5); s.connect(("::1", port)); s.sendall(b"hello v6"); d = s.recv(100); s.close()
    check("TCP relay echoes bytes over IPv6", d == b"hello v6", d)
    # PROXY protocol v1 with an IPv6 client
finally:
    g.cleanup(); echo.stop()

# ============================================================ PROXY protocol header carries the IPv6 address
echo = TcpEcho(host="::1"); port = free_port()
g = Guard({"p6": {"type": "tcp", "port": port, "bind": "::", "backendHost": "::1", "backendPort": echo.port, "proxyProtocol": "v1",
                  "connRate": 1000, "maxConnsPerIP": 400, "lazyConnect": 1}}, {})
try:
    g.start(); assert wait_port(port, 10, host="::1")
    s = socket.socket(socket.AF_INET6); s.settimeout(5); s.connect(("::1", port)); s.sendall(b"payload"); time.sleep(0.5); s.close()
    got = b"".join(echo.received)
    check("PROXY protocol v1 header names the IPv6 client (TCP6)", got.startswith(b"PROXY TCP6 ::1 ") and got.endswith(b"payload"), got[:80])
finally:
    g.cleanup(); echo.stop()

# ============================================================ UDP relay over IPv6
ue = UdpEcho(host="127.0.0.1"); port = free_port()
g = Guard({"u6": {"type": "udp", "port": port, "bind": "::", "backendHost": "127.0.0.1", "backendPort": ue.port}}, {})
try:
    g.start(); time.sleep(1.0)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM); s.settimeout(3)
    try:
        s.sendto(b"ping6", ("::1", port)); d, _ = s.recvfrom(100)
    except OSError as e: d = repr(e).encode()
    check("UDP relay round-trips a datagram from an IPv6 client", d == b"echo:ping6", d)
    s.close()
    bad = [l for l in g.stderr().splitlines() if "background error" in l or "invalid command" in l or "can't read" in l]
    check("no Tcl errors in the guard log (IPv6 UDP)", not bad, bad[:3])
finally:
    g.cleanup(); ue.stop()

# ============================================================ bans are per /64 (Linux: add real extra addresses to lo)
ip = shutil.which("ip")
added = []
def add_addr(a):
    r = subprocess.run([ip, "-6", "addr", "add", a + "/128", "dev", "lo", "nodad"], capture_output=True)
    if r.returncode == 0: added.append(a)
    return r.returncode == 0
if ip and sys.platform.startswith("linux") and add_addr("2001:db8:a::1") and add_addr("2001:db8:a::2") and add_addr("2001:db8:b::1"):
    be = HttpBackend(host="::1"); port = free_port()
    g = Guard({"web6": {"type": "http", "port": port, "bind": "::", "backendHost": "::1", "backendPort": be.port,
                        "connRate": 1000, "maxConnsPerIP": 400, "reqRate": 5000}}, {"strikeThreshold": 50})
    def from_src(src):
        try:
            s = socket.socket(socket.AF_INET6); s.settimeout(3); s.bind((src, 0)); s.connect(("::1", port))
            s.sendall(b"GET /s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            out = b""
            while True:
                d = s.recv(4096)
                if not d: break
                out += d
            s.close(); return out
        except OSError: return b""
    try:
        g.start(); assert wait_port(port, 10, host="::1")
        check("a visitor from 2001:db8:a::1 is served", status(from_src("2001:db8:a::1")) == 200)
        rc, out = g.ctl("ban", "2001:db8:a::1", 120, "ipv6 test")
        check("an IPv6 address can be banned", rc == 0, out)
        rc, out = g.ctl("bans")
        check("the ban is recorded for the whole /64 (2001:db8:a::/64)", "2001:db8:a::/64" in out, out)
        time.sleep(0.5)
        check("...so another address in the same /64 is refused", status(from_src("2001:db8:a::2")) == 0)
        check("...while a different /64 is served", status(from_src("2001:db8:b::1")) == 200)
        rc, out = g.ctl("unban", "2001:db8:a::2")
        check("unbanning any address of the /64 lifts it", rc == 0, out)
        time.sleep(0.3)
        check("...and the /64 is served again", status(from_src("2001:db8:a::1")) == 200)
        rc, out = g.ctl("allow", "2001:db8:b::/64"); rc2, out2 = g.ctl("ban", "2001:db8:b::1", 60, "x")
        check("an allowlisted IPv6 range cannot be banned", rc2 != 0, out2)
    finally:
        g.cleanup(); be.stop()
        for a in added: subprocess.run([ip, "-6", "addr", "del", a + "/128", "dev", "lo"], capture_output=True)
else:
    print("SKIP per-/64 ban tests: cannot add extra IPv6 loopback addresses here (needs Linux, `ip` and root)")

sys.exit(summary())
