#!/usr/bin/env python3
import sys, time, socket, os, re, struct, threading
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

def wait_until(fn, timeout=8, step=0.1):
    t = time.time() + timeout
    while time.time() < t:
        if fn(): return True
        time.sleep(step)
    return False

def refused(port):
    """True if a fresh connection is closed immediately without service."""
    try:
        s = socket.create_connection(("127.0.0.1", port), 3); s.settimeout(2)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        d = s.recv(100); s.close()
        return d == b""
    except OSError: return True

# =====================================================================  HTTP
be = HttpBackend(); port = free_port(); sp = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "maxConnsPerIP": 8, "connRate": 1000,
                   "reqRate": 40, "reqWindow": 10, "challengeTtl": 600, "trustedProxies": "127.0.0.1"}},
          {"strikeThreshold": 6, "strikeLeakPerSec": 0, "banSteps": "{5 30}"})
try:
    g.start(); assert wait_port(port)

    # ---- trusted proxy: real client IP comes from X-Forwarded-For ----
    r = get("/tp", extra="X-Forwarded-For: 203.0.113.7\r\n", port=port)
    q = be.requests[-1][1]
    check("trusted proxy: backend sees chain and real client", q.get("x-real-ip") == "203.0.113.7" and q.get("x-forwarded-for", "").startswith("203.0.113.7") and q["x-forwarded-for"].endswith("127.0.0.1"), q)

    # ---- challenge: pin level 2, cookie dance ----
    rc, out = g.ctl("level", 2); check("ctl level 2", rc == 0, out)
    # trusted proxy sends XFF so each test client gets its own identity
    xff = "X-Forwarded-For: 198.51.100.9\r\n"
    r = get("/page?x=1", extra=xff, port=port)
    m = re.search(rb"Set-Cookie: (tg_ok=[^;]+);", r)
    check("under attack: unverified GET gets 307 + cookie", status(r) == 307 and m and b"Location: /page?x=1" in r, r[:200])
    ck = m.group(1).decode() if m else ""
    n0 = len(be.requests)
    r = get("/page?x=1", extra=xff + f"Cookie: {ck}\r\n", port=port)
    check("valid cookie passes the challenge", status(r) == 200 and len(be.requests) == n0 + 1, r[:80])
    r = get("/page", extra="X-Forwarded-For: 198.51.100.77\r\nCookie: tg_ok=9999999999.00000000000000000000000000000000\r\n", port=port)
    check("forged cookie is rejected", status(r) == 307, r[:60])
    r = http_raw(port, b"POST /f HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.55\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    check("unverified POST under challenge -> 403", status(r) == 403, r[:60])
    r = get("//evil.example/x", extra="X-Forwarded-For: 198.51.100.56\r\n", port=port)
    check("challenge redirect is never protocol-relative (no open redirect)", b"Location: /evil.example/x" in r and b"Location: //" not in r, r[:200])
    rc, out = g.ctl("level", "auto")
    time.sleep(0.2)

    # ---- request flood from one (proxied) client -> strikes -> ban -> refused ----
    flood_xff = "X-Forwarded-For: 203.0.113.99\r\n"
    got429 = 0
    for i in range(10):
        s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
        try:
            for j in range(60):
                s.sendall(f"GET /f HTTP/1.1\r\nHost: x\r\n{flood_xff}\r\n".encode())
                d = s.recv(4096)
                if status(d) == 429: got429 += 1; break
                if d == b"": break
        except OSError: pass
        s.close()
        rc, out = g.ctl("bans")
        if "203.0.113.99" in out: break
    rc, out = g.ctl("bans")
    check("request flood: 429s then automatic ban of the real client", got429 >= 1 and "203.0.113.99" in out, (got429, out[:200]))
    r = get("/", extra=flood_xff, port=port)
    check("banned client behind proxy is cut off", r == b"" or status(r) not in (200,), r[:60])
    # other clients unaffected
    r = get("/", extra="X-Forwarded-For: 203.0.113.100\r\n", port=port)
    check("other clients unaffected by the ban", status(r) == 200, r[:60])

    # ---- manual ban / unban via CLI and escalation bookkeeping ----
    rc, out = g.ctl("ban", "198.18.0.5", 60, "test", "ban"); check("ctl ban", rc == 0 and "banned 198.18.0.5" in out, out)
    rc, out = g.ctl("bans"); check("ctl bans lists it with reason", "198.18.0.5" in out and "test ban" in out, out)
    rc, out = g.ctl("unban", "198.18.0.5"); check("ctl unban", rc == 0, out)
    rc, out = g.ctl("ban", "not-an-ip"); check("ctl rejects invalid address", rc != 0, out)
    rc, out = g.ctl("nonsense"); check("ctl rejects unknown command", rc != 0 and "unknown command" in out, out)
    # bad token
    r = subprocess.run(["tclsh8.6", MAIN, "ctl", "--config", g.conf, "status"], capture_output=True, text=True, env={**os.environ})
    check("ctl works with the right token", r.returncode == 0)
    bad = open(g.conf).read().replace(g.token, "x" * 32)
    open(g.conf + ".bad", "w").write(bad)
    r = subprocess.run(["tclsh8.6", MAIN, "ctl", "--config", g.conf + ".bad", "status"], capture_output=True, text=True)
    check("ctl with wrong token is refused", r.returncode != 0 and "authentication failed" in r.stderr, r.stderr)
    rc, out = g.ctl("status"); check("status shows summary and listeners", "Threat level" in out and "Listeners:" in out and "web" in out, out[:300])

    # ---- allowlist protects from bans ----
    rc, out = g.ctl("allow", "203.0.113.200"); check("ctl allow", rc == 0, out)
    rc, out = g.ctl("ban", "203.0.113.200"); check("allowlisted address cannot be banned", rc != 0 and "allowlist" in out, out)
    rc, out = g.ctl("disallow", "203.0.113.200"); check("ctl disallow", rc == 0, out)

    # ---- websocket upgrade tunnel ----
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.150\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n")
    d = b""
    while b"\r\n\r\n" not in d: d += s.recv(4096)
    check("websocket handshake passes (101)", status(d) == 101, d[:60])
    s.sendall(b"\x81\x05hello")
    d2 = b""
    while b"echo:" not in d2: d2 += s.recv(4096)
    check("websocket bytes tunnel both ways after 101", d2.endswith(b"\x81\x05hello"), d2)
    s.sendall(b"GET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n")   # now just opaque data
    time.sleep(0.3)
    check("data after 101 is opaque (not parsed as HTTP)", True)
    s.close()
    s = socket.create_connection(("127.0.0.1", port), 5); s.settimeout(5)
    s.sendall(b"GET /a HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.151\r\n\r\n"); s.recv(4096)
    s.sendall(b"GET /ws HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.151\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    d = s.recv(4096)
    check("Upgrade as a later request on a connection is refused", status(d) == 400, d[:60])
    s.close()

    # ---- backend down -> 502, then recovers ----
    be.stop(); time.sleep(0.2)
    r = get("/", extra="X-Forwarded-For: 203.0.113.170\r\n", port=port)
    check("backend down -> 502 Bad Gateway", status(r) == 502, r[:80])
    be2 = HttpBackend(be.port)
    time.sleep(0.2)
    r = get("/", extra="X-Forwarded-For: 203.0.113.171\r\n", port=port)
    check("backend recovers transparently", status(r) == 200, r[:80])

    # ---- persistence across restart ----
    rc, out = g.ctl("ban", "198.18.9.9", 0, "persist", "me")
    time.sleep(0.2)
    g.ctl("stop"); g.proc.wait(8)
    check("graceful stop via ctl", g.proc.returncode is not None)
    g.start()
    rc, out = g.ctl("bans")
    check("bans survive a restart", "198.18.9.9" in out, out)
finally:
    g.stop(); be.stop()
    tail = g.stderr().splitlines()
    errs = [l for l in tail if "background error" in l]
    check("no background errors in guard log", not errs, errs[:3])
    if errs: print("\n".join(tail[-15:]))
    g.cleanup()

# =====================================================================  TCP
echo = TcpEcho(); tport = free_port()
g = Guard({"mc": {"type": "tcp", "port": tport, "backendPort": echo.port, "maxConnsPerIP": 3, "connRate": 8, "connWindow": 10,
                  "firstByteTimeout": 2, "idleTimeout": 6}},
          {"strikeThreshold": 5, "strikeLeakPerSec": 0, "banSteps": "{4 20}"})
try:
    g.start(); assert wait_port(tport)
    s = socket.create_connection(("127.0.0.1", tport), 5); s.settimeout(5)
    s.sendall(b"\x00\x01hello"); d = s.recv(100)
    check("TCP relay echoes bytes", d == b"\x00\x01hello", d)
    big = os.urandom(3_000_000); got = b""
    def reader():
        global got
        while len(got) < len(big):
            x = s.recv(65536)
            if not x: break
            got += x
    th = threading.Thread(target=reader); th.start()
    s.sendall(big); th.join(20)
    check("3 MB bidirectional transfer intact (flow control)", got == big, len(got))
    s.close()

    t = time.time(); s = socket.create_connection(("127.0.0.1", tport), 5); s.settimeout(8)
    d = s.recv(10); el = time.time() - t
    check("silent connection dropped after firstByteTimeout", d == b"" and 1.5 < el < 4.5, round(el, 1)); s.close()

    s = socket.create_connection(("127.0.0.1", tport), 5); s.settimeout(12)
    s.sendall(b"x"); s.recv(10); t = time.time()
    try: d = s.recv(10)
    except socket.timeout: d = b"T"
    check("idle connection closed after idleTimeout", d == b"" and time.time() - t < 9, round(time.time() - t, 1)); s.close()

    time.sleep(0.5)
    held = []
    for i in range(6):
        try:
            c = socket.create_connection(("127.0.0.1", tport), 3); c.settimeout(0.8); c.sendall(b"hi"); held.append(c)
        except OSError: pass
    time.sleep(0.4)
    ok = 0
    for c in held:
        try:
            if c.recv(10) == b"hi": ok += 1
        except OSError: pass
    check("TCP per-IP cap (3)", ok == 3, ok)
    for c in held: c.close()
    # connection flood -> ban
    for i in range(30):
        try:
            c = socket.create_connection(("127.0.0.1", tport), 2); c.close()
        except OSError: pass
    rc, out = g.ctl("bans")
    check("TCP connection flood leads to a ban", "127.0.0.1" in out, out[:200])
    check("banned source refused instantly", refused(tport))
    # ban expiry (4s first step) then service resumes
    ok = wait_until(lambda: "127.0.0.1" not in g.ctl("bans")[1], 12, 0.5)
    check("ban expires by itself", ok)
    time.sleep(0.5)
    s = socket.create_connection(("127.0.0.1", tport), 5); s.settimeout(5); s.sendall(b"back"); d = s.recv(10)
    check("service resumes after the ban expires", d == b"back", d); s.close()
finally:
    g.stop(); echo.stop()
    tail = g.stderr().splitlines()
    errs = [l for l in tail if "background error" in l]
    check("no background errors in TCP guard log", not errs, errs[:3])
    g.cleanup()

# ===============================================================  PROXY protocol
rec = TcpEcho(); pport = free_port(); pport2 = free_port()
g = Guard({"p1": {"type": "tcp", "port": pport, "backendPort": rec.port, "proxyProtocol": "v1"},
           "p2": {"type": "tcp", "port": pport2, "backendPort": rec.port, "proxyProtocol": "v2"}})
try:
    g.start(); assert wait_port(pport)
    s = socket.create_connection(("127.0.0.1", pport), 5); s.settimeout(3); s.sendall(b"payload"); time.sleep(0.4)
    got = b"".join(rec.received)
    m = re.match(rb"PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 (\d+) %d\r\npayload" % pport, got)
    check("PROXY protocol v1 header delivered before payload", bool(m), got[:80]); s.close()
    rec.received.clear()
    s = socket.create_connection(("127.0.0.1", pport2), 5); s.settimeout(3); s.sendall(b"payload2"); time.sleep(0.4)
    got = b"".join(rec.received)
    sig = b"\r\n\r\n\x00\r\nQUIT\n"
    ok = got.startswith(sig) and got[12] == 0x21 and got[13] == 0x11
    if ok:
        ln = struct.unpack("!H", got[14:16])[0]
        src, dst, sport, dport = struct.unpack("!4s4sHH", got[16:16 + ln])
        ok = socket.inet_ntoa(src) == "127.0.0.1" and dport == pport2 and got[16 + ln:] == b"payload2"
    check("PROXY protocol v2 binary header is valid", ok, got[:40]); s.close()
finally:
    g.stop(); rec.stop(); g.cleanup()

# ===================================================================== UDP
ue = UdpEcho(); uport = free_port()
g = Guard({"bed": {"type": "udp", "port": uport, "backendPort": ue.port, "pps": 50, "maxSessionsPerIP": 3, "sessionTimeout": 3,
                   "maxPacket": 600, "bytesPerSec": 100000, "replyBytesPerSec": 100000}},
          {"strikeThreshold": 12, "strikeLeakPerSec": 0, "banSteps": "{4 20}"})
try:
    g.start(); time.sleep(0.5)
    def udp_client():
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(2); return c
    c = udp_client(); c.sendto(b"ping1", ("127.0.0.1", uport))
    try: d, _ = c.recvfrom(100)
    except socket.timeout: d = b""
    check("UDP relay round trip", d == b"echo:ping1", d)
    check("backend sees a stable per-client source (not the player)", len(ue.sources) == 1)
    c2 = udp_client(); c2.sendto(b"two", ("127.0.0.1", uport)); d2, _ = c2.recvfrom(100)
    check("second client gets its own session and its own replies", d2 == b"echo:two" and len(ue.sources) == 2)
    c.sendto(b"x" * 700, ("127.0.0.1", uport)); time.sleep(0.3)
    check("oversize UDP packet dropped", ue.count == 2, ue.count)
    time.sleep(3.6)
    rc, out = g.ctl("status")
    sessions = re.search(r"UDP sessions\s+(\d+)", out)
    check("idle UDP sessions are reaped", sessions and sessions.group(1) == "0", out[:300])
    # session cap: 5 source ports from one IP, cap 3
    socks = [udp_client() for _ in range(5)]
    for i, k in enumerate(socks): k.sendto(b"s%d" % i, ("127.0.0.1", uport)); time.sleep(0.05)
    answered = 0
    for k in socks:
        k.settimeout(0.6)
        try: k.recvfrom(100); answered += 1
        except socket.timeout: pass
    check("UDP per-IP session cap (3 of 5)", answered == 3, answered)
    # packet flood -> dropped, then banned
    n0 = ue.count
    f = udp_client()
    for i in range(3000): f.sendto(b"flood%d" % i, ("127.0.0.1", uport))
    time.sleep(0.8)
    reached = ue.count - n0
    check("UDP flood: only a fraction reaches the game server", reached < 400, reached)
    rc, out = g.ctl("bans")
    check("UDP flood source banned", "127.0.0.1" in out, out[:200])
    c3 = udp_client(); c3.sendto(b"after", ("127.0.0.1", uport))
    try: d, _ = c3.recvfrom(100)
    except socket.timeout: d = b""
    check("banned UDP source gets nothing", d == b"")
finally:
    g.stop(); ue.stop()
    errs = [l for l in g.stderr().splitlines() if "background error" in l]
    check("no background errors in UDP guard log", not errs, errs[:3])
    g.cleanup()

# ============================================================== lockdown
echo = TcpEcho(); lport = free_port()
g = Guard({"svc": {"type": "tcp", "port": lport, "backendPort": echo.port, "lazyConnect": 0}}, {"strikeThreshold": 100000})
try:
    g.start(); assert wait_port(lport)
    def try_echo():
        try:
            s = socket.create_connection(("127.0.0.1", lport), 3); s.settimeout(2); s.sendall(b"q"); d = s.recv(5); s.close(); return d == b"q"
        except OSError: return False
    check("normal mode: stranger served", try_echo())
    g.ctl("level", 3); time.sleep(0.3)
    check("lockdown: unknown address refused", not try_echo())
    g.ctl("level", 0)
finally:
    g.stop(); echo.stop(); g.cleanup()

sys.exit(summary())
