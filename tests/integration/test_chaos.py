#!/usr/bin/env python3
"""Things going wrong around the guard rather than in it: kill -9, damaged or unwritable state, a flapping backend, disconnect storms, a busy port,
shutdown under load, and state growth from very many distinct client addresses. Linux checks use /proc; the rest run everywhere."""
import sys, os, time, socket, struct, subprocess, glob, json, re
sys.path.insert(0, os.path.dirname(__file__))
from harness import *

LINUX = os.path.isdir("/proc/self/fd")
def fds(pid):
    try: return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError: return -1
def rss_mb(pid):
    try:
        for l in open(f"/proc/{pid}/status"):
            if l.startswith("VmRSS:"): return int(l.split()[1]) / 1024
    except OSError: pass
    return -1
def wait_until(fn, timeout=10, step=0.2):
    t = time.time() + timeout
    while time.time() < t:
        if fn(): return True
        time.sleep(step)
    return False
def serves(port, host="x"):
    r = get("/", host=host, port=port, timeout=4)
    return status(r) == 200

# ---------------------------------------------------------------- kill -9, damaged and unwritable state
be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "connRate": 1000, "maxConnsPerIP": 200, "reqRate": 5000, "reqWindow": 10}},
          {"strikeThreshold": 50})
try:
    g.start(); assert wait_port(port)
    for ip in ("203.0.113.11", "203.0.113.12", "198.51.100.0/24"):
        rc, out = g.ctl("ban", ip, 3600, "chaos test"); check(f"ban {ip}", rc == 0, out)
    time.sleep(6.5)                     # bans are saved at most 5 seconds after they change
    g.proc.kill(); g.proc.wait(10)
    check("the guard died hard (kill -9)", g.proc.poll() is not None)
    g.start()                           # same config, same state folder, same ports
    rc, out = g.ctl("bans")
    check("after kill -9 and a restart the bans older than the save interval are back", all(x in out for x in ("203.0.113.11", "203.0.113.12", "198.51.100.0/24")), out[:300])
    check("...and the guard serves again on the same port", serves(port))
    g.stop(); g.proc.wait(10)

    # a damaged state file must not stop the guard from starting
    files = [f for f in glob.glob(os.path.join(g.dir, "**", "*"), recursive=True) if os.path.basename(f) == "bans.db" and b"203.0.113.11" in open(f, "rb").read()]
    check("the ban state file was found", bool(files), os.listdir(g.dir))
    for f in files: open(f, "wb").write(b"\x00\xff{{{ not a state file \x00")
    g.start()
    check("a damaged ban state file does not stop the guard: it serves", serves(port))
    check("...and the damage is logged, not hidden", "ban" in g.stderr().lower() and ("could not" in g.stderr().lower() or "corrupt" in g.stderr().lower() or "invalid" in g.stderr().lower() or "error" in g.stderr().lower()), g.stderr()[-300:])

    # an unwritable state folder (not meaningful as root, which ignores permissions)
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        os.chmod(g.dir, 0o500)
        try:
            rc, out = g.ctl("ban", "203.0.113.99", 600, "state folder unwritable")
            time.sleep(6.5)
            check("with an unwritable state folder the guard keeps serving", serves(port))
            check("...and says so in its log", "could not save" in g.stderr().lower() or "cannot" in g.stderr().lower() or "permission" in g.stderr().lower(), g.stderr()[-200:])
        finally:
            os.chmod(g.dir, 0o700)
    else:
        print("SKIP unwritable state folder check (running as root, or on Windows)")
finally:
    g.cleanup()

# ---------------------------------------------------------------- a flapping backend, and a storm of rude disconnects
be = HttpBackend(); bport = be.port; port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": bport, "connRate": 100000, "maxConnsPerIP": 5000, "reqRate": 100000, "reqWindow": 10}},
          {"strikeThreshold": 100000})
try:
    g.start(); assert wait_port(port)
    check("baseline: served", serves(port))
    f0 = fds(g.proc.pid)
    ok_all = True
    for rnd in range(5):
        be.stop(); time.sleep(0.3)
        t0 = time.time(); codes = [status(get("/", port=port, timeout=5)) for _ in range(10)]
        down_ok = all(c == 502 for c in codes) and time.time() - t0 < 25
        be = HttpBackend(port=bport)
        up_ok = wait_until(lambda: serves(port), 10)
        if not (down_ok and up_ok): ok_all = False; print("  round", rnd, "codes", codes, "recovered", up_ok)
    check("5 rounds of the backend disappearing: 502s while it is gone, normal service when it is back", ok_all)
    time.sleep(2)
    if LINUX:
        f1 = fds(g.proc.pid)
        check("...and no descriptors were left behind", f1 <= f0 + 8, (f0, f1))

    # a storm of connections that are reset (RST) at awkward moments
    N = 1500; socks = []
    for i in range(N):
        try:
            s = socket.create_connection(("127.0.0.1", port), 5)
            if i % 3 == 0: s.sendall(b"GET /half HTTP/1.1\r\nHost: x\r\n")            # incomplete request
            elif i % 3 == 1: s.sendall(b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\nabc")   # body that never ends
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            socks.append(s)
        except OSError: break
    for s in socks: s.close()                       # linger 0 = RST
    check(f"a storm of {len(socks)} reset connections (half requests, half bodies)", len(socks) >= 1000)
    time.sleep(3)
    check("...afterwards the guard serves normally", serves(port))
    if LINUX:
        time.sleep(5)
        f2 = fds(g.proc.pid)
        check("...and the descriptors drained back", f2 <= f0 + 8, (f0, f2))
    errs = [l for l in g.stderr().splitlines() if "Tcl error" in l or "background error" in l.lower()]
    check("no Tcl errors in the guard log", not errs, errs[:3])
finally:
    g.cleanup()

# ---------------------------------------------------------------- a busy port, and shutdown with many open connections
be = HttpBackend(); port = free_port()
blocker = socket.socket(); blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); blocker.bind(("0.0.0.0", port)); blocker.listen(5)
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port}, "ok": {"type": "tcp", "port": free_port(), "backendPort": be.port}}, {})
try:
    started = True
    try: g.start()
    except RuntimeError: started = False
    log = g.stderr().lower()
    check("a listener whose port is already taken is reported, not silently ignored", "cannot listen" in log or "address already in use" in log or "in use" in log or not started, log[-300:])
finally:
    g.cleanup(); blocker.close()

be = HttpBackend(); port = free_port()
g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "connRate": 100000, "maxConnsPerIP": 5000}}, {})
try:
    g.start(); assert wait_port(port)
    idle = []
    for i in range(300):
        try: idle.append(socket.create_connection(("127.0.0.1", port), 5))
        except OSError: break
    if os.name != "nt":
        t0 = time.time(); g.proc.terminate()
        try: g.proc.wait(10); took = time.time() - t0
        except subprocess.TimeoutExpired: took = 99
        check(f"SIGTERM with {len(idle)} open connections: the guard exits promptly", took < 8, took)
    for s in idle: s.close()
finally:
    g.cleanup()

# ---------------------------------------------------------------- state growth from very many distinct client addresses
if LINUX:
    be = HttpBackend(); port = free_port()
    g = Guard({"web": {"type": "http", "port": port, "backendPort": be.port, "trustedProxies": "127.0.0.1", "connRate": 100000, "maxConnsPerIP": 5000, "reqRate": 100000, "reqWindow": 10}},
              {"strikeThreshold": 100000})
    try:
        g.start(); assert wait_port(port)
        r0 = rss_mb(g.proc.pid); n = 0; t0 = time.time()
        conns = [socket.create_connection(("127.0.0.1", port), 5) for _ in range(8)]
        for s in conns: s.settimeout(10)
        i = 0
        while time.time() - t0 < 40:
            s = conns[i % 8]; i += 1
            a, b = divmod(i, 250)
            ip = "%d.%d.%d.%d" % (11 + (a // 65536) % 200, (a // 256) % 256, a % 256, b + 1)
            s.sendall(f"GET /g{i} HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: {ip}\r\n\r\n".encode())
            d = b""
            while b"\r\n\r\n" not in d: d += s.recv(65536)
            if b"Content-Length: " in d:
                ln = int(re.search(rb"Content-Length: (\d+)", d).group(1)); body = d.split(b"\r\n\r\n", 1)[1]
                while len(body) < ln: body += s.recv(65536)
            n += 1
        for s in conns: s.close()
        r1 = rss_mb(g.proc.pid)
        print(f"INFO {n} requests from {n} distinct client addresses in 40 s; guard memory {r0:.0f} -> {r1:.0f} MB")
        check("the guard still answers after the distinct-address flood", serves(port))
        check("memory growth from distinct client addresses is bounded (< 200 MB for this run)", r1 - r0 < 200, (r0, r1))
        time.sleep(30)
        r2 = rss_mb(g.proc.pid)
        print(f"INFO memory 30 s later: {r2:.0f} MB")
        errs = [l for l in g.stderr().splitlines() if "Tcl error" in l or "background error" in l.lower()]
        check("no Tcl errors in the guard log", not errs, errs[:3])
    finally:
        g.cleanup()
else:
    print("SKIP the distinct-address growth check (uses /proc)")
sys.exit(summary())
